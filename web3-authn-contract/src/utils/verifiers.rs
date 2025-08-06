use near_sdk::log;
use serde_cbor::Value as CborValue;
use ed25519_dalek::Signature as Ed25519Signature;
use x509_parser::prelude::*;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use p256::PublicKey as P256PublicKey;

use crate::utils::p256_utils::{
    extract_p256_coordinates_from_cose,
    create_p256_public_key,
    get_uncompressed_p256_pubkey,
};

pub(crate) fn verify_attestation_signature(
    attestation_stmt: &CborValue,
    auth_data: &[u8],
    client_data_hash: &[u8],
    credential_public_key: &[u8],
    fmt: &str,
) -> Result<bool, String> {
    match fmt {
        "none" => {
            // No signature to verify for "none" attestation
            Ok(true)
        }
        "packed" => verify_packed_signature(
            attestation_stmt,
            auth_data,
            client_data_hash,
            credential_public_key,
        ),
        "fido-u2f" => verify_u2f_signature(
            attestation_stmt,
            auth_data,
            client_data_hash,
            credential_public_key,
        ),
        _ => Err(format!("Unsupported attestation format: {}", fmt)),
    }
}

pub(crate)fn verify_packed_signature(
    attestation_stmt: &CborValue,
    auth_data: &[u8],
    client_data_hash: &[u8],
    credential_public_key: &[u8],
) -> Result<bool, String> {
    if let CborValue::Map(stmt_map) = attestation_stmt {
        // Extract signature
        let signature_bytes = stmt_map
            .get(&CborValue::Text("sig".to_string()))
            .and_then(|v| {
                if let CborValue::Bytes(b) = v {
                    Some(b)
                } else {
                    None
                }
            })
            .ok_or("Missing signature in packed attestation")?;

        // Extract algorithm (should be -7 for ES256)
        let alg = stmt_map
            .get(&CborValue::Text("alg".to_string()))
            .and_then(|v| {
                if let CborValue::Integer(i) = v {
                    Some(*i)
                } else {
                    None
                }
            })
            .ok_or("Missing algorithm in packed attestation")?;

        if alg != -7 {
            return Err(format!(
                "Unsupported algorithm: {} (expected -7 for ES256)",
                alg
            ));
        }

        // Check for x5c certificate chain
        if let Some(x5c_value) = stmt_map.get(&CborValue::Text("x5c".to_string())) {
            // Handle full attestation with certificate chain
            if let CborValue::Array(x5c) = x5c_value {
                match validate_certificate_chain(x5c) {
                    Ok(attestation_pubkey) => {
                        return verify_p256_signature_with_verifying_key(
                            signature_bytes,
                            auth_data,
                            client_data_hash,
                            &attestation_pubkey,
                        );
                    }
                    Err(e) => return Err(format!("Certificate chain validation failed: {}", e)),
                }
            } else {
                return Err("Invalid x5c format - expected array".to_string())
            }
        } else {
            // Self-attestation (no x5c), verify against credential key
            return verify_p256_signature_from_cose(
                signature_bytes,
                auth_data,
                client_data_hash,
                credential_public_key,
            );
        }
    }

    Err("Invalid attestation statement format".to_string())
}


/// P-256 signature verification using COSE-encoded public key
pub(crate) fn verify_p256_signature_from_cose(
    signature_bytes: &[u8],
    auth_data: &[u8],
    client_data_hash: &[u8],
    cose_public_key: &[u8],
) -> Result<bool, String> {
    // Parse COSE public key to get P-256 coordinates
    let cose_key: CborValue = serde_cbor::from_slice(cose_public_key)
        .map_err(|_| "Failed to parse COSE public key")?;

    let (x_bytes, y_bytes) = extract_p256_coordinates_from_cose(&cose_key)?;

    // Create P-256 public key from coordinates
    let public_key = create_p256_public_key(&x_bytes, &y_bytes)?;

    // Use the unified verification function
    verify_p256_signature_with_verifying_key(
        signature_bytes,
        auth_data,
        client_data_hash,
        &public_key,
    )
}

/// Core P-256 signature verification function
/// This is the unified implementation used by all other P-256 verification functions
pub(crate) fn verify_p256_signature_with_verifying_key(
    signature_bytes: &[u8],
    auth_data: &[u8],
    client_data_hash: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<bool, String> {
    // Create verification data: authData || clientDataHash
    let mut verification_data = auth_data.to_vec();
    verification_data.extend_from_slice(client_data_hash);

    // Parse signature (DER encoded)
    let signature = Signature::from_der(signature_bytes)
        .map_err(|_| "Invalid signature format")?;

    // Verify signature
    match verifying_key.verify(&verification_data, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}


pub(crate) fn verify_u2f_signature(
    attestation_stmt: &CborValue,
    auth_data: &[u8],
    client_data_hash: &[u8],
    credential_public_key: &[u8],
) -> Result<bool, String> {
    log!("Starting FIDO U2F signature verification");

    // Extract signature from attestation statement
    let signature_bytes = if let CborValue::Map(stmt_map) = attestation_stmt {
        stmt_map
            .get(&CborValue::Text("sig".to_string()))
            .and_then(|v| {
                if let CborValue::Bytes(b) = v {
                    Some(b)
                } else {
                    None
                }
            })
            .ok_or("Missing signature in U2F attestation statement")?
    } else {
        return Err("Invalid U2F attestation statement format".to_string());
    };

    // Parse authenticator data to extract components
    if auth_data.len() < 37 {
        return Err("Authenticator data too short for U2F".to_string());
    }

    // Extract RP ID hash (first 32 bytes of authData)
    let rp_id_hash = &auth_data[0..32];

    // Extract credential ID from authenticator data
    // AuthData format: rpIdHash(32) + flags(1) + counter(4) + aaguid(16) + credIdLen(2) + credId(variable) + pubKey(variable)
    if auth_data.len() < 55 {
        return Err("Authenticator data too short to contain credential".to_string());
    }

    // Skip to credential ID length (at offset 53)
    let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    if auth_data.len() < 55 + cred_id_len {
        return Err("Authenticator data too short for credential ID".to_string());
    }

    let credential_id = &auth_data[55..55 + cred_id_len];

    // Parse credential public key to get uncompressed P-256 point
    let uncompressed_pubkey = get_uncompressed_p256_pubkey(credential_public_key)?;

    // Construct U2F signature data: 0x00 || appParam || chlngParam || keyHandle || pubKey
    let mut u2f_signature_data = Vec::new();
    u2f_signature_data.push(0x00); // Reserved byte
    u2f_signature_data.extend_from_slice(rp_id_hash); // Application parameter (32 bytes)
    u2f_signature_data.extend_from_slice(client_data_hash); // Challenge parameter (32 bytes)
    u2f_signature_data.extend_from_slice(credential_id); // Key handle (variable)
    u2f_signature_data.extend_from_slice(&uncompressed_pubkey); // User public key (65 bytes)

    // For U2F attestation, we need the attestation certificate's public key
    // If no certificate is provided, we use self-attestation (credential public key)
    let verifying_key = if let CborValue::Map(stmt_map) = attestation_stmt {
        if let Some(x5c_value) = stmt_map.get(&CborValue::Text("x5c".to_string())) {
            // Certificate chain present - extract public key from attestation certificate
            if let CborValue::Array(x5c) = x5c_value {
                log!("U2F attestation with certificate chain");
                match validate_certificate_chain(x5c) {
                    Ok(attestation_pubkey) => attestation_pubkey,
                    Err(e) => return Err(format!("U2F certificate chain validation failed: {}", e)),
                }
            } else {
                return Err("Invalid x5c format in U2F attestation".to_string());
            }
        } else {
            // Self-attestation - use credential public key
            let parsed_cose_key: CborValue = serde_cbor::from_slice(credential_public_key)
                .map_err(|_| "Failed to parse COSE public key")?;

            log!("U2F self-attestation - using credential public key");
            let (
                x_bytes,
                y_bytes
            ) = extract_p256_coordinates_from_cose(&parsed_cose_key)?;

            create_p256_public_key(&x_bytes, &y_bytes)?
        }
    } else {
        return Err("Invalid attestation statement format".to_string());
    };

    // Parse and verify signature
    let signature = p256::ecdsa::Signature::from_der(signature_bytes)
        .map_err(|_| "Invalid DER signature format")?;

    // Verify signature
    use p256::ecdsa::signature::Verifier;
    match verifying_key.verify(&u2f_signature_data, &signature) {
        Ok(()) => {
            log!("U2F signature verification successful");
            Ok(true)
        }
        Err(_) => {
            log!("U2F signature verification failed");
            Ok(false)
        }
    }
}

pub(crate) fn verify_authentication_signature(
    signature_bytes: &[u8],
    signed_data: &[u8],
    credential_public_key: &[u8],
) -> Result<bool, String> {
    log!("Starting authentication signature verification");

    // Parse COSE public key to determine the algorithm and extract parameters
    let cose_key: CborValue = serde_cbor::from_slice(credential_public_key)
        .map_err(|_| "Failed to parse COSE public key")?;

    if let CborValue::Map(key_map) = &cose_key {
        // Check key type (kty)
        let kty = key_map
            .get(&CborValue::Integer(1))
            .and_then(|v| {
                if let CborValue::Integer(i) = v {
                    Some(*i)
                } else {
                    None
                }
            })
            .ok_or("Missing key type (kty) in COSE key")?;

        // Check algorithm (alg)
        let alg = key_map
            .get(&CborValue::Integer(3))
            .and_then(|v| {
                if let CborValue::Integer(i) = v {
                    Some(*i)
                } else {
                    None
                }
            })
            .ok_or("Missing algorithm (alg) in COSE key")?;

        match (kty, alg) {
            (2, -7) => {
                // P-256 with ES256 (ECDSA with SHA-256)
                verify_p256_authentication_signature(signature_bytes, signed_data, &cose_key)
            }
            (1, -8) => {
                // Ed25519 with EdDSA
                verify_ed25519_authentication_signature(signature_bytes, signed_data, &cose_key)
            }
            _ => Err(format!(
                "Unsupported key type/algorithm combination: kty={}, alg={}",
                kty, alg
            )),
        }
    } else {
        Err("Invalid COSE key format".to_string())
    }
}

fn verify_p256_authentication_signature(
    signature_bytes: &[u8],
    signed_data: &[u8],
    cose_key: &CborValue,
) -> Result<bool, String> {
    // Extract P-256 coordinates from COSE key
    let (x_bytes, y_bytes) = extract_p256_coordinates_from_cose(cose_key)?;

    // Create P-256 public key from coordinates
    let public_key = create_p256_public_key(&x_bytes, &y_bytes)?;

    // Parse signature (DER encoded)
    let signature = Signature::from_der(signature_bytes)
        .map_err(|_| "Invalid P-256 signature format")?;

    // Verify signature
    use p256::ecdsa::signature::Verifier;
    match public_key.verify(signed_data, &signature) {
        Ok(()) => {
            log!("P-256 authentication signature verification successful");
            Ok(true)
        }
        Err(_) => {
            log!("P-256 authentication signature verification failed");
            Ok(false)
        }
    }
}

fn verify_ed25519_authentication_signature(
    signature_bytes: &[u8],
    signed_data: &[u8],
    cose_key: &CborValue,
) -> Result<bool, String> {
    // Extract Ed25519 public key from COSE key
    if let CborValue::Map(key_map) = cose_key {
        let x_bytes = key_map
            .get(&CborValue::Integer(-2))
            .and_then(|v| {
                if let CborValue::Bytes(b) = v {
                    Some(b)
                } else {
                    None
                }
            })
            .ok_or("Missing x coordinate in Ed25519 COSE key")?;

        if x_bytes.len() != 32 {
            return Err("Invalid Ed25519 public key length".to_string());
        }

        if signature_bytes.len() != 64 {
            return Err("Invalid Ed25519 signature length".to_string());
        }

        // Parse the Ed25519 public key
        let public_key_array: [u8; 32] = x_bytes.as_slice().try_into()
            .map_err(|_| "Failed to convert public key to array")?;

        let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&public_key_array) {
            Ok(key) => key,
            Err(e) => return Err(format!("Invalid Ed25519 public key: {}", e)),
        };

        // Parse the signature
        let signature_array: [u8; 64] = signature_bytes.try_into()
            .map_err(|_| "Failed to convert signature to array")?;

        let signature = Ed25519Signature::from_bytes(&signature_array);

        // Verify the signature
        use ed25519_dalek::Verifier;
        match verifying_key.verify(signed_data, &signature) {
            Ok(()) => {
                log!("Ed25519 authentication signature verification successful");
                Ok(true)
            }
            Err(_) => {
                log!("Ed25519 authentication signature verification failed");
                Ok(false)
            }
        }
    } else {
        Err("Invalid COSE key format for Ed25519".to_string())
    }
}

/// Validates X.509 certificate chain and extracts the attestation public key
/// This implements basic x5c validation for WebAuthn attestation
fn validate_certificate_chain(x5c: &[CborValue]) -> Result<VerifyingKey, String> {
    if x5c.is_empty() {
        return Err("Empty certificate chain".to_string());
    }

    // Extract the leaf certificate (first in chain)
    let leaf_cert_bytes = if let CborValue::Bytes(cert_bytes) = &x5c[0] {
        cert_bytes
    } else {
        return Err("Invalid certificate format in x5c".to_string());
    };

    // Parse the X.509 certificate
    let (_, cert) = X509Certificate::from_der(leaf_cert_bytes)
        .map_err(|e| format!("Failed to parse X.509 certificate: {}", e))?;

    // Extract the public key from the certificate
    let public_key_info = cert.public_key();
    let public_key_bytes = &*public_key_info.subject_public_key.data;

    // For P-256 certificates, the public key is typically in uncompressed format
    // Check if it's the right length (65 bytes for uncompressed P-256)
    if public_key_bytes.len() == 65 && public_key_bytes[0] == 0x04 {
        // Create P-256 public key directly from uncompressed bytes
        let public_key = P256PublicKey::from_sec1_bytes(public_key_bytes)
            .map_err(|_| "Invalid P-256 public key in certificate")?;

        Ok(VerifyingKey::from(public_key))
    } else {
        return Err("Unsupported public key format in certificate".to_string());
    }
}

/////////////////////////////////////
/// TESTS
/////////////////////////////////////

mod tests {
    use super::*;
    use std::collections::BTreeMap;

    // Helper function to create a mock DER-encoded signature for testing
    fn _create_mock_der_signature() -> Vec<u8> {
        // This creates a valid DER structure but with mock values
        // Real signature would be generated by actual private key
        // DER format: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
        let r = vec![0x01u8; 32]; // Mock r value (32 bytes)
        let s = vec![0x02u8; 32]; // Mock s value (32 bytes)

        let mut der_sig = Vec::new();
        der_sig.push(0x30); // SEQUENCE tag
        der_sig.push(68); // Total length: 2 + 32 + 2 + 32 = 68
        der_sig.push(0x02); // INTEGER tag for r
        der_sig.push(32); // Length of r
        der_sig.extend_from_slice(&r);
        der_sig.push(0x02); // INTEGER tag for s
        der_sig.push(32); // Length of s
        der_sig.extend_from_slice(&s);

        der_sig
    }

    fn _build_p256_cose_key(x_coord: &[u8; 32], y_coord: &[u8; 32]) -> Vec<u8> {
        let mut map = BTreeMap::new();
        map.insert(CborValue::Integer(1), CborValue::Integer(2)); // kty: EC2
        map.insert(CborValue::Integer(3), CborValue::Integer(-7)); // alg: ES256
        map.insert(CborValue::Integer(-1), CborValue::Integer(1)); // crv: P-256
        map.insert(CborValue::Integer(-2), CborValue::Bytes(x_coord.to_vec())); // x
        map.insert(CborValue::Integer(-3), CborValue::Bytes(y_coord.to_vec())); // y
        serde_cbor::to_vec(&CborValue::Map(map)).unwrap()
    }

    // Test private key (32 bytes) - ONLY FOR TESTING
    fn _get_test_private_key() -> [u8; 32] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ]
    }

    // Generate test data with matching private/public key and signature
    fn _create_test_signature_data() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use p256::ecdsa::{SigningKey, signature::Signer};

        // Create private key from test bytes
        let private_key_bytes = _get_test_private_key();
        let signing_key = SigningKey::from_bytes(&private_key_bytes.into())
            .expect("Failed to create signing key");

        // Get public key coordinates
        let verifying_key = signing_key.verifying_key();
        let public_key_point = verifying_key.to_encoded_point(false); // Uncompressed
        let public_key_bytes = public_key_point.as_bytes();

        // Extract x and y coordinates (skip 0x04 prefix)
        let x_coord = public_key_bytes[1..33].to_vec();
        let y_coord = public_key_bytes[33..65].to_vec();

        // Create COSE public key
        let mut cose_map = BTreeMap::new();
        cose_map.insert(CborValue::Integer(1), CborValue::Integer(2)); // kty: EC2
        cose_map.insert(CborValue::Integer(3), CborValue::Integer(-7)); // alg: ES256
        cose_map.insert(CborValue::Integer(-1), CborValue::Integer(1)); // crv: P-256
        cose_map.insert(CborValue::Integer(-2), CborValue::Bytes(x_coord)); // x
        cose_map.insert(CborValue::Integer(-3), CborValue::Bytes(y_coord)); // y
        let cose_public_key = serde_cbor::to_vec(&CborValue::Map(cose_map)).unwrap();

        // Create test data to sign
        let auth_data = vec![0u8; 37];
        let client_data_hash = [0u8; 32];

        // Create verification data: authData || clientDataHash
        let mut verification_data = auth_data.clone();
        verification_data.extend_from_slice(&client_data_hash);

        // Sign the data
        let signature: p256::ecdsa::Signature = signing_key.sign(&verification_data);
        let signature_bytes = signature.to_der().as_bytes().to_vec();

        (cose_public_key, auth_data, signature_bytes)
    }

    #[test]
    fn test_verify_packed_signature_self_attestation() {
        // Test self-attestation with real cryptographic signature
        let (
            cose_public_key,
            auth_data,
            signature_bytes
        ) = _create_test_signature_data();

        let mut attestation_stmt_map = BTreeMap::new();
        attestation_stmt_map.insert(
            CborValue::Text("sig".to_string()),
            CborValue::Bytes(signature_bytes),
        );
        attestation_stmt_map.insert(
            CborValue::Text("alg".to_string()),
            CborValue::Integer(-7),
        );
        // No x5c - this is self-attestation

        let attestation_stmt = CborValue::Map(attestation_stmt_map);
        let client_data_hash = [0u8; 32];

        let result = verify_packed_signature(
            &attestation_stmt,
            &auth_data,
            &client_data_hash,
            &cose_public_key,
        );

        // With real signature data, verification should succeed
        match result {
            Ok(verified) => {
                assert!(verified, "Real signature should verify successfully");
            }
            Err(e) => {
                panic!("Should not fail with valid signature data: {}", e);
            }
        }
    }

    #[test]
    fn test_verify_packed_signature_with_x5c_invalid() {
        // Test with invalid x5c (non-array)
        let (cose_public_key, _, _) = _create_test_signature_data();

        let mock_signature = _create_mock_der_signature();
        let mut attestation_stmt_map = BTreeMap::new();
        attestation_stmt_map.insert(
            CborValue::Text("sig".to_string()),
            CborValue::Bytes(mock_signature),
        );
        attestation_stmt_map.insert(
            CborValue::Text("alg".to_string()),
            CborValue::Integer(-7),
        );
        // Invalid x5c format (should be array)
        attestation_stmt_map.insert(
            CborValue::Text("x5c".to_string()),
            CborValue::Text("invalid".to_string()),
        );

        let attestation_stmt = CborValue::Map(attestation_stmt_map);
        let auth_data = vec![0u8; 37];
        let client_data_hash = [0u8; 32];

        let result = verify_packed_signature(
            &attestation_stmt,
            &auth_data,
            &client_data_hash,
            &cose_public_key,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid x5c format"));
    }

    #[test]
    fn test_validate_certificate_chain_empty() {
        let empty_x5c = vec![];
        let result = validate_certificate_chain(&empty_x5c);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Empty certificate chain"));
    }

    #[test]
    fn test_validate_certificate_chain_invalid_format() {
        let invalid_x5c = vec![CborValue::Text("not_a_certificate".to_string())];
        let result = validate_certificate_chain(&invalid_x5c);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid certificate format"));
    }

    // Tests for FIDO U2F signature verification
    #[test]
    fn test_verify_u2f_signature_self_attestation() {

        // Use known valid P-256 coordinates (from NIST test vectors)
        // These are valid points on the P-256 curve
        let x_coord = [
            0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35,
            0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e,
            0x60, 0xf2, 0x9f, 0xb6,
        ];
        let y_coord = [
            0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28,
            0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94,
            0xd4, 0x46, 0x22, 0x99,
        ];

        // Build COSE public key
        let cose_public_key = _build_p256_cose_key(&x_coord, &y_coord);

        // Build mock authenticator data
        let rp_id_hash = [0x41u8; 32]; // Mock RP ID hash
        let flags = 0x41u8; // User present + attested credential data
        let counter = [0x00, 0x00, 0x00, 0x01u8]; // Counter = 1
        let aaguid = [0x00u8; 16]; // Mock AAGUID
        let credential_id = b"test_credential_id_12345678"; // 28 bytes
        let cred_id_len = (credential_id.len() as u16).to_be_bytes();

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash); // 32 bytes
        auth_data.push(flags); // 1 byte
        auth_data.extend_from_slice(&counter); // 4 bytes
        auth_data.extend_from_slice(&aaguid); // 16 bytes
        auth_data.extend_from_slice(&cred_id_len); // 2 bytes (total: 55 bytes)
        auth_data.extend_from_slice(credential_id); // 28 bytes
        auth_data.extend_from_slice(&cose_public_key); // Variable length

        // Mock client data hash
        let client_data_hash = [0x42u8; 32];

        // Build U2F signature data (what should be signed)
        let mut u2f_signature_data = Vec::new();
        u2f_signature_data.push(0x00); // Reserved byte
        u2f_signature_data.extend_from_slice(&rp_id_hash); // Application parameter
        u2f_signature_data.extend_from_slice(&client_data_hash); // Challenge parameter
        u2f_signature_data.extend_from_slice(credential_id); // Key handle

        // Add uncompressed public key (0x04 || x || y)
        u2f_signature_data.push(0x04);
        u2f_signature_data.extend_from_slice(&x_coord);
        u2f_signature_data.extend_from_slice(&y_coord);

        // For testing, we'll create a mock signature (normally this would be generated by a real key)
        // Since we don't have the private key, we'll create a plausible-looking DER signature
        let mock_signature = _create_mock_der_signature();

        // Build attestation statement (self-attestation, no x5c)
        let mut attestation_stmt_map = BTreeMap::new();
        attestation_stmt_map.insert(
            CborValue::Text("sig".to_string()),
            CborValue::Bytes(mock_signature),
        );
        let attestation_stmt = CborValue::Map(attestation_stmt_map);

        // Test the verification (this will fail because we have a mock signature,
        // but it should get through the parsing logic without errors)
        let result = verify_u2f_signature(
            &attestation_stmt,
            &auth_data,
            &client_data_hash,
            &cose_public_key,
        );

        // We expect this to return Ok(false) because the signature is mock/invalid
        // But it should not panic or return an error due to parsing issues
        assert!(result.is_ok(), "Should not error on parsing: {:?}", result);
        assert_eq!(
            result.unwrap(),
            false,
            "Mock signature should fail verification"
        );
    }

    #[test]
    fn test_verify_u2f_signature_invalid_public_key() {

        // Use invalid P-256 coordinates (not on the curve)
        let x_coord = [0x01u8; 32]; // Invalid point
        let y_coord = [0x02u8; 32]; // Invalid point
        let cose_public_key = _build_p256_cose_key(&x_coord, &y_coord);

        // Build minimal valid authenticator data
        let mut auth_data = vec![0u8; 55]; // Minimum length for credential data
        auth_data.extend_from_slice(b"test_cred_id_123456"); // 20 bytes credential ID
        auth_data.extend_from_slice(&cose_public_key); // COSE public key

        // Set credential ID length at correct offset (bytes 53-54)
        let cred_id_len = 20u16;
        auth_data[53] = (cred_id_len >> 8) as u8;
        auth_data[54] = (cred_id_len & 0xff) as u8;

        let client_data_hash = [0u8; 32];
        let mock_signature = _create_mock_der_signature();

        let mut attestation_stmt_map = BTreeMap::new();
        attestation_stmt_map.insert(
            CborValue::Text("sig".to_string()),
            CborValue::Bytes(mock_signature),
        );
        let attestation_stmt = CborValue::Map(attestation_stmt_map);

        let result = verify_u2f_signature(
            &attestation_stmt,
            &auth_data,
            &client_data_hash,
            &cose_public_key,
        );

        // Should fail due to invalid public key
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid P-256 public key"));
    }

    #[test]
    fn test_verify_u2f_signature_missing_signature() {

        // Empty attestation statement (missing signature)
        let attestation_stmt_map = BTreeMap::new();
        let attestation_stmt = CborValue::Map(attestation_stmt_map);

        let auth_data = vec![0u8; 100]; // Mock auth data
        let client_data_hash = [0u8; 32];
        let cose_public_key = _build_p256_cose_key(&[1u8; 32], &[2u8; 32]);

        let result = verify_u2f_signature(
            &attestation_stmt,
            &auth_data,
            &client_data_hash,
            &cose_public_key,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing signature"));
    }

    #[test]
    fn test_verify_u2f_signature_invalid_auth_data() {
        // Valid attestation statement
        let mock_signature = _create_mock_der_signature();
        let mut attestation_stmt_map = BTreeMap::new();
        attestation_stmt_map.insert(
            CborValue::Text("sig".to_string()),
            CborValue::Bytes(mock_signature),
        );
        let attestation_stmt = CborValue::Map(attestation_stmt_map);

        // Invalid auth data (too short)
        let auth_data = vec![0u8; 30]; // Too short for U2F
        let client_data_hash = [0u8; 32];
        let cose_public_key = _build_p256_cose_key(&[1u8; 32], &[2u8; 32]);

        let result = verify_u2f_signature(
            &attestation_stmt,
            &auth_data,
            &client_data_hash,
            &cose_public_key,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Authenticator data too short"));
    }

}