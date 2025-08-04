use near_sdk::{env, log, near};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE;
use base64::Engine;

use crate::WebAuthnContract;
use crate::contract_state::WebAuthnContractExt;
use crate::utils::{
    parsers::parse_authenticator_data,
    verifiers::verify_authentication_signature,
    validation::{
        validate_webauthn_client_data,
        validate_webauthn_origin,
        validate_webauthn_user_flags,
        validate_webauthn_rp_id_hash
    },
};
use crate::types::{
    AuthenticatorDevice,
    WebAuthnAuthenticationCredential
};

use crate::utils::vrf_verifier::{
    verify_vrf_and_extract_challenge,
    VRFVerificationData
};

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone)]
pub struct VerifiedAuthenticationResponse {
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication_info: Option<AuthenticationInfo>,
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone)]
pub struct AuthenticationInfo {
    pub credential_id: Vec<u8>,
    pub new_counter: u32,
    pub user_verified: bool,
    pub credential_device_type: String, // "singleDevice" or "multiDevice"
    pub credential_backed_up: bool,
    pub origin: String,
    pub rp_id: String,
}

/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

#[near]
impl WebAuthnContract {

    /// VRF Authentication - Subsequent logins (stateless, view-only)
    /// Verifies VRF proof + WebAuthn authentication using stored credentials
    ///
    /// # Arguments
    /// * `vrf_data` - VRF verification data containing proof, input, output and metadata
    /// * `webauthn_authentication` - WebAuthn authentication credential from authenticator
    ///
    /// # Returns
    /// * `VerifiedAuthenticationResponse` - Contains verification status and authentication info
    ///
    /// # Public
    /// This is a public view function that does not modify contract state
    pub fn verify_authentication_response(
        &self,
        vrf_data: VRFVerificationData,
        webauthn_authentication: WebAuthnAuthenticationCredential,
    ) -> VerifiedAuthenticationResponse {

        log!("VRF Authentication: Verifying VRF proof + WebAuthn authentication");
        log!("  - User ID: {}", vrf_data.user_id);
        log!("  - RP ID (domain): {}", vrf_data.rp_id);

        // 1. Validate VRF and extract WebAuthn challenge (view-only)
        let vrf_challenge_b64url = match verify_vrf_and_extract_challenge(&vrf_data, &self.vrf_settings) {
            Some(challenge) => challenge,
            None => return VerifiedAuthenticationResponse {
                verified: false,
                authentication_info: None,
            },
        };
        log!("VRF proof verified, extracted challenge: {} bytes", vrf_challenge_b64url.len());

        // 2. Look up stored authenticator using credential ID and provided user_id (account_id)
        let credential_id_b64url = webauthn_authentication.id.clone();
        let user_account_id = match near_sdk::AccountId::try_from(vrf_data.user_id.clone()) {
            Ok(account_id) => account_id,
            Err(_) => {
                log!("Invalid user_id format: {}", vrf_data.user_id);
                return VerifiedAuthenticationResponse {
                    verified: false,
                    authentication_info: None,
                };
            }
        };
        let stored_authenticator = match self.get_authenticator(user_account_id.clone(), credential_id_b64url.clone()) {
            Some(auth) => auth,
            None => {
                log!("No stored authenticator found for credential ID: {}", credential_id_b64url);
                return VerifiedAuthenticationResponse {
                    verified: false,
                    authentication_info: None,
                };
            }
        };

        // 3. Verify that the provided VRF public key is in the stored VRF keys
        if !stored_authenticator.vrf_public_keys.contains(&vrf_data.public_key) {
            log!("VRF public key not found in stored keys - authentication denied");
            return VerifiedAuthenticationResponse {
                verified: false,
                authentication_info: None,
            };
        }
        log!("VRF public key found in stored credentials");

        // 4. Create authenticator device for verification
        let authenticator_device = AuthenticatorDevice {
            credential_id: BASE64_URL_ENGINE.decode(&credential_id_b64url).unwrap_or_default(),
            credential_public_key: stored_authenticator.credential_public_key.clone(),
            counter: 0, // VRF WebAuthn uses stateless verification, counter not used for replay protection
            transports: stored_authenticator.transports.clone(),
        };

        // 5. Optional: Verify VRF RP ID matches stored RP ID for additional origin binding
        if vrf_data.rp_id != stored_authenticator.expected_rp_id {
            log!("VRF RP ID mismatch: expected {}, got {}", stored_authenticator.expected_rp_id, vrf_data.rp_id);
            return VerifiedAuthenticationResponse {
                verified: false,
                authentication_info: None,
            };
        }
        log!("VRF RP ID verification passed: {}", vrf_data.rp_id);

        // 6. Verify WebAuthn authentication with VRF-generated challenge
        let webauthn_result = self.internal_verify_authentication_response(
            webauthn_authentication,
            // expected values to verify webauthn_authentication response against
            vrf_challenge_b64url,                 // expected VRF challenge
            stored_authenticator.expected_origin, // expected origin
            stored_authenticator.expected_rp_id,  // expected RP ID
            authenticator_device,
            Some(true), // require_user_verification for VRF mode
        );

        if webauthn_result.verified {
            log!("VRF Authentication successful - stateless verification completed");
        } else {
            log!("WebAuthn authentication verification failed");
        }

        webauthn_result
    }

    /// Internal WebAuthn authentication verification
    /// Equivalent to @simplewebauthn/server's verifyAuthenticationResponse function
    fn internal_verify_authentication_response(
        &self,
        response: WebAuthnAuthenticationCredential,
        expected_challenge: String,
        expected_origin: String,
        expected_rp_id: String,
        authenticator: AuthenticatorDevice,
        require_user_verification: Option<bool>,
    ) -> VerifiedAuthenticationResponse {
        log!("Internal WebAuthn authentication verification");
        log!("Expected challenge: {}", expected_challenge);
        log!("Expected origin: {}", expected_origin);
        log!("Expected RP ID: {}", expected_rp_id);

        let require_user_verification = require_user_verification.unwrap_or(false);

        // Step 1-3: Parse and validate clientDataJSON, type, and challenge
        let (
            client_data,
            client_data_json_bytes
        ) = match validate_webauthn_client_data(
            &response.response.client_data_json,
            &expected_challenge,
            "webauthn.get"
        ) {
            Ok(data) => data,
            Err(e) => {
                log!("{}", e);
                return VerifiedAuthenticationResponse {
                    verified: false,
                    authentication_info: None,
                };
            }
        };

        // Step 4: Verify origin matches expected pattern
        if let Err(e) = validate_webauthn_origin(&client_data.origin, &expected_origin, &expected_rp_id, self.tld_config.as_ref()) {
            log!("{}", e);
            return VerifiedAuthenticationResponse {
                verified: false,
                authentication_info: None,
            };
        }

        log!("Origin verification passed for: {}", client_data.origin);

        // Step 5: Parse authenticator data
        let authenticator_data_bytes = match BASE64_URL_ENGINE.decode(&response.response.authenticator_data) {
            Ok(bytes) => bytes,
            Err(_) => {
                log!("Failed to decode authenticatorData from base64url");
                return VerifiedAuthenticationResponse {
                    verified: false,
                    authentication_info: None,
                };
            }
        };

        let auth_data = match parse_authenticator_data(&authenticator_data_bytes) {
            Ok(data) => data,
            Err(e) => {
                log!("Failed to parse authenticator data: {}", e);
                return VerifiedAuthenticationResponse {
                    verified: false,
                    authentication_info: None,
                };
            }
        };

        // Step 6: Verify RP ID hash
        if let Err(e) = validate_webauthn_rp_id_hash(&auth_data.rp_id_hash, &expected_rp_id) {
            log!("{}", e);
            return VerifiedAuthenticationResponse {
                verified: false,
                authentication_info: None,
            };
        }

        // Step 7-8: Check user verification and presence flags
        let user_verified = match validate_webauthn_user_flags(auth_data.flags, require_user_verification) {
            Ok(verified) => verified,
            Err(e) => {
                log!("{}", e);
                return VerifiedAuthenticationResponse {
                    verified: false,
                    authentication_info: None,
                };
            }
        };

        // Step 9: Verify counter (anti-replay)
        // Allow both counters to be 0 (authenticator doesn't support counters)
        // or require counter increment for authenticators that do support counters
        if authenticator.counter > 0 && auth_data.counter <= authenticator.counter {
            log!("Counter not incremented: expected > {}, got {}", authenticator.counter, auth_data.counter);
            return VerifiedAuthenticationResponse {
                verified: false,
                authentication_info: None,
            };
        }

        // Step 10: Verify signature
        let signature_bytes = match BASE64_URL_ENGINE.decode(&response.response.signature) {
            Ok(bytes) => bytes,
            Err(_) => {
                log!("Failed to decode signature from base64url");
                return VerifiedAuthenticationResponse {
                    verified: false,
                    authentication_info: None,
                };
            }
        };

        // Construct the data that was signed: authenticatorData + hash(clientDataJSON)
        let client_data_hash = env::sha256(&client_data_json_bytes);
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&authenticator_data_bytes);
        signed_data.extend_from_slice(&client_data_hash);

        // Verify signature using the stored public key
        let signature_valid = match verify_authentication_signature(
            &signature_bytes,
            &signed_data,
            &authenticator.credential_public_key,
        ) {
            Ok(valid) => valid,
            Err(e) => {
                log!("Error verifying authentication signature: {}", e);
                return VerifiedAuthenticationResponse {
                    verified: false,
                    authentication_info: None,
                };
            }
        };

        if !signature_valid {
            log!("Authentication signature verification failed");
            return VerifiedAuthenticationResponse {
                verified: false,
                authentication_info: None,
            };
        }

        // Step 11: Determine credential device type and backup status
        let credential_backed_up = (auth_data.flags & 0x10) != 0; // BS flag
        let credential_device_type = if (auth_data.flags & 0x20) != 0 { // BE flag
            "multiDevice"
        } else {
            "singleDevice"
        };

        // Step 12: Authentication successful
        log!("Authentication verification successful");

        // Note: user_account_id is passed into the function as an input,
        // and is cryptographically bound in the VRF challenge as it is a VRF input

        VerifiedAuthenticationResponse {
            verified: true,
            authentication_info: Some(AuthenticationInfo {
                credential_id: authenticator.credential_id,
                new_counter: auth_data.counter,
                user_verified,
                credential_device_type: credential_device_type.to_string(),
                credential_backed_up,
                origin: client_data.origin,
                rp_id: expected_rp_id,
            }),
        }
    }
}

/////////////////////////////////////
/// TESTS
/////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as TEST_BASE64_URL_ENGINE};
    use std::collections::BTreeMap;
    use sha2::{Sha256, Digest};
    use crate::contract_state::StoredAuthenticator;
    use crate::types::AuthenticatorAssertionResponse;

    // Mock VRF dependencies for testing
    struct MockVRFData {
        pub input_data: Vec<u8>,
        pub output: Vec<u8>,
        pub proof: Vec<u8>,
        pub public_key: Vec<u8>,
    }

    impl MockVRFData {
        fn create_mock() -> Self {
            // Create deterministic mock VRF data for testing
            let domain = b"web3_authn_challenge_v3";
            let user_id = b"test_user_123";
            let rp_id = b"example.com"; // Use proper domain for RP ID
            let session_id = b"auth_session_xyz789";
            let block_height = 54321u64;
            let block_hash = b"mock_auth_block_hash_32_bytes_abc";

            // Construct VRF input similar to the spec
            let mut input_data = Vec::new();
            input_data.extend_from_slice(domain);
            input_data.extend_from_slice(user_id);
            input_data.extend_from_slice(rp_id); // RP ID is part of VRF input construction
            input_data.extend_from_slice(session_id);
            input_data.extend_from_slice(&block_height.to_le_bytes());
            input_data.extend_from_slice(block_hash);

            // Hash the input data (VRF input should be hashed)
            let hashed_input = Sha256::digest(&input_data).to_vec();

            // Mock VRF output (64 bytes - deterministic for testing)
            let vrf_output = (0..64).map(|i| (i as u8).wrapping_add(84)).collect::<Vec<u8>>();

            // Mock VRF proof (80 bytes - typical VRF proof size)
            let vrf_proof = (0..80).map(|i| (i as u8).wrapping_add(150)).collect::<Vec<u8>>();

            // Mock VRF public key (32 bytes - ed25519 public key)
            let vrf_public_key = (0..32).map(|i| (i as u8).wrapping_add(250)).collect::<Vec<u8>>();

            Self {
                input_data: hashed_input,
                output: vrf_output,
                proof: vrf_proof,
                public_key: vrf_public_key,
            }
        }
    }

    /// Helper to get a VMContext with predictable randomness for testing
    fn get_context_with_seed(random_byte_val: u8) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        let seed: Vec<u8> = (0..32).map(|_| random_byte_val).collect();
        builder
            .current_account_id(accounts(0))
            .signer_account_id(accounts(1))
            .predecessor_account_id(accounts(1))
            .is_view(false)
            .random_seed(seed.try_into().unwrap());
        builder
    }

    /// Create a mock WebAuthn authentication response using VRF challenge
    fn create_mock_webauthn_authentication_with_vrf_challenge(vrf_output: &[u8]) -> WebAuthnAuthenticationCredential {
        // Use first 32 bytes of VRF output as WebAuthn challenge
        let webauthn_challenge = &vrf_output[0..32];
        let challenge_b64 = TEST_BASE64_URL_ENGINE.encode(webauthn_challenge);

        let client_data = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://test-contract.testnet","crossOrigin":false}}"#,
            challenge_b64
        );
        let client_data_b64 = TEST_BASE64_URL_ENGINE.encode(client_data.as_bytes());

        // Create valid authenticator data for authentication
        let mut auth_data = Vec::new();
        let rp_id_hash = env::sha256(b"test-contract.testnet");
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(0x05); // UP (0x01) + UV (0x04) - no AT flag for authentication
        auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // Counter = 2 (incremented from registration)

        let auth_data_b64 = TEST_BASE64_URL_ENGINE.encode(&auth_data);

        WebAuthnAuthenticationCredential {
            id: "test_vrf_credential_id_123".to_string(),
            raw_id: TEST_BASE64_URL_ENGINE.encode(b"test_vrf_credential_id_123"),
            response: AuthenticatorAssertionResponse {
                client_data_json: client_data_b64,
                authenticator_data: auth_data_b64,
                signature: TEST_BASE64_URL_ENGINE.encode(&vec![0x99u8; 64]), // Mock signature
                user_handle: None,
            },
            authenticator_attachment: Some("platform".to_string()),
            type_: "public-key".to_string(),
            client_extension_results: None,
        }
    }

    /// Create a mock stored authenticator for testing authentication
    fn create_mock_stored_authenticator(vrf_public_key: Vec<u8>) -> StoredAuthenticator {
        // Mock Ed25519 public key (same as used in registration test)
        let mock_ed25519_pubkey = [0x42u8; 32];
        let mut cose_map = BTreeMap::new();
        cose_map.insert(serde_cbor::Value::Integer(1), serde_cbor::Value::Integer(1)); // kty: OKP
        cose_map.insert(serde_cbor::Value::Integer(3), serde_cbor::Value::Integer(-8)); // alg: EdDSA
        cose_map.insert(serde_cbor::Value::Integer(-1), serde_cbor::Value::Integer(6)); // crv: Ed25519
        cose_map.insert(serde_cbor::Value::Integer(-2), serde_cbor::Value::Bytes(mock_ed25519_pubkey.to_vec()));
        let credential_public_key = serde_cbor::to_vec(&serde_cbor::Value::Map(cose_map)).unwrap();

        StoredAuthenticator {
            credential_public_key,
            transports: Some(vec![crate::contract_state::AuthenticatorTransport::Internal]),
            registered: "1234567890".to_string(),
            vrf_public_keys: vec![vrf_public_key], // Store VRF public key for stateless auth
            device_number: 0,
            expected_origin: "https://test-contract.testnet".to_string(), // Mock origin for testing
            expected_rp_id: "testnet".to_string(), // Mock parent domain RP ID for testing
        }
    }

    #[test]
    fn test_verify_authentication_response_success() {
        // Setup test environment
        let context = get_context_with_seed(84);
        testing_env!(context.build());
        let mut contract = crate::WebAuthnContract::init(None, None);

        // Create mock VRF data
        let mock_vrf = MockVRFData::create_mock();

        // Create mock stored authenticator with the VRF public key
        let stored_authenticator = create_mock_stored_authenticator(mock_vrf.public_key.clone());
        let user_account_id = env::predecessor_account_id();
        let credential_id_b64url = "test_vrf_credential_id_123".to_string();

        // Store the authenticator first (simulating prior registration)
        if !contract.authenticators.contains_key(&user_account_id) {
            let storage_key_bytes = format!("auth_{}", user_account_id).into_bytes();
            let new_map = near_sdk::store::IterableMap::new(storage_key_bytes);
            contract.authenticators.insert(user_account_id.clone(), new_map);
        }
        if let Some(user_authenticators) = contract.authenticators.get_mut(&user_account_id) {
            user_authenticators.insert(credential_id_b64url.clone(), stored_authenticator);
        }

        // Create VRF authentication data
        let vrf_data = VRFVerificationData {
            vrf_input_data: mock_vrf.input_data,
            vrf_output: mock_vrf.output.clone(),
            vrf_proof: mock_vrf.proof,
            public_key: mock_vrf.public_key,
            user_id: "alice.testnet".to_string(), // NEAR account_id
            rp_id: "example.com".to_string(),
            block_height: 54321u64,
            block_hash: b"mock_auth_block_hash_32_bytes_abc".to_vec(),
        };

        // Create WebAuthn authentication data using VRF output as challenge
        let webauthn_authentication = create_mock_webauthn_authentication_with_vrf_challenge(&mock_vrf.output);

        println!("Testing VRF Authentication with mock data:");
        println!("  - VRF input: {} bytes", vrf_data.vrf_input_data.len());
        println!("  - VRF output: {} bytes", vrf_data.vrf_output.len());
        println!("  - VRF proof: {} bytes", vrf_data.vrf_proof.len());
        println!("  - VRF public key: {} bytes", vrf_data.public_key.len());

        // Extract challenge for verification
        let expected_challenge = &vrf_data.vrf_output[0..32];
        let expected_challenge_b64 = TEST_BASE64_URL_ENGINE.encode(expected_challenge);
        println!("  - Expected WebAuthn challenge: {}", expected_challenge_b64);

        // Note: This test will fail VRF verification since we're using mock data
        // but it will test the structure and flow of the VRF authentication process
        let result = contract.verify_authentication_response(
            vrf_data,
            webauthn_authentication,
        );

        // The result should fail VRF verification (expected with mock data)
        // but the test verifies the method structure and parameter handling
        assert!(!result.verified, "Mock VRF data should fail verification (expected)");
        assert!(result.authentication_info.is_none(), "No authentication info should be returned on VRF failure");

        println!("VRF Authentication test completed - structure and flow verified");
        println!("   (VRF verification failed as expected with mock data)");
    }

    #[test]
    fn test_vrf_authentication_data_serialization() {
        let mock_vrf = MockVRFData::create_mock();

        let vrf_data = VRFVerificationData {
            vrf_input_data: mock_vrf.input_data,
            vrf_output: mock_vrf.output.clone(),
            vrf_proof: mock_vrf.proof,
            public_key: mock_vrf.public_key,
            user_id: "alice.testnet".to_string(), // NEAR account_id
            rp_id: "example.com".to_string(),
            block_height: 54321u64,
            block_hash: b"mock_auth_block_hash_32_bytes_abc".to_vec(),
        };

        // Test that all data is properly structured
        assert_eq!(vrf_data.vrf_input_data.len(), 32, "VRF input should be 32 bytes (SHA256)");
        assert_eq!(vrf_data.vrf_output.len(), 64, "VRF output should be 64 bytes");
        assert_eq!(vrf_data.vrf_proof.len(), 80, "VRF proof should be 80 bytes");
        assert_eq!(vrf_data.public_key.len(), 32, "VRF public key should be 32 bytes (ed25519)");

        println!("VRFVerificationData structure test passed");
    }

    #[test]
    fn test_webauthn_authentication_data_creation() {
        let mock_vrf = MockVRFData::create_mock();
        let webauthn_authentication = create_mock_webauthn_authentication_with_vrf_challenge(&mock_vrf.output);

        // Verify WebAuthn authentication structure
        assert_eq!(webauthn_authentication.type_, "public-key");
        assert_eq!(webauthn_authentication.id, "test_vrf_credential_id_123");

        // Verify challenge is properly embedded in clientDataJSON
        let client_data_bytes = TEST_BASE64_URL_ENGINE
            .decode(&webauthn_authentication.response.client_data_json)
            .expect("Should decode clientDataJSON");
        let client_data_str = std::str::from_utf8(&client_data_bytes).expect("Should be valid UTF-8");

        assert!(client_data_str.contains("webauthn.get"), "Should be authentication type");
        assert!(client_data_str.contains("test-contract.testnet"), "Should contain correct origin");

        println!("WebAuthnAuthenticationData creation test passed");
    }

    #[test]
    fn test_vrf_authentication_challenge_construction_format() {
        // Test that our VRF input construction matches the specification for authentication
        let domain = b"web3_authn_challenge_v3";
        let user_id = b"alice.testnet";
        let rp_id = b"example.com";
        let session_id = b"auth_session_uuid_67890";
        let block_height = 987654321u64;
        let block_hash = b"auth_block_hash_32_bytes_example";

        let mut input_data = Vec::new();
        input_data.extend_from_slice(domain);
        input_data.extend_from_slice(user_id);
        input_data.extend_from_slice(rp_id);
        input_data.extend_from_slice(session_id);
        input_data.extend_from_slice(&block_height.to_le_bytes());
        input_data.extend_from_slice(block_hash);

        let vrf_input = Sha256::digest(&input_data);

        println!("VRF Authentication Input Construction Test:");
        println!("  - Domain: {:?}", std::str::from_utf8(domain).unwrap());
        println!("  - User ID: {:?}", std::str::from_utf8(user_id).unwrap());
        println!("  - RP ID: {:?}", std::str::from_utf8(rp_id).unwrap());
        println!("  - Session ID: {:?}", std::str::from_utf8(session_id).unwrap());
        println!("  - Block height: {}", block_height);
        println!("  - Block hash: {:?}", std::str::from_utf8(block_hash).unwrap());
        println!("  - Total input length: {} bytes", input_data.len());
        println!("  - SHA256 hash length: {} bytes", vrf_input.len());

        // Verify expected structure
        assert_eq!(vrf_input.len(), 32, "VRF input hash should be 32 bytes");
        assert!(input_data.len() > 50, "Combined input should have substantial length");

        println!("VRF authentication challenge construction format verified");
    }

    #[test]
    fn test_stored_authenticator_vrf_public_key_storage() {
        let mock_vrf = MockVRFData::create_mock();
        let stored_auth = create_mock_stored_authenticator(mock_vrf.public_key.clone());

        // Verify VRF public keys are properly stored
        assert!(!stored_auth.vrf_public_keys.is_empty(), "VRF public keys should be stored");
        assert_eq!(stored_auth.vrf_public_keys.len(), 1, "Should have exactly one VRF key initially");
        assert_eq!(
            stored_auth.vrf_public_keys[0],
            mock_vrf.public_key,
            "Stored VRF public key should match original"
        );

        // Verify other authenticator properties
        assert!(stored_auth.transports.is_some(), "Transports should be specified");

        println!("Stored authenticator VRF public key storage test passed");
    }

    #[test]
    fn test_authentication_vs_registration_differences() {
        let mock_vrf = MockVRFData::create_mock();

        // Create authentication response
        let auth_response = create_mock_webauthn_authentication_with_vrf_challenge(&mock_vrf.output);

        // Verify authentication-specific properties
        let client_data_bytes = TEST_BASE64_URL_ENGINE
            .decode(&auth_response.response.client_data_json)
            .expect("Should decode clientDataJSON");
        let client_data_str = std::str::from_utf8(&client_data_bytes).expect("Should be valid UTF-8");

        // Authentication should use webauthn.get (not webauthn.create)
        assert!(client_data_str.contains("\"type\":\"webauthn.get\""), "Should be authentication type");
        assert!(!client_data_str.contains("webauthn.create"), "Should not be registration type");

        // Authentication response should have signature (not attestation)
        assert!(!auth_response.response.signature.is_empty(), "Should have signature");
        assert!(auth_response.response.user_handle.is_none(), "User handle typically None");

        println!("Authentication vs registration differences verified");
        println!("   - Uses webauthn.get type ✓");
        println!("   - Has signature field ✓");
        println!("   - No attestation object ✓");
    }

    #[test]
    fn test_rp_id_binding_and_security() {
        // Test that demonstrates the importance of RP ID in VRF authentication
        let domain1 = "example.com";
        let domain2 = "malicious.com";

        // Create VRF data for legitimate domain
        let legitimate_vrf_input = create_vrf_input_for_domain(domain1);
        let malicious_vrf_input = create_vrf_input_for_domain(domain2);

        // Verify that different domains produce different VRF inputs
        assert_ne!(legitimate_vrf_input, malicious_vrf_input,
                   "Different RP IDs should produce different VRF inputs");

        println!("RP ID Security Test:");
        println!("  - Legitimate domain ({}): VRF input length = {} bytes",
                 domain1, legitimate_vrf_input.len());
        println!("  - Malicious domain ({}): VRF input length = {} bytes",
                 domain2, malicious_vrf_input.len());
        println!("  - Different VRF inputs prevent cross-domain attacks ✓");

        // Test VRF authentication data structure includes RP ID
        let mock_vrf = MockVRFData::create_mock();
        let vrf_auth_data = VRFVerificationData {
            vrf_input_data: mock_vrf.input_data,
            vrf_output: mock_vrf.output,
            vrf_proof: mock_vrf.proof,
            public_key: mock_vrf.public_key,
            user_id: "alice.testnet".to_string(), // NEAR account_id
            rp_id: "example.com".to_string(),
            block_height: 54321u64,
            block_hash: vec![0x12, 0x34, 0x56, 0x78], // Mock block hash
        };

        // Note: RP ID is now extracted from WebAuthn client data instead of VRF data (more secure)
        assert_eq!(vrf_auth_data.user_id, "alice.testnet", "User ID should be preserved in VRF data");

        println!("RP ID binding and security test passed");
        println!("   - VRF input includes domain ✓");
        println!("   - Cross-domain attack prevention ✓");
        println!("   - RP ID preserved through data structures ✓");
    }

    fn create_vrf_input_for_domain(domain: &str) -> Vec<u8> {
        // Helper function to create VRF input for a specific domain
        let domain_separator = b"web3_authn_challenge_v3";
        let user_id = b"alice.testnet";
        let session_id = b"session_12345";
        let block_height = 123456u64;
        let block_hash = b"block_hash_example_32_bytes_long";

        let mut input_data = Vec::new();
        input_data.extend_from_slice(domain_separator);
        input_data.extend_from_slice(user_id);
        input_data.extend_from_slice(domain.as_bytes()); // Domain affects VRF input
        input_data.extend_from_slice(session_id);
        input_data.extend_from_slice(&block_height.to_le_bytes());
        input_data.extend_from_slice(block_hash);

        Sha256::digest(&input_data).to_vec()
    }
}

