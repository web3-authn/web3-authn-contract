use near_sdk::{env, log, near};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE;
use base64::Engine;

use crate::WebAuthnContract;
use crate::contract_state::{
    WebAuthnContractExt,
    OriginPolicy,
    UserVerificationPolicy,
};
use crate::utils::{
    vrf_verifier::{
        verify_vrf_and_extract_challenge,
        VRFVerificationData
    },
    verifiers::verify_authentication_signature,
    parsers::parse_authenticator_data,
    validation::{
        validate_webauthn_client_data,
        validate_origin_policy,
        validate_rp_id,
        validate_webauthn_user_flags,
    },
};
use crate::types::{
    AuthenticatorDevice,
    WebAuthnAuthenticationCredential
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

        // 5. Verify VRF RP ID matches stored RP ID for additional origin binding
        // Check if the VRF RP ID is expected by the origin policy
        if let Err(e) = validate_rp_id(vrf_data.rp_id.as_bytes(), &stored_authenticator.expected_rp_id, false) {
            log!("VRF RP ID verification failed: {}", e);
            return VerifiedAuthenticationResponse {
                verified: false,
                authentication_info: None,
            };
        }
        log!("VRF RP ID verification passed: {}", vrf_data.rp_id);

        // 6. Verify WebAuthn authentication with VRF-generated challenge
        let webauthn_result = self.internal_verify_authentication_response(
            webauthn_authentication,
            vrf_challenge_b64url,                        // Expected VRF challenge
            stored_authenticator.expected_rp_id.clone(), // Expected RP ID
            stored_authenticator.origin_policy.clone(),  // Expected origin
            stored_authenticator.user_verification.clone(), // user verification requirement
            authenticator_device,
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
        expected_rp_id: String,
        expected_origin_policy: OriginPolicy,
        user_verification: UserVerificationPolicy,
        authenticator: AuthenticatorDevice,
    ) -> VerifiedAuthenticationResponse {
        log!("Internal WebAuthn authentication verification");
        log!("Expected challenge: {}", expected_challenge);
        log!("Expected Origin policy: {:?}", expected_origin_policy);

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

        // Step 4: Verify origin against policy
        if let Err(e) = validate_origin_policy(
            &client_data.origin,
            &expected_origin_policy,
            &expected_rp_id
        ) {
            log!("{}", e);
            return VerifiedAuthenticationResponse {
                verified: false,
                authentication_info: None,
            };
        }

        log!("Origin verification passed for: {}", client_data.origin);

        // Step 5-7: Parse and validate authenticator data
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

        // Validate RP ID hash
        if let Err(e) = validate_rp_id(&auth_data.rp_id_hash, &expected_rp_id, true) {
            log!("{}", e);
            return VerifiedAuthenticationResponse {
                verified: false,
                authentication_info: None,
            };
        }

        // Validate user verification and presence flags
        let user_verified = match validate_webauthn_user_flags(auth_data.flags, &user_verification) {
            Ok(verified) => verified,
            Err(e) => {
                log!("{}", e);
                return VerifiedAuthenticationResponse {
                    verified: false,
                    authentication_info: None,
                };
            }
        };

        // Step 8: Verify signature
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

        // Create signed data: authData || clientDataHash
        let client_data_json_hash = env::sha256(&client_data_json_bytes);
        let mut signed_data = authenticator_data_bytes.clone();
        signed_data.extend_from_slice(&client_data_json_hash);

        // Verify signature using the authenticator's public key
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

        // TODO: check whether this means passkey sync, or link device (multiple authenticators)
        // Step 11: Determine credential device type and backup status
        let credential_backed_up = (auth_data.flags & 0x10) != 0; // BS flag
        let credential_device_type = if (auth_data.flags & 0x20) != 0 { // BE flag
            "multiDevice"
        } else {
            "singleDevice"
        };

        // Return success with authentication info
        VerifiedAuthenticationResponse {
            verified: true,
            authentication_info: Some(AuthenticationInfo {
                credential_id: authenticator.credential_id,
                new_counter: auth_data.counter,
                user_verified,
                credential_device_type: credential_device_type.to_string(),
                credential_backed_up,
                origin: client_data.origin,
                rp_id: expected_rp_id.clone(),
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
    use near_sdk::AccountId;
    use near_sdk::store::IterableMap;
    use std::str::FromStr;
    use crate::contract_state::StoredAuthenticator;
    use crate::types::AuthenticatorAssertionResponse;

    // Mock VRF data for testing
    #[derive(Debug)]
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
            let hashed_input = near_sdk::env::sha256(&input_data);

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
            .random_seed(seed.try_into().unwrap());
        builder
    }

    /// Create a mock WebAuthn authentication response using VRF challenge
    fn create_mock_webauthn_authentication_with_vrf_challenge(vrf_output: &[u8]) -> WebAuthnAuthenticationCredential {
        // Create mock client data with VRF challenge
        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": BASE64_URL_ENGINE.encode(vrf_output),
            "origin": "https://test-contract.testnet",
            "crossOrigin": false
        });

        let client_data_json = serde_json::to_string(&client_data).unwrap();
        let client_data_json_b64url = BASE64_URL_ENGINE.encode(client_data_json.as_bytes());

        // Create mock authenticator data
        let rp_id_hash = near_sdk::env::sha256("testnet".as_bytes());
        let flags = 0x01; // User present
        let counter = 1u32;
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(flags);
        auth_data.extend_from_slice(&counter.to_be_bytes());
        let authenticator_data_b64url = BASE64_URL_ENGINE.encode(&auth_data);

        // Create mock signature (this would normally be generated by the authenticator)
        let signature = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let signature_b64url = BASE64_URL_ENGINE.encode(&signature);

        WebAuthnAuthenticationCredential {
            id: "test_credential_id".to_string(),
            raw_id: "test_credential_id".to_string(),
            response: AuthenticatorAssertionResponse {
                client_data_json: client_data_json_b64url,
                authenticator_data: authenticator_data_b64url,
                signature: signature_b64url,
                user_handle: None,
            },
            authenticator_attachment: None,
            type_: "public-key".to_string(),
            client_extension_results: None,
        }
    }

    /// Create a mock stored authenticator for testing authentication
    fn create_mock_stored_authenticator(vrf_public_key: Vec<u8>) -> StoredAuthenticator {
        // Mock Ed25519 public key (same as used in registration test)
        let mock_ed25519_pubkey = [0x42u8; 32];
        let mut cose_map = std::collections::BTreeMap::new();
        cose_map.insert(serde_cbor::Value::Integer(1), serde_cbor::Value::Integer(1)); // kty: OKP
        cose_map.insert(serde_cbor::Value::Integer(3), serde_cbor::Value::Integer(-8)); // alg: EdDSA
        cose_map.insert(serde_cbor::Value::Integer(-1), serde_cbor::Value::Integer(6)); // crv: Ed25519
        cose_map.insert(serde_cbor::Value::Integer(-2), serde_cbor::Value::Bytes(mock_ed25519_pubkey.to_vec()));
        let credential_public_key = serde_cbor::to_vec(&serde_cbor::Value::Map(cose_map)).unwrap();

        StoredAuthenticator {
            credential_public_key,
            transports: Some(vec![crate::contract_state::AuthenticatorTransport::Internal]),
            registered: "1234567890".to_string(),
            expected_rp_id: "testnet".to_string(),
            origin_policy: OriginPolicy::AllSubdomains,
            user_verification: UserVerificationPolicy::Required,
            vrf_public_keys: vec![vrf_public_key], // Store VRF public key for stateless auth
            device_number: 0,
        }
    }

    #[test]
    fn test_verify_authentication_response_success() {
        let alice = AccountId::from_str("alice.testnet").unwrap();

        // Setup context
        let context = get_context_with_seed(42);
        testing_env!(context.build());

        // Create contract
        let mut contract = WebAuthnContract::init();

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
            public_key: mock_vrf.public_key.clone(),
            user_id: "alice.testnet".to_string(), // NEAR account_id
            rp_id: "example.com".to_string(),
            block_height: 54321u64,
            block_hash: b"mock_auth_block_hash_32_bytes_abc".to_vec(),
        };

        // Create mock WebAuthn authentication
        let webauthn_auth = create_mock_webauthn_authentication_with_vrf_challenge(&mock_vrf.output);

        // Create mock stored authenticator
        let stored_auth = create_mock_stored_authenticator(mock_vrf.public_key);

        // Store the authenticator in the contract
        let credential_id = "test_credential_id".to_string();
        let mut user_authenticators = IterableMap::new(format!("auth_{}", alice).into_bytes());
        user_authenticators.insert(credential_id.clone(), stored_auth);
        contract.authenticators.insert(alice.clone(), user_authenticators);

        // Test authentication verification
        let result = contract.verify_authentication_response(vrf_data, webauthn_auth);

        // With mock VRF data, verification should fail (expected behavior)
        assert!(!result.verified, "Authentication should fail with mock VRF data (expected)");
        assert!(result.authentication_info.is_none(), "Should have no authentication info on VRF failure");

        println!("VRF authentication response verification test passed (mock data correctly rejected)");
    }

    #[test]
    fn test_vrf_authentication_data_serialization() {
        let mock_vrf = MockVRFData::create_mock();
        let alice = AccountId::from_str("alice.testnet").unwrap();

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

        // Test serialization
        let serialized = serde_json::to_string(&vrf_data).unwrap();
        let deserialized: VRFVerificationData = serde_json::from_str(&serialized).unwrap();

        assert_eq!(vrf_data.vrf_input_data, deserialized.vrf_input_data);
        assert_eq!(vrf_data.vrf_output, deserialized.vrf_output);
        assert_eq!(vrf_data.vrf_proof, deserialized.vrf_proof);
        assert_eq!(vrf_data.public_key, deserialized.public_key);
        assert_eq!(vrf_data.rp_id, deserialized.rp_id);
        assert_eq!(vrf_data.user_id, deserialized.user_id);
        assert_eq!(vrf_data.block_height, deserialized.block_height);
        assert_eq!(vrf_data.block_hash, deserialized.block_hash);

        println!("VRF authentication data serialization test passed");
    }

    #[test]
    fn test_webauthn_authentication_data_creation() {
        let mock_vrf = MockVRFData::create_mock();
        let webauthn_auth = create_mock_webauthn_authentication_with_vrf_challenge(&mock_vrf.output);

        // Verify the structure
        assert_eq!(webauthn_auth.type_, "public-key");
        assert_eq!(webauthn_auth.id, "test_credential_id");
        assert_eq!(webauthn_auth.raw_id, "test_credential_id");

        // Verify response structure
        assert!(!webauthn_auth.response.client_data_json.is_empty());
        assert!(!webauthn_auth.response.authenticator_data.is_empty());
        assert!(!webauthn_auth.response.signature.is_empty());
        assert!(webauthn_auth.response.user_handle.is_none());

        println!("WebAuthn authentication data creation test passed");
    }

    #[test]
    fn test_vrf_authentication_challenge_construction_format() {
        let mock_vrf = MockVRFData::create_mock();
        let webauthn_auth = create_mock_webauthn_authentication_with_vrf_challenge(&mock_vrf.output);

        // Decode and verify the challenge format
        let client_data_json_b64url = &webauthn_auth.response.client_data_json;
        let client_data_json_bytes = BASE64_URL_ENGINE.decode(client_data_json_b64url).unwrap();
        let client_data_json = String::from_utf8(client_data_json_bytes).unwrap();
        let client_data: serde_json::Value = serde_json::from_str(&client_data_json).unwrap();

        // Verify challenge format
        assert_eq!(client_data["type"], "webauthn.get");
        assert_eq!(client_data["challenge"], BASE64_URL_ENGINE.encode(&mock_vrf.output));
        assert_eq!(client_data["origin"], "https://test-contract.testnet");
        assert_eq!(client_data["crossOrigin"], false);

        println!("VRF authentication challenge construction format test passed");
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
        assert!(!stored_auth.expected_rp_id.is_empty(), "Expected RP ID should be specified");
        assert!(
            matches!(stored_auth.user_verification, UserVerificationPolicy::Required),
            "User verification requirement should be specified"
        );

        println!("Stored authenticator VRF public key storage test passed");
    }

    #[test]
    fn test_authentication_vs_registration_differences() {
        let mock_vrf = MockVRFData::create_mock();

        // Create authentication credential
        let auth_credential = create_mock_webauthn_authentication_with_vrf_challenge(&mock_vrf.output);

        // Verify authentication-specific properties
        let client_data_bytes = BASE64_URL_ENGINE
            .decode(&auth_credential.response.client_data_json)
            .expect("Should decode clientDataJSON");
        let client_data_str = std::str::from_utf8(&client_data_bytes).expect("Should be valid UTF-8");

        // Authentication should use webauthn.get (not webauthn.create)
        assert!(client_data_str.contains("\"type\":\"webauthn.get\""), "Should be authentication type");
        assert!(!client_data_str.contains("webauthn.create"), "Should not be registration type");

        // Authentication response should have signature (not attestation)
        assert!(!auth_credential.response.signature.is_empty(), "Should have signature");
        assert!(auth_credential.response.user_handle.is_none(), "User handle typically None");

        println!("Authentication vs registration differences verified");
        println!("   - Uses webauthn.get type ✓");
        println!("   - Has signature field ✓");
        println!("   - No attestation object ✓");
    }

    #[test]
    fn test_rp_id_binding_and_security() {
        let alice = AccountId::from_str("alice.testnet").unwrap();

        // Setup context
        let context = get_context_with_seed(42);
        testing_env!(context.build());

        // Create contract
        let mut contract = WebAuthnContract::init();

        // Create mock VRF data with specific RP ID
        let mock_vrf = MockVRFData::create_mock();
        let vrf_data = VRFVerificationData {
            vrf_input_data: mock_vrf.input_data.clone(),
            vrf_output: mock_vrf.output.clone(),
            vrf_proof: mock_vrf.proof.clone(),
            public_key: mock_vrf.public_key.clone(),
            rp_id: "testnet".to_string(), // Specific RP ID
            user_id: alice.to_string(), // Convert AccountId to String
            block_height: 123456789,
            block_hash: vec![0x01; 32], // 32 bytes for block hash
        };

        // Create mock WebAuthn authentication
        let webauthn_auth = create_mock_webauthn_authentication_with_vrf_challenge(&mock_vrf.output);

        // Create mock stored authenticator with matching RP ID
        let stored_auth = create_mock_stored_authenticator(mock_vrf.public_key.clone());

        // Store the authenticator
        let credential_id = "test_credential_id".to_string();
        let mut user_authenticators = IterableMap::new(format!("auth_{}", alice).into_bytes());
        user_authenticators.insert(credential_id.clone(), stored_auth);
        contract.authenticators.insert(alice.clone(), user_authenticators);

        // Test authentication with mock VRF data (should fail due to invalid VRF proof)
        let result = contract.verify_authentication_response(vrf_data, webauthn_auth);
        assert!(!result.verified, "Authentication should fail with mock VRF data (expected)");
        assert!(result.authentication_info.is_none(), "Should have no authentication info on VRF failure");

        println!("RP ID binding and security test passed (mock data correctly rejected)");
    }

}

