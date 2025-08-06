use near_sdk::{env, log, near, serde_json, AccountId, Promise, NearToken, Gas, PublicKey};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE;
use base64::Engine;
use serde_cbor::Value as CborValue;

use crate::WebAuthnContract;
use crate::contract_state::WebAuthnContractExt;
use crate::types::WebAuthnRegistrationCredential;
use crate::utils::{
    parsers::{
        parse_attestation_object,
        parse_authenticator_data,
        extract_rp_id_and_origin_from_webauthn,
    },
    verifiers::verify_attestation_signature,
    validation::{
        validate_webauthn_client_data,
        validate_origin_policy,
        validate_rp_id,
        validate_webauthn_user_flags,
    },
    vrf_verifier::{
        verify_vrf_and_extract_challenge,
        VRFVerificationData
    },
};
use crate::contract_state::{
    OriginPolicy,
    UserVerificationPolicy,
    AuthenticatorOptions,
};

// WebAuthn verification structures
#[near_sdk::near(serializers = [json])]
#[derive(Debug, Clone)]
pub struct VerifyRegistrationResponse {
    pub verified: bool,
    pub registration_info: Option<RegistrationInfo>,
}

#[near_sdk::near(serializers = [json])]
#[derive(Debug, Clone)]
pub struct VerifyCanRegisterResponse {
    pub verified: bool,
    pub user_exists: bool,
}

#[near_sdk::near(serializers = [json])]
#[derive(Debug, Clone)]
pub struct RegistrationInfo {
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
}


/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

#[near]
impl WebAuthnContract {

    /// Create account and verify registration in a single transaction
    /// This function combines account creation with WebAuthn registration verification
    /// to make the registration process more robust and atomic.
    ///
    /// # Arguments
    /// * `new_account_id` - The account ID to create
    /// * `new_public_key` - The public key to add as full access key
    /// * `vrf_data` - VRF verification data
    /// * `webauthn_registration` - WebAuthn registration credential
    /// * `deterministic_vrf_public_key` - Optional deterministic VRF public key
    ///
    /// # Returns
    /// * `Promise` - Chained promise that creates account and verifies registration
    #[payable]
    pub fn create_account_and_register_user(
        &mut self,
        new_account_id: AccountId,
        new_public_key: PublicKey,
        vrf_data: VRFVerificationData,
        webauthn_registration: WebAuthnRegistrationCredential,
        deterministic_vrf_public_key: Vec<u8>,
        authenticator_options: Option<AuthenticatorOptions>,
    ) -> Promise {
        // Use the attached deposit as the initial balance for the new account
        let initial_balance_yoctonear = env::attached_deposit().as_yoctonear();
        log!("Creating account and verifying registration for: {} with balance: {}",
            new_account_id, initial_balance_yoctonear);

        // We need to chain promises to ensure the account is created before
        // registering the user with Web3Authn contract.

        // First promise: create the account + add key
        let setup_promise = Promise::new(new_account_id.clone())
            .create_account()
            .transfer(NearToken::from_yoctonear(initial_balance_yoctonear))
            .add_full_access_key(new_public_key);

        // Second promise: call the verify_and_register_user_for_account method on the current contract
        let verification_promise = Promise::new(env::current_account_id()).function_call(
            "verify_and_register_user_for_account".to_string(),
            serde_json::to_vec(&serde_json::json!({
                "account_id": new_account_id,
                "vrf_data": vrf_data,
                "webauthn_registration": webauthn_registration,
                "deterministic_vrf_public_key": deterministic_vrf_public_key,
                "authenticator_options": authenticator_options.unwrap_or(AuthenticatorOptions::default()),
                "device_number": 1, // defaults to 1 for initial registration
            })).unwrap(),
            NearToken::from_yoctonear(0), // No payment needed for verification
            Gas::from_tgas(30), // 30 TGas should be sufficient (actual usage ~23.4 TGas)
        );

        // Chain them together: both must succeed for the transaction to succeed
        setup_promise.then(verification_promise)
    }

    // Must be `#[private] pub fn` to be called as a promise
    #[private]
    pub fn verify_and_register_user_for_account(
        &mut self,
        account_id: AccountId,
        vrf_data: VRFVerificationData,
        webauthn_registration: WebAuthnRegistrationCredential,
        deterministic_vrf_public_key: Vec<u8>,
        authenticator_options: AuthenticatorOptions,
        device_number: Option<u8>,
    ) -> VerifyRegistrationResponse {

        log!("Verifying VRF proof and WebAuthn registration for account: {}", account_id);
        // 1. Validate VRF and extract WebAuthn challenge (view-only)
        let vrf_challenge_b64url = match verify_vrf_and_extract_challenge(&vrf_data, &self.vrf_settings) {
            Some(challenge) => challenge,
            None => return VerifyRegistrationResponse {
                verified: false,
                registration_info: None,
            },
        };

        // 2. Extract RP ID from WebAuthn registration data
        let (
            webauthn_rp_id,
            webauthn_origin
        ) = match extract_rp_id_and_origin_from_webauthn(&webauthn_registration) {
            Ok(data) => data,
            Err(e) => {
                log!("Failed to extract RP ID from WebAuthn data: {}", e);
                return VerifyRegistrationResponse {
                    verified: false,
                    registration_info: None,
                };
            }
        };

        // Verify that the WebAuthn RP ID matches the VRF RP ID
        if webauthn_rp_id != vrf_data.rp_id {
            log!("RP ID mismatch: WebAuthn RP ID '{}' != VRF RP ID '{}'", webauthn_rp_id, vrf_data.rp_id);
            return VerifyRegistrationResponse {
                verified: false,
                registration_info: None,
            };
        }

        let user_verification = authenticator_options
            .user_verification
            .unwrap_or(UserVerificationPolicy::Preferred);

        let expected_origin_policy = match OriginPolicy::validate(
            authenticator_options.origin_policy,
            webauthn_origin,
            webauthn_rp_id.clone(),
        ) {
            Ok(policy) => policy,
            Err(e) => {
                log!("{}", e);
                return VerifyRegistrationResponse {
                    verified: false,
                    registration_info: None,
                };
            }
        };

        // 3. Verify WebAuthn registration credential using the extracted RP ID
        let webauthn_result = self.internal_verify_registration_credential(
            webauthn_registration.clone(),
            &vrf_challenge_b64url,              // VRF challenge
            &expected_origin_policy,            // Origin policy
            &webauthn_rp_id,                    // WebAuthn RP ID
            user_verification,
        );

        // 3. If WebAuthn verification succeeded, store the authenticator and user data
        if webauthn_result.verified {
            if let Some(registration_info) = webauthn_result.registration_info {
                // Determine device number (defaults to 1 for first device, or if passed None)
                // Link Device via `link_device_register_user` passes the device number
                let device_num = device_number.unwrap_or(1);
                self.device_numbers.insert(account_id.clone(), device_num);

                // Store the authenticator and user data with dual VRF keys for the specific account
                let storage_result = self.store_authenticator_and_user_for_account(
                    account_id.clone(),
                    device_num,
                    registration_info,
                    webauthn_registration,
                    vec![
                        vrf_data.public_key,  // bootstrap VRF public key
                        deterministic_vrf_public_key
                    ],
                    expected_origin_policy,
                    webauthn_rp_id.clone(),
                );

                log!("VRF WebAuthn registration completed successfully for account: {}", account_id);
                return VerifyRegistrationResponse {
                    verified: storage_result.verified,
                    registration_info: storage_result.registration_info,
                };
            }
        }

        log!("VRF WebAuthn registration verification failed for account: {}", account_id);
        VerifyRegistrationResponse {
            verified: false,
            registration_info: None,
        }
    }

    pub fn verify_and_register_user(
        &mut self,
        vrf_data: VRFVerificationData,
        webauthn_registration: WebAuthnRegistrationCredential,
        deterministic_vrf_public_key: Vec<u8>,
        authenticator_options: Option<AuthenticatorOptions>,
    ) -> VerifyRegistrationResponse {
        let account_id = env::predecessor_account_id();
        // Delegate to the account-specific version
        self.verify_and_register_user_for_account(
            account_id,
            vrf_data,
            webauthn_registration,
            deterministic_vrf_public_key,
            authenticator_options.unwrap_or(AuthenticatorOptions::default()),
            None,
        )
    }

    // This function is only called by the Device2 account when Linking Devices
    // Previously it was used to create accounts after Testnet Faucet has created an account.
    // We now combine account creation and registration in a single transaction.
    pub fn link_device_register_user(
        &mut self,
        vrf_data: VRFVerificationData,
        webauthn_registration: WebAuthnRegistrationCredential,
        deterministic_vrf_public_key: Vec<u8>,
        authenticator_options: Option<AuthenticatorOptions>,
    ) -> VerifyRegistrationResponse {

        let account_id = env::predecessor_account_id();
        // Check if this account already has devices registered
        let device_number = self.get_device_counter(account_id.clone());
        let next_device_number = device_number + 1;
        log!("Device linking registration: account {} assigned device number {}", account_id, next_device_number);

        // Delegate to the account-specific version
        self.verify_and_register_user_for_account(
            account_id,
            vrf_data,
            webauthn_registration,
            deterministic_vrf_public_key,
            authenticator_options.unwrap_or(AuthenticatorOptions::default()),
            Some(next_device_number),
        )
    }

    /// VIEW VERSION: Check if user can register without modifying state
    /// Verifies VRF proof + WebAuthn registration but does NOT store any data
    ///
    /// # Arguments
    /// * `vrf_data` - VRF verification data containing proof, challenge, and user info
    /// * `webauthn_registration` - WebAuthn registration credential from authenticator
    ///
    /// # Returns
    /// * `VerifyCanRegisterResponse` - Contains verification status and whether user exists
    ///
    /// # Public
    /// This is a public view function that does not modify contract state
    pub fn check_can_register_user(
        &self,
        vrf_data: VRFVerificationData,
        webauthn_registration: WebAuthnRegistrationCredential,
        authenticator_options: Option<AuthenticatorOptions>,
    ) -> VerifyCanRegisterResponse {

        // 1. Check if user exists
        let user_exists = match vrf_data.user_id.parse::<AccountId>() {
            Ok(account_id) => self.registered_users.contains(&account_id),
            Err(e) => {
                log!("Account ID {} error: {}", vrf_data.user_id, e);
                return VerifyCanRegisterResponse {
                    verified: false,
                    user_exists: false,
                };
            }
        };

        // 2. Verify VRF and extract WebAuthn challenge (view-only)
        let vrf_challenge_b64url = match verify_vrf_and_extract_challenge(&vrf_data, &self.vrf_settings) {
            Some(challenge) => challenge,
            None => return VerifyCanRegisterResponse {
                verified: false,
                user_exists: user_exists,
            },
        };

        // 3. Extract RP ID from WebAuthn registration data
        let (webauthn_rp_id, webauthn_origin) = match extract_rp_id_and_origin_from_webauthn(&webauthn_registration) {
            Ok((rp_id, origin)) => (rp_id, origin),
            Err(e) => {
                log!("Failed to extract RP ID from WebAuthn data: {}", e);
                return VerifyCanRegisterResponse {
                    verified: false,
                    user_exists,
                };
            }
        };

        // Verify that the WebAuthn RP ID matches the VRF RP ID
        if webauthn_rp_id != vrf_data.rp_id {
            log!("RP ID mismatch: WebAuthn RP ID '{}' != VRF RP ID '{}'", webauthn_rp_id, vrf_data.rp_id);
            return VerifyCanRegisterResponse {
                verified: false,
                user_exists,
            };
        }

        let authenticator_options = authenticator_options
            .unwrap_or(AuthenticatorOptions::default());

        let expected_origin_policy = match OriginPolicy::validate(
            authenticator_options.origin_policy,
            webauthn_origin,
            webauthn_rp_id.clone(),
        ) {
            Ok(policy) => policy,
            Err(e) => {
                log!("{}", e);
                return VerifyCanRegisterResponse {
                    verified: false,
                    user_exists,
                };
            }
        };

        // 4. WebAuthn registration verification using the extracted RP ID
        let webauthn_response = self.internal_verify_registration_credential(
            webauthn_registration,
            &vrf_challenge_b64url,                  // Use the VRF challenge from VRF data
            &expected_origin_policy,                // origin policy
            &webauthn_rp_id,                        // WebAuthn RP ID
            UserVerificationPolicy::default(), // user verification requirement
        );

        if webauthn_response.verified {
            log!("WebAuthn registration verification: SUCCESS");
        } else {
            log!("WebAuthn registration verification: FAILED");
        }

        VerifyCanRegisterResponse {
            verified: webauthn_response.verified,
            user_exists,
        }
    }

    /// Core WebAuthn attestation verification logic that validates the registration response
    ///
    /// # Arguments
    /// * `credential` - The WebAuthn registration credential containing client data and attestation
    /// * `expected_challenge` - Base64URL-encoded VRF-generated challenge that should match client data
    /// * `origin_policy` - The origin policy for validation
    /// * `user_verification` - Whether to require user verification flag in attestation
    ///
    /// # Returns
    /// * `VerifyRegistrationResponse` - Contains verification status and registration info
    fn internal_verify_registration_credential(
        &self,
        credential: WebAuthnRegistrationCredential,
        expected_challenge: &str,
        expected_origin_policy: &OriginPolicy,
        expected_rp_id: &str,
        user_verification: UserVerificationPolicy,
    ) -> VerifyRegistrationResponse {

        log!("Contract verification of registration response");
        log!("Expected challenge: {}", expected_challenge);
        log!("Origin policy: {:?}", expected_origin_policy);

        // Steps:
        // 1. Parse and validate clientDataJSON
        // 2. Verify challenge matches expected_challenge
        // 3. Verify origin matches expected_origin
        // 4. Parse and validate attestationObject
        // 5. Verify attestation signature using existing helper methods
        // 6. Extract credential public key
        // 7. Store authenticator

        // Step 1-3: Parse and validate clientDataJSON, type, and challenge
        let (client_data, client_data_json_bytes) = match validate_webauthn_client_data(
            &credential.response.client_data_json,
            &expected_challenge,
            "webauthn.create"
        ) {
            Ok(data) => data,
            Err(e) => {
                log!("{}", e);
                return VerifyRegistrationResponse {
                    verified: false,
                    registration_info: None,
                };
            }
        };

        // Step 3: Verify origin against policy
        if let Err(e) = validate_origin_policy(
            &client_data.origin,
            &expected_origin_policy,
            &expected_rp_id
        ) {
            log!("{}", e);
            return VerifyRegistrationResponse {
                verified: false,
                registration_info: None,
            };
        }

        log!("Origin verification passed for: {}", client_data.origin);

        // Step 4: Parse and validate attestationObject
        let attestation_object_bytes =
            match BASE64_URL_ENGINE.decode(&credential.response.attestation_object) {
                Ok(bytes) => bytes,
                Err(_) => {
                    log!("Failed to decode attestationObject from base64url");
                    return VerifyRegistrationResponse {
                        verified: false,
                        registration_info: None,
                    };
                }
            };

        let attestation_object: CborValue = match serde_cbor::from_slice(&attestation_object_bytes)
        {
            Ok(obj) => obj,
            Err(e) => {
                log!("Failed to parse attestationObject CBOR: {}", e);
                return VerifyRegistrationResponse {
                    verified: false,
                    registration_info: None,
                };
            }
        };

        // Extract components from attestationObject
        let (auth_data_bytes, att_stmt, fmt) =
            match parse_attestation_object(&attestation_object) {
                Ok(data) => data,
                Err(e) => {
                    log!("Failed to parse attestation object: {}", e);
                    return VerifyRegistrationResponse {
                        verified: false,
                        registration_info: None,
                    };
                }
            };

        // Step 5-7: Parse and validate authenticator data (RpID and user presence flags)
        let auth_data = match parse_authenticator_data(&auth_data_bytes) {
            Ok(data) => data,
            Err(e) => {
                log!("Failed to parse authenticator data: {}", e);
                return VerifyRegistrationResponse {
                    verified: false,
                    registration_info: None,
                };
            }
        };

        // Validate RP ID hash
        if let Err(e) = validate_rp_id(&auth_data.rp_id_hash, &expected_rp_id, true) {
            log!("{}", e);
            return VerifyRegistrationResponse {
                verified: false,
                registration_info: None,
            };
        }

        // Validate user verification and presence flags
        let user_verified = match validate_webauthn_user_flags(auth_data.flags, &user_verification) {
            Ok(verified) => verified,
            Err(e) => {
                log!("{}", e);
                return VerifyRegistrationResponse {
                    verified: false,
                    registration_info: None,
                };
            }
        };

        // Verify attested credential data present (AT flag must be set)
        if (auth_data.flags & 0x40) == 0 {
            log!("Attested credential data flag not set");
            return VerifyRegistrationResponse {
                verified: false,
                registration_info: None,
            };
        }

        let attested_cred_data = match auth_data.attested_credential_data {
            Some(data) => data,
            None => {
                log!("No attested credential data found");
                return VerifyRegistrationResponse {
                    verified: false,
                    registration_info: None,
                };
            }
        };

        // Step 5: Verify attestation signature
        let client_data_hash = env::sha256(&client_data_json_bytes);
        match verify_attestation_signature(
            &att_stmt,
            &auth_data_bytes,
            &client_data_hash,
            &attested_cred_data.credential_public_key,
            &fmt,
        ) {
            Ok(true) => log!("Attestation signature verified successfully"),
            Ok(false) => {
                log!("Attestation signature verification failed");
                return VerifyRegistrationResponse {
                    verified: false,
                    registration_info: None,
                };
            }
            Err(e) => {
                log!("Error verifying attestation signature: {}", e);
                return VerifyRegistrationResponse {
                    verified: false,
                    registration_info: None,
                };
            }
        }

        VerifyRegistrationResponse {
            verified: true,
            registration_info: Some(RegistrationInfo {
                credential_id: attested_cred_data.credential_id,
                credential_public_key: attested_cred_data.credential_public_key,
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
    use near_sdk::serde_json::json;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as TEST_BASE64_URL_ENGINE};
    use std::collections::BTreeMap;
    use sha2::{Sha256, Digest};
    use crate::types::AuthenticatorAttestationResponse;

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
            let rp_id = b"test-contract.testnet";
            let session_id = b"session_abc123";
            let block_height = 12345u64;
            let block_hash = b"mock_block_hash_32_bytes_long_abc";

            // Construct VRF input similar to the spec
            let mut input_data = Vec::new();
            input_data.extend_from_slice(domain);
            input_data.extend_from_slice(user_id);
            input_data.extend_from_slice(rp_id);
            input_data.extend_from_slice(session_id);
            input_data.extend_from_slice(&block_height.to_le_bytes());
            input_data.extend_from_slice(block_hash);

            // Hash the input data (VRF input should be hashed)
            let hashed_input = Sha256::digest(&input_data).to_vec();

            // Mock VRF output (64 bytes - deterministic for testing)
            let vrf_output = (0..64).map(|i| (i as u8).wrapping_add(42)).collect::<Vec<u8>>();

            // Mock VRF proof (80 bytes - typical VRF proof size)
            let vrf_proof = (0..80).map(|i| (i as u8).wrapping_add(100)).collect::<Vec<u8>>();

            // Mock VRF public key (32 bytes - ed25519 public key)
            let vrf_public_key = (0..32).map(|i| (i as u8).wrapping_add(200)).collect::<Vec<u8>>();

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

    /// Create a mock WebAuthn registration response using VRF challenge
    fn create_mock_webauthn_registration_with_vrf_challenge(vrf_output: &[u8]) -> WebAuthnRegistrationCredential {
        // Use first 32 bytes of VRF output as WebAuthn challenge
        let webauthn_challenge = &vrf_output[0..32];
        let challenge_b64 = TEST_BASE64_URL_ENGINE.encode(webauthn_challenge);

        let client_data = format!(
            r#"{{"type":"webauthn.create","challenge":"{}","origin":"https://test-contract.testnet","crossOrigin":false}}"#,
            challenge_b64
        );
        let client_data_b64 = TEST_BASE64_URL_ENGINE.encode(client_data.as_bytes());

        // Create valid attestation object for "none" format
        let mut attestation_map = BTreeMap::new();
        attestation_map.insert(
            serde_cbor::Value::Text("fmt".to_string()),
            serde_cbor::Value::Text("none".to_string()),
        );

        // Create valid authenticator data
        let mut auth_data = Vec::new();
        let rp_id_hash = env::sha256(b"test-contract.testnet");
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(0x45); // UP (0x01) + UV (0x04) + AT (0x40)
        auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Counter = 1

        // AAGUID (16 bytes)
        auth_data.extend_from_slice(&[0x00u8; 16]);

        // Credential ID
        let cred_id = b"test_vrf_credential_id_123";
        auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(cred_id);

        // Create valid COSE Ed25519 public key
        let mock_ed25519_pubkey = [0x42u8; 32];
        let mut cose_map = BTreeMap::new();
        cose_map.insert(serde_cbor::Value::Integer(1), serde_cbor::Value::Integer(1)); // kty: OKP
        cose_map.insert(serde_cbor::Value::Integer(3), serde_cbor::Value::Integer(-8)); // alg: EdDSA
        cose_map.insert(serde_cbor::Value::Integer(-1), serde_cbor::Value::Integer(6)); // crv: Ed25519
        cose_map.insert(serde_cbor::Value::Integer(-2), serde_cbor::Value::Bytes(mock_ed25519_pubkey.to_vec()));
        let cose_key = serde_cbor::to_vec(&serde_cbor::Value::Map(cose_map)).unwrap();
        auth_data.extend_from_slice(&cose_key);

        attestation_map.insert(
            serde_cbor::Value::Text("authData".to_string()),
            serde_cbor::Value::Bytes(auth_data),
        );
        attestation_map.insert(
            serde_cbor::Value::Text("attStmt".to_string()),
            serde_cbor::Value::Map(BTreeMap::new()),
        );

        let attestation_object_bytes = serde_cbor::to_vec(&serde_cbor::Value::Map(attestation_map)).unwrap();
        let attestation_object_b64 = TEST_BASE64_URL_ENGINE.encode(&attestation_object_bytes);

        WebAuthnRegistrationCredential {
            id: "test_vrf_credential_id_123".to_string(),
            raw_id: TEST_BASE64_URL_ENGINE.encode(b"test_vrf_credential_id_123"),
            response: AuthenticatorAttestationResponse {
                client_data_json: client_data_b64,
                attestation_object: attestation_object_b64,
                transports: Some(vec!["internal".to_string()]),
            },
            authenticator_attachment: Some("platform".to_string()),
            type_: "public-key".to_string(),
            client_extension_results: None,
        }
    }

    #[test]
    fn test_verify_registration_response_success() {
        // Setup test environment
        let context = get_context_with_seed(42);
        testing_env!(context.build());
        let mut contract = crate::WebAuthnContract::init();

        // Create mock VRF data
        let mock_vrf = MockVRFData::create_mock();
        // use mock as determistic vrf public key just for testing
        let deterministic_vrf_public_key = mock_vrf.public_key.clone();

        // Create VRF verification data struct
        let vrf_data = VRFVerificationData {
            vrf_input_data: mock_vrf.input_data,
            vrf_output: mock_vrf.output.clone(),
            vrf_proof: mock_vrf.proof,
            public_key: mock_vrf.public_key,
            user_id: "test_user_123".to_string(),
            rp_id: "example.com".to_string(),
            block_height: 1234567890u64,
            block_hash: b"mock_block_hash_32_bytes_long_abc".to_vec(),
        };

        // Create WebAuthn registration data using VRF output as challenge
        let webauthn_registration= create_mock_webauthn_registration_with_vrf_challenge(&mock_vrf.output);

        println!("Testing VRF Registration with mock data:");
        println!("  - VRF input: {} bytes", vrf_data.vrf_input_data.len());
        println!("  - VRF output: {} bytes", vrf_data.vrf_output.len());
        println!("  - VRF proof: {} bytes", vrf_data.vrf_proof.len());
        println!("  - VRF public key: {} bytes", vrf_data.public_key.len());

        // Extract challenge for verification
        let expected_challenge = &vrf_data.vrf_output[0..32];
        let expected_challenge_b64 = TEST_BASE64_URL_ENGINE.encode(expected_challenge);
        println!("  - Expected WebAuthn challenge: {}", expected_challenge_b64);

        // Note: This test will fail VRF verification since we're using mock data
        // but it will test the structure and flow of the VRF registration process
        let result = contract.link_device_register_user(
            vrf_data,
            webauthn_registration,
            deterministic_vrf_public_key,
            Some(AuthenticatorOptions {
                user_verification: Some(UserVerificationPolicy::Required),
                origin_policy: Some(crate::contract_state::OriginPolicyInput::AllSubdomains),
            }),
        );

        // The result should fail VRF verification (expected with mock data)
        // but the test verifies the method structure and parameter handling
        assert!(!result.verified, "Mock VRF data should fail verification (expected)");
        assert!(result.registration_info.is_none(), "No registration info should be returned on VRF failure");

        println!("VRF Registration test completed - structure and flow verified");
        println!("   (VRF verification failed as expected with mock data)");
    }

    #[test]
    fn test_vrf_verification_data_serialization() {
        let mock_vrf = MockVRFData::create_mock();

        let vrf_data = VRFVerificationData {
            vrf_input_data: mock_vrf.input_data,
            vrf_output: mock_vrf.output,
            vrf_proof: mock_vrf.proof,
            public_key: mock_vrf.public_key,
            user_id: "test_user_123".to_string(),
            rp_id: "example.com".to_string(),
            block_height: 1234567890u64,
            block_hash: b"mock_block_hash_32_bytes_long_abc".to_vec(),
        };

        // Test JSON serialization
        let json_str = serde_json::to_string(&vrf_data).expect("Should serialize to JSON");
        let deserialized: VRFVerificationData = serde_json::from_str(&json_str).expect("Should deserialize from JSON");

        assert_eq!(vrf_data.vrf_input_data, deserialized.vrf_input_data);
        assert_eq!(vrf_data.vrf_output, deserialized.vrf_output);
        assert_eq!(vrf_data.vrf_proof, deserialized.vrf_proof);
        assert_eq!(vrf_data.public_key, deserialized.public_key);
        assert_eq!(vrf_data.user_id, deserialized.user_id);
        assert_eq!(vrf_data.rp_id, deserialized.rp_id);
        assert_eq!(vrf_data.block_height, deserialized.block_height);
        assert_eq!(vrf_data.block_hash, deserialized.block_hash);

        println!("VRFVerificationData serialization test passed");
    }

    #[test]
    fn test_webauthn_registration_serialization() {
        let mock_vrf = MockVRFData::create_mock();
        let webauthn_registration = create_mock_webauthn_registration_with_vrf_challenge(&mock_vrf.output);

        let json_str = serde_json::to_string(&webauthn_registration).expect("Should serialize to JSON");
        let deserialized: WebAuthnRegistrationCredential = serde_json::from_str(&json_str).expect("Should deserialize from JSON");

        assert_eq!(webauthn_registration.id, deserialized.id);
        assert_eq!(webauthn_registration.type_, deserialized.type_);

        println!("RegistrationCredential serialization test passed");
    }

    #[test]
    fn test_vrf_challenge_construction_format() {
        // Test that our VRF input construction matches the specification
        let domain = b"web3_authn_challenge_v3";
        let user_id = b"alice.testnet";
        let rp_id = b"example.com";
        let session_id = b"session_uuid_12345";
        let block_height = 123456789u64;
        let block_hash = b"block_hash_32_bytes_long_example";

        let mut input_data = Vec::new();
        input_data.extend_from_slice(domain);
        input_data.extend_from_slice(user_id);
        input_data.extend_from_slice(rp_id);
        input_data.extend_from_slice(session_id);
        input_data.extend_from_slice(&block_height.to_le_bytes());
        input_data.extend_from_slice(block_hash);

        let vrf_input = Sha256::digest(&input_data);

        println!("VRF Input Construction Test:");
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

        println!("VRF challenge construction format verified");
    }

    #[test]
    fn test_create_account_and_register_user() {
        let context = get_context_with_seed(42);
        testing_env!(context.build());
        let mut contract = crate::WebAuthnContract::init();

        let new_account_id: AccountId = "new_account.testnet".parse().unwrap();
        let new_public_key: PublicKey = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".parse().unwrap();
        let _user_id = "test_user_123".to_string();
        let _args = json!({
            "some_key": "some_value"
        });

        let mock_vrf = MockVRFData::create_mock();
        let webauthn_registration = create_mock_webauthn_registration_with_vrf_challenge(&mock_vrf.output);
        let vrf_data = VRFVerificationData {
            vrf_input_data: mock_vrf.input_data,
            vrf_output: mock_vrf.output,
            vrf_proof: mock_vrf.proof,
            public_key: mock_vrf.public_key,
            user_id: "test_user_123".to_string(),
            rp_id: "example.com".to_string(),
            block_height: 1234567890u64,
            block_hash: b"mock_block_hash_32_bytes_long_abc".to_vec(),
        };

        let _promise = contract.create_account_and_register_user(
            new_account_id,
            new_public_key,
            vrf_data,
            webauthn_registration,
            vec![1u8; 32], // Mock deterministic VRF public key
            Some(AuthenticatorOptions {
                user_verification: Some(UserVerificationPolicy::Required),
                origin_policy: Some(crate::contract_state::OriginPolicyInput::AllSubdomains),
            }),
        );

        // In test environment, promises are not actually executed
        // This test verifies the function compiles and creates the promise structure
        println!("create_account_and_register_user function executed successfully");
    }

}
