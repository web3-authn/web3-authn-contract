use super::{WebAuthnContract, WebAuthnContractExt};
use near_sdk::{log, near, require, env, AccountId, PublicKey};
use near_sdk::store::IterableMap;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE;
use base64::Engine;

use crate::contract_state::{
    AuthenticatorTransport,
    StoredAuthenticator,
    UserVerificationPolicy,
    OriginPolicy,
};
use crate::verify_registration_response::{
    RegistrationInfo,
    VerifyRegistrationResponse,
};
use crate::types::WebAuthnRegistrationCredential;
use crate::utils::parsers::{
    decode_client_data_json,
};

/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

#[near]
impl WebAuthnContract {

    /////////////////////////////////////
    /// AUTHENTICATORS
    /////////////////////////////////////

    /// Get all authenticators for a specific user
    /// @view
    pub fn get_authenticators_by_user(&self, user_id: AccountId) -> Vec<(String, StoredAuthenticator)> {
        let mut result = Vec::new();
        if let Some(user_authenticators) = self.authenticators.get(&user_id) {
            for (credential_id, authenticator) in user_authenticators.iter() {
                result.push((credential_id.clone(), authenticator.clone()));
            }
        }
        result
    }

    /// Get a specific authenticator by user and credential ID
    /// @view
    pub fn get_authenticator(&self, user_id: AccountId, credential_id: String) -> Option<StoredAuthenticator> {
        // First get user's map, then get specific authenticator
        self.authenticators.get(&user_id)
            .and_then(|user_authenticators| user_authenticators.get(&credential_id))
            .cloned()
    }

    /// Get all credential IDs associated with an account ID
    /// This enables reverse lookup for account recovery (account -> credential IDs)
    pub fn get_credential_ids_by_account(&self, account_id: AccountId) -> Vec<String> {
        if let Some(user_authenticators) = self.authenticators.get(&account_id) {
            user_authenticators.keys().cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Stores the authenticator and user data after successful registration verification for a specific account
    ///
    /// # Arguments
    /// * `account_id` - The account ID to store the authenticator for
    /// * `registration_info` - Contains the verified credential ID, public key and optional VRF public key
    /// * `credential` - The original registration credential containing transport info and attestation data
    /// * `bootstrap_vrf_public_key` - Bootstrap VRF public key (WebAuthn-bound)
    /// * `deterministic_vrf_public_key` - Optional deterministic VRF public key for account recovery
    ///
    /// # Returns
    /// * `VerifyRegistrationResponse` - Contains verification status and registration info
    ///
    /// # Params
    /// * `self` - Mutable reference to contract state
    /// * `account_id` - The account ID to store the authenticator for
    /// * `registration_info` - RegistrationInfo struct containing credential data
    /// * `credential` - RegistrationCredential struct with transport and attestation data
    /// * `bootstrap_vrf_public_key` - Vec<u8> containing bootstrap VRF public key
    /// * `deterministic_vrf_public_key` - Optional Vec<u8> containing deterministic VRF public key
    /// * for key recovery purposes
    pub(crate) fn store_authenticator_and_user_for_account(
        &mut self,
        account_id: AccountId,
        device_number: u8,
        registration_info: RegistrationInfo,
        credential: WebAuthnRegistrationCredential,
        vrf_public_keys: Vec<Vec<u8>>,
        origin_policy: OriginPolicy,
        expected_rp_id: String,
        near_public_key: Option<PublicKey>,
    ) -> VerifyRegistrationResponse {

        require!(self.only_sender_or_admin(&account_id), "Must be called by the msg.sender, owner, or admins");

        log!("Storing new authenticator for account {}", account_id);
        let credential_id_b64url = BASE64_URL_ENGINE.encode(&registration_info.credential_id);

        // Parse transports from the response if available
        let transports = if let Some(transport_strings) = &credential.response.transports {
            Some(transport_strings.iter().filter_map(|t| {
                match t.as_str() {
                    "usb" => Some(AuthenticatorTransport::Usb),
                    "nfc" => Some(AuthenticatorTransport::Nfc),
                    "ble" => Some(AuthenticatorTransport::Ble),
                    "internal" => Some(AuthenticatorTransport::Internal),
                    "hybrid" => Some(AuthenticatorTransport::Hybrid),
                    _ => None,
                }
            }).collect())
        } else {
            None
        };

        // Extract origin and RP ID from the registration credential for secure verification
        let (client_data, _) = match decode_client_data_json(&credential.response.client_data_json) {
            Ok(data) => data,
            Err(e) => {
                log!("Failed to decode client data during storage: {}", e);
                return VerifyRegistrationResponse {
                    verified: false,
                    registration_info: None,
                };
            }
        };

        let current_timestamp = env::block_timestamp_ms().to_string();
        let expected_origin = client_data.origin;

        // Prepare VRF keys for storage
        log!("Storing authenticator with {} VRF keys for account {}", vrf_public_keys.len(), account_id);
        log!("Origin binding: {} -> {}", expected_origin, expected_rp_id);

        // Store the authenticator with multiple VRF public keys and origin binding
        self.internal_store_authenticator(
            account_id.clone(),
            credential_id_b64url.clone(),
            StoredAuthenticator {
                credential_public_key: registration_info.credential_public_key.clone(),
                transports: transports,
                registered: current_timestamp,
                expected_rp_id: expected_rp_id,
                origin_policy: origin_policy,
                user_verification: UserVerificationPolicy::Preferred,
                vrf_public_keys: vrf_public_keys, // Store all VRF keys
                device_number,   // Store device number
                near_public_key,
            }
        );

        // 2. Register user in user registry if not already registered
        if !self.registered_users.contains(&account_id) {
            log!("Registering new user in user registry: {}", account_id);
            self.registered_users.insert(account_id.clone());
        } else {
            log!("User already registered in user registry: {}", account_id);
        }

        VerifyRegistrationResponse {
            verified: true,
            registration_info: Some(registration_info),
        }
    }

    /// Store a new authenticator with VRF public keys
    fn internal_store_authenticator(
        &mut self,
        user_id: AccountId,
        credential_id: String,
        authenticator: StoredAuthenticator,
    ) -> bool {
        // Check if user's authenticator map exists, if not create it
        if !self.authenticators.contains_key(&user_id) {
            // Create new IterableMap with a unique storage key based on user_id
            let storage_key_bytes = format!("auth_{}", user_id).into_bytes();
            let new_map = IterableMap::new(storage_key_bytes);
            self.authenticators.insert(user_id.clone(), new_map);
        }

        // Check for duplicate device numbers
        if let Some(user_authenticators) = self.authenticators.get(&user_id) {
            for (existing_cred_id, existing_auth) in user_authenticators.iter() {
                if existing_auth.device_number == authenticator.device_number {
                    // Allow overwrite if it's the SAME credential ID (updating existing auth),
                    // otherwise panic if another authenticator creates a conflict.
                    if *existing_cred_id != credential_id {
                        env::panic_str(&format!("Device number {} is already in use by another authenticator", authenticator.device_number));
                    }
                }
            }
        }

        // Insert the authenticator into the user's map
        if let Some(user_authenticators) = self.authenticators.get_mut(&user_id) {
            user_authenticators.insert(credential_id.clone(), authenticator);
        }
        // Update credential->user mapping for account recovery
        self.credential_to_users.insert(credential_id, user_id.clone());
        log!("Stored authenticator for user {}", user_id);
        true
    }

    /// Remove an authenticator for a given account
    /// Only the account owner can remove their own authenticators
    pub fn remove_authenticator(&mut self, credential_id: String) -> bool {
        let account_id = env::predecessor_account_id();
        log!("Attempting to remove authenticator {} for account {}", credential_id, account_id);

        // Check if the account has any authenticators
        if let Some(user_authenticators) = self.authenticators.get_mut(&account_id) {
            if user_authenticators.contains_key(&credential_id) {
                // Remove the authenticator from the user's map
                user_authenticators.remove(&credential_id);
                // Remove the credential->user mapping
                self.credential_to_users.remove(&credential_id);
                log!("Successfully removed authenticator {} for account {}", credential_id, account_id);
                // If this was the last authenticator for the user, clean up the user's authenticator map
                if user_authenticators.is_empty() {
                    self.authenticators.remove(&account_id);
                    log!("Removed empty authenticator map for account {}", account_id);
                }
                true
            } else {
                log!("Authenticator {} not found for account {}", credential_id, account_id);
                false
            }
        } else {
            log!("No authenticators found for account {}", account_id);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;
    use crate::contract_state::OriginPolicy;

    fn get_context(predecessor_account_id: AccountId) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder
            .current_account_id(accounts(0))
            .signer_account_id(predecessor_account_id.clone())
            .predecessor_account_id(predecessor_account_id);
        builder
    }

    #[test]
    fn test_internal_store_authenticator_enforces_device_uniqueness() {
        let user_id = accounts(1);
        let context = get_context(user_id.clone());
        testing_env!(context.build());

        let mut contract = WebAuthnContract::init();

        // 1. Store first authenticator (Device 1)
        let auth1 = StoredAuthenticator {
            credential_public_key: vec![1, 2, 3],
            transports: None,
            registered: "123".to_string(),
            expected_rp_id: "test".to_string(),
            origin_policy: OriginPolicy::default(),
            user_verification: UserVerificationPolicy::Preferred,
            vrf_public_keys: vec![],
            device_number: 1,
            near_public_key: None,
        };
        contract.internal_store_authenticator(user_id.clone(), "cred1".to_string(), auth1.clone());

        // 2. Store second authenticator (Device 2) - Should succeed
        let auth2 = StoredAuthenticator {
            credential_public_key: vec![4, 5, 6],
            transports: None,
            registered: "123".to_string(),
            expected_rp_id: "test".to_string(),
            origin_policy: OriginPolicy::default(),
            user_verification: UserVerificationPolicy::Preferred,
            vrf_public_keys: vec![],
            device_number: 2, // Different device number
            near_public_key: None,
        };
        contract.internal_store_authenticator(user_id.clone(), "cred2".to_string(), auth2);

        // 3. Update first authenticator (Device 1) - Should succeed (same cred ID)
        contract.internal_store_authenticator(user_id.clone(), "cred1".to_string(), auth1.clone());

        // 4. Try to store third authenticator with Device 1 (Duplicate) - Should Panic
        let auth3 = StoredAuthenticator {
            credential_public_key: vec![7, 8, 9],
            transports: None,
            registered: "123".to_string(),
            expected_rp_id: "test".to_string(),
            origin_policy: OriginPolicy::default(),
            user_verification: UserVerificationPolicy::Preferred,
            vrf_public_keys: vec![],
            device_number: 1, // Duplicate device number!
            near_public_key: None,
        };

        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.internal_store_authenticator(user_id.clone(), "cred3".to_string(), auth3);
        })).expect_err("Should panic due to duplicate device number");
    }
}
