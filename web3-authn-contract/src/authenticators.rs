use super::{WebAuthnContract, WebAuthnContractExt};
use near_sdk::{log, near, require, env, AccountId};
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
        // Insert the authenticator into the user's map
        if let Some(user_authenticators) = self.authenticators.get_mut(&user_id) {
            user_authenticators.insert(credential_id.clone(), authenticator);
        }
        // Update credential->user mapping for account recovery
        self.credential_to_users.insert(credential_id, user_id.clone());
        log!("Stored authenticator for user {}", user_id);
        true
    }
}
