pub mod utils;
mod authenticators;
mod admin;
mod types;
mod contract_state;
mod link_device;
mod verify_authentication_response;
mod verify_registration_response;
// mod migrations;

use near_sdk::{env, log, near};
use near_sdk::store::{LookupMap, IterableSet};

pub use types::{
    WebAuthnRegistrationCredential,
    WebAuthnAuthenticationCredential,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
};
use contract_state::WebAuthnContractExt;
pub use contract_state::{
    WebAuthnContract,
    VRFSettings,
    StoredAuthenticator,
    StorageKey,
    AuthenticatorTransport,
    UserVerificationPolicy,
    OriginPolicy,
};
pub use verify_registration_response::{
    VerifyRegistrationResponse,
    VerifyCanRegisterResponse,
};

/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

#[near]
impl WebAuthnContract {

    #[init]
    pub fn init() -> Self {
        let owner = env::predecessor_account_id();
        let mut contract = Self {
            contract_version: 4,
            greeting: Some("Hello".to_string()),
            owner: owner.clone(),
            vrf_settings: VRFSettings::default(),
            admins: IterableSet::new(StorageKey::Admins),
            authenticators: LookupMap::new(StorageKey::Authenticators),
            registered_users: IterableSet::new(StorageKey::RegisteredUsers),
            credential_to_users: LookupMap::new(StorageKey::CredentialToUsers),
            device_numbers: LookupMap::new(StorageKey::AccountDeviceCounters),
            device_linking_map: LookupMap::new(StorageKey::DeviceLinkingMap),
        };
        // Add contract deployer as an admin
        contract.admins.insert(owner);

        contract
    }

    pub fn get_greeting(&self) -> Option<String> {
        self.greeting.clone()
    }

    pub fn set_greeting(&mut self, greeting: String) {
        log!("Saving greeting: {}", greeting);
        self.greeting = Some(greeting);
    }

    /// Get contract state statistics (view function)
    pub fn get_contract_state(&self) -> serde_json::Value {
        // Count authenticators and credential IDs by iterating through registered users
        let mut total_authenticators = 0;
        let mut total_credential_ids = 0;

        for user_id in self.registered_users.iter() {
            if let Some(user_authenticators) = self.authenticators.get(user_id) {
                let user_auth_count = user_authenticators.keys().count();
                total_authenticators += 1; // One authenticator entry per user
                total_credential_ids += user_auth_count;
            }
        }
        let storage_usage = env::storage_usage();

        serde_json::json!({
            "contract_version": self.contract_version,
            "owner": self.owner,
            "registered_users_count": self.registered_users.len(),
            "authenticator_entries_count": total_authenticators,
            "total_credential_ids": total_credential_ids,
            "admins_count": self.admins.len(),
            "storage_usage": storage_usage,
            "vrf_settings": self.vrf_settings,
        })
    }
}
