use near_sdk::{env, log, near};
use near_sdk::store::{LookupMap, IterableSet};
use crate::contract_state::{
    WebAuthnContract,
    StorageKey,
    AuthenticatorTransport,
    UserVerificationPolicy,
    OriginPolicy,
    WebAuthnContractExt
};

// V5 StoredAuthenticator structure (current format)
#[near_sdk::near(serializers=[borsh, json])]
pub struct StoredAuthenticatorV5 {
    pub credential_public_key: Vec<u8>,
    pub transports: Option<Vec<AuthenticatorTransport>>,
    pub registered: String,
    pub expected_rp_id: String,
    pub origin_policy: OriginPolicy,
    pub user_verification: UserVerificationPolicy,
    pub vrf_public_keys: Vec<Vec<u8>>,
    pub device_number: u8,
}

// V6 StoredAuthenticator structure (new format)
#[near_sdk::near(serializers=[borsh, json])]
pub struct StoredAuthenticatorV6 {
    pub credential_public_key: Vec<u8>,
    pub transports: Option<Vec<AuthenticatorTransport>>,
    pub registered: String,
    pub expected_rp_id: String,
    pub origin_policy: OriginPolicy,
    pub user_verification: UserVerificationPolicy,
    pub vrf_public_keys: Vec<Vec<u8>>,
    pub device_number: u8,
    // Add new V6 fields here as needed
}

// V5 Contract state structure
pub struct WebAuthnContractV5 {
    pub contract_version: u32,
    pub greeting: Option<String>,
    pub owner: near_sdk::AccountId,
    pub vrf_settings: crate::contract_state::VRFSettings,
    pub admins: IterableSet<near_sdk::AccountId>,
    pub authenticators: LookupMap<near_sdk::AccountId, LookupMap<String, StoredAuthenticatorV5>>,
    pub registered_users: IterableSet<near_sdk::AccountId>,
    pub credential_to_users: LookupMap<String, near_sdk::AccountId>,
    pub device_numbers: LookupMap<near_sdk::AccountId, u8>,
    pub device_linking_map: LookupMap<String, (near_sdk::AccountId, u8)>,
}

#[near]
impl WebAuthnContract {
    /// Start migration from V5 to V6 contract structure
    #[init(ignore_state)]
    pub fn start_migration_v5_to_v6() -> Self {
        let predecessor = env::predecessor_account_id();
        let contract_account = env::current_account_id();

        // Read old V5 state from storage using the old struct definition
        let old_state: WebAuthnContractV5 = env::state_read()
            .expect("Failed to read old contract state");

        // Verify admin access
        if predecessor != contract_account && !old_state.admins.contains(&predecessor) {
            env::panic_str("Only contract owner or admins can migrate");
        }

        log!("Starting migration from V5 to V6...");

        // Create new V6 contract with migrated basic state
        Self {
            contract_version: 6,
            greeting: Some("Migrated to V6".to_string()),
            // Copy over simple fields that don't need conversion
            owner: old_state.owner,
            admins: old_state.admins,
            vrf_settings: old_state.vrf_settings,
            // Initialize complex fields that need batch migration as empty
            authenticators: LookupMap::new(StorageKey::Authenticators),
            // Preserve other state that can be directly copied
            registered_users: old_state.registered_users,
            credential_to_users: old_state.credential_to_users,
            device_numbers: old_state.device_numbers,
            device_linking_map: old_state.device_linking_map,
        }
    }
}

/// Convert V5 StoredAuthenticator to V6 StoredAuthenticator
fn migrate_authenticator_v5_to_v6(v5_auth: &StoredAuthenticatorV5) -> crate::contract_state::StoredAuthenticator {
    crate::contract_state::StoredAuthenticator {
        credential_public_key: v5_auth.credential_public_key.clone(),
        transports: v5_auth.transports.clone(),
        registered: v5_auth.registered.clone(),
        expected_rp_id: v5_auth.expected_rp_id.clone(),
        origin_policy: v5_auth.origin_policy.clone(),
        user_verification: v5_auth.user_verification.clone(),
        vrf_public_keys: v5_auth.vrf_public_keys.clone(),
        device_number: v5_auth.device_number,
    }
}
