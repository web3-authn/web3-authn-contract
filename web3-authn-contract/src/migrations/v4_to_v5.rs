use near_sdk::store::{LookupMap, IterableSet, IterableMap};
use near_sdk::{near, AccountId, env, log};

use crate::{WebAuthnContract, WebAuthnContractExt};
use crate::contract_state::{
    VRFSettings,
    AuthenticatorTransport,
    OriginPolicy,
    UserVerificationPolicy,
    StorageKey
};

// Old V4 contract structure
#[near_sdk::near(serializers=[borsh])]
pub struct WebAuthnContractV4 {
    pub contract_version: u32,
    pub greeting: Option<String>,
    pub owner: AccountId,
    pub admins: IterableSet<AccountId>,
    pub vrf_settings: VRFSettings,
    pub authenticators: LookupMap<AccountId, IterableMap<String, StoredAuthenticatorV4>>,
    pub registered_users: IterableSet<AccountId>,
    pub credential_to_users: LookupMap<String, AccountId>,
    pub device_linking_map: LookupMap<String, (AccountId, u8)>,
    pub device_numbers: LookupMap<AccountId, u8>,
}

// Migration state tracking (for V4 to V5)
#[near_sdk::near(serializers=[borsh, json])]
pub struct MigrationState {
    pub total_authenticators: u32,
    pub migrated_count: u32,
    pub accounts_to_process: Vec<AccountId>,
    pub current_account_index: usize,
    pub current_credential_index: usize,
}

// Old V4 StoredAuthenticator structure
#[near_sdk::near(serializers=[borsh, json])]
pub struct StoredAuthenticatorV4 {
    pub credential_public_key: Vec<u8>,
    pub transports: Option<Vec<AuthenticatorTransport>>,
    pub registered: String,
    pub expected_rp_id: String,
    pub origin_policy: OriginPolicy,
    pub user_verification: UserVerificationPolicy,
    pub vrf_public_keys: Vec<Vec<u8>>,
    pub device_number: u8,
}

// Migration progress reporting (for offchain tracking)
#[near_sdk::near(serializers=[borsh, json])]
pub struct MigrationProgress {
    pub migrated_authenticators: Vec<String>,
    pub migrated_count: u32,
    pub batch_size: u32,
}

#[near_sdk::near(serializers=[borsh, json])]
pub struct ExportedMigrationData {
    pub contract_version: u32,
    pub registered_users: Vec<AccountId>,
    pub exported_accounts: Vec<ExportedAccounts>,
}

#[near_sdk::near(serializers=[borsh, json])]
pub struct ExportedAccounts {
    pub account_id: AccountId,
    pub authenticators: Vec<ExportedAuthenticator>,
}

#[near_sdk::near(serializers=[borsh, json])]
pub struct ExportedAuthenticator {
    pub credential_id: String,
    pub authenticator: StoredAuthenticatorV4, // StoredAuthenticatorV4 before migration
}


/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

#[near]
impl WebAuthnContract {

    /// Start migration from V4 to V5 contract structure
    /// This is an init function that reads old V4 state and creates new V5 contract
    /// Progress tracking is handled offchain - no migration_state field
    #[init(ignore_state)]
    pub fn start_migration_v4_to_v5() -> Self {

        let predecessor = env::predecessor_account_id();
        let contract_account = env::current_account_id();

        // Read old V4 state from storage
        let old_state: WebAuthnContractV4 = env::state_read()
            .expect("Failed to read old contract state");

        // Verify admin access
        if predecessor != contract_account && !old_state.admins.contains(&predecessor) {
            env::panic_str("Only contract owner or admins can migrate");
        }

        log!("Starting migration from V4 to V5...");
        log!("Number of registered users: {}", old_state.registered_users.len());

        // Debug: Check if old authenticators have data
        let mut debug_count = 0;
        for user_id in old_state.registered_users.iter() {
            if let Some(user_auths) = old_state.authenticators.get(user_id) {
                debug_count += user_auths.len();
                log!("User {} has {} authenticators", user_id, user_auths.len());
            }
        }
        log!("Total authenticators found in old state: {}", debug_count);

        // Create new V5 contract with migrated data
        Self {
            contract_version: 5,
            greeting: old_state.greeting,
            owner: contract_account, // Contract account becomes owner
            admins: old_state.admins,
            vrf_settings: old_state.vrf_settings,
            authenticators: LookupMap::new(StorageKey::Authenticators), // Empty initially
            registered_users: old_state.registered_users,
            credential_to_users: old_state.credential_to_users,
            device_linking_map: old_state.device_linking_map,
            device_numbers: old_state.device_numbers,
        }
    }

    /// Migrate authenticators from offchain backup data
    /// This function accepts authenticator data as parameters from offchain backup
    /// Returns MigrationProgress with batch results for offchain tracking
    pub fn migrate_authenticator_batch(
        &mut self,
        exported_accounts: Vec<ExportedAccounts>,
    ) -> MigrationProgress {
        self.only_admin();

        let mut migrated_in_batch = 0;
        let batch_size = exported_accounts.len() as u32;
        let mut migrated_authenticators: Vec<String> = vec![];
        log!(
            "Migrating {} authenticators for account {:?}",
            batch_size,
            exported_accounts.iter().map(|account| account.account_id.clone()).collect::<Vec<AccountId>>()
        );

        // Process each authenticator from the backup data
        for account in exported_accounts {
            for exported_authenticator in account.authenticators {
            // Convert old authenticator to new format
            let new_authenticator = migrate_authenticator_v4_to_v5(&exported_authenticator.authenticator);
            // Store the authenticator directly
            if !self.authenticators.contains_key(&account.account_id) {
                let storage_key_bytes = format!("auth_{}", account.account_id).into_bytes();
                let new_map = IterableMap::new(storage_key_bytes);
                self.authenticators.insert(account.account_id.clone(), new_map);
            }
            if let Some(user_authenticators) = self.authenticators.get_mut(&account.account_id) {
                user_authenticators.insert(exported_authenticator.credential_id.clone(), new_authenticator);
            }

            migrated_in_batch += 1;
            migrated_authenticators.push(exported_authenticator.credential_id.clone());
            log!("Migrated authenticator {} for account {}", exported_authenticator.credential_id, account.account_id);
            }
        }

        let progress = MigrationProgress {
            migrated_authenticators,
            migrated_count: migrated_in_batch, // Return actual migrated count for this batch
            batch_size,
        };

        log!("Batch migration completed: {}/{} authenticators migrated", migrated_in_batch, batch_size);

        progress
    }

    /// Get current migration status (for offchain tracking)
    pub fn export_migration_data(&self) -> ExportedMigrationData {
        self.only_admin();

        let registered_users: Vec<AccountId> = self.registered_users.iter().map(|id| id.clone()).collect();
        let mut exported_accounts = Vec::new();

        for user_id in registered_users.iter() {
            if let Some(authenticators) = self.authenticators.get(user_id) {
                let mut user_authenticators: Vec<ExportedAuthenticator> = vec![];
                for (cred_id, authenticator) in authenticators.iter() {
                    // coerce types from StoredAuthenticator -> StoredAuthenticatorV4 before migration
                    let json: ExportedAuthenticator = serde_json::from_value(serde_json::json!({
                        "credential_id": cred_id.clone(),
                        "authenticator": authenticator.clone(),
                    })).expect("Failed to coerce StoredAuthenticator type to StoredAuthenticatorV4");
                    user_authenticators.push(json);
                }
                exported_accounts.push(ExportedAccounts {
                    account_id: user_id.clone(),
                    authenticators: user_authenticators,
                });
            }
        }

        ExportedMigrationData {
            contract_version: self.contract_version,
            registered_users: registered_users,
            exported_accounts: exported_accounts,
        }
    }
}

/// Convert V4 StoredAuthenticator to V5 StoredAuthenticator
fn migrate_authenticator_v4_to_v5(v4_auth: &StoredAuthenticatorV4) -> crate::contract_state::StoredAuthenticator {
    // V4 to V5 migration - currently no structural changes
    // This function can be extended for future V5 changes
    crate::contract_state::StoredAuthenticator {
        credential_public_key: v4_auth.credential_public_key.clone(),
        transports: v4_auth.transports.clone(),
        registered: v4_auth.registered.clone(),
        expected_rp_id: v4_auth.expected_rp_id.clone(),
        origin_policy: v4_auth.origin_policy.clone(),
        user_verification: v4_auth.user_verification.clone(),
        vrf_public_keys: v4_auth.vrf_public_keys.clone(),
        device_number: v4_auth.device_number,
    }
}

