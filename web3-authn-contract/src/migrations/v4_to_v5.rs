use near_sdk::borsh::BorshDeserialize;
use near_sdk::{env, log, near, require, AccountId};
use near_sdk::store::{IterableMap, IterableSet, LookupMap};
use near_sdk::store::key::{Sha256, ToKey};

use crate::contract_state::WebAuthnContractExt;
use crate::contract_state::{
    AuthenticatorTransport,
    OriginPolicy,
    StorageKey,
    StoredAuthenticator,
    UserVerificationPolicy,
    VRFSettings,
    WebAuthnContract,
};

/// Stored authenticator data (V4 format).
///
/// V5 adds `near_public_key`, so this is used to read the pre-upgrade state.
#[near_sdk::near(serializers=[borsh])]
#[derive(Clone)]
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

/// Contract state as stored in V4.
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
    pub allowed_origins: IterableSet<String>,
}

#[near_sdk::near(serializers=[borsh])]
struct ValueAndIndexV4 {
    value: StoredAuthenticatorV4,
    key_index: u32,
}

#[near_sdk::near(serializers=[borsh])]
struct ValueAndIndexV5 {
    value: StoredAuthenticator,
    key_index: u32,
}

#[near]
impl WebAuthnContract {
    /// Migrates contract state from V4 to V5.
    ///
    /// V5 adds `StoredAuthenticator.near_public_key: Option<PublicKey>`.
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        let predecessor = env::predecessor_account_id();
        let contract_account = env::current_account_id();

        let old_state: WebAuthnContractV4 = env::state_read()
            .expect("Failed to read old contract state");

        // Verify admin/owner access.
        let is_admin = old_state.admins.contains(&predecessor);
        require!(
            predecessor == contract_account || predecessor == old_state.owner || is_admin,
            "Only contract owner or admins can migrate"
        );

        require!(
            old_state.contract_version == 4,
            "Can only migrate from contract_version 4"
        );

        log!("Starting migration v4 -> v5 (add near_public_key to StoredAuthenticator)...");

        let user_ids: Vec<AccountId> = old_state.registered_users.iter().cloned().collect();
        log!("Migrating authenticators for {} users...", user_ids.len());

        let mut migrated_authenticators: u64 = 0;

        for user_id in user_ids {
            // `IterableMap` uses:
            // - key vector storage at:   prefix + b'v' + index(u32 LE)
            // - value lookup storage at: sha256((prefix + b"m") + borsh(key))
            let mut prefix = format!("auth_{}", user_id).into_bytes();

            let mut keys_prefix = prefix.clone();
            keys_prefix.push(b'v');

            prefix.push(b'm');
            let values_prefix = prefix;

            let mut index: u32 = 0;
            loop {
                let mut key_storage_key = Vec::with_capacity(keys_prefix.len() + 4);
                key_storage_key.extend_from_slice(&keys_prefix);
                key_storage_key.extend_from_slice(&index.to_le_bytes());

                let Some(raw_key) = env::storage_read(&key_storage_key) else { break };
                let credential_id: String = String::try_from_slice(&raw_key)
                    .unwrap_or_else(|_| env::panic_str("Failed to deserialize credential_id key"));

                let value_storage_key = Sha256::to_key(&values_prefix, &credential_id, &mut Vec::new());
                let raw_value = env::storage_read(value_storage_key.as_ref())
                    .unwrap_or_else(|| env::panic_str("IterableMap is in an inconsistent state (missing value)"));

                let v4: ValueAndIndexV4 = ValueAndIndexV4::try_from_slice(&raw_value)
                    .unwrap_or_else(|_| env::panic_str("Cannot deserialize element"));

                let v5 = ValueAndIndexV5 {
                    value: StoredAuthenticator {
                        credential_public_key: v4.value.credential_public_key,
                        transports: v4.value.transports,
                        registered: v4.value.registered,
                        expected_rp_id: v4.value.expected_rp_id,
                        origin_policy: v4.value.origin_policy,
                        user_verification: v4.value.user_verification,
                        vrf_public_keys: v4.value.vrf_public_keys,
                        device_number: v4.value.device_number,
                        near_public_key: None,
                    },
                    key_index: v4.key_index,
                };

                let raw_v5 = near_sdk::borsh::to_vec(&v5)
                    .unwrap_or_else(|_| env::panic_str("Failed to serialize migrated authenticator"));
                env::storage_write(value_storage_key.as_ref(), &raw_v5);

                migrated_authenticators += 1;
                index += 1;
            }
        }

        log!("Migration complete: migrated {} authenticators", migrated_authenticators);

        Self {
            contract_version: 5,
            greeting: old_state.greeting,
            owner: old_state.owner,
            admins: old_state.admins,
            vrf_settings: old_state.vrf_settings,
            authenticators: LookupMap::new(StorageKey::Authenticators),
            registered_users: old_state.registered_users,
            credential_to_users: old_state.credential_to_users,
            device_linking_map: old_state.device_linking_map,
            device_numbers: old_state.device_numbers,
            allowed_origins: old_state.allowed_origins,
        }
    }
}
