use near_sdk::{AccountId, PanicOnDefault, BorshStorageKey};
use near_sdk::store::{LookupMap, IterableSet, IterableMap};
use near_sdk::borsh::BorshSerialize;

/// TLD configuration for domain parsing
/// Allows contract deployment to specify which complex TLD patterns to support
#[near_sdk::near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct TldConfiguration {
    /// List of two-part TLDs that require 3 parts for registrable domain
    /// Format: (second_level_domain, top_level_domain)
    /// Example: ("co", "uk") for .co.uk domains
    pub multi_part_tlds: Vec<(String, String)>,
    /// Whether to enable complex TLD support (default: false for standard domains only)
    pub enabled: bool,
}

impl Default for TldConfiguration {
    fn default() -> Self {
        Self {
            multi_part_tlds: vec![], // Empty by default - only standard domains supported
            enabled: false,          // Disabled by default for simplicity and performance
        }
    }
}

/// VRF configuration settings
#[near_sdk::near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct VRFSettings {
    pub max_input_age_ms: u64, // Maximum age for VRF input components (default: 5 minutes)
    pub max_block_age: u64,    // Maximum block age for block hash validation
    pub enabled: bool,         // Feature flag for VRF functionality
    pub max_authenticators_per_account: usize, // Maximum number of authenticators per account
}

impl Default for VRFSettings {
    fn default() -> Self {
        Self {
            max_input_age_ms: 300_000, // 5 minutes
            max_block_age: 100,        // 100 blocks (~60 seconds, accommodates TouchID delays)
            enabled: true,
            max_authenticators_per_account: 10,
        }
    }
}

/// Stored authenticator data (part of contract state)
#[near_sdk::near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct StoredAuthenticator {
    pub credential_public_key: Vec<u8>,
    pub transports: Option<Vec<AuthenticatorTransport>>,
    pub registered: String, // ISO timestamp of registration
    pub vrf_public_keys: Vec<Vec<u8>>, // VRF public keys for stateless authentication (max 5, FIFO)
    pub device_number: u8, // Device number for this authenticator (1-indexed for UX)
    pub expected_origin: String, // Origin URL where this authenticator was registered (e.g., "https://example.com")
    pub expected_rp_id: String, // RP ID where this authenticator was registered (e.g., "example.com")
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone, PartialEq)]
pub enum AuthenticatorTransport {
    #[serde(rename = "usb")]
    Usb,
    #[serde(rename = "nfc")]
    Nfc,
    #[serde(rename = "ble")]
    Ble,
    #[serde(rename = "internal")]
    Internal,
    #[serde(rename = "hybrid")]
    Hybrid,
}

/// Storage keys for the contract's persistent collections
#[derive(BorshSerialize, BorshStorageKey)]
#[borsh(crate = "near_sdk::borsh")]
pub enum StorageKey {
    Authenticators,
    RegisteredUsers,
    Admins,
    CredentialToUsers,
    AccountDeviceCounters,
    DeviceLinkingMap,
}

/// Main contract state
#[near_sdk::near(contract_state)]
#[derive(PanicOnDefault)]
pub struct WebAuthnContract {
    pub greeting: String,
    // Admins
    pub admins: IterableSet<AccountId>,
    // VRF challenge verification settings
    pub vrf_settings: VRFSettings,
    // TLD configuration for domain parsing
    pub tld_config: Option<TldConfiguration>,
    // Authenticators: 1-to-many: AccountId -> [{ CredentialID: AuthenticatorData }, ...]
    pub authenticators: LookupMap<AccountId, IterableMap<String, StoredAuthenticator>>,
    // Registered users
    pub registered_users: IterableSet<AccountId>,
    // Reverse Lookup account associated with a WebAuthn (TouchId) credential_id (1:1 mapping)
    // May be needed for future account recovery flow (discover accounts with TouchID)
    pub credential_to_users: LookupMap<String, AccountId>,
    // Temporary mapping for device linking: Device2 public key -> (Device1 account ID, device number)
    // Required for Link Device Flow
    pub device_linking_map: LookupMap<String, (AccountId, u8)>,
    // Device counter per account: AccountId -> next device number
    pub device_numbers: LookupMap<AccountId, u8>,
}