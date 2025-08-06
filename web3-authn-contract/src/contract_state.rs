use near_sdk::{AccountId, PanicOnDefault, BorshStorageKey};
use near_sdk::store::{LookupMap, IterableSet, IterableMap};
use near_sdk::borsh::BorshSerialize;


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

/// Stored authenticator data (V4 format - new flexible configuration)
#[near_sdk::near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct StoredAuthenticator {
    pub credential_public_key: Vec<u8>,
    pub transports: Option<Vec<AuthenticatorTransport>>,
    pub registered: String, // ISO timestamp of registration
    pub expected_rp_id: String, // Single RP ID for this authenticator
    pub origin_policy: OriginPolicy,
    pub user_verification: UserVerificationPolicy,
    pub vrf_public_keys: Vec<Vec<u8>>, // VRF public keys for stateless authentication (max 5, FIFO)
    pub device_number: u8, // Device number for this authenticator (1-indexed for UX)
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

/// Options for configuring WebAuthn authenticator behavior during registration
///
/// # JSON Format
/// ```json
/// {
///   "user_verification": "Required" | "Preferred" | "Discouraged" | null,
///   "origin_policy": {
///     "Single": null
///   } | {
///     "Multiple": ["sub.example.com", "api.example.com"]
///   } | "AllSubdomains" | null
/// }
/// ```
///
/// # Examples
///
/// ## Require user verification with multiple allowed origins:
/// ```json
/// {
///   "user_verification": "Required",
///   "origin_policy": {
///     "Multiple": ["app.example.com", "admin.example.com"]
///   }
/// }
/// ```
///
/// ## Preferred user verification with all subdomains allowed:
/// ```json
/// {
///   "user_verification": "Preferred",
///   "origin_policy": "AllSubdomains"
/// }
/// ```
///
/// ## Default options (both fields null):
/// ```json
/// {
///   "user_verification": null,
///   "origin_policy": null
/// }
/// ```
#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone)]
pub struct AuthenticatorOptions {
    pub user_verification: Option<UserVerificationPolicy>,
    pub origin_policy: Option<OriginPolicyInput>,
}
impl Default for AuthenticatorOptions {
    fn default() -> Self {
        Self {
            user_verification: None,
            origin_policy: None,
        }
    }
}

/// User verification policy for WebAuthn authenticators
///
/// # JSON Format
/// ```json
/// "required" | "preferred" | "discouraged"
/// ```
#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone)]
pub enum UserVerificationPolicy {
    #[serde(rename = "required")]
    Required,     // UV flag must be set
    #[serde(rename = "preferred")]
    Preferred,    // UV preferred but not required
    #[serde(rename = "discouraged")]
    Discouraged,  // UV should not be used
}
impl Default for UserVerificationPolicy {
    fn default() -> Self {
        Self::Preferred
    }
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone)]
pub enum OriginPolicy {
    Single(String),        // allow single origin
    Multiple(Vec<String>), // allow multiple pre-specified origins
    AllSubdomains,         // allow all sub-domains associated with RpID
}
impl Default for OriginPolicy {
    fn default() -> Self {
        Self::AllSubdomains
    }
}
impl OriginPolicy {
    pub fn validate(
        origin_policy_input: Option<OriginPolicyInput>,
        credential_origin: String,
        rp_id: String,
    ) -> Result<Self, String> {
        let o = match origin_policy_input {
            Some(OriginPolicyInput::Single) => {
                // Validate that credential_origin ends with rp_id
                if !credential_origin.ends_with(&rp_id) {
                    return Err(format!("Credential origin '{}' does not match RP ID '{}'", credential_origin, rp_id));
                }
                Self::Single(credential_origin)
            },
            Some(OriginPolicyInput::Multiple(origins)) => {
                let all_origins = [vec![credential_origin], origins].concat();
                // Validate that each origin in origins ends with rp_id
                for origin in &all_origins {
                    if !origin.ends_with(&rp_id) {
                        return Err(format!("Origin '{}' does not match RP ID '{}'", origin, rp_id));
                    }
                }
                Self::Multiple(all_origins)
            },
            Some(OriginPolicyInput::AllSubdomains) => {
                Self::AllSubdomains
            },
            None => Self::default(), // Defaults to all subdomains
        };
        Ok(o)
    }
}

/// Origin policy input for WebAuthn registration (user-provided)
///
/// # JSON Format
/// ```json
/// "single" | {
///   "multiple": ["sub.example.com", "api.example.com"]
/// } | "allSubdomains"
/// ```
///
/// # Examples
///
/// ## Single origin (uses credential.origin):
/// ```json
/// "single"
/// ```
///
/// ## Multiple allowed origins (additional to credential.origin):
/// ```json
/// {
///   "multiple": ["sub.example.com", "api.example.com"]
/// }
/// ```
///
/// ## Allow all subdomains of RP ID:
/// ```json
/// "allSubdomains"
/// ```
///
/// # Notes
/// - `single` uses the credential's origin as the only allowed origin
/// - `multiple` adds additional origins to the credential's origin
/// - `allSubdomains` allows any subdomain of the RP ID
/// - This is converted to `OriginPolicy` during registration
/// - The `multiple` variant stores domain names (without protocol)
#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone)]
pub enum OriginPolicyInput {
    #[serde(rename = "single")]
    Single,                // uses credential.origin as the origin
    #[serde(rename = "multiple")]
    Multiple(Vec<String>), // allow multiple pre-specified origins
    #[serde(rename = "allSubdomains")]
    AllSubdomains,         // allow all sub-domains associated with RpID
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

/// Main contract state (V4)
#[near_sdk::near(contract_state)]
#[derive(PanicOnDefault)]
pub struct WebAuthnContract {
    // Track contract version for migrations
    pub contract_version: u32,
    // Test greeting
    pub greeting: Option<String>,
    // Contract owner (can add/remove admins and transfer ownership)
    pub owner: AccountId,
    // Admins
    pub admins: IterableSet<AccountId>,
    // VRF challenge verification settings
    pub vrf_settings: VRFSettings,
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

/////////////////////////////////////
/// TESTS
/////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::serde_json;

    #[test]
    fn test_authenticator_options_serialization() {
        println!("Testing AuthenticatorOptions serialization...");

        // Test complex AuthenticatorOptions with all variants
        let options = AuthenticatorOptions {
            user_verification: Some(UserVerificationPolicy::Required),
            origin_policy: Some(OriginPolicyInput::Multiple(vec![
                "sub.example.com".to_string(),
                "api.example.com".to_string(),
            ])),
        };

        let json_str = serde_json::to_string(&options).unwrap();
        println!("Serialized JSON: {}", json_str);

        let deserialized: AuthenticatorOptions = serde_json::from_str(&json_str).unwrap();

        // Verify all fields are correctly deserialized
        assert!(matches!(deserialized.user_verification, Some(UserVerificationPolicy::Required)));
        match deserialized.origin_policy {
            Some(OriginPolicyInput::Multiple(origins)) => {
                assert_eq!(origins.len(), 2);
                assert_eq!(origins[0], "sub.example.com");
                assert_eq!(origins[1], "api.example.com");
            },
            _ => panic!("Expected Multiple variant in origin_policy"),
        }

        println!("✓ AuthenticatorOptions serialization test passed");
    }

    #[test]
    fn test_origin_policy_enum_serialization() {
        println!("Testing OriginPolicy enum serialization...");

        // Test all enum variants
        let variants = vec![
            OriginPolicy::Single("example.com".to_string()),
            OriginPolicy::Multiple(vec!["app.example.com".to_string(), "admin.example.com".to_string()]),
            OriginPolicy::AllSubdomains,
        ];

        for (i, variant) in variants.iter().enumerate() {
            let json_str = serde_json::to_string(variant).unwrap();
            println!("Variant {} JSON: {}", i, json_str);

            let deserialized: OriginPolicy = serde_json::from_str(&json_str).unwrap();

            // Verify round-trip serialization
            let json_str2 = serde_json::to_string(&deserialized).unwrap();
            assert_eq!(json_str, json_str2, "Round-trip serialization failed for variant {}", i);
        }

        println!("✓ OriginPolicy enum serialization test passed");
    }

    #[test]
    fn test_lowercase_json_serialization() {
        println!("Testing lowercase JSON serialization...");

        // Test UserVerificationPolicy lowercase serialization
        let uv_required = UserVerificationPolicy::Required;
        let json_str = serde_json::to_string(&uv_required).unwrap();
        assert_eq!(json_str, "\"required\"");

        let uv_preferred = UserVerificationPolicy::Preferred;
        let json_str = serde_json::to_string(&uv_preferred).unwrap();
        assert_eq!(json_str, "\"preferred\"");

        // Test OriginPolicyInput lowercase serialization
        let single = OriginPolicyInput::Single;
        let json_str = serde_json::to_string(&single).unwrap();
        assert_eq!(json_str, "\"single\"");

        let multiple = OriginPolicyInput::Multiple(vec!["example.com".to_string()]);
        let json_str = serde_json::to_string(&multiple).unwrap();
        assert_eq!(json_str, "{\"multiple\":[\"example.com\"]}");

        let all_subdomains = OriginPolicyInput::AllSubdomains;
        let json_str = serde_json::to_string(&all_subdomains).unwrap();
        assert_eq!(json_str, "\"allSubdomains\"");

        // Test deserialization from lowercase
        let deserialized_uv: UserVerificationPolicy = serde_json::from_str("\"required\"").unwrap();
        assert!(matches!(deserialized_uv, UserVerificationPolicy::Required));

        let deserialized_single: OriginPolicyInput = serde_json::from_str("\"single\"").unwrap();
        assert!(matches!(deserialized_single, OriginPolicyInput::Single));

        println!("✓ Lowercase JSON serialization test passed");
    }
}