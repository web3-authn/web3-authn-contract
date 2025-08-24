use serde::{Deserialize, Serialize};

// V5 StoredAuthenticator structure - matches contract
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StoredAuthenticatorV5 {
    pub credential_public_key: Vec<u8>,
    pub transports: Option<Vec<AuthenticatorTransport>>,
    pub registered: String,
    pub expected_rp_id: String,
    pub origin_policy: OriginPolicyV5,
    pub user_verification: UserVerificationPolicy,
    pub vrf_public_keys: Vec<Vec<u8>>,
    pub device_number: u8,
}

// V6 StoredAuthenticator structure - new format
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StoredAuthenticatorV6 {
    pub credential_public_key: Vec<u8>,
    pub transports: Option<Vec<AuthenticatorTransport>>,
    pub registered: String,
    pub expected_rp_id: String,
    pub origin_policy: OriginPolicyV5, // Same as V5 for now
    pub user_verification: UserVerificationPolicy,
    pub vrf_public_keys: Vec<Vec<u8>>,
    pub device_number: u8,
    // Add new V6 fields here as needed
}

// V5 OriginPolicy struct format
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OriginPolicyV5 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub single: Option<String>,
    #[serde(rename = "allSubdomains", skip_serializing_if = "Option::is_none")]
    pub all_subdomains: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiple: Option<Vec<String>>,
}

// Supporting enums to match contract
#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum UserVerificationPolicy {
    #[serde(rename = "required")]
    Required,
    #[serde(rename = "preferred")]
    Preferred,
    #[serde(rename = "discouraged")]
    Discouraged,
}

// V5 specific exported migration data structure
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportedMigrationDataV5 {
    pub contract_version: u32,
    pub registered_users: Vec<AccountId>,
    pub exported_accounts: Vec<ExportedAccountsV5>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExportedAccountsV5 {
    pub account_id: AccountId,
    pub authenticators: Vec<ExportedAuthenticatorV5>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExportedAuthenticatorV5 {
    pub credential_id: String,
    pub authenticator: StoredAuthenticatorV5,
}

// Type alias for AccountId
type AccountId = String;

/// Convert V5 StoredAuthenticator to V6 StoredAuthenticator
pub fn migrate_authenticator_v5_to_v6(v5_auth: &StoredAuthenticatorV5) -> StoredAuthenticatorV6 {
    StoredAuthenticatorV6 {
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