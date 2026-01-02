# Web3Authn Contract API Reference

This document overviews the API for the Web3Authn contract, which implements VRF-based WebAuthn authentication for NEAR blockchain.

## Contract Overview

The Web3Authn contract provides serverless, stateless WebAuthn authentication using Verifiable Random Functions (VRF) for challenge generation. It supports account creation, user registration, device linking, and secure authentication without requiring centralized servers.

## Core Data Structures

### VRFVerificationData
```rust
pub struct VRFVerificationData {
    pub vrf_input_data: Vec<u8>,    // SHA256 hash of VRF input components
    pub vrf_output: Vec<u8>,        // VRF output used as WebAuthn challenge
    pub vrf_proof: Vec<u8>,         // Bincode serialized VRF proof
    pub public_key: Vec<u8>,        // Bincode serialized VRF public key
    pub user_id: String,            // NEAR account ID
    pub rp_id: String,              // Relying Party ID
    pub block_height: u64,          // NEAR block height for freshness
    pub block_hash: Vec<u8>,        // NEAR block hash for entropy
    pub intent_digest_32: Option<Vec<u8>>, // Optional 32-byte UI intent digest bound into VRF input
}
```

### WebAuthnRegistrationCredential
```rust
pub struct WebAuthnRegistrationCredential {
    pub id: String,                                   // Base64URL credential ID
    pub raw_id: String,                               // Base64URL credential ID
    pub response: AuthenticatorAttestationResponse,   // Registration response
    pub authenticator_attachment: Option<String>,     // Device type
    pub type_: String,                                // Always "public-key"
    pub client_extension_results: Option<ClientExtensionResults>,
}
```

### WebAuthnAuthenticationCredential
```rust
pub struct WebAuthnAuthenticationCredential {
    pub id: String,                                   // Base64URL credential ID
    pub raw_id: String,                               // Base64URL credential ID (JSON: "rawId")
    pub response: AuthenticatorAssertionResponse,    // Authentication response
    pub authenticator_attachment: Option<String>,    // Device type
    pub type_: String,                               // Always "public-key"
    pub client_extension_results: Option<ClientExtensionResults>,
}
```

## Public API Methods

### Initialization

#### init
Initializes the contract with default VRF settings and sets the contract owner to the deployer.

```rust
#[init]
pub fn init() -> WebAuthnContract
```

### Account Creation & Registration

#### create_account_and_register_user
Creates a new NEAR account and registers WebAuthn credentials atomically.

```rust
#[payable]
pub fn create_account_and_register_user(
    &mut self,
    new_account_id: AccountId,
    new_public_key: PublicKey,
    vrf_data: VRFVerificationData,
    webauthn_registration: WebAuthnRegistrationCredential,
    deterministic_vrf_public_key: Vec<u8>,
    authenticator_options: Option<AuthenticatorOptions>,
) -> Promise
```

#### verify_and_register_user
Registers WebAuthn credentials for the calling account (predecessor).

```rust
pub fn verify_and_register_user(
    &mut self,
    vrf_data: VRFVerificationData,
    webauthn_registration: WebAuthnRegistrationCredential,
    deterministic_vrf_public_key: Vec<u8>,
    authenticator_options: Option<AuthenticatorOptions>,
) -> VerifyRegistrationResponse
```

#### check_can_register_user
Checks if a user can register without performing registration (view function).

```rust
pub fn check_can_register_user(
    &self,
    vrf_data: VRFVerificationData,
    webauthn_registration: WebAuthnRegistrationCredential,
    authenticator_options: Option<AuthenticatorOptions>,
) -> VerifyCanRegisterResponse
```

### Authentication

#### verify_authentication_response
Verifies WebAuthn authentication using VRF-generated challenges.

```rust
pub fn verify_authentication_response(
    &self,
    vrf_data: VRFVerificationData,
    webauthn_authentication: WebAuthnAuthenticationCredential,
) -> VerifiedAuthenticationResponse
```

### Device Management

#### link_device_register_user
Links a new device to an existing account (called by the account owner).

```rust
pub fn link_device_register_user(
    &mut self,
    vrf_data: VRFVerificationData,
    webauthn_registration: WebAuthnRegistrationCredential,
    deterministic_vrf_public_key: Vec<u8>,
    authenticator_options: Option<AuthenticatorOptions>,
) -> VerifyRegistrationResponse
```

#### store_device_linking_mapping
Stores temporary mapping for device linking discovery.

```rust
pub fn store_device_linking_mapping(
    &mut self,
    device_public_key: String,
    target_account_id: AccountId,
) -> CryptoHash
```

#### get_device_linking_account
Retrieves device linking information for discovery.

```rust
pub fn get_device_linking_account(
    &self,
    device_public_key: String,
) -> Option<(AccountId, u8)>
```

#### cleanup_device_linking
Cleans up temporary device linking mappings.

```rust
pub fn cleanup_device_linking(
    &mut self,
    device_public_key: String,
)
```

### User Management

#### get_authenticators_by_user
Retrieves all authenticators for a specific user.

```rust
pub fn get_authenticators_by_user(
    &self,
    user_id: AccountId,
) -> Vec<(String, StoredAuthenticator)>
```

#### get_authenticator
Retrieves a specific authenticator by user and credential ID.

```rust
pub fn get_authenticator(
    &self,
    user_id: AccountId,
    credential_id: String,
) -> Option<StoredAuthenticator>
```

#### get_credential_ids_by_account
Retrieves all credential IDs associated with an account.

```rust
pub fn get_credential_ids_by_account(
    &self,
    account_id: AccountId,
) -> Vec<String>
```

#### get_device_counter
Gets the current device counter for an account.

```rust
pub fn get_device_counter(&self, account_id: AccountId) -> u8
```

#### remove_authenticator
Removes an authenticator for the calling account (only account owner can remove their own authenticators).

```rust
pub fn remove_authenticator(&mut self, credential_id: String) -> bool
```

### Admin Functions

#### get_owner
Returns the contract owner account ID.

```rust
pub fn get_owner(&self) -> &AccountId
```

#### transfer_ownership
Transfers contract ownership to a new account (only current owner can call).

```rust
pub fn transfer_ownership(&mut self, new_owner: AccountId) -> bool
```

#### add_admin
Adds a new admin (contract owner only).

```rust
pub fn add_admin(&mut self, admin_id: AccountId) -> bool
```

#### remove_admin
Removes an admin (contract owner only).

```rust
pub fn remove_admin(&mut self, admin_id: AccountId) -> bool
```

#### is_admin
Checks if an account is an admin.

```rust
pub fn is_admin(&self, account_id: AccountId) -> bool
```

#### get_admins
Retrieves all admin account IDs.

```rust
pub fn get_admins(&self) -> Vec<AccountId>
```

#### set_vrf_settings
Updates VRF settings (admin only).

```rust
pub fn set_vrf_settings(&mut self, settings: VRFSettings)
```

#### get_vrf_settings
Retrieves current VRF settings.

```rust
pub fn get_vrf_settings(&self) -> &VRFSettings
```

#### get_allowed_origins
Retrieves the list of allowed origins.

```rust
pub fn get_allowed_origins(&self) -> Vec<String>
```

#### add_allowed_origin
Adds a single allowed origin (admin only).

```rust
#[payable]
pub fn add_allowed_origin(&mut self, origin: String) -> bool
```

#### remove_allowed_origin
Removes a single allowed origin (admin only).

```rust
#[payable]
pub fn remove_allowed_origin(&mut self, origin: String) -> bool
```

#### set_allowed_origins
Replaces the full set of allowed origins (admin only).

```rust
#[payable]
pub fn set_allowed_origins(&mut self, origins: Vec<String>) -> bool
```

### Utility Functions

#### get_greeting
Retrieves the contract greeting.

```rust
pub fn get_greeting(&self) -> Option<String>
```

#### set_greeting
Sets the contract greeting.

```rust
pub fn set_greeting(&mut self, greeting: String)
```

#### get_contract_state
Retrieves comprehensive contract state statistics.

```rust
pub fn get_contract_state(&self) -> serde_json::Value
```

## Response Structures

### VerifyRegistrationResponse
```rust
pub struct VerifyRegistrationResponse {
    pub verified: bool,
    pub registration_info: Option<RegistrationInfo>,
}
```

### VerifyCanRegisterResponse
```rust
pub struct VerifyCanRegisterResponse {
    pub verified: bool,
    pub user_exists: bool,
}
```

### VerifiedAuthenticationResponse
```rust
pub struct VerifiedAuthenticationResponse {
    pub verified: bool,
    pub authentication_info: Option<AuthenticationInfo>,
}
```

### RegistrationInfo
```rust
pub struct RegistrationInfo {
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
}
```

### AuthenticationInfo
```rust
pub struct AuthenticationInfo {
    pub credential_id: Vec<u8>,
    pub new_counter: u32,
    pub user_verified: bool,
    pub credential_device_type: String,
    pub credential_backed_up: bool,
    pub origin: String,
    pub rp_id: String,
}
```

## Configuration Structures

### VRFSettings
```rust
pub struct VRFSettings {
    pub max_input_age_ms: u64,                    // Max age for VRF input (default: 5 min)
    pub max_block_age: u64,                       // Max block age (default: 200 blocks)
    pub enabled: bool,                            // VRF feature flag (default: true)
    pub max_authenticators_per_account: usize,    // Max authenticators per account (default: 10)
}
```

### AuthenticatorOptions
```rust
pub struct AuthenticatorOptions {
    pub user_verification: Option<UserVerificationPolicy>,  // User verification requirement
    pub origin_policy: Option<OriginPolicyInput>,          // Origin validation policy
}
```

When `authenticator_options` is `None` or omitted, defaults are used:
- `user_verification`: `Preferred` (UV preferred but not required)
- `origin_policy`: `allSubdomains: true` (allows all subdomains of the RP ID)
