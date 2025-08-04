use crate::contract_state::AuthenticatorTransport;

// WebAuthn Authentication credential (equivalent to @simplewebauthn/server types)
// Differs from WebAuthnRegistrationCredential in the "response" field
#[near_sdk::near(serializers = [json, borsh])]
#[derive(Debug, Clone)]
pub struct WebAuthnAuthenticationCredential {
    pub id: String, // Base64URL credential ID
    #[serde(rename = "rawId")]
    pub raw_id: String, // Base64URL credential ID
    pub response: AuthenticatorAssertionResponse,
    #[serde(rename = "authenticatorAttachment", skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
    #[serde(rename = "type")]
    pub type_: String, // Should be "public-key"
    #[serde(
        rename = "clientExtensionResults",
        skip_serializing_if = "Option::is_none"
    )]
    #[borsh(skip)]
    pub client_extension_results: Option<ClientExtensionResults>,
}

// WebAuthn Registration credential (equivalent to @simplewebauthn/server types)
// Differs from WebAuthnAuthenticationCredential in the "response" field
#[near_sdk::near(serializers = [json, borsh])]
#[derive(Debug, Clone)]
pub struct WebAuthnRegistrationCredential {
    pub id: String, // Base64URL credential ID
    #[serde(rename = "rawId")]
    pub raw_id: String, // Base64URL credential ID
    pub response: AuthenticatorAttestationResponse,
    #[serde(rename = "authenticatorAttachment", skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
    #[serde(rename = "type")]
    pub type_: String, // Should be "public-key"
    #[serde(
        rename = "clientExtensionResults",
        skip_serializing_if = "Option::is_none"
    )]
    #[borsh(skip)]
    pub client_extension_results: Option<ClientExtensionResults>,
}

/**
 * https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse
 */
#[near_sdk::near(serializers = [json, borsh])]
#[derive(Debug, Clone)]
pub struct AuthenticatorAssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String, // Base64URL encoded
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String, // Base64URL encoded
    pub signature: String, // Base64URL encoded
    #[serde(rename = "userHandle", skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>, // Base64URL encoded
}

/**
 * https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse
 */
#[near_sdk::near(serializers = [json, borsh])]
#[derive(Debug, Clone)]
pub struct AuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    pub transports: Option<Vec<String>>,
}

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Debug, Clone)]
pub struct AuthenticatorDevice {
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub counter: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<AuthenticatorTransport>>,
}
impl Default for AuthenticatorDevice {
    fn default() -> Self {
        Self {
            credential_id: vec![],
            credential_public_key: vec![],
            counter: 0,
            transports: None,
        }
    }
}

#[near_sdk::near(serializers = [json, borsh])]
#[derive(Debug, Clone)]
pub struct ClientExtensionResults {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf: Option<PRFExtensionResults>,
}

#[near_sdk::near(serializers = [json, borsh])]
#[derive(Debug, Clone)]
pub struct PRFExtensionResults {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<PRFResults>,
}

#[near_sdk::near(serializers = [json, borsh])]
#[derive(Debug, Clone)]
pub struct PRFResults {
    // SECURITY: Avoid deserializing PRF output. We don't send PRF output from the client.
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub first: Option<String>,
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub second: Option<String>,
}
