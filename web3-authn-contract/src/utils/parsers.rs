use serde_cbor::Value as CborValue;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE;
use base64::Engine;
use serde_json;

// WebAuthn client data structure
#[near_sdk::near(serializers = [json, borsh])]
#[derive(Debug)]
pub struct ClientDataJSON {
    #[serde(rename = "type")]
    pub type_: String,
    pub challenge: String,
    pub origin: String,
    #[serde(rename = "crossOrigin", default)]
    pub cross_origin: bool,
}

#[derive(Debug)]
pub struct AttestedCredentialData {
    pub(crate) _aaguid: Vec<u8>,
    pub(crate) credential_id: Vec<u8>,
    pub(crate) credential_public_key: Vec<u8>,
}

#[derive(Debug)]
pub struct AuthenticatorData {
    pub(crate) rp_id_hash: Vec<u8>,
    pub(crate) flags: u8,
    pub(crate) counter: u32,
    pub(crate) attested_credential_data: Option<AttestedCredentialData>,
}

pub fn parse_attestation_object(
    attestation_object: &CborValue
) -> Result<(Vec<u8>, CborValue, String), String> {
    if let CborValue::Map(map) = attestation_object {
        // Extract authData (required)
        let auth_data = map
            .get(&CborValue::Text("authData".to_string()))
            .ok_or("Missing authData in attestation object")?;

        let auth_data_bytes = if let CborValue::Bytes(bytes) = auth_data {
            bytes.clone()
        } else {
            return Err("authData must be bytes".to_string());
        };

        // Extract fmt (required)
        let fmt = map
            .get(&CborValue::Text("fmt".to_string()))
            .ok_or("Missing fmt in attestation object")?;

        let fmt_string = if let CborValue::Text(s) = fmt {
            s.clone()
        } else {
            return Err("fmt must be text".to_string());
        };

        // Extract attStmt (required)
        let att_stmt = map
            .get(&CborValue::Text("attStmt".to_string()))
            .ok_or("Missing attStmt in attestation object")?
            .clone();

        Ok((auth_data_bytes, att_stmt, fmt_string))
    } else {
        Err("Attestation object must be a CBOR map".to_string())
    }
}

pub fn parse_authenticator_data(auth_data_bytes: &[u8]) -> Result<AuthenticatorData, String> {
    if auth_data_bytes.len() < 37 {
        return Err("Authenticator data too short".to_string());
    }

    // Parse fixed-length portion
    let rp_id_hash = auth_data_bytes[0..32].to_vec();
    let flags = auth_data_bytes[32];
    let counter = u32::from_be_bytes([
        auth_data_bytes[33],
        auth_data_bytes[34],
        auth_data_bytes[35],
        auth_data_bytes[36],
    ]);

    let mut offset = 37;
    let mut attested_credential_data = None;

    // Check if attested credential data is present (AT flag = bit 6)
    if (flags & 0x40) != 0 {
        if auth_data_bytes.len() < offset + 18 {
            return Err("Authenticator data too short for attested credential data".to_string());
        }

        // Parse attested credential data
        let aaguid = auth_data_bytes[offset..offset + 16].to_vec();
        offset += 16;

        let credential_id_length =
            u16::from_be_bytes([auth_data_bytes[offset], auth_data_bytes[offset + 1]]) as usize;
        offset += 2;

        if auth_data_bytes.len() < offset + credential_id_length {
            return Err("Authenticator data too short for credential ID".to_string());
        }

        let credential_id = auth_data_bytes[offset..offset + credential_id_length].to_vec();
        offset += credential_id_length;

        // The rest is the credential public key (COSE format)
        let credential_public_key = auth_data_bytes[offset..].to_vec();

        attested_credential_data = Some(AttestedCredentialData {
            _aaguid: aaguid,
            credential_id,
            credential_public_key,
        });
    }

    Ok(AuthenticatorData {
        rp_id_hash,
        flags,
        counter,
        attested_credential_data,
    })
}

/// Decodes and parses clientDataJSON from a WebAuthn response
///
/// # Arguments
/// * `client_data_json_b64url` - Base64URL-encoded clientDataJSON string
///
/// # Returns
/// * `Result<(ClientDataJSON, Vec<u8>), String>` - Parsed client data and bytes, or error message
///
/// # Errors
/// * Returns error string if base64 decoding fails
/// * Returns error string if JSON parsing fails
pub fn decode_client_data_json(client_data_json_b64url: &str) -> Result<(ClientDataJSON, Vec<u8>), String> {
    // Decode base64url-encoded clientDataJSON
    let client_data_json_bytes = match BASE64_URL_ENGINE.decode(client_data_json_b64url) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err("Failed to decode clientDataJSON from base64url".to_string());
        }
    };

    // Parse JSON into ClientDataJSON struct
    let client_data: ClientDataJSON = match serde_json::from_slice(&client_data_json_bytes) {
        Ok(data) => data,
        Err(e) => {
            return Err(format!("Failed to parse clientDataJSON: {}", e));
        }
    };

    Ok((client_data, client_data_json_bytes))
}

/// Extract RP ID from origin URL
///
/// # Arguments
/// * `origin` - Origin URL (e.g., "https://app.example.com", "https://app.example.com:8443/login")
///
/// # Returns
/// * `String` - Extracted RP ID
pub fn extract_rp_id(origin: &str) -> String {
    // Remove protocol
    let without_protocol = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .unwrap_or(origin);

    // Split on first '/' to remove path, query string, fragment
    let domain_with_port = without_protocol
        .split_once('/')
        .map(|(domain_part, _)| domain_part)
        .unwrap_or(without_protocol);

    // Split on first '?' to remove query string (in case no path)
    let domain_with_port = domain_with_port
        .split_once('?')
        .map(|(domain_part, _)| domain_part)
        .unwrap_or(domain_with_port);

    // Split on first '#' to remove fragment (in case no path or query)
    let domain_with_port = domain_with_port
        .split_once('#')
        .map(|(domain_part, _)| domain_part)
        .unwrap_or(domain_with_port);

    domain_with_port.to_string()
}

/// Extract RP ID from WebAuthn registration data
/// First tries to get rpId from client data, falls back to origin hostname
///
/// # Arguments
/// * `webauthn_registration` - WebAuthn registration credential
///
/// # Returns
/// * `Result<String, String>` - Extracted RP ID or error message
pub fn extract_rp_id_and_origin_from_webauthn(
    webauthn_registration: &crate::types::WebAuthnRegistrationCredential,
) -> Result<(String, String), String> {
    // Decode clientDataJSON from base64url
    let client_data_json = BASE64_URL_ENGINE
        .decode(&webauthn_registration.response.client_data_json)
        .map_err(|_| "Failed to decode client data JSON".to_string())?;

    let client_data_str = String::from_utf8(client_data_json)
        .map_err(|_| "Invalid UTF-8 in client data JSON".to_string())?;

    let client_data: serde_json::Value = serde_json::from_str(&client_data_str)
        .map_err(|_| "Failed to parse client data JSON".to_string())?;

    // Extract origin
    let origin = client_data
        .get("origin")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Origin missing from clientDataJSON".to_string())?
        .to_string();

    // Derive rp_id from the origin (strip https:// and port, if present)
    let rp_id = extract_rp_id_from_origin(&origin)?;

    Ok((rp_id, origin))
}

pub fn extract_rp_id_from_origin(origin: &str) -> Result<String, String> {
    let origin = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .ok_or_else(|| "Invalid origin scheme (must be https)".to_string())?;

    // Remove port, if present
    let rp_id = origin.split(':').next().unwrap_or(origin);

    Ok(rp_id.to_string())
}

////////////////////////////
/// Tests
////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_rp_id_parent_domains() {
        // Test standard commercial domain subdomain extraction
        assert_eq!(extract_rp_id("https://app.example.com"), "app.example.com");
        assert_eq!(extract_rp_id("https://wallet.example.com"), "wallet.example.com");
        assert_eq!(extract_rp_id("https://api.wallet.example.com"), "api.wallet.example.com");

        // Test different TLDs
        assert_eq!(extract_rp_id("https://app.company.org"), "app.company.org");
        assert_eq!(extract_rp_id("https://portal.business.net"), "portal.business.net");
        assert_eq!(extract_rp_id("https://api.service.io"), "api.service.io");

        // Test parent domain (no change)
        assert_eq!(extract_rp_id("https://example.com"), "example.com");
        assert_eq!(extract_rp_id("https://company.org"), "company.org");

        // Test localhost (no change)
        assert_eq!(extract_rp_id("https://localhost:3000"), "localhost:3000");
        assert_eq!(extract_rp_id("http://localhost"), "localhost");

        // Test without protocol
        assert_eq!(extract_rp_id("app.example.com"), "app.example.com");
        assert_eq!(extract_rp_id("example.com"), "example.com");

        // Test edge cases
        assert_eq!(extract_rp_id("domain"), "domain");

        println!("Parent domain extraction tests passed!");
    }

    #[test]
    fn test_extract_rp_id_exact_domains() {
        // Test exact domain extraction
        assert_eq!(extract_rp_id("https://app.example.com"), "app.example.com");
        assert_eq!(extract_rp_id("https://wallet.example.com"), "wallet.example.com");
        assert_eq!(extract_rp_id("https://example.com"), "example.com");
        assert_eq!(extract_rp_id("http://localhost:3000"), "localhost:3000");

        // Test URL parsing fixes - paths, ports, query strings
        assert_eq!(extract_rp_id("https://app.example.com/login"), "app.example.com");
        assert_eq!(extract_rp_id("https://app.example.com:8443"), "app.example.com:8443");
        assert_eq!(extract_rp_id("https://app.example.com:8443/api/auth"), "app.example.com:8443");
        assert_eq!(extract_rp_id("https://app.example.com?token=123"), "app.example.com");
        assert_eq!(extract_rp_id("https://app.example.com#section"), "app.example.com");
        assert_eq!(extract_rp_id("https://app.example.com/login?token=123#section"), "app.example.com");

        println!("Exact domain extraction tests passed!");
    }

    #[test]
    fn test_domain_validation_and_edge_cases() {
        // Test valid domains
        assert_eq!(extract_rp_id("https://valid-domain.com"), "valid-domain.com");
        assert_eq!(extract_rp_id("https://app.valid-domain.com"), "app.valid-domain.com");

        // Test invalid domains (should return as-is, not crash)
        assert_eq!(extract_rp_id("https://invalid..domain.com"), "invalid..domain.com");
        assert_eq!(extract_rp_id("https://-invalid.com"), "-invalid.com");
        assert_eq!(extract_rp_id("https://invalid-.com"), "invalid-.com");
        assert_eq!(extract_rp_id("https://"), "");

        // Test malformed URLs
        assert_eq!(extract_rp_id("not-a-url"), "not-a-url");
        assert_eq!(extract_rp_id(""), "");

        println!("Domain validation tests passed!");
    }
}
