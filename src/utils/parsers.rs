use serde_cbor::Value as CborValue;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE;
use base64::Engine;
use serde_json;
use crate::contract_state::TldConfiguration;

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

/// Extract RP ID from origin with optional parent domain and TLD configuration
///
/// # Arguments
/// * `origin` - Origin URL (e.g., "https://app.example.com", "https://app.example.com:8443/login")
/// * `extract_parent` - If true, extracts parent domain; if false, extracts exact domain
/// * `tld_config` - Optional TLD configuration for complex domain support
///
/// # Returns
/// * `String` - Extracted RP ID
pub fn extract_rp_id(origin: &str, extract_parent: bool, tld_config: Option<&TldConfiguration>) -> String {
    // Extract domain from URL, handling paths, ports, query strings
    let domain = extract_domain_from_origin(origin);

    // For exact domain extraction, return as-is
    if !extract_parent {
        return domain;
    }

    // Handle localhost and IP addresses (no subdomain extraction)
    if domain.starts_with("localhost") || domain.parse::<std::net::IpAddr>().is_ok() {
        return domain;
    }

    // Split by dots and extract parent domain
    let parts: Vec<&str> = domain.split('.').collect();

    if parts.len() < 2 {
        return domain;
    }

    // Validate domain parts (basic sanity check)
    if !is_valid_domain_parts(&parts) {
        return domain; // Return as-is if invalid format
    }

    // Determine how many parts make up the registrable domain
    let registrable_parts = if let Some(config) = tld_config {
        if config.enabled {
            // Check for multi-part TLDs
            if parts.len() >= 3 {
                let tld = parts[parts.len() - 1];
                let second_level = parts[parts.len() - 2];

                for (sld, tld_part) in &config.multi_part_tlds {
                    if second_level == sld && tld == tld_part {
                        return if parts.len() > 3 {
                            // Extract parent domain for subdomain
                            let start_idx = parts.len() - 3;
                            parts[start_idx..].join(".")
                        } else {
                            // Already a registrable domain
                            domain
                        };
                    }
                }
            }
        }
        2 // Default to standard TLD
    } else {
        2 // Default: standard commercial TLD (domain.com)
    };

    // Extract the registrable domain (parent domain for subdomains)
    if parts.len() > registrable_parts {
        let start_idx = parts.len() - registrable_parts;
        parts[start_idx..].join(".")
    } else {
        domain
    }
}

/// Extract domain from origin URL, handling paths, ports, query strings
fn extract_domain_from_origin(origin: &str) -> String {
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

/// Basic validation for domain parts
fn is_valid_domain_parts(parts: &[&str]) -> bool {
    for part in parts {
        if part.is_empty() {
            return false; // Empty parts like "app..com"
        }

        // Check for valid ASCII alphanumerics, hyphens, and basic format
        if !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }

        // Cannot start or end with hyphen
        if part.starts_with('-') || part.ends_with('-') {
            return false;
        }
    }
    true
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
        assert_eq!(extract_rp_id("https://app.example.com", true, None), "example.com");
        assert_eq!(extract_rp_id("https://wallet.example.com", true, None), "example.com");
        assert_eq!(extract_rp_id("https://api.wallet.example.com", true, None), "example.com");

        // Test different TLDs
        assert_eq!(extract_rp_id("https://app.company.org", true, None), "company.org");
        assert_eq!(extract_rp_id("https://portal.business.net", true, None), "business.net");
        assert_eq!(extract_rp_id("https://api.service.io", true, None), "service.io");

        // Test parent domain (no change)
        assert_eq!(extract_rp_id("https://example.com", true, None), "example.com");
        assert_eq!(extract_rp_id("https://company.org", true, None), "company.org");

        // Test localhost (no change)
        assert_eq!(extract_rp_id("https://localhost:3000", true, None), "localhost:3000");
        assert_eq!(extract_rp_id("http://localhost", true, None), "localhost");

        // Test without protocol
        assert_eq!(extract_rp_id("app.example.com", true, None), "example.com");
        assert_eq!(extract_rp_id("example.com", true, None), "example.com");

        // Test edge cases
        assert_eq!(extract_rp_id("domain", true, None), "domain");

        println!("Parent domain extraction tests passed!");
    }

    #[test]
    fn test_extract_rp_id_exact_domains() {
        // Test exact domain extraction
        assert_eq!(extract_rp_id("https://app.example.com", false, None), "app.example.com");
        assert_eq!(extract_rp_id("https://wallet.example.com", false, None), "wallet.example.com");
        assert_eq!(extract_rp_id("https://example.com", false, None), "example.com");
        assert_eq!(extract_rp_id("http://localhost:3000", false, None), "localhost:3000");

        // Test URL parsing fixes - paths, ports, query strings
        assert_eq!(extract_rp_id("https://app.example.com/login", false, None), "app.example.com");
        assert_eq!(extract_rp_id("https://app.example.com:8443", false, None), "app.example.com:8443");
        assert_eq!(extract_rp_id("https://app.example.com:8443/api/auth", false, None), "app.example.com:8443");
        assert_eq!(extract_rp_id("https://app.example.com?token=123", false, None), "app.example.com");
        assert_eq!(extract_rp_id("https://app.example.com#section", false, None), "app.example.com");
        assert_eq!(extract_rp_id("https://app.example.com/login?token=123#section", false, None), "app.example.com");

        println!("Exact domain extraction tests passed!");
    }

    #[test]
    fn test_tld_configuration() {
        // Test complex TLD configuration
        let config = TldConfiguration {
            enabled: true,
            multi_part_tlds: vec![
                ("co".to_string(), "uk".to_string()),
                ("gov".to_string(), "uk".to_string()),
                ("com".to_string(), "au".to_string()),
            ],
        };

        // Test UK domains
        assert_eq!(extract_rp_id("https://app.bbc.co.uk", true, Some(&config)), "bbc.co.uk");
        assert_eq!(extract_rp_id("https://portal.hmrc.gov.uk", true, Some(&config)), "hmrc.gov.uk");

        // Test AU domains
        assert_eq!(extract_rp_id("https://app.westpac.com.au", true, Some(&config)), "westpac.com.au");

        // Test standard domains still work
        assert_eq!(extract_rp_id("https://app.example.com", true, Some(&config)), "example.com");

        // Test without TLD config (standard behavior)
        assert_eq!(extract_rp_id("https://app.bbc.co.uk", true, None), "co.uk");

        println!("TLD configuration tests passed!");
    }

    #[test]
    fn test_domain_validation_and_edge_cases() {
        // Test valid domains
        assert_eq!(extract_rp_id("https://valid-domain.com", true, None), "valid-domain.com");
        assert_eq!(extract_rp_id("https://app.valid-domain.com", true, None), "valid-domain.com");

        // Test invalid domains (should return as-is, not crash)
        assert_eq!(extract_rp_id("https://invalid..domain.com", true, None), "invalid..domain.com");
        assert_eq!(extract_rp_id("https://-invalid.com", true, None), "-invalid.com");
        assert_eq!(extract_rp_id("https://invalid-.com", true, None), "invalid-.com");
        assert_eq!(extract_rp_id("https://", true, None), "");

        // Test malformed URLs
        assert_eq!(extract_rp_id("not-a-url", true, None), "not-a-url");
        assert_eq!(extract_rp_id("", true, None), "");

        println!("Domain validation tests passed!");
    }
}
