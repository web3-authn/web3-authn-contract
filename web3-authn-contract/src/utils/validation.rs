use near_sdk::{env, log};

// ============================================================================
// WEBAUTHN COMMON VALIDATION FUNCTIONS (REFACTORED FROM AUTH/REGISTRATION)
// ============================================================================

use crate::utils::parsers::{decode_client_data_json, parse_authenticator_data, ClientDataJSON};
use crate::contract_state::{OriginPolicy, UserVerificationPolicy};

/// Validate client data JSON and challenge for WebAuthn operations
/// Returns (client_data, client_data_json_bytes) on success
pub fn validate_webauthn_client_data(
    client_data_json_b64: &str,
    expected_challenge: &str,
    expected_type: &str, // "webauthn.get" or "webauthn.create"
) -> Result<(ClientDataJSON, Vec<u8>), String> {
    // Step 1: Parse and validate clientDataJSON
    let (client_data, client_data_json_bytes) = decode_client_data_json(client_data_json_b64)?;

    // Step 2: Verify type
    if client_data.type_ != expected_type {
        return Err(format!("Invalid type: expected {}, got {}", expected_type, client_data.type_));
    }

    // Step 3: Verify challenge matches expected_challenge
    if client_data.challenge != expected_challenge {
        return Err(format!("Challenge mismatch: expected {}, got {}", expected_challenge, client_data.challenge));
    }

    Ok((client_data, client_data_json_bytes))
}

/// Validate origin against OriginPolicy (new flexible configuration)
pub fn validate_origin_policy(
    client_origin: &str,
    origin_policy: &OriginPolicy,
    expected_rp_id: &str,
) -> Result<(), String> {
    // WebAuthn requires HTTPS
    if !client_origin.starts_with("https://") {
        return Err(format!("Origin must use HTTPS: {}", client_origin));
    }

    // Check if client origin is allowed based on policy
    let origin_allowed = match origin_policy {
        OriginPolicy::Single(allowed_origin) => {
            // Allow only the exact origin specified
            client_origin == allowed_origin
        }
        OriginPolicy::Multiple(allowed_origins) => {
            // Check if origin is in the whitelist
            allowed_origins.iter().any(|allowed_origin| {
                client_origin == allowed_origin
            })
        }
        OriginPolicy::AllSubdomains => {
            // Allow any subdomain of the RP ID
            if !client_origin.contains(expected_rp_id) {
                return Err(format!("Credential origin '{}' does not match RP ID '{}'", client_origin, expected_rp_id));
            }
            client_origin.ends_with(&expected_rp_id)
        }
    };

    if !origin_allowed {
        match origin_policy {
            OriginPolicy::Single(allowed_origin) => {
                return Err(format!(
                    "Origin '{}' not allowed by strict policy. Expected: {}",
                    client_origin, allowed_origin
                ));
            }
            OriginPolicy::Multiple(allowed_origins) => {
                return Err(format!(
                    "Origin '{}' not in whitelist. Allowed origins: {:?}",
                    client_origin, allowed_origins
                ));
            }
            OriginPolicy::AllSubdomains => {
                return Err(format!(
                    "Origin '{}' not allowed by subdomain policy. Expected RP ID: {}",
                    client_origin, expected_rp_id
                ));
            }
        }
    }

    Ok(())
}

/// Validate RP ID against expected RP ID
/// Checks if the provided RP ID matches the expected RP ID
///
/// # Arguments
/// * `rp_id` - The RP ID to validate (can be plain text or hash)
/// * `expected_rp_id` - Expected RP ID
/// * `is_hash` - Whether the rp_id is a SHA-256 hash (true) or plain text (false)
pub fn validate_rp_id(
    rp_id: &[u8],
    expected_rp_id: &str,
    is_hash: bool,
) -> Result<(), String> {
    let rp_id_allowed = if is_hash {
        // Compare hash directly
        let expected_hash = env::sha256(expected_rp_id.as_bytes());
        rp_id == expected_hash
    } else {
        // Compare plain text
        let rp_id_str = std::str::from_utf8(rp_id)
            .map_err(|_| "Invalid UTF-8 in RP ID")?;
        rp_id_str == expected_rp_id
    };

    if !rp_id_allowed {
        if is_hash {
            return Err(format!(
                "RP ID hash not allowed. Expected RP ID: {}",
                expected_rp_id
            ));
        } else {
            let rp_id_str = std::str::from_utf8(rp_id)
                .map_err(|_| "Invalid UTF-8 in RP ID")?;
            return Err(format!(
                "RP ID '{}' not allowed. Expected RP ID: {}",
                rp_id_str, expected_rp_id
            ));
        }
    }

    Ok(())
}

/// Validate user verification and presence flags based on UserVerificationPolicy
pub fn validate_webauthn_user_flags(
    auth_data_flags: u8,
    user_verification: &UserVerificationPolicy,
) -> Result<bool, String> {
    // Check user verification based on requirement
    let user_verified = (auth_data_flags & 0x04) != 0;

    match user_verification {
        UserVerificationPolicy::Required => {
            if !user_verified {
                return Err("User verification required but not performed".to_string());
            }
        }
        UserVerificationPolicy::Preferred => {
            // UV preferred but not required - just log if not present
            if !user_verified {
                log!("User verification preferred but not performed");
            }
        }
        UserVerificationPolicy::Discouraged => {
            // UV should not be used - this is just informational
            if user_verified {
                log!("User verification performed but was discouraged");
            }
        }
    }

    // Verify user presence (UP flag must be set)
    if (auth_data_flags & 0x01) == 0 {
        return Err("User presence flag not set".to_string());
    }

    Ok(user_verified)
}

/////////////////////////////////////
/// TESTS
/////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract_state::{OriginPolicy, UserVerificationPolicy};

    #[test]
    fn test_validate_origin_policy() {
        let policy = OriginPolicy::AllSubdomains;
        let expected_rp_id = "example.com";

        // Test subdomain matching
        assert!(validate_origin_policy("https://app.example.com", &policy, expected_rp_id).is_ok());
        assert!(validate_origin_policy("https://api.example.com", &policy, expected_rp_id).is_ok());
        assert!(validate_origin_policy("https://sub.app.example.com", &policy, expected_rp_id).is_ok());
        assert!(validate_origin_policy("https://wallet.example.com", &policy, expected_rp_id).is_ok());
        assert!(validate_origin_policy("https://api.wallet.example.com", &policy, expected_rp_id).is_ok());

        // Test disallowed origins
        assert!(validate_origin_policy("https://malicious.com", &policy, expected_rp_id).is_err());
        assert!(validate_origin_policy("https://example.evil.com", &policy, expected_rp_id).is_err());

        // Test HTTP (should fail)
        assert!(validate_origin_policy("http://app.example.com", &policy, expected_rp_id).is_err());
    }

    #[test]
    fn test_validate_origin_policy_strict() {
        let policy = OriginPolicy::Single("https://app.example.com".to_string());
        let expected_rp_id = "app.example.com";

        // Test exact match allowed
        assert!(validate_origin_policy("https://app.example.com", &policy, expected_rp_id).is_ok());

        // Test subdomain not allowed with strict policy
        assert!(validate_origin_policy("https://sub.app.example.com", &policy, expected_rp_id).is_err());
        assert!(validate_origin_policy("https://api.app.example.com", &policy, expected_rp_id).is_err());
    }

    #[test]
    fn test_validate_origin_policy_whitelist() {
        let policy = OriginPolicy::Multiple(vec![
            "https://app.example.com".to_string(),
            "https://api.example.com".to_string(),
        ]);
        let expected_rp_id = "example.com";

        // Test whitelisted origins
        assert!(validate_origin_policy("https://app.example.com", &policy, expected_rp_id).is_ok());
        assert!(validate_origin_policy("https://api.example.com", &policy, expected_rp_id).is_ok());

        // Test non-whitelisted origins
        assert!(validate_origin_policy("https://wallet.example.com", &policy, expected_rp_id).is_err());
        assert!(validate_origin_policy("https://malicious.com", &policy, expected_rp_id).is_err());
    }

    #[test]
    fn test_validate_webauthn_user_flags() {
        // Test user presence flag (UP = 0x01)
        assert!(validate_webauthn_user_flags(0x01, &UserVerificationPolicy::Preferred).is_ok()); // UP set, UV not required
        assert!(validate_webauthn_user_flags(0x00, &UserVerificationPolicy::Preferred).is_err()); // UP not set

        // Test user verification flag (UV = 0x04)
        assert!(validate_webauthn_user_flags(0x05, &UserVerificationPolicy::Required).is_ok()); // UP + UV set, UV required
        assert!(validate_webauthn_user_flags(0x01, &UserVerificationPolicy::Required).is_err()); // UP set but UV not set, UV required

        // Test preferred verification
        assert!(validate_webauthn_user_flags(0x01, &UserVerificationPolicy::Preferred).is_ok()); // UP set, UV preferred but not required

        // Test discouraged verification
        assert!(validate_webauthn_user_flags(0x01, &UserVerificationPolicy::Discouraged).is_ok()); // UP set, UV discouraged
    }

    #[test]
    fn test_validate_rp_id() {
        let expected_rp_id = "example.com";

        // Test valid RP ID (plain text)
        assert!(validate_rp_id("example.com".as_bytes(), expected_rp_id, false).is_ok());

        // Test invalid RP ID (plain text)
        assert!(validate_rp_id("malicious.com".as_bytes(), expected_rp_id, false).is_err());
        assert!(validate_rp_id("example.evil.com".as_bytes(), expected_rp_id, false).is_err());

        // Test valid RP ID (hash)
        let test_rp_id = "example.com";
        let correct_hash = env::sha256(test_rp_id.as_bytes());
        let wrong_hash = vec![0u8; 32];

        assert!(validate_rp_id(&correct_hash, expected_rp_id, true).is_ok());
        assert!(validate_rp_id(&wrong_hash, expected_rp_id, true).is_err());
    }
}