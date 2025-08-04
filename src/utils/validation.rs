use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE;
use base64::Engine;
use near_sdk::env;

// ============================================================================
// WEBAUTHN COMMON VALIDATION FUNCTIONS (REFACTORED FROM AUTH/REGISTRATION)
// ============================================================================

use crate::utils::parsers::{decode_client_data_json, extract_rp_id, parse_authenticator_data, ClientDataJSON};
use crate::contract_state::TldConfiguration;

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

/// Validate origin matches expected pattern with TLD configuration support
pub fn validate_webauthn_origin(
    client_origin: &str,
    expected_origin: &str,
    expected_rp_id: &str,
    tld_config: Option<&TldConfiguration>,
) -> Result<(), String> {
    // Extract parent domain from client origin
    let client_parent_domain = extract_rp_id(client_origin, true, tld_config);

    // Check if origin is valid (exact match OR parent domain match)
    let origin_valid = client_origin == expected_origin // Exact match (backward compatibility)
        || client_parent_domain == expected_rp_id; // Parent domain match (subdomain support)

    if !origin_valid {
        return Err(format!(
            "Origin verification failed: client origin '{}' (parent: '{}') does not match expected origin '{}' or RP ID '{}'",
            client_origin, client_parent_domain, expected_origin, expected_rp_id
        ));
    }

    Ok(())
}

/// Validate authenticator data RP ID hash
pub fn validate_webauthn_rp_id_hash(
    auth_data_rp_id_hash: &[u8],
    expected_rp_id: &str,
) -> Result<(), String> {
    let expected_rp_id_hash = env::sha256(expected_rp_id.as_bytes());
    if auth_data_rp_id_hash != expected_rp_id_hash {
        return Err("RP ID hash mismatch".to_string());
    }
    Ok(())
}

/// Validate user verification and presence flags
pub fn validate_webauthn_user_flags(
    auth_data_flags: u8,
    require_user_verification: bool,
) -> Result<bool, String> {
    // Check user verification if required
    let user_verified = (auth_data_flags & 0x04) != 0;
    if require_user_verification && !user_verified {
        return Err("User verification required but not performed".to_string());
    }

    // Verify user presence (UP flag must be set)
    if (auth_data_flags & 0x01) == 0 {
        return Err("User presence flag not set".to_string());
    }

    Ok(user_verified)
}

/// Parse and validate authenticator data from base64url
pub fn validate_webauthn_authenticator_data(
    authenticator_data_b64: &str,
    expected_rp_id: &str,
    require_user_verification: bool,
) -> Result<(crate::utils::parsers::AuthenticatorData, Vec<u8>, bool), String> {
    // Decode authenticator data
    let authenticator_data_bytes = BASE64_URL_ENGINE.decode(authenticator_data_b64)
        .map_err(|_| "Failed to decode authenticatorData from base64url".to_string())?;

    // Parse authenticator data
    let auth_data = parse_authenticator_data(&authenticator_data_bytes)?;

    // Validate RP ID hash
    validate_webauthn_rp_id_hash(&auth_data.rp_id_hash, expected_rp_id)?;

    // Validate user verification and presence flags
    let user_verified = validate_webauthn_user_flags(auth_data.flags, require_user_verification)?;

    Ok((auth_data, authenticator_data_bytes, user_verified))
}

/////////////////////////////////////
/// TESTS
/////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_webauthn_user_flags() {
        // Test user presence flag (UP = 0x01)
        assert!(validate_webauthn_user_flags(0x01, false).is_ok()); // UP set, UV not required
        assert!(validate_webauthn_user_flags(0x00, false).is_err()); // UP not set

        // Test user verification flag (UV = 0x04)
        assert!(validate_webauthn_user_flags(0x05, true).is_ok()); // UP + UV set, UV required
        assert!(validate_webauthn_user_flags(0x01, true).is_err()); // UP set but UV not set, UV required
    }

    #[test]
    fn test_validate_webauthn_rp_id_hash() {
        let test_rp_id = "example.com";
        let correct_hash = env::sha256(test_rp_id.as_bytes());
        let wrong_hash = vec![0u8; 32];

        assert!(validate_webauthn_rp_id_hash(&correct_hash, test_rp_id).is_ok());
        assert!(validate_webauthn_rp_id_hash(&wrong_hash, test_rp_id).is_err());
    }
}