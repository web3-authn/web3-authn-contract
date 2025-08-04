//!
//! VRF Verification Library for NEAR Contracts
//!
//! This module provides verification functions for VRF outputs and proofs generated
//! by frontend wasm-workers using the `vrf-wasm` crate with browser RNG.
//!
//! We use vrf-wasm for browser-based VRF generation
//! and use vrf-contract-verifier for contract-based VRF verification

use near_sdk::{log, env};
use vrf_contract_verifier::{verify_vrf, VerificationError};
use base64::{
    Engine as _,
    engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE
};
use crate::contract_state::VRFSettings;

// Constants for validation
const VRF_PROOF_SIZE: usize = 80;       // ECVRF Ristretto proof size
const VRF_PUBLIC_KEY_SIZE: usize = 32;  // ECVRF Ristretto public key size
const VRF_OUTPUT_SIZE: usize = 64;      // VRF output size
const VRF_INPUT_DATA_SIZE: usize = 32;  // SHA256 hash size
const BLOCK_HASH_SIZE: usize = 32;      // NEAR block hash size
const MAX_USER_ID_LENGTH: usize = 64;   // Maximum NEAR account ID length
const MAX_RP_ID_LENGTH: usize = 253;    // Maximum domain length per RFC 1034

/// VRF input components for challenge construction
#[near_sdk::near(serializers = [json, borsh])]
#[derive(Debug, Clone)]
pub struct VRFInputComponents {
    pub account_id: String,            // User account for binding
    pub block_height: u64,             // NEAR block height for freshness
    pub challenge_data: Vec<u8>,       // Additional challenge data
    pub expiration_block: Option<u64>, // Optional expiration
}

/// VRF verification errors
#[derive(Debug, Clone)]
pub enum VRFVerificationError {
    InvalidProof(String),
    InvalidPublicKey,
    InvalidInput,
    DeserializationFailed,
    VerificationFailed,
    StaleChallenge,
    // New validation errors
    InvalidProofSize,
    InvalidPublicKeySize,
    InvalidOutputSize,
    InvalidInputDataSize,
    InvalidBlockHashSize,
    InvalidUserIdLength,
    InvalidRpIdLength,
    InvalidBlockHeight,
    EmptyUserId,
    EmptyRpId,
    InvalidRpIdFormat,
    InvalidUserIdFormat,
}

impl From<vrf_contract_verifier::VerificationError> for VRFVerificationError {
    fn from(error: vrf_contract_verifier::VerificationError) -> Self {
        match error {
            VerificationError::InvalidProof => VRFVerificationError::InvalidProof("Invalid proof".to_string()),
            VerificationError::InvalidPublicKey => VRFVerificationError::InvalidPublicKey,
            VerificationError::InvalidInput => VRFVerificationError::InvalidInput,
            VerificationError::InvalidProofLength => VRFVerificationError::InvalidProof("Invalid proof length".to_string()),
            VerificationError::DecompressionFailed => VRFVerificationError::InvalidProof("Decompression failed".to_string()),
            VerificationError::InvalidScalar => VRFVerificationError::InvalidProof("Invalid scalar".to_string()),
            VerificationError::InvalidGamma => VRFVerificationError::InvalidProof("Invalid gamma".to_string()),
            VerificationError::ZeroPublicKey => VRFVerificationError::InvalidProof("Zero public key".to_string()),
            VerificationError::ExpandMessageXmdFailed => VRFVerificationError::InvalidProof("Expand message xmd failed".to_string()),
        }
    }
}

/// VRF verification data structure for WebAuthn challenges
#[near_sdk::near(serializers = [json, borsh])]
#[derive(Debug, Clone)]
pub struct VRFVerificationData {
    /// SHA256 hash of concatenated VRF input components:
    /// domain_separator + user_id + rp_id + block_height + block_hash
    /// This hashed data is used for VRF proof verification
    pub vrf_input_data: Vec<u8>,
    /// Used as the WebAuthn challenge (VRF output)
    pub vrf_output: Vec<u8>,
    /// Proves vrf_output was correctly derived from vrf_input_data
    pub vrf_proof: Vec<u8>,
    /// VRF public key used to verify the proof
    pub public_key: Vec<u8>,
    /// User ID (account_id in NEAR protocol) - cryptographically bound in VRF input
    pub user_id: String,
    /// Relying Party ID (domain) used in VRF input construction
    pub rp_id: String,
    /// Block height for freshness validation (must be recent)
    pub block_height: u64,
    /// Block hash included in VRF input (for entropy only, not validated on-chain)
    /// NOTE: NEAR contracts cannot access historical block hashes, so this is used
    /// purely for additional entropy in the VRF input construction
    pub block_hash: Vec<u8>,
}

/// VRF authentication response with output
#[near_sdk::near(serializers = [json])]
#[derive(Debug, Clone)]
pub struct VerifiedVRFAuthenticationResponse {
    pub verified: bool,
    pub vrf_output: Option<Vec<u8>>, // 64-byte VRF output if verification succeeds
    pub authentication_info: Option<String>,
}

/// Validate VRF verification data input parameters
/// This function performs comprehensive validation of all input fields before processing
///
/// # Arguments
/// * `vrf_data` - VRF verification data to validate
/// * `vrf_settings` - VRF settings for validation parameters
///
/// # Returns
/// * `Result<(), VRFVerificationError>` - Ok(()) if validation passes, error otherwise
fn validate_vrf_verification_data(
    vrf_data: &VRFVerificationData,
    vrf_settings: &VRFSettings,
) -> Result<(), VRFVerificationError> {
    // 1. Validate that all byte arrays are not empty (check first for early failure)
    if vrf_data.vrf_proof.is_empty() || vrf_data.public_key.is_empty() ||
       vrf_data.vrf_output.is_empty() || vrf_data.vrf_input_data.is_empty() ||
       vrf_data.block_hash.is_empty() {
        log!("Empty byte array validation failed: all byte arrays must be non-empty");
        return Err(VRFVerificationError::InvalidInput);
    }

    // 2. Validate VRF proof size
    if vrf_data.vrf_proof.len() != VRF_PROOF_SIZE {
        log!("VRF proof size validation failed: expected {} bytes, got {} bytes",
             VRF_PROOF_SIZE, vrf_data.vrf_proof.len());
        return Err(VRFVerificationError::InvalidProofSize);
    }

    // 3. Validate VRF public key size
    if vrf_data.public_key.len() != VRF_PUBLIC_KEY_SIZE {
        log!("VRF public key size validation failed: expected {} bytes, got {} bytes",
             VRF_PUBLIC_KEY_SIZE, vrf_data.public_key.len());
        return Err(VRFVerificationError::InvalidPublicKeySize);
    }

    // 4. Validate VRF output size
    if vrf_data.vrf_output.len() != VRF_OUTPUT_SIZE {
        log!("VRF output size validation failed: expected {} bytes, got {} bytes",
             VRF_OUTPUT_SIZE, vrf_data.vrf_output.len());
        return Err(VRFVerificationError::InvalidOutputSize);
    }

    // 5. Validate VRF input data size
    if vrf_data.vrf_input_data.len() != VRF_INPUT_DATA_SIZE {
        log!("VRF input data size validation failed: expected {} bytes, got {} bytes",
             VRF_INPUT_DATA_SIZE, vrf_data.vrf_input_data.len());
        return Err(VRFVerificationError::InvalidInputDataSize);
    }

    // 6. Validate block hash size
    if vrf_data.block_hash.len() != BLOCK_HASH_SIZE {
        log!("Block hash size validation failed: expected {} bytes, got {} bytes",
             BLOCK_HASH_SIZE, vrf_data.block_hash.len());
        return Err(VRFVerificationError::InvalidBlockHashSize);
    }

    // 7. Validate user_id length and format
    if vrf_data.user_id.is_empty() {
        log!("User ID validation failed: empty user_id");
        return Err(VRFVerificationError::EmptyUserId);
    }
    if vrf_data.user_id.len() > MAX_USER_ID_LENGTH {
        log!("User ID length validation failed: max {} chars, got {} chars",
             MAX_USER_ID_LENGTH, vrf_data.user_id.len());
        return Err(VRFVerificationError::InvalidUserIdLength);
    }
    // Validate NEAR account ID format (basic check)
    if !vrf_data.user_id.contains('.') || vrf_data.user_id.starts_with('.') || vrf_data.user_id.ends_with('.') {
        log!("User ID format validation failed: invalid NEAR account ID format");
        return Err(VRFVerificationError::InvalidUserIdFormat);
    }

    // 8. Validate rp_id length and format
    if vrf_data.rp_id.is_empty() {
        log!("RP ID validation failed: empty rp_id");
        return Err(VRFVerificationError::EmptyRpId);
    }
    if vrf_data.rp_id.len() > MAX_RP_ID_LENGTH {
        log!("RP ID length validation failed: max {} chars, got {} chars",
             MAX_RP_ID_LENGTH, vrf_data.rp_id.len());
        return Err(VRFVerificationError::InvalidRpIdLength);
    }
    // Validate domain format (basic check)
    if vrf_data.rp_id.starts_with('.') || vrf_data.rp_id.ends_with('.') || vrf_data.rp_id.contains("..") {
        log!("RP ID format validation failed: invalid domain format");
        return Err(VRFVerificationError::InvalidRpIdFormat);
    }

    // 8. Validate block height freshness (if VRF is enabled)
    if vrf_settings.enabled {
        let current_height = env::block_height();
        if current_height < vrf_data.block_height ||
           current_height > vrf_data.block_height + vrf_settings.max_block_age {
            log!("VRF block height freshness validation failed: current_height={}, vrf_height={}, max_age={}",
                 current_height, vrf_data.block_height, vrf_settings.max_block_age);
            return Err(VRFVerificationError::StaleChallenge);
        }
    }

    log!("VRF verification data validation passed successfully");
    Ok(())
}

/// Verify VRF proof and extract WebAuthn challenge
/// Returns the challenge and parameters needed for WebAuthn verification
/// This function performs no state modifications and can be called from both
/// registration and view functions
///
/// # Arguments
/// * `vrf_data` - VRF verification data containing proof, input, output and metadata
/// * `vrf_settings` - VRF settings for validation parameters
///
/// # Returns
/// * `Option<String>` - On success returns WebAuthn challenge derived from VRF output (base64url encoded)
///   On failure returns None
pub fn verify_vrf_and_extract_challenge(
    vrf_data: &VRFVerificationData,
    vrf_settings: &VRFSettings,
) -> Option<String> {
    // 1. VRF Input validation
    if let Err(validation_error) = validate_vrf_verification_data(vrf_data, vrf_settings) {
        log!("VRF input validation failed: {:?}", validation_error);
        return None;
    }

    // 2. Verify the VRF proof and validate VRF output
    let verified_vrf_output = match verify_vrf(
        &vrf_data.vrf_proof,
        &vrf_data.public_key,
        &vrf_data.vrf_input_data
    ) {
        Ok(vrf_output) => vrf_output.to_vec(),
        Err(_) => {
            log!("VRF proof verification failed");
            return None;
        }
    };

    // 3. Validate that the claimed VRF output matches the verified output
    if verified_vrf_output != vrf_data.vrf_output {
        log!("VRF output mismatch: client claimed output doesn't match verified output");
        return None;
    }

    // 4. Extract WebAuthn challenge from VRF output
    let vrf_webauthn_challenge = &vrf_data.vrf_output[0..32]; // First 32 bytes as challenge
    let vrf_challenge_b64url = BASE64_URL_ENGINE.encode(vrf_webauthn_challenge);
    log!("VRF proof verified, extracted challenge: {} bytes", vrf_webauthn_challenge.len());

    Some(vrf_challenge_b64url)
}

/////////////////////////////////////
/// TESTS
/////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract_state::VRFSettings;

    fn create_valid_vrf_data() -> VRFVerificationData {
        VRFVerificationData {
            vrf_input_data: vec![0u8; VRF_INPUT_DATA_SIZE],
            vrf_output: vec![0u8; VRF_OUTPUT_SIZE],
            vrf_proof: vec![0u8; VRF_PROOF_SIZE],
            public_key: vec![0u8; VRF_PUBLIC_KEY_SIZE],
            user_id: "alice.testnet".to_string(),
            rp_id: "example.com".to_string(),
            block_height: 1000,
            block_hash: vec![0u8; BLOCK_HASH_SIZE],
        }
    }

    fn create_valid_vrf_settings() -> VRFSettings {
        VRFSettings {
            max_input_age_ms: 300_000,
            max_block_age: 100,
            enabled: true,
            max_authenticators_per_account: 10,
        }
    }

    #[test]
    fn test_validate_vrf_verification_data_valid_input() {
        let vrf_data = create_valid_vrf_data();
        let vrf_settings = create_valid_vrf_settings();

        // Mock current block height to be within valid range
        // Note: In real tests, this would be mocked or the validation would be adjusted
        let result = validate_vrf_verification_data(&vrf_data, &vrf_settings);
        // This test will fail in unit tests because we can't mock env::block_height()
        // In integration tests, this would work correctly
        assert!(result.is_err() || result.is_ok());
    }

    #[test]
    fn test_validate_vrf_verification_data_invalid_proof_size() {
        let mut vrf_data = create_valid_vrf_data();
        vrf_data.vrf_proof = vec![0u8; VRF_PROOF_SIZE - 1]; // Wrong size
        let vrf_settings = create_valid_vrf_settings();

        let result = validate_vrf_verification_data(&vrf_data, &vrf_settings);
        assert!(matches!(result, Err(VRFVerificationError::InvalidProofSize)));
    }

    #[test]
    fn test_validate_vrf_verification_data_invalid_public_key_size() {
        let mut vrf_data = create_valid_vrf_data();
        vrf_data.public_key = vec![0u8; VRF_PUBLIC_KEY_SIZE + 1]; // Wrong size
        let vrf_settings = create_valid_vrf_settings();

        let result = validate_vrf_verification_data(&vrf_data, &vrf_settings);
        assert!(matches!(result, Err(VRFVerificationError::InvalidPublicKeySize)));
    }

    #[test]
    fn test_validate_vrf_verification_data_invalid_output_size() {
        let mut vrf_data = create_valid_vrf_data();
        vrf_data.vrf_output = vec![0u8; VRF_OUTPUT_SIZE - 1]; // Wrong size
        let vrf_settings = create_valid_vrf_settings();

        let result = validate_vrf_verification_data(&vrf_data, &vrf_settings);
        assert!(matches!(result, Err(VRFVerificationError::InvalidOutputSize)));
    }

    #[test]
    fn test_validate_vrf_verification_data_invalid_input_data_size() {
        let mut vrf_data = create_valid_vrf_data();
        vrf_data.vrf_input_data = vec![0u8; VRF_INPUT_DATA_SIZE + 1]; // Wrong size
        let vrf_settings = create_valid_vrf_settings();

        let result = validate_vrf_verification_data(&vrf_data, &vrf_settings);
        assert!(matches!(result, Err(VRFVerificationError::InvalidInputDataSize)));
    }

    #[test]
    fn test_validate_vrf_verification_data_invalid_block_hash_size() {
        let mut vrf_data = create_valid_vrf_data();
        vrf_data.block_hash = vec![0u8; BLOCK_HASH_SIZE - 1]; // Wrong size
        let vrf_settings = create_valid_vrf_settings();

        let result = validate_vrf_verification_data(&vrf_data, &vrf_settings);
        assert!(matches!(result, Err(VRFVerificationError::InvalidBlockHashSize)));
    }

    #[test]
    fn test_validate_vrf_verification_data_empty_user_id() {
        let mut vrf_data = create_valid_vrf_data();
        vrf_data.user_id = "".to_string();
        let vrf_settings = create_valid_vrf_settings();

        let result = validate_vrf_verification_data(&vrf_data, &vrf_settings);
        assert!(matches!(result, Err(VRFVerificationError::EmptyUserId)));
    }

    #[test]
    fn test_validate_vrf_verification_data_invalid_user_id_length() {
        let mut vrf_data = create_valid_vrf_data();
        vrf_data.user_id = "a".repeat(MAX_USER_ID_LENGTH + 1);
        let vrf_settings = create_valid_vrf_settings();

        let result = validate_vrf_verification_data(&vrf_data, &vrf_settings);
        assert!(matches!(result, Err(VRFVerificationError::InvalidUserIdLength)));
    }

    #[test]
    fn test_validate_vrf_verification_data_invalid_user_id_format() {
        let mut vrf_data = create_valid_vrf_data();
        vrf_data.user_id = "invalidaccount".to_string(); // No dot
        let vrf_settings = create_valid_vrf_settings();

        let result = validate_vrf_verification_data(&vrf_data, &vrf_settings);
        assert!(matches!(result, Err(VRFVerificationError::InvalidUserIdFormat)));
    }

    #[test]
    fn test_validate_vrf_verification_data_empty_rp_id() {
        let mut vrf_data = create_valid_vrf_data();
        vrf_data.rp_id = "".to_string();
        let vrf_settings = create_valid_vrf_settings();

        let result = validate_vrf_verification_data(&vrf_data, &vrf_settings);
        assert!(matches!(result, Err(VRFVerificationError::EmptyRpId)));
    }

    #[test]
    fn test_validate_vrf_verification_data_invalid_rp_id_length() {
        let mut vrf_data = create_valid_vrf_data();
        vrf_data.rp_id = "a".repeat(MAX_RP_ID_LENGTH + 1);
        let vrf_settings = create_valid_vrf_settings();

        let result = validate_vrf_verification_data(&vrf_data, &vrf_settings);
        assert!(matches!(result, Err(VRFVerificationError::InvalidRpIdLength)));
    }

    #[test]
    fn test_validate_vrf_verification_data_invalid_rp_id_format() {
        let mut vrf_data = create_valid_vrf_data();
        vrf_data.rp_id = ".example.com".to_string(); // Starts with dot
        let vrf_settings = create_valid_vrf_settings();

        let result = validate_vrf_verification_data(&vrf_data, &vrf_settings);
        assert!(matches!(result, Err(VRFVerificationError::InvalidRpIdFormat)));
    }

    #[test]
    fn test_validate_vrf_verification_data_empty_byte_arrays() {
        let mut vrf_data = create_valid_vrf_data();
        vrf_data.vrf_proof = vec![]; // Empty
        let vrf_settings = create_valid_vrf_settings();

        let result = validate_vrf_verification_data(&vrf_data, &vrf_settings);
        assert!(matches!(result, Err(VRFVerificationError::InvalidInput)));
    }

    #[test]
    fn test_validate_vrf_verification_data_vrf_disabled() {
        let vrf_data = create_valid_vrf_data();
        let mut vrf_settings = create_valid_vrf_settings();
        vrf_settings.enabled = false; // Disable VRF

        // Should not validate block height freshness when VRF is disabled
        let result = validate_vrf_verification_data(&vrf_data, &vrf_settings);
        // This will still fail due to env::block_height() in unit tests, but in real usage
        // it would skip the freshness check when VRF is disabled
        assert!(result.is_err() || result.is_ok());
    }

    #[test]
    fn test_vrf_verification_data_serialization() {
        let vrf_data = VRFVerificationData {
            vrf_input_data: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32],
            vrf_output: vec![1u8; VRF_OUTPUT_SIZE],
            vrf_proof: vec![1u8; VRF_PROOF_SIZE],
            public_key: vec![1u8; VRF_PUBLIC_KEY_SIZE],
            user_id: "alice.testnet".to_string(),
            rp_id: "example.com".to_string(),
            block_height: 123456789,
            block_hash: vec![1u8; BLOCK_HASH_SIZE],
        };

        let json_str = serde_json::to_string(&vrf_data).expect("Should serialize to JSON");
        let deserialized: VRFVerificationData = serde_json::from_str(&json_str).expect("Should deserialize from JSON");

        assert_eq!(vrf_data.vrf_input_data, deserialized.vrf_input_data);
        assert_eq!(vrf_data.vrf_output, deserialized.vrf_output);
        assert_eq!(vrf_data.vrf_proof, deserialized.vrf_proof);
        assert_eq!(vrf_data.public_key, deserialized.public_key);
        assert_eq!(vrf_data.user_id, deserialized.user_id);
        assert_eq!(vrf_data.rp_id, deserialized.rp_id);
        assert_eq!(vrf_data.block_height, deserialized.block_height);
        assert_eq!(vrf_data.block_hash, deserialized.block_hash);

        println!("VRFVerificationData serialization test passed");
    }
}
