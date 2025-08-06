use serde_json::json;
use rand_core::SeedableRng;
use vrf_wasm::{
    ecvrf::{ECVRFProof, ECVRFPublicKey, ECVRFKeyPair},
    traits::WasmRngFromSeed,
    VRFKeyPair,
    VRFProof,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_ENGINE};
use std::collections::BTreeMap;
use serde_cbor;
use sha2::{Sha256, Digest};


// Test VRF data structure for authentication (subsequent logins)
#[derive(Debug)]
pub struct VrfData {
    pub input_data: Vec<u8>,    // VRF input (hashed to 32 bytes)
    pub output: Vec<u8>,        // VRF output (64 bytes full hash)
    pub proof: ECVRFProof,      // VRF proof
    pub public_key: ECVRFPublicKey, // VRF public key (same as registration)
    pub user_id: String,        // NEAR account_id
    pub rp_id: String,          // Relying Party ID used in construction
    pub block_height: u64,
    pub block_hash: Vec<u8>,
}

impl VrfData {
    pub fn proof_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.proof).unwrap()
    }

    pub fn pubkey_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.public_key).unwrap()
    }

    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "vrf_input_data": self.input_data,
            "vrf_output": self.output,
            "vrf_proof": self.proof_bytes(),
            "public_key": self.pubkey_bytes(),
            "user_id": self.user_id,
            "rp_id": self.rp_id,
            "block_height": self.block_height,
            "block_hash": self.block_hash
        })
    }
}

pub fn generate_account_creation_data() -> (String, String, String, u64, String) {
    let rp_id = "example.com";
    let user_id = "test_user.testnet"; // Fixed: Added .testnet to make it a valid NEAR account ID
    let session_id = "test_session";
    let block_height = 123456789u64;
    let new_public_key = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp";
    (
        rp_id.to_string(),
        user_id.to_string(),
        session_id.to_string(),
        block_height,
        new_public_key.to_string()
    )
}

/// Generate VRF data for registration testing with custom block height
pub async fn generate_vrf_data(
    rp_id: &str,
    user_id: &str,
    session_id: &str,
    block_height: Option<u64>,
    seed: Option<[u8; 32]>,
) -> Result<VrfData, Box<dyn std::error::Error>> {
    println!("Generating VRF registration data...");

    // Create deterministic keypair for testing
    let seed = seed.unwrap_or([42u8; 32]);
    let mut rng = WasmRngFromSeed::from_seed(seed);
    let keypair = ECVRFKeyPair::generate(&mut rng);

    // Construct VRF input according to specification
    let domain = b"web3_authn_challenge_v3";
    let block_hash = b"test_block_hash_32_bytes_for_reg";
    let timestamp = 1700000000u64;
    let block_height = block_height.unwrap_or(123456789u64);

    let mut input_data = Vec::new();
    input_data.extend_from_slice(domain);
    input_data.extend_from_slice(user_id.as_bytes());
    input_data.extend_from_slice(rp_id.as_bytes());
    input_data.extend_from_slice(session_id.as_bytes());
    input_data.extend_from_slice(&block_height.to_le_bytes());
    input_data.extend_from_slice(block_hash);
    input_data.extend_from_slice(&timestamp.to_le_bytes());

    // Hash the input data (VRF input should be hashed)
    let vrf_input = Sha256::digest(&input_data).to_vec();

    // Generate VRF proof
    let proof = keypair.prove(&vrf_input);
    let vrf_output = proof.to_hash().to_vec();

    // Verify the proof works locally
    assert!(proof.verify(&vrf_input, &keypair.pk).is_ok(), "Generated VRF proof should be valid");

    println!("Generated VRF registration data:");
    println!("  - VRF input: {} bytes", vrf_input.len());
    println!("  - VRF output: {} bytes", vrf_output.len());
    println!("  - RP ID: {}", rp_id);
    println!("  - User ID: {}", user_id);
    println!("  - Session ID: {}", session_id);

    Ok(VrfData {
        input_data: vrf_input,
        output: vrf_output,
        proof,
        public_key: keypair.pk,
        user_id: user_id.to_string(),
        rp_id: rp_id.to_string(),
        block_height: block_height,
        block_hash: block_hash.to_vec(),
    })
}

pub fn generate_deterministic_vrf_public_key() -> Vec<u8> {
    let deterministic_seed = [99u8; 32];
    let mut det_rng = WasmRngFromSeed::from_seed(deterministic_seed);
    let det_keypair = ECVRFKeyPair::generate(&mut det_rng);
    bincode::serialize(&det_keypair.pk).unwrap()
}

/// Create mock WebAuthn registration response for account creation test
pub fn create_mock_webauthn_registration(
    vrf_output: &[u8],
    rp_id: &str,
    account_id: &str,
    challenge: Option<&[u8]>
) -> serde_json::Value {
    // Use first 32 bytes of VRF output as WebAuthn challenge
    let webauthn_challenge = challenge.unwrap_or(&vrf_output[0..32]);
    let challenge_b64 = BASE64_URL_ENGINE.encode(webauthn_challenge);

    let origin = format!("https://{}", rp_id);
    let client_data = format!(
        r#"{{"type":"webauthn.create","challenge":"{}","origin":"{}","rpId":"{}","crossOrigin":false}}"#,
        challenge_b64, origin, rp_id
    );
    let client_data_b64 = BASE64_URL_ENGINE.encode(client_data.as_bytes());

    // Create valid attestation object for "none" format
    let mut attestation_map = BTreeMap::new();
    attestation_map.insert(
        serde_cbor::Value::Text("fmt".to_string()),
        serde_cbor::Value::Text("none".to_string()),
    );

    // Create valid authenticator data with RP ID hash
    let mut auth_data = Vec::new();
    let rp_id_hash = sha2::Sha256::digest(rp_id.as_bytes());
    auth_data.extend_from_slice(&rp_id_hash);
    auth_data.push(0x45); // UP (0x01) + UV (0x04) + AT (0x40)
    auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Counter = 1

    // AAGUID (16 bytes)
    auth_data.extend_from_slice(&[0x00u8; 16]);

    // Credential ID (use account_id as credential ID for clarity)
    let cred_id = format!("cred_{}", account_id);
    auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(cred_id.as_bytes());

    // Create valid COSE Ed25519 public key
    let mock_ed25519_pubkey = [0x42u8; 32];
    let mut cose_map = BTreeMap::new();
    cose_map.insert(serde_cbor::Value::Integer(1), serde_cbor::Value::Integer(1)); // kty: OKP
    cose_map.insert(serde_cbor::Value::Integer(3), serde_cbor::Value::Integer(-8)); // alg: EdDSA
    cose_map.insert(serde_cbor::Value::Integer(-1), serde_cbor::Value::Integer(6)); // crv: Ed25519
    cose_map.insert(serde_cbor::Value::Integer(-2), serde_cbor::Value::Bytes(mock_ed25519_pubkey.to_vec()));
    let cose_key = serde_cbor::to_vec(&serde_cbor::Value::Map(cose_map)).unwrap();
    auth_data.extend_from_slice(&cose_key);

    attestation_map.insert(
        serde_cbor::Value::Text("authData".to_string()),
        serde_cbor::Value::Bytes(auth_data),
    );
    attestation_map.insert(
        serde_cbor::Value::Text("attStmt".to_string()),
        serde_cbor::Value::Map(BTreeMap::new()),
    );

    let attestation_object_bytes = serde_cbor::to_vec(&serde_cbor::Value::Map(attestation_map)).unwrap();
    let attestation_object_b64 = BASE64_URL_ENGINE.encode(&attestation_object_bytes);

    // Return WebAuthn registration data structure
    json!({
        "id": cred_id,
        "rawId": BASE64_URL_ENGINE.encode(cred_id.as_bytes()),
        "response": {
            "clientDataJSON": client_data_b64,
            "attestationObject": attestation_object_b64,
            "transports": ["internal"]
        },
        "authenticatorAttachment": "platform",
        "type": "public-key",
        "clientExtensionResults": null
    })
}

/// Create mock WebAuthn authentication response using VRF challenge
pub fn create_mock_webauthn_authentication(vrf_output: &[u8], rp_id: &str) -> serde_json::Value {
    // Use first 32 bytes of VRF output as WebAuthn challenge
    let webauthn_challenge = &vrf_output[0..32];
    let challenge_b64 = BASE64_URL_ENGINE.encode(webauthn_challenge);

    let origin = format!("https://{}", rp_id);
    let client_data = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}","rpId":"{}","crossOrigin":false}}"#,
        challenge_b64, origin, rp_id
    );
    let client_data_b64 = BASE64_URL_ENGINE.encode(client_data.as_bytes());

    // Create valid authenticator data for authentication (no AT flag, no attested credential data)
    let mut auth_data = Vec::new();
    let rp_id_hash = sha2::Sha256::digest(rp_id.as_bytes());
    auth_data.extend_from_slice(&rp_id_hash);
    auth_data.push(0x05); // UP (0x01) + UV (0x04) - no AT flag for authentication
    auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // Counter = 2 (not used for VRF)

    let auth_data_b64 = BASE64_URL_ENGINE.encode(&auth_data);

    // Return WebAuthn authentication data structure
    json!({
        "id": "vrf_e2e_test_credential_id_123",
        "rawId": BASE64_URL_ENGINE.encode(b"vrf_e2e_test_credential_id_123"),
        "response": {
            "clientDataJSON": client_data_b64,
            "authenticatorData": auth_data_b64,
            "signature": BASE64_URL_ENGINE.encode(&vec![0x88u8; 64]), // Mock signature (different from registration)
            "userHandle": null
        },
        "authenticatorAttachment": "platform",
        "type": "public-key",
        "clientExtensionResults": null
    })
}