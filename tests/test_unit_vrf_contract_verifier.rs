//! ////////////////////////////////////////
//! `vrf-contract-verifier` Integration Test
//! ////////////////////////////////////////
//!
//! Tests that the vrf-contract-verifier library is compatible with the wasm contract.
//! NOTE: add this verify_vrf_1 function in lib.rs to run these tests:
//!
//! use crate::WebAuthnContract;
//! impl WebAuthnContract {
//!     // Test vrf-wasm vs. vrf-contract-verifier compatibility (view-only verification)
//!     pub fn verify_vrf_1(
//!         &self,
//!         proof_bytes: Vec<u8>,
//!         public_key_bytes: Vec<u8>,
//!         input: Vec<u8>,
//!     ) -> Option<Vec<u8>> {
//!         vrf_contract_verifier::verify_vrf(&proof_bytes, &public_key_bytes, &input).ok()
//!             .map(|vrf_output| vrf_output.to_vec())
//!     }
//! }

// use near_workspaces::types::Gas;
// use serde_json::json;
// use tokio::sync::OnceCell;
// use rand_core::SeedableRng;

// use vrf_wasm::ecvrf::ECVRFKeyPair;
// use vrf_wasm::vrf::{VRFKeyPair, VRFProof};
// use vrf_wasm::traits::WasmRngFromSeed;

// mod utils_mocks;
// mod utils_contracts;

// // name of the `vrf-contract-verifier` based verify function in the contract
// const VERIFY_FUNCTION_NAME: &str = "verify_vrf_1";

// // Shared contract instance for all tests (deploy just once)
// static CONTRACT: OnceCell<near_workspaces::Contract> = OnceCell::const_new();

// async fn get_contract() -> &'static near_workspaces::Contract {
//     CONTRACT.get_or_init(|| async {
//         println!("Deploying shared test contract for VRF contract verifier tests...");
//         utils_contracts::deploy_test_contract().await.expect("Failed to deploy test contract")
//     }).await
// }

// ////////////////////////////////////////////////////////////
// /// BEGIN TESTS
// ////////////////////////////////////////////////////////////

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[tokio::test]
//     async fn test_vrf_contract_verifier_valid_proof_passes() -> Result<(), Box<dyn std::error::Error>> {
//         println!("Test: Valid proof should pass");

//         let contract = get_contract().await;
//         let test_data = utils_mocks::generate_test_vrf_wasm_data().await?;

//         let verification_result: serde_json::Value = contract
//             .call(VERIFY_FUNCTION_NAME)
//             .args_json(json!({
//                 "proof_bytes": test_data.proof_bytes(),
//                 "public_key_bytes": test_data.pubkey_bytes(),
//                 "input": test_data.input
//             }))
//             .gas(Gas::from_tgas(100))
//             .transact()
//             .await?
//             .json()?;

//         let verified = verification_result["verified"].as_bool().unwrap_or(false);
//         assert!(verified, "Valid proof should pass verification");

//         // Check that VRF output was returned with specific length expectation
//         let vrf_output = verification_result["vrf_output"].as_array()
//             .expect("Valid proof should return VRF output");
//         assert_eq!(vrf_output.len(), 64, "VRF output should be 64 bytes");

//         println!("PASSED: Valid proof verified successfully");
//         println!("- VRF output returned: {} bytes", vrf_output.len());
//         Ok(())
//     }

//     #[tokio::test]
//     async fn test_vrf_contract_verifier_wrong_proof_fails() -> Result<(), Box<dyn std::error::Error>> {
//         println!("Test: Wrong proof should fail");

//         let contract = get_contract().await;
//         let test_data = utils_mocks::generate_test_vrf_wasm_data().await?;

//         // Create corrupted proof by modifying some bytes
//         let mut corrupted_proof = test_data.proof_bytes();
//         if corrupted_proof.len() > 10 {
//             corrupted_proof[5] = corrupted_proof[5].wrapping_add(1);
//             corrupted_proof[10] = corrupted_proof[10].wrapping_add(1);
//         }

//         let verification_result: serde_json::Value = contract
//             .call(VERIFY_FUNCTION_NAME)
//             .args_json(json!({
//                 "proof_bytes": corrupted_proof,
//                 "public_key_bytes": test_data.pubkey_bytes(),
//                 "input": test_data.input
//             }))
//             .gas(Gas::from_tgas(100))
//             .transact()
//             .await?
//             .json()?;

//         let verified = verification_result["verified"].as_bool().unwrap_or(true);
//         assert!(!verified, "Corrupted proof should fail verification");

//         // Check that no VRF output was returned for invalid proof
//         let vrf_output = verification_result["vrf_output"].as_array();
//         assert!(vrf_output.is_none() || vrf_output.unwrap().is_empty(), "Invalid proof should not return VRF output");

//         println!("PASSED: Wrong proof correctly rejected");
//         Ok(())
//     }

//     #[tokio::test]
//     async fn test_vrf_contract_verifier_malformed_public_key_fails() -> Result<(), Box<dyn std::error::Error>> {
//         println!("Test: Malformed public key should fail");

//         let contract = get_contract().await;
//         let test_data = utils_mocks::generate_test_vrf_wasm_data().await?;

//         // Create invalid public key
//         let invalid_public_key = vec![0u8; test_data.pubkey_bytes().len()];

//         let verification_result: serde_json::Value = contract
//             .call(VERIFY_FUNCTION_NAME)
//             .args_json(json!({
//                 "proof_bytes": test_data.proof_bytes(),
//                 "public_key_bytes": invalid_public_key,
//                 "input": test_data.input
//             }))
//             .gas(Gas::from_tgas(100))
//             .transact()
//             .await?
//             .json()?;

//         let verified = verification_result["verified"].as_bool().unwrap();
//         assert!(!verified, "Malformed public key should fail verification");

//         println!("PASSED: Malformed public key correctly rejected");
//         Ok(())
//     }

//     #[tokio::test]
//     async fn test_vrf_contract_verifier_truncated_proof_fails() -> Result<(), Box<dyn std::error::Error>> {
//         println!("Test: Truncated proof should fail");

//         let contract = get_contract().await;
//         let test_data = utils_mocks::generate_test_vrf_wasm_data().await?;

//         // Truncate the proof to half its original size
//         let mut truncated_proof = test_data.proof_bytes();
//         truncated_proof.truncate(truncated_proof.len() / 2);

//         let verification_result: serde_json::Value = contract
//             .call(VERIFY_FUNCTION_NAME)
//             .args_json(json!({
//                 "proof_bytes": truncated_proof,
//                 "public_key_bytes": test_data.pubkey_bytes(),
//                 "input": test_data.input
//             }))
//             .gas(Gas::from_tgas(100))
//             .transact()
//             .await?
//             .json()?;

//         let verified = verification_result["verified"].as_bool().unwrap_or(true);
//         assert!(!verified, "Truncated proof should fail verification");

//         // Check that no VRF output was returned for invalid proof
//         let vrf_output = verification_result["vrf_output"].as_array();
//         assert!(vrf_output.is_none() || vrf_output.unwrap().is_empty(), "Invalid proof should not return VRF output");

//         println!("PASSED: Truncated proof correctly rejected");
//         Ok(())
//     }

//     #[tokio::test]
//     async fn test_vrf_contract_verifier_roundtrip_verification() -> Result<(), Box<dyn std::error::Error>> {
//         println!("Test: Roundtrip verification");

//         let contract = get_contract().await;
//         let test_data = utils_mocks::generate_test_vrf_wasm_data().await?;

//         let verification_result: serde_json::Value = contract
//             .call(VERIFY_FUNCTION_NAME)
//             .args_json(json!({
//                 "proof_bytes": test_data.proof_bytes(),
//                 "public_key_bytes": test_data.pubkey_bytes(),
//                 "input": test_data.input
//             }))
//             .gas(Gas::from_tgas(100))
//             .transact()
//             .await?
//             .json()?;

//         let verified = verification_result["verified"].as_bool().unwrap_or(false);
//         assert!(verified, "Roundtrip test requires valid proof");

//         // Extract VRF output from contract response
//         let contract_output_opt = verification_result["vrf_output"].as_array();

//         if let Some(contract_output_array) = contract_output_opt {
//             // Convert JSON array to Vec<u8>
//             let contract_output: Vec<u8> = contract_output_array
//                 .iter()
//                 .map(|v| v.as_u64().unwrap() as u8)
//                 .collect();

//             // Verify expected output length
//             assert_eq!(contract_output.len(), 64, "Contract VRF output should be 64 bytes");
//             assert_eq!(test_data.expected_output.len(), 64, "Expected VRF output should be 64 bytes");

//             // Compare with expected output
//             assert_eq!(contract_output, test_data.expected_output, "VRF outputs must match exactly");

//             println!("PASSED: Roundtrip verification successful");
//             println!("- Expected output: {} bytes", test_data.expected_output.len());
//             println!("- Contract output: {} bytes", contract_output.len());
//             println!("- VRF outputs match exactly");
//         } else {
//             return Err("Contract didn't return VRF output".into());
//         }

//         Ok(())
//     }

//     #[tokio::test]
//     async fn test_deterministic_vrf_generation() -> Result<(), Box<dyn std::error::Error>> {
//         println!("Testing deterministic VRF generation...");

//         let seed = [123u8; 32];
//         let input = b"deterministic_test";

//         // Generate twice with same seed
//         let mut rng1 = WasmRngFromSeed::from_seed(seed);
//         let keypair1 = ECVRFKeyPair::generate(&mut rng1);
//         let proof1 = keypair1.prove(input);
//         let output1 = proof1.to_hash();

//         let mut rng2 = WasmRngFromSeed::from_seed(seed);
//         let keypair2 = ECVRFKeyPair::generate(&mut rng2);
//         let proof2 = keypair2.prove(input);
//         let output2 = proof2.to_hash();

//         assert_eq!(output1, output2, "VRF outputs should be deterministic");
//         assert_eq!(output1.len(), 64, "VRF output should be 64 bytes");
//         println!("VRF generation is deterministic: {} bytes", output1.len());

//         Ok(())
//     }
// }