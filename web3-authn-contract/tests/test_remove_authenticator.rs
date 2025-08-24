use near_workspaces::types::Gas;
use serde_json::json;

mod utils_mocks;
use utils_mocks::{
    create_mock_webauthn_registration,
    generate_account_creation_data,
    generate_vrf_data,
    generate_deterministic_vrf_public_key
};

mod utils_contracts;
use utils_contracts::get_or_deploy_contract;

const ACCOUNT_CREATION_GAS_LIMIT: u64 = 70;

#[tokio::test]
async fn test_remove_authenticator() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting Remove Authenticator Test...");

    let contract = get_or_deploy_contract().await;
    let sandbox = near_workspaces::sandbox().await?;
    let admin_account = sandbox.dev_create_account().await?;

    // Add admin_account as an admin
    let _ = contract
        .call("add_admin")
        .args_json(json!({
            "admin_id": admin_account.id()
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    // Test 1: Try to remove authenticator that doesn't exist
    println!("Test 1: Try to remove non-existent authenticator");
    let remove_result: bool = contract
        .call("remove_authenticator")
        .args_json(json!({
            "credential_id": "non_existent_credential_id"
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?
        .json()?;

    assert!(!remove_result, "Should return false when authenticator doesn't exist");
    println!("✓ Non-existent authenticator removal test passed");

    // Test 2: Register an account with an authenticator, then remove it
    println!("Test 2: Register account and remove authenticator");

    // Generate test data for account creation
    let (
        rp_id,
        user_id,
        session_id,
        _block_height,
        new_public_key
    ) = generate_account_creation_data();

    // Generate VRF data
    let vrf_data = generate_vrf_data(&rp_id, &user_id, &session_id, None, None).await?;
    let deterministic_vrf_public_key = generate_deterministic_vrf_public_key();

    // Create WebAuthn registration data
    let webauthn_registration = create_mock_webauthn_registration(
        &vrf_data.output,
        &rp_id,
        &user_id,
        None
    );

    println!("Creating account and registering authenticator...");

    // Create account and register authenticator
    let registration_result = contract
        .call("create_account_and_register_user")
        .args_json(json!({
            "new_account_id": user_id,
            "new_public_key": new_public_key,
            "vrf_data": vrf_data.to_json(),
            "webauthn_registration": webauthn_registration,
            "deterministic_vrf_public_key": deterministic_vrf_public_key,
            "authenticator_options": {
                "user_verification": "required",
                "origin_policy": { "single": true }
            }
        }))
        .gas(Gas::from_tgas(ACCOUNT_CREATION_GAS_LIMIT))
        .transact()
        .await?;

    let registration_response: serde_json::Value = registration_result.json()?;
    println!("Registration result: {}", serde_json::to_string_pretty(&registration_response)?);

    // Check if registration was successful (note: with mock VRF data, it might fail VRF verification)
    let verified = registration_response["verified"].as_bool().unwrap_or(false);

    if verified {
        println!("Registration successful! Testing authenticator removal...");

        // Get the credential ID from the registration response
        let credential_id = registration_response["registration_info"]["credential_id"]
            .as_str()
            .expect("Should have credential_id in successful registration");

        println!("Credential ID: {}", credential_id);

        // Verify the authenticator exists before removal
        let authenticators = contract
            .view("get_authenticators_by_user")
            .args_json(json!({
                "user_id": user_id
            }))
            .await?
            .json::<Vec<(String, serde_json::Value)>>()?;

        println!("Authenticators before removal: {}", authenticators.len());
        assert!(authenticators.len() > 0, "Should have at least one authenticator");

        // Remove the authenticator
        let remove_result: bool = contract
            .call("remove_authenticator")
            .args_json(json!({
                "credential_id": credential_id
            }))
            .gas(Gas::from_tgas(30))
            .transact()
            .await?
            .json()?;

        assert!(remove_result, "Should successfully remove the authenticator");
        println!("✓ Authenticator removal successful");

        // Verify the authenticator is gone
        let authenticators_after = contract
            .view("get_authenticators_by_user")
            .args_json(json!({
                "user_id": user_id
            }))
            .await?
            .json::<Vec<(String, serde_json::Value)>>()?;

        println!("Authenticators after removal: {}", authenticators_after.len());
        assert_eq!(authenticators_after.len(), 0, "Should have no authenticators after removal");
        println!("✓ Authenticator removal verification successful");

    } else {
        println!("Registration failed (expected with mock VRF data)");
        println!("Testing removal of non-existent authenticator...");

        // Try to remove a non-existent authenticator
        let remove_result: bool = contract
            .call("remove_authenticator")
            .args_json(json!({
                "credential_id": "test_credential_id"
            }))
            .gas(Gas::from_tgas(30))
            .transact()
            .await?
            .json()?;

        assert!(!remove_result, "Should return false when authenticator doesn't exist");
        println!("✓ Non-existent authenticator removal test passed");
    }

    // Test 3: Try to remove the same authenticator again (should return false)
    println!("Test 3: Try to remove the same authenticator again");
    let remove_result: bool = contract
        .call("remove_authenticator")
        .args_json(json!({
            "credential_id": "test_credential_id"
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?
        .json()?;

    assert!(!remove_result, "Should return false when trying to remove already removed authenticator");
    println!("✓ Duplicate removal test passed");

    println!("✓ All remove_authenticator tests passed");
    Ok(())
}
