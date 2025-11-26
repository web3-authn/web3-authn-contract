
mod utils_mocks;
use utils_mocks::{
    create_mock_webauthn_registration,
    generate_vrf_data,
    generate_deterministic_vrf_public_key,
    generate_account_creation_data,
};

mod utils_contracts;
use utils_contracts::{get_or_deploy_contract, get_shared_worker};


#[tokio::test]
async fn test_device_counter_incremented_by_link_device_register_user() -> Result<(), Box<dyn std::error::Error>> {
    // Deploy contract using near_workspaces
    let contract = get_or_deploy_contract().await;

    // Use the same worker as the deployed contract to avoid cross-sandbox issues
    let worker = get_shared_worker().await;

    // Get the account that will be calling the contract (the test account)
    // Create a real user account we control in the sandbox
    let user = worker.dev_create_account().await?;
    let new_account_id = user.id().as_str().to_string();
    println!("User account ID: {}", new_account_id);

    // Get current block height for VRF data
    let current_block = worker.view_block().await?;
    let current_block_height = current_block.height();
    println!("Current block height: {}", current_block_height);

    // Check initial device counter (should be 0)
    let device_counter_initial = contract.view("get_device_counter")
        .args_json(serde_json::json!({
            "account_id": new_account_id.clone(),
        }))
        .await?;
    let device_counter_initial_value: u32 = device_counter_initial.json()?;
    println!("Initial device counter: {}", device_counter_initial_value);
    assert_eq!(device_counter_initial_value, 0, "Initial device counter should be 0");

    // Call verify_and_register_user with mock data
    // VRF user_id must match the on-chain account_id for verification to succeed
    let (rp_id, _gen_user_id, session_id, _block_height, _new_public_key) = generate_account_creation_data();
    let vrf_user_id = new_account_id.clone();
    let vrf_data = generate_vrf_data(&rp_id, &vrf_user_id, &session_id, Some(current_block_height), None).await?;
    let webauthn_registration = create_mock_webauthn_registration(&vrf_data.output, &rp_id, &vrf_user_id, None);
    let deterministic_vrf_public_key = generate_deterministic_vrf_public_key();

    println!("Calling verify_and_register_user as {} for device 1...", new_account_id);
    let result = user
        .call(contract.id(), "verify_and_register_user")
        .args_json(serde_json::json!({
            "vrf_data": vrf_data.to_json(),
            "webauthn_registration": webauthn_registration,
            "deterministic_vrf_public_key": deterministic_vrf_public_key,
            "authenticator_options": { "origin_policy": { "single": true } }
        }))
        .gas(near_sdk::Gas::from_tgas(200))
        .transact()
        .await?;

    println!("create_account_and_register_user result: {:?}", result);

    // Check that the device counter was incremented to 1
    let device_counter_after = contract.view("get_device_counter")
        .args_json(serde_json::json!({
            "account_id": new_account_id.clone(),
        }))
        .await?;
    let device_counter_after_value: u32 = device_counter_after.json()?;
    println!("Device counter after create_account_and_register_user: {}", device_counter_after_value);

    // The device counter should be incremented to 1 after successful registration
    assert_eq!(device_counter_after_value, 1, "Device counter should be incremented to 1 after verify_and_register_user call");

    // Prepare and perform a second registration as the same user to increment to 2
    let vrf_data_2 = generate_vrf_data(&rp_id, &vrf_user_id, &session_id, Some(current_block_height), None).await?;
    let webauthn_registration_2 = create_mock_webauthn_registration(&vrf_data_2.output, &rp_id, &vrf_user_id, None);
    let deterministic_vrf_public_key_2 = vec![1u8; 32];

    // Call link_device_register_user as the user (predecessor == user)
    println!("Calling link_device_register_user for device 2 as {}...", new_account_id);
    let result_2 = user
        .call(contract.id(), "link_device_register_user")
        .args_json(serde_json::json!({
            "vrf_data": vrf_data_2.to_json(),
            "webauthn_registration": webauthn_registration_2,
            "deterministic_vrf_public_key": deterministic_vrf_public_key_2,
            "authenticator_options": { "origin_policy": { "single": true } }
        }))
        .gas(near_sdk::Gas::from_tgas(200))
        .transact()
        .await?;

    println!("Second link_device_register_user result: {:?}", result_2);

    // Check that the device counter was incremented to 2 for the new account
    let device_counter_final = contract.view("get_device_counter")
        .args_json(serde_json::json!({
            "account_id": new_account_id.clone(),
        }))
        .await?;
    let device_counter_final_value: u32 = device_counter_final.json()?;
    println!("Final device counter: {}", device_counter_final_value);
    assert_eq!(device_counter_final_value, 2, "Device counter should be incremented to 2 after second link_device_register_user call");

    println!("✓ Test passed: Device counter correctly incremented to 2 for {}", new_account_id);
    Ok(())
}
