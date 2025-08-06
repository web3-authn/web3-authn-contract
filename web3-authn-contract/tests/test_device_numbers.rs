
mod utils_mocks;
use utils_mocks::{
    create_mock_webauthn_registration,
    generate_vrf_data,
    generate_deterministic_vrf_public_key,
    generate_account_creation_data,
};

mod utils_contracts;
use utils_contracts::get_or_deploy_contract;


#[tokio::test]
async fn test_device_counter_incremented_by_link_device_register_user() -> Result<(), Box<dyn std::error::Error>> {
    // Deploy contract using near_workspaces
    let contract = get_or_deploy_contract().await;

    // Get the sandbox for fast_forward and block operations
    let sandbox = near_workspaces::sandbox().await?;

    // Get the account that will be calling the contract (the test account)
    let test_account = contract.as_account();
    let account_id = test_account.id().clone();
    println!("Test account ID: {}", account_id);

    // Get current block height for VRF data
    let current_block = sandbox.view_block().await?;
    let current_block_height = current_block.height();
    println!("Current block height: {}", current_block_height);

    // Check initial device counter (should be 0)
    let device_counter_initial = contract.view("get_device_counter")
        .args_json(serde_json::json!({
            "account_id": account_id.clone(),
        }))
        .await?;
    let device_counter_initial_value: u32 = device_counter_initial.json()?;
    println!("Initial device counter: {}", device_counter_initial_value);
    assert_eq!(device_counter_initial_value, 0, "Initial device counter should be 0");

    // Call link_device_register_user with mock data
    // This should increment the device counter even though VRF verification will fail
    let (rp_id, user_id, session_id, block_height, new_public_key) = generate_account_creation_data();
        let vrf_data = generate_vrf_data(&rp_id, &user_id, &session_id, Some(current_block_height), None).await?;
    let webauthn_registration = create_mock_webauthn_registration(&vrf_data.output, &rp_id, &user_id, None);
    let deterministic_vrf_public_key = generate_deterministic_vrf_public_key();

    println!("Calling create_account_and_register_user...");
    let result = contract
        .call("create_account_and_register_user")
        .args_json(serde_json::json!({
            "new_account_id": account_id.clone(),
            "new_public_key": new_public_key,
            "vrf_data": vrf_data.to_json(),
            "webauthn_registration": webauthn_registration,
            "deterministic_vrf_public_key": deterministic_vrf_public_key
        }))
        .gas(near_sdk::Gas::from_tgas(200))
        .transact()
        .await?;

    println!("create_account_and_register_user result: {:?}", result);

    // Check that the device counter was incremented to 1
    let device_counter_after = contract.view("get_device_counter")
        .args_json(serde_json::json!({
            "account_id": account_id.clone(),
        }))
        .await?;
    let device_counter_after_value: u32 = device_counter_after.json()?;
    println!("Device counter after create_account_and_register_user: {}", device_counter_after_value);

    // The device counter should be incremented to 1, even though VRF verification failed
    assert_eq!(device_counter_after_value, 1, "Device counter should be incremented to 1 after create_account_and_register_user call");

    // Call link_device_register_user again to test second increment
    let vrf_data_2 = generate_vrf_data(&rp_id, &user_id, &session_id, Some(current_block_height), None).await?;
    let webauthn_registration_2 = create_mock_webauthn_registration(&vrf_data_2.output, &rp_id, &user_id, None);
    let deterministic_vrf_public_key_2 = vec![1u8; 32];

    println!("Calling link_device_register_user for device 2...");
    let result_2 = contract
        .call("link_device_register_user")
        .args_json(serde_json::json!({
            "vrf_data": vrf_data_2.to_json(),
            "webauthn_registration": webauthn_registration_2,
            "deterministic_vrf_public_key": deterministic_vrf_public_key_2
        }))
        .gas(near_sdk::Gas::from_tgas(200))
        .transact()
        .await?;

    println!("Second link_device_register_user result: {:?}", result_2);

    // Check that the device counter was incremented to 2
    let device_counter_final = contract.view("get_device_counter")
        .args_json(serde_json::json!({
            "account_id": account_id.clone(),
        }))
        .await?;
    let device_counter_final_value: u32 = device_counter_final.json()?;
    println!("Final device counter: {}", device_counter_final_value);

    // The device counter should be incremented to 2
    assert_eq!(device_counter_final_value, 2, "Device counter should be incremented to 2 after second link_device_register_user call");

    println!("✓ Test passed: Device counter is correctly incremented by link_device_register_user");
    Ok(())
}