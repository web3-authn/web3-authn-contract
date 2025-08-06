use serde_json::json;
use near_workspaces::types::Gas;
use near_workspaces::Worker;
use near_workspaces::network::Sandbox;


#[tokio::test]
async fn test_device_linking_automatic_cleanup() -> Result<(), Box<dyn std::error::Error>> {
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    async fn fast_forward(sandbox: &Worker<Sandbox>, blocks: u64) -> Result<(), Box<dyn std::error::Error>> {
        sandbox.fast_forward(blocks).await?;
        let block = sandbox.view_block().await?;
        println!("Advanced to block: {}", block.height());
        Ok(())
    }

    // Initialize contract
    let init_outcome = contract
        .call("init")
        .args_json(json!({}))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    assert!(init_outcome.is_success(), "Initialization failed: {:?}", init_outcome.outcome());

    fast_forward(&sandbox, 1).await?;

    ///////////// Step 1: Create test account /////////////
    println!("\nStep 1: Creating test account");

    // Create a test account that will own the device linking
    let test_account = sandbox.dev_create_account().await?;
    let test_account_id = test_account.id().as_str();

    // Create a device public key for testing
    let device2_public_key = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".to_string();

    ///////////// Step 2: Store device linking mapping and schedule cleanup /////////////
    println!("\nStep 2: Storing device linking mapping and scheduling cleanup");

    // Call the actual store_device_linking_mapping method from the test account
    // This will schedule mapping cleanup
    let store_mapping_request = test_account
        .call(contract.id(), "store_device_linking_mapping")
        .args_json(json!({
            "device_public_key": device2_public_key,
            "target_account_id": test_account_id
        }))
        .gas(Gas::from_tgas(30))
        .transact_async()
        .await?;

    // Wait for the async transaction to complete
    let store_mapping_outcome = store_mapping_request.await?;

    if store_mapping_outcome.is_success() {
        println!("✓ store_device_linking_mapping succeeded");
        for outcome in store_mapping_outcome.outcomes() {
            println!("store_device_linking_mapping logs: {:?}", outcome.logs);
        }
    } else {
        println!("✗ store_device_linking_mapping failed: {:?}", store_mapping_outcome.outcome());
        panic!("store_device_linking_mapping should succeed");
    }

    fast_forward(&sandbox, 1).await?;

    // Get the current block number after yield creation
    let yield_creation_block = sandbox.view_block().await?.height();
    println!("Yield was created at block: {}", yield_creation_block);

    ///////////// Step 3: Verify device linking mapping exists /////////////
    println!("\nStep 3: Verify device linking mapping exists in HashMap");

    let query_result = contract
        .call("get_device_linking_account")
        .args_json(json!({"device_public_key": device2_public_key}))
        .view()
        .await?;

    let linking_account: Option<(String, u32)> = query_result.json()?;
    println!("Device linking query result: {:?}", linking_account);

    // Verify the mapping exists and points to the test account
    assert!(linking_account.is_some(), "Device linking mapping should exist");
    let (account_id, device_number) = linking_account.unwrap();
    assert_eq!(account_id, test_account_id);
    assert_eq!(device_number, 1, "First device should get device number 1");

    ///////////// Step 4: Fast forward 200+ blocks /////////////
    println!("\nStep 4: Fast forwarding 200+ blocks to simulate passage of time");

    fast_forward(&sandbox, 240).await?;

    ///////////// Step 5: Verify device linking mapping is cleaned up /////////////
    println!("\nStep 5: Verify device linking mapping has been cleaned up");

    let query_result_after = contract
        .call("get_device_linking_account")
        .args_json(json!({"device_public_key": device2_public_key}))
        .view()
        .await?;

    let linking_account_after: Option<(String, u32)> = query_result_after.json()?;
    println!("Device linking query result after cleanup: {:?}", linking_account_after);

    // Verify the mapping has been cleaned up
    assert!(linking_account_after.is_none(), "Device linking mapping should be cleaned up after calling cleanup_device_linking");

    println!("Test passed: Device linking mapping cleanup and yield promise creation verified");

    Ok(())
}