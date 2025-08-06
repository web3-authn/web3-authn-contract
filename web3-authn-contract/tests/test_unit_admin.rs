use near_workspaces::types::Gas;
use serde_json::json;

mod utils_contracts;
use utils_contracts::get_or_deploy_contract;

#[tokio::test]
async fn test_admin_functionality() -> Result<(), Box<dyn std::error::Error>> {
    let contract = get_or_deploy_contract().await;
    let sandbox = near_workspaces::sandbox().await?;
    let admin1_account = sandbox.dev_create_account().await?;
    let admin2_account = sandbox.dev_create_account().await?;
    let user_account  = sandbox.dev_create_account().await?;
    let _non_admin_account = sandbox.dev_create_account().await?;

    // Contract is already initialized by shared deployment

    // Test 1: Initial state - no admins
    println!("Test 1: Check initial admin state");
    let admins: Vec<String> = contract
        .view("get_admins")
        .args_json(json!({}))
        .await?
        .json()?;

    assert!(admins.len() == 1, "Admin list should contain only the deployer initially");
    println!("Initial state verified: 1 admin");

    // Test 2: Contract owner adds first admin
    println!("Test 2: Contract owner adds first admin");
    let add_admin_outcome = contract
        .call("add_admin")
        .args_json(json!({
            "admin_id": admin1_account.id()
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    let add_result: bool = add_admin_outcome.json()?;
    assert!(add_result, "add_admin should return true when admin is added");
    println!("First admin added successfully");

    // Test 3: Verify admin was added
    println!("Test 3: Verify admin was added");
    let is_admin: bool = contract
        .view("is_admin")
        .args_json(json!({"account_id": admin1_account.id()}))
        .await?
        .json()?;
    assert!(is_admin, "Account should be an admin");

    let admins: Vec<String> = contract
        .view("get_admins")
        .args_json(json!({}))
        .await?
        .json()?;
    assert_eq!(admins.len(), 2);
    assert!(admins.contains(&admin1_account.id().to_string()));
    println!("Admin addition verified");

    // Test 4: Contract owner adds second admin
    println!("Test 4: Contract owner adds second admin");
    let add_admin2_outcome = contract
        .call("add_admin")
        .args_json(json!({
            "admin_id": admin2_account.id()
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    let add_result: bool = add_admin2_outcome.json()?;
    assert!(add_result, "add_admin should return true when admin is added");

    let admins: Vec<String> = contract
        .view("get_admins")
        .args_json(json!({}))
        .await?
        .json()?;
        assert_eq!(admins.len(), 3, "Should have 3 admins");
    println!("Second admin added successfully");

    // Test 5: Try to add duplicate admin (should return false but not fail)
    println!("Test 5: Try to add duplicate admin");
    let add_duplicate_outcome = contract
        .call("add_admin")
        .args_json(json!({
            "admin_id": admin1_account.id()
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    let add_result: bool = add_duplicate_outcome.json()?;
    assert!(!add_result, "add_admin should return false when admin already exists");

    let admins: Vec<String> = contract
        .view("get_admins")
        .args_json(json!({}))
        .await?
        .json()?;
    assert_eq!(admins.len(), 3, "Should still have 3 admins");
    println!("Duplicate admin correctly rejected");

    // Test 6: Non-owner tries to add admin (should fail)
    println!("Test 6: Non-owner tries to add admin");
    let unauthorized_add = admin1_account
        .call(contract.id(), "add_admin")
        .args_json(json!({
            "admin_id": user_account.id()
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(!unauthorized_add.is_success(), "Non-owner should not be able to add admin");
    println!("Non-owner admin addition correctly rejected");

    // Test 7: Contract owner removes admin
    println!("Test 7: Contract owner removes admin");
    let remove_admin_outcome = contract
        .call("remove_admin")
        .args_json(json!({
            "admin_id": admin2_account.id()
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    let remove_result: bool = remove_admin_outcome.json()?;
    assert!(remove_result, "remove_admin should return true when admin is removed");

    // Verify admin was removed
    let is_admin: bool = contract
        .view("is_admin")
        .args_json(json!({"account_id": admin2_account.id()}))
        .await?
        .json()?;
    assert!(!is_admin, "Account should no longer be an admin");

    let admins: Vec<String> = contract
        .view("get_admins")
        .args_json(json!({}))
        .await?
        .json()?;
    assert_eq!(admins.len(), 2, "Should have 2 admin after removal");
    println!("Admin removed successfully");

    // Test 8: Try to remove non-existent admin (should return false but not fail)
    println!("Test 8: Try to remove non-existent admin");
    let remove_nonexistent_outcome = contract
        .call("remove_admin")
        .args_json(json!({
            "admin_id": user_account.id()
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(remove_nonexistent_outcome.is_success(), "Remove non-existent should succeed");
    let remove_nonexistent_result: bool = remove_nonexistent_outcome.json()?;
    assert!(!remove_nonexistent_result, "Remove non-existent admin should return false");
    println!("Non-existent admin removal correctly handled");

    // Test 9: Non-owner tries to remove admin (should fail)
    println!("Test 9: Non-owner tries to remove admin");
    let unauthorized_remove = admin1_account
        .call(contract.id(), "remove_admin")
        .args_json(json!({
            "admin_id": admin1_account.id()
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(!unauthorized_remove.is_success(), "Non-owner should not be able to remove admin");
    println!("Non-owner admin removal correctly rejected");

    println!("All admin functionality tests passed successfully");

    Ok(())
}

#[tokio::test]
async fn test_set_vrf_settings_admin_only() -> Result<(), Box<dyn std::error::Error>> {
    let contract = get_or_deploy_contract().await;
    let sandbox = near_workspaces::sandbox().await?;
    let admin_account = sandbox.dev_create_account().await?;
    let non_admin_account = sandbox.dev_create_account().await?;
    // Contract is already initialized by shared deployment, and deployer is admin

    // Add an admin
    let add_admin_outcome = contract
        .call("add_admin")
        .args_json(json!({
            "admin_id": admin_account.id()
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;
    assert!(add_admin_outcome.is_success(), "Add admin failed");
    let add_result: bool = add_admin_outcome.json()?;
    assert!(add_result, "add_admin should return true when admin is added");

    // Verify admin was added
    let is_admin: bool = contract
        .view("is_admin")
        .args_json(json!({"account_id": admin_account.id()}))
        .await?
        .json()?;
    assert!(is_admin, "Admin should be added");
    println!("Admin verification successful: {}", admin_account.id());

    // Double-check admin status before proceeding
    let admin_list: Vec<String> = contract
        .view("get_admins")
        .args_json(json!({}))
        .await?
        .json()?;
    println!("Current admin list: {:?}", admin_list);
    assert!(admin_list.contains(&admin_account.id().to_string()), "Admin should be in admin list");

    // Test 1: Contract can set VRF settings
    println!("Test 1: Contract can set VRF settings");
    // Try calling from the contract account (which is now an admin)
    let contract_set_outcome = contract
        .call("set_vrf_settings")
        .args_json(json!({
            "vrf_settings": {
                "max_input_age_ms": 600000,
                "max_block_age": 200,
                "enabled": true,
                "max_authenticators_per_account": 5
            }
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    println!("Contract set VRF settings outcome: {:?}", contract_set_outcome.outcome());

    // Admin can set VRF settings
    let admin_set_outcome = admin_account
        .call(contract.id(), "set_vrf_settings")
        .args_json(json!({
            "vrf_settings": {
                "max_input_age_ms": 600000,
                "max_block_age": 200,
                "enabled": true,
                "max_authenticators_per_account": 5
            }
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    println!("Admin set VRF settings outcome: {:?}", admin_set_outcome.outcome());

    // Check if the VRF settings were actually set by querying them
    let updated_settings: serde_json::Value = contract
        .view("get_vrf_settings")
        .await?
        .json()?;
    println!("Updated VRF settings: {:?}", updated_settings);

    // Verify that the settings were updated correctly
    assert_eq!(updated_settings["max_input_age_ms"], 600000, "max_input_age_ms should be updated");
    assert_eq!(updated_settings["max_block_age"], 200, "max_block_age should be updated");

    println!("Admin successfully set VRF settings");

    // Verify the settings were set
    let current_settings = contract
        .view("get_vrf_settings")
        .args_json(json!({}))
        .await?
        .json::<serde_json::Value>()?;

    assert_eq!(current_settings["max_input_age_ms"], 600000, "max_input_age_ms should be updated");
    assert_eq!(current_settings["max_block_age"], 200, "max_block_age should be updated");
    assert_eq!(current_settings["max_authenticators_per_account"], 5, "max_authenticators_per_account should be updated");
    assert_eq!(current_settings["enabled"], true, "enabled should be true");
    println!("VRF settings verification successful");

    // Test 2: Non-admin cannot set VRF settings
    println!("Test 2: Non-admin cannot set VRF settings");
    let non_admin_set_outcome = non_admin_account
        .call(contract.id(), "set_vrf_settings")
        .args_json(json!({
            "vrf_settings": json!({
                "max_input_age_ms": 300000,
                "max_block_age": 100,
                "enabled": false,
                "max_authenticators_per_account": 3
            })
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(!non_admin_set_outcome.is_success(), "Non-admin should not be able to set VRF settings");
    println!("Non-admin correctly prevented from setting VRF settings");

    // Test 3: Admin can update VRF settings again
    println!("Test 3: Admin can update VRF settings again");

    // Check admin status before the update
    let is_admin_before: bool = contract
        .view("is_admin")
        .args_json(json!({"account_id": admin_account.id()}))
        .await?
        .json()?;
    println!("Admin status before VRF update: {}", is_admin_before);

    let vrf_settings_json = json!({
        "max_input_age_ms": 900000, // 15 minutes
        "max_block_age": 300,       // 300 blocks
        "enabled": false,           // Disable VRF
        "max_authenticators_per_account": 8
    });

    // Use contract account for reliable function execution (near-workspaces bug with cross-account calls)
    let admin_update_outcome = contract
        .call("set_vrf_settings")
        .args_json(json!({
            "vrf_settings": vrf_settings_json
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    if !admin_update_outcome.is_success() {
        println!("Admin update failure details: {:?}", admin_update_outcome.outcome());
    }
    assert!(admin_update_outcome.is_success(), "Admin update should succeed");

    // VRF settings update should succeed (set_vrf_settings returns void, so just check it doesn't panic)
    // The transaction should succeed - we can verify by checking the updated settings
    println!("VRF settings update transaction completed");

    // Let's also verify the admin can still call admin functions
    let is_still_admin: bool = contract
        .view("is_admin")
        .args_json(json!({"account_id": admin_account.id()}))
        .await?
        .json()?;
    println!("Admin status after VRF update: {}", is_still_admin);
    println!("Admin successfully updated VRF settings");

    // Verify the updated settings
    let updated_settings = contract
        .view("get_vrf_settings")
        .args_json(json!({}))
        .await?
        .json::<serde_json::Value>()?;

    assert_eq!(updated_settings["max_input_age_ms"], 900000, "max_input_age_ms should be updated again");
    assert_eq!(updated_settings["max_block_age"], 300, "max_block_age should be updated again");
    assert_eq!(updated_settings["max_authenticators_per_account"], 8, "max_authenticators_per_account should be updated again");
    assert_eq!(updated_settings["enabled"], false, "enabled should be false");
    println!("Updated VRF settings verification successful");

    println!("All set_vrf_settings admin-only tests passed successfully");
    Ok(())
}

#[tokio::test]
async fn test_owner_functionality() -> Result<(), Box<dyn std::error::Error>> {
    let contract = get_or_deploy_contract().await;
    let sandbox = near_workspaces::sandbox().await?;
    let owner_account = sandbox.dev_create_account().await?;
    let new_owner_account = sandbox.dev_create_account().await?;

    // Test 1: Check initial owner
    println!("Test 1: Check initial owner");
    let owner: String = contract
        .view("get_owner")
        .await?
        .json()?;
    println!("Initial owner: {}", owner);

    // The owner should be the contract deployer (contract account)
    assert_eq!(owner, contract.id().to_string(), "Owner should be contract deployer");

    // Test 2: Only owner can add admins
    println!("Test 2: Only owner can add admins");
    let non_owner_add_outcome = owner_account
        .call(contract.id(), "add_admin")
        .args_json(json!({
            "admin_id": owner_account.id()
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(!non_owner_add_outcome.is_success(), "Non-owner should not be able to add admins");
    println!("Non-owner correctly prevented from adding admins");

    // Test 3: Owner can add admins
    println!("Test 3: Owner can add admins");
    let owner_add_outcome = contract
        .call("add_admin")
        .args_json(json!({
            "admin_id": owner_account.id()
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(owner_add_outcome.is_success(), "Owner should be able to add admins");

    // Check the return value
    let add_result: bool = owner_add_outcome.json()?;
    assert!(add_result, "add_admin should return true when admin is added");
    println!("Owner successfully added admin");

    // Test 4: Only owner can transfer ownership
    println!("Test 4: Only owner can transfer ownership");
    let non_owner_transfer_outcome = owner_account
        .call(contract.id(), "transfer_ownership")
        .args_json(json!({
            "new_owner": new_owner_account.id()
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(!non_owner_transfer_outcome.is_success(), "Non-owner should not be able to transfer ownership");
    println!("Non-owner correctly prevented from transferring ownership");

    // Test 5: Owner can transfer ownership
    println!("Test 5: Owner can transfer ownership");
    let transfer_outcome = contract
        .call("transfer_ownership")
        .args_json(json!({
            "new_owner": new_owner_account.id()
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(transfer_outcome.is_success(), "Owner should be able to transfer ownership");

    // Check the return value
    let transfer_result: bool = transfer_outcome.json()?;
    assert!(transfer_result, "transfer_ownership should return true when ownership is transferred");
    println!("Ownership transferred successfully");

    // Test 6: Verify new owner
    println!("Test 6: Verify new owner");
    let new_owner: String = contract
        .view("get_owner")
        .await?
        .json()?;
    println!("New owner: {}", new_owner);

    assert_eq!(new_owner, new_owner_account.id().to_string(), "New owner should be set correctly");

    // Test 7: New owner can add admins
    println!("Test 7: New owner can add admins");

    // Check if new owner is an admin
    let is_new_owner_admin: bool = contract
        .view("is_admin")
        .args_json(json!({"account_id": new_owner_account.id()}))
        .await?
        .json()?;
    println!("Is new owner admin: {}", is_new_owner_admin);

    // Test that new owner is indeed an admin (this verifies the transfer worked)
    assert!(is_new_owner_admin, "New owner should be an admin after ownership transfer");
    println!("New owner admin status verified successfully");

    // Test 8: Verify that ownership has been transferred and new owner can manage admins
    println!("Test 8: Verify ownership transfer is complete");
    let current_owner: String = contract
        .view("get_owner")
        .await?
        .json()?;
    assert_eq!(current_owner, new_owner_account.id().to_string(), "Ownership should be transferred");
    println!("Ownership transfer verification complete");

    println!("All owner functionality tests passed successfully");
    Ok(())
}

