use near_workspaces::types::Gas;
use serde_json::json;

#[tokio::test]
async fn test_admin_functionality() -> Result<(), Box<dyn std::error::Error>> {
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;
    let admin1_account = sandbox.dev_create_account().await?;
    let admin2_account = sandbox.dev_create_account().await?;
    let user_account  = sandbox.dev_create_account().await?;
    let _non_admin_account = sandbox.dev_create_account().await?;

    // Initialize the contract
    let init_outcome = contract
        .call("init")
        .args_json(json!({
            "vrf_settings": null,
            "tld_config": null
        }))
        .transact()
        .await?;
    assert!(init_outcome.is_success(), "Initialization failed: {:?}", init_outcome.outcome());

    // Test 1: Initial state - no admins
    println!("Test 1: Check initial admin state");
    let admins: Vec<String> = contract
        .view("get_admins")
        .args_json(json!({}))
        .await?
        .json()?;
    assert!(admins.is_empty(), "Admin list should be empty initially");
    println!("Initial state verified: no admins");

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

    assert!(add_admin_outcome.is_success(), "Add admin failed: {:?}", add_admin_outcome.outcome());
    let add_result: bool = add_admin_outcome.json()?;
    assert!(add_result, "Add admin should return true");
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
    assert_eq!(admins.len(), 1);
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

    assert!(add_admin2_outcome.is_success(), "Add second admin failed");
    let add_result2: bool = add_admin2_outcome.json()?;
    assert!(add_result2, "Add second admin should return true");

    let admins: Vec<String> = contract
        .view("get_admins")
        .args_json(json!({}))
        .await?
        .json()?;
    assert_eq!(admins.len(), 2, "Should have 2 admins");
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

    assert!(add_duplicate_outcome.is_success(), "Duplicate add should succeed");
    let duplicate_result: bool = add_duplicate_outcome.json()?;
    assert!(!duplicate_result, "Duplicate admin add should return false");

    let admins: Vec<String> = contract
        .view("get_admins")
        .args_json(json!({}))
        .await?
        .json()?;
    assert_eq!(admins.len(), 2, "Should still have 2 admins");
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

    assert!(remove_admin_outcome.is_success(), "Remove admin failed");
    let remove_result: bool = remove_admin_outcome.json()?;
    assert!(remove_result, "Remove admin should return true");

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
    assert_eq!(admins.len(), 1, "Should have 1 admin after removal");
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
async fn test_set_tld_config_admin_only() -> Result<(), Box<dyn std::error::Error>> {
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;
    let admin_account = sandbox.dev_create_account().await?;
    let non_admin_account = sandbox.dev_create_account().await?;

    // Initialize the contract
    let init_outcome = contract
        .call("init")
        .args_json(json!({
            "vrf_settings": null,
            "tld_config": null
        }))
        .transact()
        .await?;
    assert!(init_outcome.is_success(), "Initialization failed: {:?}", init_outcome.outcome());

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

    // Test 1: Admin can set TLD config
    println!("Test 1: Admin can set TLD config");
    let tld_config = json!({
        "multi_part_tlds": [["co", "uk"], ["com", "au"]],
        "enabled": true
    });

    let admin_set_outcome = admin_account
        .call(contract.id(), "set_tld_config")
        .args_json(json!({
            "tld_config": tld_config
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(admin_set_outcome.is_success(), "Admin should be able to set TLD config");
    println!("Admin successfully set TLD config");

    // Verify the config was set
    let current_config = contract
        .view("get_tld_config")
        .args_json(json!({}))
        .await?
        .json::<Option<serde_json::Value>>()?;
    assert!(current_config.is_some(), "TLD config should be set");
    println!("TLD config verification successful");

    // Test 2: Non-admin cannot set TLD config
    println!("Test 2: Non-admin cannot set TLD config");
    let non_admin_set_outcome = non_admin_account
        .call(contract.id(), "set_tld_config")
        .args_json(json!({
            "tld_config": json!({
                "multi_part_tlds": [["gov", "uk"]],
                "enabled": true
            })
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(!non_admin_set_outcome.is_success(), "Non-admin should not be able to set TLD config");
    println!("Non-admin correctly prevented from setting TLD config");

    // Test 3: Admin can disable TLD config
    println!("Test 3: Admin can disable TLD config");
    let admin_disable_outcome = admin_account
        .call(contract.id(), "set_tld_config")
        .args_json(json!({
            "tld_config": null
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(admin_disable_outcome.is_success(), "Admin should be able to disable TLD config");
    println!("Admin successfully disabled TLD config");

    // Verify the config was disabled
    let current_config_after_disable = contract
        .view("get_tld_config")
        .args_json(json!({}))
        .await?
        .json::<Option<serde_json::Value>>()?;
    assert!(current_config_after_disable.is_none(), "TLD config should be disabled");
    println!("TLD config disable verification successful");

    println!("All set_tld_config admin-only tests passed successfully");

    Ok(())
}

#[tokio::test]
async fn test_set_vrf_settings_admin_only() -> Result<(), Box<dyn std::error::Error>> {
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;
    let admin_account = sandbox.dev_create_account().await?;
    let non_admin_account = sandbox.dev_create_account().await?;

    // Initialize the contract
    let init_outcome = contract
        .call("init")
        .args_json(json!({
            "vrf_settings": null,
            "tld_config": null
        }))
        .transact()
        .await?;
    assert!(init_outcome.is_success(), "Initialization failed: {:?}", init_outcome.outcome());

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

    // Test 1: Admin can set VRF settings
    println!("Test 1: Admin can set VRF settings");
    let vrf_settings = json!({
        "max_input_age_ms": 600000, // 10 minutes
        "max_block_age": 200,       // 200 blocks
        "enabled": true,
        "max_authenticators_per_account": 5
    });

    let admin_set_outcome = admin_account
        .call(contract.id(), "set_vrf_settings")
        .args_json(json!({
            "settings": vrf_settings
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(admin_set_outcome.is_success(), "Admin should be able to set VRF settings");
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
            "settings": json!({
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
    let updated_vrf_settings = json!({
        "max_input_age_ms": 900000, // 15 minutes
        "max_block_age": 300,       // 300 blocks
        "enabled": false,           // Disable VRF
        "max_authenticators_per_account": 8
    });

    let admin_update_outcome = admin_account
        .call(contract.id(), "set_vrf_settings")
        .args_json(json!({
            "settings": updated_vrf_settings
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(admin_update_outcome.is_success(), "Admin should be able to update VRF settings");
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

