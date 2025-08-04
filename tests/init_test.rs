use near_workspaces::types::Gas;
use serde_json::json;

#[tokio::test]
async fn test_basic_contract_init() -> Result<(), Box<dyn std::error::Error>> {
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    println!("\nContract deployed successfully: {:?}", contract.id());

    // Try a simple init with minimal parameters
    let init_outcome = contract
        .call("init")
        .args_json(json!({
            "vrf_settings": null,
            "tld_config": null
        }))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;

    println!("init_outcome: {:?}", init_outcome.outcome());
    assert!(init_outcome.is_success(), "Initialization failed: {:?}", init_outcome.outcome());
    Ok(())
}

#[tokio::test]
async fn test_contract_init_with_custom_settings() -> Result<(), Box<dyn std::error::Error>> {
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    println!("\nContract deployed successfully: {:?}", contract.id());

    // Custom VRF settings
    let custom_vrf_settings = json!({
        "max_input_age_ms": 120000, // 2 minutes
        "max_block_age": 200,       // 200 blocks
        "enabled": false,           // Disable VRF
        "max_authenticators_per_account": 5
    });

    // Custom TLD configuration
    let custom_tld_config = json!({
        "multi_part_tlds": [
            ["co", "uk"],
            ["com", "au"],
            ["gov", "uk"],
            ["org", "uk"]
        ],
        "enabled": true
    });

    // Initialize contract with custom settings
    let init_outcome = contract
        .call("init")
        .args_json(json!({
            "vrf_settings": custom_vrf_settings,
            "tld_config": custom_tld_config
        }))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;

    println!("init_outcome: {:?}", init_outcome.outcome());
    assert!(init_outcome.is_success(), "Initialization failed: {:?}", init_outcome.outcome());

    // Verify the settings were applied correctly
    println!("Verifying custom settings were applied...");

    // Check VRF settings
    let vrf_settings = contract
        .view("get_vrf_settings")
        .args_json(json!({}))
        .await?
        .json::<serde_json::Value>()?;

    assert_eq!(vrf_settings["max_input_age_ms"], 120000, "max_input_age_ms should be 120000");
    assert_eq!(vrf_settings["max_block_age"], 200, "max_block_age should be 200");
    assert_eq!(vrf_settings["enabled"], false, "VRF should be disabled");
    assert_eq!(vrf_settings["max_authenticators_per_account"], 5, "max_authenticators_per_account should be 5");
    println!("✓ VRF settings verified");

    // Check TLD configuration
    let tld_config = contract
        .view("get_tld_config")
        .args_json(json!({}))
        .await?
        .json::<Option<serde_json::Value>>()?;

    assert!(tld_config.is_some(), "TLD config should be set");
    let tld_config_value = tld_config.unwrap();
    assert_eq!(tld_config_value["enabled"], true, "TLD config should be enabled");

    let multi_part_tlds = tld_config_value["multi_part_tlds"].as_array().unwrap();
    assert_eq!(multi_part_tlds.len(), 4, "Should have 4 multi-part TLDs");

    // Verify specific TLDs
    let expected_tlds = vec![
        vec!["co", "uk"],
        vec!["com", "au"],
        vec!["gov", "uk"],
        vec!["org", "uk"]
    ];

    for (i, expected_tld) in expected_tlds.iter().enumerate() {
        let actual_tld = multi_part_tlds[i].as_array().unwrap();
        assert_eq!(actual_tld[0], expected_tld[0], "TLD {} first part mismatch", i);
        assert_eq!(actual_tld[1], expected_tld[1], "TLD {} second part mismatch", i);
    }
    println!("✓ TLD configuration verified");

    // Check contract state
    let contract_state = contract
        .view("get_contract_state")
        .args_json(json!({}))
        .await?
        .json::<serde_json::Value>()?;

    assert_eq!(contract_state["registered_users_count"], 0, "Should start with 0 registered users");
    assert_eq!(contract_state["admins_count"], 0, "Should start with 0 admins");
    println!("✓ Contract state verified");

    println!("All custom settings verified successfully!");
    Ok(())
}