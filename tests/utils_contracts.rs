use near_workspaces::types::Gas;
use serde_json::json;

pub async fn deploy_test_contract() -> Result<near_workspaces::Contract, Box<dyn std::error::Error>> {
    println!("Deploying test contract...");

    let contract_wasm = near_workspaces::compile_project("./").await?;
    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    // Initialize contract with default settings
    let _init_result = contract
        .call("init")
        .args_json(json!({
            "vrf_settings": null,
            "tld_config": null
        }))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;

    println!("Contract deployed and initialized");
    Ok(contract)
}

