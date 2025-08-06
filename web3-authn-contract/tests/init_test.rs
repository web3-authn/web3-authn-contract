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
        .args_json(json!({}))
        .gas(Gas::from_tgas(150))
        .transact()
        .await?;

    println!("init_outcome: {:?}", init_outcome.outcome());

    // Check if the transaction was successful
    if init_outcome.outcome().is_success() {
        println!("✓ Contract initialization successful");
    } else {
        panic!("Initialization failed: {:?}", init_outcome.outcome());
    }
    Ok(())
}
