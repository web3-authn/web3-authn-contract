use std::sync::Mutex;
use std::sync::Once;
use near_workspaces::types::Gas;
use serde_json::json;
use near_workspaces::{Worker};
use near_workspaces::network::Sandbox;

// Shared contract instance for all tests (deploy just once)
static CONTRACT: Mutex<Option<near_workspaces::Contract>> = Mutex::new(None);
static INIT: Once = Once::new();
static WORKER: Mutex<Option<Worker<Sandbox>>> = Mutex::new(None);

pub async fn get_or_deploy_contract() -> near_workspaces::Contract {
    // Try to get existing contract first
    if let Some(contract) = CONTRACT.lock().unwrap().clone() {
        return contract;
    }

    // Initialize contract if not already done
    INIT.call_once(|| {
        println!("Deploying shared test contract for all E2E tests...");
    });

    // Deploy contract (this will only happen once due to the Once)
    let contract = {
        let contract_wasm = near_workspaces::compile_project("./").await.expect("Failed to compile project");
        let sandbox = near_workspaces::sandbox().await.expect("Failed to create sandbox");
        // Store the worker for reuse across tests
        *WORKER.lock().unwrap() = Some(sandbox.clone());
        let contract = sandbox.dev_deploy(&contract_wasm).await.expect("Failed to deploy contract");

        // Initialize contract with default settings
        let _init_result = contract
            .call("init")
            .args_json(json!({}))
            .gas(Gas::from_tgas(100))
            .transact()
            .await.expect("Failed to initialize contract");

        println!("Shared contract deployed and initialized successfully");
        contract
    };

    // Store the contract for future use
    *CONTRACT.lock().unwrap() = Some(contract.clone());

    contract
}

/// Returns the shared worker used to deploy the contract.
/// Must be called after `get_or_deploy_contract()` has initialized the worker.
pub async fn get_shared_worker() -> Worker<Sandbox> {
    WORKER
        .lock()
        .unwrap()
        .as_ref()
        .expect("Worker not initialized; call get_or_deploy_contract() first")
        .clone()
}

pub async fn deploy_new_contract() -> near_workspaces::Contract {
    // Deploy contract (this will only happen once due to the Once)
    let contract_wasm = near_workspaces::compile_project("./").await.expect("Failed to compile project");
    let sandbox = near_workspaces::sandbox().await.expect("Failed to create sandbox");
    let contract = sandbox.dev_deploy(&contract_wasm).await.expect("Failed to deploy contract");

    // Initialize contract with default settings
    let _init_result = contract
        .call("init")
        .args_json(json!({
            "vrf_settings": null,
        }))
        .gas(Gas::from_tgas(100))
        .transact()
        .await.expect("Failed to initialize contract");

    println!("Shared contract deployed and initialized successfully");
    contract
}
