mod utils_mocks;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use serde_json::json;

use utils_mocks::{
    create_mock_webauthn_registration,
    generate_deterministic_vrf_public_key,
    generate_vrf_data,
};

// IMPORTANT: This test verifies that a *real* V4 on-chain state can be upgraded to the
// current contract and successfully migrated to V5.
//
// To make this meaningful, we must build/deploy the historical V4 wasm first, create state via
// normal contract calls, then deploy the current wasm and run `migrate()`.
//
// If we didn't pin to a specific V4 git revision, the test could silently start generating
// "V4 state" using whatever the current code is (making the migration test a false positive).
const V4_GIT_REV: &str = "d240f6b";

// Ensures we don't leave temp directories behind even if the test fails/panics.
struct TempDirGuard(PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("CARGO_MANIFEST_DIR should be inside the workspace")
        .to_path_buf()
}

fn run_cmd(cmd: &mut Command, current_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let output = cmd.current_dir(current_dir).output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "Command failed: {cmd:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
    .into())
}

// Build `web3-authn-contract` wasm exactly as it existed at `rev`, without modifying the current
// working tree (no `git checkout`, no committed fixtures).
//
// This keeps the test hermetic and ensures we're truly testing a V4 -> V5 upgrade path.
async fn compile_contract_wasm_at_git_rev(rev: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    println!("Compiling historical contract wasm at git rev {rev}...");
    let started_at = Instant::now();

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let temp_dir = std::env::temp_dir().join(format!("web3-authn-contract-{rev}-{now}"));
    std::fs::create_dir_all(&temp_dir)?;
    let _guard = TempDirGuard(temp_dir.clone());

    let tar_path = temp_dir.join("repo.tar");
    let extracted_root = temp_dir.join("repo");
    std::fs::create_dir_all(&extracted_root)?;

    let repo_root = repo_root();

    println!("  - Creating archive from git (repo: {})", repo_root.display());
    let mut git_archive = Command::new("git");
    git_archive
        .arg("archive")
        .arg("--format=tar")
        .arg("-o")
        .arg(&tar_path)
        .arg(rev);
    run_cmd(&mut git_archive, &repo_root)?;

    println!("  - Extracting archive (tar: {})", tar_path.display());
    let mut tar_extract = Command::new("tar");
    tar_extract.arg("-xf").arg(&tar_path).arg("-C").arg(&extracted_root);
    run_cmd(&mut tar_extract, &repo_root)?;

    let extracted_contract_root = extracted_root.join("web3-authn-contract");
    let extracted_contract_root_str = extracted_contract_root
        .to_str()
        .ok_or("Extracted repo contract path is not valid UTF-8")?;
    println!(
        "  - Compiling extracted contract (path: {})",
        extracted_contract_root.display()
    );
    let wasm = near_workspaces::compile_project(extracted_contract_root_str).await?;
    println!(
        "  - V4 wasm compiled ({} bytes) in {:?}",
        wasm.len(),
        started_at.elapsed()
    );
    Ok(wasm)
}

#[tokio::test]
async fn test_migrate_v4_to_v5_then_register_new_authenticator() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting migration dry-run test (v4 -> v5)...");
    println!("  - V4 git rev: {V4_GIT_REV}");

    // Deploy V4 contract and create real on-chain V4 state via contract calls (no patch_state).
    println!("[1/12] Building historical V4 wasm...");
    let v4_wasm = compile_contract_wasm_at_git_rev(V4_GIT_REV).await?;

    println!("[2/12] Spawning sandbox worker...");
    let worker = near_workspaces::sandbox().await?;

    println!("[3/12] Deploying V4 contract...");
    let contract = worker.dev_deploy(&v4_wasm).await?;
    println!("  - Deployed V4 contract: {}", contract.id());

    // Initialize V4 contract.
    println!("[4/12] Initializing V4 contract...");
    let init_outcome = contract
        .call("init")
        .args_json(json!({}))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    println!("  - init success: {}", init_outcome.is_success());
    println!("  - init logs: {:?}", init_outcome.logs());
    println!("  - init gas burnt: {:?}", init_outcome.total_gas_burnt);
    assert!(init_outcome.is_success(), "V4 init failed: {init_outcome:#?}");

    // Create a real user account via the contract (same flow as in E2E tests),
    // but we generate the keypair so we can sign transactions as that user later.
    println!("[5/12] Creating user account + registering first authenticator (V4)...");
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let user_id = format!("u{now}.{}", contract.id());
    let user_account_id: near_workspaces::AccountId = user_id.parse()?;
    let user_sk = SecretKey::from_random(KeyType::ED25519);
    let user_pk = user_sk.public_key().to_string();
    println!("  - new_account_id: {user_account_id}");
    println!("  - new_public_key: {user_pk}");

    let rp_id = "example.com";
    let session_id = "create_account_session";
    let current_block_height = worker.view_block().await?.height();
    println!("  - rp_id: {rp_id}");
    println!("  - session_id: {session_id}");
    println!("  - block height: {current_block_height}");
    let vrf_data = generate_vrf_data(rp_id, &user_id, session_id, Some(current_block_height), None).await?;
    let webauthn_registration = create_mock_webauthn_registration(&vrf_data.output, rp_id, &user_id, None);
    let deterministic_vrf_public_key = generate_deterministic_vrf_public_key();

    let create_outcome = contract
        .call("create_account_and_register_user")
        .args_json(json!({
            "new_account_id": user_account_id,
            "new_public_key": user_pk,
            "vrf_data": vrf_data.to_json(),
            "webauthn_registration": webauthn_registration,
            "deterministic_vrf_public_key": deterministic_vrf_public_key,
            "authenticator_options": { "origin_policy": { "single": true } }
        }))
        .deposit(NearToken::from_near(1))
        .gas(Gas::from_tgas(200))
        .transact()
        .await?;
    println!(
        "  - create_account_and_register_user success: {}",
        create_outcome.is_success()
    );
    println!("  - create logs: {:?}", create_outcome.logs());
    println!("  - create gas burnt: {:?}", create_outcome.total_gas_burnt);
    assert!(
        create_outcome.is_success(),
        "create_account_and_register_user (V4) failed: {create_outcome:#?}\nlogs: {:?}",
        create_outcome.logs()
    );

    let user = near_workspaces::Account::from_secret_key(user_account_id.clone(), user_sk, &worker);
    println!("  - user account created: {}", user.id());

    // Ensure we created real V4 state.
    println!("[6/12] Verifying V4 state (authenticators + device counter)...");
    let authenticators_v4: Vec<(String, serde_json::Value)> = contract
        .view("get_authenticators_by_user")
        .args_json(json!({ "user_id": user.id() }))
        .await?
        .json()?;
    assert_eq!(authenticators_v4.len(), 1);
    let legacy_cred_id = authenticators_v4[0].0.clone();
    println!("  - legacy credential_id: {legacy_cred_id}");

    let device_counter_v4: u8 = contract
        .view("get_device_counter")
        .args_json(json!({ "account_id": user.id() }))
        .await?
        .json()?;
    println!("  - device_counter (V4): {device_counter_v4}");
    assert_eq!(device_counter_v4, 1);

    // Upgrade to V5 code (no init call).
    println!("[7/12] Compiling current contract wasm (V5)...");
    let v5_wasm = near_workspaces::compile_project("./").await?;
    println!("  - V5 wasm compiled ({} bytes)", v5_wasm.len());

    println!("[8/12] Deploying current wasm (upgrade)...");
    let contract = contract.as_account().deploy(&v5_wasm).await?.into_result()?;
    println!("  - Contract upgraded (account: {})", contract.id());

    // Sanity-check: V5 code can read V4 top-level state before migration.
    println!("[9/12] Reading contract state pre-migration...");
    let contract_state_before: serde_json::Value = contract
        .view("get_contract_state")
        .args_json(json!({}))
        .await?
        .json()?;
    println!(
        "  - contract_version before migrate(): {:?}",
        contract_state_before["contract_version"].as_u64()
    );
    assert_eq!(contract_state_before["contract_version"].as_u64(), Some(4));

    // Run on-chain migration.
    println!("[10/12] Running migrate()...");
    let migrate_outcome = contract
        .call("migrate")
        .args_json(json!({}))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    println!("  - migrate success: {}", migrate_outcome.is_success());
    println!("  - migrate logs: {:?}", migrate_outcome.logs());
    println!("  - migrate gas burnt: {:?}", migrate_outcome.total_gas_burnt);
    if migrate_outcome.is_failure() {
        panic!("migrate() failed: {migrate_outcome:#?}\nlogs: {:?}", migrate_outcome.logs());
    }

    // Verify we can read state as V5.
    println!("[11/12] Verifying V5 state and legacy authenticator deserialization...");
    let contract_state: serde_json::Value = contract
        .view("get_contract_state")
        .args_json(json!({}))
        .await?
        .json()?;
    println!(
        "  - contract_version after migrate(): {:?}",
        contract_state["contract_version"].as_u64()
    );
    assert_eq!(contract_state["contract_version"].as_u64(), Some(5));

    // Legacy authenticator should still be present and deserializable; `near_public_key` is None.
    let authenticators_before: Vec<(String, serde_json::Value)> = contract
        .view("get_authenticators_by_user")
        .args_json(json!({
            "user_id": user.id(),
        }))
        .await?
        .json()?;

    assert_eq!(authenticators_before.len(), 1);
    assert_eq!(authenticators_before[0].0, legacy_cred_id);
    assert!(authenticators_before[0].1.get("near_public_key").is_none());
    println!(
        "  - legacy authenticator ok (credential_id: {})",
        authenticators_before[0].0
    );

    // Device counter should reflect the legacy device_number.
    let device_counter: u8 = contract
        .view("get_device_counter")
        .args_json(json!({
            "account_id": user.id(),
        }))
        .await?
        .json()?;
    println!("  - device_counter (V5): {device_counter}");
    assert_eq!(device_counter, 1);

    // Register a new authenticator on V5 state and confirm it stores `near_public_key`.
    println!("[12/12] Registering second authenticator on V5 state...");
    let current_block_height = worker.view_block().await?.height();
    let vrf_user_id = user.id().as_str().to_string();
    let vrf_data = generate_vrf_data(rp_id, &vrf_user_id, "link_device_session", Some(current_block_height), None).await?;
    let credential_id_hint = format!("{vrf_user_id}-device2");
    println!("  - link_device credential_id_hint: {credential_id_hint}");
    let webauthn_registration = create_mock_webauthn_registration(&vrf_data.output, rp_id, &credential_id_hint, None);
    let deterministic_vrf_public_key = generate_deterministic_vrf_public_key();

    let register_outcome = user.call(contract.id(), "link_device_register_user")
        .args_json(json!({
            "vrf_data": vrf_data.to_json(),
            "webauthn_registration": webauthn_registration,
            "deterministic_vrf_public_key": deterministic_vrf_public_key,
            "authenticator_options": { "origin_policy": { "single": true } }
        }))
        .gas(Gas::from_tgas(200))
        .transact()
        .await?;
    println!(
        "  - link_device_register_user success: {}",
        register_outcome.is_success()
    );
    println!("  - link_device logs: {:?}", register_outcome.logs());
    println!("  - link_device gas burnt: {:?}", register_outcome.total_gas_burnt);
    if register_outcome.is_failure() {
        panic!("link_device_register_user failed: {register_outcome:#?}\nlogs: {:?}", register_outcome.logs());
    }

    let authenticators_after: Vec<(String, serde_json::Value)> = contract
        .view("get_authenticators_by_user")
        .args_json(json!({
            "user_id": user.id(),
        }))
        .await?
        .json()?;

    assert_eq!(authenticators_after.len(), 2);
    println!("Authenticators after migration + new registration:");
    for (credential_id, authenticator) in &authenticators_after {
        let device_number = authenticator.get("device_number").and_then(|v| v.as_u64());
        let near_public_key = authenticator.get("near_public_key").and_then(|v| v.as_str());
        println!(
            "  - credential_id: {credential_id} | device_number: {device_number:?} | near_public_key: {near_public_key:?}"
        );
    }

    let mut saw_legacy = false;
    let mut saw_new_with_pk = false;
    for (credential_id, authenticator) in authenticators_after {
        if credential_id == legacy_cred_id {
            saw_legacy = true;
            assert!(authenticator.get("near_public_key").is_none());
            assert_eq!(authenticator.get("device_number").and_then(|v| v.as_u64()), Some(1));
        } else {
            let pk = authenticator
                .get("near_public_key")
                .and_then(|v| v.as_str())
                .expect("New authenticator should include near_public_key");
            assert!(pk.starts_with("ed25519:") || pk.starts_with("secp256k1:"));
            assert_eq!(authenticator.get("device_number").and_then(|v| v.as_u64()), Some(2));
            saw_new_with_pk = true;
        }
    }

    assert!(saw_legacy, "Should still return legacy authenticator after migration");
    assert!(saw_new_with_pk, "Should return new authenticator with near_public_key after migration");

    Ok(())
}
