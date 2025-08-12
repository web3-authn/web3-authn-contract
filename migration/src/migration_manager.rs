use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tracing::info;

use near_api::*;
use crate::near_client::NearClient;

// Migration progress tracking
#[derive(Debug, Serialize, Deserialize)]
pub struct MigrationProgress {
    pub total_authenticators: u32,
    pub migrated_count: u32,
    pub batches_completed: Vec<ContractMigrationProgress>,
    pub backup_files: Vec<String>,
}

// Contract's MigrationProgress structure (for RPC calls)
#[derive(Debug, Serialize, Deserialize)]
pub struct ContractMigrationProgress {
    pub migrated_authenticators: Vec<String>,
    pub migrated_count: u32,
    pub batch_size: u32,
}

// Migration configuration
#[derive(Debug, Clone)]
pub struct MigrationConfig {
    pub batch_size: u32,
    pub backup_file: String,
}

impl MigrationConfig {
    pub fn new(backup_file: String) -> Self {
        Self {
            batch_size: 10,
            backup_file,
        }
    }
}

// Migration operations
pub struct MigrationManager {
    config: MigrationConfig,
    near_client: NearClient,
}

impl MigrationManager {
    pub async fn new(config: MigrationConfig) -> Result<Self> {
        let near_client = NearClient::new()
            .map_err(|e| anyhow::anyhow!("Failed to create NearClient: {}", e))?;

        Ok(Self {
            config,
            near_client
        })
    }

    /// Create comprehensive backup of contract state
    pub async fn backup_exported_migration_data(&self) -> Result<ExportedMigrationData> {
        info!("Creating backup for contract");
        let result: Data<ExportedMigrationData> = self.near_client.call(
            "export_migration_data",
            serde_json::json!({})
        ).await
        .map_err(|e| anyhow::anyhow!("Failed to get contract state: {}", e))?;

        let exported_migration_data = result.data;
        info!(
            "Contract state: {} registered users, {} authenticators",
            exported_migration_data.registered_users.len(),
            exported_migration_data.exported_accounts.iter().map(|account| account.authenticators.len() as u32).sum::<u32>()
        );

        // Create backups directory if it doesn't exist
        let backups_dir = "backups";
        fs::create_dir_all(backups_dir).await
            .map_err(|e| anyhow::anyhow!("Failed to create backups directory: {}", e))?;

        // Save backup to file
        match serde_json::to_string_pretty(&exported_migration_data) {
            Err(e) => anyhow::bail!("Failed to serialize exported migration data: {}", e),
            Ok(json) => {
                let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
                let file_name = format!("{}/{}_{}.json", backups_dir, self.config.backup_file, timestamp);
                fs::write(&file_name, json).await
                    .map_err(|e| anyhow::anyhow!("Failed to save backup to {}: {}", file_name, e))?;

                info!("Backup saved to {} with {} authenticators", file_name, exported_migration_data.exported_accounts.iter().map(|account| account.authenticators.len() as u32).sum::<u32>());
                Ok(exported_migration_data)
            }
        }
    }

    pub async fn migrate_authenticator_batch_from_file(&self, backup_file: String) -> Result<Vec<ContractMigrationProgress>> {
        info!("Loading exported migration data from backup file: {}", backup_file);

        // Determine the full path to the backup file
        let backup_path = if backup_file.starts_with("backups/") {
            backup_file.clone()
        } else {
            format!("backups/{}", backup_file)
        };

        info!("Reading from backup file: {}", backup_path);

        // Load exported migration data from backup json file
        let backup_content = tokio::fs::read_to_string(&backup_path).await
            .map_err(|e| anyhow::anyhow!("Failed to read backup file: {}", e))?;
        let exported_migration_data: ExportedMigrationData = serde_json::from_str(&backup_content)
            .map_err(|e| anyhow::anyhow!("Failed to parse backup file: {}", e))?;

        info!("Loaded {} accounts with {} total authenticators",
              exported_migration_data.exported_accounts.len(),
              exported_migration_data.exported_accounts.iter().map(|account| account.authenticators.len() as u32).sum::<u32>());

        // Split the entries into batches (by batch_size)
        let batch_size = self.config.batch_size as usize;
        let accounts = exported_migration_data.exported_accounts;
        let total_accounts = accounts.len();
        let total_batches = (total_accounts + batch_size - 1) / batch_size; // Ceiling division

        info!("Splitting {} accounts into {} batches of size {}", total_accounts, total_batches, batch_size);

        let mut all_results = Vec::new();

        // Process each batch with 3s delays between calls
        for (batch_num, chunk) in accounts.chunks(batch_size).enumerate() {
            let batch_num = batch_num + 1; // 1-indexed batch numbers
            info!("Processing batch {}/{} with {} accounts", batch_num, total_batches, chunk.len());

            // Call migrate_authenticator_batch for this chunk
            let result = self.migrate_authenticator_batch(chunk.to_vec()).await?;
            let migrated_count = result.migrated_count;
            all_results.push(result);

            info!("Completed batch {}/{} - migrated {} authenticators",
                  batch_num, total_batches, migrated_count);

            // Add 3s delay between batches (except for the last batch)
            if batch_num < total_batches {
                info!("Waiting 3 seconds before next batch...");
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            }
        }

        let total_migrated = all_results.iter().map(|r| r.migrated_count).sum::<u32>();
        info!("Migration completed! Total batches: {}, Total migrated: {}", total_batches, total_migrated);

        Ok(all_results)
    }

    // Helper methods
    async fn migrate_authenticator_batch(&self, exported_accounts: Vec<ExportedAccounts>) -> Result<ContractMigrationProgress> {
        info!("Migrating {} accounts with {} authenticators", exported_accounts.len(), exported_accounts.iter().map(|account| account.authenticators.len() as u32).sum::<u32>());

        // Use near_client to call the function with transaction
        let _result = self.near_client.call_with_transaction(
            "migrate_authenticator_batch",
            serde_json::json!({
                "exported_accounts": exported_accounts,
            })
        ).await
        .map_err(|e| anyhow::anyhow!("Failed to call migrate_authenticator_batch: {}", e))?;

        info!("Transaction sent successfully");
        // Return a default progress for now
        Ok(ContractMigrationProgress {
            migrated_authenticators: vec![],
            migrated_count: exported_accounts.iter().map(|account| account.authenticators.len() as u32).sum(),
            batch_size: exported_accounts.len() as u32,
        })
    }
}

// Generic exported migration data structure
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportedMigrationData {
    pub contract_version: u32,
    pub registered_users: Vec<AccountId>,
    pub exported_accounts: Vec<ExportedAccounts>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExportedAccounts {
    pub account_id: AccountId,
    pub authenticators: Vec<ExportedAuthenticator>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExportedAuthenticator {
    pub credential_id: String,
    pub authenticator: serde_json::Value, // Generic authenticator data
}