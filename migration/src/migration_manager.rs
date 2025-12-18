use anyhow::Result;
use serde_json::Value;
use tracing::info;

use near_api::{NearGas, NearToken};

use crate::near_client::NearClient;

pub struct MigrationManager {
    near_client: NearClient,
}

impl MigrationManager {
    pub async fn new() -> Result<Self> {
        let near_client = NearClient::new()
            .map_err(|e| anyhow::anyhow!("Failed to create NearClient: {}", e))?;

        Ok(Self { near_client })
    }

    pub async fn get_contract_state(&self) -> Result<Value> {
        let result: near_api::Data<Value> = self
            .near_client
            .call("get_contract_state", ())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to call get_contract_state: {}", e))?;
        Ok(result.data)
    }

    pub async fn migrate_v4_to_v5(&self, gas_tgas: u64) -> Result<()> {
        info!("Calling contract migrate() with {} Tgas...", gas_tgas);

        let outcome = self
            .near_client
            .call_with_transaction(
                "migrate",
                (),
                NearGas::from_tgas(gas_tgas),
                NearToken::from_yoctonear(0),
            )
            .await
            .map_err(|e| anyhow::anyhow!("Failed to call migrate: {}", e))?;

        info!("Migration transaction sent. Status: {:?}", outcome.status);

        let state = self.get_contract_state().await?;
        info!("Contract state after migration: {}", serde_json::to_string_pretty(&state)?);

        Ok(())
    }
}
