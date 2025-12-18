use near_api::*;
use near_primitives::types::AccountId;
use near_crypto::SecretKey;

use std::sync::Arc;
use dotenv::dotenv;
use near_api::{NearGas, NearToken};

pub struct NearClient {
    signer_account_id: AccountId,
    signer: Arc<Signer>,
    contract_id: AccountId,
    network: NetworkConfig,
}

impl NearClient {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        dotenv().ok();
        // Read environment variables
        let signer_account_id = std::env::var("SIGNER_ACCOUNT_ID")
            .map_err(|_| "SIGNER_ACCOUNT_ID environment variable not set")?;
        let signer_private_key = std::env::var("SIGNER_PRIVATE_KEY")
            .map_err(|_| "SIGNER_PRIVATE_KEY environment variable not set")?;

        let contract_id = std::env::var("CONTRACT_ID")
            .map_err(|_| "CONTRACT_ID environment variable not set")?;
        let network_name = std::env::var("NEAR_NETWORK_ID").unwrap_or_else(|_| "testnet".to_string());

        // Parse account IDs
        let signer_account_id = AccountId::try_from(signer_account_id)?;
        // Initialize signer
        let secret_key: SecretKey = signer_private_key.parse()?;
        let signer = Signer::new(Signer::from_secret_key(secret_key))?;
        // Contract ID
        let contract_id = AccountId::try_from(contract_id)?;

        let rpc_url = match network_name.as_str() {
            "mainnet" => "https://rpc.mainnet.near.org".to_string(),
            "testnet" => "https://rpc.testnet.near.org".to_string(),
            _ => format!("https://rpc.{}.near.org", network_name),
        };

        // Initialize network configuration
        let mut network = if network_name == "mainnet" {
            NetworkConfig::mainnet()
        } else {
            NetworkConfig::testnet()
        };
        network.rpc_endpoints = vec![RPCEndpoint::new(rpc_url.parse().unwrap())];

        Ok(Self {
            signer_account_id,
            signer,
            contract_id,
            network
        })
    }

    pub async fn call<Args, T>(
        &self,
        method: &str,
        args: Args,
    ) -> Result<Data<T>, Box<dyn std::error::Error>>
    where
        Args: serde::Serialize,
        T: serde::de::DeserializeOwned + Send + Sync,
    {
        Contract(self.contract_id.clone())
            .call_function(method, args)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?
            .read_only()
            .fetch_from(&self.network)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    pub async fn call_with_transaction<Args>(
        &self,
        method: &str,
        args: Args,
        gas: NearGas,
        deposit: NearToken,
    ) -> Result<near_primitives::views::FinalExecutionOutcomeView, Box<dyn std::error::Error>>
    where
        Args: serde::Serialize,
    {
        Contract(self.contract_id.clone())
            .call_function(method, args)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?
            .transaction()
            .gas(gas)
            .deposit(deposit)
            .with_signer(self.signer_account_id.clone(), self.signer.clone())
            .send_to(&self.network)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }
}
