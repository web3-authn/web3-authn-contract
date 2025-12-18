use clap::{Parser, Subcommand};
use anyhow::Result;
use tracing::info;

mod near_client;
mod migration_manager;

use migration_manager::MigrationManager;


#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print `get_contract_state`
    ContractState,

    /// Call on-chain `migrate()` (v4 -> v5)
    MigrateV4ToV5 {
        /// Gas to attach (in Tgas)
        #[arg(long, default_value = "300")]
        gas_tgas: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let manager = MigrationManager::new().await?;

    match cli.command {
        Commands::ContractState => {
            let state = manager.get_contract_state().await?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }

        Commands::MigrateV4ToV5 { gas_tgas } => {
            manager.migrate_v4_to_v5(gas_tgas).await?;
            info!("Migration completed successfully");
        }
    }

    Ok(())
}
