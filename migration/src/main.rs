use clap::{Parser, Subcommand};
use anyhow::Result;
use tracing::info;

mod v4_to_v5;
use v4_to_v5::{MigrationManager, MigrationConfig};
mod near_client;


#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create backup of contract state
    Backup {
        /// Output file for backup
        #[arg(long, default_value = "backup.json")]
        output: String,
    },

    /// Migrate contract data from backup
    Migrate {
        /// Backup file to migrate from
        #[arg(long)]
        backup_file: String,

        /// Batch size for migration
        #[arg(long, default_value = "3")]
        batch_size: u32,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Backup { output } => {
            let config = MigrationConfig::new(output.clone());
            let manager = MigrationManager::new(config).await?;
            manager.backup_exported_migration_data().await?;
        }

        Commands::Migrate { backup_file, batch_size } => {
            let mut config = MigrationConfig::new(backup_file.clone());
            config.batch_size = batch_size;

            let manager = MigrationManager::new(config).await?;
            let results = manager.migrate_authenticator_batch_from_file(backup_file).await?;

            let total_migrated = results.iter().map(|r| r.migrated_count).sum::<u32>();
            info!("Migration completed successfully! Total migrated: {}", total_migrated);
        }
    }

    Ok(())
}