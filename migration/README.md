# Migration

First uncomment `mod migrations` in web3-authn-contract/src/lib.rs.
Then `just deploy-dev` to deploy the migration function to the contract.
Then follow the steps below.

## Usage

1. Set your private key as an environment variable:
   ```bash
   export PRIVATE_KEY="ed25519:your_private_key_here"
   ```

2. Create backup before deploying new contract version
```bash
cargo run -- backup --output v4_backup.json
```
This will create a backup file in `migration/backups/` with a timestamp.

3. Deploy new contract version (V5)


4. Migrate from backup with batch processing
```bash
cargo run -- migrate --backup-file v4_backup_20241206_143022.json --batch-size 3
```

The tool will automatically look for backup files in `migration/backups/` directory.

#### Create Backup

Call the backup command (before you deploy the next migrated version of the contract) to export all existing v4 authenticators
to local json file.

This will:
- Call the contract's `export_migration_data` method
- Create `migration/backups/` directory if it doesn't exist
- Save all authenticators and contract state to a timestamped JSON file in the backups directory
- Display statistics about the exported data

## Backup Directory Structure

Backups are automatically saved to the `migration/backups/` directory with the following naming convention:
```
migration/backups/{output_name}_{timestamp}.json
```

Example: `migration/backups/v4_backup_20241206_143022.json`

#### Migrate from Backup

Migrates authenticators from the backup file in batches with 3-second delays between batches:

```bash
cargo run -- migrate \
  --contract-id your-contract.testnet \
  --network testnet \
  --backup-file backup_20241206_143022.json \
  --batch-size 5
```

This will:
- Load the exported migration data from the backup file
- Split accounts into batches based on the `--batch-size` parameter
- Call `migrate_authenticator_batch(exported_accounts)` - Migrates a batch of accounts
- Wait 3 seconds between each batch call
- Display progress and final migration statistics
