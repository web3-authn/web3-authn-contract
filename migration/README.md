# Migration

This workspace uses an **on-chain migration** method (`migrate()`) for state-breaking upgrades.

## Usage

1. Configure environment variables (either export them, or create `migration/.env`):
   - `NEAR_NETWORK_ID` (e.g. `testnet` / `mainnet`)
   - `CONTRACT_ID` (contract account)
   - `SIGNER_ACCOUNT_ID` (must be contract `owner` or in `admins`)
   - `SIGNER_PRIVATE_KEY` (e.g. `ed25519:...`)

2. Deploy the upgraded contract WASM (e.g. `just upgrade-dev` / `just upgrade`).

3. Confirm current state:
   ```bash
   cargo run -p migration -- contract-state
   ```

4. Run the on-chain migration (example for v4 -> v5):
   ```bash
   cargo run -p migration -- migrate-v4-to-v5 --gas-tgas 300
   ```

Notes:
- `migrate()` is guarded and can only migrate from `contract_version == 4`.
- After migration, newly registered devices will start storing `near_public_key` on each authenticator; existing authenticators will have `near_public_key = None`.
