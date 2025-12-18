#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"

GAS_TGAS="${1:-300}"

cd "${REPO_ROOT}"

echo "==> Running sandbox migration dry-run test (v4 -> v5)..."
cargo test -p web3-authn-contract --test migration_test_v4_to_v5 -- --nocapture

echo "==> Dry-run succeeded. Running on-chain migration (gas: ${GAS_TGAS} Tgas)..."
cd "${REPO_ROOT}/migration"
cargo run -- migrate-v4-to-v5 --gas-tgas "${GAS_TGAS}"
