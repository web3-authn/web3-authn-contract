#!/bin/bash

# Development contract upgrade script
# This script can be used to upgrade the contract without requiring a clean git state
# Useful for rapid development and testing

source .env
echo "Upgrading contract: $CONTRACT_ID"
echo "Building contract with non-reproducible WASM (faster for dev)..."

# Build the contract using non-reproducible WASM for faster development builds
cargo near build non-reproducible-wasm

cargo near deploy build-non-reproducible-wasm $CONTRACT_ID \
    without-init-call \
    network-config $NEAR_NETWORK_ID \
	sign-with-plaintext-private-key \
	--signer-public-key $DEPLOYER_PUBLIC_KEY \
	--signer-private-key $DEPLOYER_PRIVATE_KEY \
    send

# If storage layout has changed, run the on-chain migration (if one exists for your upgrade), e.g.:
# near contract call-function as-transaction $CONTRACT_ID migrate json-args 'null' \
#   prepaid-gas '300 Tgas' attached-deposit '0 NEAR' \
#   sign-as $DEPLOYER_ACCOUNT network-config $NEAR_NETWORK_ID \
#   sign-with-plaintext-private-key $DEPLOYER_PRIVATE_KEY send
