#!/bin/bash
source .env

echo "Upgrading contract: $CONTRACT_ID"
echo "Building contract with reproducible WASM..."

# Deploy contract without initialization call
cargo near deploy build-reproducible-wasm $CONTRACT_ID \
	without-init-call \
	network-config $NEAR_NETWORK_ID \
	sign-with-plaintext-private-key \
	--signer-public-key $DEPLOYER_PUBLIC_KEY \
	--signer-private-key $DEPLOYER_PRIVATE_KEY \
	send

# This only works if storage layout hasn't changed from last deployment
# If storage layout has changed, run the on-chain migration (if one exists for your upgrade), e.g.:
# near contract call-function as-transaction $CONTRACT_ID migrate json-args 'null' \
#   prepaid-gas '300 Tgas' attached-deposit '0 NEAR' \
#   sign-as $DEPLOYER_ACCOUNT network-config $NEAR_NETWORK_ID \
#   sign-with-plaintext-private-key $DEPLOYER_PRIVATE_KEY send
