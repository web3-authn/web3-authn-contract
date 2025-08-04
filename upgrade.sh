#!/bin/bash
source .env

echo "Upgrading contract: $WEBAUTHN_CONTRACT_ID"
echo "Building contract with reproducible WASM..."

# Deploy contract without initialization call
cargo near deploy build-reproducible-wasm $WEBAUTHN_CONTRACT_ID \
	without-init-call \
	network-config testnet \
	sign-with-plaintext-private-key \
	--signer-public-key $DEPLOYER_PUBLIC_KEY \
	--signer-private-key $DEPLOYER_PRIVATE_KEY \
	send

# This only works if storage layout hasn't changed from last deployment
# If storage layout has changed, you must delete and re-create the contract, see README.md