#!/bin/bash
source .env

# Deploy the contract
cargo near deploy build-reproducible-wasm $WEBAUTHN_CONTRACT_ID \
	with-init-call init json-args '{}' \
	prepaid-gas '100.0 Tgas' \
	attached-deposit '0 NEAR' \
	network-config testnet \
	sign-with-plaintext-private-key \
	--signer-public-key $DEPLOYER_PUBLIC_KEY \
	--signer-private-key $DEPLOYER_PRIVATE_KEY \
	send
