# Web3Authn Contract Management Commands
# List all available commands
default:
    @echo "Available commands:"
    @echo "  just deploy      - Deploy contract to production"
    @echo "  just deploy-dev  - Deploy contract to development"
    @echo "  just upgrade     - Upgrade contract in production"
    @echo "  just upgrade-dev - Upgrade contract in development"
    @echo ""
    @echo "Make sure to set up your .env file before running any commands."

# Deploy the contract to production (reproducible WASM)
deploy:
    @echo "Deploying contract to production..."
    cd ./web3-authn-contract && sh ./scripts/deploy.sh && cd ..

# Deploy the contract to development (non-reproducible WASM, faster builds)
deploy-dev:
    @echo "Deploying contract to development..."
    cd ./web3-authn-contract && sh ./scripts/deploy-dev.sh && cd ..

# Upgrade the contract in production (reproducible WASM)
upgrade:
    @echo "Upgrading contract in production..."
    cd ./web3-authn-contract && sh ./scripts/upgrade.sh && cd ..

# Upgrade the contract in development (non-reproducible WASM, faster builds)
upgrade-dev:
    @echo "Upgrading contract in development..."
    cd ./web3-authn-contract && sh ./scripts/upgrade-dev.sh && cd ..
