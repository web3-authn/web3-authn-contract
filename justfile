# Web3Authn Contract Management Commands
#
# This justfile provides convenient commands to manage the Web3Authn contract
# deployment and upgrades. Make sure to set up your .env file first.

# List all available commands
default:
    @echo "Available commands:"
    @echo "  just deploy      - Deploy contract to production"
    @echo "  just deploy-dev  - Deploy contract to development"
    @echo "  just upgrade     - Upgrade contract in production"
    @echo "  just upgrade-dev - Upgrade contract in development"
    @echo "  just build       - Build contract for production"
    @echo "  just build-dev   - Build contract for development"
    @echo "  just test        - Run all tests"
    @echo "  just test-unit   - Run only unit tests"
    @echo "  just test-integration - Run only integration tests"
    @echo "  just validate-env - Validate environment variables"
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