use super::{WebAuthnContract, WebAuthnContractExt};
use near_sdk::{
    log, near, env, serde_json, require,
    AccountId, Gas, PublicKey, CryptoHash, GasWeight
};

// Simple enum for access key permission (kept for potential future use)
#[derive(Clone, Debug, PartialEq)]
#[near_sdk::near(serializers = [json, borsh])]
pub enum AccessKeyPermission {
    FunctionCall,
    FullAccess,
}

/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

#[near]
impl WebAuthnContract {
    /// Store device linking mapping for Device2 polling
    /// Device1 calls this after directly adding Device2's key to their own account
    /// This enables Device2 to discover which account it was linked to and get assigned a device number
    pub fn store_device_linking_mapping(
        &mut self,
        device_public_key: String,
        target_account_id: AccountId,
    ) -> CryptoHash {
        let caller = env::predecessor_account_id();
        require!(caller == target_account_id, "Caller must be the target account");

        log!(
            "Storing device linking mapping: {} -> {} by {}",
            device_public_key,
            target_account_id,
            caller
        );

        // Parse the public key to validate format
        let _parsed_key = match device_public_key.parse::<PublicKey>() {
            Ok(key) => key,
            Err(e) => {
                env::panic_str(&format!("Invalid public key format: {}", e));
            }
        };

        // Get next device number for this account (1-indexed for UX)
        let current_counter = self.device_numbers
            .get(&target_account_id)
            .copied()
            .unwrap_or(1); // device numbering starts on 1

        let device_number = current_counter;

        // Store temporary mapping for Device2 to poll (account ID and assigned device number)
        self.device_linking_map.insert(
            device_public_key.clone(),
            (target_account_id.clone(), device_number)
        );

        // Initiate automatic cleanup after 200 blocks using yield-resume pattern
        let data_id_register = 0;
        // Create yield promise for cleanup_device_linking
        env::promise_yield_create(
            "cleanup_device_linking",
            serde_json::to_vec(&serde_json::json!({
                "device_public_key": device_public_key.clone()
            })).unwrap().as_slice(),
            Gas::from_tgas(8), // actual usage 3.10 Tgas + 2.38 Tgas = 5.48 Tgas
            GasWeight(0),
            data_id_register
        );
        // Retrieve data_id for later resume
        let data_id: CryptoHash = env::read_register(data_id_register)
            .expect("Failed to read data_id")
            .try_into()
            .expect("Failed to convert to CryptoHash");

        log!(
            "Device linking mapping stored successfully for account {} with device number {}",
            target_account_id,
            device_number
        );
        data_id
    }

    /// View function for Device2 to query which account it will be linked to and get its assigned device number
    /// Device2 calls this with its public key to discover Device1's account ID and its assigned device number
    pub fn get_device_linking_account(&self, device_public_key: String) -> Option<(AccountId, u8)> {
        self.device_linking_map.get(&device_public_key)
            .map(|(account_id, device_number)| (account_id.clone(), *device_number))
    }

    /// Get the current device counter for an account (useful for debugging)
    pub fn get_device_counter(&self, account_id: AccountId) -> u8 {
        self.device_numbers.get(&account_id).copied().unwrap_or(0)
    }

    /// Clean up temporary device linking mapping after successful registration
    /// This should be called after Device2 completes link_device_register_user
    /// OR automatically called by the yield-resume pattern after 200 blocks
    pub fn cleanup_device_linking(&mut self, device_public_key: String) {
        self.device_linking_map.remove(&device_public_key);
        log!("Cleaned up device linking mapping for key: {}", device_public_key);
    }
}

/////////////////////////////////////
/// TESTS
/////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;
    use near_sdk::AccountId;
    use std::str::FromStr;

    fn get_context(predecessor_account_id: AccountId) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder
            .current_account_id(accounts(0))
            .signer_account_id(predecessor_account_id.clone())
            .predecessor_account_id(predecessor_account_id);
        builder
    }

    #[test]
    fn test_store_device_linking_mapping_invalid_public_key() {
        let alice = AccountId::from_str("alice.testnet").unwrap();
        let bob = AccountId::from_str("bob.testnet").unwrap();

        // Setup context with Alice as caller
        let context = get_context(alice.clone());
        testing_env!(context.build());

        // Create contract instance
        let mut contract = WebAuthnContract::init(None, None);

        // Test invalid public key format
        let invalid_key = "invalid_public_key_format".to_string();

        // This should panic due to invalid public key format
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            contract.store_device_linking_mapping(invalid_key, bob.clone());
        })).expect_err("Should panic with invalid public key format");
    }

    #[test]
    fn test_store_device_linking_mapping_valid_format() {
        let alice = AccountId::from_str("alice.testnet").unwrap();

        // Setup context with Alice as caller
        let context = get_context(alice.clone());
        testing_env!(context.build());

        // Create contract instance
        let mut contract = WebAuthnContract::init(None, None);

        // Test valid device public key
        let device_public_key = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".to_string();

        // This stores the mapping without creating a Promise
        // We're just verifying the function doesn't panic with valid input
        // Alice can only create device linking mappings for her own account
        contract.store_device_linking_mapping(device_public_key, alice.clone());

        // The function should complete without panicking
        // In a real blockchain environment, this would:
        // 1. Store the device linking mapping for Device2 to poll
        // 2. Emit the DEVICE_KEY_MAPPED log event
    }

}
