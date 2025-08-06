use near_sdk::{log, near,  env, require, AccountId};
use crate::contract_state::{
    WebAuthnContract,
    WebAuthnContractExt,
    VRFSettings,
};

/////////////////////////////////////
///////////// Contract //////////////
/////////////////////////////////////

#[near]
impl WebAuthnContract {

    /// Checks if msg.sender (env::predecessor_account_id()) has permission to register a new user
    /// Returns true if predecessor is the user themselves, contract owner, or an admin
    /// @non-view - uses env::predecessor_account_id()
    pub(crate) fn only_sender_or_admin(&self, user_id: &AccountId) -> bool {
        // Allow the user themselves (msg.sender), contract owner, or admins to register new users
        let predecessor = env::predecessor_account_id();
        let contract_account = env::current_account_id();
        let is_admin = self.admins.contains(&predecessor);
        if predecessor != *user_id && predecessor != contract_account && !is_admin {
            false
        } else {
            true
        }
    }

    pub(crate) fn only_admin(&self) {
        require!(
            self.admins.contains(&env::predecessor_account_id()),
            "Only admins can call this function"
        );
    }

    /// Add a new admin (only contract owner can call this)
    pub fn add_admin(&mut self, admin_id: AccountId) -> bool {
        let predecessor = env::predecessor_account_id();
        if predecessor != self.owner {
            env::panic_str("Only the contract owner can add admins");
        }

        if self.admins.contains(&admin_id) {
            log!("Admin {} already exists", admin_id);
            return false;
        }

        self.admins.insert(admin_id.clone());
        log!("Admin {} added successfully", admin_id);
        true
    }

    /// Remove an admin (only contract owner can call this)
    pub fn remove_admin(&mut self, admin_id: AccountId) -> bool {
        let predecessor = env::predecessor_account_id();

        if predecessor != self.owner {
            env::panic_str("Only the contract owner can remove admins");
        }

        if !self.admins.contains(&admin_id) {
            log!("Admin {} does not exist", admin_id);
            return false;
        }

        self.admins.remove(&admin_id);
        log!("Admin {} removed successfully", admin_id);
        true
    }

    /// Check if an account is an admin
    pub fn is_admin(&self, account_id: AccountId) -> bool {
        self.admins.contains(&account_id)
    }

    /// Get all admins
    pub fn get_admins(&self) -> Vec<AccountId> {
        self.admins.iter().cloned().collect()
    }

    /// Get VRF settings
    pub fn get_vrf_settings(&self) -> &VRFSettings {
        &self.vrf_settings
    }

    /// Set VRF settings (admin only)
    pub fn set_vrf_settings(&mut self, vrf_settings: VRFSettings) {
        self.only_admin();
        self.vrf_settings = vrf_settings;
        log!("VRF settings updated successfully");
    }

    /// Get contract owner
    pub fn get_owner(&self) -> &AccountId {
        &self.owner
    }

        /// Transfer contract ownership (only current owner can call this)
    pub fn transfer_ownership(&mut self, new_owner: AccountId) -> bool {
        let predecessor = env::predecessor_account_id();

        if predecessor != self.owner {
            env::panic_str("Only the contract owner can transfer ownership");
        }

        if new_owner == self.owner {
            log!("New owner is the same as current owner");
            return false;
        }

        let old_owner = self.owner.clone();
        self.owner = new_owner.clone();

        // Add the new owner as an admin if they're not already one
        if !self.admins.contains(&new_owner) {
            self.admins.insert(new_owner.clone());
            log!("New owner {} added as admin", new_owner);
        }

        log!("Ownership transferred from {} to {}", old_owner, new_owner);
        true
    }
}