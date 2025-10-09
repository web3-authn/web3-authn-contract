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

    // ==============================
    // Owner and admin assertions
    // ==============================

    // (assert_owner removed; use only_admin for admin-controlled operations)

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

    // ==============================
    // Allowed origins management
    // ==============================

    /// Return the list of allowed origins (canonical strings)
    pub fn get_allowed_origins(&self) -> Vec<String> {
        let mut v: Vec<String> = self.allowed_origins.iter().cloned().collect();
        v.sort();
        v
    }

    /// Add a single allowed origin (admin-only)
    #[payable]
    pub fn add_allowed_origin(&mut self, origin: String) -> bool {
        self.only_admin();

        let normalized = match Self::normalize_origin(&origin) {
            Ok(s) => s,
            Err(e) => env::panic_str(&e),
        };

        // Enforce max count only if inserting a new one
        if !self.allowed_origins.contains(&normalized) {
            require!(
                (self.allowed_origins.len() as usize) < Self::MAX_ALLOWED_ORIGINS_COUNT,
                "Allowed origins limit reached"
            );
        }

        let inserted = self.allowed_origins.insert(normalized.clone());
        log!("added origin: {}", normalized);
        inserted
    }

    /// Remove a single allowed origin (admin-only)
    #[payable]
    pub fn remove_allowed_origin(&mut self, origin: String) -> bool {
        self.only_admin();

        let normalized = match Self::normalize_origin(&origin) {
            Ok(s) => s,
            Err(e) => env::panic_str(&e),
        };

        let removed = if self.allowed_origins.contains(&normalized) {
            self.allowed_origins.remove(&normalized);
            true
        } else {
            false
        };
        log!("removed origin: {}", normalized);
        removed
    }

    /// Replace the full set of allowed origins (admin-only)
    #[payable]
    pub fn set_allowed_origins(&mut self, origins: Vec<String>) -> bool {
        self.only_admin();

        let mut normalized: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for o in origins.iter() {
            let n = match Self::normalize_origin(o) {
                Ok(s) => s,
                Err(e) => env::panic_str(&e),
            };
            require!(n.len() <= Self::MAX_ORIGIN_LENGTH, "Origin too long");
            if normalized.len() >= Self::MAX_ALLOWED_ORIGINS_COUNT {
                env::panic_str("Allowed origins limit reached");
            }
            normalized.insert(n);
        }

        // Clear existing set
        let existing: Vec<String> = self.allowed_origins.iter().cloned().collect();
        for o in existing.iter() {
            self.allowed_origins.remove(o);
        }

        // Insert new set
        for o in normalized.iter() {
            self.allowed_origins.insert(o.clone());
        }

        log!("Set {} origins", normalized.len());
        true
    }

    // ==============================
    // Helpers: Origin normalization
    // ==============================

    const MAX_ORIGIN_LENGTH: usize = 255;
    const MAX_ALLOWED_ORIGINS_COUNT: usize = 5000;

    fn normalize_origin(input: &str) -> Result<String, String> {
        let s = input.trim().to_lowercase();
        if s.is_empty() {
            return Err("Origin cannot be empty".to_string());
        }
        if s.len() > Self::MAX_ORIGIN_LENGTH {
            return Err("Origin too long".to_string());
        }
        if s.contains(' ') {
            return Err("Origin cannot contain spaces".to_string());
        }
        if s.contains('*') {
            return Err("Wildcards are not allowed in origin".to_string());
        }
        if s.ends_with('/') {
            return Err("Origin must not have a trailing slash".to_string());
        }

        let parts: Vec<&str> = s.split("://").collect();
        if parts.len() != 2 {
            return Err("Origin must be in the form scheme://host[:port]".to_string());
        }

        let scheme = parts[0];
        let hostport = parts[1];
        if hostport.is_empty() {
            return Err("Origin host is missing".to_string());
        }
        if hostport.contains('/') || hostport.contains('?') || hostport.contains('#') {
            return Err("Origin must not contain path, query, or fragment".to_string());
        }

        match scheme {
            "https" => {}
            "http" => {
                // Only allow for localhost development
                let hp = hostport;
                let host = if let Some((h, _p)) = hp.split_once(':') { h } else { hp };
                if host != "localhost" && host != "127.0.0.1" {
                    return Err("http scheme only allowed for localhost".to_string());
                }
            }
            _ => return Err("Only https scheme is allowed (http for localhost)".to_string()),
        }

        // Validate host and optional port
        let (host, port_opt) = if let Some((h, p)) = hostport.split_once(':') {
            (h, Some(p))
        } else {
            (hostport, None)
        };

        if host.is_empty() {
            return Err("Origin host is empty".to_string());
        }
        if host.starts_with('.') || host.ends_with('.') || host.starts_with('-') || host.ends_with('-') {
            return Err("Invalid host format".to_string());
        }
        if !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
            return Err("Host contains invalid characters".to_string());
        }

        if let Some(port) = port_opt {
            if port.is_empty() {
                return Err("Port must not be empty".to_string());
            }
            if !port.chars().all(|c| c.is_ascii_digit()) {
                return Err("Port must be numeric".to_string());
            }
            // Basic range check
            if let Ok(pn) = port.parse::<u32>() {
                if pn == 0 || pn > 65535 {
                    return Err("Port out of range".to_string());
                }
            }
        }

        Ok(format!("{}://{}", scheme, hostport))
    }
}
