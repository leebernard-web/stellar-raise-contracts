//! Contract State Size Limits
//!
//! Defines maximum size limits for all campaign-related on-chain state and
//! provides guard functions that return typed errors when limits are exceeded.
//!
//! ## Why limits matter
//! - **Resource efficiency**: caps ledger entry sizes, keeping state-rent predictable.
//! - **Frontend reliability**: the UI can query these constants to pre-validate inputs.
//! - **Scalability**: bounded collections prevent runaway storage growth.
//!
//! All byte constants are measured in UTF-8 bytes; count constants are item counts.

use soroban_sdk::{contract, contractimpl, contracterror, Address, Env, String, Vec};

use crate::{DataKey, RoadmapItem};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum length of any single string field (title, description, social links) in bytes.
/// @dev Shared limit used by `check_string_len`.
pub const MAX_STRING_LEN: u32 = 256;

/// Maximum number of unique contributors (and pledgers) tracked per campaign.
/// @dev Bounds both the `Contributors` and `Pledgers` persistent lists.
pub const MAX_CONTRIBUTORS: u32 = 128;

/// Maximum number of roadmap milestones stored per campaign.
pub const MAX_ROADMAP_ITEMS: u32 = 32;

/// Maximum number of stretch goals (milestones) stored per campaign.
pub const MAX_STRETCH_GOALS: u32 = 32;

// Legacy aliases kept for backward compatibility with contract_state_size.test.rs
pub const MAX_TITLE_LENGTH: u32 = MAX_STRING_LEN;
pub const MAX_DESCRIPTION_LENGTH: u32 = MAX_STRING_LEN;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors returned when a state-size limit is exceeded.
///
/// Discriminants are stable and must not be renumbered — they are part of the
/// on-chain ABI.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum StateSizeError {
    /// The `Contributors` or `Pledgers` list has reached `MAX_CONTRIBUTORS`.
    ContributorLimitExceeded = 100,
    /// The `Roadmap` list has reached `MAX_ROADMAP_ITEMS`.
    RoadmapLimitExceeded = 101,
    /// The `StretchGoals` list has reached `MAX_STRETCH_GOALS`.
    StretchGoalLimitExceeded = 102,
    /// A string field exceeds `MAX_STRING_LEN` bytes.
    StringTooLong = 103,
}

// ── Guard functions ───────────────────────────────────────────────────────────

/// Returns `Err(StringTooLong)` if `s` exceeds `MAX_STRING_LEN` bytes.
///
/// @param s  The string to validate.
/// @return   `Ok(())` when within bounds.
pub fn check_string_len(s: &String) -> Result<(), StateSizeError> {
    if s.len() > MAX_STRING_LEN {
        Err(StateSizeError::StringTooLong)
    } else {
        Ok(())
    }
}

/// Returns `Err(ContributorLimitExceeded)` if the `Contributors` list is full.
///
/// Reads `DataKey::Contributors` from persistent storage; treats a missing key
/// as an empty list (safe default).
///
/// @param env  The contract environment.
/// @return     `Ok(())` when below `MAX_CONTRIBUTORS`.
pub fn check_contributor_limit(env: &Env) -> Result<(), StateSizeError> {
    let count = env
        .storage()
        .persistent()
        .get::<DataKey, Vec<Address>>(&DataKey::Contributors)
        .map(|v| v.len())
        .unwrap_or(0);
    if count >= MAX_CONTRIBUTORS {
        Err(StateSizeError::ContributorLimitExceeded)
    } else {
        Ok(())
    }
}

/// Returns `Err(ContributorLimitExceeded)` if the `Pledgers` list is full.
///
/// Mirrors `check_contributor_limit` but reads `DataKey::Pledgers`.
///
/// @param env  The contract environment.
/// @return     `Ok(())` when below `MAX_CONTRIBUTORS`.
pub fn check_pledger_limit(env: &Env) -> Result<(), StateSizeError> {
    let count = env
        .storage()
        .persistent()
        .get::<DataKey, Vec<Address>>(&DataKey::Pledgers)
        .map(|v| v.len())
        .unwrap_or(0);
    if count >= MAX_CONTRIBUTORS {
        Err(StateSizeError::ContributorLimitExceeded)
    } else {
        Ok(())
    }
}

/// Returns `Err(RoadmapLimitExceeded)` if the `Roadmap` list is full.
///
/// Reads `DataKey::Roadmap` from instance storage.
///
/// @param env  The contract environment.
/// @return     `Ok(())` when below `MAX_ROADMAP_ITEMS`.
pub fn check_roadmap_limit(env: &Env) -> Result<(), StateSizeError> {
    let count = env
        .storage()
        .instance()
        .get::<DataKey, Vec<RoadmapItem>>(&DataKey::Roadmap)
        .map(|v| v.len())
        .unwrap_or(0);
    if count >= MAX_ROADMAP_ITEMS {
        Err(StateSizeError::RoadmapLimitExceeded)
    } else {
        Ok(())
    }
}

/// Returns `Err(StretchGoalLimitExceeded)` if the `StretchGoals` list is full.
///
/// Reads `DataKey::StretchGoals` from instance storage.
///
/// @param env  The contract environment.
/// @return     `Ok(())` when below `MAX_STRETCH_GOALS`.
pub fn check_stretch_goal_limit(env: &Env) -> Result<(), StateSizeError> {
    let count = env
        .storage()
        .instance()
        .get::<DataKey, Vec<i128>>(&DataKey::StretchGoals)
        .map(|v| v.len())
        .unwrap_or(0);
    if count >= MAX_STRETCH_GOALS {
        Err(StateSizeError::StretchGoalLimitExceeded)
    } else {
        Ok(())
    }
}

// ── Capacity / length validators (called from lib.rs and other modules) ───────

/// Returns `Err(ContributorLimitExceeded)` if `count >= MAX_CONTRIBUTORS`.
/// @param count  Current length of the contributors list.
pub fn validate_contributor_capacity(count: u32) -> Result<(), StateSizeError> {
    if count >= MAX_CONTRIBUTORS {
        Err(StateSizeError::ContributorLimitExceeded)
    } else {
        Ok(())
    }
}

/// Returns `Err(ContributorLimitExceeded)` if `count >= MAX_CONTRIBUTORS`.
/// @param count  Current length of the pledgers list.
pub fn validate_pledger_capacity(count: u32) -> Result<(), StateSizeError> {
    if count >= MAX_CONTRIBUTORS {
        Err(StateSizeError::ContributorLimitExceeded)
    } else {
        Ok(())
    }
}

/// Returns `Err(RoadmapLimitExceeded)` if `count >= MAX_ROADMAP_ITEMS`.
/// @param count  Current length of the roadmap list.
pub fn validate_roadmap_capacity(count: u32) -> Result<(), StateSizeError> {
    if count >= MAX_ROADMAP_ITEMS {
        Err(StateSizeError::RoadmapLimitExceeded)
    } else {
        Ok(())
    }
}

/// Returns `Err(StretchGoalLimitExceeded)` if `count >= MAX_STRETCH_GOALS`.
/// @param count  Current length of the stretch goals list.
pub fn validate_stretch_goal_capacity(count: u32) -> Result<(), StateSizeError> {
    if count >= MAX_STRETCH_GOALS {
        Err(StateSizeError::StretchGoalLimitExceeded)
    } else {
        Ok(())
    }
}

/// Returns `Err(StringTooLong)` if `title` exceeds `MAX_STRING_LEN`.
pub fn validate_title(title: &String) -> Result<(), StateSizeError> {
    check_string_len(title)
}

/// Returns `Err(StringTooLong)` if `description` exceeds `MAX_STRING_LEN`.
pub fn validate_description(description: &String) -> Result<(), StateSizeError> {
    check_string_len(description)
}

/// Returns `Err(StringTooLong)` if `social_links` exceeds `MAX_STRING_LEN`.
pub fn validate_social_links(social_links: &String) -> Result<(), StateSizeError> {
    check_string_len(social_links)
}

/// Returns `Err(StringTooLong)` if `description` (roadmap item) exceeds `MAX_STRING_LEN`.
pub fn validate_roadmap_description(description: &String) -> Result<(), StateSizeError> {
    check_string_len(description)
}

/// Returns `Err(StringTooLong)` if `desc` (bonus goal description) exceeds `MAX_STRING_LEN`.
pub fn validate_bonus_goal_description(desc: &String) -> Result<(), StateSizeError> {
    check_string_len(desc)
}

/// Returns `Err(StringTooLong)` if the combined metadata length exceeds the aggregate limit.
/// @param title_len        Length of the title string in bytes.
/// @param description_len  Length of the description string in bytes.
/// @param socials_len      Length of the social links string in bytes.
pub fn validate_metadata_total_length(title_len: u32, description_len: u32, socials_len: u32) -> Result<(), StateSizeError> {
    const AGGREGATE_LIMIT: u32 = MAX_TITLE_LENGTH + MAX_DESCRIPTION_LENGTH + MAX_STRING_LEN;
    if title_len.saturating_add(description_len).saturating_add(socials_len) > AGGREGATE_LIMIT {
        Err(StateSizeError::StringTooLong)
    } else {
        Ok(())
    }
}

// ── Queryable contract (used by contract_state_size.test.rs) ─────────────────

/// Standalone contract that exposes state-size constants over the Soroban ABI.
/// @dev Primarily used by the frontend to query limits without off-chain config.
#[contract]
pub struct ContractStateSize;

#[contractimpl]
impl ContractStateSize {
    /// Returns `MAX_TITLE_LENGTH`.
    pub fn max_title_length(_env: Env) -> u32 { MAX_TITLE_LENGTH }
    /// Returns `MAX_DESCRIPTION_LENGTH`.
    pub fn max_description_length(_env: Env) -> u32 { MAX_DESCRIPTION_LENGTH }
    /// Returns `MAX_STRING_LEN` (social links limit).
    pub fn max_social_links_length(_env: Env) -> u32 { MAX_STRING_LEN }
    /// Returns `MAX_CONTRIBUTORS`.
    pub fn max_contributors(_env: Env) -> u32 { MAX_CONTRIBUTORS }
    /// Returns `MAX_ROADMAP_ITEMS`.
    pub fn max_roadmap_items(_env: Env) -> u32 { MAX_ROADMAP_ITEMS }
    /// Returns `MAX_STRETCH_GOALS`.
    pub fn max_stretch_goals(_env: Env) -> u32 { MAX_STRETCH_GOALS }

    /// Returns `true` if `title` length is within `MAX_TITLE_LENGTH`.
    pub fn validate_title(_env: Env, title: String) -> bool {
        title.len() <= MAX_TITLE_LENGTH
    }
    /// Returns `true` if `description` length is within `MAX_DESCRIPTION_LENGTH`.
    pub fn validate_description(_env: Env, description: String) -> bool {
        description.len() <= MAX_DESCRIPTION_LENGTH
    }
    /// Returns `true` if `total_len` is within the aggregate metadata limit.
    pub fn validate_metadata_aggregate(_env: Env, total_len: u32) -> bool {
        total_len <= MAX_TITLE_LENGTH + MAX_DESCRIPTION_LENGTH + MAX_STRING_LEN
    }
}

// ── Standalone helpers (called from lib.rs) ───────────────────────────────────

/// Returns `Ok(())` if `count < MAX_CONTRIBUTORS`, else `Err("limit exceeded")`.
#[inline]
pub fn validate_contributor_capacity(count: u32) -> Result<(), &'static str> {
    if count >= MAX_CONTRIBUTORS {
        Err("contributor limit exceeded")
    } else {
        Ok(())
    }
}

/// Panics if the contributor list is at capacity.
#[inline]
pub fn check_contributor_limit(env: &soroban_sdk::Env) -> Result<(), &'static str> {
    use soroban_sdk::Vec;
    let count: u32 = env
        .storage()
        .persistent()
        .get::<_, Vec<soroban_sdk::Address>>(&crate::DataKey::Contributors)
        .map(|v| v.len())
        .unwrap_or(0);
    validate_contributor_capacity(count)
}

/// Returns `Ok(())` if `count < MAX_CONTRIBUTORS`, else `Err("limit exceeded")`.
#[inline]
pub fn validate_pledger_capacity(count: u32) -> Result<(), &'static str> {
    if count >= MAX_CONTRIBUTORS {
        Err("pledger limit exceeded")
    } else {
        Ok(())
    }
}

/// Panics if the pledger list is at capacity.
#[inline]
pub fn check_pledger_limit(env: &soroban_sdk::Env) -> Result<(), &'static str> {
    use soroban_sdk::Vec;
    let count: u32 = env
        .storage()
        .persistent()
        .get::<_, Vec<soroban_sdk::Address>>(&crate::DataKey::Pledgers)
        .map(|v| v.len())
        .unwrap_or(0);
    validate_pledger_capacity(count)
}

/// Validates total metadata length.
#[inline]
pub fn validate_metadata_total_length(total_len: u32) -> Result<(), &'static str> {
    const AGGREGATE_LIMIT: u32 =
        MAX_TITLE_LENGTH + MAX_DESCRIPTION_LENGTH + MAX_SOCIAL_LINKS_LENGTH;
    if total_len > AGGREGATE_LIMIT {
        Err("metadata too long")
    } else {
        Ok(())
    }
}

/// Validates a title string length.
#[inline]
pub fn validate_title(title: &soroban_sdk::String) -> Result<(), &'static str> {
    if title.len() > MAX_TITLE_LENGTH {
        Err("title too long")
    } else {
        Ok(())
    }
}

/// Validates a description string length.
#[inline]
pub fn validate_description(desc: &soroban_sdk::String) -> Result<(), &'static str> {
    if desc.len() > MAX_DESCRIPTION_LENGTH {
        Err("description too long")
    } else {
        Ok(())
    }
}

/// Validates social links string length.
#[inline]
pub fn validate_social_links(links: &soroban_sdk::String) -> Result<(), &'static str> {
    if links.len() > MAX_SOCIAL_LINKS_LENGTH {
        Err("social links too long")
    } else {
        Ok(())
    }
}

/// Validates a generic string length (uses description limit).
#[inline]
pub fn check_string_len(s: &soroban_sdk::String) -> Result<(), &'static str> {
    validate_description(s)
}

/// Validates roadmap item capacity.
#[inline]
pub fn validate_roadmap_capacity(count: u32) -> Result<(), &'static str> {
    if count >= MAX_ROADMAP_ITEMS {
        Err("roadmap limit exceeded")
    } else {
        Ok(())
    }
}

/// Checks roadmap limit from storage.
#[inline]
pub fn check_roadmap_limit(env: &soroban_sdk::Env) -> Result<(), &'static str> {
    use soroban_sdk::Vec;
    let count: u32 = env
        .storage()
        .persistent()
        .get::<_, Vec<crate::RoadmapItem>>(&crate::DataKey::Roadmap)
        .map(|v| v.len())
        .unwrap_or(0);
    validate_roadmap_capacity(count)
}

/// Validates a roadmap item description length.
#[inline]
pub fn validate_roadmap_description(desc: &soroban_sdk::String) -> Result<(), &'static str> {
    validate_description(desc)
}

/// Validates stretch goal capacity.
#[inline]
pub fn validate_stretch_goal_capacity(count: u32) -> Result<(), &'static str> {
    if count >= MAX_STRETCH_GOALS {
        Err("stretch goal limit exceeded")
    } else {
        Ok(())
    }
}

/// Checks stretch goal limit from storage.
#[inline]
pub fn check_stretch_goal_limit(env: &soroban_sdk::Env) -> Result<(), &'static str> {
    use soroban_sdk::Vec;
    let count: u32 = env
        .storage()
        .persistent()
        .get::<_, Vec<i128>>(&crate::DataKey::StretchGoals)
        .map(|v| v.len())
        .unwrap_or(0);
    validate_stretch_goal_capacity(count)
}
