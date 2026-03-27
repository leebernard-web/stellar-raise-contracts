//! # Contract State Size Limits
//!
//! This module enforces upper-bound limits on the size of unbounded collections
//! and metadata fields stored in contract state to prevent:
//!
//! - **DoS via state bloat**: an attacker flooding the contributors or roadmap
//!   lists until operations become too expensive to execute.
//! - **Gas exhaustion**: iteration over an unbounded `Vec` in `withdraw`,
//!   `refund`, or `collect_pledges` can exceed Soroban resource limits.
//! - **Ledger entry size violations**: Soroban enforces a hard cap on the
//!   serialised size of each ledger entry; exceeding it causes a host panic.
//! - **Metadata bloat**: oversized title, description, or social links fields.
//!
//! ## Security Assumptions
//!
//! 1. `MAX_CONTRIBUTORS` caps the `Contributors` persistent list. Any
//!    `contribute` call that would push the list past this limit is rejected.
//! 2. `MAX_PLEDGERS` caps the `Pledgers` persistent list. Any `pledge` call
//!    that would push the list past this limit is rejected.
//! 3. `MAX_ROADMAP_ITEMS` caps the `Roadmap` instance list.
//! 4. `MAX_STRETCH_GOALS` caps the `StretchGoals` list.
//! 5. `MAX_TITLE_LENGTH` caps the campaign title.
//! 6. `MAX_DESCRIPTION_LENGTH` caps the campaign description.
//! 7. `MAX_SOCIAL_LINKS_LENGTH` caps the social links field.
//! 8. `MAX_BONUS_GOAL_DESCRIPTION_LENGTH` caps the bonus goal description.
//! 9. `MAX_ROADMAP_DESCRIPTION_LENGTH` caps each roadmap item description.
//! 10. `MAX_METADATA_TOTAL_LENGTH` caps the combined size of title + description
//!     + social links to prevent fragmented metadata from exceeding total budget.
//!
//! ## Limits (rationale)
//!
//! | Constant                             | Value  | Rationale                                        |
//! |--------------------------------------|--------|--------------------------------------------------|
//! | `MAX_CONTRIBUTORS`                   |    128 | Keeps `withdraw`/`refund` batch within gas limit |
//! | `MAX_PLEDGERS`                       |    128 | Same as contributors for pledging phase         |
//! | `MAX_ROADMAP_ITEMS`                  |     32 | Cosmetic list; reasonable bound for roadmap      |
//! | `MAX_STRETCH_GOALS`                  |     32 | Small advisory list for milestone tracking       |
//! | `MAX_TITLE_LENGTH`                   |    128 | Prevents oversized titles                        |
//! | `MAX_DESCRIPTION_LENGTH`             |  2,048 | Allows detailed campaign descriptions            |
//! | `MAX_SOCIAL_LINKS_LENGTH`            |    512 | Social media link space                          |
//! | `MAX_BONUS_GOAL_DESCRIPTION_LENGTH`  |    280 | Twitter-length for bonus descriptions            |
//! | `MAX_ROADMAP_DESCRIPTION_LENGTH`     |    280 | Per-item roadmap description limit              |
//! | `MAX_METADATA_TOTAL_LENGTH`          |  2,688 | Sum budget: 128 + 2,048 + 512                    |

#![allow(missing_docs)]

use soroban_sdk::{contracterror, Env, String, Vec};

use crate::DataKey;

// ── Limits ───────────────────────────────────────────────────────────────────

/// Maximum number of unique contributors tracked on-chain.
/// This prevents DoS via unbounded contributor list growth.
pub const MAX_CONTRIBUTORS: u32 = 128;

/// Maximum number of unique pledgers tracked on-chain.
/// This prevents DoS via unbounded pledger list growth.
pub const MAX_PLEDGERS: u32 = 128;

/// Maximum number of roadmap items stored in instance storage.
pub const MAX_ROADMAP_ITEMS: u32 = 32;

/// Maximum number of stretch-goal milestones.
pub const MAX_STRETCH_GOALS: u32 = 32;

/// Maximum byte length of the campaign title.
pub const MAX_TITLE_LENGTH: u32 = 128;

/// Maximum byte length of the campaign description.
pub const MAX_DESCRIPTION_LENGTH: u32 = 2_048;

/// Maximum byte length of social links field.
pub const MAX_SOCIAL_LINKS_LENGTH: u32 = 512;

/// Maximum byte length of bonus goal description.
pub const MAX_BONUS_GOAL_DESCRIPTION_LENGTH: u32 = 280;

/// Maximum byte length of roadmap item description.
pub const MAX_ROADMAP_DESCRIPTION_LENGTH: u32 = 280;

/// Maximum combined byte length of title + description + socials.
/// This prevents fragmented metadata from collectively exceeding storage budget.
/// Budget: MAX_TITLE_LENGTH (128) + MAX_DESCRIPTION_LENGTH (2048) + MAX_SOCIAL_LINKS_LENGTH (512) = 2688
pub const MAX_METADATA_TOTAL_LENGTH: u32 = 2_688;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Returned when a state-size limit would be exceeded.
///
/// @notice Callers should treat this as a permanent rejection for the current
///         campaign state; the limit will not change without a contract upgrade.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum StateSizeError {
    /// The contributors list is full.
    ContributorLimitExceeded = 100,
    /// The pledgers list is full.
    PledgerLimitExceeded = 101,
    /// The roadmap list is full.
    RoadmapLimitExceeded = 102,
    /// The stretch-goals list is full.
    StretchGoalLimitExceeded = 103,
    /// A string field exceeds its maximum byte length.
    StringTooLong = 104,
    /// Combined metadata exceeds total budget.
    MetadataTotalExceeded = 105,
}

// ── Validation helpers ────────────────────────────────────────────────────────

/// Assert that title does not exceed MAX_TITLE_LENGTH bytes.
///
/// @param title The title to validate.
/// @return Ok(()) when within limits, Err with message otherwise.
pub fn validate_title(title: &String) -> Result<(), &'static str> {
    if title.len() > MAX_TITLE_LENGTH {
        return Err("title exceeds MAX_TITLE_LENGTH bytes");
    }
    Ok(())
}

/// Assert that description does not exceed MAX_DESCRIPTION_LENGTH bytes.
///
/// @param description The description to validate.
/// @return Ok(()) when within limits, Err with message otherwise.
pub fn validate_description(description: &String) -> Result<(), &'static str> {
    if description.len() > MAX_DESCRIPTION_LENGTH {
        return Err("description exceeds MAX_DESCRIPTION_LENGTH bytes");
    }
    Ok(())
}

/// Assert that social links do not exceed MAX_SOCIAL_LINKS_LENGTH bytes.
///
/// @param socials The social links string to validate.
/// @return Ok(()) when within limits, Err with message otherwise.
pub fn validate_social_links(socials: &String) -> Result<(), &'static str> {
    if socials.len() > MAX_SOCIAL_LINKS_LENGTH {
        return Err("social links exceed MAX_SOCIAL_LINKS_LENGTH bytes");
    }
    Ok(())
}

/// Assert that bonus goal description does not exceed MAX_BONUS_GOAL_DESCRIPTION_LENGTH bytes.
///
/// @param description The bonus goal description to validate.
/// @return Ok(()) when within limits, Err with message otherwise.
pub fn validate_bonus_goal_description(description: &String) -> Result<(), &'static str> {
    if description.len() > MAX_BONUS_GOAL_DESCRIPTION_LENGTH {
        return Err("bonus goal description exceeds MAX_BONUS_GOAL_DESCRIPTION_LENGTH bytes");
    }
    Ok(())
}

/// Assert that roadmap description does not exceed MAX_ROADMAP_DESCRIPTION_LENGTH bytes.
///
/// @param description The roadmap item description to validate.
/// @return Ok(()) when within limits, Err with message otherwise.
pub fn validate_roadmap_description(description: &String) -> Result<(), &'static str> {
    if description.len() > MAX_ROADMAP_DESCRIPTION_LENGTH {
        return Err("roadmap description exceeds MAX_ROADMAP_DESCRIPTION_LENGTH bytes");
    }
    Ok(())
}

/// Validate combined metadata length with overflow protection.
///
/// @param title_len Current title byte length.
/// @param desc_len Current description byte length.
/// @param socials_len Current social links byte length.
/// @return Ok(()) when total <= MAX_METADATA_TOTAL_LENGTH, Err otherwise.
pub fn validate_metadata_total_length(
    title_len: u32,
    desc_len: u32,
    socials_len: u32,
) -> Result<(), &'static str> {
    // Overflow-safe addition using checked_add
    let total = title_len
        .checked_add(desc_len)
        .and_then(|sum| sum.checked_add(socials_len));

    match total {
        Some(sum) if sum <= MAX_METADATA_TOTAL_LENGTH => Ok(()),
        _ => Err("metadata exceeds MAX_METADATA_TOTAL_LENGTH bytes"),
    }
}

/// Validate contributor capacity (number of current contributors).
///
/// @param current_count Current number of contributors.
/// @return Ok(()) when count < MAX_CONTRIBUTORS, Err otherwise.
pub fn validate_contributor_capacity(current_count: u32) -> Result<(), &'static str> {
    if current_count >= MAX_CONTRIBUTORS {
        return Err("contributors exceed MAX_CONTRIBUTORS");
    }
    Ok(())
}

/// Validate pledger capacity (number of current pledgers).
///
/// @param current_count Current number of pledgers.
/// @return Ok(()) when count < MAX_PLEDGERS, Err otherwise.
pub fn validate_pledger_capacity(current_count: u32) -> Result<(), &'static str> {
    if current_count >= MAX_PLEDGERS {
        return Err("pledgers exceed MAX_PLEDGERS");
    }
    Ok(())
}

/// Validate roadmap capacity against MAX_ROADMAP_ITEMS.
///
/// @param current_count Current number of roadmap items.
/// @return Ok(()) when within limits, Err otherwise.
pub fn validate_roadmap_capacity(current_count: u32) -> Result<(), &'static str> {
    if current_count >= MAX_ROADMAP_ITEMS {
        return Err("roadmap exceeds MAX_ROADMAP_ITEMS");
    }
    Ok(())
}

/// Validate stretch goal capacity against MAX_STRETCH_GOALS.
///
/// @param current_count Current number of stretch goals.
/// @return Ok(()) when within limits, Err otherwise.
pub fn validate_stretch_goal_capacity(current_count: u32) -> Result<(), &'static str> {
    if current_count >= MAX_STRETCH_GOALS {
        return Err("stretch goals exceed MAX_STRETCH_GOALS");
    }
    Ok(())
}

/// Check contributor limit by reading from storage.
///
/// @param env Soroban environment reference.
/// @return Ok(()) when within limits, Err otherwise.
pub fn check_contributor_limit(env: &Env) -> Result<(), StateSizeError> {
    let contributors: Vec<soroban_sdk::Address> = env
        .storage()
        .persistent()
        .get(&DataKey::Contributors)
        .unwrap_or_else(|| Vec::new(env));

    if contributors.len() >= MAX_CONTRIBUTORS {
        return Err(StateSizeError::ContributorLimitExceeded);
    }
    Ok(())
}

/// Check pledger limit by reading from storage.
///
/// @param env Soroban environment reference.
/// @return Ok(()) when within limits, Err otherwise.
pub fn check_pledger_limit(env: &Env) -> Result<(), StateSizeError> {
    let pledgers: Vec<soroban_sdk::Address> = env
        .storage()
        .persistent()
        .get(&DataKey::Pledgers)
        .unwrap_or_else(|| Vec::new(env));

    if pledgers.len() >= MAX_PLEDGERS {
        return Err(StateSizeError::PledgerLimitExceeded);
    }
    Ok(())
}

/// Check roadmap limit by reading from storage.
///
/// @param env Soroban environment reference.
/// @return Ok(()) when within limits, Err otherwise.
pub fn check_roadmap_limit(env: &Env) -> Result<(), StateSizeError> {
    let roadmap: Vec<crate::RoadmapItem> = env
        .storage()
        .instance()
        .get(&DataKey::Roadmap)
        .unwrap_or_else(|| Vec::new(env));

    if roadmap.len() >= MAX_ROADMAP_ITEMS {
        return Err(StateSizeError::RoadmapLimitExceeded);
    }
    Ok(())
}

/// Check stretch goal limit by reading from storage.
///
/// @param env Soroban environment reference.
/// @return Ok(()) when within limits, Err otherwise.
pub fn check_stretch_goal_limit(env: &Env) -> Result<(), StateSizeError> {
    let goals: Vec<i128> = env
        .storage()
        .instance()
        .get(&DataKey::StretchGoals)
        .unwrap_or_else(|| Vec::new(env));

    if goals.len() >= MAX_STRETCH_GOALS {
        return Err(StateSizeError::StretchGoalLimitExceeded);
    }
    Ok(())
}

/// Legacy constant for backwards compatibility (MAX_STRING_LEN = MAX_DESCRIPTION_LENGTH)
pub const MAX_STRING_LEN: u32 = MAX_DESCRIPTION_LENGTH;

/// Legacy function for backwards compatibility.
/// Checks that a string does not exceed MAX_DESCRIPTION_LENGTH bytes.
///
/// @param s The string to validate.
/// @return Ok(()) when within limits, Err otherwise.
pub fn check_string_len(s: &String) -> Result<(), StateSizeError> {
    if s.len() > MAX_STRING_LEN {
        return Err(StateSizeError::StringTooLong);
    }
    Ok(())
}
