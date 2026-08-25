//! Post-activation health audit for Atom's inline entry hooks.
//!
//! Hook installation is transactional and fail-closed, but a later-loading
//! writer can take an activated function entry without chaining. This audit
//! covers the inline entry hooks through the pre-existing
//! `InlineHookContainer::owns_entry` capability and nothing else.
//!
//! Direct-callsite and pointer-slot capabilities are deliberately **not**
//! byte-audited: their bytes are legitimately shared with other owners, a
//! displaced call can still execute through a chained writer, and only
//! execution proves health. Those capabilities report their live callback
//! counters through their own subsystem diagnostics (for Ballistics, the
//! `Detour entries` line in the requested summary) instead of byte
//! comparisons here.
//!
//! The audit runs only off the hot path: once after post-Deferred render
//! installation completes and on each user-requested summary edge.

use std::sync::Mutex;

use libpsycho::ffi::fnptr::Function;
use libpsycho::os::windows::hook::inline::{
    errors::InlineHookError, inlinehook::InlineHookContainer,
};

/// Live state of one audited inline entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HookOwnership {
    /// The installed jump still owns the function entry.
    Owned,
    /// The hook never completed activation; nothing was displaced.
    Dormant,
    /// Another writer took the entry after activation.
    Lost,
}

struct RegisteredHook {
    capability: &'static str,
    probe: Box<dyn Fn() -> HookOwnership + Send>,
}

static REGISTRY: Mutex<Vec<RegisteredHook>> = Mutex::new(Vec::new());

/// Register an inline entry hook for later ownership audits.
pub(crate) fn register_inline<T: Function>(
    capability: &'static str,
    container: &'static InlineHookContainer<T>,
) {
    match REGISTRY.lock() {
        Ok(mut registry) => registry.push(RegisteredHook {
            capability,
            probe: Box::new(move || classify_inline(container)),
        }),
        Err(_) => {
            // Registration is best-effort diagnosability; a poisoned registry
            // must never break subsystem initialization.
            log::debug!("[INTEGRITY] Registry unavailable; '{capability}' is not audited");
        }
    }
}

fn classify_inline<T: Function>(container: &InlineHookContainer<T>) -> HookOwnership {
    if !container.is_enabled() {
        return HookOwnership::Dormant;
    }
    match container.owns_entry() {
        Ok(true) => HookOwnership::Owned,
        Ok(false) => HookOwnership::Lost,
        Err(InlineHookError::NotEnabled) => HookOwnership::Dormant,
        Err(error) => {
            // A read failure is not evidence of displacement; report the
            // hook as unclassifiable rather than claiming loss.
            log::debug!("[INTEGRITY] Entry audit unavailable: {error}");
            HookOwnership::Dormant
        }
    }
}

fn describe_loss(capability: &str) -> String {
    format!(
        "{capability} no longer owns its function entry; its behavior stays inactive until restart"
    )
}

/// Classify and log every registered inline hook's live ownership.
///
/// Normal all-owned results are `DEBUG`; each lost capability is one `WARN`.
pub(crate) fn audit_and_log() {
    let Ok(registry) = REGISTRY.lock() else {
        return;
    };
    let mut owned = 0_usize;
    let mut dormant = 0_usize;
    let mut lost = 0_usize;
    for hook in registry.iter() {
        match (hook.probe)() {
            HookOwnership::Owned => owned += 1,
            HookOwnership::Dormant => {
                dormant += 1;
                log::debug!(
                    "[INTEGRITY] {} is installed but not enabled",
                    hook.capability
                );
            }
            HookOwnership::Lost => {
                lost += 1;
                log::warn!("[INTEGRITY] {}", describe_loss(hook.capability));
            }
        }
    }
    log::debug!(
        "[INTEGRITY] Entry audit complete: {owned} owned, {dormant} dormant, {lost} lost of {}",
        registry.len()
    );
}

#[cfg(test)]
mod tests {
    use super::{HookOwnership, describe_loss};

    #[test]
    fn loss_message_names_the_capability_without_attribution() {
        assert_eq!(
            describe_loss("Atom complete post-UpdateCamera sample"),
            "Atom complete post-UpdateCamera sample no longer owns its function entry; its behavior stays inactive until restart"
        );
    }

    #[test]
    fn ownership_states_are_distinguishable() {
        assert_ne!(HookOwnership::Owned, HookOwnership::Dormant);
        assert_ne!(HookOwnership::Dormant, HookOwnership::Lost);
        assert_eq!(HookOwnership::Lost, HookOwnership::Lost);
    }
}
