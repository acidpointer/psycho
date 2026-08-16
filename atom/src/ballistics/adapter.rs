//! Scoped override of FNV's native MissileProjectile flight-policy decision.
//!
//! Atom does not mutate a completed projectile. The canonical launch wrapper
//! publishes a bounded, thread-owned request while its chained predecessor is
//! active. The initializer's existing hitscan-predicate call is chained once;
//! for the matching form and ordinary launch context, Atom returns false so
//! the engine derives its complete physical runtime policy itself.

use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use libpsycho::os::windows::winapi::get_current_thread_id;

use super::{ProjectileCapability, ShotContext, SourceKind};

const POLICY_SLOT_CAPACITY: usize = 8;

struct PolicySlot {
    thread_id: AtomicU32,
    form_token: AtomicU32,
    force_physical: AtomicBool,
    observed: AtomicBool,
    forced: AtomicBool,
}

impl PolicySlot {
    const fn new() -> Self {
        Self {
            thread_id: AtomicU32::new(0),
            form_token: AtomicU32::new(0),
            force_physical: AtomicBool::new(false),
            observed: AtomicBool::new(false),
            forced: AtomicBool::new(false),
        }
    }
}

static POLICY_SLOTS: [PolicySlot; POLICY_SLOT_CAPACITY] =
    [const { PolicySlot::new() }; POLICY_SLOT_CAPACITY];
static ACTIVE_ROOT_SCOPES: AtomicU32 = AtomicU32::new(0);

/// Result of one eligible launch's native initialization policy scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PolicyResult {
    /// Atom changed a chained hitscan answer to native physical flight.
    ForcedPhysical,
    /// An earlier hook owner had already selected native physical flight.
    AlreadyPhysical,
    /// VATS-like, targeted, unknown-source, or unsupported launch context.
    ContextRejected,
    /// The chained launch route did not reach the audited native decision.
    PolicyNotObserved,
    /// All bounded thread-policy slots were already active.
    CapacityUnavailable,
}

#[derive(Clone, Copy)]
struct PreviousFrame {
    form_token: u32,
    force_physical: bool,
    observed: bool,
    forced: bool,
}

/// RAII publication of one native physical-policy request.
///
/// Nested launches on the same thread temporarily replace and then restore the
/// outer frame. Independent launch threads use separate fixed slots. No heap,
/// lock, TLS value, engine pointer, or form identity survives the scope.
pub(crate) struct NativePolicyScope {
    slot_index: usize,
    owner_thread: u32,
    previous: Option<PreviousFrame>,
    active: bool,
    // The native launch and initializer callbacks are synchronous on their
    // owning thread. Making the guard !Send turns that ABI fact into a Rust
    // invariant instead of relying on a comment at every future callsite.
    _not_send: PhantomData<*mut ()>,
}

impl NativePolicyScope {
    /// Begin a policy scope for an eligible canonical launch.
    pub(crate) fn begin(context: ShotContext) -> Result<Self, PolicyResult> {
        if !context_is_supported(context) {
            return Err(PolicyResult::ContextRejected);
        }

        let owner_thread = get_current_thread_id();
        if owner_thread == 0 {
            return Err(PolicyResult::CapacityUnavailable);
        }

        // Reentrant launch handlers execute sequentially on the same native
        // thread. Preserve the outer frame on the Rust stack and expose only
        // the innermost request to the initializer hook.
        for (slot_index, slot) in POLICY_SLOTS.iter().enumerate() {
            if slot.thread_id.load(Ordering::Acquire) == owner_thread {
                let previous = PreviousFrame {
                    form_token: slot.form_token.load(Ordering::Relaxed),
                    force_physical: slot.force_physical.swap(false, Ordering::AcqRel),
                    observed: slot.observed.load(Ordering::Relaxed),
                    forced: slot.forced.load(Ordering::Relaxed),
                };
                slot.form_token
                    .store(context.projectile().form_token(), Ordering::Relaxed);
                slot.observed.store(false, Ordering::Relaxed);
                slot.forced.store(false, Ordering::Relaxed);
                slot.force_physical.store(true, Ordering::Release);
                return Ok(Self {
                    slot_index,
                    owner_thread,
                    previous: Some(previous),
                    active: true,
                    _not_send: PhantomData,
                });
            }
        }

        for (slot_index, slot) in POLICY_SLOTS.iter().enumerate() {
            if slot
                .thread_id
                .compare_exchange(0, owner_thread, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            slot.form_token
                .store(context.projectile().form_token(), Ordering::Relaxed);
            slot.observed.store(false, Ordering::Relaxed);
            slot.forced.store(false, Ordering::Relaxed);
            slot.force_physical.store(true, Ordering::Release);
            ACTIVE_ROOT_SCOPES.fetch_add(1, Ordering::Release);
            return Ok(Self {
                slot_index,
                owner_thread,
                previous: None,
                active: true,
                _not_send: PhantomData,
            });
        }

        Err(PolicyResult::CapacityUnavailable)
    }

    /// Close the request and report whether native initialization consumed it.
    pub(crate) fn finish(mut self) -> PolicyResult {
        match self.restore() {
            PolicyOutcome::Forced => PolicyResult::ForcedPhysical,
            PolicyOutcome::AlreadyPhysical => PolicyResult::AlreadyPhysical,
            PolicyOutcome::NotObserved => PolicyResult::PolicyNotObserved,
        }
    }

    fn restore(&mut self) -> PolicyOutcome {
        if !self.active {
            return PolicyOutcome::NotObserved;
        }
        self.active = false;

        let slot = &POLICY_SLOTS[self.slot_index];
        // Moving this crate-private guard across threads would violate the
        // native callback contract. Fail closed and release a root slot if a
        // future refactor ever does so despite the scoped callsite ownership.
        if get_current_thread_id() != self.owner_thread {
            slot.force_physical.store(false, Ordering::Release);
            if self.previous.is_none() {
                slot.form_token.store(0, Ordering::Relaxed);
                slot.observed.store(false, Ordering::Relaxed);
                slot.forced.store(false, Ordering::Relaxed);
                slot.thread_id.store(0, Ordering::Release);
                ACTIVE_ROOT_SCOPES.fetch_sub(1, Ordering::Release);
            }
            return PolicyOutcome::NotObserved;
        }

        slot.force_physical.store(false, Ordering::Release);
        let observed = slot.observed.load(Ordering::Relaxed);
        let forced = slot.forced.load(Ordering::Relaxed);
        if let Some(previous) = self.previous {
            slot.form_token
                .store(previous.form_token, Ordering::Relaxed);
            slot.observed.store(previous.observed, Ordering::Relaxed);
            slot.forced.store(previous.forced, Ordering::Relaxed);
            slot.force_physical
                .store(previous.force_physical, Ordering::Release);
        } else {
            slot.form_token.store(0, Ordering::Relaxed);
            slot.observed.store(false, Ordering::Relaxed);
            slot.forced.store(false, Ordering::Relaxed);
            slot.thread_id.store(0, Ordering::Release);
            ACTIVE_ROOT_SCOPES.fetch_sub(1, Ordering::Release);
        }
        match (observed, forced) {
            (_, true) => PolicyOutcome::Forced,
            (true, false) => PolicyOutcome::AlreadyPhysical,
            (false, false) => PolicyOutcome::NotObserved,
        }
    }
}

#[derive(Clone, Copy)]
enum PolicyOutcome {
    Forced,
    AlreadyPhysical,
    NotObserved,
}

impl Drop for NativePolicyScope {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// Observe a chained predicate result and decide whether Atom should force it false.
///
/// Every matching initialization in the canonical launch scope receives the
/// same policy. This preserves multi-projectile weapons whose launch owner may
/// initialize more than one same-form projectile before returning.
pub(crate) fn apply_native_policy(form_token: u32, predecessor_hitscan: bool) -> bool {
    if form_token == 0 || ACTIVE_ROOT_SCOPES.load(Ordering::Acquire) == 0 {
        return false;
    }
    let thread_id = get_current_thread_id();
    for slot in &POLICY_SLOTS {
        if slot.thread_id.load(Ordering::Acquire) != thread_id
            || !slot.force_physical.load(Ordering::Acquire)
            || slot.form_token.load(Ordering::Relaxed) != form_token
        {
            continue;
        }
        slot.observed.store(true, Ordering::Relaxed);
        if predecessor_hitscan {
            slot.forced.store(true, Ordering::Relaxed);
            return true;
        }
        return false;
    }
    false
}

fn context_is_supported(context: ShotContext) -> bool {
    context.capability() == ProjectileCapability::DiscreteHitscan
        && context.projectile().form_token() != 0
        && context.source_kind() != SourceKind::Unknown
        && context.source_token() != 0
        && !context.always_hit()
        && !context.ignore_gravity()
        && !context.has_live_target()
}

#[cfg(test)]
mod tests {
    use super::{NativePolicyScope, PolicyResult, apply_native_policy, context_is_supported};
    use crate::ballistics::{ProjectileCapability, ProjectileProfile, ShotContext, SourceKind};

    fn context(form_token: u32) -> ShotContext {
        ShotContext::new(
            1,
            SourceKind::Player,
            20,
            10,
            ProjectileProfile::new(form_token, 0x0001_0000, 1, 0.4, 40_640.0, 10_000.0, false),
            ProjectileCapability::DiscreteHitscan,
            [0.0; 3],
            [0.0; 2],
            false,
            false,
            false,
        )
    }

    #[test]
    fn matching_native_policy_covers_same_form_initializers_then_releases() {
        let scope = NativePolicyScope::begin(context(30)).unwrap();
        assert!(!apply_native_policy(31, true));
        assert!(apply_native_policy(30, true));
        assert!(apply_native_policy(30, true));
        assert_eq!(scope.finish(), PolicyResult::ForcedPhysical);
        assert!(!apply_native_policy(30, true));
    }

    #[test]
    fn earlier_hook_owner_can_keep_a_round_physical_without_false_failure() {
        let scope = NativePolicyScope::begin(context(30)).unwrap();
        assert!(!apply_native_policy(30, false));
        assert_eq!(scope.finish(), PolicyResult::AlreadyPhysical);
    }

    #[test]
    fn unmatched_initializer_is_reported_without_changing_its_answer() {
        let scope = NativePolicyScope::begin(context(30)).unwrap();
        assert!(!apply_native_policy(31, true));
        assert_eq!(scope.finish(), PolicyResult::PolicyNotObserved);
    }

    #[test]
    fn nested_launch_restores_the_outer_thread_policy() {
        let outer = NativePolicyScope::begin(context(30)).unwrap();
        let inner = NativePolicyScope::begin(context(31)).unwrap();
        assert!(!apply_native_policy(30, true));
        assert!(apply_native_policy(31, true));
        assert_eq!(inner.finish(), PolicyResult::ForcedPhysical);
        assert!(apply_native_policy(30, true));
        assert_eq!(outer.finish(), PolicyResult::ForcedPhysical);
    }

    #[test]
    fn targeted_and_ignore_gravity_launches_remain_native() {
        let context = |always_hit, ignore_gravity, has_live_target| {
            ShotContext::new(
                1,
                SourceKind::Player,
                20,
                10,
                ProjectileProfile::new(30, 0x0001_0000, 1, 0.4, 40_640.0, 10_000.0, false),
                ProjectileCapability::DiscreteHitscan,
                [0.0; 3],
                [0.0; 2],
                always_hit,
                ignore_gravity,
                has_live_target,
            )
        };

        assert!(context_is_supported(context(false, false, false)));
        assert!(!context_is_supported(context(true, false, false)));
        assert!(!context_is_supported(context(false, true, false)));
        assert!(!context_is_supported(context(false, false, true)));
    }
}
