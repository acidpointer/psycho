//! Deferred, transactional Ballistics lifecycle wrappers.
//!
//! Every detour captures and calls the target currently encoded by its native
//! caller. This composes with earlier callsite owners without identifying
//! them. Immutable surrounding instructions prove the supported FNV caller;
//! the mutable `E8` displacement is deliberately excluded. A scoped policy
//! request makes FNV's initializer construct physical flight before launch
//! returns; Atom never rewrites an already-initialized projectile.

use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};

use libpsycho::os::windows::{
    hook::{
        callsite::{Rel32CallHookContainer, Rel32CallHookError},
        pointer::{PointerSlotHookContainer, PointerSlotHookError},
        transaction::ModificationTransaction,
    },
    memory::{MemoryError, read_bytes},
};
use thiserror::Error;

use super::adapter;
use super::native::{self, NiPoint3};
use super::pool::{Correlation, InsertOutcome, observations};
use super::{ProjectileCapability, ShotContext, telemetry};

static COUNT_HOOK: Rel32CallHookContainer<native::CountFn> = Rel32CallHookContainer::new();
static LAUNCH_HOOK: Rel32CallHookContainer<native::LaunchFn> = Rel32CallHookContainer::new();
static HIT_BUILD_HOOK: Rel32CallHookContainer<native::HitBuildFn> = Rel32CallHookContainer::new();
static HIT_COMMIT_HOOK: Rel32CallHookContainer<native::HitCommitFn> = Rel32CallHookContainer::new();
static COLLISION_HOOK: Rel32CallHookContainer<native::CollisionFn> = Rel32CallHookContainer::new();
static HITSCAN_POLICY_HOOK: Rel32CallHookContainer<native::HitscanPolicyFn> =
    Rel32CallHookContainer::new();
static MISSILE_UPDATE_HOOK: PointerSlotHookContainer<native::MissileUpdateFn> =
    PointerSlotHookContainer::new();

static SHOT_SEQUENCE: AtomicU32 = AtomicU32::new(0);
static ACTIVE_LAUNCHES: AtomicU32 = AtomicU32::new(0);
static ACTIVE_UPDATES: AtomicU32 = AtomicU32::new(0);

const FINGERPRINTS: &[(usize, &[u8])] = &[
    (
        0x0052_4402,
        &[
            0x8B, 0x45, 0xD4, 0x50, 0x6A, 0x00, 0x0F, 0xB6, 0x4D, 0xEA, 0x51, 0x8B, 0x8D, 0xC8,
            0xFD, 0xFF, 0xFF,
        ],
    ),
    (
        0x0052_4418,
        &[
            0x88, 0x85, 0x5F, 0xFE, 0xFF, 0xFF, 0x0F, 0xB6, 0x95, 0x5F, 0xFE, 0xFF, 0xFF,
        ],
    ),
    (
        0x0052_45A1,
        &[
            0x51, 0x8B, 0x55, 0x90, 0x52, 0x8B, 0x45, 0x08, 0x50, 0x8B, 0x8D, 0x48, 0xFE, 0xFF,
            0xFF, 0x51, 0x8B, 0x8D, 0xC8, 0xFD, 0xFF, 0xFF,
        ],
    ),
    (0x0052_45BC, &[0x50]),
    (
        0x0052_45C2,
        &[0x83, 0xC4, 0x40, 0x89, 0x85, 0x58, 0xFE, 0xFF, 0xFF],
    ),
    (
        0x009B_7CFE,
        &[0x8B, 0x4D, 0xF8, 0xE8, 0xDA, 0x04, 0xA6, 0xFF, 0x8B, 0xC8],
    ),
    (
        0x009B_7D0D,
        &[
            0x88, 0x45, 0xF7, 0x8A, 0x45, 0xF7, 0x88, 0x45, 0xFC, 0x8B, 0x4D, 0xF8,
        ],
    ),
    (
        0x009C_1E4C,
        &[
            0x8B, 0x55, 0xA8, 0x52, 0x6A, 0x00, 0x8B, 0x45, 0xC8, 0x50, 0x6A, 0x00, 0x8D, 0x4D,
            0xC4,
        ],
    ),
    (0x009C_1E60, &[0x50]),
    (
        0x009C_1E66,
        &[0x83, 0xC4, 0x14, 0x6A, 0x00, 0x8B, 0x4D, 0xC8],
    ),
    (0x009C_1E92, &[0x50, 0x8B, 0x4D, 0xC8]),
    (
        0x009C_1E9B,
        &[0xC7, 0x45, 0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0x8D, 0x4D, 0xC4],
    ),
    (
        0x009C_2038,
        &[
            0x8B, 0x45, 0xE4, 0x8B, 0x48, 0x20, 0x51, 0x8B, 0x55, 0xC0, 0x52, 0x8B, 0x45, 0xE4,
            0x83, 0xC0, 0x10, 0x50, 0x8B, 0x4D, 0xE4, 0x83, 0xC1, 0x04, 0x51, 0x8B, 0x55, 0xE8,
            0x52, 0x8B, 0x4D, 0xA8,
        ],
    ),
    (
        0x009C_205D,
        &[
            0x8B, 0x45, 0xC0, 0x50, 0x8D, 0x4D, 0xAC, 0x51, 0x8B, 0x4D, 0xA8,
        ],
    ),
];

/// Failure to validate or install Ballistics observation hooks.
#[derive(Debug, Error)]
pub(crate) enum HookInstallError {
    /// Reading an immutable caller fingerprint failed.
    #[error(transparent)]
    Memory(#[from] MemoryError),
    /// A supported-runtime call context differs from the researched binary.
    #[error("native ballistics caller fingerprint mismatch at 0x{address:08X}")]
    FingerprintMismatch { address: usize },
    /// A direct call could not be captured, chained, enabled, or rolled back.
    #[error(transparent)]
    Callsite(#[from] Rel32CallHookError),
    /// The MissileProjectile update slot could not be chained transactionally.
    #[error(transparent)]
    Pointer(#[from] PointerSlotHookError),
}

/// Current call targets captured during deferred installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HookPredecessors {
    pub(crate) count: usize,
    pub(crate) launch: usize,
    pub(crate) hit_build: usize,
    pub(crate) hit_commit: usize,
    pub(crate) collision: usize,
    pub(crate) hitscan_policy: usize,
    pub(crate) missile_update: usize,
}

pub(crate) fn install() -> Result<HookPredecessors, HookInstallError> {
    validate_fingerprints()?;
    unsafe {
        COUNT_HOOK.init(
            "Atom projectile count observation",
            native::COUNT_CALLSITE as *mut c_void,
            count_detour,
        )?;
        LAUNCH_HOOK.init(
            "Atom projectile launch observation",
            native::LAUNCH_CALLSITE as *mut c_void,
            launch_detour,
        )?;
        HIT_BUILD_HOOK.init(
            "Atom projectile hit observation",
            native::HIT_BUILD_CALLSITE as *mut c_void,
            hit_build_detour,
        )?;
        HIT_COMMIT_HOOK.init(
            "Atom projectile hit commit observation",
            native::HIT_COMMIT_CALLSITE as *mut c_void,
            hit_commit_detour,
        )?;
        COLLISION_HOOK.init(
            "Atom projectile collision observation",
            native::COLLISION_CALLSITE as *mut c_void,
            collision_detour,
        )?;
        HITSCAN_POLICY_HOOK.init(
            "Atom native projectile flight policy",
            native::HITSCAN_POLICY_CALLSITE as *mut c_void,
            hitscan_policy_detour,
        )?;
        MISSILE_UPDATE_HOOK.init(
            "Atom MissileProjectile update observation",
            native::MISSILE_UPDATE_SLOT as *mut *mut c_void,
            missile_update_detour,
        )?;
    }

    let predecessors = HookPredecessors {
        count: COUNT_HOOK.predecessor_address()?,
        launch: LAUNCH_HOOK.predecessor_address()?,
        hit_build: HIT_BUILD_HOOK.predecessor_address()?,
        hit_commit: HIT_COMMIT_HOOK.predecessor_address()?,
        collision: COLLISION_HOOK.predecessor_address()?,
        hitscan_policy: HITSCAN_POLICY_HOOK.predecessor_address()?,
        missile_update: MISSILE_UPDATE_HOOK.predecessor_address()?,
    };
    let mut transaction = ModificationTransaction::new();
    transaction.enable_callsite(&COUNT_HOOK)?;
    transaction.enable_callsite(&LAUNCH_HOOK)?;
    transaction.enable_callsite(&HIT_BUILD_HOOK)?;
    transaction.enable_callsite(&HIT_COMMIT_HOOK)?;
    transaction.enable_callsite(&COLLISION_HOOK)?;
    transaction.enable_callsite(&HITSCAN_POLICY_HOOK)?;
    transaction.enable_pointer(&MISSILE_UPDATE_HOOK)?;
    transaction.commit();
    Ok(predecessors)
}

fn validate_fingerprints() -> Result<(), HookInstallError> {
    for &(address, expected) in FINGERPRINTS {
        if read_bytes(address as *const c_void, expected.len())? != expected {
            return Err(HookInstallError::FingerprintMismatch { address });
        }
    }
    Ok(())
}

unsafe extern "thiscall" fn count_detour(
    weapon: *mut c_void,
    apply_perk: u8,
    use_ammo: u8,
    source: *mut c_void,
) -> u8 {
    let predecessor = COUNT_HOOK
        .original()
        .unwrap_or_else(|_| native::native_count());
    let count = unsafe { predecessor(weapon, apply_perk, use_ammo, source) };
    if telemetry::enabled() {
        telemetry::record_projectile_count(count);
    }
    count
}

#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn launch_detour(
    projectile: *mut c_void,
    source: *mut c_void,
    controller: *mut c_void,
    weapon: *mut c_void,
    position: NiPoint3,
    rotation_z: f32,
    rotation_x: f32,
    opaque: *mut c_void,
    live_target: *mut c_void,
    always_hit: u32,
    ignore_gravity: u32,
    angular_z: f32,
    angular_x: f32,
    cell: *mut c_void,
) -> *mut c_void {
    let predecessor = LAUNCH_HOOK
        .original()
        .unwrap_or_else(|_| native::native_launch());
    let config = super::current_config();
    let tracing = telemetry::enabled();
    if !tracing && !config.enabled() {
        return unsafe {
            predecessor(
                projectile,
                source,
                controller,
                weapon,
                position,
                rotation_z,
                rotation_x,
                opaque,
                live_target,
                always_hit,
                ignore_gravity,
                angular_z,
                angular_x,
                cell,
            )
        };
    }

    let profile = unsafe { native::profile(projectile) };
    let capability = native::classify_profile(profile);
    if tracing
        && (projectile.is_null()
            || !profile.gravity().is_finite()
            || !profile.speed().is_finite()
            || !profile.range().is_finite()
            || profile.speed() <= 0.0
            || profile.range() <= 0.0)
    {
        telemetry::record_invalid_value();
    }
    let context = ShotContext::new(
        if tracing {
            SHOT_SEQUENCE
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1)
        } else {
            0
        },
        unsafe { native::source_kind(source) },
        source as usize as u32,
        weapon as usize as u32,
        profile,
        capability,
        [position.x, position.y, position.z],
        [rotation_z, rotation_x],
        always_hit != 0,
        ignore_gravity != 0,
        !live_target.is_null(),
    );
    let launch_tick = if tracing { telemetry::now_tick() } else { 0 };
    if tracing {
        telemetry::record_launch(context.source_kind(), capability);
    }

    let policy_scope = if config.enabled() && capability == ProjectileCapability::DiscreteHitscan {
        Some(adapter::NativePolicyScope::begin(context))
    } else {
        None
    };

    if tracing {
        ACTIVE_LAUNCHES.fetch_add(1, Ordering::AcqRel);
    }
    let result = unsafe {
        predecessor(
            projectile,
            source,
            controller,
            weapon,
            position,
            rotation_z,
            rotation_x,
            opaque,
            live_target,
            always_hit,
            ignore_gravity,
            angular_z,
            angular_x,
            cell,
        )
    };
    if tracing {
        ACTIVE_LAUNCHES.fetch_sub(1, Ordering::AcqRel);
    }
    let policy_result = policy_scope.map(|scope| match scope {
        Ok(scope) => scope.finish(),
        Err(result) => result,
    });
    let selected_path = selected_flight_path(capability, policy_result);
    if tracing {
        if let Some(policy_result) = policy_result {
            telemetry::record_policy_result(policy_result);
        }
    } else {
        return result;
    }

    let Some(observations) = observations() else {
        if tracing {
            telemetry::record_pool_overflow();
        }
        return result;
    };
    match observations.insert(
        result as usize as u32,
        context,
        selected_path,
        launch_tick,
        telemetry::max_interval_ticks(),
    ) {
        InsertOutcome::Added => {}
        InsertOutcome::ReplacedExpired => {
            if tracing {
                telemetry::record_expired_misses(1);
            }
        }
        InsertOutcome::ReplacedGeneration => {
            if tracing {
                telemetry::record_stale_generation();
            }
        }
        InsertOutcome::Overflow => {
            if tracing {
                telemetry::record_pool_overflow();
            }
        }
        InsertOutcome::InvalidToken | InsertOutcome::LifecycleRace => {
            if tracing {
                telemetry::record_invalid_value();
            }
        }
    }
    result
}

/// Resolve the launch-time path independently of later runtime-marker edits.
///
/// A projectile presentation extension may add a hitscan marker to a physical
/// object after initialization. The scoped predicate result remains the
/// authoritative record of what FNV constructed, while the live marker pair
/// is retained separately as compatibility evidence.
fn selected_flight_path(
    capability: ProjectileCapability,
    policy_result: Option<adapter::PolicyResult>,
) -> native::RuntimeFlightPath {
    if matches!(
        policy_result,
        Some(adapter::PolicyResult::ForcedPhysical | adapter::PolicyResult::AlreadyPhysical)
    ) {
        return native::RuntimeFlightPath::Physical;
    }
    match capability {
        ProjectileCapability::DiscreteHitscan => native::RuntimeFlightPath::Hitscan,
        ProjectileCapability::DiscretePhysical => native::RuntimeFlightPath::Physical,
        _ => native::RuntimeFlightPath::Ambiguous,
    }
}

unsafe extern "thiscall" fn hitscan_policy_detour(projectile_form: *mut c_void) -> u8 {
    let predecessor = HITSCAN_POLICY_HOOK
        .original()
        .unwrap_or_else(|_| native::native_hitscan_policy());
    let native_hitscan = unsafe { predecessor(projectile_form) };
    if adapter::apply_native_policy(projectile_form as usize as u32, native_hitscan != 0) {
        0
    } else {
        native_hitscan
    }
}

unsafe extern "C" fn hit_build_detour(
    hit_data: *mut c_void,
    unknown: *mut c_void,
    target: *mut c_void,
    attacker_context: *mut c_void,
    projectile: *mut c_void,
) {
    note_early_contact();
    let predecessor = HIT_BUILD_HOOK
        .original()
        .unwrap_or_else(|_| native::native_hit_build());
    unsafe { predecessor(hit_data, unknown, target, attacker_context, projectile) };
    if !telemetry::enabled() {
        return;
    }
    let Some(observations) = observations() else {
        telemetry::record_untracked_hit_build();
        return;
    };
    match observations.record_actor_hit(projectile as usize as u32) {
        Correlation::First => telemetry::record_actor_hit(false),
        Correlation::Duplicate => telemetry::record_actor_hit(true),
        Correlation::Missing => telemetry::record_untracked_hit_build(),
    }
}

unsafe extern "thiscall" fn hit_commit_detour(target: *mut c_void, hit_data: *mut c_void) {
    let predecessor = HIT_COMMIT_HOOK
        .original()
        .unwrap_or_else(|_| native::native_hit_commit());
    unsafe { predecessor(target, hit_data) };
    if telemetry::enabled() {
        telemetry::record_hit_commit();
    }
}

unsafe extern "thiscall" fn collision_detour(
    projectile: *mut c_void,
    target: *mut c_void,
    point: *const NiPoint3,
    normal: *const NiPoint3,
    material: *mut c_void,
    collision_flags: u32,
) {
    note_early_contact();
    let observation = if telemetry::enabled() {
        observations().map(|pool| pool.record_contact(projectile as usize as u32))
    } else {
        None
    };
    let predecessor = COLLISION_HOOK
        .original()
        .unwrap_or_else(|_| native::native_collision());
    unsafe { predecessor(projectile, target, point, normal, material, collision_flags) };

    let Some(observation) = observation else {
        return;
    };
    match observation.correlation {
        Correlation::Missing => telemetry::record_untracked_contact(),
        correlation => {
            let duplicate = correlation == Correlation::Duplicate;
            if observation.actor_hit {
                telemetry::record_actor_contact(duplicate, observation.launch_tick);
            } else {
                telemetry::record_world_impact(duplicate, observation.launch_tick);
            }
        }
    }
}

fn note_early_contact() {
    if telemetry::enabled() && ACTIVE_LAUNCHES.load(Ordering::Acquire) != 0 {
        telemetry::record_early_contact();
    }
    if telemetry::enabled() && ACTIVE_UPDATES.load(Ordering::Acquire) != 0 {
        telemetry::record_contact_during_update();
    }
}

unsafe extern "thiscall" fn missile_update_detour(projectile: *mut c_void, delta_seconds: f32) {
    let predecessor = MISSILE_UPDATE_HOOK
        .original()
        .unwrap_or_else(|_| native::native_missile_update());
    if !telemetry::enabled() {
        unsafe { predecessor(projectile, delta_seconds) };
        return;
    }

    let observation =
        observations().and_then(|pool| pool.record_update(projectile as usize as u32));
    let pre = unsafe { native::runtime_sample(projectile) };
    let before_launch_return = ACTIVE_LAUNCHES.load(Ordering::Acquire) != 0;
    let capability = observation
        .map(|observation| observation.capability)
        .unwrap_or(super::ProjectileCapability::Unknown);
    let first =
        observation.is_some_and(|observation| observation.correlation == Correlation::First);
    telemetry::record_update_entry(
        observation.is_some(),
        first,
        capability,
        observation
            .map(|observation| observation.selected_path)
            .unwrap_or(native::RuntimeFlightPath::Ambiguous),
        pre.map(native::ProjectileRuntimeSample::policy_markers)
            .unwrap_or(native::RuntimePolicyMarkers::Neither),
        delta_seconds,
        before_launch_return,
    );

    let effective_speed = if observation.is_some() && pre.is_some() {
        unsafe { native::effective_speed(projectile) }
    } else {
        0.0
    };
    ACTIVE_UPDATES.fetch_add(1, Ordering::AcqRel);
    unsafe { predecessor(projectile, delta_seconds) };
    ACTIVE_UPDATES.fetch_sub(1, Ordering::AcqRel);

    let Some(pre) = pre else {
        telemetry::record_invalid_value();
        return;
    };
    if observation.is_none() {
        return;
    }
    let Some(post) = (unsafe { native::runtime_sample(projectile) }) else {
        telemetry::record_invalid_value();
        return;
    };
    telemetry::record_update_result(pre, post, delta_seconds, effective_speed);
}

#[cfg(test)]
mod tests {
    use super::selected_flight_path;
    use crate::ballistics::ProjectileCapability;
    use crate::ballistics::adapter::PolicyResult;
    use crate::ballistics::native::RuntimeFlightPath;

    #[test]
    fn selected_path_uses_the_scoped_initializer_result() {
        assert_eq!(
            selected_flight_path(
                ProjectileCapability::DiscreteHitscan,
                Some(PolicyResult::ForcedPhysical),
            ),
            RuntimeFlightPath::Physical
        );
        assert_eq!(
            selected_flight_path(
                ProjectileCapability::DiscreteHitscan,
                Some(PolicyResult::AlreadyPhysical),
            ),
            RuntimeFlightPath::Physical
        );
        assert_eq!(
            selected_flight_path(
                ProjectileCapability::DiscreteHitscan,
                Some(PolicyResult::ContextRejected),
            ),
            RuntimeFlightPath::Hitscan
        );
        assert_eq!(
            selected_flight_path(ProjectileCapability::DiscretePhysical, None),
            RuntimeFlightPath::Physical
        );
        assert_eq!(
            selected_flight_path(ProjectileCapability::Flame, None),
            RuntimeFlightPath::Ambiguous
        );
    }
}
