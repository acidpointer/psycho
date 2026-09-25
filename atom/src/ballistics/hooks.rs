//! Deferred, transactional Ballistics lifecycle wrappers.
//!
//! Every detour captures and calls the target currently encoded by its native
//! caller. This composes with earlier callsite owners without identifying
//! them. Hook preparation validates the live instruction and executable
//! target without comparing surrounding code to vanilla bytes. A scoped policy
//! request makes FNV's initializer construct physical flight before launch
//! returns. Ricochet creates a fresh native child on a collision-verified
//! outbound segment and lets the completed parent retain its terminal result.
//! The positive player count result also publishes one pointer-free camera
//! event before the native multi-projectile loop.
//!
//! Directly-called runtime helpers are admitted on entry readiness alone:
//! each fixed target must be mapped executable memory before Atom ever calls
//! it, and a failure keeps those addresses unreachable while physical-rounds
//! policy stays active. Compatible entry wrappers and interior patches must
//! preserve the supported ABI; vanilla-body equality cannot establish that
//! contract and is not checked. Detour predecessor fallbacks to vanilla addresses
//! follow the same unreachable-by-construction rule as the other subsystems.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use libpsycho::os::windows::hook::{
    callsite::{Rel32CallHookContainer, Rel32CallHookError},
    pointer::{PointerSlotHookContainer, PointerSlotHookError},
    transaction::ModificationTransaction,
};
use thiserror::Error;

use super::adapter;
use super::native::{self, NiPoint3};
use super::pool::{Correlation, ImpactObservation, InsertOutcome, RicochetState, observations};
use super::ricochet::{
    ContactSignature, FirstStepOutcome, FollowupContact, FollowupSample, ResponseError,
    RicochetPlan, child_spawn_path, direction_error_degrees, direction_from_rotation,
    first_step_evidence,
};
use super::{ProjectileCapability, ShotContext, SourceKind, telemetry};

static COUNT_HOOK: Rel32CallHookContainer<native::CountFn> = Rel32CallHookContainer::new();
static LAUNCH_HOOK: Rel32CallHookContainer<native::LaunchFn> = Rel32CallHookContainer::new();
static HIT_BUILD_HOOK: Rel32CallHookContainer<native::HitBuildFn> = Rel32CallHookContainer::new();
static HIT_COMMIT_HOOK: Rel32CallHookContainer<native::HitCommitFn> = Rel32CallHookContainer::new();
static COLLISION_HOOK: Rel32CallHookContainer<native::CollisionFn> = Rel32CallHookContainer::new();
static COMMON_IMPACT_HOOK: Rel32CallHookContainer<native::CommonImpactFn> =
    Rel32CallHookContainer::new();
static HITSCAN_POLICY_HOOK: Rel32CallHookContainer<native::HitscanPolicyFn> =
    Rel32CallHookContainer::new();
static MUZZLE_FLASH_HOOK: Rel32CallHookContainer<native::MuzzleFlashFn> =
    Rel32CallHookContainer::new();
static MOVEMENT_STEP_A_HOOK: Rel32CallHookContainer<native::MovementStepFn> =
    Rel32CallHookContainer::new();
static MOVEMENT_STEP_B_HOOK: Rel32CallHookContainer<native::MovementStepFn> =
    Rel32CallHookContainer::new();
static MISSILE_UPDATE_HOOK: PointerSlotHookContainer<native::MissileUpdateFn> =
    PointerSlotHookContainer::new();

static SHOT_SEQUENCE: AtomicU32 = AtomicU32::new(0);
static ACTIVE_LAUNCHES: AtomicU32 = AtomicU32::new(0);
static ACTIVE_UPDATES: AtomicU32 = AtomicU32::new(0);
static RICOCHET_MUTATION_ADMITTED: AtomicBool = AtomicBool::new(false);
/// Admission result of `native::validate_helper_entries`.
///
/// False keeps every directly-called helper address unreachable from Atom:
/// ricochet stays observe-only and trace speed sampling stops, while the
/// physical-rounds policy (which never calls helpers) remains active.
/// Interior-body differences are diagnostic only and never set this flag.
static HELPER_ENTRIES_READY: AtomicBool = AtomicBool::new(false);

/// Saturating entry counters for every Ballistics detour.
///
/// Byte-level ownership can be lost to a later writer that still chains Atom
/// (feature alive) or bypasses it (feature dead). Only execution proves
/// which. One relaxed increment per native callback is negligible next to
/// the callback's own work and gives the diagnostics summary ground truth
/// even when telemetry is disabled.
#[derive(Clone, Copy, Default)]
pub(crate) struct DetourCallCounts {
    pub(crate) count: u32,
    pub(crate) launch: u32,
    pub(crate) hit_build: u32,
    pub(crate) hit_commit: u32,
    pub(crate) collision: u32,
    pub(crate) hitscan_policy: u32,
    pub(crate) muzzle_flash: u32,
    pub(crate) movement_step_a: u32,
    pub(crate) movement_step_b: u32,
    pub(crate) missile_update: u32,
    pub(crate) common_impact: u32,
}

static COUNT_CALLS: AtomicU32 = AtomicU32::new(0);
static LAUNCH_CALLS: AtomicU32 = AtomicU32::new(0);
static HIT_BUILD_CALLS: AtomicU32 = AtomicU32::new(0);
static HIT_COMMIT_CALLS: AtomicU32 = AtomicU32::new(0);
static COLLISION_CALLS: AtomicU32 = AtomicU32::new(0);
static HITSCAN_POLICY_CALLS: AtomicU32 = AtomicU32::new(0);
static MUZZLE_FLASH_CALLS: AtomicU32 = AtomicU32::new(0);
static MOVEMENT_STEP_A_CALLS: AtomicU32 = AtomicU32::new(0);
static MOVEMENT_STEP_B_CALLS: AtomicU32 = AtomicU32::new(0);
static MISSILE_UPDATE_CALLS: AtomicU32 = AtomicU32::new(0);
static COMMON_IMPACT_CALLS: AtomicU32 = AtomicU32::new(0);

fn note_call(counter: &AtomicU32) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

pub(crate) fn detour_call_counts() -> DetourCallCounts {
    DetourCallCounts {
        count: COUNT_CALLS.load(Ordering::Relaxed),
        launch: LAUNCH_CALLS.load(Ordering::Relaxed),
        hit_build: HIT_BUILD_CALLS.load(Ordering::Relaxed),
        hit_commit: HIT_COMMIT_CALLS.load(Ordering::Relaxed),
        collision: COLLISION_CALLS.load(Ordering::Relaxed),
        hitscan_policy: HITSCAN_POLICY_CALLS.load(Ordering::Relaxed),
        muzzle_flash: MUZZLE_FLASH_CALLS.load(Ordering::Relaxed),
        movement_step_a: MOVEMENT_STEP_A_CALLS.load(Ordering::Relaxed),
        movement_step_b: MOVEMENT_STEP_B_CALLS.load(Ordering::Relaxed),
        missile_update: MISSILE_UPDATE_CALLS.load(Ordering::Relaxed),
        common_impact: COMMON_IMPACT_CALLS.load(Ordering::Relaxed),
    }
}

const PROJECTILE_FLAG_EXPLOSION: u16 = 0x0002;
const PROJECTILE_FLAG_NATIVE_BOUNCE: u16 = 0x0010;
const IMPACT_RESULT_DESTROY: u32 = 1;

/// Failure to validate or install Ballistics observation hooks.
#[derive(Debug, Error)]
pub(crate) enum HookInstallError {
    /// A direct call could not be captured, chained, enabled, or rolled back.
    #[error(transparent)]
    Callsite(#[from] Rel32CallHookError),
    /// The MissileProjectile update slot could not be chained transactionally.
    #[error(transparent)]
    Pointer(#[from] PointerSlotHookError),
    /// A directly-called helper entry is not executable.
    #[error(transparent)]
    Helper(#[from] native::HelperContractError),
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
    pub(crate) muzzle_flash: usize,
    pub(crate) movement_step_a: usize,
    pub(crate) movement_step_b: usize,
    pub(crate) missile_update: usize,
}

/// Captured hook capabilities that determine whether child mutation is safe.
///
/// The weapon launch predecessor is retained for diagnostics but deliberately
/// does not participate in admission. Ordinary weapon shots chain that owner,
/// while reflected children start at the audited native spawn boundary so an
/// aim or weapon wrapper cannot transform the reflected continuation again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RicochetAdmission {
    pub(crate) launch_predecessor: usize,
    pub(crate) common_impact_predecessor: usize,
    pub(crate) muzzle_flash_predecessor: usize,
    pub(crate) helper_entries_ready: bool,
}

impl RicochetAdmission {
    pub(crate) const fn common_impact_supported(self) -> bool {
        self.common_impact_predecessor == native::COMMON_IMPACT_TARGET
    }

    pub(crate) const fn child_presentation_supported(self) -> bool {
        self.muzzle_flash_predecessor == native::MUZZLE_FLASH_TARGET
    }

    pub(crate) const fn mutation_admitted(self) -> bool {
        self.common_impact_supported()
            && self.child_presentation_supported()
            && self.helper_entries_ready
    }
}

/// Return whether every directly-called runtime helper entry is mapped
/// executable memory.
pub(crate) fn helper_entries_ready() -> bool {
    HELPER_ENTRIES_READY.load(Ordering::Acquire)
}

pub(crate) fn install() -> Result<HookPredecessors, HookInstallError> {
    match native::validate_helper_entries() {
        Ok(()) => HELPER_ENTRIES_READY.store(true, Ordering::Release),
        Err(error) => log::warn!(
            "[BALLISTICS] Runtime helper entry contract failed: {error}. Ricochet stays observe-only and trace speed sampling is disabled; physical rounds remain active"
        ),
    }
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
        MUZZLE_FLASH_HOOK.init(
            "Atom synthetic projectile muzzle suppression",
            native::MUZZLE_FLASH_CALLSITE as *mut c_void,
            muzzle_flash_detour,
        )?;
        MOVEMENT_STEP_A_HOOK.init(
            "Atom projectile movement boundary A",
            native::MOVEMENT_STEP_CALLSITE_A as *mut c_void,
            movement_step_a_detour,
        )?;
        MOVEMENT_STEP_B_HOOK.init(
            "Atom projectile movement boundary B",
            native::MOVEMENT_STEP_CALLSITE_B as *mut c_void,
            movement_step_b_detour,
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
        muzzle_flash: MUZZLE_FLASH_HOOK.predecessor_address()?,
        movement_step_a: MOVEMENT_STEP_A_HOOK.predecessor_address()?,
        movement_step_b: MOVEMENT_STEP_B_HOOK.predecessor_address()?,
        missile_update: MISSILE_UPDATE_HOOK.predecessor_address()?,
    };
    let mut transaction = ModificationTransaction::new();
    transaction.enable_callsite(&COUNT_HOOK)?;
    transaction.enable_callsite(&LAUNCH_HOOK)?;
    transaction.enable_callsite(&HIT_BUILD_HOOK)?;
    transaction.enable_callsite(&HIT_COMMIT_HOOK)?;
    transaction.enable_callsite(&COLLISION_HOOK)?;
    transaction.enable_callsite(&HITSCAN_POLICY_HOOK)?;
    transaction.enable_callsite(&MUZZLE_FLASH_HOOK)?;
    transaction.enable_callsite(&MOVEMENT_STEP_A_HOOK)?;
    transaction.enable_callsite(&MOVEMENT_STEP_B_HOOK)?;
    transaction.enable_pointer(&MISSILE_UPDATE_HOOK)?;
    transaction.commit();
    Ok(predecessors)
}

/// Install the common-impact child-spawn seam independently.
pub(crate) fn install_ricochet_observer() -> Result<RicochetAdmission, HookInstallError> {
    let launch_predecessor = LAUNCH_HOOK.predecessor_address()?;
    let muzzle_flash_predecessor = MUZZLE_FLASH_HOOK.predecessor_address()?;
    unsafe {
        COMMON_IMPACT_HOOK.init(
            "Atom ricochet impact observation",
            native::COMMON_IMPACT_CALLSITE as *mut c_void,
            common_impact_detour,
        )?;
    }
    let admission = RicochetAdmission {
        launch_predecessor,
        common_impact_predecessor: COMMON_IMPACT_HOOK.predecessor_address()?,
        muzzle_flash_predecessor,
        helper_entries_ready: helper_entries_ready(),
    };
    let mut transaction = ModificationTransaction::new();
    transaction.enable_callsite(&COMMON_IMPACT_HOOK)?;
    transaction.commit();
    RICOCHET_MUTATION_ADMITTED.store(admission.mutation_admitted(), Ordering::Release);
    Ok(admission)
}

unsafe extern "thiscall" fn count_detour(
    weapon: *mut c_void,
    apply_perk: u8,
    use_ammo: u8,
    source: *mut c_void,
) -> u8 {
    note_call(&COUNT_CALLS);
    let predecessor = COUNT_HOOK
        .original()
        .unwrap_or_else(|_| native::native_count());
    let count = unsafe { predecessor(weapon, apply_perk, use_ammo, source) };
    if telemetry::enabled() {
        telemetry::record_projectile_count(count);
    }
    if count != 0 && unsafe { native::source_kind(source) } == SourceKind::Player {
        crate::camera::publish_player_shot();
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
    note_call(&LAUNCH_CALLS);
    let predecessor = LAUNCH_HOOK
        .original()
        .unwrap_or_else(|_| native::native_launch());
    let config = super::current_config();
    let tracing = telemetry::enabled();
    let retain_launch = tracing || config.ricochet_enabled();
    if !retain_launch && !config.enabled() {
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
        if retain_launch {
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
    let launch_tick = if retain_launch {
        telemetry::now_tick()
    } else {
        0
    };
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
    } else if !retain_launch {
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
        InsertOutcome::ReplacedExpiredPendingRicochet => {
            if tracing {
                telemetry::record_expired_misses(1);
                telemetry::record_ricochet_pending_lost(1);
            }
        }
        InsertOutcome::ReplacedGeneration => {
            if tracing {
                telemetry::record_stale_generation();
            }
        }
        InsertOutcome::ReplacedGenerationPendingRicochet => {
            if tracing {
                telemetry::record_stale_generation();
                telemetry::record_ricochet_pending_lost(1);
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
    note_call(&HITSCAN_POLICY_CALLS);
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

unsafe extern "thiscall" fn muzzle_flash_detour(projectile: *mut c_void) {
    note_call(&MUZZLE_FLASH_CALLS);
    let predecessor = MUZZLE_FLASH_HOOK
        .original()
        .unwrap_or_else(|_| native::native_muzzle_flash());
    let form_token = unsafe { native::runtime_base_form_token(projectile) };
    if adapter::synthetic_child_active(form_token) {
        return;
    }
    unsafe { predecessor(projectile) };
}

unsafe extern "C" fn hit_build_detour(
    hit_data: *mut c_void,
    unknown: *mut c_void,
    target: *mut c_void,
    attacker_context: *mut c_void,
    projectile: *mut c_void,
) {
    note_call(&HIT_BUILD_CALLS);
    note_early_contact();
    let predecessor = HIT_BUILD_HOOK
        .original()
        .unwrap_or_else(|_| native::native_hit_build());
    unsafe { predecessor(hit_data, unknown, target, attacker_context, projectile) };
    let tracing = telemetry::enabled();
    if !tracing && !super::current_config().ricochet_enabled() {
        return;
    }
    let Some(observations) = observations() else {
        if tracing {
            telemetry::record_untracked_hit_build();
        }
        return;
    };
    let correlation = observations.record_actor_hit(projectile as usize as u32);
    if tracing {
        match correlation {
            Correlation::First => telemetry::record_actor_hit(false),
            Correlation::Duplicate => telemetry::record_actor_hit(true),
            Correlation::Missing => telemetry::record_untracked_hit_build(),
        }
    }
    if tracing
        && observations
            .impact_observation(projectile as usize as u32)
            .is_some_and(|observation| {
                matches!(
                    observation.ricochet_state,
                    RicochetState::Published
                        | RicochetState::Probing
                        | RicochetState::Confirmed
                        | RicochetState::Failed
                )
            })
    {
        telemetry::record_ricochet_post_bounce_actor_hit();
    }
}

unsafe extern "thiscall" fn hit_commit_detour(target: *mut c_void, hit_data: *mut c_void) {
    note_call(&HIT_COMMIT_CALLS);
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
    rigid_body_value: *mut c_void,
    raw_material: u32,
) {
    note_call(&COLLISION_CALLS);
    note_early_contact();
    let observation = if telemetry::enabled() {
        observations().map(|pool| pool.record_contact(projectile as usize as u32))
    } else {
        None
    };
    let predecessor = COLLISION_HOOK
        .original()
        .unwrap_or_else(|_| native::native_collision());
    unsafe {
        predecessor(
            projectile,
            target,
            point,
            normal,
            rigid_body_value,
            raw_material,
        )
    };

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

unsafe extern "thiscall" fn common_impact_detour(projectile: *mut c_void) -> u8 {
    note_call(&COMMON_IMPACT_CALLS);
    let predecessor = COMMON_IMPACT_HOOK
        .original()
        .unwrap_or_else(|_| native::native_common_impacts());
    let tracing = telemetry::enabled();
    let config = super::current_config();
    if !tracing && !config.ricochet_enabled() {
        return unsafe { predecessor(projectile) };
    }

    let token = projectile as usize as u32;
    let runtime = unsafe { native::runtime_sample(projectile) };
    let impacts = unsafe { native::impact_list_sample(projectile) };
    let launch = observations().and_then(|pool| pool.impact_observation(token));

    let sample_followup = launch.is_some_and(|launch| {
        matches!(
            launch.ricochet_state,
            RicochetState::Published | RicochetState::Probing
        ) || (tracing
            && matches!(
                launch.ricochet_state,
                RicochetState::Confirmed | RicochetState::Failed
            ))
    });
    let followup = if sample_followup
        && let (Some(pool), Some(launch), Some(runtime), Some(_), Some(record)) = (
            observations(),
            launch,
            runtime,
            impacts,
            impacts.and_then(|impacts| impacts.first_ready),
        ) {
        pool.followup_contact(
            token,
            launch.generation,
            launch.lifecycle,
            FollowupSample {
                target_token: record.target_token,
                point: record.point,
                raw_material: record.raw_material,
                distance_travelled: runtime.distance_travelled,
                direction: runtime.direction,
            },
        )
    } else {
        None
    };
    if tracing
        && launch.is_some_and(|launch| {
            matches!(
                launch.ricochet_state,
                RicochetState::Published
                    | RicochetState::Probing
                    | RicochetState::Confirmed
                    | RicochetState::Failed
            )
        })
    {
        telemetry::record_ricochet_post_bounce_contact(followup);
    }

    let prepared =
        if config.ricochet_enabled() && RICOCHET_MUTATION_ADMITTED.load(Ordering::Acquire) {
            prepare_ricochet(
                projectile,
                config.ricochet_energy(),
                launch,
                runtime,
                impacts,
                followup,
            )
        } else {
            Err(if config.ricochet_enabled() {
                telemetry::RicochetRejection::CriticalAdmission
            } else {
                telemetry::RicochetRejection::Disabled
            })
        };
    let prepared = match prepared {
        Ok(prepared) => {
            let Some(pool) = observations() else {
                if tracing {
                    telemetry::record_ricochet_rejection(telemetry::RicochetRejection::Untracked);
                }
                return unsafe { predecessor(projectile) };
            };
            let Some(reservation) =
                pool.reserve_ricochet(token, prepared.launch.generation, prepared.launch.lifecycle)
            else {
                if tracing {
                    telemetry::record_ricochet_rejection(telemetry::RicochetRejection::StateRace);
                }
                return unsafe { predecessor(projectile) };
            };
            if tracing {
                telemetry::record_ricochet_candidate(
                    prepared.plan,
                    reservation.bounce_depth().saturating_add(1),
                );
            }
            Some((prepared, reservation))
        }
        Err(reason) => {
            if tracing {
                telemetry::record_ricochet_rejection(reason);
            }
            None
        }
    };

    let result = unsafe { predecessor(projectile) };
    let post_launch = observations().and_then(|pool| pool.impact_observation(token));
    if tracing {
        telemetry::record_common_impact(telemetry::CommonImpactObservation {
            launch: post_launch,
            runtime,
            impacts,
            predecessor_result: result,
        });
    }

    let Some((prepared, reservation)) = prepared else {
        return result;
    };
    let Some(pool) = observations() else {
        return result;
    };
    let post = unsafe { native::runtime_sample(projectile) };
    let post_check = validate_post_impact(prepared, post_launch, post, result);
    let (post, source) = match post_check {
        Ok(value) => value,
        Err(reason) => {
            pool.cancel_ricochet(token, reservation);
            if tracing {
                telemetry::record_ricochet_rejection(reason);
            }
            return result;
        }
    };
    let path = match child_spawn_path(
        post.position,
        prepared.runtime.direction,
        prepared.plan.reflected_vector(),
    ) {
        Ok(path) => path,
        Err(_) => {
            pool.cancel_ricochet(token, reservation);
            if tracing {
                telemetry::record_ricochet_rejection(telemetry::RicochetRejection::InvalidGeometry);
            }
            return result;
        }
    };
    if !unsafe { native::outbound_clearance_available(path) } {
        pool.cancel_ricochet(token, reservation);
        if tracing {
            telemetry::record_ricochet_rejection(telemetry::RicochetRejection::Clearance);
        }
        return result;
    }
    let (child, child_context, published) =
        match unsafe { spawn_ricochet_child(prepared, post, path.spawn_origin()) } {
            Ok(child) => child,
            Err(reason) => {
                pool.cancel_ricochet(token, reservation);
                if tracing {
                    telemetry::record_ricochet_rejection(reason);
                }
                return result;
            }
        };
    let contact = ContactSignature {
        target_token: prepared.record.target_token,
        point: prepared.record.point,
        oriented_normal: prepared.plan.oriented_normal(),
        raw_material: prepared.record.raw_material,
        distance_travelled: post.distance_travelled,
    };
    if !pool.publish_ricochet_child(
        token,
        reservation,
        child as usize as u32,
        child_context,
        telemetry::now_tick(),
        contact,
        prepared.plan.reflected_vector(),
    ) {
        unsafe { native::terminate_projectile(child) };
        pool.cancel_ricochet(token, reservation);
        if tracing {
            telemetry::record_ricochet_rejection(telemetry::RicochetRejection::StateTransfer);
        }
        return result;
    }
    if tracing {
        let authority_error = direction_from_rotation(published.rotation).and_then(|direction| {
            direction_error_degrees(prepared.plan.reflected_vector(), direction)
        });
        telemetry::record_ricochet_publication(
            source,
            authority_error,
            true,
            prepared.plan,
            reservation.bounce_depth().saturating_add(1),
        );
    }
    result
}

unsafe fn spawn_ricochet_child(
    prepared: PreparedRicochet,
    parent: native::ProjectileRuntimeSample,
    spawn_origin: [f32; 3],
) -> Result<(*mut c_void, ShotContext, native::ProjectileRuntimeSample), telemetry::RicochetRejection>
{
    if parent.base_form_token == 0
        || parent.parent_cell_token == 0
        || parent.source_weapon_token == 0
        || parent.source_token == 0
    {
        return Err(telemetry::RicochetRejection::NativeAccess);
    }
    let base_form = parent.base_form_token as usize as *mut c_void;
    let source = parent.source_token as usize as *mut c_void;
    let weapon = parent.source_weapon_token as usize as *mut c_void;
    let cell = parent.parent_cell_token as usize as *mut c_void;
    let profile = unsafe { native::profile(base_form) };
    let capability = native::classify_profile(profile);
    if profile.form_token() != parent.base_form_token
        || !matches!(
            capability,
            ProjectileCapability::DiscreteHitscan | ProjectileCapability::DiscretePhysical
        )
    {
        return Err(telemetry::RicochetRejection::Capability);
    }
    let rotation = prepared.plan.launch_rotation();
    let context = ShotContext::new(
        SHOT_SEQUENCE
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1),
        prepared.launch.source_kind,
        parent.source_token,
        parent.source_weapon_token,
        profile,
        capability,
        spawn_origin,
        rotation,
        false,
        false,
        false,
    );
    let scope = adapter::NativePolicyScope::begin_child(context)
        .map_err(|_| telemetry::RicochetRejection::ChildPolicy)?;
    let child = unsafe {
        native::native_launch()(
            base_form,
            source,
            core::ptr::null_mut(),
            weapon,
            NiPoint3 {
                x: spawn_origin[0],
                y: spawn_origin[1],
                z: spawn_origin[2],
            },
            rotation[0],
            rotation[1],
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            0,
            0,
            0.0,
            0.0,
            cell,
        )
    };
    let policy = scope.finish();
    if child.is_null() {
        return Err(telemetry::RicochetRejection::ChildSpawn);
    }
    let policy_valid = match capability {
        ProjectileCapability::DiscreteHitscan => matches!(
            policy,
            adapter::PolicyResult::ForcedPhysical | adapter::PolicyResult::AlreadyPhysical
        ),
        ProjectileCapability::DiscretePhysical => !matches!(
            policy,
            adapter::PolicyResult::ContextRejected | adapter::PolicyResult::CapacityUnavailable
        ),
        _ => false,
    };
    if !policy_valid {
        unsafe { native::terminate_projectile(child) };
        return Err(telemetry::RicochetRejection::ChildPolicy);
    }
    let published = match unsafe {
        native::initialize_ricochet_child(
            child,
            parent,
            prepared.plan.speed_retention(),
            prepared.plan.damage_retention(),
        )
    } {
        Ok(published) => published,
        Err(reason) => {
            if telemetry::enabled() {
                telemetry::record_ricochet_child_state_rejection(reason);
            }
            unsafe { native::terminate_projectile(child) };
            return Err(telemetry::RicochetRejection::ChildState);
        }
    };
    Ok((child, context, published))
}

#[derive(Clone, Copy)]
struct PreparedRicochet {
    launch: ImpactObservation,
    runtime: native::ProjectileRuntimeSample,
    record: native::ImpactRecordSample,
    plan: RicochetPlan,
}

fn prepare_ricochet(
    projectile: *mut c_void,
    configured_energy: super::RicochetEnergyConfig,
    launch: Option<ImpactObservation>,
    runtime: Option<native::ProjectileRuntimeSample>,
    impacts: Option<native::ImpactListSample>,
    followup: Option<FollowupContact>,
) -> Result<PreparedRicochet, telemetry::RicochetRejection> {
    let launch = launch.ok_or(telemetry::RicochetRejection::Untracked)?;
    validate_ricochet_state(launch.ricochet_state, followup)?;
    if launch.selected_path != native::RuntimeFlightPath::Physical
        || !matches!(
            launch.capability,
            ProjectileCapability::DiscreteHitscan | ProjectileCapability::DiscretePhysical
        )
    {
        return Err(telemetry::RicochetRejection::Capability);
    }
    if launch.source_kind == SourceKind::Unknown
        || launch.always_hit
        || launch.ignore_gravity
        || launch.has_live_target
        || unsafe { native::vats_active() }
    {
        return Err(telemetry::RicochetRejection::LaunchContext);
    }
    if launch.has_explosion
        || launch.projectile_flags & (PROJECTILE_FLAG_EXPLOSION | PROJECTILE_FLAG_NATIVE_BOUNCE)
            != 0
    {
        return Err(telemetry::RicochetRejection::SpecialForm);
    }

    let runtime = runtime.ok_or(telemetry::RicochetRejection::InvalidGeometry)?;
    if runtime.has_impacted
        || runtime.impact_result != IMPACT_RESULT_DESTROY
        || runtime.rock_it_entry_token != 0
    {
        return Err(telemetry::RicochetRejection::SpecialOutcome);
    }
    if runtime.live_target_token != 0 {
        return Err(telemetry::RicochetRejection::LaunchContext);
    }
    let impacts = impacts.ok_or(telemetry::RicochetRejection::ImpactShape)?;
    if impacts.traversal_truncated || impacts.ready_count != 1 {
        return Err(telemetry::RicochetRejection::ImpactShape);
    }
    let record = impacts
        .first_ready
        .ok_or(telemetry::RicochetRejection::ImpactShape)?;
    if !runtime.is_finite() || !record.is_finite() {
        return Err(telemetry::RicochetRejection::InvalidGeometry);
    }
    let effective_speed = unsafe { native::effective_speed(projectile) };
    let plan = super::ricochet::response(
        record.raw_material,
        configured_energy,
        runtime.direction,
        record.normal,
        effective_speed,
        runtime.speed_multiplier,
        runtime.damage,
    )
    .map_err(map_response_error)?;
    if telemetry::enabled() {
        telemetry::record_ricochet_energy(launch.bounce_depth, plan.energy());
    }
    if let Some(depletion) = plan.energy().depletion() {
        return Err(map_energy_depletion(depletion));
    }
    Ok(PreparedRicochet {
        launch,
        runtime,
        record,
        plan,
    })
}

fn validate_ricochet_state(
    state: RicochetState,
    followup: Option<FollowupContact>,
) -> Result<(), telemetry::RicochetRejection> {
    match state {
        RicochetState::Available | RicochetState::Confirmed => Ok(()),
        RicochetState::Reserved => Err(telemetry::RicochetRejection::StateRace),
        RicochetState::Published | RicochetState::Probing
            if followup.is_some_and(FollowupContact::proves_outward_progress) =>
        {
            Ok(())
        }
        RicochetState::Published | RicochetState::Probing => {
            Err(telemetry::RicochetRejection::FirstStepPending)
        }
        RicochetState::Failed => Err(telemetry::RicochetRejection::OutboundFailed),
    }
}

fn map_response_error(error: ResponseError) -> telemetry::RicochetRejection {
    match error {
        ResponseError::UnsupportedMaterial => telemetry::RicochetRejection::UnsupportedMaterial,
        ResponseError::MaterialDisabled => telemetry::RicochetRejection::MaterialDisabled,
        ResponseError::InvalidGeometry => telemetry::RicochetRejection::InvalidGeometry,
        ResponseError::InvalidEnergy => telemetry::RicochetRejection::InvalidEnergy,
    }
}

fn map_energy_depletion(
    depletion: super::ricochet::EnergyDepletion,
) -> telemetry::RicochetRejection {
    match depletion {
        super::ricochet::EnergyDepletion::Speed => telemetry::RicochetRejection::EnergySpeed,
        super::ricochet::EnergyDepletion::Damage => telemetry::RicochetRejection::EnergyDamage,
        super::ricochet::EnergyDepletion::SpeedAndDamage => {
            telemetry::RicochetRejection::EnergySpeedAndDamage
        }
    }
}

fn validate_post_impact(
    prepared: PreparedRicochet,
    launch: Option<ImpactObservation>,
    post: Option<native::ProjectileRuntimeSample>,
    predecessor_result: u8,
) -> Result<(native::ProjectileRuntimeSample, SourceKind), telemetry::RicochetRejection> {
    if predecessor_result == 0 {
        return Err(telemetry::RicochetRejection::PredecessorResult);
    }
    let launch = launch.ok_or(telemetry::RicochetRejection::StateRace)?;
    if launch.generation != prepared.launch.generation
        || launch.ricochet_state != RicochetState::Reserved
    {
        return Err(telemetry::RicochetRejection::StateRace);
    }
    if launch.actor_hit {
        return Err(telemetry::RicochetRejection::ActorTarget);
    }
    let post = post.ok_or(telemetry::RicochetRejection::Postcondition)?;
    if !post.has_impacted
        || post.impact_list_empty
        || post.impact_result != IMPACT_RESULT_DESTROY
        || !runtime_values_unchanged(prepared.runtime, post)
    {
        return Err(telemetry::RicochetRejection::Postcondition);
    }
    Ok((post, launch.source_kind))
}

fn runtime_values_unchanged(
    before: native::ProjectileRuntimeSample,
    after: native::ProjectileRuntimeSample,
) -> bool {
    same_f32(before.direction, after.direction)
        && before.distance_travelled.to_bits() == after.distance_travelled.to_bits()
        && before.speed_multiplier.to_bits() == after.speed_multiplier.to_bits()
        && before.damage.to_bits() == after.damage.to_bits()
        && before.source_weapon_token == after.source_weapon_token
        && before.source_token == after.source_token
        && before.live_target_token == after.live_target_token
        && before.rock_it_entry_token == after.rock_it_entry_token
}

fn same_f32(left: [f32; 3], right: [f32; 3]) -> bool {
    left.into_iter()
        .zip(right)
        .all(|(left, right)| left.to_bits() == right.to_bits())
}

fn note_early_contact() {
    if telemetry::enabled() && ACTIVE_LAUNCHES.load(Ordering::Acquire) != 0 {
        telemetry::record_early_contact();
    }
    if telemetry::enabled() && ACTIVE_UPDATES.load(Ordering::Acquire) != 0 {
        telemetry::record_contact_during_update();
    }
}

unsafe extern "thiscall" fn movement_step_a_detour(projectile: *mut c_void, delta_seconds: f32) {
    note_call(&MOVEMENT_STEP_A_CALLS);
    let predecessor = MOVEMENT_STEP_A_HOOK
        .original()
        .unwrap_or_else(|_| native::native_movement_step());
    unsafe { observe_movement_step(projectile, delta_seconds, predecessor) };
}

unsafe extern "thiscall" fn movement_step_b_detour(projectile: *mut c_void, delta_seconds: f32) {
    note_call(&MOVEMENT_STEP_B_CALLS);
    let predecessor = MOVEMENT_STEP_B_HOOK
        .original()
        .unwrap_or_else(|_| native::native_movement_step());
    unsafe { observe_movement_step(projectile, delta_seconds, predecessor) };
}

unsafe fn observe_movement_step(
    projectile: *mut c_void,
    delta_seconds: f32,
    predecessor: native::MovementStepFn,
) {
    if !telemetry::enabled() {
        unsafe { predecessor(projectile, delta_seconds) };
        return;
    }

    let token = projectile as usize as u32;
    let probe = observations().and_then(|pool| pool.active_first_step(token));
    let pre = probe.and_then(|_| unsafe { native::runtime_sample(projectile) });
    unsafe { predecessor(projectile, delta_seconds) };

    let Some(probe) = probe else {
        return;
    };
    let post = unsafe { native::runtime_sample(projectile) };
    let authority_error = pre
        .and_then(|sample| direction_from_rotation(sample.rotation))
        .and_then(|direction| direction_error_degrees(probe.expected_direction, direction));
    let movement_error =
        post.and_then(|sample| direction_error_degrees(probe.expected_direction, sample.direction));
    telemetry::record_ricochet_movement_boundary(
        pre.map(|sample| sample.flight_target_token != 0),
        authority_error,
        movement_error,
    );
}

unsafe extern "thiscall" fn missile_update_detour(projectile: *mut c_void, delta_seconds: f32) {
    note_call(&MISSILE_UPDATE_CALLS);
    let predecessor = MISSILE_UPDATE_HOOK
        .original()
        .unwrap_or_else(|_| native::native_missile_update());
    let tracing = telemetry::enabled();
    if !tracing && !super::current_config().ricochet_enabled() {
        unsafe { predecessor(projectile, delta_seconds) };
        return;
    }

    let token = projectile as usize as u32;
    let observation = tracing
        .then(|| observations().and_then(|pool| pool.record_update(token)))
        .flatten();
    let first_step = observations().and_then(|pool| pool.reserve_first_step(token));
    let pre = (tracing || first_step.is_some())
        .then(|| unsafe { native::runtime_sample(projectile) })
        .flatten();
    let before_launch_return = ACTIVE_LAUNCHES.load(Ordering::Acquire) != 0;
    let capability = observation
        .map(|observation| observation.capability)
        .unwrap_or(super::ProjectileCapability::Unknown);
    let first =
        observation.is_some_and(|observation| observation.correlation == Correlation::First);
    if tracing {
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
    }

    let effective_speed =
        if tracing && observation.is_some() && pre.is_some() && helper_entries_ready() {
            unsafe { native::effective_speed(projectile) }
        } else {
            0.0
        };
    ACTIVE_UPDATES.fetch_add(1, Ordering::AcqRel);
    unsafe { predecessor(projectile, delta_seconds) };
    ACTIVE_UPDATES.fetch_sub(1, Ordering::AcqRel);

    let Some(pre) = pre else {
        if let Some(probe) = first_step {
            let committed =
                observations().is_some_and(|pool| pool.complete_first_step(token, probe, false));
            if tracing {
                telemetry::record_ricochet_first_step(
                    probe.source_kind,
                    probe.bounce_depth,
                    probe.raw_material,
                    None,
                    None,
                    committed,
                );
            }
        }
        if tracing {
            telemetry::record_invalid_value();
        }
        return;
    };
    if !tracing && first_step.is_none() {
        return;
    }
    let Some(post) = (unsafe { native::runtime_sample(projectile) }) else {
        if let Some(probe) = first_step {
            let authority_error = direction_from_rotation(pre.rotation)
                .and_then(|direction| direction_error_degrees(probe.expected_direction, direction));
            let committed =
                observations().is_some_and(|pool| pool.complete_first_step(token, probe, false));
            if tracing {
                telemetry::record_ricochet_first_step(
                    probe.source_kind,
                    probe.bounce_depth,
                    probe.raw_material,
                    authority_error,
                    None,
                    committed,
                );
            }
        }
        if tracing {
            telemetry::record_invalid_value();
        }
        return;
    };
    if let Some(probe) = first_step {
        let authority_error = direction_from_rotation(pre.rotation)
            .and_then(|direction| direction_error_degrees(probe.expected_direction, direction));
        let evidence = first_step_evidence(
            probe.expected_direction,
            probe.oriented_normal,
            pre.position,
            post.position,
            post.direction,
        );
        let confirmed = evidence.outcome == FirstStepOutcome::Outward;
        let committed =
            observations().is_some_and(|pool| pool.complete_first_step(token, probe, confirmed));
        if tracing {
            telemetry::record_ricochet_first_step(
                probe.source_kind,
                probe.bounce_depth,
                probe.raw_material,
                authority_error,
                Some(evidence),
                committed,
            );
        }
    }
    if tracing && observation.is_some() {
        telemetry::record_update_result(pre, post, delta_seconds, effective_speed);
    }
}

#[cfg(test)]
mod tests {
    use super::{RicochetAdmission, selected_flight_path, validate_ricochet_state};
    use crate::ballistics::ProjectileCapability;
    use crate::ballistics::adapter::PolicyResult;
    use crate::ballistics::native::{COMMON_IMPACT_TARGET, MUZZLE_FLASH_TARGET, RuntimeFlightPath};
    use crate::ballistics::pool::RicochetState;
    use crate::ballistics::ricochet::FollowupContact;
    use crate::ballistics::telemetry::RicochetRejection;

    #[test]
    fn outward_first_update_contact_is_energy_eligible() {
        let outward = FollowupContact {
            same_target: false,
            same_material: false,
            distance_progress: Some(40.0),
            point_separation: Some(40.0),
            outward_dot: Some(0.5),
        };
        for state in [RicochetState::Published, RicochetState::Probing] {
            assert_eq!(validate_ricochet_state(state, Some(outward)), Ok(()));
            for unproven in [
                FollowupContact {
                    distance_progress: Some(0.0),
                    ..outward
                },
                FollowupContact {
                    point_separation: Some(0.0),
                    ..outward
                },
                FollowupContact {
                    outward_dot: Some(-0.5),
                    ..outward
                },
            ] {
                assert_eq!(
                    validate_ricochet_state(state, Some(unproven)),
                    Err(RicochetRejection::FirstStepPending),
                );
            }
        }
    }

    #[test]
    fn weapon_launch_owner_does_not_gate_child_ricochet() {
        for launch_predecessor in [0x009B_CA60, 0x0A7D_E850, 0x10CE_11B4] {
            assert!(
                RicochetAdmission {
                    launch_predecessor,
                    common_impact_predecessor: COMMON_IMPACT_TARGET,
                    muzzle_flash_predecessor: MUZZLE_FLASH_TARGET,
                    helper_entries_ready: true,
                }
                .mutation_admitted()
            );
        }
    }

    #[test]
    fn critical_child_seams_still_fail_closed() {
        let native = RicochetAdmission {
            launch_predecessor: 0x0A7D_E850,
            common_impact_predecessor: COMMON_IMPACT_TARGET,
            muzzle_flash_predecessor: MUZZLE_FLASH_TARGET,
            helper_entries_ready: true,
        };
        assert!(native.mutation_admitted());
        assert!(
            !RicochetAdmission {
                common_impact_predecessor: 0x0BAD_F00D,
                ..native
            }
            .mutation_admitted()
        );
        assert!(
            !RicochetAdmission {
                muzzle_flash_predecessor: 0x0BAD_F00D,
                ..native
            }
            .mutation_admitted()
        );
    }

    #[test]
    fn unavailable_helper_entry_keeps_ricochet_observe_only() {
        let admitted = RicochetAdmission {
            launch_predecessor: 0x009B_CA60,
            common_impact_predecessor: COMMON_IMPACT_TARGET,
            muzzle_flash_predecessor: MUZZLE_FLASH_TARGET,
            helper_entries_ready: true,
        };
        assert!(admitted.mutation_admitted());
        assert!(
            !RicochetAdmission {
                helper_entries_ready: false,
                ..admitted
            }
            .mutation_admitted()
        );
    }

    #[test]
    fn admission_has_no_body_difference_input_to_regress() {
        // The 2026-08-24 regression came from gating ricochet on interior-body
        // fingerprints. The struct must not carry such an input at all; this
        // compile-level guarantee is pinned by constructing every field
        // explicitly and asserting admission depends only on seams + entries.
        let full = RicochetAdmission {
            launch_predecessor: 0x009B_CA60,
            common_impact_predecessor: COMMON_IMPACT_TARGET,
            muzzle_flash_predecessor: MUZZLE_FLASH_TARGET,
            helper_entries_ready: true,
        };
        assert!(full.mutation_admitted());
        assert_eq!(
            full.mutation_admitted(),
            full.common_impact_supported() && full.child_presentation_supported()
        );
    }

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
