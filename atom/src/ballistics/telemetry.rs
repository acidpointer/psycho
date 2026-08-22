//! Bounded, allocation-free Ballistics observation telemetry.
//!
//! Native wrappers perform QPC queries and relaxed saturating increments only
//! while tracing is enabled. Snapshot formatting and logging happen later on
//! the MCM event callback, never inside a combat hook.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use libpsycho::os::windows::winapi::{get_current_thread_id, query_performance_counter};

use super::adapter::PolicyResult;
use super::native::{
    ChildInitializationError, ImpactListSample, ProjectileRuntimeSample, RuntimeFlightPath,
    RuntimePolicyMarkers,
};
use super::pool::ImpactObservation;
use super::ricochet::{
    self, CANONICAL_MATERIAL_COUNT, ContinuationEnergy, FirstStepEvidence, FirstStepOutcome,
    FollowupContact, HARD_MATERIAL_COUNT, RicochetPlan,
};
use super::{ProjectileCapability, SourceKind};

const IMPACT_BUCKET_US: [u32; 10] = [
    250, 500, 1_000, 2_000, 4_000, 8_000, 16_000, 33_000, 100_000, 500_000,
];
const IMPACT_BUCKET_COUNT: usize = IMPACT_BUCKET_US.len() + 1;
const THREAD_CAPACITY: usize = 8;
const MAX_INTERVAL_US: u32 = 30_000_000;
const UPDATE_FRAME_US: [u32; 6] = [4_000, 8_000, 16_667, 33_333, 50_000, 100_000];
const UPDATE_FRAME_BUCKET_COUNT: usize = UPDATE_FRAME_US.len() + 1;
const STEP_ERROR_PERCENT: [f32; 5] = [1.0, 5.0, 10.0, 25.0, 50.0];
const STEP_ERROR_BUCKET_COUNT: usize = STEP_ERROR_PERCENT.len() + 1;
const UPDATE_PATH_COUNT: usize = 5;
const RUNTIME_MARKER_COUNT: usize = 4;
const COMMON_IMPACT_LIST_SHAPE_COUNT: usize = 4;
const COMMON_IMPACT_RESULT_COUNT: usize = 2;
const GRAZING_ANGLE_UPPER_DEGREES: [u8; 10] = [5, 10, 15, 20, 30, 45, 60, 75, 85, 90];
const GRAZING_ANGLE_BUCKET_COUNT: usize = GRAZING_ANGLE_UPPER_DEGREES.len() + 1;
const FOLLOWUP_DISTANCE_UPPER_UNITS: [f32; 5] = [0.01, 0.1, 1.0, 8.0, 32.0];
const FOLLOWUP_DISTANCE_BUCKET_COUNT: usize = FOLLOWUP_DISTANCE_UPPER_UNITS.len() + 1;
const DIRECTION_ERROR_UPPER_DEGREES: [f32; 6] = [0.5, 1.0, 5.0, 15.0, 45.0, 90.0];
const DIRECTION_ERROR_BUCKET_COUNT: usize = DIRECTION_ERROR_UPPER_DEGREES.len() + 1;
const RICOCHET_SPEED_UPPER: [f32; 5] = [6_400.0, 10_000.0, 20_000.0, 40_000.0, 80_000.0];
const RICOCHET_SPEED_BUCKET_COUNT: usize = RICOCHET_SPEED_UPPER.len() + 1;
const RICOCHET_DAMAGE_UPPER: [f32; 6] = [6.0, 10.0, 20.0, 40.0, 80.0, 160.0];
const RICOCHET_DAMAGE_BUCKET_COUNT: usize = RICOCHET_DAMAGE_UPPER.len() + 1;
const RICOCHET_DEPTH_UPPER: [u32; 5] = [1, 2, 3, 4, 8];
const RICOCHET_DEPTH_BUCKET_COUNT: usize = RICOCHET_DEPTH_UPPER.len() + 1;

static ENABLED: AtomicBool = AtomicBool::new(false);
static MAX_INTERVAL_TICKS: AtomicU32 = AtomicU32::new(0);
static IMPACT_BUCKET_TICKS: [AtomicU32; IMPACT_BUCKET_US.len()] =
    [const { AtomicU32::new(0) }; IMPACT_BUCKET_US.len()];
static LAUNCHES: AtomicU32 = AtomicU32::new(0);
static LAUNCHES_BY_SOURCE: [AtomicU32; SourceKind::COUNT] =
    [const { AtomicU32::new(0) }; SourceKind::COUNT];
static LAUNCHES_BY_CAPABILITY: [AtomicU32; ProjectileCapability::COUNT] =
    [const { AtomicU32::new(0) }; ProjectileCapability::COUNT];
static PROJECTILE_COUNTS: [AtomicU32; 5] = [const { AtomicU32::new(0) }; 5];
static ACTOR_HITS: AtomicU32 = AtomicU32::new(0);
static WORLD_IMPACTS: AtomicU32 = AtomicU32::new(0);
static HIT_COMMITS: AtomicU32 = AtomicU32::new(0);
static FIRST_CONTACTS: AtomicU32 = AtomicU32::new(0);
static REPEATED_CONTACTS: AtomicU32 = AtomicU32::new(0);
static UNTRACKED_CONTACTS: AtomicU32 = AtomicU32::new(0);
static DUPLICATE_HIT_BUILDS: AtomicU32 = AtomicU32::new(0);
static UNTRACKED_HIT_BUILDS: AtomicU32 = AtomicU32::new(0);
static EARLY_CONTACTS: AtomicU32 = AtomicU32::new(0);
static INVALID_VALUES: AtomicU32 = AtomicU32::new(0);
static POOL_OVERFLOWS: AtomicU32 = AtomicU32::new(0);
static EXPIRED_MISSES: AtomicU32 = AtomicU32::new(0);
static STALE_GENERATIONS: AtomicU32 = AtomicU32::new(0);
static UNCLASSIFIED_FALLBACKS: AtomicU32 = AtomicU32::new(0);
static POLICY_CANDIDATES: AtomicU32 = AtomicU32::new(0);
static POLICY_FORCED: AtomicU32 = AtomicU32::new(0);
static POLICY_ALREADY_PHYSICAL: AtomicU32 = AtomicU32::new(0);
static POLICY_CONTEXT_REJECTS: AtomicU32 = AtomicU32::new(0);
static POLICY_MISSES: AtomicU32 = AtomicU32::new(0);
static POLICY_CAPACITY_FAILURES: AtomicU32 = AtomicU32::new(0);
static IMPACT_LATENCY: [AtomicU32; IMPACT_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; IMPACT_BUCKET_COUNT];
static THREAD_IDS: [AtomicU32; THREAD_CAPACITY] = [const { AtomicU32::new(0) }; THREAD_CAPACITY];
static THREAD_OVERFLOW: AtomicU32 = AtomicU32::new(0);
static MISSILE_UPDATES: AtomicU32 = AtomicU32::new(0);
static TRACKED_UPDATES: AtomicU32 = AtomicU32::new(0);
static FIRST_UPDATES: AtomicU32 = AtomicU32::new(0);
static EARLY_UPDATES: AtomicU32 = AtomicU32::new(0);
static CONTACTS_DURING_UPDATE: AtomicU32 = AtomicU32::new(0);
static PROGRESSIVE_UPDATES: AtomicU32 = AtomicU32::new(0);
static STATIONARY_UPDATES: AtomicU32 = AtomicU32::new(0);
static IMPACTED_UPDATES: AtomicU32 = AtomicU32::new(0);
static UPDATE_PATHS: [AtomicU32; UPDATE_PATH_COUNT] =
    [const { AtomicU32::new(0) }; UPDATE_PATH_COUNT];
static RUNTIME_MARKERS: [AtomicU32; RUNTIME_MARKER_COUNT] =
    [const { AtomicU32::new(0) }; RUNTIME_MARKER_COUNT];
static UPDATE_FRAME_TIME: [AtomicU32; UPDATE_FRAME_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; UPDATE_FRAME_BUCKET_COUNT];
static STEP_ERROR: [AtomicU32; STEP_ERROR_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; STEP_ERROR_BUCKET_COUNT];
static COMMON_IMPACT_CALLS: AtomicU32 = AtomicU32::new(0);
static COMMON_IMPACT_TRACKED: AtomicU32 = AtomicU32::new(0);
static COMMON_IMPACT_PHYSICAL: AtomicU32 = AtomicU32::new(0);
static COMMON_IMPACT_ACTOR: AtomicU32 = AtomicU32::new(0);
static COMMON_IMPACT_LIST_TRUNCATED: AtomicU32 = AtomicU32::new(0);
static COMMON_IMPACT_UNKNOWN_MATERIAL: AtomicU32 = AtomicU32::new(0);
static COMMON_IMPACT_INVALID_GEOMETRY: AtomicU32 = AtomicU32::new(0);
static COMMON_IMPACT_MEASURABLE_HARD_WORLD: AtomicU32 = AtomicU32::new(0);
static COMMON_IMPACTS_BY_SOURCE: [AtomicU32; SourceKind::COUNT] =
    [const { AtomicU32::new(0) }; SourceKind::COUNT];
static COMMON_IMPACT_LIST_SHAPES: [AtomicU32; COMMON_IMPACT_LIST_SHAPE_COUNT] =
    [const { AtomicU32::new(0) }; COMMON_IMPACT_LIST_SHAPE_COUNT];
static COMMON_IMPACT_RESULTS: [AtomicU32; COMMON_IMPACT_RESULT_COUNT] =
    [const { AtomicU32::new(0) }; COMMON_IMPACT_RESULT_COUNT];
static COMMON_IMPACT_MATERIALS: [AtomicU32; CANONICAL_MATERIAL_COUNT] =
    [const { AtomicU32::new(0) }; CANONICAL_MATERIAL_COUNT];
static COMMON_IMPACT_HARD_MATERIALS: [AtomicU32; HARD_MATERIAL_COUNT] =
    [const { AtomicU32::new(0) }; HARD_MATERIAL_COUNT];
static COMMON_IMPACT_GRAZING_ANGLES: [AtomicU32; GRAZING_ANGLE_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; GRAZING_ANGLE_BUCKET_COUNT];
static RICOCHET_CANDIDATES: AtomicU32 = AtomicU32::new(0);
static RICOCHET_PUBLICATIONS: AtomicU32 = AtomicU32::new(0);
static RICOCHET_CANDIDATES_BY_MATERIAL: [AtomicU32; CANONICAL_MATERIAL_COUNT] =
    [const { AtomicU32::new(0) }; CANONICAL_MATERIAL_COUNT];
static RICOCHET_PUBLICATIONS_BY_MATERIAL: [AtomicU32; CANONICAL_MATERIAL_COUNT] =
    [const { AtomicU32::new(0) }; CANONICAL_MATERIAL_COUNT];
static RICOCHET_CONFIRMED_BY_MATERIAL: [AtomicU32; CANONICAL_MATERIAL_COUNT] =
    [const { AtomicU32::new(0) }; CANONICAL_MATERIAL_COUNT];
static RICOCHET_CANDIDATES_BY_ANGLE: [AtomicU32; GRAZING_ANGLE_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; GRAZING_ANGLE_BUCKET_COUNT];
static RICOCHET_PUBLICATIONS_BY_ANGLE: [AtomicU32; GRAZING_ANGLE_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; GRAZING_ANGLE_BUCKET_COUNT];
static RICOCHET_CANDIDATES_BY_DEPTH: [AtomicU32; RICOCHET_DEPTH_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; RICOCHET_DEPTH_BUCKET_COUNT];
static RICOCHET_PUBLICATIONS_BY_DEPTH: [AtomicU32; RICOCHET_DEPTH_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; RICOCHET_DEPTH_BUCKET_COUNT];
static RICOCHET_CONFIRMED_BY_DEPTH: [AtomicU32; RICOCHET_DEPTH_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; RICOCHET_DEPTH_BUCKET_COUNT];
static RICOCHET_PUBLICATION_INVALID: AtomicU32 = AtomicU32::new(0);
static RICOCHET_MOVEMENT_BOUNDARIES: AtomicU32 = AtomicU32::new(0);
static RICOCHET_MOVEMENT_TARGET_STATUS: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];
static RICOCHET_FIRST_STEPS: AtomicU32 = AtomicU32::new(0);
static RICOCHET_FIRST_STEP_OUTWARD: AtomicU32 = AtomicU32::new(0);
static RICOCHET_FIRST_STEP_NON_OUTWARD: AtomicU32 = AtomicU32::new(0);
static RICOCHET_FIRST_STEP_STATIONARY: AtomicU32 = AtomicU32::new(0);
static RICOCHET_FIRST_STEP_INVALID: AtomicU32 = AtomicU32::new(0);
static RICOCHET_FIRST_STEP_STATE_RACES: AtomicU32 = AtomicU32::new(0);
static RICOCHET_PENDING_LOST: AtomicU32 = AtomicU32::new(0);
static RICOCHET_PUBLICATION_AUTHORITY_ERROR: [AtomicU32; DIRECTION_ERROR_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; DIRECTION_ERROR_BUCKET_COUNT];
static RICOCHET_PRE_MOVEMENT_AUTHORITY_ERROR: [AtomicU32; DIRECTION_ERROR_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; DIRECTION_ERROR_BUCKET_COUNT];
static RICOCHET_IMMEDIATE_MOVEMENT_ERROR: [AtomicU32; DIRECTION_ERROR_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; DIRECTION_ERROR_BUCKET_COUNT];
static RICOCHET_FIRST_STEP_AUTHORITY_ERROR: [AtomicU32; DIRECTION_ERROR_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; DIRECTION_ERROR_BUCKET_COUNT];
static RICOCHET_FIRST_STEP_MOVEMENT_ERROR: [AtomicU32; DIRECTION_ERROR_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; DIRECTION_ERROR_BUCKET_COUNT];
static RICOCHET_FIRST_STEP_POSITION_ERROR: [AtomicU32; DIRECTION_ERROR_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; DIRECTION_ERROR_BUCKET_COUNT];
static RICOCHET_POST_BOUNCE_CONTACTS: AtomicU32 = AtomicU32::new(0);
static RICOCHET_POST_BOUNCE_ACTOR_HITS: AtomicU32 = AtomicU32::new(0);
static RICOCHET_FOLLOWUP_SAME_TARGET: AtomicU32 = AtomicU32::new(0);
static RICOCHET_FOLLOWUP_SAME_MATERIAL: AtomicU32 = AtomicU32::new(0);
static RICOCHET_FOLLOWUP_OUTWARD: AtomicU32 = AtomicU32::new(0);
static RICOCHET_FOLLOWUP_NON_OUTWARD: AtomicU32 = AtomicU32::new(0);
static RICOCHET_FOLLOWUP_INVALID_DIRECTION: AtomicU32 = AtomicU32::new(0);
static RICOCHET_FOLLOWUP_INVALID_DISTANCE: AtomicU32 = AtomicU32::new(0);
static RICOCHET_FOLLOWUP_INVALID_POINT: AtomicU32 = AtomicU32::new(0);
static RICOCHET_FOLLOWUP_DISTANCE: [AtomicU32; FOLLOWUP_DISTANCE_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; FOLLOWUP_DISTANCE_BUCKET_COUNT];
static RICOCHET_FOLLOWUP_POINT_SEPARATION: [AtomicU32; FOLLOWUP_DISTANCE_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; FOLLOWUP_DISTANCE_BUCKET_COUNT];
static RICOCHET_PUBLICATIONS_BY_SOURCE: [AtomicU32; SourceKind::COUNT] =
    [const { AtomicU32::new(0) }; SourceKind::COUNT];
static RICOCHET_CONFIRMED_BY_SOURCE: [AtomicU32; SourceKind::COUNT] =
    [const { AtomicU32::new(0) }; SourceKind::COUNT];
static RICOCHET_REJECTIONS: [AtomicU32; RicochetRejection::COUNT] =
    [const { AtomicU32::new(0) }; RicochetRejection::COUNT];
static RICOCHET_CHILD_STATE_REJECTIONS: [AtomicU32; ChildInitializationError::COUNT] =
    [const { AtomicU32::new(0) }; ChildInitializationError::COUNT];
static RICOCHET_CURRENT_SPEED: [AtomicU32; RICOCHET_SPEED_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; RICOCHET_SPEED_BUCKET_COUNT];
static RICOCHET_NEXT_SPEED: [AtomicU32; RICOCHET_SPEED_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; RICOCHET_SPEED_BUCKET_COUNT];
static RICOCHET_CURRENT_DAMAGE: [AtomicU32; RICOCHET_DAMAGE_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; RICOCHET_DAMAGE_BUCKET_COUNT];
static RICOCHET_NEXT_DAMAGE: [AtomicU32; RICOCHET_DAMAGE_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; RICOCHET_DAMAGE_BUCKET_COUNT];
static RICOCHET_PARENT_DEPTH: [AtomicU32; RICOCHET_DEPTH_BUCKET_COUNT] =
    [const { AtomicU32::new(0) }; RICOCHET_DEPTH_BUCKET_COUNT];

/// Stable reason why one impact retained its complete native result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum RicochetRejection {
    Disabled = 0,
    CriticalAdmission = 1,
    Untracked = 2,
    Capability = 3,
    LaunchContext = 4,
    SpecialForm = 5,
    SpecialOutcome = 6,
    ImpactShape = 7,
    UnsupportedMaterial = 8,
    InvalidGeometry = 9,
    InvalidEnergy = 10,
    EnergySpeed = 11,
    EnergyDamage = 12,
    EnergySpeedAndDamage = 13,
    FirstStepPending = 14,
    OutboundFailed = 15,
    ActorTarget = 16,
    PredecessorResult = 17,
    Postcondition = 18,
    StateRace = 19,
    NativeAccess = 20,
    Clearance = 21,
    ChildSpawn = 22,
    ChildPolicy = 23,
    ChildState = 24,
    StateTransfer = 25,
    MaterialDisabled = 26,
}

impl RicochetRejection {
    pub(crate) const COUNT: usize = 27;
}

/// Value-only sample captured around one unchanged native impact traversal.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct CommonImpactObservation {
    pub(crate) launch: Option<ImpactObservation>,
    pub(crate) runtime: Option<ProjectileRuntimeSample>,
    pub(crate) impacts: Option<ImpactListSample>,
    pub(crate) predecessor_result: u8,
}

/// Point-in-time copy of Ballistics observation counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BallisticsTelemetrySnapshot {
    launches: u32,
    launches_by_source: [u32; SourceKind::COUNT],
    launches_by_capability: [u32; ProjectileCapability::COUNT],
    projectile_counts: [u32; 5],
    actor_hits: u32,
    world_impacts: u32,
    hit_commits: u32,
    first_contacts: u32,
    repeated_contacts: u32,
    untracked_contacts: u32,
    duplicate_hit_builds: u32,
    untracked_hit_builds: u32,
    early_contacts: u32,
    invalid_values: u32,
    pool_overflows: u32,
    expired_misses: u32,
    stale_generations: u32,
    unclassified_fallbacks: u32,
    policy_candidates: u32,
    policy_forced: u32,
    policy_already_physical: u32,
    policy_context_rejects: u32,
    policy_misses: u32,
    policy_capacity_failures: u32,
    impact_latency: [u32; IMPACT_BUCKET_COUNT],
    thread_ids: [u32; THREAD_CAPACITY],
    thread_overflow: u32,
    missile_updates: u32,
    tracked_updates: u32,
    first_updates: u32,
    early_updates: u32,
    contacts_during_update: u32,
    progressive_updates: u32,
    stationary_updates: u32,
    impacted_updates: u32,
    update_paths: [u32; UPDATE_PATH_COUNT],
    runtime_markers: [u32; RUNTIME_MARKER_COUNT],
    update_frame_time: [u32; UPDATE_FRAME_BUCKET_COUNT],
    step_error: [u32; STEP_ERROR_BUCKET_COUNT],
    common_impact_calls: u32,
    common_impact_tracked: u32,
    common_impact_physical: u32,
    common_impact_actor: u32,
    common_impact_list_truncated: u32,
    common_impact_unknown_material: u32,
    common_impact_invalid_geometry: u32,
    common_impact_measurable_hard_world: u32,
    common_impacts_by_source: [u32; SourceKind::COUNT],
    common_impact_list_shapes: [u32; COMMON_IMPACT_LIST_SHAPE_COUNT],
    common_impact_results: [u32; COMMON_IMPACT_RESULT_COUNT],
    common_impact_materials: [u32; CANONICAL_MATERIAL_COUNT],
    common_impact_hard_materials: [u32; HARD_MATERIAL_COUNT],
    common_impact_grazing_angles: [u32; GRAZING_ANGLE_BUCKET_COUNT],
    ricochet_candidates: u32,
    ricochet_publications: u32,
    ricochet_candidates_by_material: [u32; CANONICAL_MATERIAL_COUNT],
    ricochet_publications_by_material: [u32; CANONICAL_MATERIAL_COUNT],
    ricochet_confirmed_by_material: [u32; CANONICAL_MATERIAL_COUNT],
    ricochet_candidates_by_angle: [u32; GRAZING_ANGLE_BUCKET_COUNT],
    ricochet_publications_by_angle: [u32; GRAZING_ANGLE_BUCKET_COUNT],
    ricochet_candidates_by_depth: [u32; RICOCHET_DEPTH_BUCKET_COUNT],
    ricochet_publications_by_depth: [u32; RICOCHET_DEPTH_BUCKET_COUNT],
    ricochet_confirmed_by_depth: [u32; RICOCHET_DEPTH_BUCKET_COUNT],
    ricochet_current_speed: [u32; RICOCHET_SPEED_BUCKET_COUNT],
    ricochet_next_speed: [u32; RICOCHET_SPEED_BUCKET_COUNT],
    ricochet_current_damage: [u32; RICOCHET_DAMAGE_BUCKET_COUNT],
    ricochet_next_damage: [u32; RICOCHET_DAMAGE_BUCKET_COUNT],
    ricochet_parent_depth: [u32; RICOCHET_DEPTH_BUCKET_COUNT],
    ricochet_child_state_rejections: [u32; ChildInitializationError::COUNT],
    ricochet_publication_invalid: u32,
    ricochet_movement_boundaries: u32,
    ricochet_movement_target_status: [u32; 3],
    ricochet_first_steps: u32,
    ricochet_first_step_outward: u32,
    ricochet_first_step_non_outward: u32,
    ricochet_first_step_stationary: u32,
    ricochet_first_step_invalid: u32,
    ricochet_first_step_state_races: u32,
    ricochet_pending_lost: u32,
    ricochet_publication_authority_error: [u32; DIRECTION_ERROR_BUCKET_COUNT],
    ricochet_pre_movement_authority_error: [u32; DIRECTION_ERROR_BUCKET_COUNT],
    ricochet_immediate_movement_error: [u32; DIRECTION_ERROR_BUCKET_COUNT],
    ricochet_first_step_authority_error: [u32; DIRECTION_ERROR_BUCKET_COUNT],
    ricochet_first_step_movement_error: [u32; DIRECTION_ERROR_BUCKET_COUNT],
    ricochet_first_step_position_error: [u32; DIRECTION_ERROR_BUCKET_COUNT],
    ricochet_post_bounce_contacts: u32,
    ricochet_post_bounce_actor_hits: u32,
    ricochet_followup_same_target: u32,
    ricochet_followup_same_material: u32,
    ricochet_followup_outward: u32,
    ricochet_followup_non_outward: u32,
    ricochet_followup_invalid_direction: u32,
    ricochet_followup_invalid_distance: u32,
    ricochet_followup_invalid_point: u32,
    ricochet_followup_distance: [u32; FOLLOWUP_DISTANCE_BUCKET_COUNT],
    ricochet_followup_point_separation: [u32; FOLLOWUP_DISTANCE_BUCKET_COUNT],
    ricochet_publications_by_source: [u32; SourceKind::COUNT],
    ricochet_confirmed_by_source: [u32; SourceKind::COUNT],
    ricochet_rejections: [u32; RicochetRejection::COUNT],
}

impl BallisticsTelemetrySnapshot {
    /// Return inclusive launch-to-impact bucket bounds in microseconds.
    pub const fn impact_bucket_upper_microseconds() -> &'static [u32; 10] {
        &IMPACT_BUCKET_US
    }

    /// Return all native launches observed at Atom's canonical callsite.
    pub const fn launches(self) -> u32 {
        self.launches
    }

    /// Return launch counts indexed by [`SourceKind`] discriminant.
    pub const fn launches_by_source(self) -> [u32; SourceKind::COUNT] {
        self.launches_by_source
    }

    /// Return launch counts indexed by [`ProjectileCapability`] discriminant.
    pub const fn launches_by_capability(self) -> [u32; ProjectileCapability::COUNT] {
        self.launches_by_capability
    }

    /// Return count-call samples for `0`, `1`, `2..=4`, `5..=8`, and `9+`.
    pub const fn projectile_counts(self) -> [u32; 5] {
        self.projectile_counts
    }

    /// Return correlated actor hit-data constructions.
    pub const fn actor_hits(self) -> u32 {
        self.actor_hits
    }

    /// Return correlated contacts without an actor hit construction.
    pub const fn world_impacts(self) -> u32 {
        self.world_impacts
    }

    /// Return calls to native `Actor::ApplyHit` from projectile traversal.
    pub const fn hit_commits(self) -> u32 {
        self.hit_commits
    }

    /// Return first correlated native contact callbacks.
    pub const fn first_contacts(self) -> u32 {
        self.first_contacts
    }

    /// Return later contact callbacks for an already-correlated projectile.
    pub const fn repeated_contacts(self) -> u32 {
        self.repeated_contacts
    }

    /// Return contact callbacks not launched through the observed weapon seam.
    pub const fn untracked_contacts(self) -> u32 {
        self.untracked_contacts
    }

    /// Return repeated actor hit-data construction callbacks.
    pub const fn duplicate_hit_builds(self) -> u32 {
        self.duplicate_hit_builds
    }

    /// Return actor hit-data callbacks without an observed launch.
    pub const fn untracked_hit_builds(self) -> u32 {
        self.untracked_hit_builds
    }

    /// Return repeated hit/contact observations for the same launch.
    pub const fn duplicate_correlations(self) -> u32 {
        self.repeated_contacts
            .saturating_add(self.duplicate_hit_builds)
    }

    /// Return callbacks whose projectile was absent from the bounded pool.
    pub const fn missing_correlations(self) -> u32 {
        self.untracked_contacts
            .saturating_add(self.untracked_hit_builds)
    }

    /// Return contacts observed while a launch predecessor was still active.
    pub const fn early_contacts(self) -> u32 {
        self.early_contacts
    }

    /// Return rejected clock, form, or numeric observations.
    pub const fn invalid_values(self) -> u32 {
        self.invalid_values
    }

    /// Return launches omitted because the fixed observation pool was full.
    pub const fn pool_overflows(self) -> u32 {
        self.pool_overflows
    }

    /// Return live observations reclaimed without a correlated contact.
    pub const fn expired_misses(self) -> u32 {
        self.expired_misses
    }

    /// Return same-address launches that superseded an older generation.
    pub const fn stale_generations(self) -> u32 {
        self.stale_generations
    }

    /// Return launches whose runtime address reused an existing live slot.
    pub const fn address_reuses(self) -> u32 {
        self.stale_generations
    }

    /// Return projectile families deliberately retained as native unknowns.
    pub const fn unclassified_fallbacks(self) -> u32 {
        self.unclassified_fallbacks
    }

    /// Return discrete hitscan rounds offered to native flight policy.
    pub const fn policy_candidates(self) -> u32 {
        self.policy_candidates
    }

    /// Return rounds for which Atom selected FNV's native physical policy.
    pub const fn policy_forced(self) -> u32 {
        self.policy_forced
    }

    /// Return rounds already made physical by an earlier hook owner.
    pub const fn policy_already_physical(self) -> u32 {
        self.policy_already_physical
    }

    /// Return candidates retained as native for special launch context.
    pub const fn policy_context_rejects(self) -> u32 {
        self.policy_context_rejects
    }

    /// Return eligible launches that did not reach the audited policy callsite.
    pub const fn policy_misses(self) -> u32 {
        self.policy_misses
    }

    /// Return candidates retained as native because all policy slots were busy.
    pub const fn policy_capacity_failures(self) -> u32 {
        self.policy_capacity_failures
    }

    /// Return launch-to-first-contact histogram counts.
    pub const fn impact_latency(self) -> [u32; IMPACT_BUCKET_COUNT] {
        self.impact_latency
    }

    /// Return the bounded set of callback thread identifiers; zero is empty.
    pub const fn thread_ids(self) -> [u32; THREAD_CAPACITY] {
        self.thread_ids
    }

    /// Return callbacks seen after the thread-identity set filled.
    pub const fn thread_overflow(self) -> u32 {
        self.thread_overflow
    }

    /// Return all MissileProjectile subtype-update callbacks.
    pub const fn missile_updates(self) -> u32 {
        self.missile_updates
    }

    /// Return update callbacks correlated with the canonical launch seam.
    pub const fn tracked_updates(self) -> u32 {
        self.tracked_updates
    }

    /// Return projectiles observed at their first subtype update.
    pub const fn first_updates(self) -> u32 {
        self.first_updates
    }

    /// Return subtype updates entered before a launch predecessor returned.
    pub const fn early_updates(self) -> u32 {
        self.early_updates
    }

    /// Return contacts entered while a subtype update predecessor was active.
    pub const fn contacts_during_update(self) -> u32 {
        self.contacts_during_update
    }

    /// Return tracked updates whose native position changed.
    pub const fn progressive_updates(self) -> u32 {
        self.progressive_updates
    }

    /// Return tracked updates whose native position did not change.
    pub const fn stationary_updates(self) -> u32 {
        self.stationary_updates
    }

    /// Return tracked updates ending with impact state or impact-list data.
    pub const fn impacted_updates(self) -> u32 {
        self.impacted_updates
    }

    /// Return form/selected-launch path pairs: HH, HP, PP, PH, and other.
    pub const fn update_paths(self) -> [u32; UPDATE_PATH_COUNT] {
        self.update_paths
    }

    /// Return live hitscan-only, physical-only, both, and neither markers.
    pub const fn runtime_markers(self) -> [u32; RUNTIME_MARKER_COUNT] {
        self.runtime_markers
    }

    /// Return frame-delta counts for 4, 8, 16.667, 33.333, 50, 100+ ms.
    pub const fn update_frame_time(self) -> [u32; UPDATE_FRAME_BUCKET_COUNT] {
        self.update_frame_time
    }

    /// Return native displacement error buckets at 1, 5, 10, 25, and 50+%.
    pub const fn step_error(self) -> [u32; STEP_ERROR_BUCKET_COUNT] {
        self.step_error
    }

    /// Return inclusive grazing-angle histogram bounds in degrees.
    pub const fn grazing_angle_upper_degrees() -> &'static [u8; 10] {
        &GRAZING_ANGLE_UPPER_DEGREES
    }

    /// Return all calls through the verified common-impact seam.
    pub const fn common_impact_calls(self) -> u32 {
        self.common_impact_calls
    }

    /// Return common-impact calls correlated with Atom's canonical launch seam.
    pub const fn common_impact_tracked(self) -> u32 {
        self.common_impact_tracked
    }

    /// Return correlated calls whose launch-time path was physical.
    pub const fn common_impact_physical(self) -> u32 {
        self.common_impact_physical
    }

    /// Return tracked calls whose predecessor built actor hit data.
    pub const fn common_impact_actor(self) -> u32 {
        self.common_impact_actor
    }

    /// Return impact lists that exceeded the bounded observation walk.
    pub const fn common_impact_list_truncated(self) -> u32 {
        self.common_impact_list_truncated
    }

    /// Return physical records whose raw material was outside FNV's proven map.
    pub const fn common_impact_unknown_material(self) -> u32 {
        self.common_impact_unknown_material
    }

    /// Return hard-world records with invalid direction or normal geometry.
    pub const fn common_impact_invalid_geometry(self) -> u32 {
        self.common_impact_invalid_geometry
    }

    /// Return single-record hard-world contacts with measured incidence.
    pub const fn common_impact_measurable_hard_world(self) -> u32 {
        self.common_impact_measurable_hard_world
    }

    /// Return tracked common-impact calls indexed by [`SourceKind`].
    pub const fn common_impacts_by_source(self) -> [u32; SourceKind::COUNT] {
        self.common_impacts_by_source
    }

    /// Return missing, empty, single-ready, and multiple-ready list counts.
    pub const fn common_impact_list_shapes(self) -> [u32; COMMON_IMPACT_LIST_SHAPE_COUNT] {
        self.common_impact_list_shapes
    }

    /// Return zero and nonzero native predecessor result counts.
    pub const fn common_impact_results(self) -> [u32; COMMON_IMPACT_RESULT_COUNT] {
        self.common_impact_results
    }

    /// Return physical record counts indexed by canonical material slot.
    pub const fn common_impact_materials(self) -> [u32; CANONICAL_MATERIAL_COUNT] {
        self.common_impact_materials
    }

    /// Return physical stone, metal, and hollow-metal record counts.
    pub const fn common_impact_hard_materials(self) -> [u32; HARD_MATERIAL_COUNT] {
        self.common_impact_hard_materials
    }

    /// Return measured hard-world grazing-angle histogram counts.
    pub const fn common_impact_grazing_angles(self) -> [u32; GRAZING_ANGLE_BUCKET_COUNT] {
        self.common_impact_grazing_angles
    }

    pub(crate) const fn ricochet_candidates(self) -> u32 {
        self.ricochet_candidates
    }

    pub(crate) const fn ricochet_publications(self) -> u32 {
        self.ricochet_publications
    }

    pub(crate) const fn ricochet_material_coverage(
        self,
    ) -> (
        [u32; CANONICAL_MATERIAL_COUNT],
        [u32; CANONICAL_MATERIAL_COUNT],
        [u32; CANONICAL_MATERIAL_COUNT],
    ) {
        (
            self.ricochet_candidates_by_material,
            self.ricochet_publications_by_material,
            self.ricochet_confirmed_by_material,
        )
    }

    pub(crate) const fn ricochet_angle_coverage(
        self,
    ) -> (
        [u32; GRAZING_ANGLE_BUCKET_COUNT],
        [u32; GRAZING_ANGLE_BUCKET_COUNT],
    ) {
        (
            self.ricochet_candidates_by_angle,
            self.ricochet_publications_by_angle,
        )
    }

    pub(crate) const fn ricochet_depth_coverage(
        self,
    ) -> (
        [u32; RICOCHET_DEPTH_BUCKET_COUNT],
        [u32; RICOCHET_DEPTH_BUCKET_COUNT],
        [u32; RICOCHET_DEPTH_BUCKET_COUNT],
        [u32; RICOCHET_DEPTH_BUCKET_COUNT],
    ) {
        (
            self.ricochet_parent_depth,
            self.ricochet_candidates_by_depth,
            self.ricochet_publications_by_depth,
            self.ricochet_confirmed_by_depth,
        )
    }

    pub(crate) const fn ricochet_energy_histograms(
        self,
    ) -> (
        [u32; RICOCHET_SPEED_BUCKET_COUNT],
        [u32; RICOCHET_SPEED_BUCKET_COUNT],
        [u32; RICOCHET_DAMAGE_BUCKET_COUNT],
        [u32; RICOCHET_DAMAGE_BUCKET_COUNT],
    ) {
        (
            self.ricochet_current_speed,
            self.ricochet_next_speed,
            self.ricochet_current_damage,
            self.ricochet_next_damage,
        )
    }

    pub(crate) const fn ricochet_child_state_rejections(
        self,
    ) -> [u32; ChildInitializationError::COUNT] {
        self.ricochet_child_state_rejections
    }

    pub(crate) const fn ricochet_depth_upper() -> &'static [u32; 5] {
        &RICOCHET_DEPTH_UPPER
    }

    pub(crate) const fn ricochet_speed_upper() -> &'static [f32; 5] {
        &RICOCHET_SPEED_UPPER
    }

    pub(crate) const fn ricochet_damage_upper() -> &'static [f32; 6] {
        &RICOCHET_DAMAGE_UPPER
    }

    pub(crate) const fn ricochet_publication_invalid(self) -> u32 {
        self.ricochet_publication_invalid
    }

    pub(crate) const fn ricochet_movement_target_status(self) -> [u32; 4] {
        [
            self.ricochet_movement_boundaries,
            self.ricochet_movement_target_status[0],
            self.ricochet_movement_target_status[1],
            self.ricochet_movement_target_status[2],
        ]
    }

    pub(crate) const fn ricochet_first_step_outcomes(self) -> [u32; 6] {
        [
            self.ricochet_first_steps,
            self.ricochet_first_step_outward,
            self.ricochet_first_step_non_outward,
            self.ricochet_first_step_stationary,
            self.ricochet_first_step_invalid,
            self.ricochet_first_step_state_races,
        ]
    }

    pub(crate) const fn ricochet_pending_lost(self) -> u32 {
        self.ricochet_pending_lost
    }

    pub(crate) const fn direction_error_upper_degrees() -> &'static [f32; 6] {
        &DIRECTION_ERROR_UPPER_DEGREES
    }

    pub(crate) const fn ricochet_publication_errors(self) -> [u32; DIRECTION_ERROR_BUCKET_COUNT] {
        self.ricochet_publication_authority_error
    }

    pub(crate) const fn ricochet_first_step_errors(
        self,
    ) -> [[u32; DIRECTION_ERROR_BUCKET_COUNT]; 3] {
        [
            self.ricochet_first_step_authority_error,
            self.ricochet_first_step_movement_error,
            self.ricochet_first_step_position_error,
        ]
    }

    pub(crate) const fn ricochet_movement_boundary_errors(
        self,
    ) -> [[u32; DIRECTION_ERROR_BUCKET_COUNT]; 2] {
        [
            self.ricochet_pre_movement_authority_error,
            self.ricochet_immediate_movement_error,
        ]
    }

    pub(crate) const fn ricochet_post_bounce_contacts(self) -> u32 {
        self.ricochet_post_bounce_contacts
    }

    pub(crate) const fn ricochet_post_bounce_actor_hits(self) -> u32 {
        self.ricochet_post_bounce_actor_hits
    }

    pub(crate) const fn ricochet_followup_identity(self) -> [u32; 2] {
        [
            self.ricochet_followup_same_target,
            self.ricochet_followup_same_material,
        ]
    }

    pub(crate) const fn ricochet_followup_directions(self) -> [u32; 3] {
        [
            self.ricochet_followup_outward,
            self.ricochet_followup_non_outward,
            self.ricochet_followup_invalid_direction,
        ]
    }

    pub(crate) const fn ricochet_followup_invalid_geometry(self) -> [u32; 2] {
        [
            self.ricochet_followup_invalid_distance,
            self.ricochet_followup_invalid_point,
        ]
    }

    pub(crate) const fn ricochet_followup_distance(self) -> [u32; FOLLOWUP_DISTANCE_BUCKET_COUNT] {
        self.ricochet_followup_distance
    }

    pub(crate) const fn ricochet_followup_point_separation(
        self,
    ) -> [u32; FOLLOWUP_DISTANCE_BUCKET_COUNT] {
        self.ricochet_followup_point_separation
    }

    pub(crate) const fn followup_distance_upper_units() -> &'static [f32; 5] {
        &FOLLOWUP_DISTANCE_UPPER_UNITS
    }

    pub(crate) const fn ricochet_publications_by_source(self) -> [u32; SourceKind::COUNT] {
        self.ricochet_publications_by_source
    }

    pub(crate) const fn ricochet_confirmed_by_source(self) -> [u32; SourceKind::COUNT] {
        self.ricochet_confirmed_by_source
    }

    pub(crate) const fn ricochet_rejections(self) -> [u32; RicochetRejection::COUNT] {
        self.ricochet_rejections
    }
}

pub(crate) fn configure(enabled: bool, frequency: i64) {
    let Ok(frequency) = u32::try_from(frequency) else {
        ENABLED.store(false, Ordering::Release);
        return;
    };
    if frequency == 0 {
        ENABLED.store(false, Ordering::Release);
        return;
    }

    MAX_INTERVAL_TICKS.store(ticks_for(frequency, MAX_INTERVAL_US), Ordering::Relaxed);
    for (target, upper_us) in IMPACT_BUCKET_TICKS.iter().zip(IMPACT_BUCKET_US) {
        target.store(ticks_for(frequency, upper_us), Ordering::Relaxed);
    }
    ENABLED.store(enabled, Ordering::Release);
}

#[inline]
pub(crate) fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

pub(crate) fn reset() {
    for counter in all_scalar_counters() {
        counter.store(0, Ordering::Relaxed);
    }
    for counter in LAUNCHES_BY_SOURCE
        .iter()
        .chain(&LAUNCHES_BY_CAPABILITY)
        .chain(&PROJECTILE_COUNTS)
        .chain(&IMPACT_LATENCY)
        .chain(&THREAD_IDS)
        .chain(&UPDATE_PATHS)
        .chain(&RUNTIME_MARKERS)
        .chain(&UPDATE_FRAME_TIME)
        .chain(&STEP_ERROR)
        .chain(&COMMON_IMPACTS_BY_SOURCE)
        .chain(&COMMON_IMPACT_LIST_SHAPES)
        .chain(&COMMON_IMPACT_RESULTS)
        .chain(&COMMON_IMPACT_MATERIALS)
        .chain(&COMMON_IMPACT_HARD_MATERIALS)
        .chain(&COMMON_IMPACT_GRAZING_ANGLES)
        .chain(&RICOCHET_CANDIDATES_BY_MATERIAL)
        .chain(&RICOCHET_PUBLICATIONS_BY_MATERIAL)
        .chain(&RICOCHET_CONFIRMED_BY_MATERIAL)
        .chain(&RICOCHET_CANDIDATES_BY_ANGLE)
        .chain(&RICOCHET_PUBLICATIONS_BY_ANGLE)
        .chain(&RICOCHET_CANDIDATES_BY_DEPTH)
        .chain(&RICOCHET_PUBLICATIONS_BY_DEPTH)
        .chain(&RICOCHET_CONFIRMED_BY_DEPTH)
        .chain(&RICOCHET_PUBLICATIONS_BY_SOURCE)
        .chain(&RICOCHET_CONFIRMED_BY_SOURCE)
        .chain(&RICOCHET_REJECTIONS)
        .chain(&RICOCHET_CHILD_STATE_REJECTIONS)
        .chain(&RICOCHET_CURRENT_SPEED)
        .chain(&RICOCHET_NEXT_SPEED)
        .chain(&RICOCHET_CURRENT_DAMAGE)
        .chain(&RICOCHET_NEXT_DAMAGE)
        .chain(&RICOCHET_PARENT_DEPTH)
        .chain(&RICOCHET_FOLLOWUP_DISTANCE)
        .chain(&RICOCHET_FOLLOWUP_POINT_SEPARATION)
        .chain(&RICOCHET_PUBLICATION_AUTHORITY_ERROR)
        .chain(&RICOCHET_PRE_MOVEMENT_AUTHORITY_ERROR)
        .chain(&RICOCHET_IMMEDIATE_MOVEMENT_ERROR)
        .chain(&RICOCHET_FIRST_STEP_AUTHORITY_ERROR)
        .chain(&RICOCHET_FIRST_STEP_MOVEMENT_ERROR)
        .chain(&RICOCHET_FIRST_STEP_POSITION_ERROR)
        .chain(&RICOCHET_MOVEMENT_TARGET_STATUS)
    {
        counter.store(0, Ordering::Relaxed);
    }
}

#[inline]
pub(crate) fn now_tick() -> u32 {
    match query_performance_counter() {
        Ok(value) => value as u32,
        Err(_) => {
            increment(&INVALID_VALUES);
            0
        }
    }
}

#[inline]
pub(crate) fn max_interval_ticks() -> u32 {
    MAX_INTERVAL_TICKS.load(Ordering::Relaxed)
}

pub(crate) fn record_launch(source: SourceKind, capability: ProjectileCapability) {
    record_thread();
    increment(&LAUNCHES);
    increment(&LAUNCHES_BY_SOURCE[source as usize]);
    increment(&LAUNCHES_BY_CAPABILITY[capability as usize]);
    if capability == ProjectileCapability::Unknown {
        increment(&UNCLASSIFIED_FALLBACKS);
    }
}

pub(crate) fn record_projectile_count(count: u8) {
    record_thread();
    let bucket = match count {
        0 => 0,
        1 => 1,
        2..=4 => 2,
        5..=8 => 3,
        _ => 4,
    };
    increment(&PROJECTILE_COUNTS[bucket]);
}

pub(crate) fn record_actor_hit(duplicate: bool) {
    record_thread();
    increment(&ACTOR_HITS);
    if duplicate {
        increment(&DUPLICATE_HIT_BUILDS);
    }
}

pub(crate) fn record_world_impact(duplicate: bool, launch_tick: u32) {
    record_thread();
    increment(&WORLD_IMPACTS);
    if duplicate {
        increment(&REPEATED_CONTACTS);
    } else {
        increment(&FIRST_CONTACTS);
        record_impact_latency(launch_tick);
    }
}

pub(crate) fn record_actor_contact(duplicate: bool, launch_tick: u32) {
    record_thread();
    if duplicate {
        increment(&REPEATED_CONTACTS);
    } else {
        increment(&FIRST_CONTACTS);
        record_impact_latency(launch_tick);
    }
}

pub(crate) fn record_hit_commit() {
    record_thread();
    increment(&HIT_COMMITS);
}

pub(crate) fn record_untracked_contact() {
    record_thread();
    increment(&UNTRACKED_CONTACTS);
}

pub(crate) fn record_untracked_hit_build() {
    record_thread();
    increment(&UNTRACKED_HIT_BUILDS);
}

pub(crate) fn record_early_contact() {
    increment(&EARLY_CONTACTS);
}

pub(crate) fn record_pool_overflow() {
    increment(&POOL_OVERFLOWS);
}

pub(crate) fn record_invalid_value() {
    increment(&INVALID_VALUES);
}

pub(crate) fn record_policy_result(result: PolicyResult) {
    increment(&POLICY_CANDIDATES);
    let counter = match result {
        PolicyResult::ForcedPhysical => &POLICY_FORCED,
        PolicyResult::AlreadyPhysical => &POLICY_ALREADY_PHYSICAL,
        PolicyResult::ContextRejected => &POLICY_CONTEXT_REJECTS,
        PolicyResult::PolicyNotObserved => &POLICY_MISSES,
        PolicyResult::CapacityUnavailable => &POLICY_CAPACITY_FAILURES,
    };
    increment(counter);
}

pub(crate) fn record_expired_misses(count: u32) {
    add(&EXPIRED_MISSES, count);
}

pub(crate) fn record_stale_generation() {
    increment(&STALE_GENERATIONS);
}

pub(crate) fn record_update_entry(
    tracked: bool,
    first: bool,
    capability: ProjectileCapability,
    selected_path: RuntimeFlightPath,
    runtime_markers: RuntimePolicyMarkers,
    delta_seconds: f32,
    before_launch_return: bool,
) {
    record_thread();
    increment(&MISSILE_UPDATES);
    if tracked {
        increment(&TRACKED_UPDATES);
    }
    if first {
        increment(&FIRST_UPDATES);
    }
    if before_launch_return {
        increment(&EARLY_UPDATES);
    }

    increment(&UPDATE_PATHS[update_path_index(capability, selected_path)]);
    increment(&RUNTIME_MARKERS[runtime_marker_index(runtime_markers)]);

    if !delta_seconds.is_finite() || delta_seconds <= 0.0 {
        increment(&INVALID_VALUES);
        return;
    }
    let microseconds = (delta_seconds * 1_000_000.0).max(0.0) as u32;
    let bucket = UPDATE_FRAME_US
        .iter()
        .position(|upper| microseconds <= *upper)
        .unwrap_or(UPDATE_FRAME_BUCKET_COUNT - 1);
    increment(&UPDATE_FRAME_TIME[bucket]);
}

const fn update_path_index(
    capability: ProjectileCapability,
    selected_path: RuntimeFlightPath,
) -> usize {
    match (capability, selected_path) {
        (ProjectileCapability::DiscreteHitscan, RuntimeFlightPath::Hitscan) => 0,
        (ProjectileCapability::DiscreteHitscan, RuntimeFlightPath::Physical) => 1,
        (ProjectileCapability::DiscretePhysical, RuntimeFlightPath::Physical) => 2,
        (ProjectileCapability::DiscretePhysical, RuntimeFlightPath::Hitscan) => 3,
        _ => 4,
    }
}

const fn runtime_marker_index(runtime_markers: RuntimePolicyMarkers) -> usize {
    match runtime_markers {
        RuntimePolicyMarkers::HitscanOnly => 0,
        RuntimePolicyMarkers::PhysicalOnly => 1,
        RuntimePolicyMarkers::Both => 2,
        RuntimePolicyMarkers::Neither => 3,
    }
}

pub(crate) fn record_update_result(
    pre: ProjectileRuntimeSample,
    post: ProjectileRuntimeSample,
    delta_seconds: f32,
    effective_speed: f32,
) {
    if !pre.is_finite()
        || !post.is_finite()
        || !delta_seconds.is_finite()
        || delta_seconds <= 0.0
        || !effective_speed.is_finite()
        || effective_speed <= 0.0
    {
        increment(&INVALID_VALUES);
        return;
    }

    let displacement_squared = pre
        .position
        .into_iter()
        .zip(post.position)
        .map(|(before, after)| {
            let delta = after - before;
            delta * delta
        })
        .sum::<f32>();
    if !displacement_squared.is_finite() {
        increment(&INVALID_VALUES);
        return;
    }
    let displacement = displacement_squared.sqrt();
    if displacement > 0.001 {
        increment(&PROGRESSIVE_UPDATES);
    } else {
        increment(&STATIONARY_UPDATES);
    }
    if post.has_impacted || !post.impact_list_empty {
        increment(&IMPACTED_UPDATES);
        return;
    }

    let expected = effective_speed * delta_seconds;
    if !expected.is_finite() || expected <= f32::EPSILON {
        increment(&INVALID_VALUES);
        return;
    }
    let error_percent = ((displacement - expected).abs() / expected) * 100.0;
    let bucket = STEP_ERROR_PERCENT
        .iter()
        .position(|upper| error_percent <= *upper)
        .unwrap_or(STEP_ERROR_BUCKET_COUNT - 1);
    increment(&STEP_ERROR[bucket]);
}

pub(crate) fn record_contact_during_update() {
    increment(&CONTACTS_DURING_UPDATE);
}

/// Record one behavior-neutral sample around the native common-impact path.
pub(crate) fn record_common_impact(observation: CommonImpactObservation) {
    record_thread();
    increment(&COMMON_IMPACT_CALLS);
    increment(&COMMON_IMPACT_RESULTS[usize::from(observation.predecessor_result != 0)]);

    let list_shape = match observation.impacts {
        None => 0,
        Some(impacts) if impacts.ready_count == 0 => 1,
        Some(impacts) if impacts.ready_count == 1 => 2,
        Some(_) => 3,
    };
    increment(&COMMON_IMPACT_LIST_SHAPES[list_shape]);
    if observation
        .impacts
        .is_some_and(|impacts| impacts.traversal_truncated)
    {
        increment(&COMMON_IMPACT_LIST_TRUNCATED);
    }

    let Some(launch) = observation.launch else {
        return;
    };
    increment(&COMMON_IMPACT_TRACKED);
    increment(&COMMON_IMPACTS_BY_SOURCE[launch.source_kind as usize]);
    if launch.actor_hit {
        increment(&COMMON_IMPACT_ACTOR);
    }
    if launch.selected_path != RuntimeFlightPath::Physical {
        return;
    }
    increment(&COMMON_IMPACT_PHYSICAL);

    let Some(impacts) = observation.impacts else {
        return;
    };
    let Some(record) = impacts.first_ready else {
        return;
    };
    let Some(material) = ricochet::canonical_material(record.raw_material) else {
        increment(&COMMON_IMPACT_UNKNOWN_MATERIAL);
        return;
    };
    increment(&COMMON_IMPACT_MATERIALS[material as usize]);
    let Some(hard_material) = ricochet::hard_material(material) else {
        return;
    };
    increment(&COMMON_IMPACT_HARD_MATERIALS[hard_material as usize]);

    if launch.actor_hit
        || impacts.ready_count != 1
        || !matches!(
            launch.capability,
            ProjectileCapability::DiscreteHitscan | ProjectileCapability::DiscretePhysical
        )
    {
        return;
    }
    let Some(runtime) = observation.runtime else {
        return;
    };
    if !runtime.is_finite() || !record.is_finite() {
        increment(&COMMON_IMPACT_INVALID_GEOMETRY);
        return;
    }
    let incidence = match ricochet::incidence(runtime.direction, record.normal) {
        Ok(incidence) => incidence,
        Err(_) => {
            increment(&COMMON_IMPACT_INVALID_GEOMETRY);
            return;
        }
    };
    increment(&COMMON_IMPACT_MEASURABLE_HARD_WORLD);
    let angle = incidence.grazing_degrees();
    let bucket = GRAZING_ANGLE_UPPER_DEGREES
        .iter()
        .position(|upper| angle <= f32::from(*upper))
        .unwrap_or(GRAZING_ANGLE_BUCKET_COUNT - 1);
    increment(&COMMON_IMPACT_GRAZING_ANGLES[bucket]);
}

pub(crate) fn record_ricochet_candidate(plan: RicochetPlan, child_depth: u32) {
    increment(&RICOCHET_CANDIDATES);
    increment(&RICOCHET_CANDIDATES_BY_MATERIAL[plan.material() as usize]);
    increment(&RICOCHET_CANDIDATES_BY_ANGLE[grazing_angle_bucket(plan.grazing_degrees())]);
    increment(&RICOCHET_CANDIDATES_BY_DEPTH[ricochet_depth_bucket(child_depth)]);
}

pub(crate) fn record_ricochet_rejection(reason: RicochetRejection) {
    increment(&RICOCHET_REJECTIONS[reason as usize]);
}

pub(crate) fn record_ricochet_child_state_rejection(reason: ChildInitializationError) {
    increment(&RICOCHET_CHILD_STATE_REJECTIONS[reason as usize]);
}

pub(crate) fn record_ricochet_energy(parent_depth: u32, energy: ContinuationEnergy) {
    record_f32_bucket(
        energy.current_effective_speed(),
        &RICOCHET_SPEED_UPPER,
        &RICOCHET_CURRENT_SPEED,
    );
    record_f32_bucket(
        energy.next_effective_speed(),
        &RICOCHET_SPEED_UPPER,
        &RICOCHET_NEXT_SPEED,
    );
    record_f32_bucket(
        energy.current_damage(),
        &RICOCHET_DAMAGE_UPPER,
        &RICOCHET_CURRENT_DAMAGE,
    );
    record_f32_bucket(
        energy.next_damage(),
        &RICOCHET_DAMAGE_UPPER,
        &RICOCHET_NEXT_DAMAGE,
    );
    let bucket = RICOCHET_DEPTH_UPPER
        .iter()
        .position(|upper| parent_depth <= *upper)
        .unwrap_or(RICOCHET_DEPTH_BUCKET_COUNT - 1);
    increment(&RICOCHET_PARENT_DEPTH[bucket]);
}

pub(crate) fn record_ricochet_publication(
    source: SourceKind,
    authority_error_degrees: Option<f32>,
    child_coherent: bool,
    plan: RicochetPlan,
    child_depth: u32,
) {
    increment(&RICOCHET_PUBLICATIONS);
    increment(&RICOCHET_PUBLICATIONS_BY_SOURCE[source as usize]);
    increment(&RICOCHET_PUBLICATIONS_BY_MATERIAL[plan.material() as usize]);
    increment(&RICOCHET_PUBLICATIONS_BY_ANGLE[grazing_angle_bucket(plan.grazing_degrees())]);
    increment(&RICOCHET_PUBLICATIONS_BY_DEPTH[ricochet_depth_bucket(child_depth)]);
    record_direction_error(
        authority_error_degrees,
        &RICOCHET_PUBLICATION_AUTHORITY_ERROR,
    );
    if authority_error_degrees.is_none() || !child_coherent {
        increment(&RICOCHET_PUBLICATION_INVALID);
    }
}

pub(crate) fn record_ricochet_movement_boundary(
    flight_target_present: Option<bool>,
    authority_error_degrees: Option<f32>,
    movement_error_degrees: Option<f32>,
) {
    increment(&RICOCHET_MOVEMENT_BOUNDARIES);
    let target_status = match flight_target_present {
        Some(false) => 0,
        Some(true) => 1,
        None => 2,
    };
    increment(&RICOCHET_MOVEMENT_TARGET_STATUS[target_status]);
    record_direction_error(
        authority_error_degrees,
        &RICOCHET_PRE_MOVEMENT_AUTHORITY_ERROR,
    );
    record_direction_error(movement_error_degrees, &RICOCHET_IMMEDIATE_MOVEMENT_ERROR);
}

pub(crate) fn record_ricochet_first_step(
    source: SourceKind,
    bounce_depth: u32,
    raw_material: u32,
    authority_error_degrees: Option<f32>,
    evidence: Option<FirstStepEvidence>,
    state_committed: bool,
) {
    increment(&RICOCHET_FIRST_STEPS);
    record_direction_error(
        authority_error_degrees,
        &RICOCHET_FIRST_STEP_AUTHORITY_ERROR,
    );
    if !state_committed {
        increment(&RICOCHET_FIRST_STEP_STATE_RACES);
    }
    let Some(evidence) = evidence else {
        increment(&RICOCHET_FIRST_STEP_INVALID);
        return;
    };
    match evidence.outcome {
        FirstStepOutcome::Outward => {
            increment(&RICOCHET_FIRST_STEP_OUTWARD);
            if state_committed {
                increment(&RICOCHET_CONFIRMED_BY_SOURCE[source as usize]);
                increment(&RICOCHET_CONFIRMED_BY_DEPTH[ricochet_depth_bucket(bounce_depth)]);
                if let Some(material) = ricochet::canonical_material(raw_material) {
                    increment(&RICOCHET_CONFIRMED_BY_MATERIAL[material as usize]);
                }
            }
        }
        FirstStepOutcome::NonOutward => increment(&RICOCHET_FIRST_STEP_NON_OUTWARD),
        FirstStepOutcome::Stationary => increment(&RICOCHET_FIRST_STEP_STATIONARY),
        FirstStepOutcome::Invalid => increment(&RICOCHET_FIRST_STEP_INVALID),
    }
    record_direction_error(
        evidence.expected_error_degrees,
        &RICOCHET_FIRST_STEP_MOVEMENT_ERROR,
    );
    record_direction_error(
        evidence.position_error_degrees,
        &RICOCHET_FIRST_STEP_POSITION_ERROR,
    );
}

pub(crate) fn record_ricochet_pending_lost(count: u32) {
    add(&RICOCHET_PENDING_LOST, count);
}

pub(crate) fn record_ricochet_post_bounce_contact(followup: Option<FollowupContact>) {
    increment(&RICOCHET_POST_BOUNCE_CONTACTS);
    let Some(followup) = followup else {
        return;
    };
    if followup.same_target {
        increment(&RICOCHET_FOLLOWUP_SAME_TARGET);
    }
    if followup.same_material {
        increment(&RICOCHET_FOLLOWUP_SAME_MATERIAL);
    }
    match followup.outward_dot {
        Some(value) if value > f32::EPSILON => increment(&RICOCHET_FOLLOWUP_OUTWARD),
        Some(_) => increment(&RICOCHET_FOLLOWUP_NON_OUTWARD),
        None => increment(&RICOCHET_FOLLOWUP_INVALID_DIRECTION),
    }
    record_followup_distance(
        followup.distance_progress,
        &RICOCHET_FOLLOWUP_DISTANCE,
        &RICOCHET_FOLLOWUP_INVALID_DISTANCE,
    );
    record_followup_distance(
        followup.point_separation,
        &RICOCHET_FOLLOWUP_POINT_SEPARATION,
        &RICOCHET_FOLLOWUP_INVALID_POINT,
    );
}

fn record_followup_distance(
    value: Option<f32>,
    buckets: &[AtomicU32; FOLLOWUP_DISTANCE_BUCKET_COUNT],
    invalid: &AtomicU32,
) {
    let Some(value) = value.filter(|value| value.is_finite()) else {
        increment(invalid);
        return;
    };
    let bucket = FOLLOWUP_DISTANCE_UPPER_UNITS
        .iter()
        .position(|upper| value <= *upper)
        .unwrap_or(FOLLOWUP_DISTANCE_BUCKET_COUNT - 1);
    increment(&buckets[bucket]);
}

fn record_direction_error(value: Option<f32>, buckets: &[AtomicU32; DIRECTION_ERROR_BUCKET_COUNT]) {
    let Some(value) = value.filter(|value| value.is_finite() && *value >= 0.0) else {
        return;
    };
    let bucket = DIRECTION_ERROR_UPPER_DEGREES
        .iter()
        .position(|upper| value <= *upper)
        .unwrap_or(DIRECTION_ERROR_BUCKET_COUNT - 1);
    increment(&buckets[bucket]);
}

fn record_f32_bucket<const N: usize>(value: f32, upper_bounds: &[f32], buckets: &[AtomicU32; N]) {
    if !value.is_finite() || value < 0.0 {
        return;
    }
    let bucket = upper_bounds
        .iter()
        .position(|upper| value <= *upper)
        .unwrap_or(N - 1);
    increment(&buckets[bucket]);
}

fn grazing_angle_bucket(value: f32) -> usize {
    GRAZING_ANGLE_UPPER_DEGREES
        .iter()
        .position(|upper| value <= f32::from(*upper))
        .unwrap_or(GRAZING_ANGLE_BUCKET_COUNT - 1)
}

fn ricochet_depth_bucket(value: u32) -> usize {
    RICOCHET_DEPTH_UPPER
        .iter()
        .position(|upper| value <= *upper)
        .unwrap_or(RICOCHET_DEPTH_BUCKET_COUNT - 1)
}

pub(crate) fn record_ricochet_post_bounce_actor_hit() {
    increment(&RICOCHET_POST_BOUNCE_ACTOR_HITS);
}

/// Copy the current bounded counters without stopping collection.
pub fn snapshot() -> BallisticsTelemetrySnapshot {
    BallisticsTelemetrySnapshot {
        launches: LAUNCHES.load(Ordering::Relaxed),
        launches_by_source: load_array(&LAUNCHES_BY_SOURCE),
        launches_by_capability: load_array(&LAUNCHES_BY_CAPABILITY),
        projectile_counts: load_array(&PROJECTILE_COUNTS),
        actor_hits: ACTOR_HITS.load(Ordering::Relaxed),
        world_impacts: WORLD_IMPACTS.load(Ordering::Relaxed),
        hit_commits: HIT_COMMITS.load(Ordering::Relaxed),
        first_contacts: FIRST_CONTACTS.load(Ordering::Relaxed),
        repeated_contacts: REPEATED_CONTACTS.load(Ordering::Relaxed),
        untracked_contacts: UNTRACKED_CONTACTS.load(Ordering::Relaxed),
        duplicate_hit_builds: DUPLICATE_HIT_BUILDS.load(Ordering::Relaxed),
        untracked_hit_builds: UNTRACKED_HIT_BUILDS.load(Ordering::Relaxed),
        early_contacts: EARLY_CONTACTS.load(Ordering::Relaxed),
        invalid_values: INVALID_VALUES.load(Ordering::Relaxed),
        pool_overflows: POOL_OVERFLOWS.load(Ordering::Relaxed),
        expired_misses: EXPIRED_MISSES.load(Ordering::Relaxed),
        stale_generations: STALE_GENERATIONS.load(Ordering::Relaxed),
        unclassified_fallbacks: UNCLASSIFIED_FALLBACKS.load(Ordering::Relaxed),
        policy_candidates: POLICY_CANDIDATES.load(Ordering::Relaxed),
        policy_forced: POLICY_FORCED.load(Ordering::Relaxed),
        policy_already_physical: POLICY_ALREADY_PHYSICAL.load(Ordering::Relaxed),
        policy_context_rejects: POLICY_CONTEXT_REJECTS.load(Ordering::Relaxed),
        policy_misses: POLICY_MISSES.load(Ordering::Relaxed),
        policy_capacity_failures: POLICY_CAPACITY_FAILURES.load(Ordering::Relaxed),
        impact_latency: load_array(&IMPACT_LATENCY),
        thread_ids: load_array(&THREAD_IDS),
        thread_overflow: THREAD_OVERFLOW.load(Ordering::Relaxed),
        missile_updates: MISSILE_UPDATES.load(Ordering::Relaxed),
        tracked_updates: TRACKED_UPDATES.load(Ordering::Relaxed),
        first_updates: FIRST_UPDATES.load(Ordering::Relaxed),
        early_updates: EARLY_UPDATES.load(Ordering::Relaxed),
        contacts_during_update: CONTACTS_DURING_UPDATE.load(Ordering::Relaxed),
        progressive_updates: PROGRESSIVE_UPDATES.load(Ordering::Relaxed),
        stationary_updates: STATIONARY_UPDATES.load(Ordering::Relaxed),
        impacted_updates: IMPACTED_UPDATES.load(Ordering::Relaxed),
        update_paths: load_array(&UPDATE_PATHS),
        runtime_markers: load_array(&RUNTIME_MARKERS),
        update_frame_time: load_array(&UPDATE_FRAME_TIME),
        step_error: load_array(&STEP_ERROR),
        common_impact_calls: COMMON_IMPACT_CALLS.load(Ordering::Relaxed),
        common_impact_tracked: COMMON_IMPACT_TRACKED.load(Ordering::Relaxed),
        common_impact_physical: COMMON_IMPACT_PHYSICAL.load(Ordering::Relaxed),
        common_impact_actor: COMMON_IMPACT_ACTOR.load(Ordering::Relaxed),
        common_impact_list_truncated: COMMON_IMPACT_LIST_TRUNCATED.load(Ordering::Relaxed),
        common_impact_unknown_material: COMMON_IMPACT_UNKNOWN_MATERIAL.load(Ordering::Relaxed),
        common_impact_invalid_geometry: COMMON_IMPACT_INVALID_GEOMETRY.load(Ordering::Relaxed),
        common_impact_measurable_hard_world: COMMON_IMPACT_MEASURABLE_HARD_WORLD
            .load(Ordering::Relaxed),
        common_impacts_by_source: load_array(&COMMON_IMPACTS_BY_SOURCE),
        common_impact_list_shapes: load_array(&COMMON_IMPACT_LIST_SHAPES),
        common_impact_results: load_array(&COMMON_IMPACT_RESULTS),
        common_impact_materials: load_array(&COMMON_IMPACT_MATERIALS),
        common_impact_hard_materials: load_array(&COMMON_IMPACT_HARD_MATERIALS),
        common_impact_grazing_angles: load_array(&COMMON_IMPACT_GRAZING_ANGLES),
        ricochet_candidates: RICOCHET_CANDIDATES.load(Ordering::Relaxed),
        ricochet_publications: RICOCHET_PUBLICATIONS.load(Ordering::Relaxed),
        ricochet_candidates_by_material: load_array(&RICOCHET_CANDIDATES_BY_MATERIAL),
        ricochet_publications_by_material: load_array(&RICOCHET_PUBLICATIONS_BY_MATERIAL),
        ricochet_confirmed_by_material: load_array(&RICOCHET_CONFIRMED_BY_MATERIAL),
        ricochet_candidates_by_angle: load_array(&RICOCHET_CANDIDATES_BY_ANGLE),
        ricochet_publications_by_angle: load_array(&RICOCHET_PUBLICATIONS_BY_ANGLE),
        ricochet_candidates_by_depth: load_array(&RICOCHET_CANDIDATES_BY_DEPTH),
        ricochet_publications_by_depth: load_array(&RICOCHET_PUBLICATIONS_BY_DEPTH),
        ricochet_confirmed_by_depth: load_array(&RICOCHET_CONFIRMED_BY_DEPTH),
        ricochet_current_speed: load_array(&RICOCHET_CURRENT_SPEED),
        ricochet_next_speed: load_array(&RICOCHET_NEXT_SPEED),
        ricochet_current_damage: load_array(&RICOCHET_CURRENT_DAMAGE),
        ricochet_next_damage: load_array(&RICOCHET_NEXT_DAMAGE),
        ricochet_parent_depth: load_array(&RICOCHET_PARENT_DEPTH),
        ricochet_child_state_rejections: load_array(&RICOCHET_CHILD_STATE_REJECTIONS),
        ricochet_publication_invalid: RICOCHET_PUBLICATION_INVALID.load(Ordering::Relaxed),
        ricochet_movement_boundaries: RICOCHET_MOVEMENT_BOUNDARIES.load(Ordering::Relaxed),
        ricochet_movement_target_status: load_array(&RICOCHET_MOVEMENT_TARGET_STATUS),
        ricochet_first_steps: RICOCHET_FIRST_STEPS.load(Ordering::Relaxed),
        ricochet_first_step_outward: RICOCHET_FIRST_STEP_OUTWARD.load(Ordering::Relaxed),
        ricochet_first_step_non_outward: RICOCHET_FIRST_STEP_NON_OUTWARD.load(Ordering::Relaxed),
        ricochet_first_step_stationary: RICOCHET_FIRST_STEP_STATIONARY.load(Ordering::Relaxed),
        ricochet_first_step_invalid: RICOCHET_FIRST_STEP_INVALID.load(Ordering::Relaxed),
        ricochet_first_step_state_races: RICOCHET_FIRST_STEP_STATE_RACES.load(Ordering::Relaxed),
        ricochet_pending_lost: RICOCHET_PENDING_LOST.load(Ordering::Relaxed),
        ricochet_publication_authority_error: load_array(&RICOCHET_PUBLICATION_AUTHORITY_ERROR),
        ricochet_pre_movement_authority_error: load_array(&RICOCHET_PRE_MOVEMENT_AUTHORITY_ERROR),
        ricochet_immediate_movement_error: load_array(&RICOCHET_IMMEDIATE_MOVEMENT_ERROR),
        ricochet_first_step_authority_error: load_array(&RICOCHET_FIRST_STEP_AUTHORITY_ERROR),
        ricochet_first_step_movement_error: load_array(&RICOCHET_FIRST_STEP_MOVEMENT_ERROR),
        ricochet_first_step_position_error: load_array(&RICOCHET_FIRST_STEP_POSITION_ERROR),
        ricochet_post_bounce_contacts: RICOCHET_POST_BOUNCE_CONTACTS.load(Ordering::Relaxed),
        ricochet_post_bounce_actor_hits: RICOCHET_POST_BOUNCE_ACTOR_HITS.load(Ordering::Relaxed),
        ricochet_followup_same_target: RICOCHET_FOLLOWUP_SAME_TARGET.load(Ordering::Relaxed),
        ricochet_followup_same_material: RICOCHET_FOLLOWUP_SAME_MATERIAL.load(Ordering::Relaxed),
        ricochet_followup_outward: RICOCHET_FOLLOWUP_OUTWARD.load(Ordering::Relaxed),
        ricochet_followup_non_outward: RICOCHET_FOLLOWUP_NON_OUTWARD.load(Ordering::Relaxed),
        ricochet_followup_invalid_direction: RICOCHET_FOLLOWUP_INVALID_DIRECTION
            .load(Ordering::Relaxed),
        ricochet_followup_invalid_distance: RICOCHET_FOLLOWUP_INVALID_DISTANCE
            .load(Ordering::Relaxed),
        ricochet_followup_invalid_point: RICOCHET_FOLLOWUP_INVALID_POINT.load(Ordering::Relaxed),
        ricochet_followup_distance: load_array(&RICOCHET_FOLLOWUP_DISTANCE),
        ricochet_followup_point_separation: load_array(&RICOCHET_FOLLOWUP_POINT_SEPARATION),
        ricochet_publications_by_source: load_array(&RICOCHET_PUBLICATIONS_BY_SOURCE),
        ricochet_confirmed_by_source: load_array(&RICOCHET_CONFIRMED_BY_SOURCE),
        ricochet_rejections: load_array(&RICOCHET_REJECTIONS),
    }
}

fn record_impact_latency(launch_tick: u32) {
    if launch_tick == 0 {
        increment(&INVALID_VALUES);
        return;
    }
    let now = now_tick();
    if now == 0 {
        return;
    }
    let delta = now.wrapping_sub(launch_tick);
    if delta > MAX_INTERVAL_TICKS.load(Ordering::Relaxed) {
        increment(&INVALID_VALUES);
        return;
    }
    let bucket = IMPACT_BUCKET_TICKS
        .iter()
        .position(|upper| delta <= upper.load(Ordering::Relaxed))
        .unwrap_or(IMPACT_BUCKET_COUNT - 1);
    increment(&IMPACT_LATENCY[bucket]);
}

fn record_thread() {
    let id = get_current_thread_id();
    for slot in &THREAD_IDS {
        let current = slot.load(Ordering::Relaxed);
        if current == id {
            return;
        }
        if current == 0
            && slot
                .compare_exchange(0, id, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            return;
        }
    }
    increment(&THREAD_OVERFLOW);
}

fn ticks_for(frequency: u32, microseconds: u32) -> u32 {
    (u64::from(frequency) * u64::from(microseconds) / 1_000_000)
        .max(1)
        .min(u64::from(u32::MAX)) as u32
}

fn all_scalar_counters() -> [&'static AtomicU32; 58] {
    [
        &LAUNCHES,
        &ACTOR_HITS,
        &WORLD_IMPACTS,
        &HIT_COMMITS,
        &FIRST_CONTACTS,
        &REPEATED_CONTACTS,
        &UNTRACKED_CONTACTS,
        &DUPLICATE_HIT_BUILDS,
        &UNTRACKED_HIT_BUILDS,
        &EARLY_CONTACTS,
        &INVALID_VALUES,
        &POOL_OVERFLOWS,
        &EXPIRED_MISSES,
        &STALE_GENERATIONS,
        &UNCLASSIFIED_FALLBACKS,
        &POLICY_CANDIDATES,
        &POLICY_FORCED,
        &POLICY_ALREADY_PHYSICAL,
        &POLICY_CONTEXT_REJECTS,
        &POLICY_MISSES,
        &POLICY_CAPACITY_FAILURES,
        &THREAD_OVERFLOW,
        &MISSILE_UPDATES,
        &TRACKED_UPDATES,
        &FIRST_UPDATES,
        &EARLY_UPDATES,
        &CONTACTS_DURING_UPDATE,
        &PROGRESSIVE_UPDATES,
        &STATIONARY_UPDATES,
        &IMPACTED_UPDATES,
        &COMMON_IMPACT_CALLS,
        &COMMON_IMPACT_TRACKED,
        &COMMON_IMPACT_PHYSICAL,
        &COMMON_IMPACT_ACTOR,
        &COMMON_IMPACT_LIST_TRUNCATED,
        &COMMON_IMPACT_UNKNOWN_MATERIAL,
        &COMMON_IMPACT_INVALID_GEOMETRY,
        &COMMON_IMPACT_MEASURABLE_HARD_WORLD,
        &RICOCHET_CANDIDATES,
        &RICOCHET_PUBLICATIONS,
        &RICOCHET_PUBLICATION_INVALID,
        &RICOCHET_MOVEMENT_BOUNDARIES,
        &RICOCHET_FIRST_STEPS,
        &RICOCHET_FIRST_STEP_OUTWARD,
        &RICOCHET_FIRST_STEP_NON_OUTWARD,
        &RICOCHET_FIRST_STEP_STATIONARY,
        &RICOCHET_FIRST_STEP_INVALID,
        &RICOCHET_FIRST_STEP_STATE_RACES,
        &RICOCHET_PENDING_LOST,
        &RICOCHET_POST_BOUNCE_CONTACTS,
        &RICOCHET_POST_BOUNCE_ACTOR_HITS,
        &RICOCHET_FOLLOWUP_SAME_TARGET,
        &RICOCHET_FOLLOWUP_SAME_MATERIAL,
        &RICOCHET_FOLLOWUP_OUTWARD,
        &RICOCHET_FOLLOWUP_NON_OUTWARD,
        &RICOCHET_FOLLOWUP_INVALID_DIRECTION,
        &RICOCHET_FOLLOWUP_INVALID_DISTANCE,
        &RICOCHET_FOLLOWUP_INVALID_POINT,
    ]
}

fn increment(counter: &AtomicU32) {
    add(counter, 1);
}

fn add(counter: &AtomicU32, amount: u32) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(amount))
    });
}

fn load_array<const N: usize>(source: &[AtomicU32; N]) -> [u32; N] {
    let mut values = [0; N];
    for (value, source) in values.iter_mut().zip(source) {
        *value = source.load(Ordering::Relaxed);
    }
    values
}

#[cfg(test)]
mod tests {
    use super::{runtime_marker_index, update_path_index};
    use crate::ballistics::ProjectileCapability;
    use crate::ballistics::native::{RuntimeFlightPath, RuntimePolicyMarkers};

    #[test]
    fn launch_selection_and_live_markers_are_independent_dimensions() {
        assert_eq!(
            update_path_index(
                ProjectileCapability::DiscreteHitscan,
                RuntimeFlightPath::Physical,
            ),
            1
        );
        assert_eq!(runtime_marker_index(RuntimePolicyMarkers::Both), 2);
        assert_eq!(runtime_marker_index(RuntimePolicyMarkers::Neither), 3);
    }
}
