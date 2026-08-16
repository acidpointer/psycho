//! Bounded, allocation-free Ballistics observation telemetry.
//!
//! Native wrappers perform QPC queries and relaxed saturating increments only
//! while tracing is enabled. Snapshot formatting and logging happen later on
//! the MCM event callback, never inside a combat hook.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use libpsycho::os::windows::winapi::{get_current_thread_id, query_performance_counter};

use super::adapter::PolicyResult;
use super::native::{ProjectileRuntimeSample, RuntimeFlightPath, RuntimePolicyMarkers};
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

fn all_scalar_counters() -> [&'static AtomicU32; 30] {
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
