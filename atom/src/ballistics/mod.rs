//! Compatibility-first physical flight for FNV projectile weapons.
//!
//! Atom wraps the canonical projectile lifecycle while chaining every current
//! predecessor exactly once. When enabled, an ordinary discrete hitscan missile
//! is routed through FNV's physical branch during native initialization. Shared
//! forms, damage, attribution, impact traversal, and save state remain native.
//! Unsupported or special launch contexts fail closed per round.

mod adapter;
mod context;
mod flight;
mod hooks;
mod native;
mod pool;
mod ricochet;
pub mod telemetry;

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

use serde::Deserialize;
use thiserror::Error;

pub use context::{ProjectileCapability, ProjectileProfile, ShotContext, SourceKind};
pub use flight::{MAX_CHORD_SEGMENTS, ShadowFlight, ShadowFlightError, ShadowStep};
pub use native::classify_profile;
pub use telemetry::BallisticsTelemetrySnapshot;

pub(crate) const EXPECTED_COMMON_IMPACT_PREDECESSOR: usize = native::COMMON_IMPACT_TARGET;
pub(crate) const EXPECTED_CHILD_PRESENTATION_PREDECESSOR: usize = native::MUZZLE_FLASH_TARGET;

static CONFIG: ConfigStore = ConfigStore::new();

const MAX_RICOCHET_ENERGY_PERCENT: u8 = 75;

/// Per-material grazing energy retained by an eligible ricochet.
///
/// Values are integer percentages in `0..=75`. Zero disables continuation on
/// that known material. The strict upper bound guarantees that every
/// continuation chain loses energy even at a perfectly grazing contact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RicochetEnergyConfig {
    percentages: [u8; ricochet::CANONICAL_MATERIAL_COUNT],
}

impl RicochetEnergyConfig {
    const DEFAULT: Self = Self {
        percentages: [36, 18, 15, 12, 56, 20, 0, 0, 10, 46],
    };

    fn from_percentages(mut percentages: [u8; ricochet::CANONICAL_MATERIAL_COUNT]) -> Self {
        for percentage in &mut percentages {
            *percentage = (*percentage).min(MAX_RICOCHET_ENERGY_PERCENT);
        }
        Self { percentages }
    }

    pub(crate) const fn percentages(self) -> [u8; ricochet::CANONICAL_MATERIAL_COUNT] {
        self.percentages
    }

    /// Return Stone's retained grazing energy percentage.
    pub const fn stone(self) -> u8 {
        self.percentages[0]
    }

    /// Return Dirt's retained grazing energy percentage.
    pub const fn dirt(self) -> u8 {
        self.percentages[1]
    }

    /// Return Grass's retained grazing energy percentage.
    pub const fn grass(self) -> u8 {
        self.percentages[2]
    }

    /// Return Glass's retained grazing energy percentage.
    pub const fn glass(self) -> u8 {
        self.percentages[3]
    }

    /// Return Metal's retained grazing energy percentage.
    pub const fn metal(self) -> u8 {
        self.percentages[4]
    }

    /// Return Wood's retained grazing energy percentage.
    pub const fn wood(self) -> u8 {
        self.percentages[5]
    }

    /// Return Organic's retained grazing energy percentage.
    pub const fn organic(self) -> u8 {
        self.percentages[6]
    }

    /// Return Cloth's retained grazing energy percentage.
    pub const fn cloth(self) -> u8 {
        self.percentages[7]
    }

    /// Return Water's retained grazing energy percentage.
    pub const fn water(self) -> u8 {
        self.percentages[8]
    }

    /// Return Hollow Metal's retained grazing energy percentage.
    pub const fn hollow_metal(self) -> u8 {
        self.percentages[9]
    }
}

impl Default for RicochetEnergyConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// MCM-owned settings for physical Ballistics and its diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BallisticsConfig {
    enabled: bool,
    ricochet_enabled: bool,
    ricochet_energy: RicochetEnergyConfig,
    trace_enabled: bool,
    summary_requested: bool,
}

impl Default for BallisticsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ricochet_enabled: true,
            ricochet_energy: RicochetEnergyConfig::DEFAULT,
            trace_enabled: false,
            summary_requested: false,
        }
    }
}

impl BallisticsConfig {
    /// Deserialize Ballistics settings from Atom's shared INI text.
    ///
    /// Unknown sections and keys are accepted. Numeric booleans must be `0`
    /// or `1`, matching MCM Extender's persisted representation. Material
    /// energy percentages are bounded to the supported `0..=75` range.
    pub fn from_ini(text: &str) -> Result<Self, BallisticsConfigError> {
        let persisted: PersistedConfig = serini::from_str(text)?;
        let ballistics = persisted.ballistics;
        Ok(Self {
            enabled: numeric_bool("Ballistics:bEnabled", ballistics.enabled)?,
            ricochet_enabled: numeric_bool("Ballistics:bRicochet", ballistics.ricochet)?,
            ricochet_energy: RicochetEnergyConfig::from_percentages([
                ballistics.ricochet_stone_energy,
                ballistics.ricochet_dirt_energy,
                ballistics.ricochet_grass_energy,
                ballistics.ricochet_glass_energy,
                ballistics.ricochet_metal_energy,
                ballistics.ricochet_wood_energy,
                ballistics.ricochet_organic_energy,
                ballistics.ricochet_cloth_energy,
                ballistics.ricochet_water_energy,
                ballistics.ricochet_hollow_metal_energy,
            ]),
            trace_enabled: numeric_bool(
                "Diagnostics:bBallisticsTrace",
                persisted.diagnostics.ballistics_trace,
            )?,
            summary_requested: numeric_bool(
                "Diagnostics:bBallisticsSummary",
                persisted.diagnostics.ballistics_summary,
            )?,
        })
    }

    /// Return whether eligible discrete hitscan rounds use native physical flight.
    pub const fn enabled(self) -> bool {
        self.enabled
    }

    /// Return whether energy-depleting child-projectile ricochet is enabled.
    pub const fn ricochet_enabled(self) -> bool {
        self.ricochet_enabled
    }

    /// Return the complete per-material ricochet energy policy.
    pub const fn ricochet_energy(self) -> RicochetEnergyConfig {
        self.ricochet_energy
    }

    /// Return whether bounded native lifecycle tracing is enabled.
    pub const fn trace_enabled(self) -> bool {
        self.trace_enabled
    }

    /// Return whether MCM requested an out-of-hook summary.
    pub const fn summary_requested(self) -> bool {
        self.summary_requested
    }
}

/// Failure to deserialize a recognized Ballistics setting.
#[derive(Debug, Error)]
pub enum BallisticsConfigError {
    /// The INI document could not be deserialized.
    #[error("could not deserialize Atom.ini for Ballistics: {0}")]
    Deserialize(#[from] serini::Error),
    /// MCM's numeric boolean contract was violated.
    #[error("{field} must be 0 or 1, found {value}")]
    InvalidBoolean { field: &'static str, value: u8 },
}

/// Failure to admit Atom's fixed FNV Ballistics observer.
#[derive(Debug, Error)]
pub(crate) enum BallisticsInstallError {
    #[error(transparent)]
    Hook(#[from] hooks::HookInstallError),
}

/// Captured predecessors proving current-owner chaining at every callsite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BallisticsHookStatus {
    pub(crate) count_predecessor: usize,
    pub(crate) launch_predecessor: usize,
    pub(crate) hit_build_predecessor: usize,
    pub(crate) hit_commit_predecessor: usize,
    pub(crate) collision_predecessor: usize,
    pub(crate) hitscan_policy_predecessor: usize,
    pub(crate) muzzle_flash_predecessor: usize,
    pub(crate) movement_step_a_predecessor: usize,
    pub(crate) movement_step_b_predecessor: usize,
    pub(crate) missile_update_predecessor: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RicochetHookStatus {
    pub(crate) launch_predecessor: usize,
    pub(crate) common_impact_predecessor: usize,
    pub(crate) child_presentation_predecessor: usize,
    pub(crate) common_impact_supported: bool,
    pub(crate) child_presentation_supported: bool,
    pub(crate) helper_entries_ready: bool,
    pub(crate) mutation_admitted: bool,
}

/// Return the coherently published Ballistics configuration.
pub fn current_config() -> BallisticsConfig {
    CONFIG.load()
}

pub(crate) fn publish_config(config: BallisticsConfig, qpc_frequency: i64) {
    let previous = CONFIG.load();
    let invalidates_observations = config.ricochet_enabled() != previous.ricochet_enabled()
        || config.ricochet_energy() != previous.ricochet_energy()
        || (config.trace_enabled() && !previous.trace_enabled());
    if invalidates_observations && let Some(observations) = pool::observations() {
        let _ = observations.clear();
    }
    if config.trace_enabled() && !previous.trace_enabled() {
        telemetry::reset();
    }
    CONFIG.publish(config);
    telemetry::configure(config.trace_enabled(), qpc_frequency);
}

pub(crate) fn install_native_observer() -> Result<BallisticsHookStatus, BallisticsInstallError> {
    pool::initialize();
    let predecessors = hooks::install()?;
    Ok(BallisticsHookStatus {
        count_predecessor: predecessors.count,
        launch_predecessor: predecessors.launch,
        hit_build_predecessor: predecessors.hit_build,
        hit_commit_predecessor: predecessors.hit_commit,
        collision_predecessor: predecessors.collision,
        hitscan_policy_predecessor: predecessors.hitscan_policy,
        muzzle_flash_predecessor: predecessors.muzzle_flash,
        movement_step_a_predecessor: predecessors.movement_step_a,
        movement_step_b_predecessor: predecessors.movement_step_b,
        missile_update_predecessor: predecessors.missile_update,
    })
}

pub(crate) fn install_ricochet_observer() -> Result<RicochetHookStatus, BallisticsInstallError> {
    let admission = hooks::install_ricochet_observer()?;
    Ok(RicochetHookStatus {
        launch_predecessor: admission.launch_predecessor,
        common_impact_predecessor: admission.common_impact_predecessor,
        child_presentation_predecessor: admission.muzzle_flash_predecessor,
        common_impact_supported: admission.common_impact_supported(),
        child_presentation_supported: admission.child_presentation_supported(),
        helper_entries_ready: admission.helper_entries_ready,
        mutation_admitted: admission.mutation_admitted(),
    })
}

pub(crate) fn clear_observations() {
    let Some(observations) = pool::observations() else {
        return;
    };
    let summary = observations.clear();
    if telemetry::enabled() {
        telemetry::record_expired_misses(summary.misses);
        telemetry::record_ricochet_pending_lost(summary.pending_ricochets);
    }
}

pub(crate) fn log_requested_summary() {
    let snapshot = telemetry::snapshot();
    let source = snapshot.launches_by_source();
    let capability = snapshot.launches_by_capability();
    let counts = snapshot.projectile_counts();
    let detours = hooks::detour_call_counts();
    log::info!("[BALLISTICS_TELEMETRY] ---------------------------------------------------");
    log::info!("[BALLISTICS_TELEMETRY] Requested native lifecycle summary");
    log::info!(
        "[BALLISTICS_TELEMETRY] Detour entries: count={}, launch={}, policy={}, hit_build={}, hit_commit={}, collision={}, muzzle={}, move_a={}, move_b={}, update={}, common_impact={}",
        detours.count,
        detours.launch,
        detours.hitscan_policy,
        detours.hit_build,
        detours.hit_commit,
        detours.collision,
        detours.muzzle_flash,
        detours.movement_step_a,
        detours.movement_step_b,
        detours.missile_update,
        detours.common_impact,
    );
    log::info!(
        "[BALLISTICS_TELEMETRY] A zero entry beside a nonzero sibling means that capability was bypassed by a later writer; see the [INTEGRITY] lines for the live call target",
    );
    log::info!(
        "[BALLISTICS_TELEMETRY] Launches: total={}, player={}, actor={}, unknown={}",
        snapshot.launches(),
        source[SourceKind::Player as usize],
        source[SourceKind::Actor as usize],
        source[SourceKind::Unknown as usize],
    );
    log::info!(
        "[BALLISTICS_TELEMETRY] Projectile paths: physical={}, hitscan={}, explosive={}, grenade/thrown={}, beam={}, flame={}, continuous={}, unknown={}",
        capability[ProjectileCapability::DiscretePhysical as usize],
        capability[ProjectileCapability::DiscreteHitscan as usize],
        capability[ProjectileCapability::ExplosiveMissile as usize],
        capability[ProjectileCapability::GrenadeOrThrown as usize],
        capability[ProjectileCapability::Beam as usize],
        capability[ProjectileCapability::Flame as usize],
        capability[ProjectileCapability::ContinuousBeam as usize],
        capability[ProjectileCapability::Unknown as usize],
    );
    log::info!(
        "[BALLISTICS_TELEMETRY] Native projectile count: zero={}, one={}, 2-4={}, 5-8={}, 9+={}",
        counts[0],
        counts[1],
        counts[2],
        counts[3],
        counts[4],
    );
    log::info!(
        "[BALLISTICS_TELEMETRY] Native effects: actor_hit_builds={}, world_effect_callbacks={}, ApplyHit={}, early_contacts={}",
        snapshot.actor_hits(),
        snapshot.world_impacts(),
        snapshot.hit_commits(),
        snapshot.early_contacts(),
    );
    log::info!(
        "[BALLISTICS_TELEMETRY] Contact correlation: first={}, repeated={}, untracked={}",
        snapshot.first_contacts(),
        snapshot.repeated_contacts(),
        snapshot.untracked_contacts(),
    );
    log::info!(
        "[BALLISTICS_TELEMETRY] Hit correlation: repeated_builds={}, untracked_builds={}, expired_misses={}, address_reuses={}, pool_overflows={}",
        snapshot.duplicate_hit_builds(),
        snapshot.untracked_hit_builds(),
        snapshot.expired_misses(),
        snapshot.address_reuses(),
        snapshot.pool_overflows(),
    );
    log::info!(
        "[BALLISTICS_TELEMETRY] Fallback: unclassified={}, invalid_values={}",
        snapshot.unclassified_fallbacks(),
        snapshot.invalid_values(),
    );
    log::info!(
        "[BALLISTICS_TELEMETRY] Native policy: candidates={}, forced_physical={}, already_physical={}, context_rejects={}, policy_misses={}, capacity_failures={}",
        snapshot.policy_candidates(),
        snapshot.policy_forced(),
        snapshot.policy_already_physical(),
        snapshot.policy_context_rejects(),
        snapshot.policy_misses(),
        snapshot.policy_capacity_failures(),
    );
    log_histogram(
        BallisticsTelemetrySnapshot::impact_bucket_upper_microseconds(),
        snapshot.impact_latency(),
    );
    let paths = snapshot.update_paths();
    let markers = snapshot.runtime_markers();
    log::info!(
        "[BALLISTICS_TELEMETRY] Missile updates: total={}, tracked={}, first={}, early={}, contacts_during={}",
        snapshot.missile_updates(),
        snapshot.tracked_updates(),
        snapshot.first_updates(),
        snapshot.early_updates(),
        snapshot.contacts_during_update(),
    );
    log::info!(
        "[BALLISTICS_TELEMETRY] Launch policy at update: hitscan/native={}, hitscan/physical={}, physical/physical={}, physical/hitscan={}, other={}",
        paths[0],
        paths[1],
        paths[2],
        paths[3],
        paths[4],
    );
    log::info!(
        "[BALLISTICS_TELEMETRY] Live policy markers: hitscan_only={}, physical_only={}, both={}, neither={}",
        markers[0],
        markers[1],
        markers[2],
        markers[3],
    );
    log::info!(
        "[BALLISTICS_TELEMETRY] Native motion: progressive={}, stationary={}, impacted={}",
        snapshot.progressive_updates(),
        snapshot.stationary_updates(),
        snapshot.impacted_updates(),
    );
    log_update_histograms(snapshot);
    log_ricochet_observation(snapshot);
    let thread_ids: Vec<u32> = snapshot
        .thread_ids()
        .into_iter()
        .filter(|id| *id != 0)
        .collect();
    log::info!(
        "[BALLISTICS_TELEMETRY] Callback threads: {:?}, overflow_callbacks={}",
        thread_ids,
        snapshot.thread_overflow(),
    );
    log::info!("[BALLISTICS_TELEMETRY] Native combat owns collision, impact, and damage");
    log::info!("[BALLISTICS_TELEMETRY] ---------------------------------------------------");
}

fn log_ricochet_observation(snapshot: BallisticsTelemetrySnapshot) {
    let sources = snapshot.common_impacts_by_source();
    let shapes = snapshot.common_impact_list_shapes();
    let results = snapshot.common_impact_results();
    let materials = snapshot.common_impact_materials();
    let hard = snapshot.common_impact_hard_materials();
    log::info!(
        "[BALLISTICS_TELEMETRY] Ricochet seam: calls={}, tracked={}, physical={}, actor={}, result_zero={}, result_nonzero={}",
        snapshot.common_impact_calls(),
        snapshot.common_impact_tracked(),
        snapshot.common_impact_physical(),
        snapshot.common_impact_actor(),
        results[0],
        results[1],
    );
    log::info!(
        "[BALLISTICS_TELEMETRY] Ricochet sources: player={}, actor={}, unknown={}",
        sources[SourceKind::Player as usize],
        sources[SourceKind::Actor as usize],
        sources[SourceKind::Unknown as usize],
    );
    log::info!(
        "[BALLISTICS_TELEMETRY] Impact lists: missing={}, empty={}, single={}, multiple={}, truncated={}",
        shapes[0],
        shapes[1],
        shapes[2],
        shapes[3],
        snapshot.common_impact_list_truncated(),
    );
    log::info!(
        "[BALLISTICS_TELEMETRY] Materials: stone={}, dirt={}, grass={}, glass={}, metal={}, wood={}, organic={}, cloth={}, water={}, hollow_metal={}, unknown={}",
        materials[0],
        materials[1],
        materials[2],
        materials[3],
        materials[4],
        materials[5],
        materials[6],
        materials[7],
        materials[8],
        materials[9],
        snapshot.common_impact_unknown_material(),
    );
    log::info!(
        "[BALLISTICS_TELEMETRY] Hard contacts: stone={}, metal={}, hollow_metal={}, measurable_world={}, invalid_geometry={}",
        hard[0],
        hard[1],
        hard[2],
        snapshot.common_impact_measurable_hard_world(),
        snapshot.common_impact_invalid_geometry(),
    );
    log_grazing_histogram(
        BallisticsTelemetrySnapshot::grazing_angle_upper_degrees(),
        snapshot.common_impact_grazing_angles(),
    );
    let publications = snapshot.ricochet_publications_by_source();
    let confirmed = snapshot.ricochet_confirmed_by_source();
    let first_steps = snapshot.ricochet_first_step_outcomes();
    let rejected = snapshot.ricochet_rejections();
    log::info!(
        "[BALLISTICS_TELEMETRY] Ricochet child transition: candidates={}, published={}, publication_invalid={}, first_steps={}, outward={}, non_outward={}, stationary={}, invalid={}, state_races={}, pending_lost={}",
        snapshot.ricochet_candidates(),
        snapshot.ricochet_publications(),
        snapshot.ricochet_publication_invalid(),
        first_steps[0],
        first_steps[1],
        first_steps[2],
        first_steps[3],
        first_steps[4],
        first_steps[5],
        snapshot.ricochet_pending_lost(),
    );
    let movement_target = snapshot.ricochet_movement_target_status();
    log::info!(
        "[BALLISTICS_TELEMETRY] Pre-movement target: boundaries={}, absent={}, present={}, invalid={}",
        movement_target[0],
        movement_target[1],
        movement_target[2],
        movement_target[3],
    );
    log::info!(
        "[BALLISTICS_TELEMETRY] Ricochet sources: published_player={}, published_actor={}, outward_player={}, outward_actor={}, later_contacts={}, later_actor_hits={}",
        publications[SourceKind::Player as usize],
        publications[SourceKind::Actor as usize],
        confirmed[SourceKind::Player as usize],
        confirmed[SourceKind::Actor as usize],
        snapshot.ricochet_post_bounce_contacts(),
        snapshot.ricochet_post_bounce_actor_hits(),
    );
    let material_coverage = snapshot.ricochet_material_coverage();
    log_ricochet_material_coverage("candidates", material_coverage.0);
    log_ricochet_material_coverage("published", material_coverage.1);
    log_ricochet_material_coverage("confirmed", material_coverage.2);
    let angle_coverage = snapshot.ricochet_angle_coverage();
    log_ricochet_angle_coverage(angle_coverage.0, angle_coverage.1);
    let depth = snapshot.ricochet_depth_coverage();
    log_ricochet_depth("evaluated_parent", depth.0);
    log_ricochet_depth("candidates", depth.1);
    log_ricochet_depth("published", depth.2);
    log_ricochet_depth("confirmed", depth.3);
    let energy = snapshot.ricochet_energy_histograms();
    log_ricochet_energy(
        "current_speed",
        BallisticsTelemetrySnapshot::ricochet_speed_upper(),
        &energy.0,
    );
    log_ricochet_energy(
        "next_speed",
        BallisticsTelemetrySnapshot::ricochet_speed_upper(),
        &energy.1,
    );
    log_ricochet_energy(
        "current_damage",
        BallisticsTelemetrySnapshot::ricochet_damage_upper(),
        &energy.2,
    );
    log_ricochet_energy(
        "next_damage",
        BallisticsTelemetrySnapshot::ricochet_damage_upper(),
        &energy.3,
    );
    let publication_errors = snapshot.ricochet_publication_errors();
    log_direction_error_histogram("Child launch authority error", publication_errors);
    let movement_boundary_errors = snapshot.ricochet_movement_boundary_errors();
    log_direction_error_histogram("Pre-movement authority error", movement_boundary_errors[0]);
    log_direction_error_histogram("Immediate movement error", movement_boundary_errors[1]);
    let first_step_errors = snapshot.ricochet_first_step_errors();
    log_direction_error_histogram("First-step authority error", first_step_errors[0]);
    log_direction_error_histogram("First-step movement error", first_step_errors[1]);
    log_direction_error_histogram("First-step position error", first_step_errors[2]);
    let identity = snapshot.ricochet_followup_identity();
    let directions = snapshot.ricochet_followup_directions();
    let invalid = snapshot.ricochet_followup_invalid_geometry();
    log::info!(
        "[BALLISTICS_TELEMETRY] Followup contacts: same_target={}, same_material={}, outward={}, non_outward={}, invalid_direction={}",
        identity[0],
        identity[1],
        directions[0],
        directions[1],
        directions[2],
    );
    log::info!(
        "[BALLISTICS_TELEMETRY] Followup invalid: distance={}, point={}",
        invalid[0],
        invalid[1],
    );
    log_followup_histogram(
        "travel",
        telemetry::BallisticsTelemetrySnapshot::followup_distance_upper_units(),
        snapshot.ricochet_followup_distance(),
    );
    log_followup_histogram(
        "separation",
        telemetry::BallisticsTelemetrySnapshot::followup_distance_upper_units(),
        snapshot.ricochet_followup_point_separation(),
    );
    log::info!(
        "[BALLISTICS_TELEMETRY] Ricochet rejects: disabled={}, critical_admission={}, untracked={}, capability={}, launch={}, form={}, outcome={}, list={}",
        rejected[0],
        rejected[1],
        rejected[2],
        rejected[3],
        rejected[4],
        rejected[5],
        rejected[6],
        rejected[7],
    );
    log::info!(
        "[BALLISTICS_TELEMETRY] Ricochet rejects: unknown_material={}, disabled_material={}, geometry={}, invalid_energy={}, speed_depleted={}, damage_depleted={}, both_depleted={}, first_step_pending={}, outbound_failed={}, actor={}, predecessor={}, post={}, race={}, native={}",
        rejected[8],
        rejected[26],
        rejected[9],
        rejected[10],
        rejected[11],
        rejected[12],
        rejected[13],
        rejected[14],
        rejected[15],
        rejected[16],
        rejected[17],
        rejected[18],
        rejected[19],
        rejected[20],
    );
    log::info!(
        "[BALLISTICS_TELEMETRY] Ricochet child rejects: clearance={}, spawn={}, policy={}, state={}, transfer={}",
        rejected[21],
        rejected[22],
        rejected[23],
        rejected[24],
        rejected[25],
    );
    let child_state = snapshot.ricochet_child_state_rejections();
    log::info!(
        "[BALLISTICS_TELEMETRY] Child state detail: input={}, sample={}, form={}, cell={}, weapon={}, source={}, target={}, impacts={}, impacted={}, rock_it={}, result={}, energy={}, published_sample={}, post_write={}",
        child_state[0],
        child_state[1],
        child_state[2],
        child_state[3],
        child_state[4],
        child_state[5],
        child_state[6],
        child_state[7],
        child_state[8],
        child_state[9],
        child_state[10],
        child_state[11],
        child_state[12],
        child_state[13],
    );
}

fn log_ricochet_material_coverage(label: &str, counts: [u32; 10]) {
    log::info!(
        "[BALLISTICS_TELEMETRY] Ricochet material {label}: stone={}, dirt={}, grass={}, glass={}, metal={}, wood={}, organic={}, cloth={}, water={}, hollow_metal={}",
        counts[0],
        counts[1],
        counts[2],
        counts[3],
        counts[4],
        counts[5],
        counts[6],
        counts[7],
        counts[8],
        counts[9],
    );
}

fn log_ricochet_angle_coverage(candidates: [u32; 11], published: [u32; 11]) {
    let mut entries = Vec::with_capacity(candidates.len());
    for (index, (candidate, publication)) in candidates.into_iter().zip(published).enumerate() {
        if let Some(upper) = BallisticsTelemetrySnapshot::grazing_angle_upper_degrees().get(index) {
            entries.push(format!("<={upper}:{candidate}/{publication}"));
        } else {
            entries.push(format!(">90:{candidate}/{publication}"));
        }
    }
    log::info!(
        "[BALLISTICS_TELEMETRY] Ricochet angle candidate/published: {}",
        entries.join(", ")
    );
}

fn log_ricochet_depth(label: &str, counts: [u32; 6]) {
    let bounds = BallisticsTelemetrySnapshot::ricochet_depth_upper();
    let mut entries = Vec::with_capacity(counts.len());
    for (index, count) in counts.into_iter().enumerate() {
        if let Some(upper) = bounds.get(index) {
            entries.push(format!("<={upper}:{count}"));
        } else {
            entries.push(format!(
                ">{}:{count}",
                bounds.last().copied().unwrap_or_default()
            ));
        }
    }
    log::info!(
        "[BALLISTICS_TELEMETRY] Ricochet depth {label}: {}",
        entries.join(", ")
    );
}

fn log_ricochet_energy(label: &str, bounds: &[f32], counts: &[u32]) {
    let mut entries = Vec::with_capacity(counts.len());
    for (index, count) in counts.iter().copied().enumerate() {
        if let Some(upper) = bounds.get(index) {
            entries.push(format!("<={upper}:{count}"));
        } else {
            entries.push(format!(
                ">{}:{count}",
                bounds.last().copied().unwrap_or_default()
            ));
        }
    }
    log::info!(
        "[BALLISTICS_TELEMETRY] Ricochet energy {label}: {}",
        entries.join(", ")
    );
}

fn log_followup_histogram(label: &str, bounds: &[f32; 5], counts: [u32; 6]) {
    let mut entries = Vec::with_capacity(counts.len());
    for (index, count) in counts.into_iter().enumerate() {
        if let Some(upper) = bounds.get(index) {
            entries.push(format!("<={upper}:{count}"));
        } else {
            entries.push(format!(
                ">{}:{count}",
                bounds.last().copied().unwrap_or_default()
            ));
        }
    }
    log::info!(
        "[BALLISTICS_TELEMETRY] Followup {label}: {}",
        entries.join(", ")
    );
}

fn log_direction_error_histogram(label: &str, counts: [u32; 7]) {
    let bounds = telemetry::BallisticsTelemetrySnapshot::direction_error_upper_degrees();
    let mut entries = Vec::with_capacity(counts.len());
    for (index, count) in counts.into_iter().enumerate() {
        if let Some(upper) = bounds.get(index) {
            entries.push(format!("<={upper}:{count}"));
        } else {
            entries.push(format!(
                ">{}:{count}",
                bounds.last().copied().unwrap_or_default()
            ));
        }
    }
    log::info!("[BALLISTICS_TELEMETRY] {label}: {}", entries.join(", "));
}

fn log_grazing_histogram(bounds: &[u8; 10], counts: [u32; 11]) {
    log::info!("[BALLISTICS_TELEMETRY] Hard-world grazing angle");
    for (index, count) in counts.into_iter().enumerate() {
        if let Some(upper) = bounds.get(index) {
            log::info!("[BALLISTICS_TELEMETRY]   <= {upper:>2} deg : {count}");
        } else {
            log::info!(
                "[BALLISTICS_TELEMETRY]   >  {:>2} deg : {count}",
                bounds.last().copied().unwrap_or_default()
            );
        }
    }
}

fn log_update_histograms(snapshot: BallisticsTelemetrySnapshot) {
    const FRAME_LABELS: [&str; 7] = [
        "<=4ms",
        "<=8ms",
        "<=16.667ms",
        "<=33.333ms",
        "<=50ms",
        "<=100ms",
        ">100ms",
    ];
    const ERROR_LABELS: [&str; 6] = ["<=1%", "<=5%", "<=10%", "<=25%", "<=50%", ">50%"];

    log::info!("[BALLISTICS_TELEMETRY] Update frame delta");
    for (label, count) in FRAME_LABELS.into_iter().zip(snapshot.update_frame_time()) {
        log::info!("[BALLISTICS_TELEMETRY]   {label:>10} : {count}");
    }
    log::info!("[BALLISTICS_TELEMETRY] Native step error");
    for (label, count) in ERROR_LABELS.into_iter().zip(snapshot.step_error()) {
        log::info!("[BALLISTICS_TELEMETRY]   {label:>10} : {count}");
    }
}

fn log_histogram(bounds: &[u32; 10], counts: [u32; 11]) {
    log::info!("[BALLISTICS_TELEMETRY] Launch to first contact");
    for (index, count) in counts.into_iter().enumerate() {
        if let Some(upper) = bounds.get(index) {
            log::info!("[BALLISTICS_TELEMETRY]   <= {upper:>6} us : {count}");
        } else {
            log::info!(
                "[BALLISTICS_TELEMETRY]   >  {:>6} us : {count}",
                bounds.last().copied().unwrap_or_default()
            );
        }
    }
}

fn numeric_bool(field: &'static str, value: u8) -> Result<bool, BallisticsConfigError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(BallisticsConfigError::InvalidBoolean { field, value }),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PersistedConfig {
    #[serde(rename = "Ballistics")]
    ballistics: BallisticsSection,
    #[serde(rename = "Diagnostics")]
    diagnostics: DiagnosticsSection,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct BallisticsSection {
    #[serde(rename = "bEnabled")]
    enabled: u8,
    #[serde(rename = "bRicochet")]
    ricochet: u8,
    #[serde(rename = "iRicochetStoneEnergy")]
    ricochet_stone_energy: u8,
    #[serde(rename = "iRicochetDirtEnergy")]
    ricochet_dirt_energy: u8,
    #[serde(rename = "iRicochetGrassEnergy")]
    ricochet_grass_energy: u8,
    #[serde(rename = "iRicochetGlassEnergy")]
    ricochet_glass_energy: u8,
    #[serde(rename = "iRicochetMetalEnergy")]
    ricochet_metal_energy: u8,
    #[serde(rename = "iRicochetWoodEnergy")]
    ricochet_wood_energy: u8,
    #[serde(rename = "iRicochetOrganicEnergy")]
    ricochet_organic_energy: u8,
    #[serde(rename = "iRicochetClothEnergy")]
    ricochet_cloth_energy: u8,
    #[serde(rename = "iRicochetWaterEnergy")]
    ricochet_water_energy: u8,
    #[serde(rename = "iRicochetHollowMetalEnergy")]
    ricochet_hollow_metal_energy: u8,
}

impl Default for BallisticsSection {
    fn default() -> Self {
        let energy = RicochetEnergyConfig::DEFAULT;
        Self {
            enabled: 1,
            ricochet: 1,
            ricochet_stone_energy: energy.stone(),
            ricochet_dirt_energy: energy.dirt(),
            ricochet_grass_energy: energy.grass(),
            ricochet_glass_energy: energy.glass(),
            ricochet_metal_energy: energy.metal(),
            ricochet_wood_energy: energy.wood(),
            ricochet_organic_energy: energy.organic(),
            ricochet_cloth_energy: energy.cloth(),
            ricochet_water_energy: energy.water(),
            ricochet_hollow_metal_energy: energy.hollow_metal(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct DiagnosticsSection {
    #[serde(rename = "bBallisticsTrace")]
    ballistics_trace: u8,
    #[serde(rename = "bBallisticsSummary")]
    ballistics_summary: u8,
}

struct ConfigStore {
    sequence: AtomicU32,
    enabled: AtomicBool,
    ricochet_enabled: AtomicBool,
    ricochet_energy: [AtomicU8; ricochet::CANONICAL_MATERIAL_COUNT],
    trace_enabled: AtomicBool,
    summary_requested: AtomicBool,
}

impl ConfigStore {
    const fn new() -> Self {
        Self {
            sequence: AtomicU32::new(0),
            enabled: AtomicBool::new(false),
            ricochet_enabled: AtomicBool::new(false),
            ricochet_energy: [const { AtomicU8::new(0) }; ricochet::CANONICAL_MATERIAL_COUNT],
            trace_enabled: AtomicBool::new(false),
            summary_requested: AtomicBool::new(false),
        }
    }

    fn publish(&self, config: BallisticsConfig) {
        self.sequence.fetch_add(1, Ordering::AcqRel);
        self.enabled.store(config.enabled, Ordering::Relaxed);
        self.ricochet_enabled
            .store(config.ricochet_enabled, Ordering::Relaxed);
        for (destination, percentage) in self
            .ricochet_energy
            .iter()
            .zip(config.ricochet_energy.percentages())
        {
            destination.store(percentage, Ordering::Relaxed);
        }
        self.summary_requested
            .store(config.summary_requested, Ordering::Relaxed);
        self.trace_enabled
            .store(config.trace_enabled, Ordering::Relaxed);
        self.sequence.fetch_add(1, Ordering::Release);
    }

    fn load(&self) -> BallisticsConfig {
        loop {
            let before = self.sequence.load(Ordering::Acquire);
            if before & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }
            let config = BallisticsConfig {
                enabled: self.enabled.load(Ordering::Relaxed),
                ricochet_enabled: self.ricochet_enabled.load(Ordering::Relaxed),
                ricochet_energy: RicochetEnergyConfig::from_percentages(core::array::from_fn(
                    |index| self.ricochet_energy[index].load(Ordering::Relaxed),
                )),
                trace_enabled: self.trace_enabled.load(Ordering::Relaxed),
                summary_requested: self.summary_requested.load(Ordering::Relaxed),
            };
            if before == self.sequence.load(Ordering::Acquire) {
                return config;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BallisticsConfig, BallisticsConfigError, ConfigStore};

    #[test]
    fn diagnostics_parse_numeric_booleans_and_ignore_future_keys() {
        let config = BallisticsConfig::from_ini(
            "[Ballistics]\nbEnabled=1\niRicochetWoodEnergy=75\n[Diagnostics]\nbBallisticsTrace=1\nbBallisticsSummary=0\nfuture=42\n",
        )
        .unwrap();
        assert!(config.enabled());
        assert!(config.ricochet_enabled());
        assert!(config.trace_enabled());
        assert!(!config.summary_requested());
        assert_eq!(config.ricochet_energy().wood(), 75);
    }

    #[test]
    fn physical_flight_is_the_accepted_default() {
        assert!(BallisticsConfig::default().enabled());
        assert!(BallisticsConfig::default().ricochet_enabled());
        assert!(BallisticsConfig::from_ini("").unwrap().enabled());
        assert!(BallisticsConfig::from_ini("").unwrap().ricochet_enabled());
        assert!(!BallisticsConfig::default().trace_enabled());
        let energy = BallisticsConfig::default().ricochet_energy();
        assert_eq!(
            [
                energy.stone(),
                energy.dirt(),
                energy.grass(),
                energy.glass(),
                energy.metal(),
                energy.wood(),
                energy.organic(),
                energy.cloth(),
                energy.water(),
                energy.hollow_metal(),
            ],
            [36, 18, 15, 12, 56, 20, 0, 0, 10, 46]
        );
    }

    #[test]
    fn invalid_numeric_boolean_is_rejected() {
        assert!(matches!(
            BallisticsConfig::from_ini("[Diagnostics]\nbBallisticsTrace=2\n"),
            Err(BallisticsConfigError::InvalidBoolean { .. })
        ));
        assert!(matches!(
            BallisticsConfig::from_ini("[Ballistics]\nbEnabled=2\n"),
            Err(BallisticsConfigError::InvalidBoolean { .. })
        ));
        assert!(matches!(
            BallisticsConfig::from_ini("[Ballistics]\nbRicochet=2\n"),
            Err(BallisticsConfigError::InvalidBoolean { .. })
        ));
    }

    #[test]
    fn config_store_round_trips_one_coherent_material_policy() {
        let config = BallisticsConfig::from_ini(
            "[Ballistics]\niRicochetStoneEnergy=75\niRicochetMetalEnergy=1\n",
        )
        .unwrap();
        let store = ConfigStore::new();
        store.publish(config);

        assert_eq!(store.load(), config);
    }
}
