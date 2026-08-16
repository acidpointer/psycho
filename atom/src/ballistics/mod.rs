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
pub mod telemetry;

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use serde::Deserialize;
use thiserror::Error;

pub use context::{ProjectileCapability, ProjectileProfile, ShotContext, SourceKind};
pub use flight::{MAX_CHORD_SEGMENTS, ShadowFlight, ShadowFlightError, ShadowStep};
pub use native::classify_profile;
pub use telemetry::BallisticsTelemetrySnapshot;

static CONFIG: ConfigStore = ConfigStore::new();

/// MCM-owned settings for physical Ballistics and its diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BallisticsConfig {
    enabled: bool,
    trace_enabled: bool,
    summary_requested: bool,
}

impl Default for BallisticsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            trace_enabled: false,
            summary_requested: false,
        }
    }
}

impl BallisticsConfig {
    /// Deserialize Ballistics diagnostic keys from Atom's shared INI text.
    ///
    /// Unknown sections and keys are accepted. Numeric booleans must be `0`
    /// or `1`, matching MCM Extender's persisted representation.
    pub fn from_ini(text: &str) -> Result<Self, BallisticsConfigError> {
        let persisted: PersistedConfig = serini::from_str(text)?;
        Ok(Self {
            enabled: numeric_bool("Ballistics:bEnabled", persisted.ballistics.enabled)?,
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
    pub(crate) missile_update_predecessor: usize,
}

/// Return the coherently published Ballistics configuration.
pub fn current_config() -> BallisticsConfig {
    CONFIG.load()
}

pub(crate) fn publish_config(config: BallisticsConfig, qpc_frequency: i64) {
    let previous = CONFIG.load();
    if config.trace_enabled() && !previous.trace_enabled() {
        if let Some(observations) = pool::observations() {
            let _ = observations.clear();
        }
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
        missile_update_predecessor: predecessors.missile_update,
    })
}

pub(crate) fn clear_observations() {
    let Some(observations) = pool::observations() else {
        return;
    };
    let summary = observations.clear();
    if telemetry::enabled() {
        telemetry::record_expired_misses(summary.misses);
    }
}

pub(crate) fn log_requested_summary() {
    let snapshot = telemetry::snapshot();
    let source = snapshot.launches_by_source();
    let capability = snapshot.launches_by_capability();
    let counts = snapshot.projectile_counts();
    log::info!("[BALLISTICS_TELEMETRY] ---------------------------------------------------");
    log::info!("[BALLISTICS_TELEMETRY] Requested native lifecycle summary");
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
}

impl Default for BallisticsSection {
    fn default() -> Self {
        Self { enabled: 1 }
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
    trace_enabled: AtomicBool,
    summary_requested: AtomicBool,
}

impl ConfigStore {
    const fn new() -> Self {
        Self {
            sequence: AtomicU32::new(0),
            enabled: AtomicBool::new(false),
            trace_enabled: AtomicBool::new(false),
            summary_requested: AtomicBool::new(false),
        }
    }

    fn publish(&self, config: BallisticsConfig) {
        self.sequence.fetch_add(1, Ordering::AcqRel);
        self.enabled.store(config.enabled, Ordering::Relaxed);
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
    use super::{BallisticsConfig, BallisticsConfigError};

    #[test]
    fn diagnostics_parse_numeric_booleans_and_ignore_future_keys() {
        let config = BallisticsConfig::from_ini(
            "[Ballistics]\nbEnabled=1\n[Diagnostics]\nbBallisticsTrace=1\nbBallisticsSummary=0\nfuture=42\n",
        )
        .unwrap();
        assert!(config.enabled());
        assert!(config.trace_enabled());
        assert!(!config.summary_requested());
    }

    #[test]
    fn physical_flight_is_the_accepted_default() {
        assert!(BallisticsConfig::default().enabled());
        assert!(BallisticsConfig::from_ini("").unwrap().enabled());
        assert!(!BallisticsConfig::default().trace_enabled());
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
    }
}
