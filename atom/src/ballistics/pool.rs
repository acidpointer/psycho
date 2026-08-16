//! Fixed-capacity launch correlation without heap allocation or locks.
//!
//! Each live projectile address is an opaque key into a bounded open-addressed
//! table. Slot payload fields are atomic because callbacks are not assumed to
//! share a thread. Publication changes `RESERVED` to `LIVE` with release
//! ordering; readers acquire that state before reading the immutable payload.

use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use std::sync::OnceLock;

use super::ShotContext;
use super::native::RuntimeFlightPath;

const EMPTY: u8 = 0;
const RESERVED: u8 = 1;
const LIVE: u8 = 2;
const FLAG_ACTOR_HIT: u8 = 1 << 0;
const FLAG_CONTACT: u8 = 1 << 1;
const FLAG_UPDATE: u8 = 1 << 2;
const TABLE_CAPACITY: usize = 2048;
const PROBE_LIMIT: usize = 32;

static OBSERVATIONS: OnceLock<Box<ObservationPool<TABLE_CAPACITY>>> = OnceLock::new();

pub(crate) fn initialize() {
    // The large table is intentionally allocated on first use at DeferredInit
    // instead of occupying loader-visible `.bss` before xNVSE's safe boundary.
    let _ = OBSERVATIONS.get_or_init(|| Box::new(ObservationPool::new()));
}

#[inline]
pub(crate) fn observations() -> Option<&'static ObservationPool<TABLE_CAPACITY>> {
    OBSERVATIONS.get().map(Box::as_ref)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InsertOutcome {
    Added,
    ReplacedExpired,
    ReplacedGeneration,
    Overflow,
    InvalidToken,
    LifecycleRace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Correlation {
    First,
    Duplicate,
    Missing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Contact {
    pub(crate) correlation: Correlation,
    pub(crate) actor_hit: bool,
    pub(crate) launch_tick: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UpdateObservation {
    pub(crate) correlation: Correlation,
    pub(crate) capability: super::ProjectileCapability,
    pub(crate) selected_path: RuntimeFlightPath,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ClearSummary {
    pub(crate) live: u32,
    pub(crate) misses: u32,
}

struct Slot {
    state: AtomicU8,
    observation_flags: AtomicU8,
    token: AtomicU32,
    generation: AtomicU32,
    launch_tick: AtomicU32,
    sequence: AtomicU32,
    source_kind: AtomicU8,
    capability: AtomicU8,
    selected_path: AtomicU8,
    source_token: AtomicU32,
    weapon_token: AtomicU32,
    projectile_form_token: AtomicU32,
    projectile_type_bits: AtomicU32,
    projectile_flags: AtomicU32,
    gravity: AtomicU32,
    speed: AtomicU32,
    range: AtomicU32,
    position: [AtomicU32; 3],
    rotation: [AtomicU32; 2],
    launch_flags: AtomicU8,
}

impl Slot {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            observation_flags: AtomicU8::new(0),
            token: AtomicU32::new(0),
            generation: AtomicU32::new(0),
            launch_tick: AtomicU32::new(0),
            sequence: AtomicU32::new(0),
            source_kind: AtomicU8::new(0),
            capability: AtomicU8::new(0),
            selected_path: AtomicU8::new(0),
            source_token: AtomicU32::new(0),
            weapon_token: AtomicU32::new(0),
            projectile_form_token: AtomicU32::new(0),
            projectile_type_bits: AtomicU32::new(0),
            projectile_flags: AtomicU32::new(0),
            gravity: AtomicU32::new(0),
            speed: AtomicU32::new(0),
            range: AtomicU32::new(0),
            position: [const { AtomicU32::new(0) }; 3],
            rotation: [const { AtomicU32::new(0) }; 2],
            launch_flags: AtomicU8::new(0),
        }
    }

    fn write_payload(
        &self,
        token: u32,
        context: ShotContext,
        selected_path: RuntimeFlightPath,
        launch_tick: u32,
    ) {
        let projectile = context.projectile();
        self.token.store(token, Ordering::Relaxed);
        self.launch_tick.store(launch_tick, Ordering::Relaxed);
        self.sequence.store(context.sequence(), Ordering::Relaxed);
        self.source_kind
            .store(context.source_kind() as u8, Ordering::Relaxed);
        self.capability
            .store(context.capability() as u8, Ordering::Relaxed);
        self.selected_path
            .store(encode_flight_path(selected_path), Ordering::Relaxed);
        self.source_token
            .store(context.source_token(), Ordering::Relaxed);
        self.weapon_token
            .store(context.weapon_token(), Ordering::Relaxed);
        self.projectile_form_token
            .store(projectile.form_token(), Ordering::Relaxed);
        self.projectile_type_bits
            .store(projectile.type_bits(), Ordering::Relaxed);
        self.projectile_flags
            .store(u32::from(projectile.flags()), Ordering::Relaxed);
        self.gravity
            .store(projectile.gravity().to_bits(), Ordering::Relaxed);
        self.speed
            .store(projectile.speed().to_bits(), Ordering::Relaxed);
        self.range
            .store(projectile.range().to_bits(), Ordering::Relaxed);
        for (target, value) in self.position.iter().zip(context.position()) {
            target.store(value.to_bits(), Ordering::Relaxed);
        }
        for (target, value) in self.rotation.iter().zip(context.rotation()) {
            target.store(value.to_bits(), Ordering::Relaxed);
        }
        let flags = u8::from(context.always_hit())
            | (u8::from(context.ignore_gravity()) << 1)
            | (u8::from(context.has_live_target()) << 2)
            | (u8::from(projectile.has_explosion()) << 3);
        self.launch_flags.store(flags, Ordering::Relaxed);
        self.observation_flags.store(0, Ordering::Relaxed);
        self.generation.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) struct ObservationPool<const N: usize> {
    lifecycle_sequence: AtomicU32,
    slots: [Slot; N],
}

impl<const N: usize> ObservationPool<N> {
    pub(crate) const fn new() -> Self {
        assert!(N.is_power_of_two());
        Self {
            lifecycle_sequence: AtomicU32::new(0),
            slots: [const { Slot::new() }; N],
        }
    }

    pub(crate) fn insert(
        &self,
        token: u32,
        context: ShotContext,
        selected_path: RuntimeFlightPath,
        launch_tick: u32,
        max_age_ticks: u32,
    ) -> InsertOutcome {
        if token == 0 {
            return InsertOutcome::InvalidToken;
        }
        let lifecycle = self.lifecycle_sequence.load(Ordering::Acquire);
        if lifecycle & 1 != 0 {
            return InsertOutcome::LifecycleRace;
        }
        let start = hash(token) & (N - 1);
        for probe in 0..PROBE_LIMIT.min(N) {
            let slot = &self.slots[(start + probe) & (N - 1)];
            let state = slot.state.load(Ordering::Acquire);
            if state == EMPTY
                && slot
                    .state
                    .compare_exchange(EMPTY, RESERVED, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                return if self.publish_insert(
                    slot,
                    token,
                    context,
                    selected_path,
                    launch_tick,
                    lifecycle,
                ) {
                    InsertOutcome::Added
                } else {
                    InsertOutcome::LifecycleRace
                };
            }
            if state != LIVE {
                continue;
            }

            let same_token = slot.token.load(Ordering::Relaxed) == token;
            let old_tick = slot.launch_tick.load(Ordering::Relaxed);
            let expired = max_age_ticks != 0
                && launch_tick != 0
                && old_tick != 0
                && launch_tick.wrapping_sub(old_tick) > max_age_ticks;
            if (same_token || expired)
                && slot
                    .state
                    .compare_exchange(LIVE, RESERVED, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                let outcome = if same_token {
                    InsertOutcome::ReplacedGeneration
                } else {
                    InsertOutcome::ReplacedExpired
                };
                return if self.publish_insert(
                    slot,
                    token,
                    context,
                    selected_path,
                    launch_tick,
                    lifecycle,
                ) {
                    outcome
                } else {
                    InsertOutcome::LifecycleRace
                };
            }
        }
        InsertOutcome::Overflow
    }

    pub(crate) fn record_actor_hit(&self, token: u32) -> Correlation {
        let Some(slot) = self.find(token) else {
            return Correlation::Missing;
        };
        let previous = slot
            .observation_flags
            .fetch_or(FLAG_ACTOR_HIT, Ordering::Relaxed);
        if previous & FLAG_ACTOR_HIT == 0 {
            Correlation::First
        } else {
            Correlation::Duplicate
        }
    }

    pub(crate) fn record_contact(&self, token: u32) -> Contact {
        let Some(slot) = self.find(token) else {
            return Contact {
                correlation: Correlation::Missing,
                actor_hit: false,
                launch_tick: 0,
            };
        };
        let previous = slot
            .observation_flags
            .fetch_or(FLAG_CONTACT, Ordering::Relaxed);
        Contact {
            correlation: if previous & FLAG_CONTACT == 0 {
                Correlation::First
            } else {
                Correlation::Duplicate
            },
            actor_hit: previous & FLAG_ACTOR_HIT != 0,
            launch_tick: slot.launch_tick.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn record_update(&self, token: u32) -> Option<UpdateObservation> {
        let slot = self.find(token)?;
        let previous = slot
            .observation_flags
            .fetch_or(FLAG_UPDATE, Ordering::Relaxed);
        Some(UpdateObservation {
            correlation: if previous & FLAG_UPDATE == 0 {
                Correlation::First
            } else {
                Correlation::Duplicate
            },
            capability: decode_capability(slot.capability.load(Ordering::Relaxed)),
            selected_path: decode_flight_path(slot.selected_path.load(Ordering::Relaxed)),
        })
    }

    pub(crate) fn clear(&self) -> ClearSummary {
        // Odd sequence values close admission while lifecycle teardown sweeps
        // the table. A writer that began on the prior even value verifies it
        // again before publication and drops its telemetry-only reservation.
        self.lifecycle_sequence.fetch_add(1, Ordering::AcqRel);
        let mut summary = ClearSummary::default();
        for slot in &self.slots {
            let state = slot.state.swap(EMPTY, Ordering::AcqRel);
            if state != LIVE {
                continue;
            }
            summary.live = summary.live.saturating_add(1);
            if slot.observation_flags.load(Ordering::Relaxed) & FLAG_CONTACT == 0 {
                summary.misses = summary.misses.saturating_add(1);
            }
        }
        self.lifecycle_sequence.fetch_add(1, Ordering::Release);
        summary
    }

    fn publish_insert(
        &self,
        slot: &Slot,
        token: u32,
        context: ShotContext,
        selected_path: RuntimeFlightPath,
        launch_tick: u32,
        lifecycle: u32,
    ) -> bool {
        slot.write_payload(token, context, selected_path, launch_tick);
        slot.state.store(LIVE, Ordering::Release);
        if self.lifecycle_sequence.load(Ordering::Acquire) != lifecycle {
            let _ = slot
                .state
                .compare_exchange(LIVE, EMPTY, Ordering::AcqRel, Ordering::Acquire);
            return false;
        }
        true
    }

    fn find(&self, token: u32) -> Option<&Slot> {
        if token == 0 {
            return None;
        }
        let start = hash(token) & (N - 1);
        for probe in 0..PROBE_LIMIT.min(N) {
            let slot = &self.slots[(start + probe) & (N - 1)];
            if slot.state.load(Ordering::Acquire) == LIVE
                && slot.token.load(Ordering::Relaxed) == token
            {
                return Some(slot);
            }
        }
        None
    }
}

fn hash(token: u32) -> usize {
    // Pointer alignment makes low bits weak. This is the 32-bit finalizer from
    // MurmurHash3, used only to distribute opaque addresses in the fixed table.
    let mut value = token;
    value ^= value >> 16;
    value = value.wrapping_mul(0x85EB_CA6B);
    value ^= value >> 13;
    value = value.wrapping_mul(0xC2B2_AE35);
    value ^= value >> 16;
    value as usize
}

fn decode_capability(value: u8) -> super::ProjectileCapability {
    use super::ProjectileCapability;

    match value {
        0 => ProjectileCapability::DiscretePhysical,
        1 => ProjectileCapability::DiscreteHitscan,
        2 => ProjectileCapability::ExplosiveMissile,
        3 => ProjectileCapability::GrenadeOrThrown,
        4 => ProjectileCapability::Beam,
        5 => ProjectileCapability::Flame,
        6 => ProjectileCapability::ContinuousBeam,
        _ => ProjectileCapability::Unknown,
    }
}

const fn encode_flight_path(path: RuntimeFlightPath) -> u8 {
    match path {
        RuntimeFlightPath::Hitscan => 0,
        RuntimeFlightPath::Physical => 1,
        RuntimeFlightPath::Ambiguous => 2,
    }
}

const fn decode_flight_path(value: u8) -> RuntimeFlightPath {
    match value {
        0 => RuntimeFlightPath::Hitscan,
        1 => RuntimeFlightPath::Physical,
        _ => RuntimeFlightPath::Ambiguous,
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::{Correlation, InsertOutcome, ObservationPool};
    use crate::ballistics::native::RuntimeFlightPath;
    use crate::ballistics::{ProjectileCapability, ProjectileProfile, ShotContext, SourceKind};

    fn context(sequence: u32) -> ShotContext {
        ShotContext::new(
            sequence,
            SourceKind::Player,
            10,
            20,
            ProjectileProfile::new(30, 0x10000, 1, 0.1, 1000.0, 5000.0, false),
            ProjectileCapability::DiscreteHitscan,
            [1.0, 2.0, 3.0],
            [0.5, 0.25],
            false,
            false,
            false,
        )
    }

    #[test]
    fn address_reuse_supersedes_the_old_generation() {
        let pool = ObservationPool::<8>::new();
        assert_eq!(
            pool.insert(0x1000, context(1), RuntimeFlightPath::Hitscan, 10, 100,),
            InsertOutcome::Added
        );
        assert_eq!(
            pool.insert(0x1000, context(2), RuntimeFlightPath::Physical, 20, 100,),
            InsertOutcome::ReplacedGeneration
        );
        assert_eq!(pool.record_actor_hit(0x1000), Correlation::First);
        assert_eq!(pool.record_actor_hit(0x1000), Correlation::Duplicate);
    }

    #[test]
    fn clear_reports_uncontacted_live_rounds_as_misses() {
        let pool = ObservationPool::<8>::new();
        pool.insert(0x1000, context(1), RuntimeFlightPath::Hitscan, 10, 100);
        pool.insert(0x2000, context(2), RuntimeFlightPath::Physical, 10, 100);
        let _ = pool.record_contact(0x1000);

        let summary = pool.clear();
        assert_eq!(summary.live, 2);
        assert_eq!(summary.misses, 1);
        assert_eq!(pool.record_actor_hit(0x1000), Correlation::Missing);
    }

    #[test]
    fn update_observation_preserves_capability_and_first_call_state() {
        let pool = ObservationPool::<8>::new();
        pool.insert(0x1000, context(1), RuntimeFlightPath::Physical, 10, 100);

        let first = pool.record_update(0x1000).unwrap();
        assert_eq!(first.correlation, Correlation::First);
        assert_eq!(first.capability, ProjectileCapability::DiscreteHitscan);
        assert_eq!(first.selected_path, RuntimeFlightPath::Physical);

        let repeated = pool.record_update(0x1000).unwrap();
        assert_eq!(repeated.correlation, Correlation::Duplicate);
        assert_eq!(repeated.selected_path, RuntimeFlightPath::Physical);
    }

    #[test]
    fn production_pool_stays_within_the_documented_memory_budget() {
        assert_eq!(size_of::<ObservationPool<2048>>(), 152 * 1024 + 4);
        assert!(size_of::<ObservationPool<2048>>() <= 1024 * 1024);
    }
}
