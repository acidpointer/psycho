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
use super::ricochet::{ContactSignature, FollowupContact};

const EMPTY: u8 = 0;
const RESERVED: u8 = 1;
const LIVE: u8 = 2;
const FLAG_ACTOR_HIT: u8 = 1 << 0;
const FLAG_CONTACT: u8 = 1 << 1;
const FLAG_UPDATE: u8 = 1 << 2;
const RICOCHET_GENERATION_MASK: u32 = 0x1FFF_FFFF;
const RICOCHET_AVAILABLE: u32 = 0x0000_0000;
const RICOCHET_RESERVED: u32 = 0x2000_0000;
const RICOCHET_PUBLISHED: u32 = 0x4000_0000;
const RICOCHET_PROBING: u32 = 0x6000_0000;
const RICOCHET_CONFIRMED: u32 = 0x8000_0000;
const RICOCHET_FAILED: u32 = 0xA000_0000;
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
    ReplacedExpiredPendingRicochet,
    ReplacedGeneration,
    ReplacedGenerationPendingRicochet,
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

/// Generation-owned expectation claimed by exactly one post-bounce update.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct FirstStepProbe {
    pub(crate) lifecycle: u32,
    pub(crate) generation: u32,
    pub(crate) source_kind: super::SourceKind,
    pub(crate) bounce_depth: u32,
    pub(crate) raw_material: u32,
    pub(crate) expected_direction: [f32; 3],
    pub(crate) oriented_normal: [f32; 3],
}

/// Immutable launch context needed to classify a common-impact callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ImpactObservation {
    pub(crate) lifecycle: u32,
    pub(crate) generation: u32,
    pub(crate) source_kind: super::SourceKind,
    pub(crate) capability: super::ProjectileCapability,
    pub(crate) selected_path: RuntimeFlightPath,
    pub(crate) actor_hit: bool,
    pub(crate) projectile_flags: u16,
    pub(crate) always_hit: bool,
    pub(crate) ignore_gravity: bool,
    pub(crate) has_live_target: bool,
    pub(crate) has_explosion: bool,
    pub(crate) ricochet_state: RicochetState,
    pub(crate) bounce_depth: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RicochetState {
    Available,
    Reserved,
    Published,
    Probing,
    Confirmed,
    Failed,
}

/// Exclusive right to replace one terminal projectile with its next child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RicochetReservation {
    lifecycle: u32,
    generation: u32,
    prior_state: RicochetState,
    bounce_depth: u32,
}

impl RicochetReservation {
    pub(crate) const fn bounce_depth(self) -> u32 {
        self.bounce_depth
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ClearSummary {
    pub(crate) live: u32,
    pub(crate) misses: u32,
    pub(crate) pending_ricochets: u32,
}

struct Slot {
    state: AtomicU8,
    observation_flags: AtomicU8,
    ricochet_state: AtomicU32,
    bounce_depth: AtomicU32,
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
    contact_target: AtomicU32,
    contact_material: AtomicU32,
    contact_distance: AtomicU32,
    contact_point: [AtomicU32; 3],
    contact_normal: [AtomicU32; 3],
    expected_direction: [AtomicU32; 3],
}

impl Slot {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            observation_flags: AtomicU8::new(0),
            ricochet_state: AtomicU32::new(RICOCHET_AVAILABLE),
            bounce_depth: AtomicU32::new(0),
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
            contact_target: AtomicU32::new(0),
            contact_material: AtomicU32::new(0),
            contact_distance: AtomicU32::new(0),
            contact_point: [const { AtomicU32::new(0) }; 3],
            contact_normal: [const { AtomicU32::new(0) }; 3],
            expected_direction: [const { AtomicU32::new(0) }; 3],
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
        let generation =
            self.generation.load(Ordering::Relaxed).wrapping_add(1) & RICOCHET_GENERATION_MASK;
        self.generation.store(generation, Ordering::Relaxed);
        self.ricochet_state.store(
            ricochet_word(generation, RICOCHET_AVAILABLE),
            Ordering::Relaxed,
        );
        self.bounce_depth.store(0, Ordering::Relaxed);
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
                let pending_ricochet = ricochet_is_pending(decode_ricochet_state(
                    slot.ricochet_state.load(Ordering::Acquire),
                ));
                let outcome = match (same_token, pending_ricochet) {
                    (true, true) => InsertOutcome::ReplacedGenerationPendingRicochet,
                    (true, false) => InsertOutcome::ReplacedGeneration,
                    (false, true) => InsertOutcome::ReplacedExpiredPendingRicochet,
                    (false, false) => InsertOutcome::ReplacedExpired,
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

    /// Copy the immutable launch classification without changing correlation state.
    pub(crate) fn impact_observation(&self, token: u32) -> Option<ImpactObservation> {
        let lifecycle = self.lifecycle_sequence.load(Ordering::Acquire);
        if lifecycle & 1 != 0 {
            return None;
        }
        let slot = self.find(token)?;
        let generation = slot.generation.load(Ordering::Acquire);
        let launch_flags = slot.launch_flags.load(Ordering::Relaxed);
        let ricochet_word = slot.ricochet_state.load(Ordering::Acquire);
        if ricochet_word & RICOCHET_GENERATION_MASK != generation {
            return None;
        }
        let observation = ImpactObservation {
            lifecycle,
            generation,
            source_kind: decode_source_kind(slot.source_kind.load(Ordering::Relaxed)),
            capability: decode_capability(slot.capability.load(Ordering::Relaxed)),
            selected_path: decode_flight_path(slot.selected_path.load(Ordering::Relaxed)),
            actor_hit: slot.observation_flags.load(Ordering::Relaxed) & FLAG_ACTOR_HIT != 0,
            projectile_flags: slot.projectile_flags.load(Ordering::Relaxed) as u16,
            always_hit: launch_flags & (1 << 0) != 0,
            ignore_gravity: launch_flags & (1 << 1) != 0,
            has_live_target: launch_flags & (1 << 2) != 0,
            has_explosion: launch_flags & (1 << 3) != 0,
            ricochet_state: decode_ricochet_state(ricochet_word),
            bounce_depth: slot.bounce_depth.load(Ordering::Relaxed),
        };
        if slot.state.load(Ordering::Acquire) == LIVE
            && slot.token.load(Ordering::Relaxed) == token
            && slot.generation.load(Ordering::Acquire) == generation
            && self.lifecycle_sequence.load(Ordering::Acquire) == lifecycle
        {
            Some(observation)
        } else {
            None
        }
    }

    pub(crate) fn reserve_ricochet(
        &self,
        token: u32,
        generation: u32,
        lifecycle: u32,
    ) -> Option<RicochetReservation> {
        if lifecycle & 1 != 0 || self.lifecycle_sequence.load(Ordering::Acquire) != lifecycle {
            return None;
        }
        let slot = self.find_generation(token, generation)?;
        let current = slot.ricochet_state.load(Ordering::Acquire);
        if current & RICOCHET_GENERATION_MASK != generation {
            return None;
        }
        let prior_state = decode_ricochet_state(current);
        if !matches!(
            prior_state,
            RicochetState::Available | RicochetState::Confirmed
        ) {
            return None;
        }
        if slot
            .ricochet_state
            .compare_exchange(
                current,
                ricochet_word(generation, RICOCHET_RESERVED),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return None;
        }
        let reservation = RicochetReservation {
            lifecycle,
            generation,
            prior_state,
            bounce_depth: slot.bounce_depth.load(Ordering::Relaxed),
        };
        if self.lifecycle_sequence.load(Ordering::Acquire) == lifecycle {
            Some(reservation)
        } else {
            self.cancel_ricochet(token, reservation);
            None
        }
    }

    pub(crate) fn cancel_ricochet(&self, token: u32, reservation: RicochetReservation) {
        let Some(slot) = self.find_generation(token, reservation.generation) else {
            return;
        };
        let _ = slot.ricochet_state.compare_exchange(
            ricochet_word(reservation.generation, RICOCHET_RESERVED),
            ricochet_word(
                reservation.generation,
                encode_ricochet_state(reservation.prior_state),
            ),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    /// Replace one terminal parent observation with its freshly spawned child.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn publish_ricochet_child(
        &self,
        parent_token: u32,
        reservation: RicochetReservation,
        child_token: u32,
        child_context: ShotContext,
        launch_tick: u32,
        contact: ContactSignature,
        expected_direction: [f32; 3],
    ) -> bool {
        let parent_generation = reservation.generation;
        let lifecycle = reservation.lifecycle;
        if child_token == 0
            || child_token == parent_token
            || lifecycle & 1 != 0
            || self.lifecycle_sequence.load(Ordering::Acquire) != lifecycle
        {
            return false;
        }
        let Some(parent_slot) = self.find_generation(parent_token, parent_generation) else {
            return false;
        };
        if parent_slot
            .state
            .compare_exchange(LIVE, RESERVED, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        if parent_slot.token.load(Ordering::Relaxed) != parent_token
            || parent_slot.generation.load(Ordering::Acquire) != parent_generation
            || parent_slot.ricochet_state.load(Ordering::Acquire)
                != ricochet_word(parent_generation, RICOCHET_RESERVED)
            || self.lifecycle_sequence.load(Ordering::Acquire) != lifecycle
        {
            self.release_transaction_slot(parent_slot, lifecycle);
            return false;
        }

        let child_start = hash(child_token) & (N - 1);
        let mut child_slot = None;
        for probe in 0..PROBE_LIMIT.min(N) {
            let candidate = &self.slots[(child_start + probe) & (N - 1)];
            let state = candidate.state.load(Ordering::Acquire);
            let replace_stale_child =
                state == LIVE && candidate.token.load(Ordering::Relaxed) == child_token;
            if (state == EMPTY || replace_stale_child)
                && candidate
                    .state
                    .compare_exchange(state, RESERVED, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                child_slot = Some(candidate);
                break;
            }
        }
        let Some(child_slot) = child_slot else {
            self.release_transaction_slot(parent_slot, lifecycle);
            return false;
        };
        if self.lifecycle_sequence.load(Ordering::Acquire) != lifecycle {
            child_slot.state.store(EMPTY, Ordering::Release);
            parent_slot.state.store(EMPTY, Ordering::Release);
            return false;
        }

        child_slot.write_payload(
            child_token,
            child_context,
            RuntimeFlightPath::Physical,
            launch_tick,
        );
        let child_generation = child_slot.generation.load(Ordering::Relaxed);
        child_slot
            .contact_target
            .store(contact.target_token, Ordering::Relaxed);
        child_slot
            .contact_material
            .store(contact.raw_material, Ordering::Relaxed);
        child_slot
            .contact_distance
            .store(contact.distance_travelled.to_bits(), Ordering::Relaxed);
        for (target, value) in child_slot.contact_point.iter().zip(contact.point) {
            target.store(value.to_bits(), Ordering::Relaxed);
        }
        for (target, value) in child_slot
            .contact_normal
            .iter()
            .zip(contact.oriented_normal)
        {
            target.store(value.to_bits(), Ordering::Relaxed);
        }
        for (target, value) in child_slot.expected_direction.iter().zip(expected_direction) {
            target.store(value.to_bits(), Ordering::Relaxed);
        }
        child_slot.ricochet_state.store(
            ricochet_word(child_generation, RICOCHET_PUBLISHED),
            Ordering::Relaxed,
        );
        let Some(child_depth) = reservation.bounce_depth.checked_add(1) else {
            child_slot.state.store(EMPTY, Ordering::Release);
            self.release_transaction_slot(parent_slot, lifecycle);
            return false;
        };
        child_slot
            .bounce_depth
            .store(child_depth, Ordering::Relaxed);
        child_slot.state.store(LIVE, Ordering::Release);
        parent_slot.state.store(EMPTY, Ordering::Release);
        if self.lifecycle_sequence.load(Ordering::Acquire) != lifecycle {
            let _ =
                child_slot
                    .state
                    .compare_exchange(LIVE, EMPTY, Ordering::AcqRel, Ordering::Acquire);
            return false;
        }
        true
    }

    /// Claim the first native update after a published reflection.
    pub(crate) fn reserve_first_step(&self, token: u32) -> Option<FirstStepProbe> {
        let lifecycle = self.lifecycle_sequence.load(Ordering::Acquire);
        if lifecycle & 1 != 0 {
            return None;
        }
        let slot = self.find(token)?;
        let generation = slot.generation.load(Ordering::Acquire);
        slot.ricochet_state
            .compare_exchange(
                ricochet_word(generation, RICOCHET_PUBLISHED),
                ricochet_word(generation, RICOCHET_PROBING),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;
        self.probing_first_step(token, lifecycle, generation)
    }

    /// Snapshot the generation currently claimed by the Missile update wrapper.
    pub(crate) fn active_first_step(&self, token: u32) -> Option<FirstStepProbe> {
        let lifecycle = self.lifecycle_sequence.load(Ordering::Acquire);
        if lifecycle & 1 != 0 {
            return None;
        }
        let slot = self.find(token)?;
        let generation = slot.generation.load(Ordering::Acquire);
        self.probing_first_step(token, lifecycle, generation)
    }

    fn probing_first_step(
        &self,
        token: u32,
        lifecycle: u32,
        generation: u32,
    ) -> Option<FirstStepProbe> {
        let slot = self.find_generation(token, generation)?;
        if slot.ricochet_state.load(Ordering::Acquire)
            != ricochet_word(generation, RICOCHET_PROBING)
        {
            return None;
        }
        let probe = FirstStepProbe {
            lifecycle,
            generation,
            source_kind: decode_source_kind(slot.source_kind.load(Ordering::Relaxed)),
            bounce_depth: slot.bounce_depth.load(Ordering::Relaxed),
            raw_material: slot.contact_material.load(Ordering::Relaxed),
            expected_direction: load_f32_array(&slot.expected_direction),
            oriented_normal: load_f32_array(&slot.contact_normal),
        };
        if slot.state.load(Ordering::Acquire) == LIVE
            && slot.token.load(Ordering::Relaxed) == token
            && slot.generation.load(Ordering::Acquire) == generation
            && slot.ricochet_state.load(Ordering::Acquire)
                == ricochet_word(generation, RICOCHET_PROBING)
            && self.lifecycle_sequence.load(Ordering::Acquire) == lifecycle
        {
            Some(probe)
        } else {
            None
        }
    }

    /// Complete the single claimed post-bounce update observation.
    pub(crate) fn complete_first_step(
        &self,
        token: u32,
        probe: FirstStepProbe,
        confirmed: bool,
    ) -> bool {
        if probe.lifecycle & 1 != 0
            || self.lifecycle_sequence.load(Ordering::Acquire) != probe.lifecycle
        {
            return false;
        }
        let Some(slot) = self.find_generation(token, probe.generation) else {
            return false;
        };
        let target = if confirmed {
            RICOCHET_CONFIRMED
        } else {
            RICOCHET_FAILED
        };
        slot.ricochet_state
            .compare_exchange(
                ricochet_word(probe.generation, RICOCHET_PROBING),
                ricochet_word(probe.generation, target),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Describe a later child contact without changing native impact policy.
    pub(crate) fn followup_contact(
        &self,
        token: u32,
        generation: u32,
        lifecycle: u32,
        target_token: u32,
        point: [f32; 3],
        raw_material: u32,
        distance_travelled: f32,
        direction: [f32; 3],
    ) -> Option<FollowupContact> {
        if lifecycle & 1 != 0 || self.lifecycle_sequence.load(Ordering::Acquire) != lifecycle {
            return None;
        }
        let Some(slot) = self.find_generation(token, generation) else {
            return None;
        };
        let current = slot.ricochet_state.load(Ordering::Acquire);
        if current & RICOCHET_GENERATION_MASK != generation
            || !ricochet_is_after_publication(decode_ricochet_state(current))
        {
            return None;
        }
        let contact = ContactSignature {
            target_token: slot.contact_target.load(Ordering::Relaxed),
            point: load_f32_array(&slot.contact_point),
            oriented_normal: load_f32_array(&slot.contact_normal),
            raw_material: slot.contact_material.load(Ordering::Relaxed),
            distance_travelled: f32::from_bits(slot.contact_distance.load(Ordering::Relaxed)),
        };
        let followup = contact.followup_contact(
            target_token,
            point,
            raw_material,
            distance_travelled,
            direction,
        );
        if slot.state.load(Ordering::Acquire) == LIVE
            && slot.token.load(Ordering::Relaxed) == token
            && slot.generation.load(Ordering::Acquire) == generation
            && self.lifecycle_sequence.load(Ordering::Acquire) == lifecycle
        {
            Some(followup)
        } else {
            None
        }
    }

    pub(crate) fn clear(&self) -> ClearSummary {
        // Odd sequence values close admission while lifecycle teardown sweeps
        // the table. A writer or ricochet transaction that began on the prior
        // even value verifies it again before publishing gameplay state.
        self.lifecycle_sequence.fetch_add(1, Ordering::AcqRel);
        let mut summary = ClearSummary::default();
        for slot in &self.slots {
            if slot
                .state
                .compare_exchange(LIVE, EMPTY, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            summary.live = summary.live.saturating_add(1);
            if slot.observation_flags.load(Ordering::Relaxed) & FLAG_CONTACT == 0 {
                summary.misses = summary.misses.saturating_add(1);
            }
            if ricochet_is_pending(decode_ricochet_state(
                slot.ricochet_state.load(Ordering::Acquire),
            )) {
                summary.pending_ricochets = summary.pending_ricochets.saturating_add(1);
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

    fn find_generation(&self, token: u32, generation: u32) -> Option<&Slot> {
        let slot = self.find(token)?;
        (slot.generation.load(Ordering::Acquire) == generation).then_some(slot)
    }

    fn release_transaction_slot(&self, slot: &Slot, lifecycle: u32) {
        if self.lifecycle_sequence.load(Ordering::Acquire) == lifecycle {
            slot.state.store(LIVE, Ordering::Release);
        } else {
            slot.state.store(EMPTY, Ordering::Release);
        }
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

fn decode_source_kind(value: u8) -> super::SourceKind {
    use super::SourceKind;

    match value {
        0 => SourceKind::Player,
        1 => SourceKind::Actor,
        _ => SourceKind::Unknown,
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

const fn ricochet_word(generation: u32, state: u32) -> u32 {
    (generation & RICOCHET_GENERATION_MASK) | state
}

const fn encode_ricochet_state(state: RicochetState) -> u32 {
    match state {
        RicochetState::Available => RICOCHET_AVAILABLE,
        RicochetState::Reserved => RICOCHET_RESERVED,
        RicochetState::Published => RICOCHET_PUBLISHED,
        RicochetState::Probing => RICOCHET_PROBING,
        RicochetState::Confirmed => RICOCHET_CONFIRMED,
        RicochetState::Failed => RICOCHET_FAILED,
    }
}

const fn decode_ricochet_state(value: u32) -> RicochetState {
    match value & !RICOCHET_GENERATION_MASK {
        RICOCHET_AVAILABLE => RicochetState::Available,
        RICOCHET_RESERVED => RicochetState::Reserved,
        RICOCHET_PUBLISHED => RicochetState::Published,
        RICOCHET_PROBING => RicochetState::Probing,
        RICOCHET_CONFIRMED => RicochetState::Confirmed,
        _ => RicochetState::Failed,
    }
}

const fn ricochet_is_after_publication(state: RicochetState) -> bool {
    matches!(
        state,
        RicochetState::Published
            | RicochetState::Probing
            | RicochetState::Confirmed
            | RicochetState::Failed
    )
}

const fn ricochet_is_pending(state: RicochetState) -> bool {
    matches!(state, RicochetState::Published | RicochetState::Probing)
}

fn load_f32_array(source: &[AtomicU32; 3]) -> [f32; 3] {
    let mut values = [0.0; 3];
    for (value, source) in values.iter_mut().zip(source) {
        *value = f32::from_bits(source.load(Ordering::Relaxed));
    }
    values
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::{Correlation, InsertOutcome, ObservationPool, RicochetState};
    use crate::ballistics::native::RuntimeFlightPath;
    use crate::ballistics::ricochet::ContactSignature;
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
    fn child_transfer_rekeys_a_reused_address_and_owns_one_native_step() {
        let pool = ObservationPool::<8>::new();
        pool.insert(0x2000, context(99), RuntimeFlightPath::Physical, 1, 100);
        pool.insert(0x1000, context(1), RuntimeFlightPath::Physical, 10, 100);
        let launch = pool.impact_observation(0x1000).unwrap();
        let reservation = pool
            .reserve_ricochet(0x1000, launch.generation, launch.lifecycle)
            .unwrap();
        assert!(pool.publish_ricochet_child(
            0x1000,
            reservation,
            0x2000,
            context(2),
            11,
            ContactSignature {
                target_token: 7,
                point: [1.0, 2.0, 3.0],
                oriented_normal: [0.0, 1.0, 0.0],
                raw_material: 5,
                distance_travelled: 10.0,
            },
            [1.0, 0.1, 0.0],
        ));
        assert!(pool.impact_observation(0x1000).is_none());
        assert_eq!(
            pool.impact_observation(0x2000).unwrap().ricochet_state,
            RicochetState::Published
        );

        let probe = pool.reserve_first_step(0x2000).unwrap();
        assert_eq!(probe.expected_direction, [1.0, 0.1, 0.0]);
        assert_eq!(pool.active_first_step(0x2000), Some(probe));
        assert!(pool.reserve_first_step(0x2000).is_none());
        assert!(pool.complete_first_step(0x2000, probe, true));
        assert!(pool.active_first_step(0x2000).is_none());
        assert_eq!(
            pool.impact_observation(0x2000).unwrap().ricochet_state,
            RicochetState::Confirmed
        );
        assert!(!pool.complete_first_step(0x2000, probe, false));
    }

    #[test]
    fn confirmed_child_can_reserve_and_publish_the_next_energy_admitted_bounce() {
        let pool = ObservationPool::<8>::new();
        pool.insert(0x1000, context(1), RuntimeFlightPath::Physical, 10, 100);
        let original = pool.impact_observation(0x1000).unwrap();
        let first = pool
            .reserve_ricochet(0x1000, original.generation, original.lifecycle)
            .unwrap();
        assert_eq!(first.bounce_depth(), 0);
        assert!(pool.publish_ricochet_child(
            0x1000,
            first,
            0x2000,
            context(2),
            11,
            ContactSignature {
                target_token: 7,
                point: [1.0, 2.0, 3.0],
                oriented_normal: [0.0, 1.0, 0.0],
                raw_material: 5,
                distance_travelled: 10.0,
            },
            [1.0, 0.1, 0.0],
        ));
        let probe = pool.reserve_first_step(0x2000).unwrap();
        assert_eq!(probe.bounce_depth, 1);
        assert!(pool.complete_first_step(0x2000, probe, true));

        let child = pool.impact_observation(0x2000).unwrap();
        assert_eq!(child.ricochet_state, RicochetState::Confirmed);
        assert_eq!(child.bounce_depth, 1);
        let cancelled = pool
            .reserve_ricochet(0x2000, child.generation, child.lifecycle)
            .unwrap();
        pool.cancel_ricochet(0x2000, cancelled);
        assert_eq!(
            pool.impact_observation(0x2000).unwrap().ricochet_state,
            RicochetState::Confirmed
        );

        let second = pool
            .reserve_ricochet(0x2000, child.generation, child.lifecycle)
            .unwrap();
        assert_eq!(second.bounce_depth(), 1);
        assert!(pool.publish_ricochet_child(
            0x2000,
            second,
            0x3000,
            context(3),
            12,
            ContactSignature {
                target_token: 8,
                point: [4.0, 5.0, 6.0],
                oriented_normal: [1.0, 0.0, 0.0],
                raw_material: 0,
                distance_travelled: 20.0,
            },
            [0.1, 1.0, 0.0],
        ));
        let next = pool.impact_observation(0x3000).unwrap();
        assert_eq!(next.ricochet_state, RicochetState::Published);
        assert_eq!(next.bounce_depth, 2);
    }

    #[test]
    fn replacement_and_clear_report_unobserved_published_steps() {
        let pool = ObservationPool::<8>::new();
        for (token, child_token, sequence) in [(0x1000, 0x3000, 1), (0x2000, 0x4000, 2)] {
            pool.insert(
                token,
                context(sequence),
                RuntimeFlightPath::Physical,
                10,
                100,
            );
            let launch = pool.impact_observation(token).unwrap();
            let reservation = pool
                .reserve_ricochet(token, launch.generation, launch.lifecycle)
                .unwrap();
            assert!(pool.publish_ricochet_child(
                token,
                reservation,
                child_token,
                context(sequence + 10),
                11,
                ContactSignature {
                    target_token: 7,
                    point: [1.0, 2.0, 3.0],
                    oriented_normal: [0.0, 1.0, 0.0],
                    raw_material: 5,
                    distance_travelled: 10.0,
                },
                [1.0, 0.1, 0.0],
            ));
        }

        assert_eq!(
            pool.insert(0x3000, context(3), RuntimeFlightPath::Physical, 20, 100,),
            InsertOutcome::ReplacedGenerationPendingRicochet,
        );
        let summary = pool.clear();
        assert_eq!(summary.pending_ricochets, 1);
    }

    #[test]
    fn production_pool_stays_within_the_documented_memory_budget() {
        assert!(size_of::<ObservationPool<2048>>() <= 1024 * 1024);
    }
}
