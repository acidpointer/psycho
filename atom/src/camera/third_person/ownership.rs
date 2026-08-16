//! Deterministic third-person ownership epochs.
//!
//! The machine is deliberately independent of native pointers and hooks. A
//! caller first reduces the live engine state to [`OwnershipInput`], then the
//! machine decides whether Atom may write. `Acquire` observes one complete
//! stable native frame without writing; `Release` revokes permission in the
//! first frame that another owner appears.

/// Current owner and locomotion policy for third-person output.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OwnershipState {
    /// FNV or another provider owns all outputs.
    #[default]
    Native,
    /// Atom is seeding state from one stable native frame and cannot write.
    Acquire,
    /// Atom may emit each enabled capability and uses movement-facing policy.
    Explore,
    /// Atom may emit each enabled capability and uses view-facing policy.
    Combat,
    /// Atom revoked all output and is discarding temporal history.
    Release,
}

impl OwnershipState {
    /// Return whether this epoch permits capability-specific Atom output.
    ///
    /// Individual configuration and native-hook gates remain authoritative;
    /// an owned epoch never implies that every optional output is enabled.
    pub const fn is_owned(self) -> bool {
        matches!(self, Self::Explore | Self::Combat)
    }
}

/// Pointer-free facts used to classify one player update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnershipInput {
    enabled: bool,
    stable_third_person: bool,
    native_owner: bool,
    world_ready: bool,
    combat: bool,
    cell: u32,
}

impl OwnershipInput {
    /// Construct one ownership sample.
    ///
    /// `native_owner` combines VATS, TFC, menus, disabled controls, furniture,
    /// scripted animation, death/ragdoll, and explicit external ownership.
    /// `cell` is a stable process-local token; zero is never world-ready.
    pub const fn new(
        enabled: bool,
        stable_third_person: bool,
        native_owner: bool,
        world_ready: bool,
        combat: bool,
        cell: u32,
    ) -> Self {
        Self {
            enabled,
            stable_third_person,
            native_owner,
            world_ready,
            combat,
            cell,
        }
    }

    fn eligible(self) -> bool {
        self.enabled
            && self.stable_third_person
            && !self.native_owner
            && self.world_ready
            && self.cell != 0
    }
}

/// Observable result of advancing one ownership sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnershipTransition {
    previous: OwnershipState,
    current: OwnershipState,
    epoch: u32,
}

impl OwnershipTransition {
    /// Return the state before this sample.
    pub const fn previous(self) -> OwnershipState {
        self.previous
    }

    /// Return the state selected for this sample.
    pub const fn current(self) -> OwnershipState {
        self.current
    }

    /// Return the wrapping ownership epoch after this sample.
    pub const fn epoch(self) -> u32 {
        self.epoch
    }

    /// Return whether this sample starts a fresh native-state seed.
    pub fn begins_acquire(self) -> bool {
        self.current == OwnershipState::Acquire && self.previous != OwnershipState::Acquire
    }
}

/// Fixed-size ownership classifier with explicit acquire/release frames.
#[derive(Clone, Copy, Debug, Default)]
pub struct OwnershipMachine {
    state: OwnershipState,
    epoch: u32,
    cell: u32,
}

impl OwnershipMachine {
    /// Construct a native-owned machine with no retained world token.
    pub const fn new() -> Self {
        Self {
            state: OwnershipState::Native,
            epoch: 0,
            cell: 0,
        }
    }

    /// Return the current ownership state.
    pub const fn state(self) -> OwnershipState {
        self.state
    }

    /// Return the current wrapping ownership epoch.
    pub const fn epoch(self) -> u32 {
        self.epoch
    }

    /// Advance one complete engine-state sample.
    ///
    /// A cell change while Atom is acquiring or owned enters `Release` in the
    /// same sample. Reacquisition always passes through a new `Acquire` frame,
    /// ensuring old spring, recenter, aim, and facing data cannot be reused.
    pub fn advance(&mut self, input: OwnershipInput) -> OwnershipTransition {
        let previous = self.state;
        let cell_changed = self.cell != 0 && input.cell != 0 && self.cell != input.cell;
        let current = if !input.eligible() || cell_changed {
            match previous {
                OwnershipState::Native | OwnershipState::Release => OwnershipState::Native,
                _ => OwnershipState::Release,
            }
        } else {
            match previous {
                OwnershipState::Native | OwnershipState::Release => OwnershipState::Acquire,
                OwnershipState::Acquire | OwnershipState::Explore | OwnershipState::Combat => {
                    if input.combat {
                        OwnershipState::Combat
                    } else {
                        OwnershipState::Explore
                    }
                }
            }
        };

        let ownership_boundary = matches!(
            (previous.is_owned(), current.is_owned()),
            (false, true) | (true, false)
        ) || (current == OwnershipState::Acquire
            && previous != OwnershipState::Acquire);
        if ownership_boundary {
            self.epoch = self.epoch.wrapping_add(1).max(1);
        }
        self.cell = if input.eligible() { input.cell } else { 0 };
        self.state = current;
        OwnershipTransition {
            previous,
            current,
            epoch: self.epoch,
        }
    }

    /// Revoke ownership and discard the current cell token immediately.
    pub fn force_release(&mut self) -> OwnershipTransition {
        let previous = self.state;
        self.state = if previous == OwnershipState::Native {
            OwnershipState::Native
        } else {
            OwnershipState::Release
        };
        self.cell = 0;
        if previous.is_owned() {
            self.epoch = self.epoch.wrapping_add(1).max(1);
        }
        OwnershipTransition {
            previous,
            current: self.state,
            epoch: self.epoch,
        }
    }
}
