//! Safe wrapper for the NVSE player controls interface.
//!
//! Allows plugins to enable/disable specific player controls programmatically.
//! Unlike the vanilla DisablePlayerControls command, changes made through this
//! interface are NOT save-baked and reset on each save load.
//!
//! # Per-mod tracking
//!
//! Controls are tracked per mod name. If two mods both disable movement,
//! movement stays disabled until BOTH mods re-enable it. This prevents
//! conflicts between plugins.
//!
//! # Usage
//!
//! ```no_run
//! use libnvse::api::player_controls::ControlFlags;
//!
//! // Disable movement and jumping
//! controls.disable(ControlFlags::MOVEMENT | ControlFlags::JUMPING)?;
//!
//! // Re-enable them later
//! controls.enable(ControlFlags::MOVEMENT | ControlFlags::JUMPING)?;
//!
//! // Check if movement is disabled by any mod
//! if controls.is_disabled(ControlFlags::MOVEMENT) {
//!     log::info!("Movement is currently disabled");
//! }
//! ```

use std::ffi::CStr;
use std::ptr::NonNull;

use thiserror::Error;

use crate::NVSETogglePlayerControlsInterface as NVSETogglePlayerControlsInterfaceFFI;
use crate::TogglePlayerControlsAlt::CheckDisabledHow;

// -- Control flags ----------------------------------------------------------

bitflags::bitflags! {
    /// Flags for player control types that can be toggled.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ControlFlags: u32 {
        // Vanilla flags
        const MOVEMENT      = 1 << 0;
        const LOOKING       = 1 << 1;
        const PIPBOY        = 1 << 2;
        const FIGHTING      = 1 << 3;
        const POV           = 1 << 4;
        const ROLLOVER_TEXT = 1 << 5;
        const SNEAKING      = 1 << 6;
        // xNVSE extended flags
        const ATTACKING         = 1 << 7;
        const ENTER_VATS        = 1 << 8;
        const JUMPING           = 1 << 9;
        const AIMING_OR_BLOCKING = 1 << 10;
        const RUNNING           = 1 << 11;
        const SLEEP             = 1 << 12;
        const WAIT              = 1 << 13;
        const FAST_TRAVEL       = 1 << 14;
        const RELOAD            = 1 << 15;
    }
}

/// How to check if controls are disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisabledCheck {
    /// Check only controls disabled by the calling mod.
    ByCallingMod,
    /// Check controls disabled by any mod (via this interface).
    ByAnyMod,
    /// Check controls disabled by any mod OR vanilla DisablePlayerControls.
    ByAnyModOrVanilla,
    /// Check only vanilla DisablePlayerControls state.
    ByVanillaOnly,
}

impl DisabledCheck {
    fn to_ffi(self) -> CheckDisabledHow {
        match self {
            Self::ByCallingMod => CheckDisabledHow::ByCallingMod,
            Self::ByAnyMod => CheckDisabledHow::ByAnyMod,
            Self::ByAnyModOrVanilla => CheckDisabledHow::ByAnyModOrVanilla,
            Self::ByVanillaOnly => CheckDisabledHow::ByVanillaOnly,
        }
    }
}

// -- Error ------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum PlayerControlsError {
    #[error("NVSETogglePlayerControlsInterface pointer is NULL")]
    InterfaceIsNull,

    #[error("DisablePlayerControlsAlt function pointer is NULL")]
    DisableFnIsNull,

    #[error("EnablePlayerControlsAlt function pointer is NULL")]
    EnableFnIsNull,
}

pub type PlayerControlsResult<T> = Result<T, PlayerControlsError>;

// -- Wrapper ----------------------------------------------------------------

/// Safe wrapper around NVSETogglePlayerControlsInterface.
///
/// Provides per-mod control toggling that does NOT persist in saves.
/// Your mod name is used as the identity for tracking which controls
/// you have disabled.
pub struct PlayerControls {
    ptr: NonNull<NVSETogglePlayerControlsInterfaceFFI>,
    /// Static mod name pointer - must live for the game session.
    /// Points to a &'static CStr.
    mod_name: &'static CStr,
}

impl PlayerControls {
    /// Create a PlayerControls wrapper.
    ///
    /// `mod_name` must be a `&'static CStr` that identifies your mod.
    /// Use the same name consistently so enable/disable tracking works.
    pub fn from_raw(
        raw: *mut NVSETogglePlayerControlsInterfaceFFI,
        mod_name: &'static CStr,
    ) -> PlayerControlsResult<Self> {
        let ptr = NonNull::new(raw).ok_or(PlayerControlsError::InterfaceIsNull)?;
        Ok(Self { ptr, mod_name })
    }

    /// Disable the specified player controls.
    ///
    /// Controls stay disabled until explicitly re-enabled by your mod.
    /// Changes reset when a save is loaded.
    pub fn disable(&self, flags: ControlFlags) -> PlayerControlsResult<()> {
        let iface = unsafe { self.ptr.as_ref() };
        let disable_fn = iface
            .DisablePlayerControlsAlt
            .ok_or(PlayerControlsError::DisableFnIsNull)?;

        unsafe { disable_fn(flags.bits(), self.mod_name.as_ptr()) };
        Ok(())
    }

    /// Re-enable the specified player controls (for this mod).
    ///
    /// The control only becomes truly enabled when ALL mods that disabled
    /// it have re-enabled it.
    pub fn enable(&self, flags: ControlFlags) -> PlayerControlsResult<()> {
        let iface = unsafe { self.ptr.as_ref() };
        let enable_fn = iface
            .EnablePlayerControlsAlt
            .ok_or(PlayerControlsError::EnableFnIsNull)?;

        unsafe { enable_fn(flags.bits(), self.mod_name.as_ptr()) };
        Ok(())
    }

    /// Check if specific controls are disabled.
    ///
    /// Returns true if ALL the specified flags are currently disabled,
    /// according to the specified check mode.
    pub fn is_disabled(&self, flags: ControlFlags) -> bool {
        self.is_disabled_how(DisabledCheck::ByAnyModOrVanilla, flags)
    }

    /// Check if specific controls are disabled, with a specific check mode.
    pub fn is_disabled_how(&self, how: DisabledCheck, flags: ControlFlags) -> bool {
        let iface = unsafe { self.ptr.as_ref() };
        let check_fn = match iface.GetPlayerControlsDisabledAlt {
            Some(f) => f,
            None => return false,
        };

        unsafe { check_fn(how.to_ffi(), flags.bits(), self.mod_name.as_ptr()) }
    }

    /// Get the full bitmask of currently disabled controls.
    pub fn get_disabled_flags(&self, how: DisabledCheck) -> ControlFlags {
        let iface = unsafe { self.ptr.as_ref() };
        let get_fn = match iface.GetDisabledPlayerControls {
            Some(f) => f,
            None => return ControlFlags::empty(),
        };

        let raw = unsafe { get_fn(how.to_ffi(), self.mod_name.as_ptr()) };
        ControlFlags::from_bits_truncate(raw)
    }
}
