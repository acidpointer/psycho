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

    /// Neither read-only disabled-control query is available.
    #[error("player-controls read function pointers are both NULL")]
    ReadFnsAreNull,
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

/// Copyable, read-only view of xNVSE's combined control-disable state.
///
/// Gameplay hooks may retain this value after plugin load because it contains
/// only xNVSE's process-lifetime function pointer and Atom's static plugin
/// name. It cannot enable or disable controls. Calls are allocation-free and
/// use the same ownership policies as [`PlayerControls`].
#[derive(Clone, Copy)]
pub struct PlayerControlsReader {
    check_disabled: Option<unsafe extern "C" fn(CheckDisabledHow, u32, *const i8) -> bool>,
    get_disabled: Option<unsafe extern "fastcall" fn(CheckDisabledHow, *const i8) -> u32>,
    mod_name: &'static CStr,
}

impl PlayerControlsReader {
    /// Return whether any requested control is disabled for the ownership
    /// policy.
    ///
    /// xNVSE 6.3 exposes the mask predicate in its plugin interface but leaves
    /// the later complete-mask slot null. Prefer the complete mask when it is
    /// available and otherwise use the established predicate directly. Both
    /// paths implement the same any-intersection semantics.
    pub fn any_disabled(self, how: DisabledCheck, flags: ControlFlags) -> bool {
        if flags.is_empty() {
            return false;
        }
        if let Some(get_disabled) = self.get_disabled {
            let raw = unsafe { get_disabled(how.to_ffi(), self.mod_name.as_ptr()) };
            return ControlFlags::from_bits_truncate(raw).intersects(flags);
        }
        self.check_disabled.is_some_and(|check_disabled| unsafe {
            check_disabled(how.to_ffi(), flags.bits(), self.mod_name.as_ptr())
        })
    }

    /// Return the complete disabled-control mask for the requested ownership
    /// policy, limited to flags known by this wrapper.
    ///
    /// When xNVSE does not publish its complete-mask extension, this method
    /// reconstructs the known mask with allocation-free single-bit predicate
    /// calls. Hot paths that need only an ownership gate should call
    /// [`Self::any_disabled`] so the fallback remains one native call.
    pub fn get_disabled_flags(self, how: DisabledCheck) -> ControlFlags {
        if let Some(get_disabled) = self.get_disabled {
            let raw = unsafe { get_disabled(how.to_ffi(), self.mod_name.as_ptr()) };
            return ControlFlags::from_bits_truncate(raw);
        }
        let Some(check_disabled) = self.check_disabled else {
            return ControlFlags::empty();
        };

        let mut disabled = ControlFlags::empty();
        for bit in 0..u32::BITS {
            let raw = 1_u32 << bit;
            if ControlFlags::all().bits() & raw != 0
                && unsafe { check_disabled(how.to_ffi(), raw, self.mod_name.as_ptr()) }
            {
                disabled.insert(ControlFlags::from_bits_retain(raw));
            }
        }
        disabled
    }
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
    /// Returns true if any specified flag is currently disabled,
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
        self.reader()
            .map(|reader| reader.get_disabled_flags(how))
            .unwrap_or_else(|_| ControlFlags::empty())
    }

    /// Create a copyable read-only control-state reader for gameplay hooks.
    ///
    /// The returned reader never changes xNVSE state. It accepts either the
    /// established predicate or the later complete-mask extension and fails
    /// closed at construction only when neither read capability is present.
    pub fn reader(&self) -> PlayerControlsResult<PlayerControlsReader> {
        let iface = unsafe { self.ptr.as_ref() };
        let check_disabled = iface.GetPlayerControlsDisabledAlt;
        let get_disabled = iface.GetDisabledPlayerControls;
        if check_disabled.is_none() && get_disabled.is_none() {
            return Err(PlayerControlsError::ReadFnsAreNull);
        }
        Ok(PlayerControlsReader {
            check_disabled,
            get_disabled,
            mod_name: self.mod_name,
        })
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::c_char;

    use super::{
        CheckDisabledHow, ControlFlags, DisabledCheck, NVSETogglePlayerControlsInterfaceFFI,
        PlayerControls,
    };

    unsafe extern "C" fn check_disabled(
        _how: CheckDisabledHow,
        flags: u32,
        _mod_name: *const c_char,
    ) -> bool {
        (ControlFlags::MOVEMENT | ControlFlags::POV).bits() & flags != 0
    }

    unsafe extern "fastcall" fn get_disabled(
        _how: CheckDisabledHow,
        _mod_name: *const c_char,
    ) -> u32 {
        ControlFlags::FIGHTING.bits()
    }

    #[test]
    fn reader_falls_back_to_the_xnvse_mask_predicate() {
        let mut interface = NVSETogglePlayerControlsInterfaceFFI {
            GetPlayerControlsDisabledAlt: Some(check_disabled),
            ..Default::default()
        };
        let controls = PlayerControls::from_raw(&mut interface, c"Atom").expect("interface");
        let reader = controls.reader().expect("predicate reader");

        assert!(reader.any_disabled(
            DisabledCheck::ByAnyModOrVanilla,
            ControlFlags::MOVEMENT | ControlFlags::LOOKING
        ));
        assert!(!reader.any_disabled(DisabledCheck::ByAnyModOrVanilla, ControlFlags::LOOKING));
        assert_eq!(
            reader.get_disabled_flags(DisabledCheck::ByAnyModOrVanilla),
            ControlFlags::MOVEMENT | ControlFlags::POV
        );
    }

    #[test]
    fn reader_accepts_the_complete_mask_without_the_predicate() {
        let mut interface = NVSETogglePlayerControlsInterfaceFFI {
            GetDisabledPlayerControls: Some(get_disabled),
            ..Default::default()
        };
        let reader = PlayerControls::from_raw(&mut interface, c"Atom")
            .expect("interface")
            .reader()
            .expect("complete-mask reader");

        assert!(reader.any_disabled(DisabledCheck::ByAnyModOrVanilla, ControlFlags::FIGHTING));
    }
}
