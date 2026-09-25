//! Fallout: New Vegas 1.4.0.525 native input layout bridge.
//!
//! Fixed addresses and offsets in this module are admitted only after plugin
//! query rejects other runtimes and DeferredInit validates the surrounding
//! executable/data ranges. The sampler detour receives the native input owner
//! as `this`; device snapshots occur after the chained sampler returns, when
//! xNVSE has completed its normal input injection path. Final-heading guards
//! read engine-owned player/HUD state synchronously on the same game thread.
//! No native owner is retained. Unavailable optional mouse context uses neutral
//! context gain after the live look guard admits the configured profile. Hot
//! paths use bounded reads and at most one live ADS virtual call.

use core::ffi::c_void;
use core::mem::size_of;
use std::sync::OnceLock;

use libnvse::api::player_controls::{ControlFlags, DisabledCheck, PlayerControlsReader};
use libpsycho::os::windows::memory::{MemoryError, validate_memory_range};
use libpsycho::os::windows::winapi::get_foreground_window;
use thiserror::Error;

use super::controller::NativeControllerState;
use super::frame::{NativeInputState, NativeMouseState};
use super::mouse::MouseContext;

pub(super) const NATIVE_SAMPLER_ADDRESS: usize = 0x00A2_3010;
pub(super) const NATIVE_MOUSE_GETTER_ADDRESS: usize = 0x00A2_39E0;
pub(super) const VANILLA_INVERT_Y_VALUE_ADDRESS: usize = 0x011E_0A60;

const KEYBOARD_CURRENT_OFFSET: usize = 0x18F8;
const KEYBOARD_PREVIOUS_OFFSET: usize = 0x19F8;
const MOUSE_CURRENT_OFFSET: usize = 0x1B24;
const MOUSE_PREVIOUS_OFFSET: usize = 0x1B38;
const CONTROLLER_CURRENT_ADDRESS: usize = 0x011F_35A8;
const CONTROLLER_PREVIOUS_ADDRESS: usize = 0x011F_35B8;
const CONTROLLER_MODE_ADDRESS: usize = 0x011F_35C8;
const TOP_LEVEL_WINDOW_ADDRESS: usize = 0x011C_6FC0;
const INPUT_OWNER_ADDRESS: usize = 0x011F_35CC;
const INTERFACE_MANAGER_ADDRESS: usize = 0x011D_8A80;
const PLAYER_ADDRESS: usize = 0x011D_EA3C;
const HUD_MAIN_MENU_ADDRESS: usize = 0x011D_96C0;
const HUD_SCOPE_VISIBLE_OFFSET: usize = 0x1FC;
const PLAYER_PROCESS_OFFSET: usize = 0x68;
const PROCESS_IS_AIMING_VTABLE_OFFSET: usize = 0x404;

// Published at DeferredInit from the service captured during plugin load.
// The reader contains process-lifetime callbacks and performs no mutation.
static PLAYER_CONTROLS: OnceLock<PlayerControlsReader> = OnceLock::new();

type ProcessIsAimingFn = unsafe extern "thiscall" fn(*mut c_void) -> u8;
const KEYBOARD_BINDINGS_OFFSET: usize = 0x1B94;
const MOUSE_BINDINGS_OFFSET: usize = 0x1BB0;
// FNV keeps DirectInput joystick binds at +0x1BCC and the active XInput binds
// in the final 28 bytes of the 0x1C04-byte owner. The bound-control dispatcher
// reads +0x1BE8 when controller mode is active.
const CONTROLLER_BINDINGS_OFFSET: usize = 0x1BE8;
const CONTROL_COUNT: usize = 28;
const INTERFACE_MANAGER_ACTIVE_OFFSET: usize = 0x000;
const INTERFACE_MANAGER_MODE_OFFSET: usize = 0x00C;
const GAMEPLAY_INTERFACE_MODE: u32 = 1;
const MIN_ENGINE_POINTER: usize = 0x1_0000;

const _: [(); 20] = [(); size_of::<NativeMouseState>()];
const _: [(); 16] = [(); size_of::<NativeControllerState>()];

/// Retain the read-only combined control query before input hooks activate.
///
/// The optional reader was acquired from xNVSE during plugin load and remains
/// valid for the process lifetime. If absent, final mouse transforms preserve
/// native heading rather than ignoring script-owned look suppression.
pub(super) fn publish_player_controls(controls: Option<PlayerControlsReader>) {
    if let Some(controls) = controls {
        let _ = PLAYER_CONTROLS.set(controls);
    }
}

/// Failure to admit the fixed native input data contract.
#[derive(Debug, Error)]
pub(crate) enum NativeContractError {
    /// A proven native range is not readable in this process.
    #[error(transparent)]
    Memory(#[from] MemoryError),
    /// A byte documented as a native boolean has an impossible value.
    #[error("native boolean at 0x{address:08X} has value {value}")]
    InvalidBoolean { address: usize, value: u8 },
}

/// Validate native data globals once at DeferredInit.
pub(super) fn validate_data_contract() -> Result<(), NativeContractError> {
    validate_memory_range(
        CONTROLLER_CURRENT_ADDRESS as *const c_void,
        size_of::<NativeControllerState>(),
    )?;
    validate_memory_range(
        CONTROLLER_PREVIOUS_ADDRESS as *const c_void,
        size_of::<NativeControllerState>(),
    )?;
    validate_memory_range(CONTROLLER_MODE_ADDRESS as *const c_void, 1)?;
    validate_memory_range(VANILLA_INVERT_Y_VALUE_ADDRESS as *const c_void, 1)?;
    validate_memory_range(
        TOP_LEVEL_WINDOW_ADDRESS as *const c_void,
        size_of::<*mut c_void>(),
    )?;
    validate_memory_range(
        INPUT_OWNER_ADDRESS as *const c_void,
        size_of::<*mut c_void>(),
    )?;
    validate_memory_range(
        INTERFACE_MANAGER_ADDRESS as *const c_void,
        size_of::<*mut c_void>(),
    )?;
    validate_memory_range(PLAYER_ADDRESS as *const c_void, size_of::<*mut c_void>())?;
    validate_memory_range(
        HUD_MAIN_MENU_ADDRESS as *const c_void,
        size_of::<*mut c_void>(),
    )?;

    validate_boolean(CONTROLLER_MODE_ADDRESS)?;
    validate_boolean(VANILLA_INVERT_Y_VALUE_ADDRESS)?;
    Ok(())
}

/// Return FNV's process-lifetime input owner at DeferredInit.
pub(super) fn input_owner() -> *mut c_void {
    unsafe { core::ptr::read_volatile(INPUT_OWNER_ADDRESS as *const *mut c_void) }
}

/// Copy one sample from the engine-owned input object and XInput global.
///
/// # Safety
///
/// `input_owner` must be the live object passed to the proven native sampler
/// callsite. The native predecessor must have returned before this function is
/// called, and no other thread may destroy that object during the copy.
pub(super) unsafe fn capture(input_owner: *mut c_void) -> Option<NativeInputState> {
    let input = input_owner.cast::<u8>();
    if input.is_null() {
        return None;
    }

    let keyboard_current = unsafe {
        core::ptr::read_unaligned(input.add(KEYBOARD_CURRENT_OFFSET).cast::<[u8; 256]>())
    };
    let keyboard_previous = unsafe {
        core::ptr::read_unaligned(input.add(KEYBOARD_PREVIOUS_OFFSET).cast::<[u8; 256]>())
    };
    let mouse_current = unsafe {
        core::ptr::read_unaligned(input.add(MOUSE_CURRENT_OFFSET).cast::<NativeMouseState>())
    };
    let mouse_previous = unsafe {
        core::ptr::read_unaligned(input.add(MOUSE_PREVIOUS_OFFSET).cast::<NativeMouseState>())
    };
    let controller_current = unsafe {
        core::ptr::read_unaligned(
            (CONTROLLER_CURRENT_ADDRESS as *const u8).cast::<NativeControllerState>(),
        )
    };
    let controller_previous = unsafe {
        core::ptr::read_unaligned(
            (CONTROLLER_PREVIOUS_ADDRESS as *const u8).cast::<NativeControllerState>(),
        )
    };
    let keyboard_bindings = unsafe {
        core::ptr::read_unaligned(
            input
                .add(KEYBOARD_BINDINGS_OFFSET)
                .cast::<[u8; CONTROL_COUNT]>(),
        )
    };
    let mouse_bindings = unsafe {
        core::ptr::read_unaligned(
            input
                .add(MOUSE_BINDINGS_OFFSET)
                .cast::<[u8; CONTROL_COUNT]>(),
        )
    };
    let controller_bindings = unsafe {
        core::ptr::read_unaligned(
            input
                .add(CONTROLLER_BINDINGS_OFFSET)
                .cast::<[u8; CONTROL_COUNT]>(),
        )
    };
    let controller_mode = controller_mode();
    let top_level =
        unsafe { core::ptr::read_volatile(TOP_LEVEL_WINDOW_ADDRESS as *const *mut c_void) };
    let focused = !top_level.is_null() && get_foreground_window() == top_level;
    let menu_mode = unsafe { menu_mode_active() };

    Some(NativeInputState::from_engine(
        keyboard_current,
        keyboard_previous,
        mouse_current,
        mouse_previous,
        controller_current,
        controller_previous,
        keyboard_bindings,
        mouse_bindings,
        controller_bindings,
        controller_mode,
        focused,
        menu_mode,
    ))
}

/// Publish Atom's processed controller state to FNV's current XInput slot.
///
/// FNV has already copied the prior processed current state into its previous
/// slot before Atom runs. Replacing only the new current payload therefore
/// preserves native held/pressed/released comparisons without manufacturing a
/// second controller timeline.
pub(super) fn publish_controller(state: NativeControllerState) {
    unsafe {
        core::ptr::write_volatile(
            CONTROLLER_CURRENT_ADDRESS as *mut NativeControllerState,
            state,
        );
    }
}

/// Return whether FNV currently presents controller input as active.
pub(super) fn controller_mode() -> bool {
    unsafe { core::ptr::read_volatile(CONTROLLER_MODE_ADDRESS as *const u8) != 0 }
}

/// Return the vanilla Y-inversion setting applied after the mouse getter.
pub(super) fn vanilla_y_inverted() -> bool {
    unsafe { core::ptr::read_volatile(VANILLA_INVERT_Y_VALUE_ADDRESS as *const u8) != 0 }
}

/// Preserve native look-disable and live menu guards at the heading boundary.
///
/// # Safety
///
/// Called only on the game thread with the live player received by the
/// admitted heading callsite. The player and InterfaceManager remain owned by
/// the engine throughout this synchronous call; no pointer is retained.
pub(super) unsafe fn mouse_heading_allowed(player: *mut c_void) -> bool {
    let current = unsafe { core::ptr::read_volatile(PLAYER_ADDRESS as *const *mut c_void) };
    if !is_engine_pointer(player.cast()) || player != current {
        return false;
    }
    // xNVSE extends the engine's 0x005A03F0 query with per-mod flags. Reading
    // player+0x680 alone would bypass those owners when rebuilding cached
    // counts. Use its public combined query, as the camera owners already do.
    let Some(controls) = PLAYER_CONTROLS.get() else {
        return false;
    };
    !controls.any_disabled(DisabledCheck::ByAnyModOrVanilla, ControlFlags::LOOKING)
        && !unsafe { menu_mode_active() }
}

/// Read scope visibility first, then the process' native ADS predicate.
///
/// Missing owners or callback return `None` so the caller retains its selected
/// profile with neutral context gain. Native creation/destruction publishes
/// and clears HUD ownership; the scope byte is maintained by 0x0077F3C0 and
/// reset by 0x0077F270.
/// The live process vtable is used, preserving a compatible installed provider.
///
/// # Safety
///
/// `player` must satisfy [`mouse_heading_allowed`]'s game-thread lifetime
/// contract. Its process and live vtable must satisfy FNV's IsAiming ABI
/// (thiscall, no arguments, boolean in AL), as in 0x008BBC10. No pointer escapes.
pub(super) unsafe fn mouse_context(player: *mut c_void) -> Option<MouseContext> {
    let hud = unsafe { core::ptr::read_volatile(HUD_MAIN_MENU_ADDRESS as *const *const u8) };
    if !is_engine_pointer(hud) {
        return None;
    }
    if unsafe { core::ptr::read_unaligned(hud.add(HUD_SCOPE_VISIBLE_OFFSET)) } != 0 {
        return Some(MouseContext::Scope);
    }
    let process = unsafe {
        core::ptr::read_unaligned(
            player
                .cast::<u8>()
                .add(PLAYER_PROCESS_OFFSET)
                .cast::<*mut c_void>(),
        )
    };
    if !is_engine_pointer(process.cast()) {
        return None;
    }
    let vtable = unsafe { core::ptr::read_unaligned(process.cast::<*const u8>()) };
    if !is_engine_pointer(vtable) {
        return None;
    }
    let callback = unsafe {
        core::ptr::read_unaligned(vtable.add(PROCESS_IS_AIMING_VTABLE_OFFSET).cast::<usize>())
    };
    if callback < MIN_ENGINE_POINTER {
        return None;
    }
    // The native virtual dispatch at 0x008BBC2E proves the slot and ABI. Use
    // its live target, without identifying or allowlisting a provider module.
    let is_aiming: ProcessIsAimingFn = unsafe { core::mem::transmute(callback) };
    Some(if unsafe { is_aiming(process) } != 0 {
        MouseContext::Aim
    } else {
        MouseContext::Hip
    })
}

fn validate_boolean(address: usize) -> Result<(), NativeContractError> {
    let value = unsafe { core::ptr::read_volatile(address as *const u8) };
    if value <= 1 {
        Ok(())
    } else {
        Err(NativeContractError::InvalidBoolean { address, value })
    }
}

/// Reproduce FNV's side-effect-free `MenuMode` predicate from stable state.
///
/// The shared helper at `0x00702360` is a common inline-hook target and may no
/// longer contain the native entry by `DeferredInit`. Its researched body adds
/// no policy beyond these two InterfaceManager fields, so reading the fields
/// avoids executing an unknown replacement while preserving native semantics.
unsafe fn menu_mode_active() -> bool {
    let manager =
        unsafe { core::ptr::read_volatile(INTERFACE_MANAGER_ADDRESS as *const *const u8) };
    is_engine_pointer(manager)
        && menu_mode_from_fields(
            unsafe { core::ptr::read_unaligned(manager.add(INTERFACE_MANAGER_ACTIVE_OFFSET)) },
            unsafe {
                core::ptr::read_unaligned(manager.add(INTERFACE_MANAGER_MODE_OFFSET).cast::<u32>())
            },
        )
}

const fn menu_mode_from_fields(active: u8, mode: u32) -> bool {
    active != 0 && mode != GAMEPLAY_INTERFACE_MODE
}

fn is_engine_pointer(pointer: *const u8) -> bool {
    pointer as usize >= MIN_ENGINE_POINTER
}

#[cfg(test)]
mod tests {
    use super::menu_mode_from_fields;

    #[test]
    fn menu_context_matches_the_native_interface_manager_policy() {
        assert!(!menu_mode_from_fields(0, 0));
        assert!(!menu_mode_from_fields(1, 1));
        assert!(menu_mode_from_fields(1, 0));
        assert!(menu_mode_from_fields(1, 2));
    }
}
