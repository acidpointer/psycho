//! Fallout: New Vegas 1.4.0.525 native input layout bridge.
//!
//! Fixed addresses and offsets in this module are admitted only after plugin
//! query rejects other runtimes and DeferredInit validates the surrounding
//! executable/data ranges. The sampler detour receives the native input owner
//! as `this`; reads below occur only after the chained sampler returns, when
//! xNVSE has completed its normal input injection path.

use core::ffi::c_void;
use core::mem::size_of;

use libpsycho::os::windows::memory::{MemoryError, validate_memory_range};
use libpsycho::os::windows::winapi::get_foreground_window;
use thiserror::Error;

use super::controller::NativeControllerState;
use super::frame::{NativeInputState, NativeMouseState};

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
