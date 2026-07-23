//! DirectInput suppression while the ImGui menu owns input.

use core::{
    ffi::c_void,
    mem::size_of,
    ptr,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::sync::LazyLock;

use libpsycho::{ffi::fnptr::FnPtr, hook::traits::Hook, os::windows::hook::vmt::vmthook::VmtHook};
use parking_lot::Mutex;

const FOCUS_SUBSYSTEM_PTR: usize = 0x011F35CC;
const KEYBOARD_DEVICE_OFFSET: usize = 0x2C;
const MOUSE_DEVICE_OFFSET: usize = 0x30;
const GET_DEVICE_STATE_INDEX: usize = 0x24 / size_of::<*mut c_void>();
const GET_DEVICE_DATA_INDEX: usize = 0x28 / size_of::<*mut c_void>();
const MAX_ZEROED_STATE_BYTES: u32 = 0x100;
const DIMOUSESTATE_LZ_OFFSET: usize = 0x08;
const DIDEVICEOBJECTDATA_DWOFS_OFFSET: usize = 0x00;
const DIDEVICEOBJECTDATA_DWDATA_OFFSET: usize = 0x04;
const DIMOFS_Z: u32 = 0x08;
const DI_OK: i32 = 0;

type GetDeviceStateFn = unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> i32;
type GetDeviceDataFn =
    unsafe extern "system" fn(*mut c_void, u32, *mut c_void, *mut u32, u32) -> i32;

static MENU_INPUT_BLOCKED: AtomicBool = AtomicBool::new(false);
static KEYBOARD_DEVICE: AtomicUsize = AtomicUsize::new(0);
static MOUSE_DEVICE: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_GET_DEVICE_STATE: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_GET_DEVICE_DATA: AtomicUsize = AtomicUsize::new(0);
static DIRECT_INPUT_HOOKS: LazyLock<Mutex<DirectInputHooks>> =
    LazyLock::new(|| Mutex::new(DirectInputHooks::default()));

#[derive(Default)]
struct DirectInputHooks {
    get_device_state: Option<VmtHook<GetDeviceStateFn>>,
    get_device_data: Option<VmtHook<GetDeviceDataFn>>,
    hooked_vtable: usize,
    error_logs: u32,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum BlockedDeviceKind {
    Keyboard,
    Mouse,
}

pub(crate) fn set_menu_input_blocked(blocked: bool) {
    if blocked {
        refresh_devices();
        ensure_hooks_installed();
    }

    let previous = MENU_INPUT_BLOCKED.swap(blocked, Ordering::AcqRel);
    if previous != blocked {
        log::info!(
            "[INPUT] Game DirectInput capture {}",
            if blocked { "blocked" } else { "restored" }
        );
    }
}

#[cfg(test)]
pub(crate) fn set_menu_input_blocked_for_test(blocked: bool) {
    MENU_INPUT_BLOCKED.store(blocked, Ordering::Release);
}

#[cfg(test)]
pub(crate) fn menu_input_blocked_for_test() -> bool {
    MENU_INPUT_BLOCKED.load(Ordering::Acquire)
}

fn ensure_hooks_installed() {
    let mut hooks = DIRECT_INPUT_HOOKS.lock();
    if hooks.get_device_state.is_some() && hooks.get_device_data.is_some() {
        return;
    }

    let Some(device) = hook_source_device() else {
        if hooks.error_logs < 4 {
            log::warn!("[INPUT] DirectInput devices are not ready for capture hooks");
            hooks.error_logs += 1;
        }
        return;
    };

    let vtable = unsafe { read_vtable(device) };
    if vtable == 0 {
        if hooks.error_logs < 4 {
            log::warn!("[INPUT] DirectInput device has no vtable");
            hooks.error_logs += 1;
        }
        return;
    }

    match install_hooks(&mut hooks, device, vtable) {
        Ok(()) => log::info!("[INPUT] DirectInput mouse/keyboard capture hooks installed"),
        Err(err) => {
            if hooks.error_logs < 4 {
                log::warn!("[INPUT] DirectInput capture hook install failed: {err:#}");
                hooks.error_logs += 1;
            }
        }
    }
}

fn install_hooks(
    hooks: &mut DirectInputHooks,
    device: *mut c_void,
    vtable: usize,
) -> anyhow::Result<()> {
    if hooks.hooked_vtable != 0 && hooks.hooked_vtable != vtable {
        anyhow::bail!(
            "unexpected DirectInput device vtable change: old=0x{:X}, new=0x{:X}",
            hooks.hooked_vtable,
            vtable
        );
    }

    if hooks.get_device_state.is_none() {
        let hook = unsafe {
            VmtHook::new(
                "IDirectInputDevice8::GetDeviceState",
                device,
                GET_DEVICE_STATE_INDEX,
                get_device_state_detour as GetDeviceStateFn,
            )
        }?;
        let original = hook.original();
        ORIGINAL_GET_DEVICE_STATE.store(original as usize, Ordering::Release);
        hook.enable()?;
        hooks.get_device_state = Some(hook);
    }

    if hooks.get_device_data.is_none() {
        let hook = unsafe {
            VmtHook::new(
                "IDirectInputDevice8::GetDeviceData",
                device,
                GET_DEVICE_DATA_INDEX,
                get_device_data_detour as GetDeviceDataFn,
            )
        }?;
        let original = hook.original();
        ORIGINAL_GET_DEVICE_DATA.store(original as usize, Ordering::Release);
        hook.enable()?;
        hooks.get_device_data = Some(hook);
    }

    hooks.hooked_vtable = vtable;
    Ok(())
}

fn hook_source_device() -> Option<*mut c_void> {
    let mouse = MOUSE_DEVICE.load(Ordering::Acquire) as *mut c_void;
    if !mouse.is_null() {
        return Some(mouse);
    }

    let keyboard = KEYBOARD_DEVICE.load(Ordering::Acquire) as *mut c_void;
    (!keyboard.is_null()).then_some(keyboard)
}

fn refresh_devices() {
    let focus = unsafe { read_game_ptr(FOCUS_SUBSYSTEM_PTR) };
    if focus.is_null() {
        KEYBOARD_DEVICE.store(0, Ordering::Release);
        MOUSE_DEVICE.store(0, Ordering::Release);
        return;
    }

    let keyboard = unsafe { read_game_ptr(focus as usize + KEYBOARD_DEVICE_OFFSET) };
    let mouse = unsafe { read_game_ptr(focus as usize + MOUSE_DEVICE_OFFSET) };
    KEYBOARD_DEVICE.store(keyboard as usize, Ordering::Release);
    MOUSE_DEVICE.store(mouse as usize, Ordering::Release);
}

fn blocked_device_kind(device: *mut c_void) -> Option<BlockedDeviceKind> {
    if !MENU_INPUT_BLOCKED.load(Ordering::Acquire) || device.is_null() {
        return None;
    }

    let device = device as usize;
    if device == KEYBOARD_DEVICE.load(Ordering::Acquire) {
        Some(BlockedDeviceKind::Keyboard)
    } else if device == MOUSE_DEVICE.load(Ordering::Acquire) {
        Some(BlockedDeviceKind::Mouse)
    } else {
        None
    }
}

unsafe extern "system" fn get_device_state_detour(
    device: *mut c_void,
    data_size: u32,
    data: *mut c_void,
) -> i32 {
    if let Some(kind) = blocked_device_kind(device) {
        let result = if kind == BlockedDeviceKind::Mouse {
            unsafe { call_original_get_device_state(device, data_size, data) }
        } else {
            DI_OK
        };

        if kind == BlockedDeviceKind::Mouse && direct_input_succeeded(result) {
            queue_mouse_wheel_from_state(data_size, data);
        }

        if !data.is_null() && data_size <= MAX_ZEROED_STATE_BYTES {
            unsafe { ptr::write_bytes(data, 0, data_size as usize) };
        }
        return DI_OK;
    }

    unsafe { call_original_get_device_state(device, data_size, data) }
}

unsafe extern "system" fn get_device_data_detour(
    device: *mut c_void,
    object_data_size: u32,
    object_data: *mut c_void,
    inout_count: *mut u32,
    flags: u32,
) -> i32 {
    if let Some(kind) = blocked_device_kind(device) {
        if kind == BlockedDeviceKind::Mouse {
            let result = unsafe {
                call_original_get_device_data(
                    device,
                    object_data_size,
                    object_data,
                    inout_count,
                    flags,
                )
            };
            if direct_input_succeeded(result) {
                queue_mouse_wheel_from_buffer(object_data_size, object_data, inout_count);
            }
            if !inout_count.is_null() {
                unsafe { *inout_count = 0 };
            }
            return DI_OK;
        }

        if !inout_count.is_null() {
            unsafe { *inout_count = 0 };
        }
        return DI_OK;
    }

    unsafe {
        call_original_get_device_data(device, object_data_size, object_data, inout_count, flags)
    }
}

unsafe fn call_original_get_device_state(
    device: *mut c_void,
    data_size: u32,
    data: *mut c_void,
) -> i32 {
    let original = ORIGINAL_GET_DEVICE_STATE.load(Ordering::Acquire);
    if original == 0 {
        return DI_OK;
    }

    let Ok(original) = (unsafe { FnPtr::<GetDeviceStateFn>::from_raw(original as *mut c_void) })
    else {
        return DI_OK;
    };
    unsafe { original.as_fn()(device, data_size, data) }
}

unsafe fn call_original_get_device_data(
    device: *mut c_void,
    object_data_size: u32,
    object_data: *mut c_void,
    inout_count: *mut u32,
    flags: u32,
) -> i32 {
    let original = ORIGINAL_GET_DEVICE_DATA.load(Ordering::Acquire);
    if original == 0 {
        return DI_OK;
    }

    let Ok(original) = (unsafe { FnPtr::<GetDeviceDataFn>::from_raw(original as *mut c_void) })
    else {
        return DI_OK;
    };
    unsafe { original.as_fn()(device, object_data_size, object_data, inout_count, flags) }
}

fn queue_mouse_wheel_from_state(data_size: u32, data: *mut c_void) {
    if data.is_null() || data_size < (DIMOUSESTATE_LZ_OFFSET + size_of::<i32>()) as u32 {
        return;
    }

    let wheel = unsafe {
        ptr::read_unaligned(
            (data as *const u8)
                .add(DIMOUSESTATE_LZ_OFFSET)
                .cast::<i32>(),
        )
    };
    queue_mouse_wheel(wheel);
}

fn queue_mouse_wheel_from_buffer(
    object_data_size: u32,
    object_data: *mut c_void,
    inout_count: *mut u32,
) {
    if object_data.is_null()
        || inout_count.is_null()
        || object_data_size < (DIDEVICEOBJECTDATA_DWDATA_OFFSET + size_of::<u32>()) as u32
    {
        return;
    }

    let count = unsafe { *inout_count } as usize;
    let stride = object_data_size as usize;
    for index in 0..count {
        let base = unsafe { (object_data as *const u8).add(index * stride) };
        let offset =
            unsafe { ptr::read_unaligned(base.add(DIDEVICEOBJECTDATA_DWOFS_OFFSET).cast::<u32>()) };
        if offset != DIMOFS_Z {
            continue;
        }

        let wheel = unsafe {
            ptr::read_unaligned(base.add(DIDEVICEOBJECTDATA_DWDATA_OFFSET).cast::<u32>())
        } as i32;
        queue_mouse_wheel(wheel);
    }
}

fn queue_mouse_wheel(wheel: i32) {
    if wheel != 0 {
        psycho_imgui::queue_mouse_wheel_delta(wheel, 0);
    }
}

fn direct_input_succeeded(result: i32) -> bool {
    result >= 0
}

unsafe fn read_game_ptr(address: usize) -> *mut c_void {
    unsafe { (address as *const *mut c_void).read() }
}

unsafe fn read_vtable(object: *mut c_void) -> usize {
    if object.is_null() {
        return 0;
    }
    unsafe { *(object as *const usize) }
}
