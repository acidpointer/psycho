//! DirectInput suppression while the dashboard owns keyboard and mouse input.

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

static INPUT_BLOCKED: AtomicBool = AtomicBool::new(false);
static KEYBOARD_DEVICE: AtomicUsize = AtomicUsize::new(0);
static MOUSE_DEVICE: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_GET_DEVICE_STATE: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_GET_DEVICE_DATA: AtomicUsize = AtomicUsize::new(0);
static HOOKS: LazyLock<Mutex<DirectInputHooks>> =
    LazyLock::new(|| Mutex::new(DirectInputHooks::default()));

#[derive(Default)]
struct DirectInputHooks {
    state: Option<VmtHook<GetDeviceStateFn>>,
    data: Option<VmtHook<GetDeviceDataFn>>,
    vtable: usize,
    error_logs: u32,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DeviceKind {
    Keyboard,
    Mouse,
}

pub(crate) fn set_blocked(blocked: bool) {
    refresh_devices();
    if blocked {
        ensure_hooks();
    }
    let previous = INPUT_BLOCKED.swap(blocked, Ordering::AcqRel);
    if previous != blocked {
        log::info!(
            "[DASHBOARD] Game input {}",
            if blocked { "captured" } else { "restored" }
        );
    }
}

fn ensure_hooks() {
    let mut hooks = HOOKS.lock();
    if hooks.state.is_some() && hooks.data.is_some() {
        return;
    }
    let Some(device) = hook_source_device() else {
        log_hook_error(&mut hooks, "DirectInput devices are not ready");
        return;
    };
    let vtable = unsafe { read_vtable(device) };
    if vtable == 0 {
        log_hook_error(&mut hooks, "DirectInput device has no vtable");
        return;
    }
    if let Err(error) = install_hooks(&mut hooks, device, vtable) {
        log_hook_error(&mut hooks, &format!("DirectInput hook failed: {error:#}"));
    } else {
        log::info!("[DASHBOARD] DirectInput capture bridge installed");
    }
}

fn log_hook_error(hooks: &mut DirectInputHooks, message: &str) {
    if hooks.error_logs < 4 {
        log::warn!("[DASHBOARD] {message}");
        hooks.error_logs += 1;
    }
}

fn install_hooks(
    hooks: &mut DirectInputHooks,
    device: *mut c_void,
    vtable: usize,
) -> anyhow::Result<()> {
    if hooks.vtable != 0 && hooks.vtable != vtable {
        anyhow::bail!("DirectInput vtable changed unexpectedly");
    }
    if hooks.state.is_none() {
        let hook = unsafe {
            VmtHook::new(
                "dashboard IDirectInputDevice8::GetDeviceState",
                device,
                GET_DEVICE_STATE_INDEX,
                get_device_state_detour as GetDeviceStateFn,
            )
        }?;
        ORIGINAL_GET_DEVICE_STATE.store(hook.original() as usize, Ordering::Release);
        hook.enable()?;
        hooks.state = Some(hook);
    }
    if hooks.data.is_none() {
        let hook = unsafe {
            VmtHook::new(
                "dashboard IDirectInputDevice8::GetDeviceData",
                device,
                GET_DEVICE_DATA_INDEX,
                get_device_data_detour as GetDeviceDataFn,
            )
        }?;
        ORIGINAL_GET_DEVICE_DATA.store(hook.original() as usize, Ordering::Release);
        hook.enable()?;
        hooks.data = Some(hook);
    }
    hooks.vtable = vtable;
    Ok(())
}

fn refresh_devices() {
    let focus = unsafe { read_game_ptr(FOCUS_SUBSYSTEM_PTR) };
    if focus.is_null() {
        KEYBOARD_DEVICE.store(0, Ordering::Release);
        MOUSE_DEVICE.store(0, Ordering::Release);
        return;
    }
    KEYBOARD_DEVICE.store(
        unsafe { read_game_ptr(focus as usize + KEYBOARD_DEVICE_OFFSET) } as usize,
        Ordering::Release,
    );
    MOUSE_DEVICE.store(
        unsafe { read_game_ptr(focus as usize + MOUSE_DEVICE_OFFSET) } as usize,
        Ordering::Release,
    );
}

fn hook_source_device() -> Option<*mut c_void> {
    let mouse = MOUSE_DEVICE.load(Ordering::Acquire) as *mut c_void;
    if !mouse.is_null() {
        return Some(mouse);
    }
    let keyboard = KEYBOARD_DEVICE.load(Ordering::Acquire) as *mut c_void;
    (!keyboard.is_null()).then_some(keyboard)
}

fn blocked_kind(device: *mut c_void) -> Option<DeviceKind> {
    if !INPUT_BLOCKED.load(Ordering::Acquire) || device.is_null() {
        return None;
    }
    let address = device as usize;
    if address == KEYBOARD_DEVICE.load(Ordering::Acquire) {
        Some(DeviceKind::Keyboard)
    } else if address == MOUSE_DEVICE.load(Ordering::Acquire) {
        Some(DeviceKind::Mouse)
    } else {
        None
    }
}

unsafe extern "system" fn get_device_state_detour(
    device: *mut c_void,
    data_size: u32,
    data: *mut c_void,
) -> i32 {
    if let Some(kind) = blocked_kind(device) {
        let result = if kind == DeviceKind::Mouse {
            unsafe { call_original_state(device, data_size, data) }
        } else {
            DI_OK
        };
        if kind == DeviceKind::Mouse && result >= 0 {
            queue_wheel_from_state(data_size, data);
        }
        if !data.is_null() && data_size <= MAX_ZEROED_STATE_BYTES {
            unsafe { ptr::write_bytes(data, 0, data_size as usize) };
        }
        return DI_OK;
    }
    unsafe { call_original_state(device, data_size, data) }
}

unsafe extern "system" fn get_device_data_detour(
    device: *mut c_void,
    object_size: u32,
    object_data: *mut c_void,
    count: *mut u32,
    flags: u32,
) -> i32 {
    if let Some(kind) = blocked_kind(device) {
        if kind == DeviceKind::Mouse {
            let result =
                unsafe { call_original_data(device, object_size, object_data, count, flags) };
            if result >= 0 {
                queue_wheel_from_buffer(object_size, object_data, count);
            }
        }
        if !count.is_null() {
            unsafe { *count = 0 };
        }
        return DI_OK;
    }
    unsafe { call_original_data(device, object_size, object_data, count, flags) }
}

unsafe fn call_original_state(device: *mut c_void, size: u32, data: *mut c_void) -> i32 {
    let original = ORIGINAL_GET_DEVICE_STATE.load(Ordering::Acquire);
    let Ok(original) = (unsafe { FnPtr::<GetDeviceStateFn>::from_raw(original as *mut c_void) })
    else {
        return DI_OK;
    };
    unsafe { original.as_fn()(device, size, data) }
}

unsafe fn call_original_data(
    device: *mut c_void,
    size: u32,
    data: *mut c_void,
    count: *mut u32,
    flags: u32,
) -> i32 {
    let original = ORIGINAL_GET_DEVICE_DATA.load(Ordering::Acquire);
    let Ok(original) = (unsafe { FnPtr::<GetDeviceDataFn>::from_raw(original as *mut c_void) })
    else {
        return DI_OK;
    };
    unsafe { original.as_fn()(device, size, data, count, flags) }
}

fn queue_wheel_from_state(size: u32, data: *mut c_void) {
    if data.is_null() || size < (DIMOUSESTATE_LZ_OFFSET + size_of::<i32>()) as u32 {
        return;
    }
    let wheel = unsafe {
        ptr::read_unaligned(
            (data as *const u8)
                .add(DIMOUSESTATE_LZ_OFFSET)
                .cast::<i32>(),
        )
    };
    queue_wheel(wheel);
}

fn queue_wheel_from_buffer(size: u32, data: *mut c_void, count: *mut u32) {
    if data.is_null()
        || count.is_null()
        || size < (DIDEVICEOBJECTDATA_DWDATA_OFFSET + size_of::<u32>()) as u32
    {
        return;
    }
    let count = unsafe { *count } as usize;
    for index in 0..count {
        let base = unsafe { (data as *const u8).add(index * size as usize) };
        let offset =
            unsafe { ptr::read_unaligned(base.add(DIDEVICEOBJECTDATA_DWOFS_OFFSET).cast::<u32>()) };
        if offset == DIMOFS_Z {
            let wheel = unsafe {
                ptr::read_unaligned(base.add(DIDEVICEOBJECTDATA_DWDATA_OFFSET).cast::<u32>())
            } as i32;
            queue_wheel(wheel);
        }
    }
}

fn queue_wheel(wheel: i32) {
    if wheel != 0 {
        psycho_imgui::queue_mouse_wheel_delta(wheel, 0);
    }
}

unsafe fn read_game_ptr(address: usize) -> *mut c_void {
    unsafe { (address as *const *mut c_void).read() }
}

unsafe fn read_vtable(object: *mut c_void) -> usize {
    if object.is_null() {
        0
    } else {
        unsafe { *(object as *const usize) }
    }
}
