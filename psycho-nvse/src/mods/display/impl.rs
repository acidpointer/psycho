//! Borderless fullscreen -- fixes broken alt-tab with DXVK
//!
//! Forces the game into borderless windowed mode regardless of INI settings.
//! Hooks GetPrivateProfileIntA to intercept INI reads, CreateWindowExA to
//! strip decorations and size the window to screen, SetWindowPos to prevent
//! the game from moving/resizing the window.
//!
//! Replaces OneTweak with a cleaner, single-purpose implementation.

use std::ffi::CStr;
use std::sync::atomic::{AtomicPtr, Ordering};

use libc::c_void;
use libpsycho::os::windows::hook::iat::iathook::IatHookContainer;
use libpsycho::os::windows::winapi::get_module_handle_a;

// ============================================================================
// Win32 constants
// ============================================================================

const WS_OVERLAPPEDWINDOW: u32 = 0x00CF0000;
const WS_POPUP: u32 = 0x80000000;
const WS_VISIBLE: u32 = 0x10000000;

const WS_EX_OVERLAPPEDWINDOW: u32 = 0x00000300;
const WS_EX_TOPMOST: u32 = 0x00000008;

const SWP_NOCOPYBITS: u32 = 0x0100;
const SWP_NOSENDCHANGING: u32 = 0x0400;
const SWP_FRAMECHANGED: u32 = 0x0020;

const GWL_STYLE: i32 = -16;
const GWL_EXSTYLE: i32 = -20;
const GWLP_WNDPROC: i32 = -4;
const WM_ACTIVATE: u32 = 0x0006;
const SM_CXSCREEN: i32 = 0;
const SM_CYSCREEN: i32 = 1;

const HWND_TOP: *mut c_void = std::ptr::null_mut();

// ============================================================================
// Win32 FFI
// ============================================================================

unsafe extern "system" {
    fn GetSystemMetrics(index: i32) -> i32;
    fn SetWindowLongA(hwnd: *mut c_void, index: i32, new_long: i32) -> i32;
    fn ShowCursor(show: i32) -> i32;
    fn CallWindowProcA(
        prev: *mut c_void,
        hwnd: *mut c_void,
        msg: u32,
        wparam: usize,
        lparam: isize,
    ) -> isize;
}

// ============================================================================
// Hook function type signatures
// ============================================================================

#[allow(non_snake_case)]
type GetPrivateProfileIntAFn =
    unsafe extern "system" fn(*const u8, *const u8, i32, *const u8) -> u32;

#[allow(non_snake_case)]
type CreateWindowExAFn = unsafe extern "system" fn(
    u32,
    *const u8,
    *const u8,
    u32,
    i32,
    i32,
    i32,
    i32,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut c_void,
) -> *mut c_void;

#[allow(non_snake_case)]
type SetWindowPosFn =
    unsafe extern "system" fn(*mut c_void, *mut c_void, i32, i32, i32, i32, u32) -> i32;

// ============================================================================
// IAT hook containers
// ============================================================================

static GET_PRIVATE_PROFILE_INT_HOOK: std::sync::LazyLock<
    IatHookContainer<GetPrivateProfileIntAFn>,
> = std::sync::LazyLock::new(IatHookContainer::new);

static CREATE_WINDOW_EX_HOOK: std::sync::LazyLock<IatHookContainer<CreateWindowExAFn>> =
    std::sync::LazyLock::new(IatHookContainer::new);

static SET_WINDOW_POS_HOOK: std::sync::LazyLock<IatHookContainer<SetWindowPosFn>> =
    std::sync::LazyLock::new(IatHookContainer::new);

// ============================================================================
// Global state
// ============================================================================

static GAME_HWND: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIG_WNDPROC: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

// ============================================================================
// Helpers
// ============================================================================

#[inline]
unsafe fn cstr_eq_ignore_case(ptr: *const u8, target: &[u8]) -> bool {
    if ptr.is_null() {
        return false;
    }
    let s = unsafe { CStr::from_ptr(ptr as *const i8) };
    let bytes = s.to_bytes();
    bytes.len() == target.len()
        && bytes
            .iter()
            .zip(target)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn screen_width() -> i32 {
    unsafe { GetSystemMetrics(SM_CXSCREEN) }
}

fn screen_height() -> i32 {
    unsafe { GetSystemMetrics(SM_CYSCREEN) }
}

// ============================================================================
// Hook: GetPrivateProfileIntA
// ============================================================================

unsafe extern "system" fn hook_get_private_profile_int(
    app_name: *const u8,
    key_name: *const u8,
    default: i32,
    file_name: *const u8,
) -> u32 {
    let is_display = unsafe { cstr_eq_ignore_case(app_name, b"Display") };

    if is_display {
        if unsafe { cstr_eq_ignore_case(key_name, b"bFull Screen") } {
            log::debug!("[DISPLAY] INI: bFull Screen -> 0 (forced windowed)");
            return 0;
        }
        // iSize W/H: let the game read its own INI values.
        // the render resolution stays as the user configured (e.g. 1920x1080).
        // DXVK stretches the backbuffer to fill the borderless window automatically.
        if unsafe { cstr_eq_ignore_case(key_name, b"bAlwaysActive") } {
            return 1;
        }
    }

    match GET_PRIVATE_PROFILE_INT_HOOK.original() {
        Ok(original) => unsafe { original(app_name, key_name, default, file_name) },
        Err(_) => default as u32,
    }
}

// ============================================================================
// Hook: CreateWindowExA
// ============================================================================

unsafe extern "system" fn hook_create_window_ex(
    ex_style: u32,
    class_name: *const u8,
    window_name: *const u8,
    style: u32,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    parent: *mut c_void,
    menu: *mut c_void,
    instance: *mut c_void,
    param: *mut c_void,
) -> *mut c_void {
    let original = match CREATE_WINDOW_EX_HOOK.original() {
        Ok(f) => f,
        Err(_) => return std::ptr::null_mut(),
    };

    let hwnd = unsafe {
        original(
            ex_style,
            class_name,
            window_name,
            style,
            x,
            y,
            width,
            height,
            parent,
            menu,
            instance,
            param,
        )
    };

    if hwnd.is_null() || !parent.is_null() {
        return hwnd;
    }

    // only apply to the first top-level window
    if GAME_HWND
        .compare_exchange(
            std::ptr::null_mut(),
            hwnd,
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .is_err()
    {
        return hwnd;
    }

    log::info!("[DISPLAY] Game window created: {:p}", hwnd);

    let new_style = (style & !WS_OVERLAPPEDWINDOW) | WS_POPUP | WS_VISIBLE;
    let new_exstyle = ex_style & !(WS_EX_OVERLAPPEDWINDOW | WS_EX_TOPMOST);

    unsafe {
        SetWindowLongA(hwnd, GWL_STYLE, new_style as i32);
        SetWindowLongA(hwnd, GWL_EXSTYLE, new_exstyle as i32);
    }

    let sw = screen_width();
    let sh = screen_height();

    if let Ok(set_pos) = SET_WINDOW_POS_HOOK.original() {
        unsafe {
            set_pos(
                hwnd,
                HWND_TOP,
                0,
                0,
                sw,
                sh,
                SWP_NOCOPYBITS | SWP_NOSENDCHANGING | SWP_FRAMECHANGED,
            );
        }
    }

    // subclass WndProc
    let wndproc_ptr: *const () = our_wndproc as *const ();
    let old = unsafe { SetWindowLongA(hwnd, GWLP_WNDPROC, wndproc_ptr as i32) };
    if old != 0 {
        ORIG_WNDPROC.store(old as usize as *mut c_void, Ordering::SeqCst);
        log::info!("[DISPLAY] WndProc subclassed (original: {:#x})", old);
    }

    log::info!(
        "[DISPLAY] Borderless applied: {}x{}, style={:#x}, exstyle={:#x}",
        sw,
        sh,
        new_style,
        new_exstyle
    );

    hwnd
}

// ============================================================================
// Hook: SetWindowPos
// ============================================================================

unsafe extern "system" fn hook_set_window_pos(
    hwnd: *mut c_void,
    insert_after: *mut c_void,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    flags: u32,
) -> i32 {
    let original = match SET_WINDOW_POS_HOOK.original() {
        Ok(f) => f,
        Err(_) => return 0,
    };

    let game_hwnd = GAME_HWND.load(Ordering::Relaxed);

    if !game_hwnd.is_null() && hwnd == game_hwnd {
        return unsafe {
            original(
                hwnd,
                HWND_TOP,
                0,
                0,
                screen_width(),
                screen_height(),
                flags | SWP_NOCOPYBITS | SWP_NOSENDCHANGING,
            )
        };
    }

    unsafe { original(hwnd, insert_after, x, y, cx, cy, flags) }
}

// ============================================================================
// WndProc subclass
// ============================================================================

unsafe extern "system" fn our_wndproc(
    hwnd: *mut c_void,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    if msg == WM_ACTIVATE {
        let activated = (wparam & 0xFFFF) != 0;
        if activated {
            unsafe { while ShowCursor(0) >= 0 {} }
        } else {
            unsafe { while ShowCursor(1) < 0 {} }
        }
    }

    let orig = ORIG_WNDPROC.load(Ordering::Relaxed);
    if !orig.is_null() {
        unsafe { CallWindowProcA(orig, hwnd, msg, wparam, lparam) }
    } else {
        0
    }
}

// ============================================================================
// Installation
// ============================================================================

pub fn install_display_hooks() -> anyhow::Result<()> {
    log::info!("[DISPLAY] Installing borderless fullscreen hooks");

    let module_base = get_module_handle_a(None)?.as_ptr();

    unsafe {
        GET_PRIVATE_PROFILE_INT_HOOK.init(
            "GetPrivateProfileIntA",
            module_base,
            None,
            "GetPrivateProfileIntA",
            hook_get_private_profile_int,
        )?;
    }
    GET_PRIVATE_PROFILE_INT_HOOK.enable()?;
    log::info!("[DISPLAY] Hooked GetPrivateProfileIntA");

    unsafe {
        CREATE_WINDOW_EX_HOOK.init(
            "CreateWindowExA",
            module_base,
            None,
            "CreateWindowExA",
            hook_create_window_ex,
        )?;
    }
    CREATE_WINDOW_EX_HOOK.enable()?;
    log::info!("[DISPLAY] Hooked CreateWindowExA");

    unsafe {
        SET_WINDOW_POS_HOOK.init(
            "SetWindowPos",
            module_base,
            None,
            "SetWindowPos",
            hook_set_window_pos,
        )?;
    }
    SET_WINDOW_POS_HOOK.enable()?;
    log::info!("[DISPLAY] Hooked SetWindowPos");

    log::info!(
        "[DISPLAY] All hooks installed (screen: {}x{})",
        screen_width(),
        screen_height()
    );

    Ok(())
}
