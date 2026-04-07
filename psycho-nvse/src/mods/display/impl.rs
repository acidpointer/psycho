//! Borderless fullscreen -- fixes broken alt-tab with DXVK
//!
//! Forces the game into borderless windowed mode regardless of INI settings.
//! Hooks GetPrivateProfileIntA to intercept INI reads, CreateWindowExA to
//! strip decorations and size the window to screen. A watchdog thread polls
//! the window rect every 100ms and fixes any rogue resizes from DXVK, Wine,
//! ghost window recovery, or the game itself.
//!
//! Replaces OneTweak with a cleaner, single-purpose implementation.

use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, Ordering};

use libc::c_void;
use libpsycho::os::windows::hook::iat::iathook::IatHookContainer;
use libpsycho::os::windows::winapi::get_module_handle_a;

// ============================================================================
// Win32 constants
// ============================================================================

const WS_POPUP: u32 = 0x80000000;
const WS_VISIBLE: u32 = 0x10000000;

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

/// max iterations for ShowCursor loop to prevent hangs on Wine/Proton
const CURSOR_LOOP_LIMIT: i32 = 32;

// ============================================================================
// Win32 FFI
// ============================================================================

unsafe extern "system" {
    fn GetSystemMetrics(index: i32) -> i32;
    fn GetWindowLongA(hwnd: *mut c_void, index: i32) -> i32;
    fn SetWindowLongA(hwnd: *mut c_void, index: i32, new_long: i32) -> i32;
    fn DefWindowProcA(hwnd: *mut c_void, msg: u32, wparam: usize, lparam: isize) -> isize;
    fn ShowCursor(show: i32) -> i32;
    fn CallWindowProcA(
        prev: *mut c_void,
        hwnd: *mut c_void,
        msg: u32,
        wparam: usize,
        lparam: isize,
    ) -> isize;
    fn GetClassNameA(hwnd: *mut c_void, buf: *mut u8, max_count: i32) -> i32;
    fn MonitorFromWindow(hwnd: *mut c_void, flags: u32) -> *mut c_void;
    fn GetMonitorInfoA(monitor: *mut c_void, info: *mut MonitorInfoA) -> i32;
    fn DisableProcessWindowsGhosting();
    fn GetWindowRect(hwnd: *mut c_void, rect: *mut Rect) -> i32;
    fn SetWindowPos(
        hwnd: *mut c_void,
        after: *mut c_void,
        x: i32,
        y: i32,
        cx: i32,
        cy: i32,
        flags: u32,
    ) -> i32;
    fn IsWindow(hwnd: *mut c_void) -> i32;
}

const MONITOR_DEFAULTTONEAREST: u32 = 0x00000002;

#[repr(C)]
struct Rect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

#[repr(C)]
struct MonitorInfoA {
    cb_size: u32,
    rc_monitor: Rect,
    rc_work: Rect,
    dw_flags: u32,
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

// ============================================================================
// IAT hook containers
// ============================================================================

static GET_PRIVATE_PROFILE_INT_HOOK: std::sync::LazyLock<
    IatHookContainer<GetPrivateProfileIntAFn>,
> = std::sync::LazyLock::new(IatHookContainer::new);

static CREATE_WINDOW_EX_HOOK: std::sync::LazyLock<IatHookContainer<CreateWindowExAFn>> =
    std::sync::LazyLock::new(IatHookContainer::new);

// ============================================================================
// Global state
// ============================================================================

static GAME_HWND: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIG_WNDPROC: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Cached monitor rect -- set once when we find the game window.
static SCREEN_X: AtomicI32 = AtomicI32::new(0);
static SCREEN_Y: AtomicI32 = AtomicI32::new(0);
static SCREEN_W: AtomicI32 = AtomicI32::new(0);
static SCREEN_H: AtomicI32 = AtomicI32::new(0);

/// Set to true once borderless is fully configured. The watchdog
/// only starts enforcing after this is set.
static BORDERLESS_READY: AtomicBool = AtomicBool::new(false);

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

/// Check if an LPCSTR contains a substring (case-insensitive).
#[inline]
unsafe fn cstr_contains_ignore_case(ptr: *const u8, needle: &[u8]) -> bool {
    if ptr.is_null() {
        return false;
    }
    let s = unsafe { CStr::from_ptr(ptr as *const i8) };
    let haystack = s.to_bytes();
    haystack
        .windows(needle.len())
        .any(|w| w.iter().zip(needle).all(|(a, b)| a.eq_ignore_ascii_case(b)))
}

/// Get the monitor dimensions for a given window (handles multi-monitor).
/// Falls back to primary monitor via GetSystemMetrics if MonitorFromWindow fails.
fn get_monitor_rect(hwnd: *mut c_void) -> (i32, i32, i32, i32) {
    let monitor = unsafe { MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) };
    if !monitor.is_null() {
        let mut info = MonitorInfoA {
            cb_size: std::mem::size_of::<MonitorInfoA>() as u32,
            rc_monitor: Rect {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            },
            rc_work: Rect {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            },
            dw_flags: 0,
        };
        if unsafe { GetMonitorInfoA(monitor, &mut info) } != 0 {
            let r = &info.rc_monitor;
            return (r.left, r.top, r.right - r.left, r.bottom - r.top);
        }
    }
    // fallback: primary monitor
    let w = unsafe { GetSystemMetrics(SM_CXSCREEN) };
    let h = unsafe { GetSystemMetrics(SM_CYSCREEN) };
    (0, 0, w, h)
}

/// Check if a window's class name matches any known Fallout/Gamebryo patterns.
fn is_game_window(hwnd: *mut c_void) -> bool {
    let mut buf = [0u8; 128];
    let len = unsafe { GetClassNameA(hwnd, buf.as_mut_ptr(), buf.len() as i32) };
    if len <= 0 {
        return false;
    }
    let name = &buf[..len as usize];
    name.eq_ignore_ascii_case(b"Gamebryo Application")
}

/// Apply borderless style + fullscreen positioning to the game window.
/// Uses raw user32 SetWindowPos (not hooked), safe to call from any thread.
unsafe fn force_borderless(hwnd: *mut c_void) {
    let sw = SCREEN_W.load(Ordering::Relaxed);
    let sh = SCREEN_H.load(Ordering::Relaxed);
    if sw <= 0 || sh <= 0 {
        return;
    }

    unsafe {
        SetWindowLongA(hwnd, GWL_STYLE, (WS_POPUP | WS_VISIBLE) as i32);
        SetWindowLongA(hwnd, GWL_EXSTYLE, 0);
        SetWindowPos(
            hwnd,
            HWND_TOP,
            SCREEN_X.load(Ordering::Relaxed),
            SCREEN_Y.load(Ordering::Relaxed),
            sw,
            sh,
            SWP_NOCOPYBITS | SWP_NOSENDCHANGING | SWP_FRAMECHANGED,
        );
    }
}

/// Restore our WndProc if something replaced it (ghost window, etc).
/// Only updates ORIG_WNDPROC if the current WndProc is neither ours
/// nor the already-saved original (avoids saving garbage ghost pointers).
unsafe fn restore_wndproc_if_needed(hwnd: *mut c_void) {
    let current = unsafe { GetWindowLongA(hwnd, GWLP_WNDPROC) } as usize;
    let ours = our_wndproc as *const () as usize;
    if current == ours || current == 0 {
        return;
    }

    // the current WndProc is neither ours nor null -- something replaced us.
    // only update ORIG_WNDPROC if the current value looks like the game's
    // original (not some transient ghost pointer). we check: is the saved
    // original still non-null? if so, keep it (it's the game's real one).
    let saved = ORIG_WNDPROC.load(Ordering::Relaxed);
    let wndproc_ptr: *const () = our_wndproc as *const ();
    let old = unsafe { SetWindowLongA(hwnd, GWLP_WNDPROC, wndproc_ptr as i32) };
    if old != 0 && saved.is_null() {
        // first time saving -- this is the game's real WndProc
        ORIG_WNDPROC.store(old as usize as *mut c_void, Ordering::SeqCst);
    }
    // if saved is already set, don't overwrite with ghost/transient WndProc
    log::warn!("[DISPLAY] WndProc was replaced ({:#x}), re-installed ours", current);
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
    // only intercept reads from Fallout INI files
    let is_fallout_ini = unsafe { cstr_contains_ignore_case(file_name, b"Fallout") };

    if is_fallout_ini {
        let is_display = unsafe { cstr_eq_ignore_case(app_name, b"Display") };
        if is_display {
            if unsafe { cstr_eq_ignore_case(key_name, b"bFull Screen") } {
                log::debug!("[DISPLAY] INI: bFull Screen -> 0 (forced windowed)");
                return 0;
            }
            // log the render resolution the game reads from its INI
            if unsafe { cstr_eq_ignore_case(key_name, b"iSize W") } {
                let val = match GET_PRIVATE_PROFILE_INT_HOOK.original() {
                    Ok(f) => unsafe { f(app_name, key_name, default, file_name) },
                    Err(_) => default as u32,
                };
                log::info!("[DISPLAY] INI: iSize W = {} (render width)", val);
                return val;
            }
            if unsafe { cstr_eq_ignore_case(key_name, b"iSize H") } {
                let val = match GET_PRIVATE_PROFILE_INT_HOOK.original() {
                    Ok(f) => unsafe { f(app_name, key_name, default, file_name) },
                    Err(_) => default as u32,
                };
                log::info!("[DISPLAY] INI: iSize H = {} (render height)", val);
                return val;
            }
        }

        // bAlwaysActive lives under General section
        let is_general = unsafe { cstr_eq_ignore_case(app_name, b"General") };
        if is_general && unsafe { cstr_eq_ignore_case(key_name, b"bAlwaysActive") } {
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

    // verify this is the actual game window
    if !is_game_window(hwnd) {
        return hwnd;
    }

    // only apply to the first game window
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

    // get the monitor this window is on (handles multi-monitor)
    let (mx, my, mw, mh) = get_monitor_rect(hwnd);
    SCREEN_X.store(mx, Ordering::Relaxed);
    SCREEN_Y.store(my, Ordering::Relaxed);
    SCREEN_W.store(mw, Ordering::Relaxed);
    SCREEN_H.store(mh, Ordering::Relaxed);

    // apply borderless style + position
    unsafe { force_borderless(hwnd) };

    // subclass WndProc for focus handling
    let wndproc_ptr: *const () = our_wndproc as *const ();
    let old = unsafe { SetWindowLongA(hwnd, GWLP_WNDPROC, wndproc_ptr as i32) };
    if old != 0 {
        ORIG_WNDPROC.store(old as usize as *mut c_void, Ordering::SeqCst);
        log::info!("[DISPLAY] WndProc subclassed (original: {:#x})", old);
    } else {
        log::warn!("[DISPLAY] SetWindowLongA for WndProc returned 0");
    }

    // signal watchdog that borderless is ready
    BORDERLESS_READY.store(true, Ordering::Release);

    log::info!(
        "[DISPLAY] Borderless applied: {}x{} at ({},{})",
        mw, mh, mx, my
    );

    hwnd
}

// ============================================================================
// WndProc subclass -- focus handling + cursor management
// ============================================================================

unsafe fn call_original_wndproc(
    hwnd: *mut c_void,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    let orig = ORIG_WNDPROC.load(Ordering::Relaxed);
    if !orig.is_null() {
        unsafe { CallWindowProcA(orig, hwnd, msg, wparam, lparam) }
    } else {
        unsafe { DefWindowProcA(hwnd, msg, wparam, lparam) }
    }
}

unsafe extern "system" fn our_wndproc(
    hwnd: *mut c_void,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    if msg == WM_ACTIVATE {
        // let the game handle WM_ACTIVATE first, then fix up
        let result = unsafe { call_original_wndproc(hwnd, msg, wparam, lparam) };

        let activated = (wparam & 0xFFFF) != 0;
        if activated {
            // force borderless back in case game's handler messed with it
            unsafe { force_borderless(hwnd) };
            for _ in 0..CURSOR_LOOP_LIMIT {
                if unsafe { ShowCursor(0) } < 0 {
                    break;
                }
            }
        } else {
            for _ in 0..CURSOR_LOOP_LIMIT {
                if unsafe { ShowCursor(1) } >= 0 {
                    break;
                }
            }
        }
        return result;
    }

    unsafe { call_original_wndproc(hwnd, msg, wparam, lparam) }
}

// ============================================================================
// Watchdog thread
// ============================================================================

fn watchdog_loop() {
    log::info!("[DISPLAY] Watchdog thread started");

    loop {
        std::thread::sleep(std::time::Duration::from_millis(100));

        // don't enforce until borderless is fully configured
        if !BORDERLESS_READY.load(Ordering::Acquire) {
            continue;
        }

        let hwnd = GAME_HWND.load(Ordering::Relaxed);
        if hwnd.is_null() {
            continue;
        }

        // check window is still valid (game might have exited)
        if unsafe { IsWindow(hwnd) } == 0 {
            continue;
        }

        let sx = SCREEN_X.load(Ordering::Relaxed);
        let sy = SCREEN_Y.load(Ordering::Relaxed);
        let sw = SCREEN_W.load(Ordering::Relaxed);
        let sh = SCREEN_H.load(Ordering::Relaxed);
        if sw <= 0 || sh <= 0 {
            continue;
        }

        // check current window rect
        let mut rect = Rect {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        if unsafe { GetWindowRect(hwnd, &mut rect) } == 0 {
            continue;
        }

        let cw = rect.right - rect.left;
        let ch = rect.bottom - rect.top;

        if cw != sw || ch != sh || rect.left != sx || rect.top != sy {
            unsafe { force_borderless(hwnd) };
            unsafe { restore_wndproc_if_needed(hwnd) };
        }
    }
}

// ============================================================================
// Installation
// ============================================================================

pub fn install_display_hooks() -> anyhow::Result<()> {
    log::info!("[DISPLAY] Installing borderless fullscreen hooks");

    // prevent "(Not Responding)" ghost window during loading screens
    unsafe { DisableProcessWindowsGhosting() };

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

    // watchdog: polls window rect and fixes rogue resizes from DXVK,
    // Wine internals, ghost window recovery, or the game itself.
    std::thread::spawn(watchdog_loop);

    log::info!("[DISPLAY] All hooks + watchdog installed");

    Ok(())
}
