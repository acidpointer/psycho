//! Alt-tab fix for Fallout: New Vegas
//!
//! - DisableProcessWindowsGhosting: prevents "(Not Responding)" ghost window
//!   that corrupts window state during loading screens
//! - Watchdog thread: monitors game window and restores it from a corrupted
//!   rect/style, but only when the game already owns the foreground. If the
//!   user has alt-tabbed to another window, the watchdog stays quiet so it
//!   doesn't fight the user for focus.

use std::sync::atomic::{AtomicI32, AtomicPtr, Ordering};

use libc::c_void;

unsafe extern "system" {
    fn DisableProcessWindowsGhosting();
    fn GetWindowRect(hwnd: *mut c_void, rect: *mut Rect) -> i32;
    fn GetWindowLongA(hwnd: *mut c_void, index: i32) -> i32;
    fn SetWindowLongA(hwnd: *mut c_void, index: i32, new_long: i32) -> i32;
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
    fn FindWindowA(class_name: *const u8, window_name: *const u8) -> *mut c_void;
    fn ShowWindow(hwnd: *mut c_void, cmd: i32) -> i32;
    fn GetForegroundWindow() -> *mut c_void;
}

const GWL_STYLE: i32 = -16;
const SWP_NOCOPYBITS: u32 = 0x0100;
const SWP_NOSENDCHANGING: u32 = 0x0400;
const SWP_FRAMECHANGED: u32 = 0x0020;
const HWND_TOP: *mut c_void = std::ptr::null_mut();
const WS_MINIMIZE: u32 = 0x20000000;
const SW_RESTORE: i32 = 9;

#[repr(C)]
struct Rect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

// ============================================================================
// Game addresses (diagnostic)
// ============================================================================

const NI_DX9_RENDERER_PTR: usize = 0x11C73B4;
const NI_RENDERER_WIDTH_OFFSET: usize = 0xA98;
const NI_RENDERER_HEIGHT_OFFSET: usize = 0xA9C;
const IS_FULLSCREEN_FUNC: usize = 0x446E10;

// ============================================================================
// Global state
// ============================================================================

static GAME_HWND: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

static EXPECTED_X: AtomicI32 = AtomicI32::new(i32::MIN);
static EXPECTED_Y: AtomicI32 = AtomicI32::new(i32::MIN);
static EXPECTED_W: AtomicI32 = AtomicI32::new(0);
static EXPECTED_H: AtomicI32 = AtomicI32::new(0);
static EXPECTED_STYLE: AtomicI32 = AtomicI32::new(0);

// ============================================================================
// Helpers
// ============================================================================

fn is_game_fullscreen() -> bool {
    let func: unsafe extern "C" fn() -> bool =
        unsafe { std::mem::transmute(IS_FULLSCREEN_FUNC as *const ()) };
    unsafe { func() }
}

fn find_game_window() -> *mut c_void {
    for class in [
        c"Gamebryo Application".as_ptr().cast::<u8>(),
        c"Fallout: New Vegas".as_ptr().cast::<u8>(),
    ] {
        let hwnd = unsafe { FindWindowA(class, std::ptr::null()) };
        if !hwnd.is_null() {
            return hwnd;
        }
    }
    std::ptr::null_mut()
}

// ============================================================================
// Watchdog
// ============================================================================

fn watchdog_loop() {
    log::info!("[DISPLAY] Watchdog thread started");

    // phase 1: find the game window
    let hwnd = loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let hwnd = find_game_window();
        if !hwnd.is_null() {
            GAME_HWND.store(hwnd, Ordering::SeqCst);
            log::info!("[DISPLAY] Watchdog found game window: {:p}", hwnd);
            break hwnd;
        }
    };

    // phase 2: wait for D3D9 init (window leaves initial 320x240)
    loop {
        std::thread::sleep(std::time::Duration::from_millis(100));

        if unsafe { IsWindow(hwnd) } == 0 {
            log::warn!("[DISPLAY] Game window destroyed during init");
            return;
        }

        let mut rect = Rect { left: 0, top: 0, right: 0, bottom: 0 };
        if unsafe { GetWindowRect(hwnd, &mut rect) } == 0 {
            continue;
        }

        let w = rect.right - rect.left;
        let h = rect.bottom - rect.top;

        if w > 640 && h > 480 {
            let style = unsafe { GetWindowLongA(hwnd, GWL_STYLE) };
            EXPECTED_X.store(rect.left, Ordering::Relaxed);
            EXPECTED_Y.store(rect.top, Ordering::Relaxed);
            EXPECTED_W.store(w, Ordering::Relaxed);
            EXPECTED_H.store(h, Ordering::Relaxed);
            EXPECTED_STYLE.store(style, Ordering::Relaxed);

            log::info!(
                "[DISPLAY] Watchdog captured: {}x{} at ({},{}) style={:#x}",
                w, h, rect.left, rect.top, style
            );
            break;
        }
    }

    // phase 3: monitor and restore
    let mut fix_count: u32 = 0;
    loop {
        std::thread::sleep(std::time::Duration::from_millis(100));

        if unsafe { IsWindow(hwnd) } == 0 {
            log::info!("[DISPLAY] Game window gone, watchdog exiting");
            return;
        }

        let ex = EXPECTED_X.load(Ordering::Relaxed);
        let ey = EXPECTED_Y.load(Ordering::Relaxed);
        let ew = EXPECTED_W.load(Ordering::Relaxed);
        let eh = EXPECTED_H.load(Ordering::Relaxed);
        if ew <= 0 || eh <= 0 {
            continue;
        }

        let mut rect = Rect { left: 0, top: 0, right: 0, bottom: 0 };
        if unsafe { GetWindowRect(hwnd, &mut rect) } == 0 {
            continue;
        }

        let cw = rect.right - rect.left;
        let ch = rect.bottom - rect.top;

        if cw != ew || ch != eh || rect.left != ex || rect.top != ey {
            // Skip restore if another window owns the foreground - user has
            // legitimately alt-tabbed away. Only recover when the game is
            // already foreground but its rect/style is corrupted (original bug).
            let fg = unsafe { GetForegroundWindow() };
            if fg != hwnd {
                continue;
            }

            fix_count += 1;
            let current_style = unsafe { GetWindowLongA(hwnd, GWL_STYLE) };
            log::warn!(
                "[DISPLAY] Watchdog fix #{}: rect=({},{} {}x{}) expected=({},{} {}x{}) style={:#x}",
                fix_count, rect.left, rect.top, cw, ch, ex, ey, ew, eh, current_style,
            );

            if (current_style as u32) & WS_MINIMIZE != 0 {
                unsafe { ShowWindow(hwnd, SW_RESTORE) };
            }

            let expected_style = EXPECTED_STYLE.load(Ordering::Relaxed);
            unsafe {
                SetWindowLongA(hwnd, GWL_STYLE, expected_style);
                SetWindowPos(
                    hwnd, HWND_TOP, ex, ey, ew, eh,
                    SWP_NOCOPYBITS | SWP_NOSENDCHANGING | SWP_FRAMECHANGED,
                );
            }
        }
    }
}

// ============================================================================
// Diagnostics (called at DeferredInit)
// ============================================================================

pub fn verify_display_resolution() {
    let renderer_ptr = unsafe { *(NI_DX9_RENDERER_PTR as *const *const u8) };
    if renderer_ptr.is_null() {
        log::warn!("[DISPLAY] NiDX9Renderer not initialized yet");
        return;
    }

    let actual_w = unsafe { *(renderer_ptr.add(NI_RENDERER_WIDTH_OFFSET) as *const u32) };
    let actual_h = unsafe { *(renderer_ptr.add(NI_RENDERER_HEIGHT_OFFSET) as *const u32) };
    let fullscreen = is_game_fullscreen();

    log::info!(
        "[DISPLAY] D3D9 backbuffer: {}x{}, fullscreen: {}",
        actual_w, actual_h, fullscreen
    );
}

// ============================================================================
// Installation
// ============================================================================

pub fn install_display_hooks() -> anyhow::Result<()> {
    log::info!("[DISPLAY] Installing alt-tab fix");

    unsafe { DisableProcessWindowsGhosting() };

    std::thread::spawn(watchdog_loop);

    log::info!("[DISPLAY] Installed");
    Ok(())
}
