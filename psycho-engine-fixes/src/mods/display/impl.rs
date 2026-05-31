//! Alt-tab fix for Fallout: New Vegas.
//!
//! Ghidra audit: the game already owns a focused/inactive window contract at
//! 0x00871C90 and stores the real HWND in OSGlobals+0x8. Stay inside that
//! contract instead of polling arbitrary desktop windows from a worker thread.

use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use libc::c_void;
use libpsycho::os::windows::hook::inline::inlinehook::InlineHookContainer;
use libpsycho::os::windows::winapi::{safe_write_8, safe_write_32};
use psycho_engine_fixes_api::{PSYCHO_EVENT_DEFERRED_INIT, PSYCHO_EVENT_ON_FRAME_PRESENT};

unsafe extern "system" {
    fn AdjustWindowRectEx(rect: *mut Rect, style: u32, menu: i32, ex_style: u32) -> i32;
    fn DisableProcessWindowsGhosting();
    fn GetActiveWindow() -> *mut c_void;
    fn GetWindowLongA(hwnd: *mut c_void, index: i32) -> i32;
    fn IsWindow(hwnd: *mut c_void) -> i32;
    fn SetWindowPos(
        hwnd: *mut c_void,
        after: *mut c_void,
        x: i32,
        y: i32,
        cx: i32,
        cy: i32,
        flags: u32,
    ) -> i32;
    fn ShowWindow(hwnd: *mut c_void, cmd: i32) -> i32;
}

const FOCUS_STATE_FUNC: usize = 0x00871C90;
const FOCUS_SUBSYSTEM_FUNC: usize = 0x007FDF30;
const FOCUS_INACTIVE_SIDE_EFFECT_FUNC: usize = 0x00AA50A0;
const OS_GLOBALS_PTR: usize = 0x011DEA0C;
const OS_GLOBALS_HWND_OFFSET: usize = 0x8;
const OS_GLOBALS_ACTIVE_OFFSET: usize = 0x3;

const NI_DX9_RENDERER_PTR: usize = 0x011C73B4;
const NI_RENDERER_WIDTH_OFFSET: usize = 0xA98;
const NI_RENDERER_HEIGHT_OFFSET: usize = 0xA9C;
const IS_FULLSCREEN_FUNC: usize = 0x00446E10;

const CONFIG_WIDTH_ADDR: usize = 0x0118947C;
const CONFIG_HEIGHT_ADDR: usize = 0x01189480;

const GWL_STYLE: i32 = -16;
const HWND_TOP: *mut c_void = std::ptr::null_mut();
const SW_RESTORE: i32 = 9;
const SWP_NOZORDER: u32 = 0x0004;
const SWP_NOACTIVATE: u32 = 0x0010;
const SWP_NOCOPYBITS: u32 = 0x0100;
const SWP_NOOWNERZORDER: u32 = 0x0200;
const WINDOW_REPAIR_FLAGS: u32 = SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOCOPYBITS | SWP_NOOWNERZORDER;
const WS_MINIMIZE: u32 = 0x20000000;

const MAIN_LOOP_REGAIN_SET_WINDOW_POS_CALL: usize = 0x0086B4BF;
const MAIN_LOOP_LOSE_SET_WINDOW_POS_CALL: usize = 0x0086B628;

type FocusStateFn = unsafe extern "thiscall" fn(*mut c_void, u8);
type FocusSubsystemFn = unsafe extern "C" fn() -> *mut c_void;
type FocusInactiveSideEffectFn = unsafe extern "thiscall" fn(*mut c_void);
type IsFullscreenFn = unsafe extern "C" fn() -> u8;
type SetWindowPosFn =
    unsafe extern "system" fn(*mut c_void, *mut c_void, i32, i32, i32, i32, u32) -> i32;

const INDIRECT_CALL_OPCODE: u8 = 0xFF;
const INDIRECT_CALL_MODRM_ABSOLUTE: u8 = 0x15;
const REL_CALL_OPCODE: u8 = 0xE8;
const NOP_OPCODE: u8 = 0x90;

static FOCUS_STATE_HOOK: LazyLock<InlineHookContainer<FocusStateFn>> =
    LazyLock::new(InlineHookContainer::new);
static DISPLAY_TWEAKS_INSTALLED: AtomicBool = AtomicBool::new(false);
static PENDING_FULLSCREEN_REPAIR: AtomicBool = AtomicBool::new(false);
static LAST_OS_GLOBALS: AtomicUsize = AtomicUsize::new(0);
static REPAIR_ATTEMPTS: AtomicU32 = AtomicU32::new(0);
static REPAIR_IN_PROGRESS: AtomicBool = AtomicBool::new(false);
static FORCED_INACTIVE_CORRECTIONS: AtomicU32 = AtomicU32::new(0);
static SKIPPED_VANILLA_WINDOW_REPAIRS: AtomicU32 = AtomicU32::new(0);

#[repr(C)]
struct Rect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

struct WindowSize {
    width: i32,
    height: i32,
    source: &'static str,
}

struct RepairGuard;

impl Drop for RepairGuard {
    fn drop(&mut self) {
        REPAIR_IN_PROGRESS.store(false, Ordering::Release);
    }
}

fn enter_repair() -> Option<RepairGuard> {
    REPAIR_IN_PROGRESS
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .ok()
        .map(|_| RepairGuard)
}

fn is_game_fullscreen() -> bool {
    let func: IsFullscreenFn = unsafe { std::mem::transmute(IS_FULLSCREEN_FUNC as *const ()) };
    unsafe { func() != 0 }
}

fn os_globals_from_global() -> *mut c_void {
    unsafe { *(OS_GLOBALS_PTR as *const *mut c_void) }
}

fn current_os_globals() -> *mut c_void {
    let global = os_globals_from_global();
    if !global.is_null() {
        return global;
    }

    let cached = LAST_OS_GLOBALS.load(Ordering::Acquire);
    if cached != 0 {
        cached as *mut c_void
    } else {
        os_globals_from_global()
    }
}

fn game_hwnd_from_os_globals(os_globals: *mut c_void) -> *mut c_void {
    if os_globals.is_null() {
        return std::ptr::null_mut();
    }

    unsafe { *((os_globals as *const u8).add(OS_GLOBALS_HWND_OFFSET) as *const *mut c_void) }
}

fn os_globals_active(os_globals: *mut c_void) -> u8 {
    if os_globals.is_null() {
        return 0;
    }

    unsafe { *((os_globals as *const u8).add(OS_GLOBALS_ACTIVE_OFFSET) as *const u8) }
}

fn set_os_globals_active(os_globals: *mut c_void, active: u8) {
    if os_globals.is_null() {
        return;
    }

    unsafe { *((os_globals as *mut u8).add(OS_GLOBALS_ACTIVE_OFFSET)) = active };
}

fn sane_size(width: u32, height: u32) -> Option<(i32, i32)> {
    if width == 0 || height == 0 || width > 16384 || height > 16384 {
        return None;
    }

    Some((width as i32, height as i32))
}

fn renderer_size() -> Option<WindowSize> {
    let renderer_ptr = unsafe { *(NI_DX9_RENDERER_PTR as *const *const u8) };
    if renderer_ptr.is_null() {
        return None;
    }

    let width = unsafe { *(renderer_ptr.add(NI_RENDERER_WIDTH_OFFSET) as *const u32) };
    let height = unsafe { *(renderer_ptr.add(NI_RENDERER_HEIGHT_OFFSET) as *const u32) };
    let (width, height) = sane_size(width, height)?;

    Some(WindowSize {
        width,
        height,
        source: "renderer",
    })
}

fn configured_size() -> Option<WindowSize> {
    let width = unsafe { *(CONFIG_WIDTH_ADDR as *const u32) };
    let height = unsafe { *(CONFIG_HEIGHT_ADDR as *const u32) };
    let (width, height) = sane_size(width, height)?;

    Some(WindowSize {
        width,
        height,
        source: "config",
    })
}

fn window_size() -> Option<WindowSize> {
    renderer_size().or_else(configured_size)
}

fn fullscreen_window_rect(hwnd: *mut c_void) -> Option<(Rect, &'static str)> {
    let size = window_size()?;
    let mut rect = Rect {
        left: 0,
        top: 0,
        right: size.width,
        bottom: size.height,
    };

    let style = unsafe { GetWindowLongA(hwnd, GWL_STYLE) };
    if unsafe { AdjustWindowRectEx(&mut rect, style as u32, 0, 0) } == 0 {
        return None;
    }

    Some((rect, size.source))
}

fn game_window_is_active(hwnd: *mut c_void) -> bool {
    unsafe { GetActiveWindow() == hwnd }
}

fn correct_forced_fullscreen_inactive(os_globals: *mut c_void) {
    if os_globals_active(os_globals) == 0 {
        return;
    }

    let focus_subsystem: FocusSubsystemFn =
        unsafe { std::mem::transmute(FOCUS_SUBSYSTEM_FUNC as *const ()) };
    let inactive_side_effect: FocusInactiveSideEffectFn =
        unsafe { std::mem::transmute(FOCUS_INACTIVE_SIDE_EFFECT_FUNC as *const ()) };

    let focus = unsafe { focus_subsystem() };
    if !focus.is_null() {
        unsafe { inactive_side_effect(focus) };
    }
    set_os_globals_active(os_globals, 0);

    let count = FORCED_INACTIVE_CORRECTIONS.fetch_add(1, Ordering::AcqRel) + 1;
    if count <= 3 || count.is_power_of_two() {
        log::info!(
            "[DISPLAY] corrected fullscreen focus loss #{}: vanilla forced active state",
            count
        );
    }
}

fn repair_fullscreen_window(reason: &str, require_active_window: bool) {
    if !is_game_fullscreen() {
        return;
    }

    let Some(_guard) = enter_repair() else {
        return;
    };

    let hwnd = game_hwnd_from_os_globals(current_os_globals());
    if hwnd.is_null() || unsafe { IsWindow(hwnd) } == 0 {
        log::warn!("[DISPLAY] fullscreen repair skipped: game window is not available");
        return;
    }

    if require_active_window && !game_window_is_active(hwnd) {
        log::debug!("[DISPLAY] fullscreen repair skipped: game window is not active");
        return;
    }

    let style = unsafe { GetWindowLongA(hwnd, GWL_STYLE) };
    if (style as u32) & WS_MINIMIZE != 0 {
        unsafe { ShowWindow(hwnd, SW_RESTORE) };
    }

    let Some(rect) = fullscreen_window_rect(hwnd) else {
        log::warn!("[DISPLAY] fullscreen repair skipped: invalid window geometry");
        return;
    };
    let (rect, size_source) = rect;

    let width = rect.right - rect.left;
    let height = rect.bottom - rect.top;
    if width <= 0 || height <= 0 {
        log::warn!(
            "[DISPLAY] fullscreen repair skipped: bad rect ({},{} {}x{})",
            rect.left,
            rect.top,
            width,
            height
        );
        return;
    }

    let attempt = REPAIR_ATTEMPTS.fetch_add(1, Ordering::AcqRel) + 1;
    let ok = unsafe {
        SetWindowPos(
            hwnd,
            HWND_TOP,
            rect.left,
            rect.top,
            width,
            height,
            WINDOW_REPAIR_FLAGS,
        )
    } != 0;

    if !ok {
        log::warn!(
            "[DISPLAY] fullscreen repair failed #{}: reason={} size_source={} rect=({},{} {}x{})",
            attempt,
            reason,
            size_source,
            rect.left,
            rect.top,
            width,
            height
        );
    } else if attempt <= 3 || attempt.is_power_of_two() {
        log::info!(
            "[DISPLAY] fullscreen repair #{}: reason={} size_source={} rect=({},{} {}x{})",
            attempt,
            reason,
            size_source,
            rect.left,
            rect.top,
            width,
            height
        );
    }
}

unsafe extern "thiscall" fn hook_focus_state(this: *mut c_void, active: u8) {
    let Ok(original) = FOCUS_STATE_HOOK.original() else {
        return;
    };

    unsafe { original(this, active) };

    if !this.is_null() {
        LAST_OS_GLOBALS.store(this as usize, Ordering::Release);
    }

    if active != 0 {
        PENDING_FULLSCREEN_REPAIR.store(true, Ordering::Release);
    } else {
        correct_forced_fullscreen_inactive(this);
        PENDING_FULLSCREEN_REPAIR.store(false, Ordering::Release);
    }
}

unsafe extern "system" fn hook_main_loop_set_window_pos(
    hwnd: *mut c_void,
    after: *mut c_void,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    flags: u32,
) -> i32 {
    if DISPLAY_TWEAKS_INSTALLED.load(Ordering::Acquire) && is_game_fullscreen() {
        let count = SKIPPED_VANILLA_WINDOW_REPAIRS.fetch_add(1, Ordering::AcqRel) + 1;
        if count <= 3 || count.is_power_of_two() {
            log::info!(
                "[DISPLAY] skipped vanilla fullscreen SetWindowPos #{}: rect=({},{} {}x{}) flags={:#x}",
                count,
                x,
                y,
                cx,
                cy,
                flags
            );
        }
        return 1;
    }

    unsafe { SetWindowPos(hwnd, after, x, y, cx, cy, flags) }
}

unsafe fn replace_indirect_call(call_addr: usize, target: SetWindowPosFn) -> anyhow::Result<()> {
    let ptr = call_addr as *const u8;
    let opcode = unsafe { *ptr };
    let modrm = unsafe { *ptr.add(1) };
    if opcode != INDIRECT_CALL_OPCODE || modrm != INDIRECT_CALL_MODRM_ABSOLUTE {
        anyhow::bail!(
            "expected FF 15 indirect call at 0x{call_addr:08X}, found {opcode:02X} {modrm:02X}"
        );
    }

    let target_addr = target as usize;
    let next_instruction = call_addr.wrapping_add(5);
    let offset = target_addr.wrapping_sub(next_instruction) as u32;

    safe_write_8(call_addr as *mut c_void, REL_CALL_OPCODE)?;
    safe_write_32((call_addr + 1) as *mut c_void, offset)?;
    safe_write_8((call_addr + 5) as *mut c_void, NOP_OPCODE)?;

    Ok(())
}

pub fn observe_event(kind: u32) {
    if !DISPLAY_TWEAKS_INSTALLED.load(Ordering::Acquire) {
        return;
    }

    match kind {
        PSYCHO_EVENT_DEFERRED_INIT => {
            verify_display_resolution();
        }
        PSYCHO_EVENT_ON_FRAME_PRESENT => {
            if PENDING_FULLSCREEN_REPAIR.swap(false, Ordering::AcqRel) {
                repair_fullscreen_window("focus-regain-present", true);
            }
        }
        _ => {}
    }
}

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
        actual_w,
        actual_h,
        fullscreen
    );
}

pub fn install_display_hooks() -> anyhow::Result<()> {
    log::info!("[DISPLAY] Installing alt-tab fix");

    unsafe { DisableProcessWindowsGhosting() };

    FOCUS_STATE_HOOK.init(
        "display_focus_state",
        FOCUS_STATE_FUNC as *mut c_void,
        hook_focus_state,
    )?;
    FOCUS_STATE_HOOK.enable()?;
    unsafe {
        replace_indirect_call(
            MAIN_LOOP_REGAIN_SET_WINDOW_POS_CALL,
            hook_main_loop_set_window_pos as SetWindowPosFn,
        )?;
        replace_indirect_call(
            MAIN_LOOP_LOSE_SET_WINDOW_POS_CALL,
            hook_main_loop_set_window_pos as SetWindowPosFn,
        )?;
    }
    DISPLAY_TWEAKS_INSTALLED.store(true, Ordering::Release);

    log::info!("[DISPLAY] Installed");
    Ok(())
}
