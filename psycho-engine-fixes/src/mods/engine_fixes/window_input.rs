//! Owns cursor confinement and system-key delivery at audited window/input boundaries.
//!
//! # Cursor ownership
//!
//! FalloutNV.exe creates its visible top-level window at the audited
//! `CreateWindowExA` caller in [`super::display`]. When cursor confinement is
//! enabled, that boundary passes the returned HWND here and this module
//! subclasses only that window. The subclass always chains the displaced
//! procedure first, then updates `ClipCursor` from the renderer child's client
//! rectangle (or the top-level client as a startup fallback). This ordering
//! lets the game's procedure finish focus, minimization, DPI, and placement
//! state changes before Psycho observes their result. Native fullscreen aliases
//! the two HWND roles; framed and borderless windowed modes use a child. The
//! same selection therefore covers every mode without consulting a mode flag.
//!
//! `ClipCursor` is a desktop-wide shared resource rather than HWND state. The
//! module therefore releases its rectangle on every audited deactivation path
//! and before recalculating after a display-topology change. Release is
//! ownership-aware: if the live rectangle no longer equals Psycho's last
//! successful rectangle, a later owner is left untouched. The normal window
//! procedure path has no cursor warping, allocation, lock, or routine logging;
//! exceptional failures use throttled support logs. No polling thread exists.
//!
//! # System-key delivery
//!
//! FalloutNV.exe configures its DirectInput keyboard with `DISCL_NOWINKEY` in
//! both native branches, and one branch additionally requests exclusive
//! access. The patch changes both cooperative-level immediates to
//! `DISCL_NONEXCLUSIVE | DISCL_FOREGROUND` (`0x06`). The surrounding function
//! fingerprint and both original/replacement states are preflighted before a
//! rollback-capable transaction writes either site. This preserves DirectInput
//! delivery to the game while allowing Windows/Super, PrintScreen, and media
//! commands to continue through the operating system.
//!
//! The executable contract is FalloutNV.exe 1.4.0.525 (PE32 x86). Static
//! evidence and compatibility boundaries are documented in
//! `docs/window_input_policy.md`.

use std::{
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicUsize, Ordering},
};

use anyhow::Context;
use libpsycho::os::windows::{
    hook::transaction::ModificationTransaction,
    patch::OwnedCodePatch,
    winapi::{
        Rect, call_window_proc_a, client_rect_in_screen, clip_cursor, cursor_clip_rect,
        get_foreground_window, get_last_error_code, is_iconic, is_window, load_pointer,
        reset_last_error, set_window_long_a,
    },
};

use super::patching;

const RENDERER_CHILD_HWND_GLOBAL: usize = 0x011C6FBC;
const GWL_WNDPROC: i32 = -4;

const WM_MOVE: u32 = 0x0003;
const WM_SIZE: u32 = 0x0005;
const WM_ACTIVATE: u32 = 0x0006;
const WM_SETFOCUS: u32 = 0x0007;
const WM_KILLFOCUS: u32 = 0x0008;
const WM_ACTIVATEAPP: u32 = 0x001C;
const WM_WINDOWPOSCHANGED: u32 = 0x0047;
const WM_DISPLAYCHANGE: u32 = 0x007E;
const WM_NCDESTROY: u32 = 0x0082;
const WM_DPICHANGED: u32 = 0x02E0;
const SIZE_MINIMIZED: usize = 1;
const WA_INACTIVE: usize = 0;

const COOPERATIVE_LEVEL_SHARED_FOREGROUND: u8 = 0x06;
const KEYBOARD_SHARED_SITE: usize = 0x00A22782;
const KEYBOARD_EXCLUSIVE_SITE: usize = 0x00A227A1;

static KEYBOARD_SHARED_PATCH: OwnedCodePatch = OwnedCodePatch::new(
    "DirectInput keyboard shared cooperative level",
    KEYBOARD_SHARED_SITE,
    &[0x6A, 0x16],
    &[0x6A, COOPERATIVE_LEVEL_SHARED_FOREGROUND],
);
static KEYBOARD_EXCLUSIVE_PATCH: OwnedCodePatch = OwnedCodePatch::new(
    "DirectInput keyboard exclusive cooperative level",
    KEYBOARD_EXCLUSIVE_SITE,
    &[0x6A, 0x15],
    &[0x6A, COOPERATIVE_LEVEL_SHARED_FOREGROUND],
);

// These three fixed spans cover the branch selector, both GetActiveWindow IAT
// calls, both DirectInput device loads, and both vtable +0x34 dispatches. The
// only omitted bytes are the two cooperative-level immediates owned above.
const KEYBOARD_PREFIX_ADDRESS: usize = 0x00A2277A;
const KEYBOARD_PREFIX: &[u8] = &[0x0F, 0xB6, 0x4D, 0xA0, 0x85, 0xC9, 0x74, 0x1F, 0x6A];
const KEYBOARD_MIDDLE_ADDRESS: usize = 0x00A22784;
const KEYBOARD_MIDDLE: &[u8] = &[
    0xFF, 0x15, 0xFC, 0xF2, 0xFD, 0x00, 0x50, 0x8B, 0x55, 0xA8, 0x8B, 0x42, 0x2C, 0x8B, 0x4D, 0xA8,
    0x8B, 0x51, 0x2C, 0x8B, 0x00, 0x52, 0x8B, 0x48, 0x34, 0xFF, 0xD1, 0xEB, 0x1D, 0x6A,
];
const KEYBOARD_SUFFIX_ADDRESS: usize = 0x00A227A3;
const KEYBOARD_SUFFIX: &[u8] = &[
    0xFF, 0x15, 0xFC, 0xF2, 0xFD, 0x00, 0x50, 0x8B, 0x55, 0xA8, 0x8B, 0x42, 0x2C, 0x8B, 0x4D, 0xA8,
    0x8B, 0x51, 0x2C, 0x8B, 0x00, 0x52, 0x8B, 0x48, 0x34, 0xFF, 0xD1, 0x68, 0xB4, 0x0C, 0x10, 0x01,
];

static CURSOR_LOCK_CONFIGURED: AtomicBool = AtomicBool::new(false);
static SYSTEM_KEY_PASSTHROUGH_CONFIGURED: AtomicBool = AtomicBool::new(false);
static SYSTEM_KEY_PASSTHROUGH_INSTALLED: AtomicBool = AtomicBool::new(false);
static ATTACHED_HWND: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_WNDPROC: AtomicUsize = AtomicUsize::new(0);
static CLIP_ACTIVE: AtomicBool = AtomicBool::new(false);
static LAST_CLIP_LEFT: AtomicI32 = AtomicI32::new(0);
static LAST_CLIP_TOP: AtomicI32 = AtomicI32::new(0);
static LAST_CLIP_RIGHT: AtomicI32 = AtomicI32::new(0);
static LAST_CLIP_BOTTOM: AtomicI32 = AtomicI32::new(0);
static CURSOR_ATTACHMENTS: AtomicU32 = AtomicU32::new(0);
static CURSOR_APPLIES: AtomicU32 = AtomicU32::new(0);
static CURSOR_RELEASES: AtomicU32 = AtomicU32::new(0);
static CURSOR_FAILURES: AtomicU32 = AtomicU32::new(0);
static CURSOR_OWNERSHIP_LOSSES: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CursorMessageAction {
    None,
    Refresh,
    Release,
    ReleaseThenRefresh,
}

/// Point-in-time ownership and activity for support diagnostics.
///
/// The snapshot uses only atomic reads and never calls Win32 or takes a lock.
#[derive(Clone, Copy)]
pub(crate) struct DiagnosticSnapshot {
    /// Whether cursor confinement was requested at startup.
    pub cursor_lock_configured: bool,
    /// Whether Psycho subclassed the audited top-level game window.
    pub cursor_window_attached: bool,
    /// Whether Psycho currently owns an applied clipping rectangle.
    pub cursor_clip_active: bool,
    /// Successful top-level window subclass installations.
    pub cursor_attachments: u32,
    /// Successful cursor rectangle applications.
    pub cursor_applies: u32,
    /// Successful cursor rectangle releases.
    pub cursor_releases: u32,
    /// Failed subclass, rectangle lookup, or clipping operations.
    pub cursor_failures: u32,
    /// Releases skipped because a later component replaced the clip rectangle.
    pub cursor_ownership_losses: u32,
    /// Whether system-key passthrough was requested at startup.
    pub system_key_passthrough_configured: bool,
    /// Whether both DirectInput cooperative-level sites passed and installed.
    pub system_key_passthrough_installed: bool,
}

/// Configure cursor confinement before the audited window-creation shim runs.
pub(crate) fn configure_cursor_lock(enabled: bool) {
    CURSOR_LOCK_CONFIGURED.store(enabled, Ordering::Release);
    if enabled {
        log::info!("[WINDOW_INPUT] Cursor confinement enabled");
    } else {
        log::info!("[WINDOW_INPUT] Cursor confinement disabled by config");
    }
}

/// Install the configured DirectInput system-key passthrough patch.
///
/// Both native setup branches are verified before either write. An error
/// leaves both sites original (or rolls back the first write if the second
/// write unexpectedly fails).
pub(crate) fn install_system_key_passthrough(enabled: bool) -> anyhow::Result<()> {
    SYSTEM_KEY_PASSTHROUGH_CONFIGURED.store(enabled, Ordering::Release);
    if !enabled {
        log::info!("[WINDOW_INPUT] System-key passthrough disabled by config");
        return Ok(());
    }

    preflight_keyboard_setup()?;
    let mut transaction = ModificationTransaction::new();
    transaction
        .apply_patch(&KEYBOARD_SHARED_PATCH)
        .context("patch shared DirectInput keyboard branch")?;
    transaction
        .apply_patch(&KEYBOARD_EXCLUSIVE_PATCH)
        .context("patch exclusive DirectInput keyboard branch")?;
    transaction.commit();

    SYSTEM_KEY_PASSTHROUGH_INSTALLED.store(true, Ordering::Release);
    log::info!(
        "[WINDOW_INPUT] System-key passthrough installed: cooperative_level=0x{:02X}",
        COOPERATIVE_LEVEL_SHARED_FOREGROUND,
    );
    Ok(())
}

/// Subclass the audited top-level game window returned by `CreateWindowExA`.
///
/// This function is deliberately idempotent because the display shim may see
/// renderer recreation. A second distinct live window is not touched: one
/// global predecessor cannot safely represent two simultaneous subclasses.
pub(crate) fn attach_top_level_window(hwnd: *mut c_void) {
    if !CURSOR_LOCK_CONFIGURED.load(Ordering::Acquire) || !is_window(hwnd) {
        return;
    }

    let hwnd_address = hwnd as usize;
    let attached = ATTACHED_HWND.load(Ordering::Acquire);
    if attached == hwnd_address {
        refresh_cursor_clip(hwnd);
        return;
    }
    if attached != 0 {
        let count = CURSOR_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
        if should_log(count) {
            log::warn!(
                "[WINDOW_INPUT] cursor subclass refused a second live HWND: attached=0x{attached:08X} requested=0x{hwnd_address:08X}"
            );
        }
        return;
    }

    // SetWindowLongA uses zero for both failure and a legitimate NULL previous
    // value. Clearing LastError first is the only documented way to distinguish
    // them, even though Fallout's registered WndProc is expected to be non-NULL.
    reset_last_error();
    let previous = set_window_long_a(
        hwnd,
        GWL_WNDPROC,
        cursor_window_proc as *const () as usize as u32 as i32,
    );
    let error = get_last_error_code();
    if previous == 0 && error != 0 {
        let count = CURSOR_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
        if should_log(count) {
            log::warn!(
                "[WINDOW_INPUT] top-level cursor subclass failed: HWND=0x{hwnd_address:08X} error={error}"
            );
        }
        return;
    }

    ORIGINAL_WNDPROC.store((previous as u32) as usize, Ordering::Release);
    ATTACHED_HWND.store(hwnd_address, Ordering::Release);
    CURSOR_ATTACHMENTS.fetch_add(1, Ordering::Relaxed);
    log::info!(
        "[WINDOW_INPUT] Cursor confinement attached: HWND=0x{hwnd_address:08X} predecessor=0x{:08X}",
        previous as u32,
    );
    refresh_cursor_clip(hwnd);
}

/// Capture cursor and system-key state without mutating runtime ownership.
pub(crate) fn diagnostic_snapshot() -> DiagnosticSnapshot {
    DiagnosticSnapshot {
        cursor_lock_configured: CURSOR_LOCK_CONFIGURED.load(Ordering::Acquire),
        cursor_window_attached: ATTACHED_HWND.load(Ordering::Acquire) != 0,
        cursor_clip_active: CLIP_ACTIVE.load(Ordering::Acquire),
        cursor_attachments: CURSOR_ATTACHMENTS.load(Ordering::Relaxed),
        cursor_applies: CURSOR_APPLIES.load(Ordering::Relaxed),
        cursor_releases: CURSOR_RELEASES.load(Ordering::Relaxed),
        cursor_failures: CURSOR_FAILURES.load(Ordering::Relaxed),
        cursor_ownership_losses: CURSOR_OWNERSHIP_LOSSES.load(Ordering::Relaxed),
        system_key_passthrough_configured: SYSTEM_KEY_PASSTHROUGH_CONFIGURED
            .load(Ordering::Acquire),
        system_key_passthrough_installed: SYSTEM_KEY_PASSTHROUGH_INSTALLED.load(Ordering::Acquire),
    }
}

unsafe extern "system" fn cursor_window_proc(
    hwnd: *mut c_void,
    message: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    let predecessor = ORIGINAL_WNDPROC.load(Ordering::Acquire);
    let result = if predecessor == 0 {
        0
    } else {
        // The predecessor was captured from SetWindowLongA for this exact HWND
        // and stays published until WM_NCDESTROY finishes chaining.
        unsafe { call_window_proc_a(predecessor as *mut c_void, hwnd, message, wparam, lparam) }
    };

    match cursor_message_action(message, wparam) {
        CursorMessageAction::None => {}
        CursorMessageAction::Refresh => refresh_cursor_clip(hwnd),
        CursorMessageAction::Release => release_cursor_clip(),
        CursorMessageAction::ReleaseThenRefresh => {
            // ClipCursor's unrestricted rectangle follows virtual-desktop
            // topology. Releasing first prevents a stale pre-change rectangle
            // from surviving a monitor add/remove before the new client clip.
            release_cursor_clip();
            refresh_cursor_clip(hwnd);
        }
    }

    if message == WM_NCDESTROY {
        ATTACHED_HWND.store(0, Ordering::Release);
        ORIGINAL_WNDPROC.store(0, Ordering::Release);
    }
    result
}

fn cursor_message_action(message: u32, wparam: usize) -> CursorMessageAction {
    match message {
        WM_KILLFOCUS | WM_NCDESTROY => CursorMessageAction::Release,
        WM_ACTIVATEAPP if wparam == 0 => CursorMessageAction::Release,
        WM_ACTIVATEAPP => CursorMessageAction::Refresh,
        WM_ACTIVATE if wparam & 0xFFFF == WA_INACTIVE || wparam >> 16 != 0 => {
            CursorMessageAction::Release
        }
        WM_ACTIVATE | WM_SETFOCUS => CursorMessageAction::Refresh,
        WM_SIZE if wparam == SIZE_MINIMIZED => CursorMessageAction::Release,
        WM_SIZE | WM_MOVE | WM_WINDOWPOSCHANGED | WM_DPICHANGED => CursorMessageAction::Refresh,
        WM_DISPLAYCHANGE => CursorMessageAction::ReleaseThenRefresh,
        _ => CursorMessageAction::None,
    }
}

fn refresh_cursor_clip(top_level: *mut c_void) {
    if !CURSOR_LOCK_CONFIGURED.load(Ordering::Acquire)
        || ATTACHED_HWND.load(Ordering::Acquire) != top_level as usize
        || get_foreground_window() != top_level
        || is_iconic(top_level)
    {
        release_cursor_clip();
        return;
    }

    let target = renderer_window()
        .filter(|&hwnd| is_window(hwnd))
        .unwrap_or(top_level);
    let Some(rect) = client_rect_in_screen(target).filter(valid_clip_rect) else {
        record_cursor_failure("could not resolve a non-empty client rectangle");
        release_cursor_clip();
        return;
    };
    if CLIP_ACTIVE.load(Ordering::Acquire) && last_clip_rect() == rect {
        return;
    }

    if !clip_cursor(Some(&rect)) {
        record_cursor_failure("ClipCursor failed while applying the game client rectangle");
        return;
    }
    store_last_clip_rect(rect);
    CLIP_ACTIVE.store(true, Ordering::Release);
    CURSOR_APPLIES.fetch_add(1, Ordering::Relaxed);
}

fn release_cursor_clip() {
    if !CLIP_ACTIVE.load(Ordering::Acquire) {
        return;
    }

    let owned = last_clip_rect();
    if let Some(current) = cursor_clip_rect()
        && current != owned
    {
        // Another component replaced the process-independent desktop clip
        // after Psycho. Clearing it here would break that newer owner's focus
        // policy, so relinquish our bookkeeping without touching Win32 state.
        CLIP_ACTIVE.store(false, Ordering::Release);
        CURSOR_OWNERSHIP_LOSSES.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // A failed GetClipCursor query does not prove ownership loss. Releasing is
    // safer than leaving the user trapped when the game is no longer active.
    if clip_cursor(None) {
        CLIP_ACTIVE.store(false, Ordering::Release);
        CURSOR_RELEASES.fetch_add(1, Ordering::Relaxed);
    } else {
        record_cursor_failure("ClipCursor failed while releasing confinement");
    }
}

fn renderer_window() -> Option<*mut c_void> {
    load_pointer(RENDERER_CHILD_HWND_GLOBAL as *mut *mut c_void)
        .ok()
        .filter(|hwnd| !hwnd.is_null())
}

fn valid_clip_rect(rect: &Rect) -> bool {
    rect.right > rect.left && rect.bottom > rect.top
}

fn last_clip_rect() -> Rect {
    Rect {
        left: LAST_CLIP_LEFT.load(Ordering::Acquire),
        top: LAST_CLIP_TOP.load(Ordering::Acquire),
        right: LAST_CLIP_RIGHT.load(Ordering::Acquire),
        bottom: LAST_CLIP_BOTTOM.load(Ordering::Acquire),
    }
}

fn store_last_clip_rect(rect: Rect) {
    LAST_CLIP_LEFT.store(rect.left, Ordering::Release);
    LAST_CLIP_TOP.store(rect.top, Ordering::Release);
    LAST_CLIP_RIGHT.store(rect.right, Ordering::Release);
    LAST_CLIP_BOTTOM.store(rect.bottom, Ordering::Release);
}

fn preflight_keyboard_setup() -> anyhow::Result<()> {
    // Exact surrounding fingerprints prevent the two-byte immediates from
    // being interpreted outside the proven SetCooperativeLevel control flow.
    unsafe { patching::verify_bytes(KEYBOARD_PREFIX_ADDRESS, KEYBOARD_PREFIX) }
        .context("verify DirectInput keyboard branch prefix")?;
    unsafe { patching::verify_bytes(KEYBOARD_MIDDLE_ADDRESS, KEYBOARD_MIDDLE) }
        .context("verify DirectInput keyboard branch middle")?;
    unsafe { patching::verify_bytes(KEYBOARD_SUFFIX_ADDRESS, KEYBOARD_SUFFIX) }
        .context("verify DirectInput keyboard branch suffix")?;
    KEYBOARD_SHARED_PATCH
        .verify()
        .context("verify shared DirectInput cooperative level")?;
    KEYBOARD_EXCLUSIVE_PATCH
        .verify()
        .context("verify exclusive DirectInput cooperative level")?;
    Ok(())
}

fn record_cursor_failure(reason: &str) {
    let count = CURSOR_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
    if should_log(count) {
        log::warn!("[WINDOW_INPUT] cursor confinement failure #{count}: {reason}");
    }
}

fn should_log(count: u32) -> bool {
    count <= 3 || count.is_power_of_two()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn focus_and_minimize_messages_release_before_the_desktop_changes_owner() {
        assert_eq!(
            cursor_message_action(WM_ACTIVATE, WA_INACTIVE),
            CursorMessageAction::Release
        );
        assert_eq!(
            cursor_message_action(WM_ACTIVATE, 1 << 16),
            CursorMessageAction::Release
        );
        assert_eq!(
            cursor_message_action(WM_ACTIVATEAPP, 0),
            CursorMessageAction::Release
        );
        assert_eq!(
            cursor_message_action(WM_SIZE, SIZE_MINIMIZED),
            CursorMessageAction::Release
        );
        assert_eq!(
            cursor_message_action(WM_NCDESTROY, 0),
            CursorMessageAction::Release
        );
    }

    #[test]
    fn active_geometry_messages_refresh_and_display_changes_reset() {
        assert_eq!(
            cursor_message_action(WM_SETFOCUS, 0),
            CursorMessageAction::Refresh
        );
        assert_eq!(
            cursor_message_action(WM_WINDOWPOSCHANGED, 0),
            CursorMessageAction::Refresh
        );
        assert_eq!(
            cursor_message_action(WM_DISPLAYCHANGE, 0),
            CursorMessageAction::ReleaseThenRefresh
        );
    }

    #[test]
    fn clip_rect_validation_accepts_negative_monitor_coordinates() {
        assert!(valid_clip_rect(&Rect {
            left: -1920,
            top: 0,
            right: 0,
            bottom: 1080,
        }));
        assert!(!valid_clip_rect(&Rect {
            left: 100,
            top: 50,
            right: 100,
            bottom: 700,
        }));
    }

    #[test]
    fn keyboard_fingerprint_omits_only_the_two_owned_immediates() {
        assert_eq!(
            KEYBOARD_PREFIX_ADDRESS + KEYBOARD_PREFIX.len(),
            KEYBOARD_SHARED_SITE + 1,
        );
        assert_eq!(KEYBOARD_MIDDLE_ADDRESS, KEYBOARD_SHARED_SITE + 2);
        assert_eq!(
            KEYBOARD_MIDDLE_ADDRESS + KEYBOARD_MIDDLE.len(),
            KEYBOARD_EXCLUSIVE_SITE + 1,
        );
        assert_eq!(KEYBOARD_SUFFIX_ADDRESS, KEYBOARD_EXCLUSIVE_SITE + 2);
        assert_eq!(
            COOPERATIVE_LEVEL_SHARED_FOREGROUND,
            0x02 | 0x04,
            "NONEXCLUSIVE | FOREGROUND",
        );
    }
}
