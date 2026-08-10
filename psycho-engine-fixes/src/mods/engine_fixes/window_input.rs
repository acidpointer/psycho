//! Owns durable cursor confinement and system-key delivery.
//!
//! # Cursor ownership
//!
//! FalloutNV.exe creates its visible top-level window at the audited
//! `CreateWindowExA` caller in [`super::display`]. When cursor confinement is
//! enabled, that boundary passes the returned HWND here and this module
//! subclasses only that window. The subclass always chains the displaced
//! procedure first, then reconciles the shared desktop `ClipCursor` state. This
//! ordering lets the game's procedure finish focus, minimization, DPI, and
//! placement changes before Psycho observes their result. Native fullscreen
//! uses the top-level client, borderless windowed uses the renderer child, and
//! framed windowed uses the top-level outer rectangle so the caption and resize
//! border remain reachable. Renderer HWNDs are accepted only when they alias or
//! descend from the audited top-level HWND.
//!
//! `ClipCursor` is a desktop-wide shared resource rather than HWND state. The
//! module therefore releases unconditionally after every audited deactivation
//! path. A message-queue timer on the window thread verifies active confinement
//! without a worker thread; it repairs an overlay that releases or widens the
//! clip even when a later WndProc owner consumes the corresponding message. The
//! reconciler records both the requested rectangle and Win32's effective
//! rectangle because Wine and Windows may intersect an off-screen request with
//! the virtual desktop. A failed replacement releases an older Psycho clip as
//! a fail-safe instead of leaving a stale trap behind.
//!
//! The callback path has no cursor warping, allocation, lock, file I/O, or
//! routine logging. It performs bounded Win32 queries and normally avoids a
//! `ClipCursor` write when the requested and effective rectangles are stable.
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
        def_window_proc_a, get_foreground_window, get_last_error_code, get_window_long_a, is_child,
        is_iconic, is_window, kill_thread_timer, load_pointer, reset_last_error, set_thread_timer,
        set_window_long_a, window_rect,
    },
};

use super::patching;

const RENDERER_CHILD_HWND_GLOBAL: usize = 0x011C6FBC;
const TOP_LEVEL_HWND_GLOBAL: usize = 0x011C6FC0;
const GWL_WNDPROC: i32 = -4;
const GWL_STYLE: i32 = -16;

const WM_MOVE: u32 = 0x0003;
const WM_SIZE: u32 = 0x0005;
const WM_ACTIVATE: u32 = 0x0006;
const WM_SETFOCUS: u32 = 0x0007;
const WM_KILLFOCUS: u32 = 0x0008;
const WM_ACTIVATEAPP: u32 = 0x001C;
const WM_CANCELMODE: u32 = 0x001F;
const WM_WINDOWPOSCHANGED: u32 = 0x0047;
const WM_DISPLAYCHANGE: u32 = 0x007E;
const WM_NCDESTROY: u32 = 0x0082;
const WM_DPICHANGED: u32 = 0x02E0;
const WM_ENTERSIZEMOVE: u32 = 0x0231;
const WM_EXITSIZEMOVE: u32 = 0x0232;
const SIZE_MINIMIZED: usize = 1;
const WA_INACTIVE: usize = 0;
const WS_CAPTION: u32 = 0x00C0_0000;
const WS_THICKFRAME: u32 = 0x0004_0000;

// A 16 ms queue timer catches a one-shot overlay unclip before the cursor can
// travel far at common refresh rates. SetTimer may coalesce this interval under
// Wine or a busy message pump; correctness does not depend on exact cadence.
const CURSOR_AUDIT_INTERVAL_MS: u32 = 16;

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
static SIZE_MOVE_ACTIVE: AtomicBool = AtomicBool::new(false);
static CURSOR_TIMER_ID: AtomicUsize = AtomicUsize::new(0);
static LAST_REQUESTED_LEFT: AtomicI32 = AtomicI32::new(0);
static LAST_REQUESTED_TOP: AtomicI32 = AtomicI32::new(0);
static LAST_REQUESTED_RIGHT: AtomicI32 = AtomicI32::new(0);
static LAST_REQUESTED_BOTTOM: AtomicI32 = AtomicI32::new(0);
static LAST_EFFECTIVE_LEFT: AtomicI32 = AtomicI32::new(0);
static LAST_EFFECTIVE_TOP: AtomicI32 = AtomicI32::new(0);
static LAST_EFFECTIVE_RIGHT: AtomicI32 = AtomicI32::new(0);
static LAST_EFFECTIVE_BOTTOM: AtomicI32 = AtomicI32::new(0);
static LAST_REJECTED_RENDERER: AtomicUsize = AtomicUsize::new(0);
static CURSOR_TARGET_KIND: AtomicU32 = AtomicU32::new(0);
static CURSOR_ATTACHMENTS: AtomicU32 = AtomicU32::new(0);
static CURSOR_RECOVERY_ATTACHMENTS: AtomicU32 = AtomicU32::new(0);
static CURSOR_APPLIES: AtomicU32 = AtomicU32::new(0);
static CURSOR_RELEASES: AtomicU32 = AtomicU32::new(0);
static CURSOR_FAILURES: AtomicU32 = AtomicU32::new(0);
static CURSOR_TIMER_AUDITS: AtomicU32 = AtomicU32::new(0);
static CURSOR_REPAIRS: AtomicU32 = AtomicU32::new(0);
static CURSOR_NORMALIZATIONS: AtomicU32 = AtomicU32::new(0);
static CURSOR_SAFE_ADOPTIONS: AtomicU32 = AtomicU32::new(0);
static CURSOR_FAIL_SAFE_RELEASES: AtomicU32 = AtomicU32::new(0);
static CURSOR_RENDERER_REJECTIONS: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CursorMessageAction {
    None,
    Refresh,
    Release,
    ReleaseThenRefresh,
    SuspendForMove,
    ResumeFromMove,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttachmentSource {
    AuditedCreate,
    LaterCreateOwner,
    DeferredGlobal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RendererRelation {
    Missing,
    Aliased,
    Child,
    Unrelated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
enum ClipTargetKind {
    Unknown = 0,
    TopLevelClient = 1,
    RendererClient = 2,
    FramedOuter = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClipReconcileAction {
    Keep,
    AdoptSafe,
    Apply,
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
    /// Active rectangle role selected from the validated HWND relationship.
    pub cursor_target: &'static str,
    /// Whether the window thread's reconciliation timer is installed.
    pub cursor_timer_installed: bool,
    /// Successful top-level window subclass installations.
    pub cursor_attachments: u32,
    /// Attachments recovered after another IAT owner changed the call boundary.
    pub cursor_recovery_attachments: u32,
    /// Successful cursor rectangle applications.
    pub cursor_applies: u32,
    /// Successful cursor rectangle releases.
    pub cursor_releases: u32,
    /// Failed subclass, rectangle lookup, or clipping operations.
    pub cursor_failures: u32,
    /// Timer callbacks that audited the current desktop clip.
    pub cursor_timer_audits: u32,
    /// Unsafe external clip changes that were repaired.
    pub cursor_repairs: u32,
    /// Successful clips whose effective rectangle differed from the request.
    pub cursor_normalizations: u32,
    /// Stricter external clips retained while the game remained active.
    pub cursor_safe_adoptions: u32,
    /// Stale clips released after a replacement failed.
    pub cursor_fail_safe_releases: u32,
    /// Live renderer HWNDs rejected because they were not game descendants.
    pub cursor_renderer_rejections: u32,
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
    attach_top_level_window_from(hwnd, AttachmentSource::AuditedCreate);
}

/// Attach when a later `CreateWindowExA` IAT owner chains Psycho from a new
/// return address while preserving the exact audited bootstrap request.
pub(crate) fn attach_top_level_window_from_later_owner(hwnd: *mut c_void) {
    attach_top_level_window_from(hwnd, AttachmentSource::LaterCreateOwner);
}

/// Retry attachment from the proven engine HWND global at late engine init.
///
/// This recovers compatibility when a later IAT owner changes the bootstrap
/// request before chaining, which prevents request-level identification. The
/// engine has published the stable top-level HWND before this event.
pub(super) fn observe_event(kind: u32) {
    if kind != crate::events::DEFERRED_INIT
        || !CURSOR_LOCK_CONFIGURED.load(Ordering::Acquire)
        || ATTACHED_HWND.load(Ordering::Acquire) != 0
    {
        return;
    }

    let Some(hwnd) = load_pointer(TOP_LEVEL_HWND_GLOBAL as *mut *mut c_void)
        .ok()
        .filter(|hwnd| is_window(*hwnd))
    else {
        return;
    };
    attach_top_level_window_from(hwnd, AttachmentSource::DeferredGlobal);
}

fn attach_top_level_window_from(hwnd: *mut c_void, source: AttachmentSource) {
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
        if is_window(attached as *mut c_void) {
            let count = CURSOR_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
            if should_log(count) {
                log::warn!(
                    "[WINDOW_INPUT] cursor subclass refused a second live HWND: attached=0x{attached:08X} requested=0x{hwnd_address:08X}"
                );
            }
            return;
        }

        // A later outer WndProc can accidentally consume WM_NCDESTROY. A dead
        // HWND proves that predecessor can no longer receive messages, so its
        // process-global state may be retired before a recreated window binds.
        ATTACHED_HWND.store(0, Ordering::Release);
        ORIGINAL_WNDPROC.store(0, Ordering::Release);
        release_cursor_clip();
    }

    let provisional_predecessor = get_window_long_a(hwnd, GWL_WNDPROC);
    if provisional_predecessor == 0 {
        record_cursor_failure("could not read a non-NULL top-level WndProc");
        return;
    }

    // Publish a valid predecessor before installing the detour. Although this
    // sequence runs on the owning window thread, SetWindowLongA can synchronously
    // expose the new procedure to a sender on another thread. Prepublication
    // prevents that first message from being swallowed by an empty chain.
    ORIGINAL_WNDPROC.store((provisional_predecessor as u32) as usize, Ordering::Release);
    ATTACHED_HWND.store(hwnd_address, Ordering::Release);
    reset_last_error();
    let previous = set_window_long_a(
        hwnd,
        GWL_WNDPROC,
        cursor_window_proc as *const () as usize as u32 as i32,
    );
    let error = get_last_error_code();
    if previous == 0 && error != 0 {
        ATTACHED_HWND.store(0, Ordering::Release);
        ORIGINAL_WNDPROC.store(0, Ordering::Release);
        let count = CURSOR_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
        if should_log(count) {
            log::warn!(
                "[WINDOW_INPUT] top-level cursor subclass failed: HWND=0x{hwnd_address:08X} error={error}"
            );
        }
        return;
    }

    // A zero return with LastError still zero is documented as a successful
    // replacement of a zero-valued window long. A live WndProc cannot actually
    // be NULL, so retain the validated pre-read in this compatibility case.
    if previous != 0 {
        ORIGINAL_WNDPROC.store((previous as u32) as usize, Ordering::Release);
    }
    CURSOR_ATTACHMENTS.fetch_add(1, Ordering::Relaxed);
    if source != AttachmentSource::AuditedCreate {
        CURSOR_RECOVERY_ATTACHMENTS.fetch_add(1, Ordering::Relaxed);
    }
    log::info!(
        "[WINDOW_INPUT] Cursor confinement attached: HWND=0x{hwnd_address:08X} predecessor=0x{:08X} source={}",
        ORIGINAL_WNDPROC.load(Ordering::Acquire),
        attachment_source_name(source),
    );
    install_cursor_timer();
    refresh_cursor_clip(hwnd);
}

/// Capture cursor and system-key state without mutating runtime ownership.
pub(crate) fn diagnostic_snapshot() -> DiagnosticSnapshot {
    DiagnosticSnapshot {
        cursor_lock_configured: CURSOR_LOCK_CONFIGURED.load(Ordering::Acquire),
        cursor_window_attached: ATTACHED_HWND.load(Ordering::Acquire) != 0,
        cursor_clip_active: CLIP_ACTIVE.load(Ordering::Acquire),
        cursor_target: clip_target_name(CURSOR_TARGET_KIND.load(Ordering::Acquire)),
        cursor_timer_installed: CURSOR_TIMER_ID.load(Ordering::Acquire) != 0,
        cursor_attachments: CURSOR_ATTACHMENTS.load(Ordering::Relaxed),
        cursor_recovery_attachments: CURSOR_RECOVERY_ATTACHMENTS.load(Ordering::Relaxed),
        cursor_applies: CURSOR_APPLIES.load(Ordering::Relaxed),
        cursor_releases: CURSOR_RELEASES.load(Ordering::Relaxed),
        cursor_failures: CURSOR_FAILURES.load(Ordering::Relaxed),
        cursor_timer_audits: CURSOR_TIMER_AUDITS.load(Ordering::Relaxed),
        cursor_repairs: CURSOR_REPAIRS.load(Ordering::Relaxed),
        cursor_normalizations: CURSOR_NORMALIZATIONS.load(Ordering::Relaxed),
        cursor_safe_adoptions: CURSOR_SAFE_ADOPTIONS.load(Ordering::Relaxed),
        cursor_fail_safe_releases: CURSOR_FAIL_SAFE_RELEASES.load(Ordering::Relaxed),
        cursor_renderer_rejections: CURSOR_RENDERER_REJECTIONS.load(Ordering::Relaxed),
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
        // Attachment publishes a validated predecessor before installing this
        // procedure, so this path is defensive protection against corrupted
        // state rather than an expected chain state.
        def_window_proc_a(hwnd, message, wparam, lparam)
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
        CursorMessageAction::SuspendForMove => {
            // A framed system move/resize needs the caption and borders plus
            // temporary freedom to cross monitor edges. Win32 owns mouse
            // capture during this modal loop, so releasing here cannot click a
            // background window; confinement resumes when the loop exits.
            SIZE_MOVE_ACTIVE.store(true, Ordering::Release);
            release_cursor_clip();
        }
        CursorMessageAction::ResumeFromMove => {
            SIZE_MOVE_ACTIVE.store(false, Ordering::Release);
            refresh_cursor_clip(hwnd);
        }
    }

    if message == WM_NCDESTROY {
        if !CLIP_ACTIVE.load(Ordering::Acquire) {
            stop_cursor_timer();
        }
        SIZE_MOVE_ACTIVE.store(false, Ordering::Release);
        ATTACHED_HWND.store(0, Ordering::Release);
        ORIGINAL_WNDPROC.store(0, Ordering::Release);
        CURSOR_TARGET_KIND.store(ClipTargetKind::Unknown as u32, Ordering::Release);
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
        WM_ENTERSIZEMOVE => CursorMessageAction::SuspendForMove,
        WM_EXITSIZEMOVE | WM_CANCELMODE => CursorMessageAction::ResumeFromMove,
        _ => CursorMessageAction::None,
    }
}

fn refresh_cursor_clip(top_level: *mut c_void) {
    if !CURSOR_LOCK_CONFIGURED.load(Ordering::Acquire)
        || ATTACHED_HWND.load(Ordering::Acquire) != top_level as usize
        || get_foreground_window() != top_level
        || is_iconic(top_level)
        || SIZE_MOVE_ACTIVE.load(Ordering::Acquire)
    {
        release_cursor_clip();
        return;
    }

    let Some((requested, target_kind)) = resolve_clip_target(top_level) else {
        record_cursor_failure("could not resolve a non-empty game window rectangle");
        release_cursor_clip();
        return;
    };
    CURSOR_TARGET_KIND.store(target_kind as u32, Ordering::Release);

    let active = CLIP_ACTIVE.load(Ordering::Acquire);
    let requested_changed = !active || last_requested_rect() != requested;
    let current = cursor_clip_rect();
    match clip_reconcile_action(
        active,
        requested_changed,
        current,
        last_effective_rect(),
        requested,
        target_kind != ClipTargetKind::FramedOuter,
    ) {
        ClipReconcileAction::Keep => return,
        ClipReconcileAction::AdoptSafe => {
            // A later in-process owner may deliberately constrain an ImGui
            // interaction to a smaller region. It is safe while wholly inside
            // the game boundary, so remember its effective rectangle without
            // widening it. Deactivation still releases unconditionally to
            // guarantee the desktop can never remain trapped.
            if let Some(safe) = current {
                store_requested_rect(requested);
                store_effective_rect(safe);
                CURSOR_SAFE_ADOPTIONS.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        ClipReconcileAction::Apply => {}
    }

    if !requested_changed && active {
        CURSOR_REPAIRS.fetch_add(1, Ordering::Relaxed);
    }
    if !clip_cursor(Some(&requested)) {
        record_cursor_failure("ClipCursor failed while applying the game window rectangle");
        if active {
            // ClipCursor does not promise to clear a previous rectangle when a
            // replacement fails. User safety takes precedence over retaining
            // stale ownership: explicitly release and let the timer retry.
            CURSOR_FAIL_SAFE_RELEASES.fetch_add(1, Ordering::Relaxed);
            release_cursor_clip();
        }
        return;
    }

    // Win32 and Wine may intersect an off-screen request with the current
    // virtual desktop. Cache the post-call value, not just our request, so a
    // stable normalization is not rewritten every timer tick.
    let effective = cursor_clip_rect().unwrap_or(requested);
    if effective != requested {
        CURSOR_NORMALIZATIONS.fetch_add(1, Ordering::Relaxed);
    }
    store_requested_rect(requested);
    store_effective_rect(effective);
    CLIP_ACTIVE.store(true, Ordering::Release);
    CURSOR_APPLIES.fetch_add(1, Ordering::Relaxed);
}

fn release_cursor_clip() {
    if !CLIP_ACTIVE.load(Ordering::Acquire) {
        return;
    }

    // ClipCursor is desktop-global, but every component participating in the
    // foreground game must release before control changes applications. A
    // live rectangle mismatch is therefore not grounds to skip release: doing
    // so can trap the cursor if an overlay forgot its own deactivation path.
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

fn resolve_clip_target(top_level: *mut c_void) -> Option<(Rect, ClipTargetKind)> {
    let renderer = renderer_window();
    let relation = match renderer {
        None => RendererRelation::Missing,
        Some(hwnd) if hwnd == top_level => RendererRelation::Aliased,
        Some(hwnd) if is_window(hwnd) && is_child(top_level, hwnd) => RendererRelation::Child,
        Some(hwnd) => {
            // IsWindow alone is insufficient because a destroyed renderer HWND
            // can be recycled for another monitor's application. Record each
            // rejected value once and fall back only to the audited top-level.
            let address = hwnd as usize;
            if LAST_REJECTED_RENDERER.swap(address, Ordering::AcqRel) != address {
                let count = CURSOR_RENDERER_REJECTIONS.fetch_add(1, Ordering::Relaxed) + 1;
                if should_log(count) {
                    log::warn!(
                        "[WINDOW_INPUT] rejected unrelated renderer HWND #{count}: 0x{address:08X}; using audited top-level window"
                    );
                }
            }
            RendererRelation::Unrelated
        }
    };
    if relation != RendererRelation::Unrelated {
        LAST_REJECTED_RENDERER.store(0, Ordering::Release);
    }

    let framed = style_has_frame(get_window_long_a(top_level, GWL_STYLE) as u32);
    let target_kind = select_clip_target(relation, framed);
    let rect = match target_kind {
        ClipTargetKind::TopLevelClient => client_rect_in_screen(top_level),
        ClipTargetKind::RendererClient => renderer.and_then(client_rect_in_screen),
        ClipTargetKind::FramedOuter => window_rect(top_level),
        ClipTargetKind::Unknown => None,
    }?;
    valid_clip_rect(&rect).then_some((rect, target_kind))
}

/// Select the mode-appropriate boundary without trusting a cached mode flag.
///
/// The HWND relationship is the authoritative renderer topology. Window style
/// decides whether a child renderer sits inside user-accessible non-client
/// controls that must remain inside the clip.
fn select_clip_target(relation: RendererRelation, framed: bool) -> ClipTargetKind {
    match (relation, framed) {
        (RendererRelation::Child, true)
        | (RendererRelation::Missing | RendererRelation::Unrelated, true) => {
            ClipTargetKind::FramedOuter
        }
        (RendererRelation::Child, false) => ClipTargetKind::RendererClient,
        (RendererRelation::Aliased, _)
        | (RendererRelation::Missing | RendererRelation::Unrelated, false) => {
            ClipTargetKind::TopLevelClient
        }
    }
}

fn style_has_frame(style: u32) -> bool {
    style & (WS_CAPTION | WS_THICKFRAME) != 0
}

/// Decide whether the shared desktop clip already satisfies this refresh.
///
/// Exact equality with the cached effective rectangle wins even when Win32
/// normalized it away from the request. A changed requested boundary always
/// forces application, preventing a moved or enlarged window from inheriting a
/// stale smaller clip. Client targets may retain a newer stricter owner, while
/// framed targets require the exact outer boundary to keep window chrome usable.
fn clip_reconcile_action(
    active: bool,
    requested_changed: bool,
    current: Option<Rect>,
    effective: Rect,
    requested: Rect,
    allow_stricter: bool,
) -> ClipReconcileAction {
    if active && !requested_changed && current == Some(effective) {
        return ClipReconcileAction::Keep;
    }
    if active
        && !requested_changed
        && allow_stricter
        && current.is_some_and(|current| rect_is_within(current, requested))
    {
        return ClipReconcileAction::AdoptSafe;
    }
    ClipReconcileAction::Apply
}

fn rect_is_within(inner: Rect, outer: Rect) -> bool {
    valid_clip_rect(&inner)
        && inner.left >= outer.left
        && inner.top >= outer.top
        && inner.right <= outer.right
        && inner.bottom <= outer.bottom
}

fn valid_clip_rect(rect: &Rect) -> bool {
    rect.right > rect.left && rect.bottom > rect.top
}

fn last_requested_rect() -> Rect {
    Rect {
        left: LAST_REQUESTED_LEFT.load(Ordering::Acquire),
        top: LAST_REQUESTED_TOP.load(Ordering::Acquire),
        right: LAST_REQUESTED_RIGHT.load(Ordering::Acquire),
        bottom: LAST_REQUESTED_BOTTOM.load(Ordering::Acquire),
    }
}

fn store_requested_rect(rect: Rect) {
    LAST_REQUESTED_LEFT.store(rect.left, Ordering::Release);
    LAST_REQUESTED_TOP.store(rect.top, Ordering::Release);
    LAST_REQUESTED_RIGHT.store(rect.right, Ordering::Release);
    LAST_REQUESTED_BOTTOM.store(rect.bottom, Ordering::Release);
}

fn last_effective_rect() -> Rect {
    Rect {
        left: LAST_EFFECTIVE_LEFT.load(Ordering::Acquire),
        top: LAST_EFFECTIVE_TOP.load(Ordering::Acquire),
        right: LAST_EFFECTIVE_RIGHT.load(Ordering::Acquire),
        bottom: LAST_EFFECTIVE_BOTTOM.load(Ordering::Acquire),
    }
}

fn store_effective_rect(rect: Rect) {
    LAST_EFFECTIVE_LEFT.store(rect.left, Ordering::Release);
    LAST_EFFECTIVE_TOP.store(rect.top, Ordering::Release);
    LAST_EFFECTIVE_RIGHT.store(rect.right, Ordering::Release);
    LAST_EFFECTIVE_BOTTOM.store(rect.bottom, Ordering::Release);
}

fn install_cursor_timer() {
    if CURSOR_TIMER_ID.load(Ordering::Acquire) != 0 {
        return;
    }
    let Some(id) = set_thread_timer(CURSOR_AUDIT_INTERVAL_MS, cursor_timer_proc) else {
        record_cursor_failure("SetTimer failed for cursor reconciliation");
        return;
    };
    CURSOR_TIMER_ID.store(id, Ordering::Release);
}

fn stop_cursor_timer() {
    let id = CURSOR_TIMER_ID.swap(0, Ordering::AcqRel);
    if id != 0 && !kill_thread_timer(id) {
        // Retain the id when removal fails. The callback is still harmless
        // while unattached and can service a recreated window on this thread.
        CURSOR_TIMER_ID.store(id, Ordering::Release);
        record_cursor_failure("KillTimer failed for cursor reconciliation");
    }
}

unsafe extern "system" fn cursor_timer_proc(
    _hwnd: *mut c_void,
    _message: u32,
    timer_id: usize,
    _timestamp: u32,
) {
    if timer_id != CURSOR_TIMER_ID.load(Ordering::Acquire) {
        return;
    }
    let top_level = ATTACHED_HWND.load(Ordering::Acquire);
    if top_level == 0 {
        // A failed release during WM_NCDESTROY has no HWND left to generate a
        // later message. Keep the queue timer alive until release succeeds,
        // then retire it from the same owning thread.
        release_cursor_clip();
        if !CLIP_ACTIVE.load(Ordering::Acquire) {
            stop_cursor_timer();
        }
        return;
    }
    if !is_window(top_level as *mut c_void) {
        // An outer WndProc may consume WM_NCDESTROY instead of chaining it.
        // IsWindow is the safe lifetime boundary: once false, the captured
        // predecessor cannot receive another legitimate message and the timer
        // must not keep auditing a dead handle indefinitely.
        ATTACHED_HWND.store(0, Ordering::Release);
        ORIGINAL_WNDPROC.store(0, Ordering::Release);
        CURSOR_TARGET_KIND.store(ClipTargetKind::Unknown as u32, Ordering::Release);
        SIZE_MOVE_ACTIVE.store(false, Ordering::Release);
        release_cursor_clip();
        if !CLIP_ACTIVE.load(Ordering::Acquire) {
            stop_cursor_timer();
        }
        return;
    }
    CURSOR_TIMER_AUDITS.fetch_add(1, Ordering::Relaxed);
    refresh_cursor_clip(top_level as *mut c_void);
}

fn attachment_source_name(source: AttachmentSource) -> &'static str {
    match source {
        AttachmentSource::AuditedCreate => "audited-create",
        AttachmentSource::LaterCreateOwner => "later-create-owner",
        AttachmentSource::DeferredGlobal => "deferred-global",
    }
}

fn clip_target_name(raw: u32) -> &'static str {
    match raw {
        value if value == ClipTargetKind::TopLevelClient as u32 => "top-client",
        value if value == ClipTargetKind::RendererClient as u32 => "renderer-client",
        value if value == ClipTargetKind::FramedOuter as u32 => "framed-outer",
        _ => "unknown",
    }
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
        assert_eq!(
            cursor_message_action(WM_ENTERSIZEMOVE, 0),
            CursorMessageAction::SuspendForMove
        );
        assert_eq!(
            cursor_message_action(WM_EXITSIZEMOVE, 0),
            CursorMessageAction::ResumeFromMove
        );
        assert_eq!(
            cursor_message_action(WM_CANCELMODE, 0),
            CursorMessageAction::ResumeFromMove
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
    fn window_mode_and_hwnd_relationship_select_a_usable_boundary() {
        assert_eq!(
            select_clip_target(RendererRelation::Aliased, false),
            ClipTargetKind::TopLevelClient
        );
        assert_eq!(
            select_clip_target(RendererRelation::Child, false),
            ClipTargetKind::RendererClient
        );
        assert_eq!(
            select_clip_target(RendererRelation::Child, true),
            ClipTargetKind::FramedOuter
        );
        assert_eq!(
            select_clip_target(RendererRelation::Unrelated, true),
            ClipTargetKind::FramedOuter
        );
        assert_eq!(
            select_clip_target(RendererRelation::Unrelated, false),
            ClipTargetKind::TopLevelClient
        );
        assert_eq!(
            select_clip_target(RendererRelation::Missing, true),
            ClipTargetKind::FramedOuter
        );
        assert_eq!(
            select_clip_target(RendererRelation::Missing, false),
            ClipTargetKind::TopLevelClient
        );
        assert!(style_has_frame(WS_CAPTION));
        assert!(style_has_frame(WS_THICKFRAME));
        assert!(!style_has_frame(0x8000_0000));
    }

    #[test]
    fn reconciliation_repairs_escape_but_preserves_stricter_active_clips() {
        let requested = Rect {
            left: -1920,
            top: 0,
            right: 0,
            bottom: 1080,
        };
        let effective = requested;
        let stricter = Rect {
            left: -1600,
            top: 100,
            right: -200,
            bottom: 900,
        };
        let escaped = Rect {
            left: -1920,
            top: 0,
            right: 1920,
            bottom: 1080,
        };
        let normalized = Rect {
            left: -1800,
            top: 0,
            right: 0,
            bottom: 1080,
        };

        assert_eq!(
            clip_reconcile_action(true, false, Some(effective), effective, requested, true),
            ClipReconcileAction::Keep
        );
        assert_eq!(
            clip_reconcile_action(true, false, Some(stricter), effective, requested, true),
            ClipReconcileAction::AdoptSafe
        );
        assert_eq!(
            clip_reconcile_action(true, false, Some(normalized), normalized, requested, true),
            ClipReconcileAction::Keep,
            "a stable effective Win32/Wine normalization must not thrash"
        );
        assert_eq!(
            clip_reconcile_action(true, false, Some(escaped), effective, requested, true),
            ClipReconcileAction::Apply
        );
        assert_eq!(
            clip_reconcile_action(true, true, Some(stricter), effective, requested, true),
            ClipReconcileAction::Apply,
            "geometry changes must not preserve a stale smaller rectangle"
        );
        assert_eq!(
            clip_reconcile_action(false, true, Some(stricter), effective, requested, true),
            ClipReconcileAction::Apply,
            "initial activation must establish Psycho's release responsibility"
        );
        assert_eq!(
            clip_reconcile_action(true, false, None, effective, requested, true),
            ClipReconcileAction::Apply,
            "an unreadable shared clip cannot prove confinement"
        );
        assert_eq!(
            clip_reconcile_action(true, false, Some(stricter), effective, requested, false),
            ClipReconcileAction::Apply,
            "framed mode must restore access to caption and resize borders"
        );
    }

    #[test]
    fn containment_rejects_empty_and_outside_rectangles() {
        let outer = Rect {
            left: 100,
            top: -900,
            right: 1700,
            bottom: 0,
        };

        assert!(rect_is_within(
            Rect {
                left: 200,
                top: -800,
                right: 1600,
                bottom: -100,
            },
            outer
        ));
        assert!(!rect_is_within(Rect { left: 99, ..outer }, outer));
        assert!(!rect_is_within(
            Rect {
                right: 100,
                ..outer
            },
            outer
        ));
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
