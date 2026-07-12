//! Repairs FalloutNV.exe's exclusive-fullscreen window placement calls.
//!
//! The startup/reset paths use valid geometry but place the outer window at the
//! configured location, leaving the fullscreen client area offset from its
//! monitor. Three later paths also pass the adjusted bottom edge as `y` and
//! `top - bottom` as the height, producing malformed focus/lifecycle moves.
//!
//! Psycho owns only narrow, callsite-specific correction boundaries:
//! - renderer creation/reset: preserve size and align the client to its monitor;
//! - focus regain: restore an iconic window, normalize the rectangle, and call;
//! - focus loss: suppress the activating window move;
//! - renderer lifecycle: normalize the rectangle and call.
//! - renderer child resize: pass through unchanged.
//!
//! The game's focus managers and D3D9 reset path remain untouched. Installation
//! replaces only FalloutNV.exe's `SetWindowPos` IAT pointer. An earlier IAT hook
//! is captured and chained, while directly modified or unknown callsites are
//! reported and left alone.
//!
//! Engine addresses and instruction contracts are proven by:
//! - `analysis/ghidra/output/perf/display_current_fix_contract_audit.txt`
//! - `analysis/ghidra/output/perf/display_focus_timer_target_followup.txt`
//! - `analysis/ghidra/output/perf/display_startup_position_followup.txt`

use std::ffi::c_void;
use std::slice;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicUsize, Ordering};

use anyhow::{Context, ensure};
use libpsycho::os::windows::winapi::{
    PointerExchange, client_origin, compare_exchange_pointer, get_last_error_code,
    get_module_handle_a, get_proc_address, get_tick_count, is_iconic, is_window, load_pointer,
    nearest_monitor_rect, nearest_monitor_rect_from_point, set_last_error, show_window,
    virtual_query, window_rect,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_GUARD, PAGE_NOACCESS,
};

/// FalloutNV.exe's imported `user32!SetWindowPos` pointer.
const SET_WINDOW_POS_IAT: usize = 0x00FDF2A4;
const FULLSCREEN_PREDICATE: usize = 0x00446E10;
const TOP_LEVEL_HWND_GLOBAL: usize = 0x011C6FC0;
const RENDERER_CHILD_HWND_GLOBAL: usize = 0x011C6FBC;
const SW_RESTORE: i32 = 9;
const SWP_NOSIZE: u32 = 0x0001;
const SWP_NOZORDER: u32 = 0x0004;
const SWP_NOACTIVATE: u32 = 0x0010;
const SWP_SHOWWINDOW: u32 = 0x0040;
const SWP_ASYNCWINDOWPOS: u32 = 0x4000;
const CATCH_UP_FLAGS: u32 = SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_ASYNCWINDOWPOS;

/// Reject corrupt runtime arguments before applying an audited correction.
const MAX_WINDOW_EXTENT: i32 = 32768;

type SetWindowPosFn =
    unsafe extern "system" fn(*mut c_void, *mut c_void, i32, i32, i32, i32, u32) -> i32;
type IsFullscreenFn = unsafe extern "C" fn() -> u8;

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum TransitionSite {
    RendererCreation = 0,
    DeviceReset = 1,
    ChildResize = 2,
    FocusRegain = 3,
    FocusLoss = 4,
    RendererLifecycle = 5,
}

impl TransitionSite {
    const ALL: [Self; 6] = [
        Self::RendererCreation,
        Self::DeviceReset,
        Self::ChildResize,
        Self::FocusRegain,
        Self::FocusLoss,
        Self::RendererLifecycle,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    const fn name(self) -> &'static str {
        match self {
            Self::RendererCreation => "renderer-create",
            Self::DeviceReset => "device-reset",
            Self::ChildResize => "child-resize",
            Self::FocusRegain => "focus-regain",
            Self::FocusLoss => "focus-loss",
            Self::RendererLifecycle => "renderer-lifecycle",
        }
    }

    const fn from_return_address(address: usize) -> Option<Self> {
        match address {
            0x004DA957 => Some(Self::RendererCreation),
            0x004DC4D4 => Some(Self::DeviceReset),
            0x004D7867 => Some(Self::ChildResize),
            0x0086B4C5 => Some(Self::FocusRegain),
            0x0086B62E => Some(Self::FocusLoss),
            0x0087271B => Some(Self::RendererLifecycle),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum CallsiteCoverage {
    Unknown = 0,
    Covered = 1,
    ExternalOwner = 2,
    Conflict = 3,
}

impl CallsiteCoverage {
    fn from_raw(value: u8) -> Self {
        match value {
            1 => Self::Covered,
            2 => Self::ExternalOwner,
            3 => Self::Conflict,
            _ => Self::Unknown,
        }
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Covered => "covered",
            Self::ExternalOwner => "external",
            Self::Conflict => "conflict",
        }
    }
}

/// Full instruction fingerprint for one audited argument-construction path.
///
/// Fingerprinting only the indirect call would not prove that the surrounding
/// code still constructs the malformed rectangle we intend to repair.
struct CallsiteContract {
    site: TransitionSite,
    start: usize,
    call_offset: usize,
    expected: &'static [u8],
}

// 0x004DA8FE..0x004DA957: renderer size, configured location, HWND, and show.
const RENDERER_CREATION_BYTES: &[u8] = &[
    0x8B, 0x8D, 0xA4, 0xFE, 0xFF, 0xFF, 0x2B, 0x8D, 0x9C, 0xFE, 0xFF, 0xFF, 0x89, 0x8D, 0xAC, 0xFE,
    0xFF, 0xFF, // adjusted width
    0x8B, 0x95, 0xA8, 0xFE, 0xFF, 0xFF, 0x2B, 0x95, 0xA0, 0xFE, 0xFF, 0xFF, 0x89, 0x95, 0x98, 0xFE,
    0xFF, 0xFF, // adjusted height
    0x6A, 0x40, 0x8B, 0x85, 0x98, 0xFE, 0xFF, 0xFF, 0x50, 0x8B, 0x8D, 0xAC, 0xFE, 0xFF, 0xFF, 0x51,
    0xB9, 0x54, 0x76, 0x1C, 0x01, 0xE8, 0xB4, 0x5A, 0xF7, 0xFF, 0x50, // configured Y
    0xB9, 0xD4, 0x75, 0x1C, 0x01, 0xE8, 0xA9, 0x5A, 0xF7, 0xFF, 0x50, // configured X
    0x6A, 0x00, 0x8B, 0x15, 0xC0, 0x6F, 0x1C, 0x01, 0x52, // parent HWND
    0xFF, 0x15, 0xA4, 0xF2, 0xFD, 0x00, // call [SetWindowPos IAT]
];

// 0x004DC496..0x004DC4D4: successful D3D recreation window placement.
const DEVICE_RESET_BYTES: &[u8] = &[
    0x8B, 0x55, 0xF0, 0x2B, 0x55, 0xE8, 0x89, 0x55, 0xF8, // adjusted width
    0x8B, 0x45, 0xF4, 0x2B, 0x45, 0xEC, 0x89, 0x45, 0xE4, // adjusted height
    0x6A, 0x40, 0x8B, 0x4D, 0xE4, 0x51, 0x8B, 0x55, 0xF8, 0x52, 0xB9, 0x54, 0x76, 0x1C, 0x01, 0xE8,
    0x34, 0x3F, 0xF7, 0xFF, 0x50, // configured Y
    0xB9, 0xD4, 0x75, 0x1C, 0x01, 0xE8, 0x29, 0x3F, 0xF7, 0xFF, 0x50, // configured X
    0x6A, 0x00, 0x8B, 0x45, 0xE0, 0x50, // HWND
    0xFF, 0x15, 0xA4, 0xF2, 0xFD, 0x00, // call [SetWindowPos IAT]
];

// 0x004D7839..0x004D7867: WM_SIZE child resize, always exact pass-through.
const CHILD_RESIZE_BYTES: &[u8] = &[
    0x6A, 0x02, // SWP_NOZORDER
    0x8B, 0x4D, 0x14, 0xC1, 0xE9, 0x10, 0x81, 0xE1, 0xFF, 0xFF, 0x00, 0x00, 0x0F, 0xB7, 0xD1, 0x52,
    0x8B, 0x45, 0x14, 0x25, 0xFF, 0xFF, 0x00, 0x00, 0x0F, 0xB7, 0xC8, 0x51, // height/width
    0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0x8B, 0x55, 0xC0, 0x52, // origin and child HWND
    0xFF, 0x15, 0xA4, 0xF2, 0xFD, 0x00, // call [SetWindowPos IAT]
];

// 0x0086B48F..0x0086B4C5: flags, malformed cy/cx/y/x, insert-after, HWND, call.
const FOCUS_REGAIN_BYTES: &[u8] = &[
    0x6A, 0x00, // push flags
    0x8B, 0x95, 0x04, 0xFD, 0xFF, 0xFF, 0x2B, 0x95, 0x0C, 0xFD, 0xFF, 0xFF, 0x52, // cy
    0x8B, 0x85, 0x08, 0xFD, 0xFF, 0xFF, 0x2B, 0x85, 0x00, 0xFD, 0xFF, 0xFF, 0x50, // cx
    0x8B, 0x8D, 0x0C, 0xFD, 0xFF, 0xFF, 0x51, // y = adjusted bottom
    0x8B, 0x95, 0x00, 0xFD, 0xFF, 0xFF, 0x52, // x
    0x6A, 0x00, // hWndInsertAfter
    0x8B, 0x45, 0xDC, 0x50, // HWND
    0xFF, 0x15, 0xA4, 0xF2, 0xFD, 0x00, // call [SetWindowPos IAT]
];

// 0x0086B5F8..0x0086B62E: the focus-loss variant of the same broken geometry.
const FOCUS_LOSS_BYTES: &[u8] = &[
    0x6A, 0x00, // push flags
    0x8B, 0x85, 0xF0, 0xFC, 0xFF, 0xFF, 0x2B, 0x85, 0xF8, 0xFC, 0xFF, 0xFF, 0x50, // cy
    0x8B, 0x8D, 0xF4, 0xFC, 0xFF, 0xFF, 0x2B, 0x8D, 0xEC, 0xFC, 0xFF, 0xFF, 0x51, // cx
    0x8B, 0x95, 0xF8, 0xFC, 0xFF, 0xFF, 0x52, // y = adjusted bottom
    0x8B, 0x85, 0xEC, 0xFC, 0xFF, 0xFF, 0x50, // x
    0x6A, 0x00, // hWndInsertAfter
    0x8B, 0x4D, 0xDC, 0x51, // HWND
    0xFF, 0x15, 0xA4, 0xF2, 0xFD, 0x00, // call [SetWindowPos IAT]
];

// 0x008726F2..0x0087271B: renderer lifecycle construction and HWND lookup.
const RENDERER_LIFECYCLE_BYTES: &[u8] = &[
    0x6A, 0x00, // push flags
    0x8B, 0x55, 0xD4, 0x2B, 0x55, 0xDC, 0x52, // cy
    0x8B, 0x45, 0xD8, 0x2B, 0x45, 0xD0, 0x50, // cx
    0x8B, 0x4D, 0xDC, 0x51, // y = adjusted bottom
    0x8B, 0x55, 0xD0, 0x52, // x
    0x6A, 0x00, // hWndInsertAfter
    0xA1, 0x0C, 0xEA, 0x1D, 0x01, 0x8B, 0x48, 0x08, 0x51, // OSGlobals HWND
    0xFF, 0x15, 0xA4, 0xF2, 0xFD, 0x00, // call [SetWindowPos IAT]
];

const CALLSITE_CONTRACTS: [CallsiteContract; 6] = [
    CallsiteContract {
        site: TransitionSite::RendererCreation,
        start: 0x004DA8FE,
        call_offset: 0x53,
        expected: RENDERER_CREATION_BYTES,
    },
    CallsiteContract {
        site: TransitionSite::DeviceReset,
        start: 0x004DC496,
        call_offset: 0x38,
        expected: DEVICE_RESET_BYTES,
    },
    CallsiteContract {
        site: TransitionSite::ChildResize,
        start: 0x004D7839,
        call_offset: 0x28,
        expected: CHILD_RESIZE_BYTES,
    },
    CallsiteContract {
        site: TransitionSite::FocusRegain,
        start: 0x0086B48F,
        call_offset: 0x30,
        expected: FOCUS_REGAIN_BYTES,
    },
    CallsiteContract {
        site: TransitionSite::FocusLoss,
        start: 0x0086B5F8,
        call_offset: 0x30,
        expected: FOCUS_LOSS_BYTES,
    },
    CallsiteContract {
        site: TransitionSite::RendererLifecycle,
        start: 0x008726F2,
        call_offset: 0x23,
        expected: RENDERER_LIFECYCLE_BYTES,
    },
];

const FULLSCREEN_PREDICATE_BYTES: &[u8] = &[
    0x55, 0x8B, 0xEC, 0xB9, 0xB4, 0x77, 0x1C, 0x01, 0xE8, 0x43, 0x1F, 0xFC, 0xFF, 0x8A, 0x00, 0x5D,
    0xC3,
];

const _: () = {
    assert!(RENDERER_CREATION_BYTES.len() == 0x59);
    assert!(DEVICE_RESET_BYTES.len() == 0x3E);
    assert!(CHILD_RESIZE_BYTES.len() == 0x2E);
    assert!(FOCUS_REGAIN_BYTES.len() == 0x36);
    assert!(FOCUS_LOSS_BYTES.len() == 0x36);
    assert!(RENDERER_LIFECYCLE_BYTES.len() == 0x29);
    assert!(FULLSCREEN_PREDICATE_BYTES.len() == 0x11);

    assert!(CALLSITE_CONTRACTS[0].call_offset + 6 == RENDERER_CREATION_BYTES.len());
    assert!(CALLSITE_CONTRACTS[1].call_offset + 6 == DEVICE_RESET_BYTES.len());
    assert!(CALLSITE_CONTRACTS[2].call_offset + 6 == CHILD_RESIZE_BYTES.len());
    assert!(CALLSITE_CONTRACTS[3].call_offset + 6 == FOCUS_REGAIN_BYTES.len());
    assert!(CALLSITE_CONTRACTS[4].call_offset + 6 == FOCUS_LOSS_BYTES.len());
    assert!(CALLSITE_CONTRACTS[5].call_offset + 6 == RENDERER_LIFECYCLE_BYTES.len());
};

static INSTALLED: AtomicBool = AtomicBool::new(false);
static PREDECESSOR: AtomicUsize = AtomicUsize::new(0);
static PREDECESSOR_VANILLA: AtomicBool = AtomicBool::new(false);
static CALLSITE_COVERAGE: [AtomicU8; 6] =
    [const { AtomicU8::new(CallsiteCoverage::Unknown as u8) }; 6];
static FULLSCREEN_PREDICATE_VALID: AtomicBool = AtomicBool::new(false);

static RENDERER_CREATION_OBSERVATIONS: AtomicU32 = AtomicU32::new(0);
static RENDERER_CREATION_CORRECTIONS: AtomicU32 = AtomicU32::new(0);
static DEVICE_RESET_OBSERVATIONS: AtomicU32 = AtomicU32::new(0);
static DEVICE_RESET_CORRECTIONS: AtomicU32 = AtomicU32::new(0);
static CHILD_RESIZE_PASSTHROUGHS: AtomicU32 = AtomicU32::new(0);
static LOSS_SUPPRESSIONS: AtomicU32 = AtomicU32::new(0);
static REGAIN_NORMALIZATIONS: AtomicU32 = AtomicU32::new(0);
static LIFECYCLE_NORMALIZATIONS: AtomicU32 = AtomicU32::new(0);
static CONTRACT_MISMATCHES: AtomicU32 = AtomicU32::new(0);
static PREDECESSOR_FAILURES: AtomicU32 = AtomicU32::new(0);
static MONITOR_POINT_SELECTIONS: AtomicU32 = AtomicU32::new(0);
static MONITOR_WINDOW_SELECTIONS: AtomicU32 = AtomicU32::new(0);
static MONITOR_FALLBACKS: AtomicU32 = AtomicU32::new(0);
static RESTORE_ATTEMPTS: AtomicU32 = AtomicU32::new(0);
static CATCH_UP_ATTEMPTS: AtomicU32 = AtomicU32::new(0);
static CATCH_UP_SUCCESSES: AtomicU32 = AtomicU32::new(0);
static CATCH_UP_FAILURES: AtomicU32 = AtomicU32::new(0);
static LAST_TRANSITION_MS: AtomicU32 = AtomicU32::new(0);
static LAST_RESULT: AtomicBool = AtomicBool::new(false);
static LAST_ERROR: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy)]
pub(crate) struct DiagnosticSnapshot {
    pub installed: bool,
    pub predecessor: usize,
    pub predecessor_vanilla: bool,
    pub site_states: [CallsiteCoverage; 6],
    pub renderer_creation_observations: u32,
    pub renderer_creation_corrections: u32,
    pub device_reset_observations: u32,
    pub device_reset_corrections: u32,
    pub child_resize_passthroughs: u32,
    pub loss_suppressions: u32,
    pub regain_normalizations: u32,
    pub lifecycle_normalizations: u32,
    pub contract_mismatches: u32,
    pub predecessor_failures: u32,
    pub monitor_point_selections: u32,
    pub monitor_window_selections: u32,
    pub monitor_fallbacks: u32,
    pub restore_attempts: u32,
    pub catch_up_attempts: u32,
    pub catch_up_successes: u32,
    pub catch_up_failures: u32,
    pub last_transition_ms: u32,
    pub last_result: bool,
    pub last_error: u32,
}

pub(crate) fn diagnostic_snapshot() -> DiagnosticSnapshot {
    DiagnosticSnapshot {
        installed: INSTALLED.load(Ordering::Acquire),
        predecessor: PREDECESSOR.load(Ordering::Acquire),
        predecessor_vanilla: PREDECESSOR_VANILLA.load(Ordering::Acquire),
        site_states: TransitionSite::ALL.map(callsite_coverage),
        renderer_creation_observations: RENDERER_CREATION_OBSERVATIONS.load(Ordering::Relaxed),
        renderer_creation_corrections: RENDERER_CREATION_CORRECTIONS.load(Ordering::Relaxed),
        device_reset_observations: DEVICE_RESET_OBSERVATIONS.load(Ordering::Relaxed),
        device_reset_corrections: DEVICE_RESET_CORRECTIONS.load(Ordering::Relaxed),
        child_resize_passthroughs: CHILD_RESIZE_PASSTHROUGHS.load(Ordering::Relaxed),
        loss_suppressions: LOSS_SUPPRESSIONS.load(Ordering::Relaxed),
        regain_normalizations: REGAIN_NORMALIZATIONS.load(Ordering::Relaxed),
        lifecycle_normalizations: LIFECYCLE_NORMALIZATIONS.load(Ordering::Relaxed),
        contract_mismatches: CONTRACT_MISMATCHES.load(Ordering::Relaxed),
        predecessor_failures: PREDECESSOR_FAILURES.load(Ordering::Relaxed),
        monitor_point_selections: MONITOR_POINT_SELECTIONS.load(Ordering::Relaxed),
        monitor_window_selections: MONITOR_WINDOW_SELECTIONS.load(Ordering::Relaxed),
        monitor_fallbacks: MONITOR_FALLBACKS.load(Ordering::Relaxed),
        restore_attempts: RESTORE_ATTEMPTS.load(Ordering::Relaxed),
        catch_up_attempts: CATCH_UP_ATTEMPTS.load(Ordering::Relaxed),
        catch_up_successes: CATCH_UP_SUCCESSES.load(Ordering::Relaxed),
        catch_up_failures: CATCH_UP_FAILURES.load(Ordering::Relaxed),
        last_transition_ms: LAST_TRANSITION_MS.load(Ordering::Acquire),
        last_result: LAST_RESULT.load(Ordering::Acquire),
        last_error: LAST_ERROR.load(Ordering::Acquire),
    }
}

pub(crate) fn site_state_name(state: CallsiteCoverage) -> &'static str {
    state.name()
}

#[derive(Clone, Copy)]
struct WindowRequest {
    hwnd: *mut c_void,
    insert_after: *mut c_void,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    flags: u32,
}

impl WindowRequest {
    fn with_position(self, x: i32, y: i32) -> Self {
        Self { x, y, ..self }
    }

    fn corrected_malformed(self, geometry: MalformedGeometry) -> Self {
        let (x, y) = monitor_relative_position(self.hwnd, self.x, geometry.top);
        Self {
            x,
            y,
            height: geometry.height,
            ..self
        }
    }
}

#[derive(Clone, Copy)]
struct MalformedGeometry {
    top: i32,
    height: i32,
}

/// ABI bridge for an imported stdcall function.
///
/// On entry, `[esp]` is the original caller return address and the seven
/// `SetWindowPos` arguments begin at `[esp + 4]`. The bridge passes the caller
/// in fastcall `ecx`, reserves `edx`, and jumps without changing the stack.
/// Consequently `checked_set_window_pos` receives the original seven stack
/// arguments and returns with stdcall cleanup (`ret 28`).
///
/// This exact generated contract is verified in the i686 release binary.
#[unsafe(naked)]
unsafe extern "system" fn set_window_pos_entry(
    _hwnd: *mut c_void,
    _insert_after: *mut c_void,
    _x: i32,
    _y: i32,
    _width: i32,
    _height: i32,
    _flags: u32,
) -> i32 {
    core::arch::naked_asm!(
        "mov ecx, [esp]",
        "xor edx, edx",
        "jmp {}",
        sym checked_set_window_pos,
    );
}

unsafe extern "fastcall" fn checked_set_window_pos(
    caller: usize,
    _reserved: usize,
    hwnd: *mut c_void,
    insert_after: *mut c_void,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    flags: u32,
) -> i32 {
    let request = WindowRequest {
        hwnd,
        insert_after,
        x,
        y,
        width,
        height,
        flags,
    };

    if !INSTALLED.load(Ordering::Acquire) {
        return unsafe { call_predecessor(request) };
    }

    let Some(site) = TransitionSite::from_return_address(caller) else {
        return unsafe { call_predecessor(request) };
    };
    if callsite_coverage(site) != CallsiteCoverage::Covered {
        return unsafe { call_predecessor(request) };
    }

    match site {
        TransitionSite::RendererCreation => unsafe {
            handle_valid_fullscreen_position(site, request, &RENDERER_CREATION_OBSERVATIONS)
        },
        TransitionSite::DeviceReset => unsafe {
            handle_valid_fullscreen_position(site, request, &DEVICE_RESET_OBSERVATIONS)
        },
        TransitionSite::ChildResize => {
            CHILD_RESIZE_PASSTHROUGHS.fetch_add(1, Ordering::Relaxed);
            unsafe { call_predecessor(request) }
        }
        TransitionSite::FocusLoss => {
            if decode_malformed_geometry(request).is_none() {
                record_contract_mismatch(site, caller, request);
                return unsafe { call_predecessor(request) };
            }
            suppress_focus_loss()
        }
        TransitionSite::FocusRegain => {
            let Some(geometry) = decode_malformed_geometry(request) else {
                record_contract_mismatch(site, caller, request);
                return unsafe { call_predecessor(request) };
            };
            restore_if_iconic(request.hwnd);
            let count = REGAIN_NORMALIZATIONS.fetch_add(1, Ordering::Relaxed) + 1;
            unsafe { execute_corrected_request(site, count, request.corrected_malformed(geometry)) }
        }
        TransitionSite::RendererLifecycle => {
            let Some(geometry) = decode_malformed_geometry(request) else {
                record_contract_mismatch(site, caller, request);
                return unsafe { call_predecessor(request) };
            };
            let count = LIFECYCLE_NORMALIZATIONS.fetch_add(1, Ordering::Relaxed) + 1;
            unsafe { execute_corrected_request(site, count, request.corrected_malformed(geometry)) }
        }
    }
}

unsafe fn handle_valid_fullscreen_position(
    site: TransitionSite,
    request: WindowRequest,
    observations: &AtomicU32,
) -> i32 {
    observations.fetch_add(1, Ordering::Relaxed);
    if !is_exclusive_fullscreen() {
        return unsafe { call_predecessor(request) };
    }
    if !valid_position_request(request) {
        record_contract_mismatch(site, site_return_address(site), request);
        return unsafe { call_predecessor(request) };
    }

    let Some(corrected) = align_client_to_requested_monitor(request) else {
        MONITOR_FALLBACKS.fetch_add(1, Ordering::Relaxed);
        return unsafe { call_predecessor(request) };
    };
    let count = match site {
        TransitionSite::RendererCreation => {
            RENDERER_CREATION_CORRECTIONS.fetch_add(1, Ordering::Relaxed) + 1
        }
        TransitionSite::DeviceReset => DEVICE_RESET_CORRECTIONS.fetch_add(1, Ordering::Relaxed) + 1,
        _ => return unsafe { call_predecessor(request) },
    };
    unsafe { execute_corrected_request(site, count, corrected) }
}

fn valid_position_request(request: WindowRequest) -> bool {
    request.width > 0
        && request.width <= MAX_WINDOW_EXTENT
        && request.height > 0
        && request.height <= MAX_WINDOW_EXTENT
        && request.flags == SWP_SHOWWINDOW
}

const fn site_return_address(site: TransitionSite) -> usize {
    match site {
        TransitionSite::RendererCreation => 0x004DA957,
        TransitionSite::DeviceReset => 0x004DC4D4,
        TransitionSite::ChildResize => 0x004D7867,
        TransitionSite::FocusRegain => 0x0086B4C5,
        TransitionSite::FocusLoss => 0x0086B62E,
        TransitionSite::RendererLifecycle => 0x0087271B,
    }
}

fn decode_malformed_geometry(request: WindowRequest) -> Option<MalformedGeometry> {
    if request.width <= 0 || request.width > MAX_WINDOW_EXTENT || request.height >= 0 {
        return None;
    }

    let top = request.y.checked_add(request.height)?;
    let height = request.height.checked_neg()?;
    if height == 0 || height > MAX_WINDOW_EXTENT {
        return None;
    }

    Some(MalformedGeometry { top, height })
}

fn is_exclusive_fullscreen() -> bool {
    if !FULLSCREEN_PREDICATE_VALID.load(Ordering::Acquire) {
        return false;
    }
    let predicate: IsFullscreenFn = unsafe { std::mem::transmute(FULLSCREEN_PREDICATE) };
    unsafe { predicate() != 0 }
}

fn align_client_to_requested_monitor(request: WindowRequest) -> Option<WindowRequest> {
    let monitor = if let Some(monitor) = nearest_monitor_rect_from_point(request.x, request.y) {
        MONITOR_POINT_SELECTIONS.fetch_add(1, Ordering::Relaxed);
        monitor
    } else {
        MONITOR_FALLBACKS.fetch_add(1, Ordering::Relaxed);
        let monitor = nearest_monitor_rect(request.hwnd)?;
        MONITOR_WINDOW_SELECTIONS.fetch_add(1, Ordering::Relaxed);
        monitor
    };
    align_client_to_monitor(request, monitor.left, monitor.top)
}

fn align_client_to_current_monitor(request: WindowRequest) -> Option<WindowRequest> {
    let monitor = nearest_monitor_rect(request.hwnd)?;
    MONITOR_WINDOW_SELECTIONS.fetch_add(1, Ordering::Relaxed);
    align_client_to_monitor(request, monitor.left, monitor.top)
}

fn align_client_to_monitor(
    request: WindowRequest,
    monitor_left: i32,
    monitor_top: i32,
) -> Option<WindowRequest> {
    let outer = window_rect(request.hwnd)?;
    let client = client_origin(request.hwnd)?;
    let nonclient_x = client.x.checked_sub(outer.left)?;
    let nonclient_y = client.y.checked_sub(outer.top)?;
    let x = monitor_left.checked_sub(nonclient_x)?;
    let y = monitor_top.checked_sub(nonclient_y)?;
    Some(request.with_position(x, y))
}

fn restore_if_iconic(hwnd: *mut c_void) {
    if is_iconic(hwnd) {
        RESTORE_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        // ShowWindow reports prior visibility, not operation success.
        show_window(hwnd, SW_RESTORE);
    }
}

fn monitor_relative_position(hwnd: *mut c_void, x: i32, y: i32) -> (i32, i32) {
    if let Some(monitor) = nearest_monitor_rect(hwnd)
        && let (Some(x), Some(y)) = (x.checked_add(monitor.left), y.checked_add(monitor.top))
    {
        MONITOR_WINDOW_SELECTIONS.fetch_add(1, Ordering::Relaxed);
        return (x, y);
    }

    // The engine's primary-monitor coordinates remain the safest fallback.
    MONITOR_FALLBACKS.fetch_add(1, Ordering::Relaxed);
    (x, y)
}

fn suppress_focus_loss() -> i32 {
    let count = LOSS_SUPPRESSIONS.fetch_add(1, Ordering::Relaxed) + 1;
    LAST_TRANSITION_MS.store(get_tick_count(), Ordering::Release);
    LAST_RESULT.store(true, Ordering::Release);
    LAST_ERROR.store(0, Ordering::Release);

    if should_log(count) {
        log::info!(
            "[DISPLAY] suppressed audited focus-loss SetWindowPos #{}",
            count
        );
    }
    1
}

unsafe fn execute_corrected_request(
    site: TransitionSite,
    count: u32,
    request: WindowRequest,
) -> i32 {
    let result = unsafe { call_predecessor(request) };
    record_predecessor_result(site, count, result, request);
    result
}

fn record_contract_mismatch(site: TransitionSite, caller: usize, request: WindowRequest) {
    let count = CONTRACT_MISMATCHES.fetch_add(1, Ordering::Relaxed) + 1;
    if should_log(count) {
        log::warn!(
            "[DISPLAY] {} contract mismatch #{} at 0x{:08X}: ({},{} {}x{}) flags={:#x}; chained unchanged",
            site.name(),
            count,
            caller,
            request.x,
            request.y,
            request.width,
            request.height,
            request.flags,
        );
    }
}

fn record_predecessor_result(
    site: TransitionSite,
    count: u32,
    result: i32,
    request: WindowRequest,
) {
    // GetLastError must be captured before logging or calling another WinAPI.
    let (error, failure_count) = if result == 0 {
        let failure_count = PREDECESSOR_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
        (get_last_error_code(), failure_count)
    } else {
        (0, 0)
    };

    LAST_TRANSITION_MS.store(get_tick_count(), Ordering::Release);
    LAST_RESULT.store(result != 0, Ordering::Release);
    LAST_ERROR.store(error, Ordering::Release);

    if result == 0 && should_log(failure_count) {
        log::warn!(
            "[DISPLAY] corrected {} SetWindowPos #{} failed: error={} rect=({},{} {}x{}) flags={:#x}",
            site.name(),
            count,
            error,
            request.x,
            request.y,
            request.width,
            request.height,
            request.flags,
        );
    } else if should_log(count) {
        log::info!(
            "[DISPLAY] corrected {} SetWindowPos #{}: rect=({},{} {}x{}) flags={:#x}",
            site.name(),
            count,
            request.x,
            request.y,
            request.width,
            request.height,
            request.flags,
        );
    }

    if result == 0 {
        // Logging may change the thread's last-error value. Preserve the
        // predecessor's observable SetWindowPos failure contract.
        set_last_error(error);
    }
}

#[inline]
fn should_log(count: u32) -> bool {
    count <= 3 || count.is_power_of_two()
}

fn catch_up_existing_window() {
    if !is_exclusive_fullscreen() {
        return;
    }

    let parent_slot = TOP_LEVEL_HWND_GLOBAL as *mut *mut c_void;
    let child_slot = RENDERER_CHILD_HWND_GLOBAL as *mut *mut c_void;
    let Some(hwnd) = load_pointer(parent_slot)
        .ok()
        .filter(|hwnd| is_window(*hwnd))
    else {
        return;
    };
    if load_pointer(child_slot)
        .ok()
        .is_none_or(|child| child.is_null())
    {
        return;
    }

    let Some(outer) = window_rect(hwnd) else {
        return;
    };
    let request = WindowRequest {
        hwnd,
        insert_after: std::ptr::null_mut(),
        x: outer.left,
        y: outer.top,
        width: 0,
        height: 0,
        flags: CATCH_UP_FLAGS,
    };
    let Some(corrected) = align_client_to_current_monitor(request) else {
        MONITOR_FALLBACKS.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if corrected.x == request.x && corrected.y == request.y {
        return;
    }

    let attempt = CATCH_UP_ATTEMPTS.fetch_add(1, Ordering::Relaxed) + 1;
    let result = unsafe { call_predecessor(corrected) };
    let error = if result == 0 {
        get_last_error_code()
    } else {
        0
    };
    LAST_TRANSITION_MS.store(get_tick_count(), Ordering::Release);
    LAST_RESULT.store(result != 0, Ordering::Release);
    LAST_ERROR.store(error, Ordering::Release);

    if result != 0 {
        CATCH_UP_SUCCESSES.fetch_add(1, Ordering::Relaxed);
        log::info!(
            "[DISPLAY] queued late-install position catch-up #{}: ({},{}) -> ({},{})",
            attempt,
            request.x,
            request.y,
            corrected.x,
            corrected.y,
        );
    } else {
        CATCH_UP_FAILURES.fetch_add(1, Ordering::Relaxed);
        log::warn!(
            "[DISPLAY] late-install position catch-up #{} failed: error={}",
            attempt,
            error,
        );
    }
}

unsafe fn call_predecessor(request: WindowRequest) -> i32 {
    let target = PREDECESSOR.load(Ordering::Acquire);
    if target == 0 || target == set_window_pos_entry as *const () as usize {
        PREDECESSOR_FAILURES.fetch_add(1, Ordering::Relaxed);
        LAST_ERROR.store(0, Ordering::Release);
        return 0;
    }

    // PREDECESSOR is published only after installation verifies a committed,
    // executable target with the SetWindowPos ABI.
    let predecessor: SetWindowPosFn = unsafe { std::mem::transmute(target) };
    unsafe {
        predecessor(
            request.hwnd,
            request.insert_after,
            request.x,
            request.y,
            request.width,
            request.height,
            request.flags,
        )
    }
}

pub fn install_display_hooks() -> anyhow::Result<()> {
    let coverage = audit_callsites();
    ensure!(
        [0, 1, 3, 4, 5]
            .into_iter()
            .any(|index| coverage[index] == CallsiteCoverage::Covered),
        "all corrective SetWindowPos callsites are externally owned or conflicted"
    );
    audit_fullscreen_predicate();

    let owner = claim_set_window_pos_iat()?;
    INSTALLED.store(true, Ordering::Release);
    catch_up_existing_window();

    log::info!(
        "[DISPLAY] Exclusive-fullscreen window fix installed: predecessor=0x{:08X} ({}) sites={}/{}/{}/{}/{}/{}",
        owner.address,
        if owner.is_vanilla {
            "vanilla"
        } else {
            "external"
        },
        coverage[0].name(),
        coverage[1].name(),
        coverage[2].name(),
        coverage[3].name(),
        coverage[4].name(),
        coverage[5].name(),
    );
    Ok(())
}

#[derive(Clone, Copy)]
struct IatOwner {
    address: usize,
    is_vanilla: bool,
}

fn claim_set_window_pos_iat() -> anyhow::Result<IatOwner> {
    ensure!(
        is_readable(SET_WINDOW_POS_IAT, std::mem::size_of::<*mut c_void>()),
        "SetWindowPos IAT slot 0x{SET_WINDOW_POS_IAT:08X} is unreadable"
    );
    ensure!(
        SET_WINDOW_POS_IAT.is_multiple_of(std::mem::align_of::<*mut c_void>()),
        "SetWindowPos IAT slot is misaligned"
    );

    let slot = SET_WINDOW_POS_IAT as *mut *mut c_void;
    let shim = set_window_pos_entry as *const () as *mut c_void;
    let current = load_pointer(slot).context("read SetWindowPos IAT slot")?;

    if current == shim {
        let predecessor = PREDECESSOR.load(Ordering::Acquire);
        ensure!(
            predecessor != 0,
            "Psycho owns the IAT slot without a predecessor"
        );
        return Ok(IatOwner {
            address: predecessor,
            is_vanilla: PREDECESSOR_VANILLA.load(Ordering::Acquire),
        });
    }

    ensure!(
        is_executable(current as usize),
        "SetWindowPos predecessor 0x{:08X} is not executable",
        current as usize
    );

    let owner = IatOwner {
        address: current as usize,
        is_vanilla: vanilla_set_window_pos() == Some(current),
    };

    // Publish before the pointer swap. The shim may run as soon as the atomic
    // exchange succeeds, including through a later hook that captures it.
    PREDECESSOR.store(owner.address, Ordering::Release);
    PREDECESSOR_VANILLA.store(owner.is_vanilla, Ordering::Release);

    let exchange =
        compare_exchange_pointer(slot, current, shim).context("replace SetWindowPos IAT slot")?;
    if let PointerExchange::Mismatch(observed) = exchange {
        PREDECESSOR.store(0, Ordering::Release);
        PREDECESSOR_VANILLA.store(false, Ordering::Release);
        anyhow::bail!(
            "SetWindowPos IAT ownership changed during install: expected 0x{:08X}, found 0x{:08X}",
            current as usize,
            observed as usize,
        );
    }

    let observed = match load_pointer(slot).context("read back SetWindowPos IAT slot") {
        Ok(observed) => observed,
        Err(error) => {
            restore_predecessor_if_owned(slot, shim, current);
            return Err(error);
        }
    };
    if observed != shim {
        // A later hook may legitimately own the slot and chain Psycho. Do not
        // overwrite it and do not clear PREDECESSOR: our shim must remain a
        // valid pass-through target in that external chain.
        restore_predecessor_if_owned(slot, shim, current);
        anyhow::bail!(
            "SetWindowPos IAT readback failed: expected 0x{:08X}, found 0x{:08X}",
            shim as usize,
            observed as usize,
        );
    }

    Ok(owner)
}

fn audit_callsites() -> [CallsiteCoverage; 6] {
    let mut coverage = [CallsiteCoverage::Unknown; 6];
    for contract in &CALLSITE_CONTRACTS {
        let state = classify_callsite(contract);
        coverage[contract.site.index()] = state;
        CALLSITE_COVERAGE[contract.site.index()].store(state as u8, Ordering::Release);

        match state {
            CallsiteCoverage::Covered => {
                log::info!("[DISPLAY] {} callsite covered", contract.site.name())
            }
            CallsiteCoverage::ExternalOwner => log::warn!(
                "[DISPLAY] {} callsite has a direct external owner; left untouched",
                contract.site.name()
            ),
            _ => log::warn!(
                "[DISPLAY] {} callsite fingerprint conflict; left untouched",
                contract.site.name()
            ),
        }
    }
    coverage
}

fn audit_fullscreen_predicate() {
    let valid = is_readable(FULLSCREEN_PREDICATE, FULLSCREEN_PREDICATE_BYTES.len())
        && unsafe {
            slice::from_raw_parts(
                FULLSCREEN_PREDICATE as *const u8,
                FULLSCREEN_PREDICATE_BYTES.len(),
            )
        } == FULLSCREEN_PREDICATE_BYTES;
    FULLSCREEN_PREDICATE_VALID.store(valid, Ordering::Release);
    if !valid {
        log::warn!(
            "[DISPLAY] fullscreen predicate fingerprint conflict; renderer creation/reset policies will pass through"
        );
    }
}

fn classify_callsite(contract: &CallsiteContract) -> CallsiteCoverage {
    if !is_readable(contract.start, contract.expected.len()) {
        return CallsiteCoverage::Conflict;
    }

    // The fixed executable address and full range were validated above.
    let actual =
        unsafe { slice::from_raw_parts(contract.start as *const u8, contract.expected.len()) };
    if actual == contract.expected {
        CallsiteCoverage::Covered
    } else if actual.get(contract.call_offset) == Some(&0xE8) {
        CallsiteCoverage::ExternalOwner
    } else {
        CallsiteCoverage::Conflict
    }
}

fn callsite_coverage(site: TransitionSite) -> CallsiteCoverage {
    CallsiteCoverage::from_raw(CALLSITE_COVERAGE[site.index()].load(Ordering::Acquire))
}

fn restore_predecessor_if_owned(
    slot: *mut *mut c_void,
    shim: *mut c_void,
    predecessor: *mut c_void,
) {
    if load_pointer(slot).ok() != Some(shim) {
        return;
    }
    if !matches!(
        compare_exchange_pointer(slot, shim, predecessor),
        Ok(PointerExchange::Exchanged)
    ) {
        log::error!("[DISPLAY] failed to restore SetWindowPos IAT predecessor");
    }
}

fn vanilla_set_window_pos() -> Option<*mut c_void> {
    let user32 = get_module_handle_a(Some("user32.dll")).ok()?;
    get_proc_address(user32, "SetWindowPos").ok()
}

fn is_readable(address: usize, len: usize) -> bool {
    if address < 0x10000 {
        return false;
    }
    let Ok(info) = virtual_query(address as *mut c_void) else {
        return false;
    };
    if info.state != MEM_COMMIT.0 || info.protect == PAGE_NOACCESS {
        return false;
    }
    if (info.protect.0 & PAGE_GUARD.0) != 0 {
        return false;
    }
    address.saturating_add(len) <= (info.base_address as usize).saturating_add(info.region_size)
}

fn is_executable(address: usize) -> bool {
    if address < 0x10000 {
        return false;
    }
    let Ok(info) = virtual_query(address as *mut c_void) else {
        return false;
    };
    info.state == MEM_COMMIT.0
        && (info.protect.0 & PAGE_GUARD.0) == 0
        && matches!(
            info.protect,
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        )
}
