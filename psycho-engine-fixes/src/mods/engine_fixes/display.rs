//! Owns FalloutNV.exe's audited fullscreen and windowed placement boundaries.
//!
//! The exclusive startup path creates a visible 320x240 bootstrap window and
//! never applies the windowed renderer's later placement call. Psycho corrects
//! that one audited `CreateWindowExA` request to a visible popup at the loaded
//! render size before the window becomes visible.
//! The windowed path has the inverse ordering problem: the same bootstrap
//! becomes visible at hard-coded `(0,0)` before the renderer applies the
//! optional `iLocation X/Y` settings. When both settings retain their zero
//! default, the renderer keeps the parent in that corner. Psycho creates the
//! parent at its final size and centered origin, then preserves its live origin
//! when renderer recreation repeats the placement call.
//! Three later paths also pass the adjusted bottom edge as `y` and `top - bottom`
//! as the height, producing malformed focus/lifecycle moves.
//!
//! Psycho owns only narrow, callsite-specific correction boundaries:
//! - exclusive bootstrap creation: use popup style and the loaded render size;
//! - windowed bootstrap creation: use final size/origin and, when configured,
//!   an undecorated popup style;
//! - windowed renderer placement: preserve the live parent origin while sizing;
//! - child resize: pass through unchanged;
//! - device reset: preserve size and align the client to its monitor;
//! - focus regain: restore an iconic window, normalize the rectangle, and call;
//! - focus loss: suppress the activating window move;
//! - renderer lifecycle: normalize the rectangle and call.
//!
//! `bFull Screen` is authoritative. A true value always selects native
//! fullscreen even when borderless-windowed is enabled; a false value selects
//! the windowed renderer branch and its framed or borderless policy.
//! Native fullscreen is identified from the game's audited setting accessor.
//! A live, undecorated window that exactly covers its monitor is treated as
//! borderless fullscreen for transition correction. When another hook already
//! established that window, its style and size remain externally owned.
//!
//! The game's focus managers and D3D9 reset path remain untouched. Installation
//! replaces FalloutNV.exe's `CreateWindowExA` and `SetWindowPos` IAT pointers.
//! Earlier IAT hooks are captured and chained, while directly modified or
//! unknown callsites are reported and left alone.
//!
//! Engine addresses and instruction contracts are proven by:
//! - `analysis/ghidra/output/perf/display_current_fix_contract_audit.txt`
//! - `analysis/ghidra/output/perf/display_focus_timer_target_followup.txt`
//! - `analysis/ghidra/output/perf/display_startup_position_followup.txt`
//! - `analysis/ghidra/output/perf/display_exclusive_startup_owner_followup.txt`

use std::ffi::{c_char, c_void};
use std::slice;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicUsize, Ordering};

use anyhow::{Context, ensure};
use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::winapi::{
        PointerExchange, Rect, adjust_window_rect_ex, client_origin, compare_exchange_pointer,
        get_last_error_code, get_module_handle_a, get_proc_address, get_tick_count,
        get_window_long_a, is_iconic, is_window, load_pointer, nearest_monitor_rect,
        nearest_monitor_rect_from_point, set_last_error, show_window, virtual_query, window_rect,
    },
};
/// FalloutNV.exe's imported `user32!SetWindowPos` pointer.
const SET_WINDOW_POS_IAT: usize = 0x00FDF2A4;
const CREATE_WINDOW_EX_A_IAT: usize = 0x00FDF2B8;
const FULLSCREEN_PREDICATE: usize = 0x00446E10;
const INT_SETTING_ACCESSOR: usize = 0x004503F0;
const TOP_LEVEL_HWND_GLOBAL: usize = 0x011C6FC0;
const RENDERER_CHILD_HWND_GLOBAL: usize = 0x011C6FBC;
const SIZE_WIDTH_SETTING: usize = 0x011C73DC;
const SIZE_HEIGHT_SETTING: usize = 0x011C718C;
const LOCATION_X_SETTING: usize = 0x011C75D4;
const LOCATION_Y_SETTING: usize = 0x011C7654;
const VANILLA_BOOTSTRAP_WIDTH: i32 = 320;
const VANILLA_BOOTSTRAP_HEIGHT: i32 = 240;
const SW_RESTORE: i32 = 9;
const SWP_NOSIZE: u32 = 0x0001;
const SWP_NOZORDER: u32 = 0x0004;
const SWP_NOACTIVATE: u32 = 0x0010;
const SWP_SHOWWINDOW: u32 = 0x0040;
const SWP_ASYNCWINDOWPOS: u32 = 0x4000;
const CATCH_UP_FLAGS: u32 = SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_ASYNCWINDOWPOS;
const WS_VISIBLE: u32 = 0x1000_0000;
const WS_POPUP: u32 = 0x8000_0000;
const FULLSCREEN_BOOTSTRAP_STYLE: u32 = WS_POPUP | WS_VISIBLE;
const WS_CHILD: u32 = 0x4000_0000;
const WS_CAPTION: u32 = 0x00C0_0000;
const WS_THICKFRAME: u32 = 0x0004_0000;
const GWL_STYLE: i32 = -16;

/// Reject corrupt runtime arguments before applying an audited correction.
const MAX_WINDOW_EXTENT: i32 = 32768;

type SetWindowPosFn =
    unsafe extern "system" fn(*mut c_void, *mut c_void, i32, i32, i32, i32, u32) -> i32;
type CreateWindowExAFn = unsafe extern "system" fn(
    u32,
    *const c_char,
    *const c_char,
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
type IsFullscreenFn = unsafe extern "C" fn() -> u8;
type IntSettingFn = unsafe extern "fastcall" fn(usize) -> i32;

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum TransitionSite {
    WindowedParentPlacement = 0,
    DeviceReset = 1,
    ChildResize = 2,
    FocusRegain = 3,
    FocusLoss = 4,
    RendererLifecycle = 5,
}

impl TransitionSite {
    const ALL: [Self; 6] = [
        Self::WindowedParentPlacement,
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
            Self::WindowedParentPlacement => "windowed-parent",
            Self::DeviceReset => "device-reset",
            Self::ChildResize => "child-resize",
            Self::FocusRegain => "focus-regain",
            Self::FocusLoss => "focus-loss",
            Self::RendererLifecycle => "renderer-lifecycle",
        }
    }

    const fn from_return_address(address: usize) -> Option<Self> {
        match address {
            0x004DA957 => Some(Self::WindowedParentPlacement),
            0x004DC4D4 => Some(Self::DeviceReset),
            0x004D7867 => Some(Self::ChildResize),
            0x0086B4C5 => Some(Self::FocusRegain),
            0x0086B62E => Some(Self::FocusLoss),
            0x0087271B => Some(Self::RendererLifecycle),
            _ => None,
        }
    }
}

/// Audit result for one executable caller or import boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum CallsiteCoverage {
    /// The boundary has not been inspected or published yet.
    Unknown = 0,
    /// The complete expected instruction sequence is present.
    Covered = 1,
    /// A direct external call owner replaced the audited indirect call.
    ExternalOwner = 2,
    /// The live instructions do not satisfy any supported ownership contract.
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

    /// Return the stable lowercase diagnostic label for this state.
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

struct ByteContract {
    start: usize,
    call_offset: usize,
    expected: &'static [u8],
}

// 0x0086AF12..0x0086AF48: visible 320x240 bootstrap window construction.
const BOOTSTRAP_CREATE_BYTES: &[u8] = &[
    0x6A, 0x00, 0x8B, 0x55, 0x08, 0x52, 0x6A, 0x00, 0x6A,
    0x00, // param, instance, menu, parent
    0x8B, 0x45, 0xF0, 0x2B, 0x45, 0xE8, 0x50, // height
    0x8B, 0x4D, 0xEC, 0x2B, 0x4D, 0xE4, 0x51, // width
    0x6A, 0x00, 0x6A, 0x00, // y, x
    0x68, 0x00, 0x00, 0x00, 0x10, // WS_VISIBLE
    0x8B, 0x15, 0xE8, 0x2F, 0x1A, 0x01, 0x52, // title
    0xA1, 0xE8, 0x2F, 0x1A, 0x01, 0x50, // class
    0x6A, 0x00, // extended style
    0xFF, 0x15, 0xB8, 0xF2, 0xFD, 0x00, // call [CreateWindowExA IAT]
];

const BOOTSTRAP_CREATE_CONTRACT: ByteContract = ByteContract {
    start: 0x0086AF12,
    call_offset: 0x30,
    expected: BOOTSTRAP_CREATE_BYTES,
};

// 0x004DA8FE..0x004DA957: windowed parent placement only.
const WINDOWED_PARENT_PLACEMENT_BYTES: &[u8] = &[
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
        site: TransitionSite::WindowedParentPlacement,
        start: 0x004DA8FE,
        call_offset: 0x53,
        expected: WINDOWED_PARENT_PLACEMENT_BYTES,
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

const INT_SETTING_ACCESSOR_BYTES: &[u8] = &[
    0x55, 0x8B, 0xEC, 0x51, 0x89, 0x4D, 0xFC, 0x8B, 0x4D, 0xFC, 0xE8, 0xD1, 0xD0, 0xFE, 0xFF, 0x8B,
    0x00, 0x8B, 0xE5, 0x5D, 0xC3,
];

const _: () = {
    assert!(BOOTSTRAP_CREATE_BYTES.len() == 0x36);
    assert!(WINDOWED_PARENT_PLACEMENT_BYTES.len() == 0x59);
    assert!(DEVICE_RESET_BYTES.len() == 0x3E);
    assert!(CHILD_RESIZE_BYTES.len() == 0x2E);
    assert!(FOCUS_REGAIN_BYTES.len() == 0x36);
    assert!(FOCUS_LOSS_BYTES.len() == 0x36);
    assert!(RENDERER_LIFECYCLE_BYTES.len() == 0x29);
    assert!(FULLSCREEN_PREDICATE_BYTES.len() == 0x11);
    assert!(INT_SETTING_ACCESSOR_BYTES.len() == 0x15);

    assert!(BOOTSTRAP_CREATE_CONTRACT.call_offset + 6 == BOOTSTRAP_CREATE_BYTES.len());
    assert!(CALLSITE_CONTRACTS[0].call_offset + 6 == WINDOWED_PARENT_PLACEMENT_BYTES.len());
    assert!(CALLSITE_CONTRACTS[1].call_offset + 6 == DEVICE_RESET_BYTES.len());
    assert!(CALLSITE_CONTRACTS[2].call_offset + 6 == CHILD_RESIZE_BYTES.len());
    assert!(CALLSITE_CONTRACTS[3].call_offset + 6 == FOCUS_REGAIN_BYTES.len());
    assert!(CALLSITE_CONTRACTS[4].call_offset + 6 == FOCUS_LOSS_BYTES.len());
    assert!(CALLSITE_CONTRACTS[5].call_offset + 6 == RENDERER_LIFECYCLE_BYTES.len());
};

static INSTALLED: AtomicBool = AtomicBool::new(false);
static PREDECESSOR: AtomicUsize = AtomicUsize::new(0);
static PREDECESSOR_VANILLA: AtomicBool = AtomicBool::new(false);
static CREATE_WINDOW_INSTALLED: AtomicBool = AtomicBool::new(false);
static FULLSCREEN_REPAIR_ENABLED: AtomicBool = AtomicBool::new(false);
static WINDOWED_PLACEMENT_ENABLED: AtomicBool = AtomicBool::new(false);
static BORDERLESS_WINDOWED_ENABLED: AtomicBool = AtomicBool::new(false);
static CREATE_WINDOW_PREDECESSOR: AtomicUsize = AtomicUsize::new(0);
static CREATE_WINDOW_PREDECESSOR_VANILLA: AtomicBool = AtomicBool::new(false);
static BOOTSTRAP_CREATE_COVERAGE: AtomicU8 = AtomicU8::new(CallsiteCoverage::Unknown as u8);
static CALLSITE_COVERAGE: [AtomicU8; 6] =
    [const { AtomicU8::new(CallsiteCoverage::Unknown as u8) }; 6];
static FULLSCREEN_PREDICATE_VALID: AtomicBool = AtomicBool::new(false);
static INT_SETTING_ACCESSOR_VALID: AtomicBool = AtomicBool::new(false);

static BOOTSTRAP_CREATE_OBSERVATIONS: AtomicU32 = AtomicU32::new(0);
static BOOTSTRAP_CREATE_CORRECTIONS: AtomicU32 = AtomicU32::new(0);
static BOOTSTRAP_WINDOWED_CORRECTIONS: AtomicU32 = AtomicU32::new(0);
static BOOTSTRAP_CREATE_FAILURES: AtomicU32 = AtomicU32::new(0);
static WINDOWED_PARENT_OBSERVATIONS: AtomicU32 = AtomicU32::new(0);
static WINDOWED_PARENT_CORRECTIONS: AtomicU32 = AtomicU32::new(0);
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

/// Point-in-time counters and ownership state for support diagnostics.
///
/// All counters are monotonic for the process lifetime. The snapshot performs
/// only atomic reads and never calls Win32 or takes a lock.
#[derive(Clone, Copy)]
pub(crate) struct DiagnosticSnapshot {
    /// Whether Psycho owns the `SetWindowPos` IAT boundary.
    pub installed: bool,
    /// Captured predecessor address for `SetWindowPos`.
    pub predecessor: usize,
    /// Whether the `SetWindowPos` predecessor is the vanilla user32 export.
    pub predecessor_vanilla: bool,
    /// Whether Psycho owns the `CreateWindowExA` IAT boundary.
    pub create_window_installed: bool,
    /// Whether borderless style is requested for the windowed renderer branch.
    pub borderless_windowed_enabled: bool,
    /// Captured predecessor address for `CreateWindowExA`.
    pub create_window_predecessor: usize,
    /// Whether the creation predecessor is the vanilla user32 export.
    pub create_window_predecessor_vanilla: bool,
    /// Audit state of the visible bootstrap creation caller.
    pub bootstrap_create_state: CallsiteCoverage,
    /// Audit states of the six placement callers in `TransitionSite::ALL` order.
    pub site_states: [CallsiteCoverage; 6],
    /// Number of audited bootstrap requests observed.
    pub bootstrap_create_observations: u32,
    /// Number of fullscreen and windowed bootstrap requests corrected.
    pub bootstrap_create_corrections: u32,
    /// Corrected bootstrap requests belonging to the windowed branch.
    pub bootstrap_windowed_corrections: u32,
    /// Corrected bootstrap requests whose predecessor returned NULL.
    pub bootstrap_create_failures: u32,
    /// Number of audited windowed parent placement requests observed.
    pub windowed_parent_observations: u32,
    /// Windowed parent requests whose origin was preserved or centered.
    pub windowed_parent_corrections: u32,
    /// Number of audited device-reset placement requests observed.
    pub device_reset_observations: u32,
    /// Device-reset requests aligned to a monitor client origin.
    pub device_reset_corrections: u32,
    /// Number of audited renderer-child resizes chained unchanged.
    pub child_resize_passthroughs: u32,
    /// Fullscreen focus-loss placement requests safely suppressed.
    pub loss_suppressions: u32,
    /// Fullscreen focus-regain rectangles normalized.
    pub regain_normalizations: u32,
    /// Fullscreen lifecycle rectangles normalized.
    pub lifecycle_normalizations: u32,
    /// Runtime requests rejected by an audited argument contract.
    pub contract_mismatches: u32,
    /// Create or placement predecessor calls that failed.
    pub predecessor_failures: u32,
    /// Monitor selections made from requested screen points.
    pub monitor_point_selections: u32,
    /// Monitor selections made from live windows.
    pub monitor_window_selections: u32,
    /// Monitor lookups or alignments that required a fallback.
    pub monitor_fallbacks: u32,
    /// Iconic windows for which `SW_RESTORE` was requested.
    pub restore_attempts: u32,
    /// Late-install position catch-up calls attempted.
    pub catch_up_attempts: u32,
    /// Late-install position catch-up calls accepted by the predecessor.
    pub catch_up_successes: u32,
    /// Late-install position catch-up calls rejected by the predecessor.
    pub catch_up_failures: u32,
    /// Tick count recorded for the last corrected transition.
    pub last_transition_ms: u32,
    /// Whether the last corrected transition succeeded.
    pub last_result: bool,
    /// Preserved Win32 error from the last failed corrected transition.
    pub last_error: u32,
}

/// Capture display ownership and transition counters without mutating state.
pub(crate) fn diagnostic_snapshot() -> DiagnosticSnapshot {
    DiagnosticSnapshot {
        installed: INSTALLED.load(Ordering::Acquire),
        predecessor: PREDECESSOR.load(Ordering::Acquire),
        predecessor_vanilla: PREDECESSOR_VANILLA.load(Ordering::Acquire),
        create_window_installed: CREATE_WINDOW_INSTALLED.load(Ordering::Acquire),
        borderless_windowed_enabled: BORDERLESS_WINDOWED_ENABLED.load(Ordering::Acquire),
        create_window_predecessor: CREATE_WINDOW_PREDECESSOR.load(Ordering::Acquire),
        create_window_predecessor_vanilla: CREATE_WINDOW_PREDECESSOR_VANILLA
            .load(Ordering::Acquire),
        bootstrap_create_state: CallsiteCoverage::from_raw(
            BOOTSTRAP_CREATE_COVERAGE.load(Ordering::Acquire),
        ),
        site_states: TransitionSite::ALL.map(callsite_coverage),
        bootstrap_create_observations: BOOTSTRAP_CREATE_OBSERVATIONS.load(Ordering::Relaxed),
        bootstrap_create_corrections: BOOTSTRAP_CREATE_CORRECTIONS.load(Ordering::Relaxed),
        bootstrap_windowed_corrections: BOOTSTRAP_WINDOWED_CORRECTIONS.load(Ordering::Relaxed),
        bootstrap_create_failures: BOOTSTRAP_CREATE_FAILURES.load(Ordering::Relaxed),
        windowed_parent_observations: WINDOWED_PARENT_OBSERVATIONS.load(Ordering::Relaxed),
        windowed_parent_corrections: WINDOWED_PARENT_CORRECTIONS.load(Ordering::Relaxed),
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

/// Return the stable diagnostic label for a callsite audit state.
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

#[derive(Clone, Copy)]
struct BootstrapGeometry {
    x: i32,
    y: i32,
    width: i32,
    height: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BootstrapMode {
    NativeFullscreen,
    FramedWindowed,
    BorderlessWindowed,
}

impl BootstrapMode {
    const fn name(self) -> &'static str {
        match self {
            Self::NativeFullscreen => "native-fullscreen",
            Self::FramedWindowed => "framed-windowed",
            Self::BorderlessWindowed => "borderless-windowed",
        }
    }
}

const fn select_bootstrap_mode(
    engine_fullscreen: bool,
    fullscreen_repair: bool,
    windowed_placement: bool,
    borderless_windowed: bool,
) -> Option<BootstrapMode> {
    if engine_fullscreen {
        return if fullscreen_repair {
            Some(BootstrapMode::NativeFullscreen)
        } else {
            None
        };
    }
    if !windowed_placement {
        return None;
    }
    if borderless_windowed {
        Some(BootstrapMode::BorderlessWindowed)
    } else {
        Some(BootstrapMode::FramedWindowed)
    }
}

const fn windowed_bootstrap_style(original: u32, borderless: bool) -> u32 {
    if borderless {
        FULLSCREEN_BOOTSTRAP_STYLE
    } else {
        original
    }
}

#[derive(Clone, Copy)]
struct CreateWindowRequest {
    extended_style: u32,
    class_name: *const c_char,
    window_name: *const c_char,
    style: u32,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    parent: *mut c_void,
    menu: *mut c_void,
    instance: *mut c_void,
    param: *mut c_void,
}

impl CreateWindowRequest {
    fn as_fullscreen_bootstrap(self, width: i32, height: i32) -> Self {
        Self {
            style: FULLSCREEN_BOOTSTRAP_STYLE,
            width,
            height,
            ..self
        }
    }

    fn as_windowed_bootstrap(self, style: u32, x: i32, y: i32, width: i32, height: i32) -> Self {
        Self {
            style,
            x,
            y,
            width,
            height,
            ..self
        }
    }
}

/// ABI bridge for FalloutNV.exe's imported `CreateWindowExA`.
///
/// The twelve stdcall arguments remain on the original stack. The bridge puts
/// the caller return address in fastcall `ecx` and the Rust body retains the
/// required 48-byte stdcall cleanup.
#[unsafe(naked)]
unsafe extern "system" fn create_window_ex_a_entry(
    _extended_style: u32,
    _class_name: *const c_char,
    _window_name: *const c_char,
    _style: u32,
    _x: i32,
    _y: i32,
    _width: i32,
    _height: i32,
    _parent: *mut c_void,
    _menu: *mut c_void,
    _instance: *mut c_void,
    _param: *mut c_void,
) -> *mut c_void {
    core::arch::naked_asm!(
        "mov ecx, [esp]",
        "xor edx, edx",
        "jmp {}",
        sym checked_create_window_ex_a,
    );
}

unsafe extern "fastcall" fn checked_create_window_ex_a(
    caller: usize,
    _reserved: usize,
    extended_style: u32,
    class_name: *const c_char,
    window_name: *const c_char,
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
    let request = CreateWindowRequest {
        extended_style,
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
    };

    if !CREATE_WINDOW_INSTALLED.load(Ordering::Acquire)
        || caller != 0x0086AF48
        || CallsiteCoverage::from_raw(BOOTSTRAP_CREATE_COVERAGE.load(Ordering::Acquire))
            != CallsiteCoverage::Covered
    {
        return unsafe { call_create_window_predecessor(request) };
    }

    BOOTSTRAP_CREATE_OBSERVATIONS.fetch_add(1, Ordering::Relaxed);
    if !valid_bootstrap_create_request(request) {
        record_bootstrap_contract_mismatch(caller, request);
        return unsafe { call_create_window_predecessor(request) };
    }

    // The pure selector checks the engine setting first. This is the critical
    // mode boundary: borderless-windowed must never turn an explicit
    // `bFull Screen=1` request into the child-window renderer path.
    let Some(mode) = select_bootstrap_mode(
        engine_requests_fullscreen(),
        FULLSCREEN_REPAIR_ENABLED.load(Ordering::Acquire),
        WINDOWED_PLACEMENT_ENABLED.load(Ordering::Acquire),
        BORDERLESS_WINDOWED_ENABLED.load(Ordering::Acquire),
    ) else {
        return unsafe { call_create_window_predecessor(request) };
    };
    let corrected = match mode {
        BootstrapMode::NativeFullscreen => {
            let Some((width, height)) = bootstrap_size() else {
                record_bootstrap_contract_mismatch(caller, request);
                return unsafe { call_create_window_predecessor(request) };
            };
            request.as_fullscreen_bootstrap(width, height)
        }
        BootstrapMode::FramedWindowed | BootstrapMode::BorderlessWindowed => {
            if !CREATE_WINDOW_PREDECESSOR_VANILLA.load(Ordering::Acquire) {
                return unsafe { call_create_window_predecessor(request) };
            }
            let Some(corrected) =
                windowed_bootstrap_request(request, mode == BootstrapMode::BorderlessWindowed)
            else {
                record_bootstrap_contract_mismatch(caller, request);
                return unsafe { call_create_window_predecessor(request) };
            };
            BOOTSTRAP_WINDOWED_CORRECTIONS.fetch_add(1, Ordering::Relaxed);
            corrected
        }
    };

    let count = BOOTSTRAP_CREATE_CORRECTIONS.fetch_add(1, Ordering::Relaxed) + 1;
    let hwnd = unsafe { call_create_window_predecessor(corrected) };
    record_bootstrap_create_result(count, mode, hwnd, corrected);
    hwnd
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
    if !FULLSCREEN_REPAIR_ENABLED.load(Ordering::Acquire)
        && matches!(
            site,
            TransitionSite::DeviceReset
                | TransitionSite::FocusRegain
                | TransitionSite::FocusLoss
                | TransitionSite::RendererLifecycle
        )
    {
        return unsafe { call_predecessor(request) };
    }

    match site {
        TransitionSite::WindowedParentPlacement => {
            WINDOWED_PARENT_OBSERVATIONS.fetch_add(1, Ordering::Relaxed);
            if !WINDOWED_PLACEMENT_ENABLED.load(Ordering::Acquire)
                || engine_requests_fullscreen()
                || !PREDECESSOR_VANILLA.load(Ordering::Acquire)
            {
                return unsafe { call_predecessor(request) };
            }
            let Some(mut corrected) =
                stable_windowed_parent_request(request, window_rect(request.hwnd))
            else {
                record_contract_mismatch(site, caller, request);
                return unsafe { call_predecessor(request) };
            };

            // Missing iLocation settings resolve to (0,0). The bootstrap is
            // already centered in the normal path, but this fallback also
            // covers a late hook install or a failed bootstrap correction.
            if request.x == 0
                && request.y == 0
                && corrected.x == 0
                && corrected.y == 0
                && let Some(centered) = center_window_request(corrected)
            {
                corrected = centered;
            }
            if corrected.x == request.x && corrected.y == request.y {
                return unsafe { call_predecessor(request) };
            }

            let count = WINDOWED_PARENT_CORRECTIONS.fetch_add(1, Ordering::Relaxed) + 1;
            unsafe { execute_corrected_request(site, count, corrected) }
        }
        TransitionSite::DeviceReset => unsafe {
            handle_valid_fullscreen_position(site, request, &DEVICE_RESET_OBSERVATIONS)
        },
        TransitionSite::ChildResize => {
            CHILD_RESIZE_PASSTHROUGHS.fetch_add(1, Ordering::Relaxed);
            unsafe { call_predecessor(request) }
        }
        TransitionSite::FocusLoss => {
            if !uses_fullscreen_window_policy(request.hwnd) {
                return unsafe { call_predecessor(request) };
            }
            if decode_malformed_geometry(request).is_none() {
                record_contract_mismatch(site, caller, request);
                return unsafe { call_predecessor(request) };
            }
            suppress_focus_loss()
        }
        TransitionSite::FocusRegain => {
            if !uses_fullscreen_window_policy(request.hwnd) {
                return unsafe { call_predecessor(request) };
            }
            let Some(geometry) = decode_malformed_geometry(request) else {
                record_contract_mismatch(site, caller, request);
                return unsafe { call_predecessor(request) };
            };
            restore_if_iconic(request.hwnd);
            let count = REGAIN_NORMALIZATIONS.fetch_add(1, Ordering::Relaxed) + 1;
            unsafe { execute_corrected_request(site, count, request.corrected_malformed(geometry)) }
        }
        TransitionSite::RendererLifecycle => {
            if !uses_fullscreen_window_policy(request.hwnd) {
                return unsafe { call_predecessor(request) };
            }
            let Some(geometry) = decode_malformed_geometry(request) else {
                record_contract_mismatch(site, caller, request);
                return unsafe { call_predecessor(request) };
            };
            let count = LIFECYCLE_NORMALIZATIONS.fetch_add(1, Ordering::Relaxed) + 1;
            unsafe { execute_corrected_request(site, count, request.corrected_malformed(geometry)) }
        }
    }
}

fn valid_bootstrap_create_request(request: CreateWindowRequest) -> bool {
    request.extended_style == 0
        && request.style == WS_VISIBLE
        && request.x == 0
        && request.y == 0
        && request.width == VANILLA_BOOTSTRAP_WIDTH
        && request.height == VANILLA_BOOTSTRAP_HEIGHT
        && request.class_name == request.window_name
        && !request.class_name.is_null()
        && request.parent.is_null()
        && request.menu.is_null()
        && !request.instance.is_null()
        && request.param.is_null()
}

fn bootstrap_size() -> Option<(i32, i32)> {
    if !INT_SETTING_ACCESSOR_VALID.load(Ordering::Acquire) {
        return None;
    }

    let width = read_int_setting(SIZE_WIDTH_SETTING)?;
    let height = read_int_setting(SIZE_HEIGHT_SETTING)?;
    if width <= 0 || width > MAX_WINDOW_EXTENT || height <= 0 || height > MAX_WINDOW_EXTENT {
        return None;
    }

    Some((width, height))
}

fn windowed_bootstrap_geometry() -> Option<BootstrapGeometry> {
    let (width, height) = bootstrap_size()?;
    let x = read_int_setting(LOCATION_X_SETTING)?;
    let y = read_int_setting(LOCATION_Y_SETTING)?;
    if !(-MAX_WINDOW_EXTENT..=MAX_WINDOW_EXTENT).contains(&x)
        || !(-MAX_WINDOW_EXTENT..=MAX_WINDOW_EXTENT).contains(&y)
    {
        return None;
    }

    Some(BootstrapGeometry {
        x,
        y,
        width,
        height,
    })
}

fn windowed_bootstrap_request(
    request: CreateWindowRequest,
    borderless: bool,
) -> Option<CreateWindowRequest> {
    let geometry = windowed_bootstrap_geometry()?;
    let style = windowed_bootstrap_style(request.style, borderless);

    // The renderer creates an exact client-sized child. Compute the top-level
    // outer extent now with the same style the later renderer path will query,
    // preventing a second visible resize when the child is published.
    let mut outer = Rect {
        left: 0,
        top: 0,
        right: geometry.width,
        bottom: geometry.height,
    };
    if !adjust_window_rect_ex(&mut outer, style, false, request.extended_style) {
        return None;
    }
    let width = outer.right.checked_sub(outer.left)?;
    let height = outer.bottom.checked_sub(outer.top)?;
    if width <= 0 || width > MAX_WINDOW_EXTENT || height <= 0 || height > MAX_WINDOW_EXTENT {
        return None;
    }

    let (x, y) = if geometry.x == 0 && geometry.y == 0 {
        let monitor = nearest_monitor_rect_from_point(0, 0);
        if monitor.is_some() {
            MONITOR_POINT_SELECTIONS.fetch_add(1, Ordering::Relaxed);
        } else {
            MONITOR_FALLBACKS.fetch_add(1, Ordering::Relaxed);
        }
        monitor
            .and_then(|monitor| centered_window_origin(monitor, width, height))
            .unwrap_or((geometry.x, geometry.y))
    } else {
        (geometry.x, geometry.y)
    };

    Some(request.as_windowed_bootstrap(style, x, y, width, height))
}

fn centered_window_origin(monitor: Rect, width: i32, height: i32) -> Option<(i32, i32)> {
    if width <= 0 || height <= 0 {
        return None;
    }
    let monitor_width = monitor.right.checked_sub(monitor.left)?;
    let monitor_height = monitor.bottom.checked_sub(monitor.top)?;
    if monitor_width <= 0 || monitor_height <= 0 {
        return None;
    }

    // Oversized windows stay anchored to the monitor origin so their caption
    // cannot be centered off-screen and become unreachable.
    let x_offset = monitor_width.checked_sub(width)?.max(0) / 2;
    let y_offset = monitor_height.checked_sub(height)?.max(0) / 2;
    Some((
        monitor.left.checked_add(x_offset)?,
        monitor.top.checked_add(y_offset)?,
    ))
}

fn stable_windowed_parent_request(
    request: WindowRequest,
    live: Option<Rect>,
) -> Option<WindowRequest> {
    if !valid_position_request(request) {
        return None;
    }
    let live = live?;
    let live_width = live.right.checked_sub(live.left)?;
    let live_height = live.bottom.checked_sub(live.top)?;
    if live_width <= 0 || live_height <= 0 {
        return None;
    }

    // A nonzero engine origin wins only while the live parent still has the
    // exact hard-coded bootstrap geometry. Once final sizing has happened,
    // even a live (0,0) origin may be a deliberate user move and must survive
    // renderer recreation.
    if live.left == 0
        && live.top == 0
        && live_width == VANILLA_BOOTSTRAP_WIDTH
        && live_height == VANILLA_BOOTSTRAP_HEIGHT
        && (request.x != 0 || request.y != 0)
    {
        Some(request)
    } else {
        Some(request.with_position(live.left, live.top))
    }
}

fn center_window_request(request: WindowRequest) -> Option<WindowRequest> {
    let monitor = nearest_monitor_rect_from_point(request.x, request.y)?;
    MONITOR_POINT_SELECTIONS.fetch_add(1, Ordering::Relaxed);
    let (x, y) = centered_window_origin(monitor, request.width, request.height)?;
    Some(request.with_position(x, y))
}

fn read_int_setting(setting: usize) -> Option<i32> {
    if !is_readable(setting, std::mem::size_of::<usize>()) {
        return None;
    }
    let accessor =
        unsafe { FnPtr::<IntSettingFn>::from_address_unchecked(INT_SETTING_ACCESSOR) }.as_fn();
    Some(unsafe { accessor(setting) })
}

fn record_bootstrap_contract_mismatch(caller: usize, request: CreateWindowRequest) {
    let count = CONTRACT_MISMATCHES.fetch_add(1, Ordering::Relaxed) + 1;
    if should_log(count) {
        log::warn!(
            "[DISPLAY] bootstrap-create contract mismatch #{} at 0x{:08X}: ({},{} {}x{}) style={:#x} ex={:#x}; chained unchanged",
            count,
            caller,
            request.x,
            request.y,
            request.width,
            request.height,
            request.style,
            request.extended_style,
        );
    }
}

fn record_bootstrap_create_result(
    count: u32,
    mode: BootstrapMode,
    hwnd: *mut c_void,
    request: CreateWindowRequest,
) {
    let error = if hwnd.is_null() {
        BOOTSTRAP_CREATE_FAILURES.fetch_add(1, Ordering::Relaxed);
        get_last_error_code()
    } else {
        0
    };
    LAST_TRANSITION_MS.store(get_tick_count(), Ordering::Release);
    LAST_RESULT.store(!hwnd.is_null(), Ordering::Release);
    LAST_ERROR.store(error, Ordering::Release);

    if hwnd.is_null() {
        log::warn!(
            "[DISPLAY] corrected {} bootstrap CreateWindowExA #{} failed: error={} rect=({},{} {}x{})",
            mode.name(),
            count,
            error,
            request.x,
            request.y,
            request.width,
            request.height,
        );
        set_last_error(error);
    } else {
        log::info!(
            "[DISPLAY] corrected {} bootstrap window #{}: rect=({},{} {}x{}) style={:#x}",
            mode.name(),
            count,
            request.x,
            request.y,
            request.width,
            request.height,
            request.style,
        );
    }
}

unsafe fn handle_valid_fullscreen_position(
    site: TransitionSite,
    request: WindowRequest,
    observations: &AtomicU32,
) -> i32 {
    observations.fetch_add(1, Ordering::Relaxed);
    if !uses_fullscreen_window_policy(request.hwnd) {
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
        TransitionSite::WindowedParentPlacement => 0x004DA957,
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

fn engine_requests_fullscreen() -> bool {
    if !FULLSCREEN_PREDICATE_VALID.load(Ordering::Acquire) {
        return false;
    }
    let predicate =
        unsafe { FnPtr::<IsFullscreenFn>::from_address_unchecked(FULLSCREEN_PREDICATE) }.as_fn();
    unsafe { predicate() != 0 }
}

fn uses_fullscreen_window_policy(hwnd: *mut c_void) -> bool {
    engine_requests_fullscreen() || is_borderless_fullscreen(hwnd)
}

fn is_borderless_fullscreen(hwnd: *mut c_void) -> bool {
    if !is_window(hwnd) {
        return false;
    }

    let style = get_window_long_a(hwnd, GWL_STYLE) as u32;
    if style & WS_CHILD != 0 || style & (WS_CAPTION | WS_THICKFRAME) != 0 {
        return false;
    }

    let Some(window) = window_rect(hwnd) else {
        return false;
    };
    let Some(monitor) = nearest_monitor_rect(hwnd) else {
        return false;
    };
    window.left == monitor.left
        && window.top == monitor.top
        && window.right == monitor.right
        && window.bottom == monitor.bottom
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
    let parent_slot = TOP_LEVEL_HWND_GLOBAL as *mut *mut c_void;
    let child_slot = RENDERER_CHILD_HWND_GLOBAL as *mut *mut c_void;
    let Some(hwnd) = load_pointer(parent_slot)
        .ok()
        .filter(|hwnd| is_window(*hwnd))
    else {
        return;
    };
    if !uses_fullscreen_window_policy(hwnd) {
        return;
    }
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

unsafe fn call_create_window_predecessor(request: CreateWindowRequest) -> *mut c_void {
    let target = CREATE_WINDOW_PREDECESSOR.load(Ordering::Acquire);
    if target == 0 || target == create_window_ex_a_entry as *const () as usize {
        PREDECESSOR_FAILURES.fetch_add(1, Ordering::Relaxed);
        LAST_ERROR.store(0, Ordering::Release);
        return std::ptr::null_mut();
    }

    let Ok(predecessor) = (unsafe { FnPtr::<CreateWindowExAFn>::from_raw(target as *mut c_void) })
    else {
        PREDECESSOR_FAILURES.fetch_add(1, Ordering::Relaxed);
        LAST_ERROR.store(0, Ordering::Release);
        return std::ptr::null_mut();
    };
    let predecessor = predecessor.as_fn();
    unsafe {
        predecessor(
            request.extended_style,
            request.class_name,
            request.window_name,
            request.style,
            request.x,
            request.y,
            request.width,
            request.height,
            request.parent,
            request.menu,
            request.instance,
            request.param,
        )
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
    let Ok(predecessor) = (unsafe { FnPtr::<SetWindowPosFn>::from_raw(target as *mut c_void) })
    else {
        PREDECESSOR_FAILURES.fetch_add(1, Ordering::Relaxed);
        LAST_ERROR.store(0, Ordering::Release);
        return 0;
    };
    let predecessor = predecessor.as_fn();
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

/// Install the audited display IAT shims for the requested runtime policies.
///
/// `fullscreen_repair` controls only the native-fullscreen startup and
/// transition repairs. `borderless_windowed` controls only the renderer branch
/// selected by `bFull Screen=0`; it cannot override an explicit fullscreen
/// request.
///
/// Installation verifies every executable fingerprint and atomically chains
/// existing IAT owners. It returns an error only when neither requested policy
/// has a safe boundary to install.
pub fn install_display_hooks(
    fullscreen_repair: bool,
    borderless_windowed: bool,
) -> anyhow::Result<()> {
    FULLSCREEN_REPAIR_ENABLED.store(fullscreen_repair, Ordering::Release);
    WINDOWED_PLACEMENT_ENABLED.store(fullscreen_repair || borderless_windowed, Ordering::Release);
    BORDERLESS_WINDOWED_ENABLED.store(borderless_windowed, Ordering::Release);

    let coverage = audit_callsites();
    let bootstrap_coverage = audit_bootstrap_create_callsite();
    audit_fullscreen_predicate();
    audit_int_setting_accessor();

    let mut installed_any = false;
    let create_owner = if bootstrap_coverage == CallsiteCoverage::Covered
        && FULLSCREEN_PREDICATE_VALID.load(Ordering::Acquire)
        && INT_SETTING_ACCESSOR_VALID.load(Ordering::Acquire)
    {
        match claim_create_window_iat() {
            Ok(owner) => {
                CREATE_WINDOW_INSTALLED.store(true, Ordering::Release);
                installed_any = true;
                Some(owner)
            }
            Err(error) => {
                log::warn!("[DISPLAY] bootstrap window correction unavailable: {error}");
                None
            }
        }
    } else {
        None
    };

    let corrective_set_window_site = (fullscreen_repair
        && [1, 3, 4, 5]
            .into_iter()
            .any(|index| coverage[index] == CallsiteCoverage::Covered))
        || (WINDOWED_PLACEMENT_ENABLED.load(Ordering::Acquire)
            && coverage[TransitionSite::WindowedParentPlacement.index()]
                == CallsiteCoverage::Covered);
    let set_window_owner = if corrective_set_window_site {
        match claim_set_window_pos_iat() {
            Ok(owner) => {
                INSTALLED.store(true, Ordering::Release);
                installed_any = true;
                Some(owner)
            }
            Err(error) => {
                log::warn!("[DISPLAY] transition correction unavailable: {error}");
                None
            }
        }
    } else {
        None
    };

    ensure!(
        installed_any,
        "no audited display IAT boundary is available"
    );

    if fullscreen_repair && set_window_owner.is_some() {
        catch_up_existing_window();
    }

    if borderless_windowed && create_owner.is_some_and(|owner| !owner.is_vanilla) {
        log::warn!(
            "[DISPLAY] borderless-windowed style deferred to the existing CreateWindowExA owner"
        );
    }

    log::info!(
        "[DISPLAY] Window management installed: fullscreen={} borderless_windowed={} create={} setpos={} bootstrap={} sites={}/{}/{}/{}/{}/{}",
        fullscreen_repair,
        borderless_windowed,
        iat_owner_name(create_owner),
        iat_owner_name(set_window_owner),
        bootstrap_coverage.name(),
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

fn iat_owner_name(owner: Option<IatOwner>) -> String {
    match owner {
        Some(owner) => format!(
            "0x{:08X}:{}",
            owner.address,
            if owner.is_vanilla {
                "vanilla"
            } else {
                "external"
            }
        ),
        None => "off".to_owned(),
    }
}

fn claim_create_window_iat() -> anyhow::Result<IatOwner> {
    claim_iat_pointer(
        "CreateWindowExA",
        CREATE_WINDOW_EX_A_IAT,
        create_window_ex_a_entry as *const () as *mut c_void,
        &CREATE_WINDOW_PREDECESSOR,
        &CREATE_WINDOW_PREDECESSOR_VANILLA,
        vanilla_user32_proc("CreateWindowExA"),
    )
}

fn claim_set_window_pos_iat() -> anyhow::Result<IatOwner> {
    claim_iat_pointer(
        "SetWindowPos",
        SET_WINDOW_POS_IAT,
        set_window_pos_entry as *const () as *mut c_void,
        &PREDECESSOR,
        &PREDECESSOR_VANILLA,
        vanilla_user32_proc("SetWindowPos"),
    )
}

fn claim_iat_pointer(
    name: &str,
    slot_address: usize,
    shim: *mut c_void,
    predecessor: &AtomicUsize,
    predecessor_vanilla: &AtomicBool,
    vanilla_target: Option<*mut c_void>,
) -> anyhow::Result<IatOwner> {
    ensure!(
        is_readable(slot_address, std::mem::size_of::<*mut c_void>()),
        "{name} IAT slot 0x{slot_address:08X} is unreadable"
    );
    ensure!(
        slot_address.is_multiple_of(std::mem::align_of::<*mut c_void>()),
        "{name} IAT slot is misaligned"
    );

    let slot = slot_address as *mut *mut c_void;
    let current = load_pointer(slot).with_context(|| format!("read {name} IAT slot"))?;

    if current == shim {
        let address = predecessor.load(Ordering::Acquire);
        ensure!(
            address != 0,
            "Psycho owns the {name} IAT slot without a predecessor"
        );
        return Ok(IatOwner {
            address,
            is_vanilla: predecessor_vanilla.load(Ordering::Acquire),
        });
    }

    ensure!(
        is_executable(current as usize),
        "{name} predecessor 0x{:08X} is not executable",
        current as usize
    );

    let owner = IatOwner {
        address: current as usize,
        is_vanilla: vanilla_target == Some(current),
    };

    // Publish before the pointer swap. The shim may run as soon as the atomic
    // exchange succeeds, including through a later hook that captures it.
    predecessor.store(owner.address, Ordering::Release);
    predecessor_vanilla.store(owner.is_vanilla, Ordering::Release);

    let exchange = compare_exchange_pointer(slot, current, shim)
        .with_context(|| format!("replace {name} IAT slot"))?;
    if let PointerExchange::Mismatch(observed) = exchange {
        predecessor.store(0, Ordering::Release);
        predecessor_vanilla.store(false, Ordering::Release);
        anyhow::bail!(
            "{name} IAT ownership changed during install: expected 0x{:08X}, found 0x{:08X}",
            current as usize,
            observed as usize,
        );
    }

    let observed = match load_pointer(slot).with_context(|| format!("read back {name} IAT slot")) {
        Ok(observed) => observed,
        Err(error) => {
            restore_predecessor_if_owned(name, slot, shim, current);
            return Err(error);
        }
    };
    if observed != shim {
        // A later hook may legitimately own the slot and chain Psycho. Do not
        // overwrite it and do not clear PREDECESSOR: our shim must remain a
        // valid pass-through target in that external chain.
        restore_predecessor_if_owned(name, slot, shim, current);
        anyhow::bail!(
            "{name} IAT readback failed: expected 0x{:08X}, found 0x{:08X}",
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

fn audit_bootstrap_create_callsite() -> CallsiteCoverage {
    let state = classify_bytes(
        BOOTSTRAP_CREATE_CONTRACT.start,
        BOOTSTRAP_CREATE_CONTRACT.call_offset,
        BOOTSTRAP_CREATE_CONTRACT.expected,
    );
    BOOTSTRAP_CREATE_COVERAGE.store(state as u8, Ordering::Release);
    match state {
        CallsiteCoverage::Covered => log::info!("[DISPLAY] bootstrap-create callsite covered"),
        CallsiteCoverage::ExternalOwner => log::warn!(
            "[DISPLAY] bootstrap-create callsite has a direct external owner; left untouched"
        ),
        _ => log::warn!("[DISPLAY] bootstrap-create callsite fingerprint conflict; left untouched"),
    }
    state
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
            "[DISPLAY] fullscreen predicate fingerprint conflict; bootstrap/reset policies will pass through"
        );
    }
}

fn audit_int_setting_accessor() {
    let valid = is_readable(INT_SETTING_ACCESSOR, INT_SETTING_ACCESSOR_BYTES.len())
        && unsafe {
            slice::from_raw_parts(
                INT_SETTING_ACCESSOR as *const u8,
                INT_SETTING_ACCESSOR_BYTES.len(),
            )
        } == INT_SETTING_ACCESSOR_BYTES;
    INT_SETTING_ACCESSOR_VALID.store(valid, Ordering::Release);
    if !valid {
        log::warn!(
            "[DISPLAY] integer setting accessor fingerprint conflict; bootstrap correction will pass through"
        );
    }
}

fn classify_callsite(contract: &CallsiteContract) -> CallsiteCoverage {
    classify_bytes(contract.start, contract.call_offset, contract.expected)
}

fn classify_bytes(start: usize, call_offset: usize, expected: &[u8]) -> CallsiteCoverage {
    if !is_readable(start, expected.len()) {
        return CallsiteCoverage::Conflict;
    }

    // The fixed executable address and full range were validated above.
    let actual = unsafe { slice::from_raw_parts(start as *const u8, expected.len()) };
    if actual == expected {
        CallsiteCoverage::Covered
    } else if actual.get(call_offset) == Some(&0xE8) {
        CallsiteCoverage::ExternalOwner
    } else {
        CallsiteCoverage::Conflict
    }
}

fn callsite_coverage(site: TransitionSite) -> CallsiteCoverage {
    CallsiteCoverage::from_raw(CALLSITE_COVERAGE[site.index()].load(Ordering::Acquire))
}

fn restore_predecessor_if_owned(
    name: &str,
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
        log::error!("[DISPLAY] failed to restore {name} IAT predecessor");
    }
}

fn vanilla_user32_proc(name: &str) -> Option<*mut c_void> {
    let user32 = get_module_handle_a(Some("user32.dll")).ok()?;
    get_proc_address(user32, name).ok()
}

fn is_readable(address: usize, len: usize) -> bool {
    if address < 0x10000 {
        return false;
    }
    let Ok(info) = virtual_query(address as *mut c_void) else {
        return false;
    };
    if !info.is_accessible() {
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
    info.is_executable()
}

#[cfg(test)]
mod tests {
    use super::{
        BootstrapMode, CreateWindowRequest, Rect, WS_POPUP, WS_VISIBLE, centered_window_origin,
        select_bootstrap_mode, stable_windowed_parent_request, windowed_bootstrap_style,
    };
    use std::ffi::c_void;

    fn request() -> CreateWindowRequest {
        CreateWindowRequest {
            extended_style: 0,
            class_name: std::ptr::dangling::<i8>(),
            window_name: std::ptr::dangling::<i8>(),
            style: WS_VISIBLE,
            x: 0,
            y: 0,
            width: 320,
            height: 240,
            parent: std::ptr::null_mut(),
            menu: std::ptr::null_mut(),
            instance: std::ptr::dangling_mut::<c_void>(),
            param: std::ptr::null_mut(),
        }
    }

    #[test]
    fn unset_windowed_origin_centers_within_the_selected_monitor() {
        let monitor = Rect {
            left: -1920,
            top: 0,
            right: 0,
            bottom: 1080,
        };

        assert_eq!(
            centered_window_origin(monitor, 800, 600),
            Some((-1360, 240))
        );
        assert_eq!(
            centered_window_origin(monitor, 2560, 1440),
            Some((-1920, 0))
        );
    }

    #[test]
    fn borderless_windowed_bootstrap_is_visible_popup_at_final_geometry() {
        let original = request();
        let borderless_style = windowed_bootstrap_style(original.style, true);
        let corrected = original.as_windowed_bootstrap(borderless_style, 560, 240, 800, 600);

        assert_eq!(corrected.style, WS_POPUP | WS_VISIBLE);
        assert_eq!(windowed_bootstrap_style(original.style, false), WS_VISIBLE);
        assert_eq!((corrected.x, corrected.y), (560, 240));
        assert_eq!((corrected.width, corrected.height), (800, 600));
    }

    #[test]
    fn explicit_fullscreen_precedes_borderless_windowed() {
        assert_eq!(
            select_bootstrap_mode(true, true, true, true),
            Some(BootstrapMode::NativeFullscreen)
        );
        assert_eq!(select_bootstrap_mode(true, false, true, true), None);
        assert_eq!(
            select_bootstrap_mode(false, true, true, true),
            Some(BootstrapMode::BorderlessWindowed)
        );
    }

    #[test]
    fn renderer_recreation_preserves_a_manually_moved_parent_origin() {
        let request = super::WindowRequest {
            hwnd: std::ptr::dangling_mut::<c_void>(),
            insert_after: std::ptr::null_mut(),
            x: 0,
            y: 0,
            width: 800,
            height: 600,
            flags: super::SWP_SHOWWINDOW,
        };
        let live = Rect {
            left: 317,
            top: 211,
            right: 1117,
            bottom: 811,
        };

        let corrected =
            stable_windowed_parent_request(request, Some(live)).expect("valid placement");
        assert_eq!((corrected.x, corrected.y), (317, 211));
        assert_eq!((corrected.width, corrected.height), (800, 600));
    }

    #[test]
    fn configured_origin_replaces_only_the_unmodified_vanilla_bootstrap() {
        let request = super::WindowRequest {
            hwnd: std::ptr::dangling_mut::<c_void>(),
            insert_after: std::ptr::null_mut(),
            x: 25,
            y: 40,
            width: 800,
            height: 600,
            flags: super::SWP_SHOWWINDOW,
        };
        let bootstrap = Rect {
            left: 0,
            top: 0,
            right: 320,
            bottom: 240,
        };
        let deliberately_moved = Rect {
            left: 0,
            top: 0,
            right: 800,
            bottom: 600,
        };

        let seeded =
            stable_windowed_parent_request(request, Some(bootstrap)).expect("valid bootstrap");
        assert_eq!((seeded.x, seeded.y), (25, 40));
        let preserved = stable_windowed_parent_request(request, Some(deliberately_moved))
            .expect("valid live window");
        assert_eq!((preserved.x, preserved.y), (0, 0));
    }
}
