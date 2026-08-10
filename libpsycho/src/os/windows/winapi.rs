//! Shared Win32 boundary for Psycho crates.
//!
//! The module exposes stable Rust-facing types and small wrappers so engine
//! features do not scatter raw FFI declarations, handle conversions, or error
//! conventions across the workspace. Wrappers preserve Win32 semantics unless
//! their documentation explicitly adds validation or ownership requirements.
//! Unsafe operations remain marked when Rust cannot validate pointer lifetime,
//! buffer extent, callback validity, or a captured function address.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, NulError, OsStr};
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicPtr, Ordering};

use libc::c_void;
use thiserror::Error;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, FILETIME, GetLastError, HANDLE,
    HMODULE, HWND, INVALID_HANDLE_VALUE, STILL_ACTIVE, SetLastError, WIN32_ERROR,
};
use windows::Win32::Storage::FileSystem::{
    CopyFileA, CreateFileA, DeleteFileA, FILE_ATTRIBUTE_NORMAL, FILE_BEGIN, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_SHARE_READ, FlushFileBuffers, GetFileAttributesA, GetFileSizeEx,
    INVALID_FILE_ATTRIBUTES, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExA,
    MoveFileExW, OPEN_EXISTING, ReadFile, SetFilePointerEx,
};
use windows::Win32::System::Console::{
    AllocConsole, CONSOLE_MODE, ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetStdHandle,
    STD_OUTPUT_HANDLE, SetConsoleMode,
};
use windows::Win32::System::LibraryLoader::{
    DisableThreadLibraryCalls, GetModuleFileNameW, GetModuleHandleA, GetModuleHandleW,
    GetProcAddress, LoadLibraryA, LoadLibraryW,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RELEASE, MEM_RESERVE,
    MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    PAGE_WRITECOPY, VIRTUAL_ALLOCATION_TYPE, VIRTUAL_FREE_TYPE, VirtualAlloc, VirtualFree,
    VirtualProtect,
};
use windows::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
use windows::Win32::System::ProcessStatus::{
    EnumProcessModules, GetModuleBaseNameA, GetModuleInformation, MODULEINFO,
};
use windows::Win32::System::SystemInformation::{
    CACHE_RELATIONSHIP, CacheData, CacheInstruction, CacheTrace, CacheUnified,
    FIRMWARE_TABLE_PROVIDER, GROUP_AFFINITY, GetLogicalProcessorInformationEx, GetNativeSystemInfo,
    GetPhysicallyInstalledSystemMemory, GetSystemDirectoryW, GetSystemFirmwareTable,
    GetSystemTimeAsFileTime, GetTickCount as WinGetTickCount, GlobalMemoryStatusEx, MEMORYSTATUSEX,
    NUMA_NODE_RELATIONSHIP, PROCESSOR_RELATIONSHIP, RelationAll, RelationCache, RelationNumaNode,
    RelationNumaNodeEx, RelationProcessorCore, RelationProcessorPackage, SYSTEM_INFO,
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,
};
use windows::Win32::System::SystemServices::MEM_TOP_DOWN;
use windows::Win32::System::Threading::{
    ALL_PROCESSOR_GROUPS, CRITICAL_SECTION, CreateThread, EnterCriticalSection,
    GetActiveProcessorCount, GetCurrentThread, GetCurrentThreadId as WinGetCurrentThreadId,
    GetExitCodeThread, GetProcessTimes, GetThreadPriority, InitializeCriticalSection,
    LeaveCriticalSection, OpenThread, ReleaseSemaphore as WinReleaseSemaphore, SetThreadPriority,
    Sleep as WinSleep, THREAD_CREATION_FLAGS, THREAD_PRIORITY, THREAD_PRIORITY_ABOVE_NORMAL,
    THREAD_PRIORITY_BELOW_NORMAL, THREAD_PRIORITY_HIGHEST, THREAD_PRIORITY_IDLE,
    THREAD_PRIORITY_LOWEST, THREAD_PRIORITY_MIN, THREAD_PRIORITY_NORMAL,
    THREAD_PRIORITY_TIME_CRITICAL, THREAD_QUERY_LIMITED_INFORMATION,
    WaitForSingleObject as WinWaitForSingleObject,
};
use windows::Win32::System::{
    Diagnostics::Debug::FlushInstructionCache, Memory::VirtualQuery, Threading::GetCurrentProcess,
};
use windows::Win32::UI::WindowsAndMessaging::{
    MB_OK, MESSAGEBOX_RESULT, MESSAGEBOX_STYLE, MessageBoxA,
};
use windows::core::{PCSTR, PCWSTR};

#[derive(Debug, Error)]
pub enum WinapiError {
    #[error("Windows core API error: {0}")]
    WindowsCore(#[from] windows::core::Error),

    #[error("Input PTR is NULL")]
    InputNullPtr(),

    #[error("Proc address is NULL for function: {0}")]
    ProcAddressIsNull(String),

    #[error("Size can't be zero")]
    ZeroSize(),

    #[error("VirtualQuery failed with error code: {0}")]
    VirtualQuery(u32),

    #[error("Interior nul bytes found: {0}")]
    NulError(#[from] NulError),

    #[error(
        "Target address 0x{target_addr:x} is out of range from source 0x{source_addr:x} (distance: {distance}). Relative CALL is limited to +/-2GB on x86_64."
    )]
    CallTargetOutOfRange {
        source_addr: usize,
        target_addr: usize,
        distance: isize,
    },

    #[error("Pointer address 0x{0:x} is not naturally aligned")]
    MisalignedPointer(usize),

    #[error("Windows reported a negative file size: {0}")]
    NegativeFileSize(i64),

    #[error("Windows returned malformed processor topology: {0}")]
    MalformedProcessorTopology(&'static str),

    #[error("Windows firmware table is too large: {0} bytes")]
    FirmwareTableTooLarge(u32),

    #[error("Windows returned malformed firmware data: {0}")]
    MalformedFirmwareTable(&'static str),

    #[error("Windows value overflowed while converting {0}")]
    IntegerOverflow(&'static str),
}

pub type WinapiResult<T> = std::result::Result<T, WinapiError>;

/// Win32-compatible boolean for exported ABI functions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct WinBool(pub i32);

impl From<bool> for WinBool {
    fn from(value: bool) -> Self {
        Self(i32::from(value))
    }
}

impl From<WinBool> for bool {
    fn from(value: WinBool) -> Self {
        value.0 != 0
    }
}

/// Outcome of an atomic pointer comparison that completed without a WinAPI error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PointerExchange {
    /// `expected` was present and was replaced.
    Exchanged,
    /// The pointer had already changed; contains the value that was observed.
    Mismatch(*mut c_void),
}

/// Wrapped WinAPI type MEMORY_BASIC_INFORMATION
pub struct MemoryBasicInformation {
    pub base_address: *mut c_void,
    pub allocation_base: *mut c_void,
    pub allocation_protect: u32,
    //pub partition_id: u16,
    pub region_size: usize,
    pub state: u32,
    pub protect: PAGE_PROTECTION_FLAGS,
    pub r#type: u32,
}

/// Stable memory-state classification independent of the Windows bindings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryState {
    Commit,
    Free,
    Reserve,
    Unknown(u32),
}

/// Stable memory-type classification independent of the Windows bindings.
///
/// Win32 exposes these values only for committed pages. Keeping the raw
/// fallback prevents a newer or emulated value from being silently counted as
/// allocator-private memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryType {
    /// Executable image mapping (`MEM_IMAGE`).
    Image,
    /// Mapped section or file (`MEM_MAPPED`).
    Mapped,
    /// Process-private allocation (`MEM_PRIVATE`).
    Private,
    /// Unrecognized raw Win32 memory-type value.
    Unknown(u32),
}

/// Stable cache classification independent of Windows binding constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessorCacheType {
    /// Cache shared by instructions and data.
    Unified,
    /// Instruction cache.
    Instruction,
    /// Data cache.
    Data,
    /// Trace cache.
    Trace,
    /// Cache type not known to this version of libpsycho.
    Unknown(i32),
}

/// One cache record reported by `GetLogicalProcessorInformationEx`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessorCacheInfo {
    /// Cache hierarchy level, starting at one.
    pub level: u8,
    /// Hardware associativity, or `0xff` for fully associative.
    pub associativity: u8,
    /// Cache-line size in bytes.
    pub line_size: u16,
    /// Cache capacity in bytes.
    pub size: u32,
    /// Logical processors that share this cache.
    pub shared_logical_processor_count: u32,
    /// Cache use classification.
    pub cache_type: ProcessorCacheType,
}

/// Count of physical cores in one Windows efficiency class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessorEfficiencyClass {
    /// Windows efficiency class. Higher values represent faster cores.
    pub class: u8,
    /// Number of physical cores in this class.
    pub core_count: u32,
}

/// Stable processor-topology snapshot produced by Win32.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessorTopology {
    /// Physical core records visible to the operating system.
    pub physical_core_count: u32,
    /// Physical processor-package records visible to the operating system.
    pub package_count: u32,
    /// NUMA node records visible to the operating system.
    pub numa_node_count: u32,
    /// Cache records reported by Windows.
    pub caches: Vec<ProcessorCacheInfo>,
    /// Physical core counts grouped by Windows efficiency class.
    pub efficiency_classes: Vec<ProcessorEfficiencyClass>,
}

/// Native system layout needed by hardware and allocator policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeSystemLayout {
    /// Native operating-system page size in bytes.
    pub page_size: u32,
    /// Native virtual-allocation granularity in bytes.
    pub allocation_granularity: u32,
    /// Active logical processors visible to the operating system.
    pub logical_processor_count: u32,
}

/// Physical and virtual memory values returned by `GlobalMemoryStatusEx`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemMemoryStatus {
    /// Approximate percentage of physical memory currently in use.
    pub memory_load_percent: u32,
    /// Total physical memory in bytes.
    pub total_physical_bytes: u64,
    /// Currently available physical memory in bytes.
    pub available_physical_bytes: u64,
    /// Current system commit limit in bytes.
    pub total_page_file_bytes: u64,
    /// Commit headroom available to the system in bytes.
    pub available_page_file_bytes: u64,
    /// User-mode virtual-address-space size for this process in bytes.
    pub total_virtual_bytes: u64,
    /// User-mode virtual-address-space headroom for this process in bytes.
    pub available_virtual_bytes: u64,
}

impl MemoryBasicInformation {
    pub fn memory_state(&self) -> MemoryState {
        match self.state {
            state if state == MEM_COMMIT.0 => MemoryState::Commit,
            state if state == MEM_FREE.0 => MemoryState::Free,
            state if state == MEM_RESERVE.0 => MemoryState::Reserve,
            state => MemoryState::Unknown(state),
        }
    }

    /// Classify the raw Win32 `Type` field without exposing binding constants.
    pub fn memory_type(&self) -> MemoryType {
        match self.r#type {
            kind if kind == MEM_IMAGE.0 => MemoryType::Image,
            kind if kind == MEM_MAPPED.0 => MemoryType::Mapped,
            kind if kind == MEM_PRIVATE.0 => MemoryType::Private,
            kind => MemoryType::Unknown(kind),
        }
    }

    pub fn is_committed(&self) -> bool {
        self.memory_state() == MemoryState::Commit
    }

    pub fn is_free(&self) -> bool {
        self.memory_state() == MemoryState::Free
    }

    pub fn is_reserved(&self) -> bool {
        self.memory_state() == MemoryState::Reserve
    }

    pub fn is_accessible(&self) -> bool {
        self.is_committed() && self.protect != PAGE_NOACCESS && (self.protect.0 & PAGE_GUARD.0) == 0
    }

    pub fn is_executable(&self) -> bool {
        self.is_accessible()
            && matches!(
                self.protect,
                PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
            )
    }

    pub fn is_writable(&self) -> bool {
        self.is_accessible()
            && matches!(
                self.protect,
                PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
            )
    }

    pub fn contains_range(&self, address: usize, size: usize) -> bool {
        let Some(end) = address.checked_add(size) else {
            return false;
        };
        let base = self.base_address as usize;
        let Some(region_end) = base.checked_add(self.region_size) else {
            return false;
        };
        address >= base && end <= region_end
    }
}

/// Win32 RECT with plain Rust field names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

/// Win32 POINT with plain Rust field names.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

/// Callback invoked by a Win32 message-queue timer.
///
/// The arguments are the timer's optional HWND, message id, timer id, and
/// dispatch timestamp. A callback passed to [`set_thread_timer`] must remain a
/// valid function for the timer's lifetime and must not unwind across the
/// Win32 ABI boundary.
pub type TimerCallback = unsafe extern "system" fn(*mut c_void, u32, usize, u32);

#[repr(C)]
struct MonitorInfo {
    size: u32,
    monitor: Rect,
    work: Rect,
    flags: u32,
}

mod sys {
    use libc::c_void;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn IsBadReadPtr(lp: *const c_void, ucb: usize) -> i32;
    }

    #[link(name = "user32")]
    unsafe extern "system" {
        pub fn AdjustWindowRectEx(
            rect: *mut super::Rect,
            style: u32,
            menu: i32,
            ex_style: u32,
        ) -> i32;
        pub fn DisableProcessWindowsGhosting();
        pub fn CallWindowProcA(
            prev_wnd_func: *mut c_void,
            hwnd: *mut c_void,
            msg: u32,
            wparam: usize,
            lparam: isize,
        ) -> isize;
        pub fn ClipCursor(rect: *const super::Rect) -> i32;
        pub fn DefWindowProcA(hwnd: *mut c_void, msg: u32, wparam: usize, lparam: isize) -> isize;
        pub fn GetActiveWindow() -> *mut c_void;
        pub fn GetClientRect(hwnd: *mut c_void, rect: *mut super::Rect) -> i32;
        pub fn GetClipCursor(rect: *mut super::Rect) -> i32;
        pub fn GetForegroundWindow() -> *mut c_void;
        pub fn GetWindowLongA(hwnd: *mut c_void, index: i32) -> i32;
        pub fn IsChild(parent: *mut c_void, child: *mut c_void) -> i32;
        pub fn IsWindow(hwnd: *mut c_void) -> i32;
        pub fn IsIconic(hwnd: *mut c_void) -> i32;
        pub fn GetWindowRect(hwnd: *mut c_void, rect: *mut super::Rect) -> i32;
        pub fn ClientToScreen(hwnd: *mut c_void, point: *mut super::Point) -> i32;
        pub fn MonitorFromWindow(hwnd: *mut c_void, flags: u32) -> *mut c_void;
        pub fn MonitorFromPoint(point: super::Point, flags: u32) -> *mut c_void;
        pub fn GetMonitorInfoW(monitor: *mut c_void, info: *mut super::MonitorInfo) -> i32;
        pub fn SetWindowLongA(hwnd: *mut c_void, index: i32, value: i32) -> i32;
        pub fn SetTimer(
            hwnd: *mut c_void,
            id: usize,
            interval_ms: u32,
            callback: Option<super::TimerCallback>,
        ) -> usize;
        pub fn KillTimer(hwnd: *mut c_void, id: usize) -> i32;
        pub fn SetWindowPos(
            hwnd: *mut c_void,
            after: *mut c_void,
            x: i32,
            y: i32,
            cx: i32,
            cy: i32,
            flags: u32,
        ) -> i32;
        pub fn ShowWindow(hwnd: *mut c_void, cmd: i32) -> i32;
    }
}

/// Returns `true` if the memory region is readable, `false` if it is bad.
///
/// Wraps WinAPI `IsBadReadPtr`. Microsoft documents this function as obsolete
/// and says it should not be used; it is not compiler-deprecated in MinGW.
/// Prefer ownership metadata, or page queries when only mapping is knowable.
///
/// # Safety
/// Unsafe WinAPI call.
pub unsafe fn is_readable_ptr(ptr: *const c_void, ucb: usize) -> bool {
    unsafe { sys::IsBadReadPtr(ptr, ucb) == 0 }
}

/// Adjust a window rectangle for style flags.
pub fn adjust_window_rect_ex(rect: &mut Rect, style: u32, menu: bool, ex_style: u32) -> bool {
    unsafe { sys::AdjustWindowRectEx(rect, style, i32::from(menu), ex_style) != 0 }
}

/// Disable Windows ghost-window substitution for hung windows.
pub fn disable_process_windows_ghosting() {
    unsafe { sys::DisableProcessWindowsGhosting() };
}

/// Return the thread's active window, or NULL.
pub fn get_active_window() -> *mut c_void {
    unsafe { sys::GetActiveWindow() }
}

/// Return the foreground window, or NULL when no window is foreground.
pub fn get_foreground_window() -> *mut c_void {
    unsafe { sys::GetForegroundWindow() }
}

/// Restrict the system cursor to `rect`, or release the restriction for `None`.
///
/// `ClipCursor` owns one process-independent desktop resource. Callers that
/// replace an existing rectangle should therefore avoid releasing a newer
/// owner's rectangle later.
pub fn clip_cursor(rect: Option<&Rect>) -> bool {
    let rect = rect.map_or(std::ptr::null(), std::ptr::from_ref);
    unsafe { sys::ClipCursor(rect) != 0 }
}

/// Return the desktop's current shared cursor-clipping rectangle.
pub fn cursor_clip_rect() -> Option<Rect> {
    let mut rect = Rect {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    if unsafe { sys::GetClipCursor(&mut rect) } == 0 {
        return None;
    }
    Some(rect)
}

/// Call a previous Win32 window procedure.
///
/// # Safety
///
/// `wnd_proc` must be a valid procedure returned by `GetWindowLongA` or
/// `SetWindowLongA` for this window.
pub unsafe fn call_window_proc_a(
    wnd_proc: *mut c_void,
    hwnd: *mut c_void,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    unsafe { sys::CallWindowProcA(wnd_proc, hwnd, msg, wparam, lparam) }
}

/// Run the default Win32 processing for a window message.
///
/// This is a defensive fallback for a subclass whose predecessor cannot be
/// recovered. Normal subclass chains should call [`call_window_proc_a`].
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn def_window_proc_a(hwnd: *mut c_void, msg: u32, wparam: usize, lparam: isize) -> isize {
    unsafe { sys::DefWindowProcA(hwnd, msg, wparam, lparam) }
}

/// Return a window long value.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn get_window_long_a(hwnd: *mut c_void, index: i32) -> i32 {
    unsafe { sys::GetWindowLongA(hwnd, index) }
}

/// Set a window long value and return the previous value.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn set_window_long_a(hwnd: *mut c_void, index: i32, value: i32) -> i32 {
    unsafe { sys::SetWindowLongA(hwnd, index, value) }
}

/// True if `child` is a descendant of `parent`.
///
/// Equal HWND values are not a parent-child relationship; callers that allow
/// an aliased top-level/renderer HWND must handle equality separately.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn is_child(parent: *mut c_void, child: *mut c_void) -> bool {
    !parent.is_null() && !child.is_null() && unsafe { sys::IsChild(parent, child) != 0 }
}

/// True if HWND names a live window.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn is_window(hwnd: *mut c_void) -> bool {
    !hwnd.is_null() && unsafe { sys::IsWindow(hwnd) != 0 }
}

/// True if the window is minimized.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn is_iconic(hwnd: *mut c_void) -> bool {
    !hwnd.is_null() && unsafe { sys::IsIconic(hwnd) != 0 }
}

/// Create a callback timer on the calling thread's message queue.
///
/// Passing a NULL HWND and zero id asks Win32 to allocate a collision-free id.
/// The callback runs only while this same thread dispatches messages. `None`
/// means Win32 could not create the timer.
///
/// The callback must remain valid until [`kill_thread_timer`] succeeds or the
/// creating thread exits, and it must not unwind through Win32.
pub fn set_thread_timer(interval_ms: u32, callback: TimerCallback) -> Option<usize> {
    let id = unsafe { sys::SetTimer(std::ptr::null_mut(), 0, interval_ms, Some(callback)) };
    (id != 0).then_some(id)
}

/// Destroy a message-queue timer created by [`set_thread_timer`].
///
/// This must be called from the thread that created the timer. Returning
/// `false` means Win32 did not remove the requested timer.
pub fn kill_thread_timer(id: usize) -> bool {
    id != 0 && unsafe { sys::KillTimer(std::ptr::null_mut(), id) != 0 }
}

/// Return the current outer window rectangle.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn window_rect(hwnd: *mut c_void) -> Option<Rect> {
    if hwnd.is_null() {
        return None;
    }
    let mut rect = Rect {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    if unsafe { sys::GetWindowRect(hwnd, &mut rect) } == 0 {
        return None;
    }
    Some(rect)
}

/// Return a window's client rectangle in screen coordinates.
///
/// Win32 reports client extents relative to `(0, 0)`. Both corners are
/// translated so callers receive the exact half-open rectangle expected by
/// `ClipCursor`, including windows on monitors with negative coordinates.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn client_rect_in_screen(hwnd: *mut c_void) -> Option<Rect> {
    if hwnd.is_null() {
        return None;
    }
    let mut rect = Rect {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    if unsafe { sys::GetClientRect(hwnd, &mut rect) } == 0 {
        return None;
    }

    let mut top_left = Point {
        x: rect.left,
        y: rect.top,
    };
    let mut bottom_right = Point {
        x: rect.right,
        y: rect.bottom,
    };
    if unsafe { sys::ClientToScreen(hwnd, &mut top_left) } == 0
        || unsafe { sys::ClientToScreen(hwnd, &mut bottom_right) } == 0
    {
        return None;
    }

    Some(Rect {
        left: top_left.x,
        top: top_left.y,
        right: bottom_right.x,
        bottom: bottom_right.y,
    })
}

/// Return the client-area origin in screen coordinates.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn client_origin(hwnd: *mut c_void) -> Option<Point> {
    if hwnd.is_null() {
        return None;
    }
    let mut point = Point { x: 0, y: 0 };
    if unsafe { sys::ClientToScreen(hwnd, &mut point) } == 0 {
        return None;
    }
    Some(point)
}

/// Return the full rectangle of the monitor nearest to a window.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn nearest_monitor_rect(hwnd: *mut c_void) -> Option<Rect> {
    const MONITOR_DEFAULTTONEAREST: u32 = 2;

    if hwnd.is_null() {
        return None;
    }
    let monitor = unsafe { sys::MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) };
    if monitor.is_null() {
        return None;
    }
    monitor_rect(monitor)
}

/// Return the full rectangle of the monitor nearest to a screen point.
pub fn nearest_monitor_rect_from_point(x: i32, y: i32) -> Option<Rect> {
    const MONITOR_DEFAULTTONEAREST: u32 = 2;

    let monitor = unsafe { sys::MonitorFromPoint(Point { x, y }, MONITOR_DEFAULTTONEAREST) };
    if monitor.is_null() {
        return None;
    }
    monitor_rect(monitor)
}

fn monitor_rect(monitor: *mut c_void) -> Option<Rect> {
    let mut info = MonitorInfo {
        size: std::mem::size_of::<MonitorInfo>() as u32,
        monitor: Rect {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        },
        work: Rect {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        },
        flags: 0,
    };
    if unsafe { sys::GetMonitorInfoW(monitor, &mut info) } == 0 {
        return None;
    }
    Some(info.monitor)
}

/// Set position/size/z-order for a window.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn set_window_pos(
    hwnd: *mut c_void,
    after: *mut c_void,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    flags: u32,
) -> bool {
    unsafe { sys::SetWindowPos(hwnd, after, x, y, cx, cy, flags) != 0 }
}

/// Change window show state.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn show_window(hwnd: *mut c_void, cmd: i32) -> bool {
    unsafe { sys::ShowWindow(hwnd, cmd) != 0 }
}

/// Query memory with VirtualQuery(...)
pub fn virtual_query(ptr: *mut c_void) -> WinapiResult<MemoryBasicInformation> {
    if ptr.is_null() {
        return Err(WinapiError::InputNullPtr());
    }

    let mut info = unsafe { std::mem::zeroed() };
    let info_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

    let result = unsafe { VirtualQuery(Some(ptr), &mut info, info_size) };

    if result == 0 {
        let last_error = unsafe { GetLastError().0 };
        return Err(WinapiError::VirtualQuery(last_error));
    }

    let memory_basic_info = MemoryBasicInformation {
        base_address: info.BaseAddress,
        allocation_base: info.AllocationBase,
        allocation_protect: info.AllocationProtect.0,
        //partition_id: info.PartitionId,
        region_size: info.RegionSize,
        state: info.State.0,
        protect: info.Protect,
        r#type: info.Type.0,
    };

    Ok(memory_basic_info)
}

/// WinAPI: FlushInstructionCache(...)
pub fn flush_instructions_cache(base: *mut c_void, size: usize) -> WinapiResult<()> {
    if base.is_null() {
        return Err(WinapiError::InputNullPtr());
    }

    let process_handle = get_current_process()?;

    unsafe {
        FlushInstructionCache(process_handle.into(), Some(base), size)?;
    }

    Ok(())
}

/// WinAPI: SetLastError(error_code)
pub fn set_last_error(error_code: u32) {
    unsafe { SetLastError(WIN32_ERROR(error_code)) }
}

/// WinAPI: GetLastError()
pub fn get_last_error_code() -> u32 {
    unsafe { GetLastError().0 }
}

/// WinAPI: SetLastError(0)
pub fn reset_last_error() {
    set_last_error(0);
}

/// `InitializeCriticalSection` wrapper from WinAPI
///
/// # Safety
///
/// - If `ptr` is NULL, error will be returned
pub unsafe fn initialize_critical_section(ptr: *mut CRITICAL_SECTION) -> WinapiResult<()> {
    if ptr.is_null() {
        return Err(WinapiError::InputNullPtr());
    }

    unsafe { InitializeCriticalSection(ptr) };

    Ok(())
}

/// Non-owning reference to a critical section stored by the host process.
#[derive(Clone, Copy, Debug)]
pub struct BorrowedCriticalSection {
    ptr: NonNull<c_void>,
}

impl BorrowedCriticalSection {
    /// Construct a borrowed critical section from a host-owned pointer.
    ///
    /// # Safety
    ///
    /// `ptr` must point to a live `CRITICAL_SECTION` for every guard created
    /// from this value.
    pub unsafe fn from_raw(ptr: *mut c_void) -> WinapiResult<Self> {
        let ptr = NonNull::new(ptr).ok_or(WinapiError::InputNullPtr())?;
        Ok(Self { ptr })
    }

    pub fn enter(self) -> CriticalSectionGuard {
        unsafe { EnterCriticalSection(self.ptr.as_ptr().cast()) };
        CriticalSectionGuard { section: self }
    }
}

/// Releases a borrowed critical section when dropped.
pub struct CriticalSectionGuard {
    section: BorrowedCriticalSection,
}

impl Drop for CriticalSectionGuard {
    fn drop(&mut self) {
        unsafe { LeaveCriticalSection(self.section.ptr.as_ptr().cast()) };
    }
}

/// Idiomatic Rust type for storing `THREAD_PRIORITY` values.
///
/// Actually, not really better than `THREAD_PRIORITY`, but
/// implements `Debug`, `Display`, `Hash` and easier to use in Rust.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum ThreadPriority {
    AboveNormal,
    BelowNormal,
    Highest,
    Idle,
    Lowest,
    Min,
    Normal,
    TimeCritical,
    Unknown(i32),
}

impl From<ThreadPriority> for THREAD_PRIORITY {
    fn from(value: ThreadPriority) -> Self {
        match value {
            ThreadPriority::AboveNormal => THREAD_PRIORITY_ABOVE_NORMAL,
            ThreadPriority::BelowNormal => THREAD_PRIORITY_BELOW_NORMAL,
            ThreadPriority::Highest => THREAD_PRIORITY_HIGHEST,
            ThreadPriority::Idle => THREAD_PRIORITY_IDLE,
            ThreadPriority::Lowest => THREAD_PRIORITY_LOWEST,
            ThreadPriority::Min => THREAD_PRIORITY_MIN,
            ThreadPriority::Normal => THREAD_PRIORITY_NORMAL,
            ThreadPriority::TimeCritical => THREAD_PRIORITY_TIME_CRITICAL,
            ThreadPriority::Unknown(priority) => THREAD_PRIORITY(priority),
        }
    }
}

impl From<THREAD_PRIORITY> for ThreadPriority {
    fn from(value: THREAD_PRIORITY) -> Self {
        match value {
            THREAD_PRIORITY_ABOVE_NORMAL => ThreadPriority::AboveNormal,
            THREAD_PRIORITY_BELOW_NORMAL => ThreadPriority::BelowNormal,
            THREAD_PRIORITY_HIGHEST => ThreadPriority::Highest,
            THREAD_PRIORITY_IDLE => ThreadPriority::Idle,
            THREAD_PRIORITY_LOWEST => ThreadPriority::Lowest,
            THREAD_PRIORITY_NORMAL => ThreadPriority::Normal,
            THREAD_PRIORITY_TIME_CRITICAL => ThreadPriority::TimeCritical,
            val => ThreadPriority::Unknown(val.0),
        }
    }
}

/// WinAPI: SetThreadPriority(...)
pub fn set_thread_priority(thread_handle: Handle, priority: ThreadPriority) -> WinapiResult<()> {
    unsafe { SetThreadPriority(thread_handle.into(), priority.into())? };

    Ok(())
}

/// Set the priority of a live thread without taking ownership of its handle.
///
/// The caller must keep the host-owned handle valid for the duration of this
/// call. This is intended for engine thread objects whose destructor, rather
/// than Rust, closes the underlying handle.
pub fn set_borrowed_thread_priority(
    thread_handle: BorrowedHandle,
    priority: ThreadPriority,
) -> WinapiResult<()> {
    unsafe { SetThreadPriority(thread_handle.as_raw(), priority.into())? };
    Ok(())
}

/// Restores a temporary priority change on the current thread.
///
/// The Win32 pseudo-handle stored here is valid only on the creating thread,
/// so the guard must not cross a thread boundary.
#[must_use]
pub struct CurrentThreadPriorityGuard {
    thread: HANDLE,
    original: i32,
    active: bool,
    not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl CurrentThreadPriorityGuard {
    /// Restore the priority immediately and report a WinAPI failure.
    pub fn restore(&mut self) -> WinapiResult<()> {
        if !self.active {
            return Ok(());
        }
        unsafe { SetThreadPriority(self.thread, THREAD_PRIORITY(self.original))? };
        self.active = false;
        Ok(())
    }
}

impl Drop for CurrentThreadPriorityGuard {
    fn drop(&mut self) {
        if self.active
            && unsafe { SetThreadPriority(self.thread, THREAD_PRIORITY(self.original)) }.is_ok()
        {
            self.active = false;
        }
    }
}

/// Temporarily cap the calling thread's base priority.
///
/// A thread already below the requested ceiling is never raised. The returned
/// guard restores the exact preceding priority. Call
/// [`CurrentThreadPriorityGuard::restore`] when restoration failure must be
/// surfaced; `Drop` makes one final best-effort restoration attempt.
pub fn lower_current_thread_priority_scoped(
    ceiling: ThreadPriority,
) -> WinapiResult<CurrentThreadPriorityGuard> {
    let thread = unsafe { GetCurrentThread() };
    unsafe { SetLastError(WIN32_ERROR(0)) };
    let original = unsafe { GetThreadPriority(thread) };
    if original == i32::MAX {
        return Err(WinapiError::WindowsCore(windows::core::Error::from_win32()));
    }
    let ceiling = THREAD_PRIORITY::from(ceiling).0;
    unsafe { SetThreadPriority(thread, THREAD_PRIORITY(original.min(ceiling)))? };
    Ok(CurrentThreadPriorityGuard {
        thread,
        original,
        active: true,
        not_send: std::marker::PhantomData,
    })
}

/// Temporarily set the calling thread's exact base priority.
///
/// The returned guard restores the preceding priority on the same thread.
/// This differs from [`lower_current_thread_priority_scoped`]: it may raise a
/// deliberately backgrounded worker to avoid priority inversion while that
/// worker enters a process-global engine critical section.
pub fn set_current_thread_priority_scoped(
    priority: ThreadPriority,
) -> WinapiResult<CurrentThreadPriorityGuard> {
    let thread = unsafe { GetCurrentThread() };
    unsafe { SetLastError(WIN32_ERROR(0)) };
    let original = unsafe { GetThreadPriority(thread) };
    if original == i32::MAX {
        return Err(WinapiError::WindowsCore(windows::core::Error::from_win32()));
    }
    let requested = THREAD_PRIORITY::from(priority).0;
    if original == requested {
        return Ok(CurrentThreadPriorityGuard {
            thread,
            original,
            active: false,
            not_send: std::marker::PhantomData,
        });
    }
    unsafe { SetThreadPriority(thread, THREAD_PRIORITY(requested))? };
    Ok(CurrentThreadPriorityGuard {
        thread,
        original,
        active: true,
        not_send: std::marker::PhantomData,
    })
}

/// WinAPI: VirtualProtect(...)
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn virtual_protect(
    ptr: *mut c_void,
    protection_flags: PAGE_PROTECTION_FLAGS,
    size: usize,
) -> WinapiResult<PAGE_PROTECTION_FLAGS> {
    if ptr.is_null() {
        return Err(WinapiError::InputNullPtr());
    }

    if size == 0 {
        return Err(WinapiError::ZeroSize());
    }

    let target_protection_flags: PAGE_PROTECTION_FLAGS = protection_flags;
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);

    // Change protection with winapi call
    // We use PageProtectionFlags type instead raw PAGE_PROTECTION_FLAGS
    // Why we need this? Because native idiomatic type works better for
    // devs. You can do way more with custom type and cast to raw when
    // needed.
    unsafe { VirtualProtect(ptr, size, target_protection_flags, &mut old_protect)? }

    Ok(old_protect)
}

/// Wrapper for 'virtual_protect'
///
/// This function takes closure 'func' and execute it after
/// memory protection flag changed to requested: 'protection_flags'.
/// After execution finish, memory protection flags restores to initial
/// value and return result from 'func', if any.
///
/// You really want to use this instead raw 'virtual_protect' because
/// with this safe wrapper, you can freely forget about missing protection
/// flags restoration, and you just write less code!
///
/// # Safety
/// - Virtual protect automatically restores after closure evaluation
/// - Same safety rules as for `virtual_protect`
pub unsafe fn with_virtual_protect<T, U: FnOnce() -> T>(
    ptr: *mut c_void,
    protection_flags: PAGE_PROTECTION_FLAGS,
    size: usize,
    func: U,
) -> WinapiResult<T> {
    // Step 1: change protection and save old protection flags to restore it in future
    let old_ptotect = virtual_protect(ptr, protection_flags, size)?;

    // Step 2: Execute callback here, saving it's result
    let callback_result = func();

    // Step 3: Restore protection, using previously stored protection flags
    let _ = virtual_protect(ptr, old_ptotect, size)?;

    Ok(callback_result)
}

/// Very important thing which represents HANDLE from WinAPI.    
/// It tries to be safe using AtomicPtr<c_void>
#[derive(Debug)]
pub struct Handle {
    ptr: NonNull<c_void>,
}

/// Copyable non-owning handle for kernel objects owned by the host process.
#[derive(Clone, Copy, Debug)]
pub struct BorrowedHandle {
    ptr: NonNull<c_void>,
}

impl BorrowedHandle {
    /// Construct a borrowed handle without taking `CloseHandle` ownership.
    ///
    /// # Safety
    ///
    /// `ptr` must remain a valid handle while it is used.
    pub unsafe fn from_raw(ptr: *mut c_void) -> WinapiResult<Self> {
        let ptr = NonNull::new(ptr).ok_or(WinapiError::InputNullPtr())?;
        Ok(Self { ptr })
    }

    fn as_raw(self) -> HANDLE {
        HANDLE(self.ptr.as_ptr())
    }
}

// Safety: Safe, because AtomicPtr is used and pointer is not null
unsafe impl Send for Handle {}

// Safety: Safe, because AtomicPtr is used and pointer is not null
unsafe impl Sync for Handle {}

impl Handle {
    /// Construct new `Handle`
    ///
    /// # Safety
    ///
    /// - If `ptr` is NULL, error will be returned
    /// - `ptr` stored in `NonNull<c_void>` container
    pub unsafe fn new(ptr: *mut c_void) -> WinapiResult<Self> {
        if ptr.is_null() {
            return Err(WinapiError::InputNullPtr());
        }

        Ok(Self {
            ptr: unsafe { NonNull::new_unchecked(ptr) },
        })
    }

    pub fn as_ptr(&self) -> *mut c_void {
        self.ptr.as_ptr()
    }
}

impl From<Handle> for HANDLE {
    fn from(value: Handle) -> Self {
        HANDLE(value.as_ptr())
    }
}

impl TryFrom<HANDLE> for Handle {
    type Error = WinapiError;

    fn try_from(value: HANDLE) -> Result<Self, Self::Error> {
        unsafe { Handle::new(value.0) }
    }
}

/// WinAPI: GetCurrentProcess()
/// Return Handle wrapper in Result.
///
/// # Safety:
/// Handle itself tries to be as safe as possible, using AtomicPtr
/// under the hood.
pub fn get_current_process() -> WinapiResult<Handle> {
    let handle = unsafe { GetCurrentProcess() };

    handle.try_into()
}

pub type ThreadStartRoutine = unsafe extern "system" fn(*mut c_void) -> u32;

/// WinAPI: CreateThread(...)
pub fn create_thread(
    start: ThreadStartRoutine,
    parameter: Option<*mut c_void>,
) -> WinapiResult<Handle> {
    let handle = unsafe {
        CreateThread(
            None,
            0,
            Some(start),
            parameter.map(|ptr| ptr as *const c_void),
            THREAD_CREATION_FLAGS(0),
            None,
        )?
    };

    handle.try_into()
}

/// WinAPI: CloseHandle(...)
pub fn close_handle(handle: Handle) -> WinapiResult<()> {
    unsafe { CloseHandle(handle.into())? };

    Ok(())
}

/// An owned handle to an existing disk file opened for validation and durable
/// flushing. The handle is always closed when this value is dropped.
#[derive(Debug)]
pub struct DurableFile {
    handle: Option<Handle>,
}

impl DurableFile {
    fn raw_handle(&self) -> WinapiResult<HANDLE> {
        let Some(handle) = self.handle.as_ref() else {
            return Err(WinapiError::InputNullPtr());
        };
        Ok(HANDLE(handle.as_ptr()))
    }

    /// Return the current physical file length.
    pub fn len(&self) -> WinapiResult<u64> {
        let mut size = 0i64;
        unsafe { GetFileSizeEx(self.raw_handle()?, &mut size)? };
        if size < 0 {
            return Err(WinapiError::NegativeFileSize(size));
        }
        Ok(size as u64)
    }

    /// Return whether the file contains no bytes.
    pub fn is_empty(&self) -> WinapiResult<bool> {
        Ok(self.len()? == 0)
    }

    /// Read up to `buffer.len()` bytes from the start of the file.
    ///
    /// Every call seeks back to offset zero and continues across short reads
    /// until the buffer is full or the file reaches EOF. The exclusive borrow
    /// prevents another reader from racing the shared Win32 file pointer
    /// between the seek and reads.
    pub fn read_prefix(&mut self, buffer: &mut [u8]) -> WinapiResult<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }

        let handle = self.raw_handle()?;
        unsafe { SetFilePointerEx(handle, 0, None, FILE_BEGIN)? };

        let mut total = 0;
        while total < buffer.len() {
            let mut bytes_read = 0;
            unsafe {
                ReadFile(
                    handle,
                    Some(&mut buffer[total..]),
                    Some(&mut bytes_read),
                    None,
                )?
            };
            if bytes_read == 0 {
                break;
            }
            total += bytes_read as usize;
        }
        Ok(total)
    }

    /// Force cached file contents and metadata associated with this handle to
    /// stable storage before the temporary file is promoted.
    pub fn flush(&self) -> WinapiResult<()> {
        unsafe { FlushFileBuffers(self.raw_handle()?)? };
        Ok(())
    }
}

impl Drop for DurableFile {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take()
            && let Err(error) = close_handle(handle)
        {
            log::error!("Failed to close durable file handle: {error}");
        }
    }
}

/// Open an existing file without truncation for stable validation and flushing.
///
/// The owned handle permits other readers but denies new writers and delete
/// access until it is dropped. Callers can therefore validate and flush one
/// stable file image before performing a later rename or replacement.
pub fn open_existing_file_for_flush(path: &CStr) -> WinapiResult<DurableFile> {
    let handle = unsafe {
        CreateFileA(
            PCSTR(path.as_ptr().cast()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )?
    };

    Ok(DurableFile {
        handle: Some(handle.try_into()?),
    })
}

/// Return whether a filesystem path currently exists.
pub fn file_exists(path: &CStr) -> WinapiResult<bool> {
    let attributes = unsafe { GetFileAttributesA(PCSTR(path.as_ptr().cast())) };
    if attributes != INVALID_FILE_ATTRIBUTES {
        return Ok(true);
    }

    let error = unsafe { GetLastError() };
    if error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND {
        return Ok(false);
    }
    Err(windows::core::Error::from_win32().into())
}

/// Delete an existing file. Missing paths are accepted so cleanup and backup
/// rotation remain idempotent after an interrupted save.
pub fn delete_file_if_exists(path: &CStr) -> WinapiResult<()> {
    match file_exists(path)? {
        true => unsafe { DeleteFileA(PCSTR(path.as_ptr().cast()))? },
        false => return Ok(()),
    }
    Ok(())
}

/// Copy one existing file to a new path without overwriting that path.
///
/// This wrapper deliberately exposes the fail-if-exists behavior. Transaction
/// callers can then distinguish an unexpected stale destination from the
/// source image they intended to preserve.
pub fn copy_file_new(source: &CStr, destination: &CStr) -> WinapiResult<()> {
    unsafe {
        CopyFileA(
            PCSTR(source.as_ptr().cast()),
            PCSTR(destination.as_ptr().cast()),
            true,
        )?
    };
    Ok(())
}

/// Move a file to an unoccupied destination and wait for the move to reach
/// storage.
///
/// Unlike [`move_file_replace_write_through`], this fails if the destination
/// already exists. It is suitable for engine-compatible rename sequences that
/// have explicitly established a vacant destination.
pub fn move_file_write_through(source: &CStr, destination: &CStr) -> WinapiResult<()> {
    unsafe {
        MoveFileExA(
            PCSTR(source.as_ptr().cast()),
            PCSTR(destination.as_ptr().cast()),
            MOVEFILE_WRITE_THROUGH,
        )?
    };
    Ok(())
}

/// Move a file and replace an existing destination only after the source is
/// ready. `MOVEFILE_WRITE_THROUGH` keeps the rename in the durable commit path.
pub fn move_file_replace_write_through(source: &CStr, destination: &CStr) -> WinapiResult<()> {
    unsafe {
        MoveFileExA(
            PCSTR(source.as_ptr().cast()),
            PCSTR(destination.as_ptr().cast()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )?
    };
    Ok(())
}

/// Wide-path equivalent of [`move_file_write_through`].
///
/// This preserves non-ANSI user paths while retaining fail-if-exists and
/// write-through publication semantics.
pub fn move_file_write_through_wide(source: &OsStr, destination: &OsStr) -> WinapiResult<()> {
    let mut source_wide: Vec<u16> = source.encode_wide().collect();
    let mut destination_wide: Vec<u16> = destination.encode_wide().collect();
    source_wide.push(0);
    destination_wide.push(0);
    unsafe {
        MoveFileExW(
            PCWSTR(source_wide.as_ptr()),
            PCWSTR(destination_wide.as_ptr()),
            MOVEFILE_WRITE_THROUGH,
        )?
    };
    Ok(())
}

/// Wide-path equivalent of [`move_file_replace_write_through`].
///
/// This preserves non-ANSI user paths while retaining replacement and
/// write-through publication semantics.
pub fn move_file_replace_write_through_wide(
    source: &OsStr,
    destination: &OsStr,
) -> WinapiResult<()> {
    let mut source_wide: Vec<u16> = source.encode_wide().collect();
    let mut destination_wide: Vec<u16> = destination.encode_wide().collect();
    source_wide.push(0);
    destination_wide.push(0);
    unsafe {
        MoveFileExW(
            PCWSTR(source_wide.as_ptr()),
            PCWSTR(destination_wide.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )?
    };
    Ok(())
}

/// WinAPI: GetCurrentThreadId()
/// Returns the thread identifier of the calling thread.
///
/// # Safety
/// This is a safe wrapper around the Windows API call.
pub fn get_current_thread_id() -> u32 {
    unsafe { WinGetCurrentThreadId() }
}

/// Check if thread alive by `thread_id`
/// # Returns
/// `true`  - if thread is alive
/// `false` - if thread is death
pub fn is_thread_alive(thread_id: u32) -> bool {
    unsafe {
        // 1. Try to get a handle to the thread
        let handle = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, thread_id);

        if let Ok(h) = handle {
            let mut exit_code: u32 = 0;
            let success = GetExitCodeThread(h, &mut exit_code);
            let _ = CloseHandle(h); // Always close the handle!

            if success.is_ok() {
                return exit_code == STILL_ACTIVE.0 as u32;
            }
        }
    }

    false // If we can't open it or it's not active, assume it's dead
}

/// Wrapper for WinAPI HMODULE type.
///
/// # Safety
/// HMODULE pointer stored in AtomicPtr and read-only.
#[derive(Debug, Clone, Copy)]
pub struct HModule {
    ptr: NonNull<c_void>,
}

// Safety: Inner poiter stored in AtomicPtr
unsafe impl Send for HModule {}

// Safety: Inner poiter stored in AtomicPtr
unsafe impl Sync for HModule {}

impl HModule {
    /// Constructs new `HModule`
    ///
    /// # Safety
    /// - If `ptr` is NULL, error will be returned
    pub unsafe fn new(ptr: *mut c_void) -> WinapiResult<Self> {
        if ptr.is_null() {
            return Err(WinapiError::InputNullPtr());
        }

        Ok(Self {
            ptr: unsafe { NonNull::new_unchecked(ptr) },
        })
    }

    /// Returns raw pointer for HMODULE
    pub fn as_ptr(&self) -> *mut c_void {
        self.ptr.as_ptr()
    }
}

impl From<HModule> for HMODULE {
    fn from(value: HModule) -> Self {
        Self(value.as_ptr())
    }
}

impl TryFrom<HMODULE> for HModule {
    type Error = WinapiError;

    fn try_from(value: HMODULE) -> Result<Self, Self::Error> {
        unsafe { HModule::new(value.0) }
    }
}

/// WinAPI: DisableThreadLibraryCalls(...)
pub fn disable_thread_library_calls(module: HModule) -> WinapiResult<()> {
    unsafe { DisableThreadLibraryCalls(module.into())? };

    Ok(())
}

/// Wrapper for WinAPI MODULEINFO type
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ModuleInfo {
    pub base_of_dll: *mut c_void,
    pub size_of_image: u32,
    pub entry_point: *mut c_void,
}

impl From<MODULEINFO> for ModuleInfo {
    fn from(value: MODULEINFO) -> Self {
        Self {
            base_of_dll: value.lpBaseOfDll,
            size_of_image: value.SizeOfImage,
            entry_point: value.EntryPoint,
        }
    }
}

impl From<ModuleInfo> for MODULEINFO {
    fn from(value: ModuleInfo) -> Self {
        Self {
            lpBaseOfDll: value.base_of_dll,
            SizeOfImage: value.size_of_image,
            EntryPoint: value.entry_point,
        }
    }
}

impl Default for ModuleInfo {
    fn default() -> Self {
        MODULEINFO::default().into()
    }
}

/// WinAPI: GetModuleInformation(...)
/// # Safety:
/// Returns error if base is NULL or handle of current process is NULL
pub fn get_module_information(module_handle: HModule) -> WinapiResult<ModuleInfo> {
    let process_handle = get_current_process()?;

    let mut module_info: MODULEINFO = MODULEINFO::default();

    unsafe {
        GetModuleInformation(
            process_handle.into(),
            module_handle.into(),
            &mut module_info,
            std::mem::size_of::<MODULEINFO>() as u32,
        )?;
    }

    Ok(module_info.into())
}

/// WinAPI: EnumProcessModules(...)
/// Enumerate all modules loaded in the current process
/// # Safety:
/// Returns error if process handle is invalid
pub fn enum_process_modules(handle_ptr: Option<*mut c_void>) -> WinapiResult<Vec<HModule>> {
    let raw_handle = match handle_ptr {
        Some(ptr) => HANDLE(ptr),
        None => {
            let process_handle = get_current_process()?;
            HANDLE(process_handle.as_ptr())
        }
    };

    // First call to get the required buffer size
    let mut cb_needed: u32 = 0;

    unsafe {
        EnumProcessModules(raw_handle, std::ptr::null_mut(), 0, &mut cb_needed)?;
    }

    // Allocate buffer for module handles
    let module_count = (cb_needed as usize) / std::mem::size_of::<HMODULE>();
    let mut modules: Vec<HMODULE> = vec![HMODULE(std::ptr::null_mut()); module_count];

    // Second call to get the actual modules
    let mut cb_needed_actual: u32 = 0;

    unsafe {
        EnumProcessModules(
            raw_handle,
            modules.as_mut_ptr(),
            cb_needed,
            &mut cb_needed_actual,
        )?;
    }

    // Convert HMODULE to HModule, filtering out null handles
    let result: Vec<HModule> = modules
        .into_iter()
        .filter(|h| !h.0.is_null())
        .filter_map(|h| h.try_into().ok())
        .collect();

    Ok(result)
}

/// WinAPI: GetModuleBaseNameA(...)
/// Get the base name of a module
/// # Safety:
/// Returns error if module handle is invalid
pub fn get_module_base_name(module_handle: HModule) -> WinapiResult<String> {
    let process_handle = get_current_process()?;
    let process_handle_raw: HANDLE = HANDLE(process_handle.as_ptr());
    let module_handle_raw: HMODULE = HMODULE(module_handle.as_ptr());

    const MAX_PATH: usize = 260;
    let mut buffer = [0u8; MAX_PATH];

    let length =
        unsafe { GetModuleBaseNameA(process_handle_raw, Some(module_handle_raw), &mut buffer) };

    if length == 0 {
        return Err(WinapiError::WindowsCore(windows::core::Error::from_win32()));
    }

    // Convert to String, stopping at first null byte
    let name = std::str::from_utf8(&buffer[..length as usize])
        .map_err(|_| WinapiError::WindowsCore(windows::core::Error::from_win32()))?
        .to_string();

    Ok(name)
}

/// Universal string conversion
///
/// WinString stores 3 types of string under the hood:
/// - origin string   - default String from Rust std
/// - ANSI string     - CString from Rust std, used in PCSTR conversion
/// - wide bytes vec  - re-encoded bytes from original string to UTF-16 for PCWSTR conversion
///
/// When you call WinString to give any WinAPI string type, it will just get pointer from
/// some of the stored string forms and put this pointer to desired WinAPI string type.
///
/// But the real use case for it - lifetime safety. Let me explain.
///
/// Imagine, you need to call some windows function which require string as argument. And from
/// this point, pain begins. What you need is go through this steps:
/// 1. Create intermediate string representation with CString/CStr/`Vec<u16>` or whatever
/// 2. Get pointer to just created intermediate string representation
/// 3. Pass pointer to PCSTR or PCWSTR to finally create WinAPI string
/// 4. Pass string to WinAPI function
///
/// You feel it? Pain! And you even not wrote this code yet! But real pain is only starts.
/// As you know, Rust comes with borrow checker which ensures that all type lives within
/// it's scopes. So, Rust will just delete everything which comes outside of initial scope.
///
/// In case of strings, we actually pass raw pointers to WinAPI functions, so it's very important
/// to ensure that original string lives long enougth. Otherwise, we get null pointer and undefined
/// behavior.
///
/// WinString fix all this problems with callback based approach. First, you instantiate WinString,
/// and for each action which require WinAPI string type, you write callbacks.
///
/// I know, it's boring and not very cool, but it really protects from shit, trust me.
/// Better to write not so crazy beatifull code construction instead spend hours on debugging.
#[derive(Debug)]
pub struct WinString {
    origin: String,
    ansi_str: CString,
    wide_vec: Vec<u16>,
}

impl WinString {
    pub fn new(input: &str) -> WinapiResult<Self> {
        let origin = input.to_string();

        let wide_vec: Vec<u16> = OsStr::new(input)
            .encode_wide()
            // Explanation:
            // Our goal is to store wide null-terminated string
            // So what we do here is just create iterator with '0' and chain it to main iterator,
            // thus at the end of vector we will have '0': [1, 2, 3, 0]
            .chain(std::iter::once(0))
            .collect();

        let ansi_str = CString::new(input)?;

        Ok(Self {
            wide_vec,
            ansi_str,
            origin,
        })
    }

    /// Execute closure with PCSTR as input.
    /// Returns result R from closure
    pub fn with_pcstr<F, R>(&self, f: F) -> R
    where
        F: FnOnce(PCSTR) -> R,
    {
        f(self.as_pcstr())
    }

    pub fn with_ansi<F, R>(&self, f: F) -> R
    where
        F: FnOnce(*const i8) -> R,
    {
        f(self.as_ansi_ptr())
    }

    pub fn try_with_pcstr<F, T>(&self, f: F) -> WinapiResult<T>
    where
        F: FnOnce(PCSTR) -> WinapiResult<T>,
    {
        f(self.as_pcstr())
    }

    pub fn with_pcwstr<F, R>(&self, f: F) -> R
    where
        F: FnOnce(PCWSTR) -> R,
    {
        f(self.as_pcwstr())
    }

    pub fn try_with_pcwstr<F, T>(&self, f: F) -> WinapiResult<T>
    where
        F: FnOnce(PCWSTR) -> WinapiResult<T>,
    {
        f(self.as_pcwstr())
    }

    pub fn try_with_ansi<F, T>(&self, f: F) -> WinapiResult<T>
    where
        F: FnOnce(*const i8) -> WinapiResult<T>,
    {
        f(self.as_ansi_ptr())
    }

    pub fn as_string(&self) -> String {
        self.origin.clone()
    }

    fn as_pcwstr(&self) -> PCWSTR {
        PCWSTR::from_raw(self.wide_vec.as_ptr())
    }

    fn as_pcstr(&self) -> PCSTR {
        PCSTR::from_raw(self.ansi_str.as_ptr() as *const u8)
    }

    fn as_ansi_ptr(&self) -> *const i8 {
        self.ansi_str.as_ptr()
    }
}

impl TryFrom<String> for WinString {
    type Error = WinapiError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        WinString::new(value.as_str())
    }
}

impl TryFrom<&String> for WinString {
    type Error = WinapiError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        WinString::new(value.as_str())
    }
}

impl TryFrom<&str> for WinString {
    type Error = WinapiError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        WinString::new(value)
    }
}

impl From<WinString> for String {
    fn from(value: WinString) -> Self {
        value.as_string()
    }
}

/// WinAPI: GetModuleHandleA(...)
pub fn get_module_handle_a(module_name: Option<&str>) -> WinapiResult<HModule> {
    let hmodule: HMODULE = match module_name {
        Some(name) => {
            let winstr = WinString::new(name)?;

            winstr.try_with_pcstr(|lpmodulename| Ok(unsafe { GetModuleHandleA(lpmodulename) }?))?
        }

        None => unsafe { GetModuleHandleA(None) }?,
    };

    hmodule.try_into()
}

/// WinAPI: GetProcAddress(...)
pub fn get_proc_address(module: HModule, function_name: &str) -> WinapiResult<*mut c_void> {
    let proc_name = WinString::new(function_name)?;

    let proc =
        proc_name.with_pcstr(|lpprocname| unsafe { GetProcAddress(module.into(), lpprocname) });

    match proc {
        Some(proc_value) => {
            // Safety: We do pointer copy here
            let ptr = proc_value as *mut c_void;

            if ptr.is_null() {
                return Err(WinapiError::ProcAddressIsNull(function_name.to_string()));
            }

            Ok(ptr)
        }

        None => Err(WinapiError::ProcAddressIsNull(function_name.to_string())),
    }
}

/// WinAPI: LoadLibraryA(...)
pub fn load_library_a(dll: &str) -> WinapiResult<HModule> {
    let dll_name = WinString::new(dll)?;

    let hmodule =
        dll_name.try_with_pcstr(|lplibfilename| Ok(unsafe { LoadLibraryA(lplibfilename) }?))?;

    hmodule.try_into()
}

/// WinAPI: LoadLibraryW(...)
pub fn load_library_w(dll: &str) -> WinapiResult<HModule> {
    let dll_name = WinString::new(dll)?;

    let hmodule =
        dll_name.try_with_pcwstr(|lplibfilename| Ok(unsafe { LoadLibraryW(lplibfilename) }?))?;

    hmodule.try_into()
}

/// WinAPI: GetModuleFileNameW(...)
pub fn get_module_file_name_w(module: Option<HModule>) -> WinapiResult<String> {
    const MAX_PATH: usize = 260;

    let mut buffer = [0u16; MAX_PATH];
    let module = module.map(Into::into);
    let length = unsafe { GetModuleFileNameW(module, &mut buffer) } as usize;

    if length == 0 {
        return Err(WinapiError::WindowsCore(windows::core::Error::from_win32()));
    }

    if length < buffer.len() {
        return Ok(String::from_utf16_lossy(&buffer[..length]));
    }

    let mut buffer = vec![0u16; 32768];
    let length = unsafe { GetModuleFileNameW(module, &mut buffer) } as usize;

    if length == 0 || length >= buffer.len() {
        return Err(WinapiError::WindowsCore(windows::core::Error::from_win32()));
    }

    Ok(String::from_utf16_lossy(&buffer[..length]))
}

/// Load a DLL relative to the main module's directory.
pub fn load_library_relative_to_main_module_w(relative_path: &str) -> WinapiResult<HModule> {
    let mut path = get_module_file_name_w(None)?;

    match path.rfind(['\\', '/']) {
        Some(pos) => path.truncate(pos + 1),
        None => path.clear(),
    }

    path.push_str(relative_path);
    load_library_w(&path)
}

/// WinAPI: GetSystemDirectoryW(...)
pub fn get_system_directory_w() -> WinapiResult<String> {
    const MAX_PATH: usize = 260;

    let mut buffer = [0u16; MAX_PATH];
    let length = unsafe { GetSystemDirectoryW(Some(&mut buffer)) } as usize;

    if length == 0 {
        return Err(WinapiError::WindowsCore(windows::core::Error::from_win32()));
    }

    if length < buffer.len() {
        return Ok(String::from_utf16_lossy(&buffer[..length]));
    }

    let mut buffer = vec![0u16; length + 1];
    let length = unsafe { GetSystemDirectoryW(Some(&mut buffer)) } as usize;

    if length == 0 || length >= buffer.len() {
        return Err(WinapiError::WindowsCore(windows::core::Error::from_win32()));
    }

    Ok(String::from_utf16_lossy(&buffer[..length]))
}

/// Load a DLL from the Windows system directory.
pub fn load_system_library_w(dll: &str) -> WinapiResult<HModule> {
    let mut path = get_system_directory_w()?;

    if !path.ends_with('\\') {
        path.push('\\');
    }

    path.push_str(dll);
    load_library_w(&path)
}

/// If function exist in loaded dll, returns it's address as *mut c_void
/// Otherwise return error
pub fn get_proc_address_in_dll(dll: &str, function_name: &str) -> WinapiResult<*mut c_void> {
    let module_handle = get_module_handle_a(Some(dll))?;
    let proc = get_proc_address(module_handle, function_name)?;

    Ok(proc)
}

/// Memory allocation types for VirtualAlloc
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationType {
    Commit,
    Reserve,
    ReserveTopDown,
    CommitReserve,
}

impl From<AllocationType> for VIRTUAL_ALLOCATION_TYPE {
    fn from(value: AllocationType) -> Self {
        match value {
            AllocationType::Commit => MEM_COMMIT,
            AllocationType::Reserve => MEM_RESERVE,
            AllocationType::ReserveTopDown => VIRTUAL_ALLOCATION_TYPE(MEM_RESERVE.0 | MEM_TOP_DOWN),
            AllocationType::CommitReserve => MEM_COMMIT | MEM_RESERVE,
        }
    }
}

/// Memory free types for VirtualFree
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreeType {
    Release,
}

impl From<FreeType> for VIRTUAL_FREE_TYPE {
    fn from(value: FreeType) -> Self {
        match value {
            FreeType::Release => MEM_RELEASE,
        }
    }
}

/// `VirtualAlloc` wrapper from WinAPI
///
/// # Safety
/// - If `size == 0`, error will be returned
/// - If result is `NULL`, error will be returned
/// - Other safety rules is same as for `VirtualAlloc`
pub unsafe fn virtual_alloc(
    address: Option<*const c_void>,
    size: usize,
    allocation_type: AllocationType,
    protection: PAGE_PROTECTION_FLAGS,
) -> WinapiResult<*mut c_void> {
    if size == 0 {
        return Err(WinapiError::ZeroSize());
    }

    let result = unsafe { VirtualAlloc(address, size, allocation_type.into(), protection) };

    if result.is_null() {
        return Err(WinapiError::WindowsCore(windows::core::Error::from_win32()));
    }

    Ok(result)
}

/// `VirtualFree` wrapper from WinAPI
///
/// # Safety
/// - If `address` is `NULL` error will be returned
/// - Other safety rules is same as for `VirtualFree`
pub unsafe fn virtual_free(address: *mut c_void, free_type: FreeType) -> WinapiResult<()> {
    if address.is_null() {
        return Err(WinapiError::InputNullPtr());
    }

    // Per WinAPI docs, 'dwSize' must be 0 if 'dwFreeType' is MEM_RELEASE.
    let size = match free_type {
        FreeType::Release => 0,
    };

    unsafe { VirtualFree(address, size, free_type.into()) }?;

    Ok(())
}

/// Reserve address space without adding allocator hot-path validation.
///
/// Returns null on failure and leaves the Win32 last-error value available to
/// the caller. This is intended for allocators that already validate sizes.
///
/// # Safety
///
/// A non-null requested address must describe a range that may be reserved.
#[inline(always)]
pub unsafe fn virtual_reserve(address: Option<*const c_void>, size: usize) -> *mut c_void {
    unsafe { VirtualAlloc(address, size, MEM_RESERVE, PAGE_READWRITE) }
}

/// Commit pages in an existing reservation without extra validation.
///
/// # Safety
///
/// `address..address + size` must lie inside a live reservation.
#[inline(always)]
pub unsafe fn virtual_commit(address: *const c_void, size: usize) -> *mut c_void {
    unsafe { VirtualAlloc(Some(address), size, MEM_COMMIT, PAGE_READWRITE) }
}

/// Reserve and commit pages without extra allocator hot-path validation.
///
/// # Safety
///
/// A non-null requested address must describe a range that may be allocated.
#[inline(always)]
pub unsafe fn virtual_reserve_commit(address: Option<*const c_void>, size: usize) -> *mut c_void {
    unsafe { VirtualAlloc(address, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) }
}

/// Make a committed allocator range readable and writable.
///
/// The previous protection is deliberately discarded: reserve-slot ownership
/// uses explicit `PAGE_READWRITE` while leased and `PAGE_NOACCESS` while idle,
/// rather than temporarily borrowing an arbitrary caller protection.
///
/// # Safety
///
/// `address..address + size` must lie inside committed virtual memory.
#[inline]
pub unsafe fn virtual_make_readwrite(address: *mut c_void, size: usize) -> WinapiResult<()> {
    virtual_protect(address, PAGE_READWRITE, size).map(|_| ())
}

/// Make a committed allocator range inaccessible without releasing its VAS.
///
/// The pages remain committed so reacquisition does not require a new mapping
/// during address-space pressure.
///
/// # Safety
///
/// `address..address + size` must lie inside committed virtual memory.
#[inline]
pub unsafe fn virtual_make_noaccess(address: *mut c_void, size: usize) -> WinapiResult<()> {
    virtual_protect(address, PAGE_NOACCESS, size).map(|_| ())
}

/// Release a complete virtual-memory reservation.
///
/// # Safety
///
/// `address` must be the base of a live `VirtualAlloc` reservation.
#[inline(always)]
pub unsafe fn virtual_release(address: *mut c_void) -> WinapiResult<()> {
    unsafe { virtual_free(address, FreeType::Release) }
}

/// Reserve address space near the top of the process VAS.
pub fn virtual_reserve_top_down(size: usize) -> WinapiResult<*mut c_void> {
    unsafe { virtual_alloc(None, size, AllocationType::ReserveTopDown, PAGE_READWRITE) }
}

/// Return native page, allocation, and logical-processor information.
///
/// `GetNativeSystemInfo` is used so a 32-bit caller running under WOW64 sees
/// the host architecture's layout rather than an emulated 32-bit layout.
pub fn native_system_layout() -> NativeSystemLayout {
    let mut info = SYSTEM_INFO::default();
    unsafe { GetNativeSystemInfo(&mut info) };
    // SYSTEM_INFO reports only the caller's processor group on machines with
    // more than 64 logical CPUs. The group-aware count prevents a precise
    // topology profile from silently collapsing to that legacy view.
    let all_groups = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) };
    NativeSystemLayout {
        page_size: info.dwPageSize,
        allocation_granularity: info.dwAllocationGranularity,
        logical_processor_count: if all_groups == 0 {
            info.dwNumberOfProcessors
        } else {
            all_groups
        },
    }
}

/// Return physical topology and cache records visible to Windows.
///
/// The API returns a packed sequence of variable-size records. This wrapper
/// validates every record boundary before reading its relationship payload so
/// callers never need to interact with Win32 flexible-array unions.
pub fn processor_topology() -> WinapiResult<ProcessorTopology> {
    let bytes = logical_processor_information_bytes()?;
    parse_processor_topology(&bytes)
}

fn parse_processor_topology(bytes: &[u8]) -> WinapiResult<ProcessorTopology> {
    let mut offset = 0usize;
    let mut physical_core_count = 0u32;
    let mut package_count = 0u32;
    let mut numa_nodes = BTreeSet::new();
    let mut caches = Vec::new();
    let mut efficiency_classes = BTreeMap::<u8, u32>::new();

    while offset < bytes.len() {
        const HEADER_SIZE: usize = 8;
        if bytes.len() - offset < HEADER_SIZE {
            return Err(WinapiError::MalformedProcessorTopology(
                "truncated relationship header",
            ));
        }

        // The buffer is word-aligned, but individual relationship sizes are
        // controlled by Windows. Unaligned reads keep the parser correct even
        // if a compatibility layer returns an unexpectedly aligned record.
        let record = unsafe { bytes.as_ptr().add(offset) };
        let relationship = unsafe { record.cast::<i32>().read_unaligned() };
        let record_size =
            unsafe { record.add(size_of::<i32>()).cast::<u32>().read_unaligned() } as usize;
        if record_size < HEADER_SIZE || record_size > bytes.len() - offset {
            return Err(WinapiError::MalformedProcessorTopology(
                "invalid relationship size",
            ));
        }

        if relationship == RelationProcessorCore.0 || relationship == RelationProcessorPackage.0 {
            if record_size < HEADER_SIZE + size_of::<PROCESSOR_RELATIONSHIP>() {
                return Err(WinapiError::MalformedProcessorTopology(
                    "truncated processor relationship",
                ));
            }
            let processor = unsafe {
                record
                    .add(HEADER_SIZE)
                    .cast::<PROCESSOR_RELATIONSHIP>()
                    .read_unaligned()
            };
            validate_group_affinity_array(
                record_size,
                HEADER_SIZE + offset_of!(PROCESSOR_RELATIONSHIP, GroupMask),
                usize::from(processor.GroupCount),
                "processor relationship has no group masks",
            )?;
            if relationship == RelationProcessorCore.0 {
                physical_core_count = physical_core_count.saturating_add(1);
                let count = efficiency_classes
                    .entry(processor.EfficiencyClass)
                    .or_default();
                *count = count.saturating_add(1);
            } else {
                package_count = package_count.saturating_add(1);
            }
        } else if relationship == RelationNumaNode.0 || relationship == RelationNumaNodeEx.0 {
            if record_size < HEADER_SIZE + size_of::<NUMA_NODE_RELATIONSHIP>() {
                return Err(WinapiError::MalformedProcessorTopology(
                    "truncated NUMA relationship",
                ));
            }
            let numa = unsafe {
                record
                    .add(HEADER_SIZE)
                    .cast::<NUMA_NODE_RELATIONSHIP>()
                    .read_unaligned()
            };
            validate_group_affinity_array(
                record_size,
                HEADER_SIZE + offset_of!(NUMA_NODE_RELATIONSHIP, Anonymous),
                usize::from(numa.GroupCount).max(1),
                "NUMA relationship has no group masks",
            )?;
            numa_nodes.insert(numa.NodeNumber);
        } else if relationship == RelationCache.0 {
            if record_size < HEADER_SIZE + size_of::<CACHE_RELATIONSHIP>() {
                return Err(WinapiError::MalformedProcessorTopology(
                    "truncated cache relationship",
                ));
            }
            let cache = unsafe {
                record
                    .add(HEADER_SIZE)
                    .cast::<CACHE_RELATIONSHIP>()
                    .read_unaligned()
            };
            let cache_type = match cache.Type {
                kind if kind == CacheUnified => ProcessorCacheType::Unified,
                kind if kind == CacheInstruction => ProcessorCacheType::Instruction,
                kind if kind == CacheData => ProcessorCacheType::Data,
                kind if kind == CacheTrace => ProcessorCacheType::Trace,
                kind => ProcessorCacheType::Unknown(kind.0),
            };
            let group_count = usize::from(cache.GroupCount).max(1);
            let masks_offset = HEADER_SIZE + offset_of!(CACHE_RELATIONSHIP, Anonymous);
            let masks_bytes = group_count.checked_mul(size_of::<GROUP_AFFINITY>()).ok_or(
                WinapiError::MalformedProcessorTopology("cache group-mask size overflow"),
            )?;
            let masks_end = masks_offset.checked_add(masks_bytes).ok_or(
                WinapiError::MalformedProcessorTopology("cache group-mask end overflow"),
            )?;
            if masks_end > record_size {
                return Err(WinapiError::MalformedProcessorTopology(
                    "truncated cache group masks",
                ));
            }
            let mut shared_logical_processor_count = 0u32;
            for index in 0..group_count {
                let mask = unsafe {
                    record
                        .add(masks_offset + index * size_of::<GROUP_AFFINITY>())
                        .cast::<GROUP_AFFINITY>()
                        .read_unaligned()
                };
                shared_logical_processor_count =
                    shared_logical_processor_count.saturating_add(mask.Mask.count_ones());
            }
            caches.push(ProcessorCacheInfo {
                level: cache.Level,
                associativity: cache.Associativity,
                line_size: cache.LineSize,
                size: cache.CacheSize,
                shared_logical_processor_count,
                cache_type,
            });
        }

        offset += record_size;
    }

    Ok(ProcessorTopology {
        physical_core_count,
        package_count,
        numa_node_count: numa_nodes.len() as u32,
        caches,
        efficiency_classes: efficiency_classes
            .into_iter()
            .map(|(class, core_count)| ProcessorEfficiencyClass { class, core_count })
            .collect(),
    })
}

fn validate_group_affinity_array(
    record_size: usize,
    masks_offset: usize,
    group_count: usize,
    empty_reason: &'static str,
) -> WinapiResult<()> {
    if group_count == 0 {
        return Err(WinapiError::MalformedProcessorTopology(empty_reason));
    }
    let masks_bytes = group_count.checked_mul(size_of::<GROUP_AFFINITY>()).ok_or(
        WinapiError::MalformedProcessorTopology("group-mask size overflow"),
    )?;
    let masks_end =
        masks_offset
            .checked_add(masks_bytes)
            .ok_or(WinapiError::MalformedProcessorTopology(
                "group-mask end overflow",
            ))?;
    if masks_end > record_size {
        return Err(WinapiError::MalformedProcessorTopology(
            "truncated relationship group masks",
        ));
    }
    Ok(())
}

fn logical_processor_information_bytes() -> WinapiResult<Vec<u8>> {
    let mut required = 0u32;
    let first = unsafe { GetLogicalProcessorInformationEx(RelationAll, None, &mut required) };
    if required == 0 {
        return match first {
            Ok(()) => Err(WinapiError::MalformedProcessorTopology(
                "empty topology response",
            )),
            Err(error) => Err(error.into()),
        };
    }

    for attempt in 0..2 {
        // Vec<usize> provides enough alignment for every record payload,
        // unlike Vec<u8>, whose alignment is formally only one byte.
        let word_size = size_of::<usize>();
        let words = (required as usize).checked_add(word_size - 1).ok_or(
            WinapiError::MalformedProcessorTopology("topology size overflow"),
        )? / word_size;
        let mut storage = vec![0usize; words];
        let mut written = required;
        let result = unsafe {
            GetLogicalProcessorInformationEx(
                RelationAll,
                Some(
                    storage
                        .as_mut_ptr()
                        .cast::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(),
                ),
                &mut written,
            )
        };
        if written > required && attempt == 0 {
            // Processor hot-add can change the required length between calls.
            // Retry exactly once with the new authoritative length so a
            // genuinely unstable provider cannot force an allocation loop.
            required = written;
            continue;
        }
        result?;
        if written > required {
            return Err(WinapiError::MalformedProcessorTopology(
                "topology repeatedly grew during query",
            ));
        }

        let source =
            unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), written as usize) };
        return Ok(source.to_vec());
    }
    unreachable!("bounded topology retry loop always returns")
}

/// Return a point-in-time system memory snapshot.
///
/// Availability fields are intentionally not cached: they describe current
/// pressure and can change immediately after this call returns.
pub fn system_memory_status() -> WinapiResult<SystemMemoryStatus> {
    let mut status = MEMORYSTATUSEX {
        dwLength: size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    unsafe { GlobalMemoryStatusEx(&mut status)? };
    Ok(SystemMemoryStatus {
        memory_load_percent: status.dwMemoryLoad,
        total_physical_bytes: status.ullTotalPhys,
        available_physical_bytes: status.ullAvailPhys,
        total_page_file_bytes: status.ullTotalPageFile,
        available_page_file_bytes: status.ullAvailPageFile,
        total_virtual_bytes: status.ullTotalVirtual,
        available_virtual_bytes: status.ullAvailVirtual,
    })
}

/// Return the amount of physically installed memory in bytes.
///
/// This firmware-derived capacity can exceed usable physical memory because
/// hardware-reserved address ranges are excluded from `GlobalMemoryStatusEx`.
pub fn physically_installed_memory_bytes() -> WinapiResult<u64> {
    let mut kibibytes = 0u64;
    unsafe { GetPhysicallyInstalledSystemMemory(&mut kibibytes)? };
    kibibytes
        .checked_mul(1024)
        .ok_or(WinapiError::IntegerOverflow(
            "installed memory from KiB to bytes",
        ))
}

/// Read the raw SMBIOS (`RSMB`) firmware-table payload.
///
/// A defensive cap prevents corrupt firmware or a compatibility layer from
/// forcing a large allocation during an otherwise lightweight detection call.
pub fn raw_smbios_table() -> WinapiResult<Vec<u8>> {
    const RSMB_PROVIDER: FIRMWARE_TABLE_PROVIDER = FIRMWARE_TABLE_PROVIDER(0x5253_4d42);
    const MAX_FIRMWARE_TABLE_BYTES: u32 = 16 * 1024 * 1024;

    let mut required = unsafe { GetSystemFirmwareTable(RSMB_PROVIDER, 0, None) };
    if required == 0 {
        return Err(windows::core::Error::from_win32().into());
    }
    if required > MAX_FIRMWARE_TABLE_BYTES {
        return Err(WinapiError::FirmwareTableTooLarge(required));
    }

    for attempt in 0..2 {
        let mut bytes = vec![0u8; required as usize];
        let written = unsafe { GetSystemFirmwareTable(RSMB_PROVIDER, 0, Some(&mut bytes)) };
        if written == 0 {
            return Err(windows::core::Error::from_win32().into());
        }
        if written > required && attempt == 0 {
            if written > MAX_FIRMWARE_TABLE_BYTES {
                return Err(WinapiError::FirmwareTableTooLarge(written));
            }
            required = written;
            continue;
        }
        if written > required {
            return Err(WinapiError::MalformedFirmwareTable(
                "firmware table repeatedly grew during query",
            ));
        }
        bytes.truncate(written as usize);
        return Ok(bytes);
    }
    unreachable!("bounded firmware retry loop always returns")
}

/// Return the process's currently available virtual address space.
pub fn available_virtual_memory() -> WinapiResult<usize> {
    Ok(system_memory_status()?.available_virtual_bytes as usize)
}

/// WinAPI: GetModuleHandleW(...)
/// Get module handle by name (Unicode version)
/// If input is None, will return handle of current process
pub fn get_module_handle_w(module_name: Option<&str>) -> WinapiResult<HModule> {
    let hmodule = if let Some(name) = module_name {
        let winstr = WinString::new(name)?;
        winstr.try_with_pcwstr(|lpmodulename| Ok(unsafe { GetModuleHandleW(lpmodulename) }?))?
    } else {
        unsafe { GetModuleHandleW(None) }?
    };

    unsafe { HModule::new(hmodule.0) }
}

/// WinAPI: MessageBoxA(...)
/// Display a message box with text and caption
pub fn message_box_a(
    hwnd: Option<HWND>,
    text: &str,
    caption: &str,
    mb_type: Option<MESSAGEBOX_STYLE>,
) -> WinapiResult<MESSAGEBOX_RESULT> {
    // Very easy string conversion using our custom string type.
    // Closures allows us to ensure that lifetimes of strings are
    // okay.

    let text_str = WinString::new(text)?;
    let caption_str = WinString::new(caption)?;
    let style = mb_type.unwrap_or(MB_OK);
    let window = hwnd.unwrap_or(HWND(std::ptr::null_mut()));

    text_str.try_with_pcstr(|text_ptr| {
        caption_str.try_with_pcstr(|caption_ptr| {
            Ok(unsafe { MessageBoxA(Some(window), text_ptr, caption_ptr, style) })
        })
    })
}

/// Allocate a new console window for the process.
///
/// This is useful when your DLL is loaded into a process that doesn't have a console
/// (like a GUI game). After calling this, stdout/stderr will be redirected to the new console.
///
/// # Safety
/// - Can only be called once per process
/// - If the process already has a console, this will fail (returns Ok anyway)
pub fn alloc_console() -> WinapiResult<()> {
    unsafe {
        AllocConsole()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    struct TestDirectory(PathBuf);

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn ansi_path(path: &Path) -> CString {
        CString::new(path.to_string_lossy().as_bytes()).expect("test path must not contain NUL")
    }

    #[test]
    fn memory_type_classification_preserves_unknown_values() {
        let mut info = MemoryBasicInformation {
            base_address: std::ptr::null_mut(),
            allocation_base: std::ptr::null_mut(),
            allocation_protect: 0,
            region_size: 0x1000,
            state: MEM_COMMIT.0,
            protect: PAGE_READWRITE,
            r#type: MEM_PRIVATE.0,
        };
        assert_eq!(info.memory_type(), MemoryType::Private);
        info.r#type = MEM_MAPPED.0;
        assert_eq!(info.memory_type(), MemoryType::Mapped);
        info.r#type = MEM_IMAGE.0;
        assert_eq!(info.memory_type(), MemoryType::Image);
        info.r#type = 0x1234_5678;
        assert_eq!(info.memory_type(), MemoryType::Unknown(0x1234_5678));
    }

    #[test]
    fn topology_parser_walks_variable_records_and_cache_masks() {
        fn relationship_record(relationship: i32, payload_size: usize) -> Vec<u8> {
            let size = 8 + payload_size;
            let mut record = vec![0u8; size];
            record[0..4].copy_from_slice(&relationship.to_le_bytes());
            record[4..8].copy_from_slice(&(size as u32).to_le_bytes());
            record
        }

        let mut bytes = Vec::new();
        for efficiency_class in [2u8, 7u8] {
            let mut core =
                relationship_record(RelationProcessorCore.0, size_of::<PROCESSOR_RELATIONSHIP>());
            core[8 + std::mem::offset_of!(PROCESSOR_RELATIONSHIP, EfficiencyClass)] =
                efficiency_class;
            let group_count = 8 + std::mem::offset_of!(PROCESSOR_RELATIONSHIP, GroupCount);
            core[group_count..group_count + 2].copy_from_slice(&1u16.to_le_bytes());
            bytes.extend_from_slice(&core);
        }
        let mut package = relationship_record(
            RelationProcessorPackage.0,
            size_of::<PROCESSOR_RELATIONSHIP>(),
        );
        let package_group_count = 8 + std::mem::offset_of!(PROCESSOR_RELATIONSHIP, GroupCount);
        package[package_group_count..package_group_count + 2].copy_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&package);

        let mut numa = relationship_record(RelationNumaNode.0, size_of::<NUMA_NODE_RELATIONSHIP>());
        numa[8..12].copy_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&numa);

        let mut cache = relationship_record(RelationCache.0, size_of::<CACHE_RELATIONSHIP>());
        cache[8] = 3;
        cache[9] = 16;
        cache[10..12].copy_from_slice(&64u16.to_le_bytes());
        cache[12..16].copy_from_slice(&(8u32 * 1024 * 1024).to_le_bytes());
        cache[16..20].copy_from_slice(&CacheUnified.0.to_le_bytes());
        let group_count = 8 + std::mem::offset_of!(CACHE_RELATIONSHIP, GroupCount);
        cache[group_count..group_count + 2].copy_from_slice(&1u16.to_le_bytes());
        let group_mask = 8 + std::mem::offset_of!(CACHE_RELATIONSHIP, Anonymous);
        cache[group_mask..group_mask + size_of::<usize>()]
            .copy_from_slice(&0b1111usize.to_le_bytes());
        bytes.extend_from_slice(&cache);

        let topology = parse_processor_topology(&bytes).unwrap();
        assert_eq!(topology.physical_core_count, 2);
        assert_eq!(topology.package_count, 1);
        assert_eq!(topology.numa_node_count, 1);
        assert_eq!(
            topology.efficiency_classes,
            vec![
                ProcessorEfficiencyClass {
                    class: 2,
                    core_count: 1,
                },
                ProcessorEfficiencyClass {
                    class: 7,
                    core_count: 1,
                },
            ]
        );
        assert_eq!(topology.caches[0].shared_logical_processor_count, 4);
    }

    #[test]
    fn topology_parser_rejects_zero_sized_records() {
        let mut record = [0u8; 8];
        record[0..4].copy_from_slice(&RelationProcessorCore.0.to_le_bytes());
        assert!(matches!(
            parse_processor_topology(&record),
            Err(WinapiError::MalformedProcessorTopology(
                "invalid relationship size"
            ))
        ));
    }

    #[test]
    fn recovery_copy_flush_and_replacement_work_as_one_windows_sequence() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "libpsycho-save-promotion-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create isolated save-promotion test directory");
        let _cleanup = TestDirectory(directory.clone());

        let final_path = directory.join("save.fos");
        let temp_path = directory.join("save.fos.tmp");
        let recovery_path = directory.join("save.fos.txn");
        fs::write(&final_path, b"old-good-save").expect("write old final fixture");
        fs::write(&temp_path, b"new-save").expect("write temporary fixture");

        let final_path_ansi = ansi_path(&final_path);
        let temp_path_ansi = ansi_path(&temp_path);
        let recovery_path_ansi = ansi_path(&recovery_path);
        copy_file_new(&final_path_ansi, &recovery_path_ansi).expect("copy final to recovery path");
        open_existing_file_for_flush(&recovery_path_ansi)
            .expect("open recovery copy")
            .flush()
            .expect("flush recovery copy");
        move_file_replace_write_through(&temp_path_ansi, &final_path_ansi)
            .expect("replace final with temporary file");

        assert_eq!(fs::read(&final_path).unwrap(), b"new-save");
        assert_eq!(fs::read(&recovery_path).unwrap(), b"old-good-save");
        assert!(!temp_path.exists());
    }

    #[test]
    fn vacant_destination_rename_sequence_matches_engine_fallback() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "libpsycho-save-fallback-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create isolated save-fallback test directory");
        let _cleanup = TestDirectory(directory.clone());

        let final_path = directory.join("save.fos");
        let temp_path = directory.join("save.fos.tmp");
        let recovery_path = directory.join("save.fos.txn");
        fs::write(&final_path, b"old-good-save").expect("write old final fixture");
        fs::write(&temp_path, b"new-save").expect("write temporary fixture");

        let final_path_ansi = ansi_path(&final_path);
        let temp_path_ansi = ansi_path(&temp_path);
        let recovery_path_ansi = ansi_path(&recovery_path);
        move_file_write_through(&final_path_ansi, &recovery_path_ansi)
            .expect("move old final to vacant recovery path");
        move_file_write_through(&temp_path_ansi, &final_path_ansi)
            .expect("move temporary file to vacant final path");

        assert_eq!(fs::read(&final_path).unwrap(), b"new-save");
        assert_eq!(fs::read(&recovery_path).unwrap(), b"old-good-save");
        assert!(!temp_path.exists());
    }
}

/// Configure the console to display colours.
///
/// This is only needed on Windows when using the 'colors' feature.
/// It doesn't currently handle combining the 'colors' and 'stderr' features.
pub fn set_up_windows_color_terminal() -> WinapiResult<()> {
    use std::io::{IsTerminal, stdout};

    if stdout().is_terminal() {
        unsafe {
            let stdout = GetStdHandle(STD_OUTPUT_HANDLE)?;

            if stdout == INVALID_HANDLE_VALUE {
                return Ok(());
            }

            let mut mode: CONSOLE_MODE = windows::Win32::System::Console::CONSOLE_MODE(0);

            GetConsoleMode(stdout, &mut mode)?;

            SetConsoleMode(stdout, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)?;
        }
    }

    Ok(())
}

/// Safe write value to address
///
/// Uses unaligned write to support any address alignment.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn safe_write<T: Copy>(ptr: *mut c_void, data: T) -> WinapiResult<()> {
    if ptr.is_null() {
        return Err(WinapiError::InputNullPtr());
    }

    unsafe {
        with_virtual_protect(
            ptr,
            PAGE_EXECUTE_READWRITE,
            std::mem::size_of::<T>(),
            || {
                std::ptr::write_unaligned(ptr as *mut T, data);
            },
        )
    }?;

    Ok(())
}

/// Write a 32-bit value to an address
///
/// Uses unaligned write to support addresses that aren't 4-byte aligned.
/// This is necessary when patching call instructions where the offset field
/// may not be properly aligned (e.g., at address + 1).
pub fn safe_write_32(ptr: *mut c_void, data: u32) -> WinapiResult<()> {
    safe_write(ptr, data)
}

/// Atomically replace an aligned pointer while preserving page protection.
///
/// A protection-restoration failure is reported as an error. If the pointer was
/// already exchanged, the function attempts to restore `expected` before
/// returning that error and never overwrites a value installed concurrently.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn compare_exchange_pointer(
    ptr: *mut *mut c_void,
    expected: *mut c_void,
    replacement: *mut c_void,
) -> WinapiResult<PointerExchange> {
    if ptr.is_null() {
        return Err(WinapiError::InputNullPtr());
    }
    if !(ptr as usize).is_multiple_of(std::mem::align_of::<AtomicPtr<c_void>>()) {
        return Err(WinapiError::MisalignedPointer(ptr as usize));
    }

    let address = ptr.cast();
    let size = std::mem::size_of::<*mut c_void>();
    let old_protection = virtual_protect(address, PAGE_READWRITE, size)?;
    let outcome = unsafe {
        let atomic = &*(ptr as *const AtomicPtr<c_void>);
        match atomic.compare_exchange(expected, replacement, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => PointerExchange::Exchanged,
            Err(observed) => PointerExchange::Mismatch(observed),
        }
    };
    if let Err(error) = virtual_protect(address, old_protection, size) {
        if outcome == PointerExchange::Exchanged {
            let atomic = unsafe { &*(ptr as *const AtomicPtr<c_void>) };
            let _ =
                atomic.compare_exchange(replacement, expected, Ordering::AcqRel, Ordering::Acquire);
            let _ = virtual_protect(address, old_protection, size);
        }
        return Err(error);
    }
    Ok(outcome)
}

/// Atomically read an aligned pointer.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn load_pointer(ptr: *mut *mut c_void) -> WinapiResult<*mut c_void> {
    if ptr.is_null() {
        return Err(WinapiError::InputNullPtr());
    }
    if !(ptr as usize).is_multiple_of(std::mem::align_of::<AtomicPtr<c_void>>()) {
        return Err(WinapiError::MisalignedPointer(ptr as usize));
    }
    let atomic = unsafe { &*(ptr as *const AtomicPtr<c_void>) };
    Ok(atomic.load(Ordering::Acquire))
}

/// Write a 16-bit value to an address
///
/// Uses unaligned write to support addresses that aren't 2-byte aligned.
/// This is important when writing to arbitrary memory locations that may not
/// be properly aligned for u16 access.
pub fn safe_write_16(ptr: *mut c_void, data: u16) -> WinapiResult<()> {
    safe_write(ptr, data)
}

/// Write an 8-bit value to an address
///
/// Note: u8 writes don't have alignment requirements, but we use the safe_write
/// wrapper for consistency and to handle memory protection.
pub fn safe_write_8(ptr: *mut c_void, data: u8) -> WinapiResult<()> {
    safe_write(ptr, data)
}

/// Patch memory region with NOP instructions (0x90)
///
/// Fills a memory region with NOP opcodes, commonly used to disable code.
/// Uses unaligned writes for safety, though single-byte writes don't strictly
/// require alignment.
///
/// # Arguments
/// * `ptr` - Start address of the memory region to patch
/// * `size` - Number of bytes to fill with NOPs
///
/// # Safety
/// Caller must use correct memory range with valid pointer and size
pub unsafe fn patch_memory_nop(ptr: *mut c_void, size: usize) -> WinapiResult<()> {
    unsafe {
        with_virtual_protect(ptr, PAGE_EXECUTE_READWRITE, size, || {
            for i in 0..size {
                let target_ptr = (ptr as *mut u8).wrapping_add(i);
                // 0x90 is opcode for NOP instruction
                std::ptr::write_unaligned(target_ptr, 0x90);
            }
        })
    }?;

    flush_instructions_cache(ptr, size)?;

    Ok(())
}

/// Patches a relative CALL instruction to redirect to a new target address.
///
/// This function replaces the 4-byte offset in a CALL instruction (opcode 0xE8)
/// with a new offset that points to the specified function.
///
/// # Safety
/// Caller must be carefull with this function. Pointers must be valid and accesible.
///
/// # Memory Alignment
///
/// Uses `safe_write_32` which handles unaligned writes via `std::ptr::write_unaligned`.
/// This is critical because the offset field at `jump_src + 1` is often unaligned.
///
/// In Rust, direct pointer dereference requires proper alignment:
/// - `u32` must be at addresses divisible by 4 (ending in 0, 4, 8, C)
///
/// Example: When patching a CALL at 0x004742AC, the offset is at 0x004742AD (unaligned).
/// Direct write `*(ptr as *mut u32) = value` would cause undefined behavior and crash.
/// Solution: `std::ptr::write_unaligned(ptr as *mut u32, value)` works on any address.
///
/// # Arguments
/// * `jump_src` - Pointer to the CALL instruction to patch
/// * `func` - Pointer to the new function to call
///
/// # Platform Support
/// - **x86**: Full address space accessible via relative calls
/// - **x86_64**: Target must be within +/-2GB of source (i32 range limitation)
///
/// # Errors
/// Returns `WinapiError::CallTargetOutOfRange` if target is out of range on x86_64.
pub unsafe fn replace_call(jump_src: *mut c_void, func: *mut c_void) -> WinapiResult<()> {
    let jump_src_addr = jump_src as usize;
    let jump_tgt_addr = func as usize;

    // Calculate the address right after the CALL instruction (source + 5 bytes)
    let next_instruction = jump_src_addr.wrapping_add(5);

    // Calculate the signed distance from the end of the CALL to the target
    let distance = jump_tgt_addr.wrapping_sub(next_instruction) as isize;

    // On x86_64, verify the target is within +/-2GB range (i32::MIN to i32::MAX)
    // On x86, isize == i32 so this check always passes
    #[cfg(target_arch = "x86_64")]
    {
        if distance < i32::MIN as isize || distance > i32::MAX as isize {
            return Err(WinapiError::CallTargetOutOfRange {
                source_addr: jump_src_addr,
                target_addr: jump_tgt_addr,
                distance,
            });
        }
    }

    // Cast to u32 - safe because:
    // - On x86: isize is i32, always fits
    // - On x86_64: validated above
    let offset = distance as u32;

    // Write the new offset at jump_src + 1 (skip the 0xE8 CALL opcode byte)
    safe_write_32(unsafe { jump_src.add(1) }, offset)?;

    Ok(())
}

/// Patch memory with a RET instruction (0xC3)
///
/// Replaces code at the given address with a single RET (return) instruction,
/// effectively making the function return immediately.
///
/// # Arguments
/// * `ptr` - Address to patch with RET instruction
///
/// # Safety
/// Caller must ensure the pointer is valid and points to executable code.
pub unsafe fn patch_ret(ptr: *mut c_void) -> WinapiResult<()> {
    safe_write_8(ptr, 0xC3)?;
    flush_instructions_cache(ptr, 1)?;
    Ok(())
}

/// Patch memory with an unconditional JMP instruction (0xE9)
///
/// Completely replaces code at the source address with a 5-byte relative JMP
/// instruction that redirects execution to the target function. This is different
/// from inline hooking - it fully overwrites the original function without
/// preserving any original instructions.
///
/// The JMP instruction format is:
/// - Byte 0: 0xE9 (JMP opcode)
/// - Bytes 1-4: signed 32-bit relative offset
///
/// The offset is calculated as: `target - (source + 5)`
///
/// # Arguments
/// * `ptr` - Address to patch with JMP instruction (source)
/// * `target` - Address to jump to (destination function)
///
/// # Platform Support
/// - **x86**: Full address space accessible via relative jumps
/// - **x86_64**: Target must be within +/-2GB of source (i32 range limitation)
///
/// # Safety
/// Caller must ensure:
/// - Both pointers are valid and point to executable code
/// - The source location has at least 5 bytes available to overwrite
/// - Target is within valid jump range on x86_64
///
/// # Source
/// Based on C++ Heap-Replacer implementation:
/// <https://github.com/iranrmrf/Heap-Replacer/blob/master/heap_replacer/main/util.h#L112-L118>
pub unsafe fn patch_jmp(ptr: *mut c_void, target: *mut c_void) -> WinapiResult<()> {
    let jump_src_addr = ptr as usize;
    let jump_tgt_addr = target as usize;

    // Calculate the address right after the JMP instruction (source + 5 bytes)
    let next_instruction = jump_src_addr.wrapping_add(5);

    // Calculate the signed distance from the end of the JMP to the target
    let distance = jump_tgt_addr.wrapping_sub(next_instruction) as isize;

    // On x86_64, verify the target is within +/-2GB range (i32::MIN to i32::MAX)
    // On x86, isize == i32 so this check always passes
    #[cfg(target_arch = "x86_64")]
    {
        if distance < i32::MIN as isize || distance > i32::MAX as isize {
            return Err(WinapiError::CallTargetOutOfRange {
                source_addr: jump_src_addr,
                target_addr: jump_tgt_addr,
                distance,
            });
        }
    }

    // Create JMP instruction bytes
    let mut bytes = [0u8; 5];
    bytes[0] = 0xE9; // JMP opcode

    // Write the 32-bit relative offset in little-endian format
    let offset = distance as i32;
    bytes[1..5].copy_from_slice(&offset.to_le_bytes());

    // Apply the patch using our existing patch_bytes wrapper
    unsafe { patch_bytes(ptr, &bytes) }?;

    Ok(())
}

/// Patch a CALL instruction (5 bytes) with NOPs
///
/// Replaces a 5-byte CALL instruction with NOP instructions (0x90),
/// effectively disabling the function call.
///
/// # Arguments
/// * `ptr` - Address of the CALL instruction to patch
///
/// # Safety
/// Caller must ensure the pointer is valid and points to a CALL instruction.
pub unsafe fn patch_nop_call(ptr: *mut c_void) -> WinapiResult<()> {
    unsafe { patch_memory_nop(ptr, 5) }
}

/// Patch arbitrary bytes at a memory address
///
/// Writes arbitrary byte sequence to the specified address with proper
/// memory protection handling and instruction cache flushing.
///
/// # Arguments
/// * `ptr` - Address to patch
/// * `bytes` - Slice of bytes to write
///
/// # Safety
/// Caller must ensure the pointer and size are valid and the bytes represent
/// valid code/data for that location.
pub unsafe fn patch_bytes(ptr: *mut c_void, bytes: &[u8]) -> WinapiResult<()> {
    if bytes.is_empty() {
        return Err(WinapiError::ZeroSize());
    }

    unsafe {
        with_virtual_protect(ptr, PAGE_EXECUTE_READWRITE, bytes.len(), || {
            let dest = ptr as *mut u8;
            for (i, &byte) in bytes.iter().enumerate() {
                std::ptr::write_unaligned(dest.add(i), byte);
            }
        })
    }?;

    flush_instructions_cache(ptr, bytes.len())?;
    Ok(())
}

/// Check if the current process has the Large Address Aware (LAA) flag set
///
/// This reads the PE header from the current process's executable to determine
/// if the IMAGE_FILE_LARGE_ADDRESS_AWARE flag (0x0020) is set in the characteristics field.
///
/// On 32-bit Windows:
/// - Without LAA: Process limited to ~2GB address space
/// - With LAA: Process can use ~3GB address space
///
/// On 64-bit Windows:
/// - Without LAA: Process limited to ~2GB address space
/// - With LAA: Process can use full 4GB address space
///
/// # Returns
/// - `Ok(true)` if LAA flag is set
/// - `Ok(false)` if LAA flag is not set
/// - `Err` if unable to read PE header
pub fn is_large_address_aware() -> WinapiResult<bool> {
    // Get handle to the current process executable
    let module_handle = get_module_handle_a(None)?;
    let base_address = module_handle.as_ptr() as *const u8;

    // Read DOS header
    unsafe {
        // Check DOS signature "MZ" (0x5A4D)
        let dos_signature = std::ptr::read_unaligned(base_address as *const u16);
        if dos_signature != 0x5A4D {
            return Err(WinapiError::WindowsCore(windows::core::Error::from_win32()));
        }

        // Read e_lfanew offset (at offset 0x3C in DOS header)
        let e_lfanew_offset = std::ptr::read_unaligned(base_address.add(0x3C) as *const u32);

        // Get PE header address
        let pe_header = base_address.add(e_lfanew_offset as usize);

        // Check PE signature "PE\0\0" (0x00004550)
        let pe_signature = std::ptr::read_unaligned(pe_header as *const u32);
        if pe_signature != 0x00004550 {
            return Err(WinapiError::WindowsCore(windows::core::Error::from_win32()));
        }

        // Read Characteristics field from COFF File Header
        // PE signature is 4 bytes, then COFF header starts
        // Characteristics is at offset 18 (0x12) in COFF header
        let characteristics_offset = pe_header.add(4 + 0x12);
        let characteristics = std::ptr::read_unaligned(characteristics_offset as *const u16);

        // IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
        const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
        let is_laa = (characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0;

        Ok(is_laa)
    }
}

// ---------------------------------------------------------------------------
// Heap validation primitives
// ---------------------------------------------------------------------------

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetProcessHeaps(number_of_heaps: u32, process_heaps: *mut isize) -> u32;
    fn HeapValidate(heap: isize, flags: u32, mem: *const c_void) -> i32;
    fn HeapFree(heap: isize, flags: u32, mem: *mut c_void) -> i32;
    fn HeapSize(heap: isize, flags: u32, mem: *const c_void) -> usize;
    fn HeapReAlloc(heap: isize, flags: u32, mem: *mut c_void, bytes: usize) -> *mut c_void;
}

/// Maximum number of heap handles returned by `get_process_heaps`.
const MAX_PROCESS_HEAPS: usize = 64;

/// Enumerate all heap handles in the current process.
pub fn get_process_heaps() -> Vec<isize> {
    let mut handles = [0isize; MAX_PROCESS_HEAPS];
    let count = unsafe { GetProcessHeaps(MAX_PROCESS_HEAPS as u32, handles.as_mut_ptr()) } as usize;

    handles[..count.min(MAX_PROCESS_HEAPS)].to_vec()
}

/// Check if a pointer belongs to the given Windows heap.
///
/// Returns `true` if the heap recognizes the pointer as a valid allocation.
/// This is a relatively expensive call - use sparingly (fallback path only).
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn heap_validate(heap: isize, ptr: *const c_void) -> bool {
    unsafe { HeapValidate(heap, 0, ptr) != 0 }
}

/// Find which process heap owns the given pointer.
///
/// Iterates all process heaps and calls `HeapValidate` on each.
/// Returns the heap handle, or `None` if no heap claims the pointer.
pub fn find_owning_heap(heaps: &[isize], ptr: *const c_void) -> Option<isize> {
    heaps
        .iter()
        .find(|&&heap| heap_validate(heap, ptr))
        .copied()
}

/// Free a pointer through a specific Windows heap handle.
///
/// # Safety
/// The pointer must belong to the specified heap.
pub unsafe fn heap_free(heap: isize, ptr: *mut c_void) -> bool {
    unsafe { HeapFree(heap, 0, ptr) != 0 }
}

/// Query the allocated size of a pointer through a specific Windows heap.
///
/// Returns `usize::MAX` on error (same as `HeapSize` returning `(SIZE_T)-1`).
///
/// # Safety
/// The pointer must belong to the specified heap.
pub unsafe fn heap_size(heap: isize, ptr: *const c_void) -> usize {
    unsafe { HeapSize(heap, 0, ptr) }
}

/// Reallocate a pointer through a specific Windows heap.
///
/// Returns null on failure.
///
/// # Safety
/// The pointer must belong to the specified heap.
pub unsafe fn heap_realloc(heap: isize, ptr: *mut c_void, size: usize) -> *mut c_void {
    unsafe { HeapReAlloc(heap, 0, ptr, size) }
}

// ---------------------------------------------------------------------------
// Virtual memory primitives
// ---------------------------------------------------------------------------

/// Allocate virtual memory with the specified protection.
///
/// Wrapper around `VirtualAlloc`. Returns a valid pointer or an error.
/// If `address` is null, the system determines the allocation address.
pub fn virtual_alloc_rwx(size: usize) -> WinapiResult<*mut c_void> {
    let ptr = unsafe { VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) };

    if ptr.is_null() {
        return Err(WinapiError::WindowsCore(windows::core::Error::from_win32()));
    }

    Ok(ptr)
}

// ---------------------------------------------------------------------------
// Synchronization primitives
// ---------------------------------------------------------------------------

/// Wait result from `wait_for_single_object`.
pub enum WaitResult {
    /// The object was signaled (WAIT_OBJECT_0).
    Signaled,
    /// The timeout expired (WAIT_TIMEOUT).
    Timeout,
    /// Wait was abandoned.
    Abandoned,
    /// Wait failed with error code.
    Failed(u32),
}

/// Waits for a kernel object (semaphore, event, etc.) to be signaled.
/// `timeout_ms` = 0 for non-blocking probe, u32::MAX for infinite wait.
pub fn wait_for_single_object(handle: BorrowedHandle, timeout_ms: u32) -> WaitResult {
    let result = unsafe { WinWaitForSingleObject(handle.as_raw(), timeout_ms) };
    match result.0 {
        0 => WaitResult::Signaled,     // WAIT_OBJECT_0
        0x80 => WaitResult::Abandoned, // WAIT_ABANDONED
        0x102 => WaitResult::Timeout,  // WAIT_TIMEOUT
        _ => WaitResult::Failed(unsafe { GetLastError().0 }),
    }
}

/// Release a semaphore, incrementing its count by `release_count`.
pub fn release_semaphore(handle: BorrowedHandle, release_count: i32) -> WinapiResult<()> {
    unsafe { WinReleaseSemaphore(handle.as_raw(), release_count, None)? };
    Ok(())
}

/// Yield the current thread's time slice.
/// `millis` = 0 yields without sleeping.
pub fn sleep(millis: u32) {
    unsafe { WinSleep(millis) };
}

/// Returns the number of milliseconds since system start.
pub fn get_tick_count() -> u32 {
    unsafe { WinGetTickCount() }
}

/// Returns milliseconds since the current process was created.
pub fn process_elapsed_ms() -> WinapiResult<u64> {
    let process = unsafe { GetCurrentProcess() };
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();

    unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user)? };

    let now = unsafe { GetSystemTimeAsFileTime() };
    let creation = filetime_to_u64(creation);
    let now = filetime_to_u64(now);

    Ok(now.saturating_sub(creation) / 10_000)
}

/// Returns a high-resolution performance counter tick.
pub fn query_performance_counter() -> WinapiResult<i64> {
    let mut value = 0i64;
    unsafe { QueryPerformanceCounter(&mut value)? };
    Ok(value)
}

/// Returns the high-resolution performance counter frequency.
pub fn query_performance_frequency() -> WinapiResult<i64> {
    let mut value = 0i64;
    unsafe { QueryPerformanceFrequency(&mut value)? };
    Ok(value)
}

fn filetime_to_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64
}
