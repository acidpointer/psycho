//! Late-bound ABI calls into `psycho_engine_fixes.dll`.
//!
//! The helper is loaded by xNVSE after the game is already running. It must not
//! load or initialize the core DLL. Every call below is optional and resolves a
//! single named export only when the helper actually needs it.

use core::{
    ffi::c_void,
    mem::size_of,
    sync::atomic::{AtomicUsize, Ordering},
};

use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::winapi::{get_module_handle_w, get_proc_address},
};

const CORE_DLL: &str = "psycho_engine_fixes.dll";
const NOTIFY_EVENT_EXPORT: &str = "PsychoEngineFixes_NotifyEvent";
const QUERY_DASHBOARD_EXPORT: &str = "PsychoEngineFixes_QueryDashboard";
const REQUEST_DASHBOARD_REFRESH_EXPORT: &str = "PsychoEngineFixes_RequestDashboardRefresh";

// These ids mirror `psycho-engine-fixes/src/events.rs`.
pub(crate) const EVENT_DEFERRED_INIT: u32 = 1;
pub(crate) const EVENT_ON_FRAME_PRESENT: u32 = 6;

pub(crate) const DASHBOARD_ABI_VERSION: u32 = 2;
pub(crate) const DASHBOARD_FLAG_CORE_READY: u32 = 1 << 0;
pub(crate) const DASHBOARD_FLAG_PRE_CRT_BOUNDARY: u32 = 1 << 1;
pub(crate) const DASHBOARD_FLAG_VAS_VALID: u32 = 1 << 2;
pub(crate) const DASHBOARD_FLAG_BLOCK_SAMPLE_VALID: u32 = 1 << 3;
pub(crate) const DASHBOARD_FLAG_PROCESS_SAMPLE_VALID: u32 = 1 << 4;
pub(crate) const DASHBOARD_REFRESH_VAS: u32 = 1;

pub(crate) const DASHBOARD_FEATURE_DISPLAY: u64 = 1 << 0;
pub(crate) const DASHBOARD_FEATURE_SAVE_INTEGRITY: u64 = 1 << 1;
pub(crate) const DASHBOARD_FEATURE_TASK_GUARD: u64 = 1 << 2;
pub(crate) const DASHBOARD_FEATURE_PARALLEL_IO: u64 = 1 << 3;
pub(crate) const DASHBOARD_FEATURE_LOD_PREFETCH: u64 = 1 << 4;
pub(crate) const DASHBOARD_FEATURE_LOD_HANDOFF: u64 = 1 << 5;
pub(crate) const DASHBOARD_FEATURE_TREE_LIFETIME: u64 = 1 << 6;
pub(crate) const DASHBOARD_FEATURE_VERTEX_BUFFERS: u64 = 1 << 7;

type NotifyEventFn =
    unsafe extern "system" fn(kind: u32, data: *const u8, data_len: usize, bool_value: i32) -> i32;
type QueryDashboardFn = unsafe extern "system" fn(output: *mut DashboardSnapshot) -> i32;
type RequestDashboardRefreshFn = unsafe extern "system" fn(kind: u32) -> i32;

static NOTIFY_EVENT: AtomicUsize = AtomicUsize::new(0);
static QUERY_DASHBOARD: AtomicUsize = AtomicUsize::new(0);
static REQUEST_DASHBOARD_REFRESH: AtomicUsize = AtomicUsize::new(0);

/// Exact mirror of the core's version-2 plain-data dashboard ABI.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DashboardSnapshot {
    pub struct_size: u32,
    pub abi_version: u32,
    pub flags: u32,
    pub allocator_mode: u32,
    pub sample_time_ms: u64,
    pub process_sample_time_ms: u64,
    pub vas_sample_time_ms: u64,
    pub active_features: u64,
    pub process_rss_bytes: u64,
    pub process_peak_rss_bytes: u64,
    pub process_commit_bytes: u64,
    pub process_peak_commit_bytes: u64,
    pub process_page_faults: u64,
    pub vas_free_bytes: u64,
    pub vas_largest_hole_bytes: u64,
    pub vas_committed_bytes: u64,
    pub vas_reserved_bytes: u64,
    pub vas_holes: u64,
    pub pool_live_cells: u64,
    pub pool_committed_bytes: u64,
    pub pool_reserved_bytes: u64,
    pub pool_metadata_bytes: u64,
    pub pool_metadata_reserved_bytes: u64,
    pub block_slots: u64,
    pub block_live_allocations: u64,
    pub block_live_bytes: u64,
    pub block_committed_bytes: u64,
    pub direct_live_bytes: u64,
    pub direct_peak_bytes: u64,
    pub direct_max_allocation_bytes: u64,
    pub scrap_live_bytes: u64,
    pub pool_exhaustions: u64,
    pub block_overflows: u64,
    pub block_failures: u64,
    pub direct_allocations: u64,
    pub direct_frees: u64,
    pub direct_failures: u64,
    pub save_attempts: u64,
    pub save_commits: u64,
    pub save_aborts: u64,
    pub save_rejections: u64,
    pub task_dispatches: u64,
    pub task_rejections: u64,
    pub task_release_guards: u64,
    pub task_tombstones: u64,
    pub io_workers: u64,
    pub io_transactions: u64,
    pub io_contentions: u64,
    pub io_fallbacks: u64,
    pub lod_demands: u64,
    pub lod_early_demands: u64,
    pub lod_retained_demands: u64,
    pub lod_current_cells: u64,
    pub lod_current_references: u64,
    pub lod_stale_retirements_prevented: u64,
    pub speedtree_materializations: u64,
    pub speedtree_completions: u64,
    pub speedtree_materialization_contentions: u64,
    pub speedtree_compute_transactions: u64,
    pub speedtree_compute_contentions: u64,
    pub speedtree_waiters: u64,
    pub speedtree_max_materialization_wait_us: u64,
    pub speedtree_max_compute_wait_us: u64,
    pub dashboard_queries: u64,
    pub dashboard_query_last_us: u64,
    pub dashboard_query_max_us: u64,
    pub dashboard_vas_refreshes: u64,
    pub dashboard_vas_refresh_last_us: u64,
    pub dashboard_vas_refresh_max_us: u64,
}

const _: () = assert!(size_of::<DashboardSnapshot>() == 536);

impl DashboardSnapshot {
    fn request() -> Self {
        Self {
            struct_size: size_of::<Self>() as u32,
            abi_version: DASHBOARD_ABI_VERSION,
            allocator_mode: u32::MAX,
            ..Self::default()
        }
    }
}

/// Forward an xNVSE lifecycle event to the core DLL if it is available.
pub(crate) fn notify_event(kind: u32, data: *const u8, data_len: usize, bool_value: i32) -> bool {
    let Some(function) = resolve_notify_event() else {
        return false;
    };

    unsafe { function(kind, data, data_len, bool_value) != 0 }
}

/// Query a structured snapshot without loading or initializing the core DLL.
pub(crate) fn query_dashboard() -> Option<DashboardSnapshot> {
    let function = resolve_query_dashboard()?;
    let mut snapshot = DashboardSnapshot::request();
    if unsafe { function(&mut snapshot) } == 0 {
        return None;
    }
    (snapshot.abi_version == DASHBOARD_ABI_VERSION
        && snapshot.struct_size as usize >= size_of::<DashboardSnapshot>())
    .then_some(snapshot)
}

pub(crate) fn has_dashboard_api() -> bool {
    resolve_query_dashboard().is_some() && resolve_request_dashboard_refresh().is_some()
}

pub(crate) fn request_dashboard_refresh(kind: u32) -> bool {
    let Some(function) = resolve_request_dashboard_refresh() else {
        return false;
    };
    unsafe { function(kind) != 0 }
}

fn resolve_notify_event() -> Option<NotifyEventFn> {
    let ptr = resolve_cached(&NOTIFY_EVENT, NOTIFY_EVENT_EXPORT)?;

    // The export name and ABI are shared with the core DLL's definition file.
    unsafe { FnPtr::<NotifyEventFn>::from_raw(ptr as *mut c_void) }
        .ok()
        .map(|function| function.as_fn())
}

fn resolve_query_dashboard() -> Option<QueryDashboardFn> {
    let ptr = resolve_cached(&QUERY_DASHBOARD, QUERY_DASHBOARD_EXPORT)?;

    unsafe { FnPtr::<QueryDashboardFn>::from_raw(ptr as *mut c_void) }
        .ok()
        .map(|function| function.as_fn())
}

fn resolve_request_dashboard_refresh() -> Option<RequestDashboardRefreshFn> {
    let ptr = resolve_cached(&REQUEST_DASHBOARD_REFRESH, REQUEST_DASHBOARD_REFRESH_EXPORT)?;

    unsafe { FnPtr::<RequestDashboardRefreshFn>::from_raw(ptr as *mut c_void) }
        .ok()
        .map(|function| function.as_fn())
}

fn resolve_cached(cache: &AtomicUsize, export_name: &str) -> Option<usize> {
    let cached = cache.load(Ordering::Acquire);
    if cached != 0 {
        return Some(cached);
    }

    // Use GetModuleHandle only. If the core was not loaded by syringe,
    // the helper must stay passive instead of loading it from the xNVSE path.
    let module = get_module_handle_w(Some(CORE_DLL)).ok()?;
    let proc = get_proc_address(module, export_name).ok()? as usize;

    cache.store(proc, Ordering::Release);
    Some(proc)
}

#[cfg(test)]
mod tests {
    use super::{DASHBOARD_ABI_VERSION, DashboardSnapshot};
    use std::mem::size_of;

    #[test]
    fn dashboard_request_advertises_exact_storage() {
        let request = DashboardSnapshot::request();
        assert_eq!(request.abi_version, DASHBOARD_ABI_VERSION);
        assert_eq!(request.struct_size as usize, size_of::<DashboardSnapshot>());
    }
}
