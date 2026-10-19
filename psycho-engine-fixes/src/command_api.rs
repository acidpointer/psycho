//! Command ABI for late host adapters.
//!
//! The xNVSE helper owns command registration. The core owns command behavior
//! and returns text through a caller-owned buffer so no allocation crosses DLLs.
//! Dashboard queries likewise use an exact-version, fixed-width snapshot. ABI
//! revisions preserve published prefixes, while exact version and size checks
//! make mixed helper/core installations fail unavailable.

use std::{mem::size_of, ptr};

use libmimalloc::process_info::MiMallocProcessInfo;

use crate::mods::{
    engine_fixes,
    heap_replacer::{
        AllocatorMode, current_mode,
        gheap::{allocator, block, pool, va_alloc, vas, watchdog},
        mem_stats,
    },
};

const COMMAND_INFO: u32 = 1;

#[derive(Clone, Copy)]
enum Command {
    Info,
}

impl Command {
    fn from_id(id: u32) -> Option<Self> {
        match id {
            COMMAND_INFO => Some(Self::Info),
            _ => None,
        }
    }

    fn run(self) -> CommandResponse {
        match self {
            Self::Info => CommandResponse::text(mem_stats::MemStats::detailed_report()),
        }
    }
}

struct CommandResponse {
    text: String,
}

impl CommandResponse {
    fn text(text: String) -> Self {
        Self { text }
    }

    unsafe fn write_to(self, output: &mut CommandOutput) {
        let bytes = self.text.as_bytes();
        output.written = bytes.len();
        output.flags = 0;
        output.result = 0.0;

        if !output.text.is_null() && output.text_len > 0 {
            let copy_len = bytes.len().min(output.text_len);
            unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), output.text, copy_len) };
        }
    }
}

/// Caller-owned output buffer for `PsychoEngineFixes_RunCommand`.
///
/// `written` is always the full response length, even when `text_len` is too
/// small and the text is truncated.
#[repr(C)]
pub struct CommandOutput {
    pub text: *mut u8,
    pub text_len: usize,
    pub written: usize,
    pub result: f64,
    pub flags: u32,
}

/// Exact dashboard structure revision shared with the late-bound helper.
pub const DASHBOARD_ABI_VERSION: u32 = 6;

pub const DASHBOARD_FLAG_CORE_READY: u32 = 1 << 0;
pub const DASHBOARD_FLAG_PRE_CRT_BOUNDARY: u32 = 1 << 1;
pub const DASHBOARD_FLAG_VAS_VALID: u32 = 1 << 2;
pub const DASHBOARD_FLAG_BLOCK_SAMPLE_VALID: u32 = 1 << 3;
pub const DASHBOARD_FLAG_PROCESS_SAMPLE_VALID: u32 = 1 << 4;

const DASHBOARD_REFRESH_VAS: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct DashboardHeader {
    struct_size: u32,
    abi_version: u32,
}

/// Versioned, caller-owned dashboard snapshot.
///
/// Every field is a fixed-width scalar so no Rust allocation, pointer, or
/// enum representation crosses the helper/core DLL boundary.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DashboardSnapshot {
    pub struct_size: u32,
    pub abi_version: u32,
    pub flags: u32,
    pub allocator_mode: u32,
    pub sample_time_ms: u64,
    pub process_sample_time_ms: u64,
    pub vas_sample_time_ms: u64,
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
    /// Invalid encounter-zone forms rejected before changed-form RTTI.
    pub encounter_zone_load_rejections: u64,
    /// Invalid encounter-zone results rejected by the shared resolver hook.
    pub encounter_zone_access_rejections: u64,
    /// Exact encounter-zone sources removed or cleared at runtime.
    pub encounter_zone_repairs: u64,
    /// False-predicate retirements sent through the canonical native remover.
    pub cell_render_forced_cleanups: u64,
    /// Post-install replacements of the active retirement dispatch block.
    pub cell_render_patch_ownership_losses: u64,
    /// Occlusion planes: configured (1) or off (0).
    pub occlusion_configured: u64,
    /// Occlusion planes: activated after `DeferredInit` (1) or not (0).
    pub occlusion_ready: u64,
    /// Occlusion planes: a cell walk is in flight (1) or idle (0).
    pub occlusion_generation_running: u64,
    /// Occlusion planes: configured loaded-grid radius.
    pub occlusion_grid_radius: u64,
    /// Occlusion planes: shared injected-plane budget.
    pub occlusion_max_per_cell: u64,
    /// Occlusion planes: planes currently tracked in the engine list.
    pub occlusion_tracked_planes: u64,
    /// Occlusion planes: tracked planes the engine admitted for the camera.
    pub occlusion_active_planes: u64,
    /// Occlusion planes: cells in the persistent plane cache.
    pub occlusion_cached_cells: u64,
    /// Occlusion planes: current cell kind (0 none, 1 interior, 2 exterior).
    pub occlusion_cell_kind: u64,
    /// Occlusion planes: interior cell `FormID` (0 for exterior).
    pub occlusion_cell_form_id: u64,
    /// Occlusion planes: exterior cell grid X (sign-extended).
    pub occlusion_cell_x: i64,
    /// Occlusion planes: exterior cell grid Y (sign-extended).
    pub occlusion_cell_y: i64,
    /// Occlusion planes: exterior worldspace `FormID` (0 for interior).
    pub occlusion_worldspace_form_id: u64,
    /// Occlusion planes: completed cell rebuilds this session.
    pub occlusion_rebuilds: u64,
    /// Occlusion planes: wall time of the last completed generation (ms).
    pub occlusion_last_generation_ms: u64,
    /// Occlusion planes: planes created this session.
    pub occlusion_planes_created: u64,
    /// Occlusion planes: planes removed this session.
    pub occlusion_planes_removed: u64,
    /// Occlusion planes: rebuilds served from the persistent cache.
    pub occlusion_cache_hits: u64,
    /// Occlusion planes: candidates offered to the last rebuild.
    pub occlusion_last_candidates: u64,
    /// Occlusion planes: planes selected by the last rebuild.
    pub occlusion_last_selected: u64,
    /// Occlusion planes: planes created by the last rebuild.
    pub occlusion_last_created: u64,
    /// Occlusion planes: planes removed by the last rebuild.
    pub occlusion_last_removed: u64,
    /// Occlusion planes: last rebuild came from the cache (1) or regenerated (0).
    pub occlusion_last_from_cache: u64,
}

const _: () = assert!(size_of::<DashboardSnapshot>() == 704);

impl Default for DashboardSnapshot {
    fn default() -> Self {
        Self {
            struct_size: size_of::<Self>() as u32,
            abi_version: DASHBOARD_ABI_VERSION,
            flags: 0,
            allocator_mode: u32::MAX,
            sample_time_ms: 0,
            process_sample_time_ms: 0,
            vas_sample_time_ms: 0,
            process_rss_bytes: 0,
            process_peak_rss_bytes: 0,
            process_commit_bytes: 0,
            process_peak_commit_bytes: 0,
            process_page_faults: 0,
            vas_free_bytes: 0,
            vas_largest_hole_bytes: 0,
            vas_committed_bytes: 0,
            vas_reserved_bytes: 0,
            vas_holes: 0,
            pool_live_cells: 0,
            pool_committed_bytes: 0,
            pool_reserved_bytes: 0,
            pool_metadata_bytes: 0,
            pool_metadata_reserved_bytes: 0,
            block_slots: 0,
            block_live_allocations: 0,
            block_live_bytes: 0,
            block_committed_bytes: 0,
            direct_live_bytes: 0,
            direct_peak_bytes: 0,
            direct_max_allocation_bytes: 0,
            scrap_live_bytes: 0,
            pool_exhaustions: 0,
            block_overflows: 0,
            block_failures: 0,
            direct_allocations: 0,
            direct_frees: 0,
            direct_failures: 0,
            save_attempts: 0,
            save_commits: 0,
            save_aborts: 0,
            save_rejections: 0,
            task_dispatches: 0,
            task_rejections: 0,
            task_release_guards: 0,
            task_tombstones: 0,
            io_workers: 0,
            io_transactions: 0,
            io_contentions: 0,
            io_fallbacks: 0,
            lod_demands: 0,
            lod_early_demands: 0,
            lod_retained_demands: 0,
            lod_current_cells: 0,
            lod_current_references: 0,
            lod_stale_retirements_prevented: 0,
            speedtree_materializations: 0,
            speedtree_completions: 0,
            speedtree_materialization_contentions: 0,
            speedtree_compute_transactions: 0,
            speedtree_compute_contentions: 0,
            speedtree_waiters: 0,
            speedtree_max_materialization_wait_us: 0,
            speedtree_max_compute_wait_us: 0,
            encounter_zone_load_rejections: 0,
            encounter_zone_access_rejections: 0,
            encounter_zone_repairs: 0,
            cell_render_forced_cleanups: 0,
            cell_render_patch_ownership_losses: 0,
            occlusion_configured: 0,
            occlusion_ready: 0,
            occlusion_generation_running: 0,
            occlusion_grid_radius: 0,
            occlusion_max_per_cell: 0,
            occlusion_tracked_planes: 0,
            occlusion_active_planes: 0,
            occlusion_cached_cells: 0,
            occlusion_cell_kind: 0,
            occlusion_cell_form_id: 0,
            occlusion_cell_x: 0,
            occlusion_cell_y: 0,
            occlusion_worldspace_form_id: 0,
            occlusion_rebuilds: 0,
            occlusion_last_generation_ms: 0,
            occlusion_planes_created: 0,
            occlusion_planes_removed: 0,
            occlusion_cache_hits: 0,
            occlusion_last_candidates: 0,
            occlusion_last_selected: 0,
            occlusion_last_created: 0,
            occlusion_last_removed: 0,
            occlusion_last_from_cache: 0,
        }
    }
}

/// Run a diagnostic/control command requested by a host adapter.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn PsychoEngineFixes_RunCommand(
    command: u32,
    output: *mut CommandOutput,
) -> i32 {
    if output.is_null() {
        return 0;
    }

    if !crate::entry::is_initialized() {
        return 0;
    }

    let Some(command) = Command::from_id(command) else {
        return 0;
    };

    unsafe { command.run().write_to(&mut *output) };
    1
}

/// Fill a structured diagnostics snapshot for an already-loaded host adapter.
///
/// This may be called from the helper's background sampling thread. It does no
/// engine mutation and never waits for the gheap block lock.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn PsychoEngineFixes_QueryDashboard(
    output: *mut DashboardSnapshot,
) -> i32 {
    if output.is_null() || !crate::entry::is_initialized() {
        return 0;
    }

    // Read only the mandatory prefix before accepting the caller's advertised
    // storage size. This keeps malformed or older callers from making us read
    // the entire version-1 payload merely to reject it.
    let header = unsafe { ptr::read(output.cast::<DashboardHeader>()) };
    if !dashboard_header_supported(&header) {
        return 0;
    }

    let mode = current_mode();
    let process = dashboard_process_snapshot(mode);
    let engine = engine_fixes::dashboard_counters();
    let occlusion = crate::mods::perf::occlusion_dashboard_counters();
    let mut snapshot = DashboardSnapshot {
        flags: DASHBOARD_FLAG_CORE_READY,
        allocator_mode: mode.map_or(u32::MAX, |mode| match mode {
            AllocatorMode::Disabled => 0,
            AllocatorMode::ScrapHeap => 1,
            AllocatorMode::GheapAndScrapHeap => 2,
        }),
        sample_time_ms: u64::from(libpsycho::os::windows::winapi::get_tick_count()),
        pool_live_cells: pool::live_cells() as u64,
        pool_committed_bytes: pool::committed_bytes() as u64,
        pool_reserved_bytes: pool::reserved_bytes() as u64,
        pool_metadata_bytes: pool::metadata_bytes() as u64,
        pool_metadata_reserved_bytes: pool::metadata_reserved_bytes() as u64,
        direct_live_bytes: va_alloc::live_bytes(),
        direct_peak_bytes: va_alloc::peak_live_bytes(),
        direct_max_allocation_bytes: va_alloc::max_allocation_bytes(),
        scrap_live_bytes: mem_stats::global().scrap_heap_allocated(),
        pool_exhaustions: pool::exhaust_count(),
        block_overflows: allocator::block_overflow_count(),
        block_failures: block::fail_count(),
        direct_allocations: va_alloc::alloc_count(),
        direct_frees: va_alloc::free_count(),
        direct_failures: va_alloc::fail_count(),
        save_attempts: engine.save_attempts,
        save_commits: engine.save_commits,
        save_aborts: engine.save_aborts,
        save_rejections: engine.save_rejections,
        task_dispatches: engine.task_dispatches,
        task_rejections: engine.task_rejections,
        task_release_guards: engine.task_release_guards,
        task_tombstones: engine.task_tombstones,
        io_workers: engine.io_workers,
        io_transactions: engine.io_transactions,
        io_contentions: engine.io_contentions,
        io_fallbacks: engine.io_fallbacks,
        lod_demands: engine.lod_demands,
        lod_early_demands: engine.lod_early_demands,
        lod_retained_demands: engine.lod_retained_demands,
        lod_current_cells: engine.lod_current_cells,
        lod_current_references: engine.lod_current_references,
        lod_stale_retirements_prevented: engine.lod_stale_retirements_prevented,
        speedtree_materializations: engine.speedtree_materializations,
        speedtree_completions: engine.speedtree_completions,
        speedtree_materialization_contentions: engine.speedtree_materialization_contentions,
        speedtree_compute_transactions: engine.speedtree_compute_transactions,
        speedtree_compute_contentions: engine.speedtree_compute_contentions,
        speedtree_waiters: engine.speedtree_waiters,
        speedtree_max_materialization_wait_us: engine.speedtree_max_materialization_wait_us,
        speedtree_max_compute_wait_us: engine.speedtree_max_compute_wait_us,
        encounter_zone_load_rejections: engine.encounter_zone_load_rejections,
        encounter_zone_access_rejections: engine.encounter_zone_access_rejections,
        encounter_zone_repairs: engine.encounter_zone_repairs,
        cell_render_forced_cleanups: engine.cell_render_forced_cleanups,
        cell_render_patch_ownership_losses: engine.cell_render_patch_ownership_losses,
        occlusion_configured: occlusion.configured,
        occlusion_ready: occlusion.ready,
        occlusion_generation_running: occlusion.generation_running,
        occlusion_grid_radius: occlusion.grid_radius,
        occlusion_max_per_cell: occlusion.max_per_cell,
        occlusion_tracked_planes: occlusion.tracked,
        occlusion_active_planes: occlusion.active,
        occlusion_cached_cells: occlusion.cached_cells,
        occlusion_cell_kind: occlusion.cell_kind,
        occlusion_cell_form_id: occlusion.cell_form_id,
        occlusion_cell_x: occlusion.cell_x,
        occlusion_cell_y: occlusion.cell_y,
        occlusion_worldspace_form_id: occlusion.worldspace_form_id,
        occlusion_rebuilds: occlusion.rebuilds,
        occlusion_last_generation_ms: occlusion.last_generation_ms,
        occlusion_planes_created: occlusion.planes_created,
        occlusion_planes_removed: occlusion.planes_removed,
        occlusion_cache_hits: occlusion.cache_hits,
        occlusion_last_candidates: occlusion.last_candidates,
        occlusion_last_selected: occlusion.last_selected,
        occlusion_last_created: occlusion.last_created,
        occlusion_last_removed: occlusion.last_removed,
        occlusion_last_from_cache: occlusion.last_from_cache,
        ..DashboardSnapshot::default()
    };

    if let Some(process) = process {
        snapshot.flags |= DASHBOARD_FLAG_PROCESS_SAMPLE_VALID;
        snapshot.process_sample_time_ms = process.sample_time_ms;
        snapshot.process_rss_bytes = process.rss;
        snapshot.process_peak_rss_bytes = process.peak_rss;
        snapshot.process_commit_bytes = process.commit;
        snapshot.process_peak_commit_bytes = process.peak_commit;
        snapshot.process_page_faults = process.page_faults;
    }

    if crate::entry::has_pre_crt_startup_boundary() {
        snapshot.flags |= DASHBOARD_FLAG_PRE_CRT_BOUNDARY;
    }
    if let Some((summary, sampled_at_ms)) = vas::cached() {
        snapshot.flags |= DASHBOARD_FLAG_VAS_VALID;
        snapshot.vas_sample_time_ms = u64::from(sampled_at_ms);
        snapshot.vas_free_bytes = summary.total_free as u64;
        snapshot.vas_largest_hole_bytes = summary.largest_free as u64;
        snapshot.vas_committed_bytes = summary.total_commit as u64;
        snapshot.vas_reserved_bytes = summary.total_reserve as u64;
        snapshot.vas_holes = u64::from(summary.holes);
    }
    if let Some(blocks) = block::try_snapshot() {
        snapshot.flags |= DASHBOARD_FLAG_BLOCK_SAMPLE_VALID;
        snapshot.block_slots = blocks.slots as u64;
        snapshot.block_live_allocations = blocks.live_allocations as u64;
        snapshot.block_live_bytes = blocks.live_bytes as u64;
        snapshot.block_committed_bytes = blocks.committed_bytes as u64;
    }

    unsafe { ptr::write(output, snapshot) };
    1
}

/// Run an expensive dashboard refresh on the helper's sampling worker.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn PsychoEngineFixes_RequestDashboardRefresh(kind: u32) -> i32 {
    if !crate::entry::is_initialized() || kind != DASHBOARD_REFRESH_VAS {
        return 0;
    }

    i32::from(vas::refresh_for_dashboard().is_some())
}

fn dashboard_process_snapshot(mode: Option<AllocatorMode>) -> Option<watchdog::ProcessSnapshot> {
    if mode == Some(AllocatorMode::GheapAndScrapHeap) {
        return watchdog::process_snapshot();
    }

    let process = MiMallocProcessInfo::get();
    Some(watchdog::ProcessSnapshot {
        sample_time_ms: u64::from(libpsycho::os::windows::winapi::get_tick_count()),
        rss: process.get_current_rss() as u64,
        peak_rss: process.get_peak_rss() as u64,
        commit: process.get_current_commit() as u64,
        peak_commit: process.get_peak_commit() as u64,
        page_faults: process.get_page_faults() as u64,
    })
}

fn dashboard_header_supported(header: &DashboardHeader) -> bool {
    header.struct_size as usize >= size_of::<DashboardSnapshot>()
        && header.abi_version == DASHBOARD_ABI_VERSION
}

#[cfg(test)]
mod tests {
    use super::{
        DASHBOARD_ABI_VERSION, DashboardHeader, DashboardSnapshot, dashboard_header_supported,
    };
    use std::mem::size_of;

    #[test]
    fn dashboard_abi_requires_matching_version_and_complete_storage() {
        let snapshot = DashboardSnapshot::default();
        let valid = DashboardHeader {
            struct_size: snapshot.struct_size,
            abi_version: snapshot.abi_version,
        };
        assert!(dashboard_header_supported(&valid));

        let mut old = valid;
        old.struct_size -= 8;
        assert!(!dashboard_header_supported(&old));

        let mut future = valid;
        future.abi_version = DASHBOARD_ABI_VERSION + 1;
        assert!(!dashboard_header_supported(&future));
        assert_eq!(
            snapshot.struct_size as usize,
            size_of::<DashboardSnapshot>()
        );
    }
}
