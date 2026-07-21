//! Command ABI for late host adapters.
//!
//! The xNVSE helper owns command registration. The core owns command behavior
//! and returns text through a caller-owned buffer so no allocation crosses DLLs.

use std::{mem::size_of, ptr};

use libmimalloc::process_info::MiMallocProcessInfo;

use crate::mods::{
    engine_fixes,
    heap_replacer::{
        AllocatorMode, current_mode,
        gheap::{allocator, block, pool, va_alloc, vas},
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

pub const DASHBOARD_ABI_VERSION: u32 = 1;

pub const DASHBOARD_FLAG_CORE_READY: u32 = 1 << 0;
pub const DASHBOARD_FLAG_PRE_CRT_BOUNDARY: u32 = 1 << 1;
pub const DASHBOARD_FLAG_VAS_VALID: u32 = 1 << 2;
pub const DASHBOARD_FLAG_BLOCK_SAMPLE_VALID: u32 = 1 << 3;

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
    pub reserved: [u64; 8],
}

const _: () = assert!(size_of::<DashboardSnapshot>() == 472);

impl Default for DashboardSnapshot {
    fn default() -> Self {
        Self {
            struct_size: size_of::<Self>() as u32,
            abi_version: DASHBOARD_ABI_VERSION,
            flags: 0,
            allocator_mode: u32::MAX,
            sample_time_ms: 0,
            active_features: 0,
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
            reserved: [0; 8],
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

    let process = MiMallocProcessInfo::get();
    let engine = engine_fixes::dashboard_counters();
    let mut snapshot = DashboardSnapshot {
        flags: DASHBOARD_FLAG_CORE_READY,
        allocator_mode: current_mode().map_or(u32::MAX, |mode| match mode {
            AllocatorMode::Disabled => 0,
            AllocatorMode::ScrapHeap => 1,
            AllocatorMode::GheapAndScrapHeap => 2,
        }),
        sample_time_ms: u64::from(libpsycho::os::windows::winapi::get_tick_count()),
        active_features: engine.active_features,
        process_rss_bytes: process.get_current_rss() as u64,
        process_peak_rss_bytes: process.get_peak_rss() as u64,
        process_commit_bytes: process.get_current_commit() as u64,
        process_peak_commit_bytes: process.get_peak_commit() as u64,
        process_page_faults: process.get_page_faults() as u64,
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
        ..DashboardSnapshot::default()
    };

    if crate::entry::has_pre_crt_startup_boundary() {
        snapshot.flags |= DASHBOARD_FLAG_PRE_CRT_BOUNDARY;
    }
    if let Some(summary) = vas::sample() {
        snapshot.flags |= DASHBOARD_FLAG_VAS_VALID;
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
