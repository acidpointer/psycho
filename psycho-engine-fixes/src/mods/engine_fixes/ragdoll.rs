//! Guard for not-ready or internally mismatched bhkRagdollController bone tables.
//!
//! The crash at `0x00A6DF48` is not an OOM. Ghidra shows the path:
//!
//! `FUN_00C7D810 -> FUN_00C79680 -> FUN_00C74DD0 -> FUN_00A6DF40`
//!
//! `FUN_00C79680` reads `*(ragdoll + 0xA4)[boneIndex] + 0x34`.
//! During cell attach a ragdoll can have a valid hierarchy at `+0x2A4`
//! while the bone pointer table at `+0xA4` still contains NULL entries.
//! `FUN_00C75B40` and `FUN_00C79A50` also write controller transforms back
//! into `+0xA4` bone entries, so stale-but-readable tables can become silent
//! deformation bugs instead of crashes. Vanilla never checks this; with clean
//! gheap memory the latent bug becomes a reliable NULL+0x34 crash. The update
//! wrappers are void best-effort frame/update helpers, so we skip not-ready or
//! mismatched frames and let the next valid controller state retry.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use libc::c_void;
use windows::Win32::System::Memory::{MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS};

use libpsycho::os::windows::winapi::virtual_query;

use crate::mods::diagnostics;

use super::statics;

const LOW_POINTER_LIMIT: usize = 0x10000;
const RAGDOLL_MIN_SIZE: usize = RAGDOLL_HIERARCHY_OFFSET + 4;
const RAGDOLL_SCENE_ROOT_OFFSET: usize = 0x48;
const RAGDOLL_TRANSFORM_ROOT_OFFSET: usize = 0x58;
const RAGDOLL_SKELETON_STATE_OFFSET: usize = 0x88;
const RAGDOLL_TRANSFORM_BUFFER_OFFSET: usize = 0x94;
const RAGDOLL_TRANSFORM_COUNT_OFFSET: usize = 0x98;
const RAGDOLL_BONE_TABLE_OFFSET: usize = 0xA4;
const RAGDOLL_BONE_TABLE_COUNT_OFFSET: usize = 0xA8;
const RAGDOLL_BONE_TABLE_CAPACITY_OFFSET: usize = 0xAC;
const RAGDOLL_HIERARCHY_OFFSET: usize = 0x2A4;
const TRANSFORM_ROOT_MIN_SIZE: usize = 0x9C;
const SCENE_ROOT_MIN_SIZE: usize = 0x30;
const HIERARCHY_MIN_SIZE: usize = 0x10;
const BONE_GROUP_COUNT_OFFSET: usize = 0x1C;
const BONE_GROUP_MIN_SIZE: usize = BONE_GROUP_COUNT_OFFSET + 4;
const MAX_BONES: usize = 512;

static SKIPPED_UPDATES: AtomicU64 = AtomicU64::new(0);
static GUARD_CALLS: AtomicU64 = AtomicU64::new(0);
static GUARD_SKIPS: AtomicU64 = AtomicU64::new(0);
static GUARD_VIRTUAL_QUERIES: AtomicU64 = AtomicU64::new(0);
static GUARD_TOTAL_US: AtomicU64 = AtomicU64::new(0);
static GUARD_MAX_US: AtomicU64 = AtomicU64::new(0);
static GUARD_LAST_REPORT_MS: AtomicU32 = AtomicU32::new(0);
static DIAGNOSTIC_GUARD_CALLS: AtomicU64 = AtomicU64::new(0);
static DIAGNOSTIC_GUARD_SKIPS: AtomicU64 = AtomicU64::new(0);

const PERF_REPORT_MS: u32 = 5_000;

pub(super) struct DiagnosticCounters {
    pub calls: u64,
    pub skips: u64,
}

pub(super) fn take_diagnostic_counters() -> DiagnosticCounters {
    DiagnosticCounters {
        calls: DIAGNOSTIC_GUARD_CALLS.swap(0, Ordering::AcqRel),
        skips: DIAGNOSTIC_GUARD_SKIPS.swap(0, Ordering::AcqRel),
    }
}

pub unsafe extern "thiscall" fn hook_ragdoll_bone_transform_update(ragdoll: *mut c_void) {
    let original = match statics::RAGDOLL_BONE_TRANSFORM_UPDATE_HOOK.original() {
        Ok(original) => original,
        Err(e) => {
            log::error!(
                "[RAGDOLL] FUN_00C7D810 original trampoline missing: {:?}",
                e
            );
            return;
        }
    };

    let timer = diagnostics::Stopwatch::start_if_hitch_profiling();
    if let Err(reason) = ragdoll_ready_for_bone_update(ragdoll) {
        record_guard_sample(timer, true);
        log_skip("bone-transform", reason, ragdoll);
        return;
    }
    record_guard_sample(timer, false);

    unsafe { original(ragdoll) };
}

pub unsafe extern "thiscall" fn hook_ragdoll_alternate_update(ragdoll: *mut c_void, arg: u32) {
    let original = match statics::RAGDOLL_ALTERNATE_UPDATE_HOOK.original() {
        Ok(original) => original,
        Err(e) => {
            log::error!(
                "[RAGDOLL] FUN_00C7D630 original trampoline missing: {:?}",
                e
            );
            return;
        }
    };

    let timer = diagnostics::Stopwatch::start_if_hitch_profiling();
    if let Err(reason) = ragdoll_ready_for_bone_update(ragdoll) {
        record_guard_sample(timer, true);
        log_skip("alternate", reason, ragdoll);
        return;
    }
    record_guard_sample(timer, false);

    unsafe { original(ragdoll, arg) };
}

pub unsafe extern "fastcall" fn hook_ragdoll_save_load_writeback(ragdoll: *mut c_void) {
    let original = match statics::RAGDOLL_SAVE_LOAD_WRITEBACK_HOOK.original() {
        Ok(original) => original,
        Err(e) => {
            log::error!(
                "[RAGDOLL] FUN_00C75B40 original trampoline missing: {:?}",
                e
            );
            return;
        }
    };

    let timer = diagnostics::Stopwatch::start_if_hitch_profiling();
    if let Err(reason) = ragdoll_ready_for_bone_update(ragdoll) {
        record_guard_sample(timer, true);
        log_skip("save-load-writeback", reason, ragdoll);
        return;
    }
    record_guard_sample(timer, false);

    unsafe { original(ragdoll) };
}

fn ragdoll_ready_for_bone_update(ragdoll: *mut c_void) -> Result<(), &'static str> {
    if ragdoll.is_null() {
        return Err("null-ragdoll");
    }

    let mut cache = ReadableRegionCache::default();
    let base = ragdoll as usize;
    if !is_readable_cached(&mut cache, base, RAGDOLL_MIN_SIZE) {
        return Err("bad-ragdoll");
    }

    let scene_root = unsafe { read_u32_unchecked(base + RAGDOLL_SCENE_ROOT_OFFSET) };
    if scene_root == 0 || !is_readable_cached(&mut cache, scene_root as usize, SCENE_ROOT_MIN_SIZE)
    {
        return Err("bad-scene-root");
    }

    let transform_root = unsafe { read_u32_unchecked(base + RAGDOLL_TRANSFORM_ROOT_OFFSET) };
    if transform_root == 0
        || !is_readable_cached(&mut cache, transform_root as usize, TRANSFORM_ROOT_MIN_SIZE)
    {
        return Err("bad-transform-root");
    }

    let hierarchy = unsafe { read_u32_unchecked(base + RAGDOLL_HIERARCHY_OFFSET) };
    if hierarchy == 0 || !is_readable_cached(&mut cache, hierarchy as usize, HIERARCHY_MIN_SIZE) {
        return Err("bad-hierarchy");
    }

    let bone_group = unsafe { read_u32_unchecked(hierarchy as usize + 0x0C) };
    if bone_group == 0 || !is_readable_cached(&mut cache, bone_group as usize, BONE_GROUP_MIN_SIZE)
    {
        return Err("bad-bone-group");
    }

    let bone_count =
        unsafe { read_u32_unchecked(bone_group as usize + BONE_GROUP_COUNT_OFFSET) } as usize;
    if bone_count > MAX_BONES {
        return Err("bad-bone-count");
    }

    let bone_table_count =
        unsafe { read_u32_unchecked(base + RAGDOLL_BONE_TABLE_COUNT_OFFSET) } as usize;
    if bone_table_count != bone_count {
        return Err("bone-table-count-mismatch");
    }

    let bone_table_capacity =
        unsafe { read_u32_unchecked(base + RAGDOLL_BONE_TABLE_CAPACITY_OFFSET) } as usize;
    if bone_table_capacity < bone_table_count || bone_table_capacity > MAX_BONES {
        return Err("bad-bone-table-capacity");
    }

    let transform_count =
        unsafe { read_u32_unchecked(base + RAGDOLL_TRANSFORM_COUNT_OFFSET) } as usize;
    if transform_count != bone_count {
        return Err("transform-count-mismatch");
    }

    if bone_count == 0 {
        return Ok(());
    }

    let bone_table = unsafe { read_u32_unchecked(base + RAGDOLL_BONE_TABLE_OFFSET) };
    let table_len = bone_count
        .checked_mul(core::mem::size_of::<u32>())
        .ok_or("bad-bone-count")?;
    if bone_table == 0 || !is_readable_cached(&mut cache, bone_table as usize, table_len) {
        return Err("bad-bone-table");
    }

    for i in 0..bone_count {
        let bone =
            unsafe { read_u32_unchecked(bone_table as usize + i * core::mem::size_of::<u32>()) }
                as usize;
        if bone <= LOW_POINTER_LIMIT {
            return Err("null-bone");
        }
    }

    Ok(())
}

#[derive(Default)]
struct ReadableRegionCache {
    base: usize,
    end: usize,
}

impl ReadableRegionCache {
    fn contains(&self, addr: usize, end: usize) -> bool {
        self.base <= addr && end <= self.end
    }
}

fn read_u32(addr: usize) -> Option<u32> {
    if !is_readable(addr, core::mem::size_of::<u32>()) {
        return None;
    }

    Some(unsafe { read_u32_unchecked(addr) })
}

unsafe fn read_u32_unchecked(addr: usize) -> u32 {
    unsafe { core::ptr::read_unaligned(addr as *const u32) }
}

fn is_readable_cached(cache: &mut ReadableRegionCache, addr: usize, len: usize) -> bool {
    if addr < LOW_POINTER_LIMIT || len == 0 {
        return false;
    }

    let Some(end) = addr.checked_add(len) else {
        return false;
    };
    if cache.contains(addr, end) {
        return true;
    }

    let Some((base, region_end)) = query_readable_region(addr) else {
        return false;
    };
    if end > region_end {
        return false;
    }

    cache.base = base;
    cache.end = region_end;
    true
}

fn is_readable(addr: usize, len: usize) -> bool {
    if addr < LOW_POINTER_LIMIT || len == 0 {
        return false;
    }

    let Some((_, region_end)) = query_readable_region(addr) else {
        return false;
    };
    let Some(end) = addr.checked_add(len) else {
        return false;
    };
    end <= region_end
}

fn query_readable_region(addr: usize) -> Option<(usize, usize)> {
    if diagnostics::hitch_profiling_enabled() {
        GUARD_VIRTUAL_QUERIES.fetch_add(1, Ordering::Relaxed);
    }

    let Ok(info) = virtual_query(addr as *mut c_void) else {
        return None;
    };
    if info.state != MEM_COMMIT.0 || info.protect == PAGE_NOACCESS {
        return None;
    }
    if (info.protect.0 & PAGE_GUARD.0) != 0 {
        return None;
    };

    let base = info.base_address as usize;
    let region_end = base.saturating_add(info.region_size);
    Some((base, region_end))
}

fn log_skip(site: &'static str, reason: &'static str, ragdoll: *mut c_void) {
    let n = SKIPPED_UPDATES.fetch_add(1, Ordering::Relaxed) + 1;
    if !diagnostics::should_log_power_of_two(n) {
        return;
    }

    log::warn!(
        "[RAGDOLL] not-ready update skipped: site={} reason={} total={} ragdoll=0x{:08X} state={}",
        site,
        reason,
        n,
        ragdoll as usize,
        format_ragdoll_state(ragdoll),
    );
}

fn format_ragdoll_state(ragdoll: *mut c_void) -> String {
    if ragdoll.is_null() {
        return "null".to_owned();
    }

    let base = ragdoll as usize;
    format!(
        "scene=0x{:08X} transform_root=0x{:08X} hierarchy=0x{:08X} skeleton=0x{:08X} xform_buf=0x{:08X} xform_count={} table=0x{:08X} table_count={} table_capacity={}",
        read_u32(base + RAGDOLL_SCENE_ROOT_OFFSET).unwrap_or(0),
        read_u32(base + RAGDOLL_TRANSFORM_ROOT_OFFSET).unwrap_or(0),
        read_u32(base + RAGDOLL_HIERARCHY_OFFSET).unwrap_or(0),
        read_u32(base + RAGDOLL_SKELETON_STATE_OFFSET).unwrap_or(0),
        read_u32(base + RAGDOLL_TRANSFORM_BUFFER_OFFSET).unwrap_or(0),
        read_u32(base + RAGDOLL_TRANSFORM_COUNT_OFFSET).unwrap_or(u32::MAX),
        read_u32(base + RAGDOLL_BONE_TABLE_OFFSET).unwrap_or(0),
        read_u32(base + RAGDOLL_BONE_TABLE_COUNT_OFFSET).unwrap_or(u32::MAX),
        read_u32(base + RAGDOLL_BONE_TABLE_CAPACITY_OFFSET).unwrap_or(u32::MAX),
    )
}

fn record_guard_sample(timer: diagnostics::Stopwatch, skipped: bool) {
    if !diagnostics::hitch_profiling_enabled() {
        return;
    }

    GUARD_CALLS.fetch_add(1, Ordering::Relaxed);
    DIAGNOSTIC_GUARD_CALLS.fetch_add(1, Ordering::Relaxed);
    if skipped {
        GUARD_SKIPS.fetch_add(1, Ordering::Relaxed);
        DIAGNOSTIC_GUARD_SKIPS.fetch_add(1, Ordering::Relaxed);
    }

    if let Some(elapsed_us) = timer.elapsed_us() {
        GUARD_TOTAL_US.fetch_add(elapsed_us, Ordering::Relaxed);
        diagnostics::update_max_u64(&GUARD_MAX_US, elapsed_us);
    }

    maybe_log_perf();
}

fn maybe_log_perf() {
    if !diagnostics::should_tick(&GUARD_LAST_REPORT_MS, PERF_REPORT_MS) {
        return;
    }

    let calls = GUARD_CALLS.swap(0, Ordering::AcqRel);
    if calls == 0 {
        return;
    }

    let skips = GUARD_SKIPS.swap(0, Ordering::AcqRel);
    let queries = GUARD_VIRTUAL_QUERIES.swap(0, Ordering::AcqRel);
    let total_us = GUARD_TOTAL_US.swap(0, Ordering::AcqRel);
    let max_us = GUARD_MAX_US.swap(0, Ordering::AcqRel);
    let avg_us = total_us / calls.max(1);

    log::debug!(
        "[RAGDOLL_PERF] calls={} skips={} virtual_queries={} total_us={} avg_us={} max_us={}",
        calls,
        skips,
        queries,
        total_us,
        avg_us,
        max_us,
    );
}
