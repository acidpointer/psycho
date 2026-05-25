//! Havok vanilla-bug shims.
//!
//! `FUN_00CFFA00` (hkpEntity::fireAddedToWorldCallbacks) is called by
//! `hkpWorld::addEntityBatch` (FUN_00C94BD0) once per slot in the array
//! produced by `hkp3AxisSweep::addObjectBatch`. The broadphase result
//! array is allowed to contain NULL slots -- there is a dedicated
//! compactor (FUN_00D00370) that removes NULLs from other world-owned
//! arrays precisely because null slots are a normal outcome. The outer
//! loop in `addEntityBatch` forgets to filter, and the very first
//! instruction of `FUN_00CFFA00` is:
//!
//!     MOV EBX, dword ptr [EAX + 0x214]   ; EAX = entity
//!
//! so a NULL slot reaches instruction zero and faults reading `[0x214]`.
//! Vanilla almost never hits it -- gheap's different allocation layout
//! and timing make the sparse outcome reproducible on AI Linear Task
//! Thread 2 within minutes of stress flight. See
//! analysis/ghidra/output/crash/crash_cffa08_dataflow.txt.
//!
//! The fix: inline-hook `FUN_00CFFA00` entry and bail out when the entity
//! is NULL. One `test/jz` on the hot path, no behavioral change otherwise.

use std::sync::atomic::{AtomicU64, Ordering};

use libc::c_void;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, VirtualQuery,
};

use super::statics;

/// Counts how many times we skipped a NULL entity. Referenced by the log
/// threshold below -- a nonzero value means the vanilla bug is firing.
static NULL_SKIPS: AtomicU64 = AtomicU64::new(0);
static NARROWPHASE_SKIPS: AtomicU64 = AtomicU64::new(0);

const PAIR_SIZE: usize = 8;
const COLLISION_TYPE_COUNT: u8 = 8;
const DISPATCH_TABLE_ENTRIES: usize = 64;

/// Detour for `FUN_00CF7080`, the StAddAgt narrowphase pair dispatcher.
///
/// The vanilla function trusts every broadphase pair:
///
/// - pair[0] and pair[1] must be readable collision objects
/// - byte +4 on each object must be a 0..7 dispatch-table type
/// - world+0x64[type_a * 8 + type_b] must contain a valid agent
/// - agent->vtable[1] must be executable
///
/// The recurring crash moved from `0x00D0D7D8` to an EIP=0/null-call
/// inside this dispatcher once the later symptom was patched. That means
/// the real invariant break is an invalid pair/agent dispatch. Normal
/// valid arrays still run through the original function in one call; only
/// bad arrays are replayed pair-by-pair so we can skip the broken pair.
pub unsafe extern "thiscall" fn hook_havok_narrowphase_add_agents(
    dispatch_table: *mut c_void,
    pairs: *mut c_void,
    count: i32,
    filter: *mut c_void,
) {
    if count <= 0 {
        return;
    }

    let original = match statics::HAVOK_NARROWPHASE_ADD_AGENTS_HOOK.original() {
        Ok(original) => original,
        Err(e) => {
            log::error!("[HAVOK] FUN_00CF7080 original trampoline missing: {:?}", e);
            return;
        }
    };

    if !valid_filter(filter as usize) {
        log_narrowphase_skip("bad-filter", 0, 0, 0, count);
        return;
    }

    if !is_readable(
        dispatch_table as usize,
        DISPATCH_TABLE_ENTRIES * core::mem::size_of::<u32>(),
    ) {
        log_narrowphase_skip("bad-dispatch-table", 0, 0, 0, count);
        return;
    }

    let mut bad_seen = false;
    for i in 0..count as usize {
        let pair_addr = pairs as usize + i * PAIR_SIZE;
        if !valid_pair(dispatch_table as usize, pair_addr) {
            bad_seen = true;
            break;
        }
    }

    if !bad_seen {
        unsafe { original(dispatch_table, pairs, count, filter) };
        return;
    }

    for i in 0..count as usize {
        let pair_addr = pairs as usize + i * PAIR_SIZE;
        if valid_pair(dispatch_table as usize, pair_addr) {
            unsafe { original(dispatch_table, pair_addr as *mut c_void, 1, filter) };
        } else {
            let a = read_u32(pair_addr).unwrap_or(0);
            let b = read_u32(pair_addr + 4).unwrap_or(0);
            log_narrowphase_skip("bad-pair", pair_addr, a, b, count);
        }
    }
}

/// Detour for `FUN_00CFFA00`. Skips the call entirely when the game passes
/// a NULL entity pointer; otherwise tail-calls the original trampoline.
pub unsafe extern "C" fn hook_havok_entity_post_add(entity: *mut c_void) {
    if entity.is_null() {
        let n = NULL_SKIPS.fetch_add(1, Ordering::Relaxed) + 1;
        // Log at power-of-two boundaries so a misbehaving session that
        // fires thousands of times per frame does not flood the log.
        if n == 1 || n.is_power_of_two() {
            log::warn!(
                "[HAVOK] FUN_00CFFA00 NULL entity skipped (total={}). \
                 hkp3AxisSweep::addObjectBatch produced a sparse result.",
                n,
            );
        }
        return;
    }

    match statics::HAVOK_ENTITY_POST_ADD_HOOK.original() {
        Ok(original) => unsafe { original(entity) },
        Err(e) => {
            log::error!("[HAVOK] FUN_00CFFA00 original trampoline missing: {:?}", e);
        }
    }
}

fn valid_filter(filter: usize) -> bool {
    let Some(vtable) = read_u32(filter) else {
        return false;
    };
    let Some(callback) = read_u32(vtable as usize + 4) else {
        return false;
    };
    is_executable(callback as usize)
}

fn valid_pair(dispatch_table: usize, pair_addr: usize) -> bool {
    let Some(a) = read_u32(pair_addr) else {
        return false;
    };
    let Some(b) = read_u32(pair_addr + 4) else {
        return false;
    };
    if a == 0 || b == 0 {
        return false;
    }

    let Some(type_a) = read_u8(a as usize + 4) else {
        return false;
    };
    let Some(type_b) = read_u8(b as usize + 4) else {
        return false;
    };
    if type_a >= COLLISION_TYPE_COUNT || type_b >= COLLISION_TYPE_COUNT {
        return false;
    }

    let index = type_b as usize + type_a as usize * COLLISION_TYPE_COUNT as usize;
    let Some(agent) = read_u32(dispatch_table + index * core::mem::size_of::<u32>()) else {
        return false;
    };
    if agent == 0 {
        return false;
    }

    let Some(vtable) = read_u32(agent as usize) else {
        return false;
    };
    let Some(callback) = read_u32(vtable as usize + 4) else {
        return false;
    };
    is_executable(callback as usize)
}

fn read_u8(addr: usize) -> Option<u8> {
    if is_readable(addr, core::mem::size_of::<u8>()) {
        Some(unsafe { *(addr as *const u8) })
    } else {
        None
    }
}

fn read_u32(addr: usize) -> Option<u32> {
    if is_readable(addr, core::mem::size_of::<u32>()) {
        Some(unsafe { *(addr as *const u32) })
    } else {
        None
    }
}

fn is_readable(addr: usize, len: usize) -> bool {
    if addr < 0x10000 || len == 0 {
        return false;
    }

    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
    let ret = unsafe {
        VirtualQuery(
            Some(addr as *const c_void),
            &mut mbi,
            core::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if ret == 0 {
        return false;
    }

    let end = match addr.checked_add(len) {
        Some(end) => end,
        None => return false,
    };
    let region_end = mbi.BaseAddress as usize + mbi.RegionSize;
    mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && end <= region_end
}

fn is_executable(addr: usize) -> bool {
    if addr < 0x10000 {
        return false;
    }

    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
    let ret = unsafe {
        VirtualQuery(
            Some(addr as *const c_void),
            &mut mbi,
            core::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if ret == 0 || mbi.State != MEM_COMMIT {
        return false;
    }

    let protect = mbi.Protect.0;
    protect & PAGE_EXECUTE.0 != 0
        || protect & PAGE_EXECUTE_READ.0 != 0
        || protect & PAGE_EXECUTE_READWRITE.0 != 0
        || protect & PAGE_EXECUTE_WRITECOPY.0 != 0
}

fn log_narrowphase_skip(reason: &'static str, pair: usize, a: u32, b: u32, count: i32) {
    let n = NARROWPHASE_SKIPS.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 || n.is_power_of_two() {
        log::warn!(
            "[HAVOK] FUN_00CF7080 skipped invalid narrowphase pair total={} reason={} pair=0x{:08X} a=0x{:08X} b=0x{:08X} batch_count={}",
            n,
            reason,
            pair,
            a,
            b,
            count,
        );
    }
}
