//! Havok vanilla-bug shims.
//!
//! `FUN_00C94BD0` (`hkpWorld::addEntityBatch`) consumes entity pointer
//! arrays produced by several Havok queues. Some producers can leave sparse
//! NULL slots. Vanilla has at least one caller (`FUN_00C97F80`) that detects
//! sparse arrays and falls back to per-entity adds, so NULL slots are a known
//! contract edge, not random memory corruption.
//!
//! The first add loop in `FUN_00C94BD0` forgets to filter and writes:
//!
//!     MOV dword ptr [ESI + 0xD4], EAX   ; ESI = entity
//!
//! so a NULL slot faults writing `[0xD4]`. We compact NULL slots at the
//! central batch entry before vanilla sees the array.
//!
//! `FUN_00CFFA00` (hkpEntity::fireAddedToWorldCallbacks) is called by
//! `hkpWorld::addEntityBatch` once per slot after broadphase. The very first
//! instruction of `FUN_00CFFA00` is:
//!
//!     MOV EBX, dword ptr [EAX + 0x214]   ; EAX = entity
//!
//! so the post-add guard remains as a second defensive layer.
//!
//! `FUN_00C674D0` is a second consumer of sparse entity arrays. It flushes
//! the hkpWorld pending-add queue, calls `addEntityBatch`, then walks the
//! original pending array again and dereferences each slot at `[slot+0x28]`.
//! The stress-test crash at `0x00C6757A` proved that this array can contain
//! NULL entries too. We compact NULLs before calling the vanilla flush so
//! all six callers keep the same behavior for valid entries.

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use libc::c_void;
use libpsycho::os::windows::winapi::{flush_instructions_cache, patch_jmp, virtual_alloc_rwx};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, VirtualQuery,
};

use super::statics;

/// Counts how many times we skipped a NULL entity. Referenced by the log
/// threshold below -- a nonzero value means the vanilla bug is firing.
static NULL_SKIPS: AtomicU64 = AtomicU64::new(0);
static ADD_ENTITY_BATCH_NULL_FLUSHES: AtomicU64 = AtomicU64::new(0);
static ADD_ENTITY_BATCH_NULL_SLOTS: AtomicU64 = AtomicU64::new(0);
static NARROWPHASE_SKIPS: AtomicU64 = AtomicU64::new(0);
static PENDING_ADD_NULL_FLUSHES: AtomicU64 = AtomicU64::new(0);
static PENDING_ADD_NULL_SLOTS: AtomicU64 = AtomicU64::new(0);
static PENDING_ADD_LOOP_PATCHED: AtomicU64 = AtomicU64::new(0);

const PAIR_SIZE: usize = 8;
const COLLISION_TYPE_COUNT: u8 = 8;
const DISPATCH_TABLE_ENTRIES: usize = 64;
const PENDING_ADD_LOOP_SLOT_LOAD_ADDR: usize = 0x00C67577;
const PENDING_ADD_LOOP_CONTINUE_ADDR: usize = 0x00C6757E;
const PENDING_ADD_LOOP_NEXT_SLOT_ADDR: usize = 0x00C67681;

/// Installs a tiny code-cave guard inside `FUN_00C674D0` after its internal
/// `addEntityBatch` call. The entry wrapper can only filter the initial
/// pending array; the broadphase add can make that same array sparse again
/// before the later per-slot loop dereferences it.
pub fn install_pending_add_loop_null_guard() -> Result<()> {
    if PENDING_ADD_LOOP_PATCHED.swap(1, Ordering::AcqRel) != 0 {
        return Ok(());
    }

    let stub = virtual_alloc_rwx(32).context("allocating pending-add loop guard stub")?;
    let stub_addr = stub as usize;

    let mut code = Vec::with_capacity(32);
    code.extend_from_slice(&[0x8B, 0x14, 0x9E]); // mov edx, [esi + ebx*4]
    code.extend_from_slice(&[0x85, 0xD2]); // test edx, edx
    code.extend_from_slice(&[0x0F, 0x84]); // jz next slot
    code.extend_from_slice(&rel32(
        stub_addr + code.len() + 4,
        PENDING_ADD_LOOP_NEXT_SLOT_ADDR,
    ));
    code.extend_from_slice(&[0x80, 0x7A, 0x28, 0x01]); // cmp byte [edx+0x28], 1
    code.push(0xE9); // jmp back after overwritten cmp
    code.extend_from_slice(&rel32(
        stub_addr + code.len() + 4,
        PENDING_ADD_LOOP_CONTINUE_ADDR,
    ));

    unsafe {
        core::ptr::copy_nonoverlapping(code.as_ptr(), stub as *mut u8, code.len());
    }
    flush_instructions_cache(stub, code.len()).context("flushing pending-add loop guard stub")?;

    unsafe { patch_jmp(PENDING_ADD_LOOP_SLOT_LOAD_ADDR as *mut c_void, stub) }
        .context("patching pending-add loop slot load")?;

    log::info!(
        "[HAVOK] FUN_00C674D0 in-loop NULL slot guard active at 0x{:08X}",
        PENDING_ADD_LOOP_SLOT_LOAD_ADDR,
    );
    Ok(())
}

/// Detour for `FUN_00C94BD0`, hkpWorld::addEntityBatch.
///
/// The vanilla loop trusts `objects[0..count]` and faults at
/// `MOV [entity+0xD4], EAX` when a slot is NULL. Filtering centrally
/// covers all four Ghidra-confirmed callers while preserving order for
/// valid entries.
pub unsafe extern "thiscall" fn hook_havok_add_entity_batch(
    world: *mut c_void,
    objects: *mut *mut c_void,
    count: i32,
    mode: i32,
) {
    let original = match statics::HAVOK_ADD_ENTITY_BATCH_HOOK.original() {
        Ok(original) => original,
        Err(e) => {
            log::error!("[HAVOK] FUN_00C94BD0 original trampoline missing: {:?}", e);
            return;
        }
    };

    if count <= 0 {
        return;
    }

    let count_usize = count as usize;
    let Some(bytes) = count_usize.checked_mul(core::mem::size_of::<*mut c_void>()) else {
        log_add_entity_batch_nulls("count-overflow", 0, count_usize, objects as usize);
        return;
    };
    if objects.is_null() || !is_readable(objects as usize, bytes) {
        log_add_entity_batch_nulls("bad-array", 0, count_usize, objects as usize);
        return;
    }

    let (valid, nulls) = unsafe { compact_null_entities(objects, count_usize) };
    if nulls == 0 {
        unsafe { original(world, objects, count, mode) };
        return;
    }

    log_add_entity_batch_nulls("filtered", nulls, count_usize, objects as usize);

    if valid == 0 {
        return;
    }

    unsafe { original(world, objects, valid as i32, mode) };
}

/// Detour for `FUN_00C674D0`, the hkpWorld pending-add flush.
///
/// The vanilla loop trusts `objects[0..count]` and faults at
/// `CMP byte ptr [EDX + 0x28], 1` when a slot is NULL. Filtering here is
/// intentionally central: all known producers eventually flush through
/// this one function, and preserving non-null order keeps the queue
/// contract intact.
pub unsafe extern "thiscall" fn hook_havok_pending_add_flush(
    manager: *mut c_void,
    objects: *mut *mut c_void,
    count: u32,
) {
    let original = match statics::HAVOK_PENDING_ADD_FLUSH_HOOK.original() {
        Ok(original) => original,
        Err(e) => {
            log::error!("[HAVOK] FUN_00C674D0 original trampoline missing: {:?}", e);
            return;
        }
    };

    if count == 0 {
        unsafe { original(manager, objects, count) };
        return;
    }

    if objects.is_null() {
        log_pending_add_nulls("null-array", 0, count, objects as usize);
        return;
    }

    let count_usize = count as usize;
    let Some(bytes) = count_usize.checked_mul(core::mem::size_of::<*mut c_void>()) else {
        log_pending_add_nulls("count-overflow", 0, count, objects as usize);
        return;
    };
    if !is_readable(objects as usize, bytes) {
        log_pending_add_nulls("bad-array", 0, count, objects as usize);
        return;
    }

    let (write_idx, nulls) = unsafe { compact_null_entities(objects, count_usize) };

    if nulls == 0 {
        unsafe { original(manager, objects, count) };
        return;
    }

    log_pending_add_nulls("filtered", nulls, count, objects as usize);

    if write_idx == 0 {
        return;
    }

    unsafe { original(manager, objects, write_idx as u32) };
}

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

fn rel32(src_after: usize, dst: usize) -> [u8; 4] {
    let offset = (dst as isize).wrapping_sub(src_after as isize) as i32;
    offset.to_le_bytes()
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

fn log_pending_add_nulls(reason: &'static str, nulls: usize, count: u32, objects: usize) {
    if nulls != 0 {
        PENDING_ADD_NULL_SLOTS.fetch_add(nulls as u64, Ordering::Relaxed);
    }
    let n = PENDING_ADD_NULL_FLUSHES.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 || n.is_power_of_two() {
        let total_slots = PENDING_ADD_NULL_SLOTS.load(Ordering::Relaxed);
        log::warn!(
            "[HAVOK] FUN_00C674D0 filtered pending-add NULL slots event={} reason={} nulls={} count={} total_null_slots={} array=0x{:08X}",
            n,
            reason,
            nulls,
            count,
            total_slots,
            objects,
        );
    }
}

unsafe fn compact_null_entities(objects: *mut *mut c_void, count: usize) -> (usize, usize) {
    let mut write_idx = 0usize;
    let mut nulls = 0usize;
    for read_idx in 0..count {
        let entity = unsafe { *objects.add(read_idx) };
        if entity.is_null() {
            nulls += 1;
        } else {
            if write_idx != read_idx {
                unsafe { *objects.add(write_idx) = entity };
            }
            write_idx += 1;
        }
    }

    if nulls != 0 && write_idx < count {
        unsafe {
            core::ptr::write_bytes(objects.add(write_idx), 0, count - write_idx);
        }
    }

    (write_idx, nulls)
}

fn log_add_entity_batch_nulls(reason: &'static str, nulls: usize, count: usize, objects: usize) {
    if nulls != 0 {
        ADD_ENTITY_BATCH_NULL_SLOTS.fetch_add(nulls as u64, Ordering::Relaxed);
    }
    let n = ADD_ENTITY_BATCH_NULL_FLUSHES.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 || n.is_power_of_two() {
        let total_slots = ADD_ENTITY_BATCH_NULL_SLOTS.load(Ordering::Relaxed);
        log::warn!(
            "[HAVOK] FUN_00C94BD0 compacted add-entity NULL slots event={} reason={} nulls={} count={} total_null_slots={} array=0x{:08X}",
            n,
            reason,
            nulls,
            count,
            total_slots,
            objects,
        );
    }
}
