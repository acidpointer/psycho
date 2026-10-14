//! Havok input admission and independent callback/dispatch containment.
//!
//! Batch and pending entry guards validate only the readable array envelope.
//! They preserve the caller's pointer slots and original count: callers own
//! subsequent reference release, queue clearing, and count publication.
//! `havok_sparse` handles NULL at actual native reads across add, callbacks,
//! pending work, collection filtering, and deferred reference operations.
//! An entry snapshot cannot guarantee a slot remains non-NULL later.
//!
//! Narrowphase guards retain their independent pair/agent contract. Existing
//! post-add NULL containment remains for direct callback callers. Installation
//! belongs to quiescent core startup; captured providers live for process
//! lifetime. Valid batches acquire no new owner, allocate nothing, and perform
//! no per-slot scan or log. Readability is admission, not an object-lifetime proof.

use std::sync::atomic::{AtomicU64, Ordering};

use super::statics;
use anyhow::{Context, Result};
use libc::c_void;
use libpsycho::os::windows::winapi::{patch_bytes, virtual_query};

/// Counts how many times we skipped a NULL entity. Referenced by the log
/// threshold below -- a nonzero value means the vanilla bug is firing.
static NULL_SKIPS: AtomicU64 = AtomicU64::new(0);
static ADD_ENTITY_BATCH_NULL_FLUSHES: AtomicU64 = AtomicU64::new(0);
static NARROWPHASE_SKIPS: AtomicU64 = AtomicU64::new(0);
static PENDING_ADD_NULL_FLUSHES: AtomicU64 = AtomicU64::new(0);
static REMOVE_AGENT_UNLOCK_PATCHED: AtomicU64 = AtomicU64::new(0);

const PAIR_SIZE: usize = 8;
const COLLISION_TYPE_COUNT: u8 = 8;
const DISPATCH_TABLE_ENTRIES: usize = 64;
const READABLE_REGION_CACHE_ENTRIES: usize = 8;
const REMOVE_AGENT_UNLOCK_ARG_LOAD_ADDR: usize = 0x00D0D7D6;
const REMOVE_AGENT_UNLOCK_ARG_LOAD_LEN: usize = 9;
const TOI_UNLOCK_ARG_LOAD_ADDR: usize = 0x00D93FE4;
const TOI_UNLOCK_ARG_LOAD_LEN: usize = 13;

const REMOVE_AGENT_UNLOCK_ARG_PATCH: [u8; REMOVE_AGENT_UNLOCK_ARG_LOAD_LEN] =
    [0x6A, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
const TOI_UNLOCK_ARG_PATCH: [u8; TOI_UNLOCK_ARG_LOAD_LEN] = [
    0x6A, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
];

/// Replaces two unsafe dead-argument rereads before `FUN_00C91210`.
///
/// `FUN_00C911D0` / `FUN_00C91210` are thin wrappers around
/// `EnterCriticalSection` / `LeaveCriticalSection`. Both use `ECX + 0xB8`
/// as the critical-section pointer and overwrite the stack argument before
/// jumping to WinAPI. If no lock exists, they simply `ret 4`. The pushed
/// `entity + 0xCC` value is therefore only stack shape, not behavior.
///
/// Vanilla rereads the broadphase entity slot after `FUN_00CF7080`
/// (`StAddAgt`). That slot can become NULL during Havok remove/add-agent
/// processing, causing the crash at `0x00D0D7D8`. `push 0` keeps the same
/// stack contract without dereferencing a slot that may no longer be valid.
pub fn install_remove_agent_unlock_guard() -> Result<()> {
    if REMOVE_AGENT_UNLOCK_PATCHED.swap(1, Ordering::AcqRel) != 0 {
        return Ok(());
    }

    unsafe {
        patch_bytes(
            REMOVE_AGENT_UNLOCK_ARG_LOAD_ADDR as *mut c_void,
            &REMOVE_AGENT_UNLOCK_ARG_PATCH,
        )
    }
    .context("patching FUN_00D0D3F0 remove-agent unlock dead arg")?;

    unsafe {
        patch_bytes(
            TOI_UNLOCK_ARG_LOAD_ADDR as *mut c_void,
            &TOI_UNLOCK_ARG_PATCH,
        )
    }
    .context("patching FUN_00D93BA0 TOI unlock dead arg")?;

    log::info!(
        "[HAVOK] Remove-agent unlock NULL-reread guard active at 0x{:08X} and 0x{:08X}",
        REMOVE_AGENT_UNLOCK_ARG_LOAD_ADDR,
        TOI_UNLOCK_ARG_LOAD_ADDR,
    );

    Ok(())
}

/// Detour for `FUN_00C94BD0`, hkpWorld::addEntityBatch.
///
/// Preserve original slots/count for all four native callers. Admission is
/// published after the complete transaction commits; an unadmitted rollback
/// survivor forwards its provider unchanged.
/// Safety: the provider's world/array lifetime and native ABI remain required;
/// array readability does not establish ownership of individual objects.
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

    if !super::havok_sparse::is_admitted() {
        // A failed transaction can leave a detour exposed when restoration
        // loses byte ownership. Its provider is retained, but the dependent
        // native NULL consumers are not admitted; replay that provider exactly.
        unsafe { original(world, objects, count, mode) };
        return;
    }

    if count < 0 {
        return;
    }

    let count_usize = count as usize;
    let Some(_) = admitted_entity_count(objects, count_usize) else {
        log_add_entity_batch_nulls("bad-array", count_usize, objects as usize);
        return;
    };
    unsafe { original(world, objects, count, mode) };
}

/// Detour for `FUN_00C674D0`, the hkpWorld pending-add flush.
///
/// Native owns per-slot release and clearing; preserve its original range.
/// An unadmitted rollback survivor forwards its provider unchanged.
/// Safety: the provider's manager/array lifetime and ABI remain required.
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

    if !super::havok_sparse::is_admitted() {
        // Keep an unadmitted rollback survivor transparent to its provider.
        unsafe { original(manager, objects, count) };
        return;
    }

    let count_usize = count as usize;
    let Some(_) = admitted_entity_count(objects, count_usize) else {
        log_pending_add_nulls("bad-array", count, objects as usize);
        return;
    };
    unsafe { original(manager, objects, count) };
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

    let Some(pair_bytes) = (count as usize).checked_mul(PAIR_SIZE) else {
        log_narrowphase_skip("pair-count-overflow", pairs as usize, 0, 0, count);
        return;
    };
    if !is_readable(pairs as usize, pair_bytes) {
        log_narrowphase_skip("bad-pair-array", pairs as usize, 0, 0, count);
        return;
    }

    // Each dispatch slot owns one agent object. Validate an agent at most once
    // per batch instead of repeating three VirtualQuery calls for every pair
    // that maps to the same slot.
    let mut agent_states = [0u8; DISPATCH_TABLE_ENTRIES];
    let mut object_regions = ReadableRegionCache::new();
    let mut bad_seen = false;
    for i in 0..count as usize {
        let pair_addr = pairs as usize + i * PAIR_SIZE;
        if !valid_pair(
            dispatch_table as usize,
            pair_addr,
            &mut agent_states,
            &mut object_regions,
        ) {
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
        if valid_pair(
            dispatch_table as usize,
            pair_addr,
            &mut agent_states,
            &mut object_regions,
        ) {
            unsafe { original(dispatch_table, pair_addr as *mut c_void, 1, filter) };
        } else {
            let a = unsafe { core::ptr::read_unaligned(pair_addr as *const u32) };
            let b = unsafe { core::ptr::read_unaligned((pair_addr + 4) as *const u32) };
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

fn valid_pair(
    dispatch_table: usize,
    pair_addr: usize,
    agent_states: &mut [u8; DISPATCH_TABLE_ENTRIES],
    object_regions: &mut ReadableRegionCache,
) -> bool {
    let a = unsafe { core::ptr::read_unaligned(pair_addr as *const u32) };
    let b = unsafe { core::ptr::read_unaligned((pair_addr + 4) as *const u32) };
    if a == 0 || b == 0 {
        return false;
    }

    if !object_regions.contains(a as usize, 8) || !object_regions.contains(b as usize, 8) {
        return false;
    }
    let type_a = unsafe { *((a as usize + 4) as *const u8) };
    let type_b = unsafe { *((b as usize + 4) as *const u8) };
    if type_a >= COLLISION_TYPE_COUNT || type_b >= COLLISION_TYPE_COUNT {
        return false;
    }

    let index = type_b as usize + type_a as usize * COLLISION_TYPE_COUNT as usize;
    match agent_states[index] {
        1 => return true,
        2 => return false,
        _ => {}
    }

    let agent = unsafe {
        core::ptr::read_unaligned(
            (dispatch_table + index * core::mem::size_of::<u32>()) as *const u32,
        )
    };
    if agent == 0 {
        agent_states[index] = 2;
        return false;
    }

    let Some(vtable) = read_u32(agent as usize) else {
        agent_states[index] = 2;
        return false;
    };
    let Some(callback) = read_u32(vtable as usize + 4) else {
        agent_states[index] = 2;
        return false;
    };
    let valid = is_executable(callback as usize);
    agent_states[index] = if valid { 1 } else { 2 };
    valid
}

struct ReadableRegionCache {
    starts: [usize; READABLE_REGION_CACHE_ENTRIES],
    ends: [usize; READABLE_REGION_CACHE_ENTRIES],
    next: usize,
}

impl ReadableRegionCache {
    const fn new() -> Self {
        Self {
            starts: [0; READABLE_REGION_CACHE_ENTRIES],
            ends: [0; READABLE_REGION_CACHE_ENTRIES],
            next: 0,
        }
    }

    fn contains(&mut self, address: usize, len: usize) -> bool {
        let Some(end) = address.checked_add(len) else {
            return false;
        };
        for index in 0..READABLE_REGION_CACHE_ENTRIES {
            if address >= self.starts[index] && end <= self.ends[index] {
                return true;
            }
        }

        let Some((start, region_end)) = readable_region(address, len) else {
            return false;
        };
        self.starts[self.next] = start;
        self.ends[self.next] = region_end;
        self.next = (self.next + 1) % READABLE_REGION_CACHE_ENTRIES;
        true
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
    readable_region(addr, len).is_some()
}

fn readable_region(addr: usize, len: usize) -> Option<(usize, usize)> {
    if addr < 0x10000 || len == 0 {
        return None;
    }

    let Ok(info) = virtual_query(addr as *mut c_void) else {
        return None;
    };
    if !info.is_accessible() {
        return None;
    }

    let end = addr.checked_add(len)?;
    let region_start = info.base_address as usize;
    let region_end = region_start.checked_add(info.region_size)?;
    (end <= region_end).then_some((region_start, region_end))
}

fn is_executable(addr: usize) -> bool {
    if addr < 0x10000 {
        return false;
    }

    let Ok(info) = virtual_query(addr as *mut c_void) else {
        return false;
    };
    info.is_executable()
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

fn log_pending_add_nulls(reason: &'static str, count: u32, objects: usize) {
    let n = PENDING_ADD_NULL_FLUSHES.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 || n.is_power_of_two() {
        log::warn!(
            "[HAVOK] Pending flush rejected an inaccessible array event={} reason={} count={} array=0x{:08X}",
            n,
            reason,
            count,
            objects,
        );
    }
}

/// Admit a readable pointer-array envelope without inspecting or modifying slots.
/// Empty input is valid even with a NULL array. Readability is only a snapshot;
/// native caller lifetime/ownership remains required throughout the actual call.
fn admitted_entity_count(objects: *mut *mut c_void, count: usize) -> Option<usize> {
    if count == 0 {
        return Some(0);
    }
    let bytes = count.checked_mul(core::mem::size_of::<*mut c_void>())?;
    (!objects.is_null() && is_readable(objects as usize, bytes)).then_some(count)
}

fn log_add_entity_batch_nulls(reason: &'static str, count: usize, objects: usize) {
    let n = ADD_ENTITY_BATCH_NULL_FLUSHES.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 || n.is_power_of_two() {
        log::warn!(
            "[HAVOK] Entity batch rejected an inaccessible array event={} reason={} count={} array=0x{:08X}",
            n,
            reason,
            count,
            objects,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_batch_preparation_preserves_caller_slots_and_count() {
        let first = 1u8;
        let last = 2u8;
        let mut objects = [
            std::ptr::from_ref(&first).cast_mut().cast::<c_void>(),
            std::ptr::null_mut(),
            std::ptr::from_ref(&last).cast_mut().cast::<c_void>(),
        ];
        let before = objects;
        // This exercises the actual production admission mechanism. The
        // native deferred caller later releases the original count and slots.
        let accepted = admitted_entity_count(objects.as_mut_ptr(), objects.len());
        assert_eq!(
            objects, before,
            "caller-owned slots must retain their positions"
        );
        assert_eq!(
            accepted,
            Some(before.len()),
            "the caller retains its original count"
        );
    }

    #[test]
    fn empty_and_all_null_batches_retain_their_native_counts() {
        assert_eq!(admitted_entity_count(std::ptr::null_mut(), 0), Some(0));
        let mut objects = [std::ptr::null_mut(); 3];
        assert_eq!(
            admitted_entity_count(objects.as_mut_ptr(), objects.len()),
            Some(3)
        );
        assert!(objects.iter().all(|object| object.is_null()));
    }

    #[test]
    fn invalid_array_envelopes_are_rejected_without_a_read_or_write() {
        assert_eq!(admitted_entity_count(std::ptr::null_mut(), 1), None);
        assert_eq!(
            admitted_entity_count(1usize as *mut *mut c_void, usize::MAX),
            None
        );
        assert_eq!(admitted_entity_count(1usize as *mut *mut c_void, 1), None);
    }
}
