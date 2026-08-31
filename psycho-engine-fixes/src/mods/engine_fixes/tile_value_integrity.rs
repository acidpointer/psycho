//! Containment for NULL slots in Fallout's active Tile value arrays.
//!
//! # Purpose and ownership
//!
//! The 2026-08-30 reporter crash reached Tile::GetOrCreateValueWithID with a
//! NULL Tile::Value pointer in its active sorted array. Both the native
//! comparator and optional third-party inlined implementations dereference that
//! slot. This module owns only the shared Fallout boundary: it restores the
//! dense array invariant before chaining the provider already installed there.
//!
//! # Lifecycle and invariants
//!
//! Installation occurs at the core's existing quiescent pre-CRT barrier. The
//! entry fingerprint proves the Fallout 1.4.0.525 ABI before a trampoline is
//! prepared. Each call holds Fallout's tile critical section while it examines
//! the BSSimpleArray<Tile::Value*> header, compacts NULL slots, and invokes the
//! predecessor. The native function recursively enters the same critical
//! section, so the repair remains serialized through its search and insertion.
//!
//! # Failure and performance policy
//!
//! A valid dense array takes no allocation, logging, ownership inspection, or
//! write. A repaired array preserves the order and identity of every non-NULL
//! value, changes only the active count, and never frees or retains a value.
//! Header states outside the supplied crash contract are forwarded unchanged:
//! returning a synthetic result is not proven safe for every native caller.
//! Repair logging is limited to the first and power-of-two occurrences.

use std::{
    ffi::c_void,
    mem::size_of,
    ptr,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};

use anyhow::Context;
use libpsycho::os::windows::{
    hook::transaction::ModificationTransaction, winapi::BorrowedCriticalSection,
};

use super::{patching, statics};

const TILE_VALUES_DATA_OFFSET: usize = 0x14;
const TILE_VALUES_SIZE_OFFSET: usize = 0x18;
const TILE_VALUES_CAPACITY_OFFSET: usize = 0x1C;

static REPAIRS: AtomicU32 = AtomicU32::new(0);
static REMOVED_VALUES: AtomicU32 = AtomicU32::new(0);
static HEADER_BYPASSES: AtomicU32 = AtomicU32::new(0);
static LAST_TILE: AtomicU32 = AtomicU32::new(0);
static LAST_HEADER_BYPASS_TILE: AtomicU32 = AtomicU32::new(0);
static MISSING_PREDECESSOR_LOGGED: AtomicBool = AtomicBool::new(false);

/// Read-only Tile-array containment state for support reports.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct DiagnosticSnapshot {
    /// Whether entry-hook activation completed.
    pub installed: bool,
    /// Whether Psycho's jump still occupies the native entry.
    pub entry_owned: bool,
    /// Live entry state: inactive, owned, displaced, or unknown.
    pub entry_status: &'static str,
    /// Number of arrays whose NULL slots were compacted this session.
    pub repairs: u32,
    /// Total NULL pointer slots removed from active arrays this session.
    pub removed_values: u32,
    /// Headers forwarded unchanged because they were outside the proved case.
    pub header_bypasses: u32,
    /// Most recent repaired Tile address.
    pub last_tile: u32,
    /// Most recent Tile address whose header was not repaired.
    pub last_header_bypass_tile: u32,
}

/// Return a non-draining snapshot and the live entry-ownership state.
pub(super) fn diagnostic_snapshot() -> DiagnosticSnapshot {
    let installed = statics::TILE_GET_OR_CREATE_HOOK.is_enabled();
    let (entry_owned, entry_status) = if !installed {
        (false, "inactive")
    } else {
        match statics::TILE_GET_OR_CREATE_HOOK.owns_entry() {
            Ok(true) => (true, "owned"),
            Ok(false) => (false, "displaced"),
            Err(_) => (false, "unknown"),
        }
    };

    DiagnosticSnapshot {
        installed,
        entry_owned,
        entry_status,
        repairs: REPAIRS.load(Ordering::Relaxed),
        removed_values: REMOVED_VALUES.load(Ordering::Relaxed),
        header_bypasses: HEADER_BYPASSES.load(Ordering::Relaxed),
        last_tile: LAST_TILE.load(Ordering::Relaxed),
        last_header_bypass_tile: LAST_HEADER_BYPASS_TILE.load(Ordering::Relaxed),
    }
}

/// Install the shared Tile-value array containment hook.
///
/// The core's startup boundary is quiescent, so the entry cannot execute while
/// its trampoline and jump are prepared. A failed activation rolls back.
pub(super) fn install() -> anyhow::Result<()> {
    unsafe {
        patching::verify_bytes(
            statics::TILE_GET_OR_CREATE_ADDR,
            &statics::TILE_GET_OR_CREATE_ENTRY_BYTES,
        )
        .context("verify Tile::GetOrCreateValueWithID entry")?;
        statics::TILE_GET_OR_CREATE_HOOK.init(
            "tile_get_or_create_null_slot_guard",
            statics::TILE_GET_OR_CREATE_ADDR as *mut c_void,
            guard_tile_get_or_create,
        )?;
    }

    let mut transaction = ModificationTransaction::new();
    transaction
        .enable_inline(&statics::TILE_GET_OR_CREATE_HOOK)
        .context("activate Tile value NULL-slot guard")?;
    transaction.commit();

    log::info!(
        "[TILE_VALUES] NULL-slot guard active at 0x{:08X}",
        statics::TILE_GET_OR_CREATE_ADDR,
    );
    Ok(())
}

/// Compact the exact NULL-slot contract and then chain the current provider.
///
/// # Safety
///
/// The native entry is thiscall with one stack trait argument and returns a
/// Tile::Value pointer. For non-NULL tile, native code itself requires a live,
/// aligned Tile and a readable/writable active values range. The hook uses that
/// same precondition only while the native tile critical section is held. It
/// does not dereference an individual value, so a NULL array element is the
/// only element state this guard handles.
unsafe extern "thiscall" fn guard_tile_get_or_create(
    tile: *mut c_void,
    trait_id: u32,
) -> *mut c_void {
    let original = match statics::TILE_GET_OR_CREATE_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            // init publishes the trampoline before enable; reaching this branch
            // is an internal hook-order violation. Do not recurse through the
            // patched entry or unwind across the native ABI.
            if !MISSING_PREDECESSOR_LOGGED.swap(true, Ordering::Relaxed) {
                log::error!(
                    "[TILE_VALUES] Trampoline unavailable; Tile value request is rejected: {error:?}"
                );
            }
            return ptr::null_mut();
        }
    };

    if tile.is_null() {
        return unsafe { original(tile, trait_id) };
    }

    let tile_lock = match unsafe {
        BorrowedCriticalSection::from_raw(statics::TILE_CRITICAL_SECTION_ADDR as *mut c_void)
    } {
        Ok(section) => section,
        Err(error) => {
            // The fixed non-NULL host address is proved at installation. This
            // fallback preserves native behavior if that invariant is broken.
            log::error!(
                "[TILE_VALUES] Tile critical section unavailable; forwarding unchanged: {error:?}"
            );
            return unsafe { original(tile, trait_id) };
        }
    };
    let _tile_lock = tile_lock.enter();

    let removed = unsafe { compact_null_slots(tile) };
    if removed > 0 {
        record_repair(tile as usize, removed);
    }

    unsafe { original(tile, trait_id) }
}

/// Compact NULL slots from one valid active BSSimpleArray<Tile::Value*>.
///
/// # Safety
///
/// Callers hold Fallout's tile critical section. tile and the active values
/// range must meet the same validity contract the native search immediately
/// relies on. This routine reads and writes only pointer slots in that active
/// range and the array's size field; it never dereferences a value pointer.
unsafe fn compact_null_slots(tile: *mut c_void) -> u32 {
    let tile = tile.cast::<u8>();
    let data = unsafe {
        ptr::read_unaligned(tile.add(TILE_VALUES_DATA_OFFSET).cast::<*mut *mut c_void>())
    };
    let size = unsafe { ptr::read_unaligned(tile.add(TILE_VALUES_SIZE_OFFSET).cast::<u32>()) };
    if size == 0 {
        return 0;
    }
    let capacity =
        unsafe { ptr::read_unaligned(tile.add(TILE_VALUES_CAPACITY_OFFSET).cast::<u32>()) };
    let count = size as usize;
    let byte_len = match count.checked_mul(size_of::<*mut c_void>()) {
        Some(byte_len) if byte_len <= isize::MAX as usize => byte_len,
        _ => {
            record_header_bypass(tile as usize);
            return 0;
        }
    };
    if data.is_null() || size > capacity || byte_len == 0 {
        record_header_bypass(tile as usize);
        return 0;
    }

    let mut write_index = 0usize;
    for read_index in 0..count {
        let value = unsafe { ptr::read(data.add(read_index)) };
        if value.is_null() {
            continue;
        }
        if write_index != read_index {
            unsafe { ptr::write(data.add(write_index), value) };
        }
        write_index += 1;
    }

    let removed = count - write_index;
    if removed == 0 {
        return 0;
    }
    let removed = removed as u32;
    unsafe {
        ptr::write_unaligned(
            tile.add(TILE_VALUES_SIZE_OFFSET).cast::<u32>(),
            size - removed,
        )
    };
    removed
}

fn record_repair(tile: usize, removed: u32) {
    LAST_TILE.store(tile as u32, Ordering::Relaxed);
    REMOVED_VALUES.fetch_add(removed, Ordering::Relaxed);
    let repairs = REPAIRS.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    if repairs.is_power_of_two() {
        log::warn!(
            "[TILE_VALUES] Removed {removed} NULL slots from Tile 0x{tile:08X} (repair #{repairs})"
        );
    }
}

fn record_header_bypass(tile: usize) {
    LAST_HEADER_BYPASS_TILE.store(tile as u32, Ordering::Relaxed);
    let bypasses = HEADER_BYPASSES
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1);
    if bypasses.is_power_of_two() {
        log::warn!(
            "[TILE_VALUES] Header outside NULL-slot contract at Tile 0x{tile:08X}; forwarding unchanged (bypass #{bypasses})"
        );
    }
}
