//! Direct OS allocator tier for allocations larger than the block tier.
//!
//! Pools handle requests through 3584 bytes and 16 MB blocks handle medium
//! requests. This module handles requests above 16 MB, including transient
//! texture-file and decompression buffers. CRT entrypoints use the same size
//! dispatch; mimalloc is only an ownership fallback for pointers created
//! before the hooks became active.
//!
//! The rationale is straightforward. On 32-bit with LAA we have ~4 GB
//! of user VA, most of which is already reserved by the game image,
//! loaded DLLs, and the baseline runtime before our code even starts.
//! A legitimate multi-megabyte allocation request (texture, mesh, audio, or
//! BSA decompression buffer) can fail even while total free VAS is substantial
//! when no single free hole is large enough.
//!
//! Previous crash traces confirm this: worker-thread allocations of
//! 5.6 MB and 21 MB (both legitimate texture loads) failed after
//! engine init fragmented VA, our allocator returned NULL, and the
//! game's internal calloc wrapper dereferenced NULL.
//!
//! Routing huge allocations through a direct `VirtualAlloc` side table gives
//! them an exact-size lane. `free`, `msize`, and `realloc` route through a
//! small side table, and failure is clearly OS-level rather than internal
//! block fragmentation.
//!
//! ## Ownership
//!
//! - Allocation: `VirtualAlloc(NULL, rounded, MEM_RESERVE|MEM_COMMIT)`.
//!   The kernel picks the placement with first-fit-from-lowest. Each
//!   block is sized exactly to the request (page-rounded).
//! - Tracking: the returned base and rounded size are pushed into a
//!   `Mutex<Vec<Block>>`. Dispatch via linear scan; Vec stays tiny.
//! - Free: `VirtualFree(ptr, 0, MEM_RELEASE)` returns the VA to the
//!   OS immediately. No internal freelist, no deferred cleanup.
//!
//! Unlike an early reservation, nothing is held beyond actual live
//! use. Peak VA footprint is bounded by the game's live huge-object
//! working set, which is typically a few hundred MB at most during
//! texture-heavy scene loads.
//!
//! ## Dispatch cost
//!
//! `free`, `msize`, and `realloc` check pool and block ownership first. Only
//! pointers outside those tiers reach this side table, which is one `Mutex`
//! and a linear scan over a small `Vec`.
//!
//! ## Logging
//!
//! Silent on success. `ERROR` only on allocation failure. The
//! allocator's existing OOM paths surface counters via `live_count()`
//! and `live_bytes()`.

use std::ptr::null_mut;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use libc::c_void;

use libpsycho::os::windows::winapi::{virtual_release, virtual_reserve_commit};

/// OS page granularity. `VirtualAlloc` rounds up to this anyway; we
/// track the rounded size for accurate `msize` and accounting.
const PAGE_SIZE: usize = 0x1000;

#[derive(Clone, Copy)]
struct Block {
    base: usize,
    size: usize,
}

static BLOCKS: LazyLock<Mutex<Vec<Block>>> = LazyLock::new(|| Mutex::new(Vec::new()));

static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
static FREE_COUNT: AtomicU64 = AtomicU64::new(0);
static ALLOC_FAIL_COUNT: AtomicU64 = AtomicU64::new(0);
static TOTAL_VAS_BYTES: AtomicU64 = AtomicU64::new(0);
static PEAK_VAS_BYTES: AtomicU64 = AtomicU64::new(0);
static MAX_ALLOCATION_BYTES: AtomicU64 = AtomicU64::new(0);

/// Allocate `size` bytes via the arena's large-alloc range (if available)
/// or direct `VirtualAlloc`. Returns NULL on failure.
pub fn alloc(size: usize) -> *mut c_void {
    let Some(rounded) = size
        .checked_add(PAGE_SIZE - 1)
        .map(|size| size & !(PAGE_SIZE - 1))
    else {
        log::error!("[VA] alloc size overflow: size={}", size);
        return null_mut();
    };

    // Previous code had a "first-chance from reserved large-alloc sub-range"
    // fast path backed by the arena.rs unified reservation. That reservation
    // is gone with the pool/block redesign, so all allocations now take the
    // direct VirtualAlloc path.

    // Second-chance: raw VirtualAlloc. OS picks placement with
    // first-fit-from-lowest. May fail if VA is fragmented.
    let mut ptr = unsafe { virtual_reserve_commit(None, rounded) };

    // Emergency recovery: if the first attempt fails (VAS fragmented
    // beyond the request size), ask the block tier to release any
    // fully-empty 16 MB slots and try once more. Under 32-bit LAA this
    // is the difference between "coc succeeds after a 47-minute stress
    // test" and "NULL -> game memsets 0 at address 0 -> crash". See
    // the crash signature in CrashLogger.2026-04-18-18-48-55.log:
    // 89 MB texture-load request failing with 30 scattered block slots
    // live and 85 MB already owned in this side table.
    //
    // Zero cost on the success path. Runs at most once per failure; if
    // nothing is empty, block::emergency_retire_empty() returns (0,0)
    // and we fall through to the original NULL path.
    if ptr.is_null() {
        let (slots, bytes) = super::block::emergency_retire_empty();
        if slots > 0 {
            log::warn!(
                "[VA] retry after emergency retire: size={} retired={} slots ({}MB)",
                size,
                slots,
                bytes / 1024 / 1024,
            );
            ptr = unsafe { virtual_reserve_commit(None, rounded) };
        }
    }

    if ptr.is_null() {
        let fails = ALLOC_FAIL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        // Failures cascade during OOM recovery (each retry logs once).
        // Gate on powers of two so we see 1, 2, 4, 8, 16... instead of
        // dozens per second while the game retries.
        if fails.is_power_of_two() {
            if let Some(vas) = super::vas::sample() {
                log::warn!(
                    "[VA] alloc failed: size={} rounded={} total_fails={} live={} live_bytes={}MB free={}MB largest=0x{:08x}+{}MB",
                    size,
                    rounded,
                    fails,
                    live_count(),
                    live_bytes() / 1024 / 1024,
                    vas.total_free / super::vas::MB,
                    vas.largest_base,
                    vas.largest_free / super::vas::MB,
                );
            } else {
                log::warn!(
                    "[VA] alloc failed: size={} rounded={} total_fails={} live={} live_bytes={}MB",
                    size,
                    rounded,
                    fails,
                    live_count(),
                    live_bytes() / 1024 / 1024,
                );
            }
        }
        return null_mut();
    }

    let block = Block {
        base: ptr as usize,
        size: rounded,
    };
    let tracked = {
        let mut blocks = match BLOCKS.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if blocks.try_reserve(1).is_ok() {
            blocks.push(block);
            true
        } else {
            false
        }
    };
    if !tracked {
        log::error!(
            "[VA] tracking allocation failed: base=0x{:08x} size={}",
            block.base,
            block.size,
        );
        if let Err(e) = unsafe { virtual_release(ptr) } {
            log::error!(
                "[VA] tracking rollback VirtualFree failed: base=0x{:08x} err={:?}",
                block.base,
                e,
            );
        }
        return null_mut();
    }
    ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
    let total = TOTAL_VAS_BYTES.fetch_add(rounded as u64, Ordering::Relaxed) + rounded as u64;
    PEAK_VAS_BYTES.fetch_max(total, Ordering::Relaxed);
    MAX_ALLOCATION_BYTES.fetch_max(rounded as u64, Ordering::Relaxed);
    ptr
}

/// If `ptr` is a va_alloc block, release it and return `true`.
/// Otherwise return `false` without touching the pointer.
///
/// # Safety
/// Standard C free contract: the pointer must not be concurrently
/// freed by another thread.
pub unsafe fn free(ptr: *mut c_void) -> bool {
    if ptr.is_null() {
        return false;
    }
    let target = ptr as usize;

    let mut blocks = match BLOCKS.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let Some(idx) = blocks.iter().position(|b| b.base == target) else {
        return false;
    };
    let b = blocks[idx];

    // Raw VirtualAlloc block: full release returns VA to OS.
    if let Err(e) = unsafe { virtual_release(ptr) } {
        log::error!(
            "[VA] VirtualFree failed: base=0x{:08x} size={} err={:?}",
            b.base,
            b.size,
            e,
        );
        return true;
    }
    blocks.swap_remove(idx);
    drop(blocks);
    FREE_COUNT.fetch_add(1, Ordering::Relaxed);
    TOTAL_VAS_BYTES.fetch_sub(b.size as u64, Ordering::Relaxed);
    true
}

/// Return the stored (page-rounded) size for a va_alloc pointer, or
/// `None` if the pointer is not in the side table.
pub fn size_of(ptr: *const c_void) -> Option<usize> {
    if ptr.is_null() {
        return None;
    }
    let target = ptr as usize;
    let blocks = match BLOCKS.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    for b in blocks.iter() {
        if b.base == target {
            return Some(b.size);
        }
    }
    None
}

/// Current count of live blocks.
pub fn live_count() -> usize {
    match BLOCKS.lock() {
        Ok(g) => g.len(),
        Err(p) => p.into_inner().len(),
    }
}

/// Total bytes currently held by live blocks.
pub fn live_bytes() -> u64 {
    TOTAL_VAS_BYTES.load(Ordering::Relaxed)
}

pub fn peak_live_bytes() -> u64 {
    PEAK_VAS_BYTES.load(Ordering::Relaxed)
}

pub fn max_allocation_bytes() -> u64 {
    MAX_ALLOCATION_BYTES.load(Ordering::Relaxed)
}

pub fn alloc_count() -> u64 {
    ALLOC_COUNT.load(Ordering::Relaxed)
}

pub fn free_count() -> u64 {
    FREE_COUNT.load(Ordering::Relaxed)
}

pub fn fail_count() -> u64 {
    ALLOC_FAIL_COUNT.load(Ordering::Relaxed)
}
