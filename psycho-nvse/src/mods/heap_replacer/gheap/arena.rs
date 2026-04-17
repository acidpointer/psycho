//! Unified arena reservation for slab + large allocs.
//!
//! After mimalloc reserves its own arena, this module reserves a single
//! contiguous block for the slab superblock, slab metadata, and large
//! allocation pool. This prevents slab from scattering its reservations
//! across VA.
//!
//! ## Memory Layout
//!
//! ```text
//! Single VirtualAlloc(NULL, total, MEM_RESERVE)
//!   [0              .. superblock_end)      -> slab superblock
//!   [superblock_end .. meta_end)            -> slab metadata (committed)
//!   [meta_end       .. reservation_end)     -> large allocs (va_alloc)
//! ```

use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use libc::c_void;
use libpsycho::os::windows::winapi::virtual_query;
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_FREE, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};

const MB: usize = 1024 * 1024;
const VA_LIMIT: usize = 0xffff_0000;
/// Windows VirtualAlloc allocation granularity. MEM_RESERVE requires the
/// base address to be a multiple of this; VirtualQuery returns region
/// bases at page granularity (4 KB), so we must align up ourselves.
const ALLOC_GRANULARITY: usize = 0x10000;
/// Windows page size. The large-alloc sub-range base must be page-aligned
/// so per-block MEM_COMMIT/MEM_DECOMMIT stays scoped to that block --
/// otherwise adjacent sub-allocs share a page and free() zeroes a live
/// neighbour.
const PAGE_SIZE: usize = 0x1000;

// Sub-range boundaries (set during init).
static ARENA_BASE: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static ARENA_SIZE: AtomicUsize = AtomicUsize::new(0);
static SUPERBLOCK_END: AtomicUsize = AtomicUsize::new(0);
static META_END: AtomicUsize = AtomicUsize::new(0);

/// Initialize the unified arena for slab + large allocs.
///
/// Must be called AFTER mimalloc reserves its arena (so the scan finds
/// holes that don't include mimalloc's reservation).
///
/// Reserves a single contiguous range for slab superblock, metadata,
/// and large allocation pool.
pub fn init(superblock_size: usize, meta_size: usize) -> bool {
    let hole_base = scan_largest_hole();
    if hole_base == 0 {
        log::error!("[ARENA] No free VA hole found -- cannot initialize");
        return false;
    }

    // Reserve enough slack to page-align the large-alloc base without
    // losing any of the 64 MB pool. superblock_size is MB-aligned; meta_size
    // is page_count * sizeof(PageInfo), which is NOT page-aligned.
    let meta_aligned = (meta_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let minimum = superblock_size + meta_aligned + 64 * MB;

    log::info!(
        "[ARENA] Need {}MB (slab={}MB meta={}KB large=64MB), largest hole at 0x{:08x}",
        minimum / MB,
        superblock_size / MB,
        meta_size / 1024,
        hole_base,
    );

    // Try the largest hole first, then the second-largest.
    let targets = collect_free_holes(3);
    for (base, size) in &targets {
        if *size < minimum {
            continue;
        }

        // VirtualQuery returns free regions at page granularity (4 KB) but
        // MEM_RESERVE requires 64 KB allocation granularity. Round the
        // candidate base UP and shrink the usable size accordingly; a raw
        // non-aligned base makes VirtualAlloc round DOWN into the adjacent
        // committed region and fail with ERROR_INVALID_ADDRESS (487).
        let aligned_base = (*base + ALLOC_GRANULARITY - 1) & !(ALLOC_GRANULARITY - 1);
        let padding = aligned_base - *base;
        if padding >= *size || *size - padding < minimum {
            continue;
        }

        let ptr = unsafe {
            VirtualAlloc(
                Some(aligned_base as *mut c_void),
                minimum,
                MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if !ptr.is_null() {
            let base = ptr as usize;
            let sb_end = base + superblock_size;
            // Expose META_END page-aligned so the large-alloc sub-range
            // base is aligned too. The unused bytes between the end of
            // meta_size and the aligned me_end are harmless filler within
            // the reservation.
            let me_end = (sb_end + meta_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

            ARENA_BASE.store(ptr as *mut u8, Ordering::Release);
            ARENA_SIZE.store(minimum, Ordering::Release);
            SUPERBLOCK_END.store(sb_end, Ordering::Release);
            META_END.store(me_end, Ordering::Release);

            // Commit the metadata block immediately.
            if meta_size > 0 {
                let meta_ptr = unsafe {
                    VirtualAlloc(
                        Some(sb_end as *mut c_void),
                        meta_size,
                        MEM_COMMIT,
                        PAGE_READWRITE,
                    )
                };
                if meta_ptr.is_null() {
                    log::error!(
                        "[ARENA] Failed to commit metadata block ({}KB)",
                        meta_size / 1024
                    );
                    unsafe {
                        let _ = VirtualFree(ptr, 0, MEM_RELEASE);
                    }
                    return false;
                }
            }

            log::info!("[ARENA] Reserved {}MB at 0x{:08x}", minimum / MB, base,);
            log::info!(
                "[ARENA]   slab:      [0x{:08x} .. 0x{:08x}) = {}MB",
                base,
                sb_end,
                superblock_size / MB,
            );
            log::info!(
                "[ARENA]   metadata:  [0x{:08x} .. 0x{:08x}) = {}KB",
                sb_end,
                me_end,
                meta_size / 1024,
            );
            log::info!(
                "[ARENA]   large:     [0x{:08x} .. 0x{:08x}) = {}MB",
                me_end,
                base + minimum,
                (base + minimum - me_end) / MB,
            );

            return true;
        }

        log::warn!(
            "[ARENA] VirtualAlloc failed at 0x{:08x} (hole 0x{:08x}+{}MB) for {}MB: {}",
            aligned_base,
            *base,
            *size / MB,
            minimum / MB,
            std::io::Error::last_os_error(),
        );
    }

    log::error!(
        "[ARENA] All placement attempts failed (need {}MB)",
        minimum / MB
    );
    false
}

/// Collect up to `n` largest free holes from VAS scan.
fn collect_free_holes(n: usize) -> Vec<(usize, usize)> {
    let mut holes: Vec<(usize, usize)> = Vec::with_capacity(n + 1);
    let mut addr: usize = 0x10000;

    while addr < VA_LIMIT {
        let info = match virtual_query(addr as *mut c_void) {
            Ok(i) => i,
            Err(_) => break,
        };

        let base = info.base_address as usize;
        let size = info.region_size;

        if info.state == MEM_FREE.0 {
            holes.push((base, size));
            holes.sort_by(|a, b| b.1.cmp(&a.1));
            if holes.len() > n {
                holes.truncate(n);
            }
        }

        let next = base.saturating_add(size.max(0x1000));
        if next <= addr {
            break;
        }
        addr = next;
    }

    holes
}

/// Return the slab superblock sub-range (base, size). MEM_RESERVE'd.
pub fn slab_superblock_range() -> (*mut u8, usize) {
    let base = ARENA_BASE.load(Ordering::Acquire) as usize;
    let sb_end = SUPERBLOCK_END.load(Ordering::Acquire);
    if base == 0 {
        return (std::ptr::null_mut(), 0);
    }
    (base as *mut u8, sb_end - base)
}

/// Return the slab metadata sub-range (base, size). MEM_COMMIT'd.
pub fn slab_meta_range() -> (*mut u8, usize) {
    let sb_end = SUPERBLOCK_END.load(Ordering::Acquire);
    let me_end = META_END.load(Ordering::Acquire);
    if sb_end == 0 {
        return (std::ptr::null_mut(), 0);
    }
    (sb_end as *mut u8, me_end - sb_end)
}

/// Return the large-alloc sub-range (base, size). MEM_RESERVE'd.
pub fn large_alloc_range() -> (*mut u8, usize) {
    let me_end = META_END.load(Ordering::Acquire);
    let arena_base = ARENA_BASE.load(Ordering::Acquire) as usize;
    let arena_size = ARENA_SIZE.load(Ordering::Acquire);
    if me_end == 0 {
        return (std::ptr::null_mut(), 0);
    }
    (me_end as *mut u8, arena_base + arena_size - me_end)
}

/// Scan the user VA range for the largest free hole.
fn scan_largest_hole() -> usize {
    let mut addr: usize = 0x10000;
    let mut largest: usize = 0;
    let mut largest_base: usize = 0;

    while addr < VA_LIMIT {
        let info = match virtual_query(addr as *mut c_void) {
            Ok(i) => i,
            Err(_) => break,
        };

        let base = info.base_address as usize;
        let size = info.region_size;

        if info.state == MEM_FREE.0 && size > largest {
            largest = size;
            largest_base = base;
        }

        let next = base.saturating_add(size.max(0x1000));
        if next <= addr {
            break;
        }
        addr = next;
    }

    largest_base
}
