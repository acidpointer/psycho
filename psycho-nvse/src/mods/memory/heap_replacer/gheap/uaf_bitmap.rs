//! Allocation-time UAF-sensitive object tracking.
//!
//! Tracks which 64KB mimalloc segments contain UAF-sensitive objects
//! (NiRefObjects, Havok physics entities). At allocation time, when the
//! vtable is guaranteed valid, we check if the object is UAF-sensitive
//! and set a bitmap bit for its segment. At free time, we check the
//! bitmap instead of reading the potentially-corrupted vtable.
//!
//! # Design
//!
//! The game's mimalloc arena is ~512MB. We divide this into 64KB segments:
//!   512MB / 64KB = 8,192 segments = 1KB bitmap
//!
//! Each bit marks "this segment contains UAF-sensitive objects".
//! This is conservative: if a segment has ANY UAF-sensitive object,
//! ALL objects freed from that segment get pool protection.
//!
//! # Why This Works
//!
//! At allocation time:
//!   1. Object is freshly constructed by game code
//!   2. Vtable is written by constructor → guaranteed valid
//!   3. We check vtable range → set bitmap bit if UAF-sensitive
//!
//! At free time:
//!   1. Object may have corrupted vtable (race with destructor)
//!   2. We check bitmap bit → NO object memory access needed
//!   3. If bit set → ALWAYS pool → FreeNode protection applies
//!
//! This eliminates the race condition where vtable is read at free time
//! after another thread has already corrupted it with freelist pointers.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;

/// Mimalloc segment size (64KB).
/// This matches mimalloc's internal segment granularity.
const SEGMENT_SIZE: usize = 64 * 1024;

/// Base address of mimalloc arena.
/// Our reserved arena starts at a known address (configured in memory/mod.rs).
/// This is updated when arena is reserved.
static ARENA_BASE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Bitmap: 8,192 bits = 128 × u64 = 1KB
/// Bit N = "segment N contains UAF-sensitive objects"
/// Covers 512MB arena (8,192 × 64KB segments)
const BITMAP_WORDS: usize = 128;

static BITMAP: LazyLock<[AtomicU64; BITMAP_WORDS]> = LazyLock::new(|| {
    // SAFETY: We're initializing an array of AtomicU64 with zeros.
    // Using transmute because AtomicU64 doesn't implement Copy.
    // This is safe because all bits zero is a valid state for AtomicU64.
    #[allow(clippy::missing_transmute_annotations)]
    unsafe { std::mem::transmute::<[u64; BITMAP_WORDS], [AtomicU64; BITMAP_WORDS]>([0u64; BITMAP_WORDS]) }
});

/// NiRefObject vtable range: 0x01010000 - 0x010F0000
const NIREF_VTABLE_START: usize = 0x01010000;
const NIREF_VTABLE_END: usize = 0x010F0000;

/// Havok physics vtable range: 0x010C0000 - 0x010D0000
const HAVOK_VTABLE_START: usize = 0x010C0000;
const HAVOK_VTABLE_END: usize = 0x010D0000;

/// Initialize bitmap with arena base address.
/// Must be called after mimalloc arena is reserved.
pub fn init(arena_base: usize) {
    ARENA_BASE.store(arena_base, Ordering::Relaxed);
    log::info!(
        "[UAF_BITMAP] Initialized: arena base=0x{:08X}, segments={}, bitmap={} bytes",
        arena_base,
        (512 * 1024 * 1024) / SEGMENT_SIZE,
        BITMAP_WORDS * 8,
    );
}

/// Check if a vtable address indicates a UAF-sensitive object.
/// This is ONLY called at allocation time when vtable is guaranteed valid.
#[inline]
fn is_uaf_sensitive_vtable(vtable: *const u8) -> bool {
    let addr = vtable as usize;
    (addr >= NIREF_VTABLE_START && addr < NIREF_VTABLE_END)
        || (addr >= HAVOK_VTABLE_START && addr < HAVOK_VTABLE_END)
}

/// Mark a segment as containing UAF-sensitive objects.
/// Called at allocation time when vtable is valid.
///
/// # Safety
/// `ptr` must be a valid pointer to a freshly allocated object
/// with a valid vtable pointer at offset 0.
#[inline]
pub fn mark_segment(ptr: *mut u8) {
    let addr = ptr as usize;
    let base = ARENA_BASE.load(Ordering::Relaxed);
    if base == 0 || addr < base {
        return;
    }

    let offset = addr - base;
    let segment = offset / SEGMENT_SIZE;
    let word = segment / 64;
    let bit = segment % 64;

    if word < BITMAP_WORDS {
        // Only mark if vtable indicates UAF-sensitive
        let vtable = unsafe { *(ptr as *const *const u8) };
        if is_uaf_sensitive_vtable(vtable) {
            BITMAP[word].fetch_or(1u64 << bit, Ordering::Relaxed);
        }
    }
}

/// Check if a segment contains UAF-sensitive objects.
/// Called at free time instead of reading the potentially-corrupted vtable.
///
/// # Safety
/// `ptr` must be a pointer to memory within the tracked arena.
#[inline]
pub fn is_uaf_sensitive_segment(ptr: *mut u8) -> bool {
    let addr = ptr as usize;
    let base = ARENA_BASE.load(Ordering::Relaxed);
    if base == 0 || addr < base {
        return false;
    }

    let offset = addr - base;
    let segment = offset / SEGMENT_SIZE;
    let word = segment / 64;
    let bit = segment % 64;

    if word < BITMAP_WORDS {
        (BITMAP[word].load(Ordering::Relaxed) & (1u64 << bit)) != 0
    } else {
        false
    }
}

/// Clear the entire bitmap. For testing/debugging only.
#[allow(dead_code)]
pub fn clear() {
    for i in 0..BITMAP_WORDS {
        BITMAP[i].store(0, Ordering::Relaxed);
    }
}
