//! Direct OS allocator tier for allocations too large for slab or
//! mimalloc.
//!
//! Slab handles `size <= 256 KB` with zombie-safe bitmap free tracking.
//! Mimalloc handles everything in between. This module handles
//! `size >= VA_ALLOC_THRESHOLD`, allocations that would otherwise go
//! through mimalloc's internal huge-object path.
//!
//! The rationale is straightforward. On 32-bit with LAA we have ~4 GB
//! of user VA, most of which is already reserved by the game image,
//! loaded DLLs, and the baseline runtime before our code even starts.
//! Mimalloc takes a fixed chunk of that for its arena at preload. A
//! legitimate multi-megabyte allocation request (texture, mesh,
//! audio, BSA decompression buffer) may not fit inside mimalloc's
//! reserved arena because of internal fragmentation, and mimalloc's
//! own huge-object direct-VA path may fail because the free VA the
//! OS can satisfy is fragmented below the request size.
//!
//! Previous crash traces confirm this: worker-thread allocations of
//! 5.6 MB and 21 MB (both legitimate texture loads) failed after
//! engine init fragmented VA, our allocator returned NULL, and the
//! game's internal calloc wrapper dereferenced NULL.
//!
//! Routing huge allocations through a direct `VirtualAlloc` side
//! table gives them a clean separate lane: mimalloc's arena stays
//! unpolluted by huge-object metadata, `free` / `msize` / `realloc`
//! route through a tiny side table (typical steady-state ≤ 20
//! entries), and failure is clearly OS-level ("kernel refused fresh
//! VA") instead of mimalloc-internal.
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
//! Unlike a preload reservation, nothing is held beyond actual live
//! use. Peak VA footprint is bounded by the game's live huge-object
//! working set, which is typically a few hundred MB at most during
//! texture-heavy scene loads.
//!
//! ## Dispatch cost
//!
//! `free` / `msize` / `realloc` check slab range and mimalloc region
//! first -- both ~2 cycles each, fully inlined. Only pointers that
//! fall outside both regions reach the `va_alloc` side table lookup,
//! which is one `Mutex` + a linear scan over a small `Vec`.
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

use windows::Win32::System::Memory::{
	MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
};

/// Size at/above which allocations bypass mimalloc and go direct.
///
/// 2 MB sits above mimalloc's optimal object sizes on 32-bit and
/// below the smallest texture working-set we've observed in crash
/// logs (5.6 MB). Medium allocations (256 KB–2 MB) stay in mimalloc
/// where they perform well.
pub const VA_ALLOC_THRESHOLD: usize = 2 * 1024 * 1024;

/// OS page granularity. `VirtualAlloc` rounds up to this anyway; we
/// track the rounded size for accurate `msize` and accounting.
const PAGE_SIZE: usize = 0x1000;

#[derive(Clone, Copy)]
struct Block {
	base: usize,
	size: usize,
}

static BLOCKS: LazyLock<Mutex<Vec<Block>>> = LazyLock::new(|| Mutex::new(Vec::with_capacity(32)));

static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
static FREE_COUNT: AtomicU64 = AtomicU64::new(0);
static ALLOC_FAIL_COUNT: AtomicU64 = AtomicU64::new(0);
static TOTAL_VAS_BYTES: AtomicU64 = AtomicU64::new(0);

/// Allocate `size` bytes via direct `VirtualAlloc`. Returns NULL on
/// OS-level failure.
pub fn alloc(size: usize) -> *mut c_void {
	let rounded = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
	let ptr = unsafe { VirtualAlloc(None, rounded, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };
	if ptr.is_null() {
		let fails = ALLOC_FAIL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
		log::error!(
			"[VA] alloc failed: size={} rounded={} total_fails={} live={} live_bytes={}MB",
			size,
			rounded,
			fails,
			live_count(),
			live_bytes() / 1024 / 1024,
		);
		return null_mut();
	}

	let block = Block { base: ptr as usize, size: rounded };
	match BLOCKS.lock() {
		Ok(mut g) => g.push(block),
		Err(p) => p.into_inner().push(block),
	}
	ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
	TOTAL_VAS_BYTES.fetch_add(rounded as u64, Ordering::Relaxed);
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

	let removed = {
		let mut blocks = match BLOCKS.lock() {
			Ok(g) => g,
			Err(p) => p.into_inner(),
		};
		blocks.iter().position(|b| b.base == target).map(|idx| blocks.swap_remove(idx))
	};

	let Some(b) = removed else {
		return false;
	};

	if let Err(e) = unsafe { VirtualFree(ptr, 0, MEM_RELEASE) } {
		log::error!(
			"[VA] VirtualFree failed: base=0x{:08x} size={} err={:?}",
			b.base,
			b.size,
			e,
		);
	}
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

/// Membership test. Reserved for callers that need ownership without
/// the size.
#[allow(dead_code)]
pub fn contains(ptr: *const c_void) -> bool {
	size_of(ptr).is_some()
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
