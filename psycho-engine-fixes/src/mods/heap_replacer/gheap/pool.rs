//! Size-class pool allocator for small allocations.
//!
//! Adapted from NVHR's mheap with one critical divergence: each size
//! class is split into 8 MB subpools that reserve lazily. Free dispatch
//! stays O(1) via `addr_to_pool[ptr >> POOL_ALIGN_BITS]`. Each subpool
//! grows by committing `POOL_BLOCK_SIZE` (1 MB) blocks on demand and
//! never decommits.
//!
//! # Why lazy reservation
//!
//! Heavy TTW modlists consume ~2.3 GB of VA before our code runs.
//! Pre-reserving even 512 MB at heap-create time leaves the game with
//! less contiguous VA than its own init + DirectX texture pools need
//! (observed: deferred-init largest-hole of 8-13 MB vs 89 MB required
//! for coc LOD textures). Every VA byte we reserve at startup is one
//! byte the game cannot use during its init.
//!
//! Lazy subpools move per-class VA into the allocator's own lifetime:
//! if a size class is never used, no VA is reserved. If a class is used
//! early, only its first 8 MB subpool is reserved. More subpools appear
//! as actual demand grows, matching vanilla SBM's grow-on-demand
//! contract without paying the old 512 MB first-touch cost.
//!
//! # Lifecycle
//!
//! - `PoolHeap::create()` expands size-class descriptors into 8 MB
//!   base subpools plus dormant exact-size overflow descriptors and builds
//!   the `size_to_class` lookup. It does not call `VirtualAlloc`.
//! - `PoolHeap::alloc(size)` dispatches to a size class, starts from a
//!   per-class hint, and tries that class's subpools. If the selected
//!   subpool is still `POOL_STATE_NOT_INIT`, a CAS transitions it to
//!   `POOL_STATE_INITING`, the winning thread scans `addr_to_pool` from
//!   high addresses downward for a free slot, reserves user and link VA via
//!   `VirtualAlloc(MEM_RESERVE)`, and publishes `POOL_STATE_INIT`. Losers
//!   busy-wait. Neither range is committed by initialization.
//! - Subsequent allocs skip the ensure-init path (single Acquire load).
//! - A subpool commits user memory in 1 MB chunks. Virgin cells are handed
//!   out by a monotonically increasing index; only returned cells enter the
//!   LIFO free list. This keeps refill constant-work instead of constructing
//!   a link for every cell in the new chunk.
//!
//! # Zombie safety
//!
//! The free list is stored out-of-band in a separate array of link records.
//! Freed cells are NOT written to. Every byte of a freed allocation stays
//! readable for stale readers (AI, IO, Havok) until the cell is reused by a
//! new allocation. Link pages are committed with the corresponding user
//! prefix, but virgin entries are never touched or linked.
//!
//! # Dispatch
//!
//! `pool_from_addr` checks `addr_to_pool` (lazily populated) and then
//! verifies the pool is `POOL_STATE_INIT` before trusting `base/end`
//! pointers. Lookups for pointers in not-yet-inited pool ranges are
//! treated as "not ours" and fall through to block/va_alloc dispatch.
//!
//! # Concurrency
//!
//! - Hot path (already-inited pool): Acquire load + existing per-pool
//!   spinlock. No extra lock.
//! - Init path (first alloc for a subpool): global `init_lock`
//!   serialises the `addr_to_pool` scan + `VirtualAlloc` + slot claim
//!   sequence. Only paid once per subpool for the lifetime of the
//!   process.

use std::ptr::{self, null_mut};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use libc::c_void;
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc};

use crate::mods::diagnostics;

// Per-pool lifecycle states. Enables lazy VA reservation: the pool
// transitions NotInit -> Initing -> Init on success. Resource failures are
// retryable on the watchdog generation; structural failures are permanent.
// This avoids poisoning a descriptor forever after transient VAS pressure.
const POOL_STATE_NOT_INIT: u8 = 0;
const POOL_STATE_INITING: u8 = 1;
const POOL_STATE_INIT: u8 = 2;
const POOL_STATE_RETRYABLE: u8 = 3;
const POOL_STATE_PERMANENT: u8 = 4;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Reservation alignment. Every subpool is placed at `i * POOL_ALIGN` for
/// some `i`, and the free path uses `ptr >> POOL_ALIGN_BITS` to reach
/// the exact subpool. 8 MB trades some first-touch VAS for fewer
/// reservations and less fragmentation under heavy modlists.
pub const POOL_ALIGN: usize = 0x0080_0000; // 8 MB
const POOL_ALIGN_BITS: u32 = 23; // log2(POOL_ALIGN)
const POOL_SUBPOOL_SIZE: u32 = POOL_ALIGN as u32;

/// Extra exact-size capacity available after a class's normal reservation is
/// full. Descriptors are free until first use. The 8-byte class gets a larger
/// share because real large-modlist loads exceed eight million tiny cells;
/// every other class retains five lazy overflow slabs.
const DEFAULT_OVERFLOW_SUBPOOLS: usize = 5;
const TINY_CELL_OVERFLOW_SUBPOOLS: usize = 16;

/// Soft diagnostic threshold for overflow reservations. It must not reject a
/// class solely because unrelated classes happened to reserve first.
const OVERFLOW_RESERVATION_SOFT_LIMIT: usize = 256 * 1024 * 1024;

static OVERFLOW_USER_RESERVED_BYTES: AtomicUsize = AtomicUsize::new(0);
static OVERFLOW_METADATA_RESERVED_BYTES: AtomicUsize = AtomicUsize::new(0);
static OVERFLOW_REFUSALS: AtomicU64 = AtomicU64::new(0);
static RESERVATION_RETRY_GENERATION: AtomicU32 = AtomicU32::new(1);

const CLASS_STATE_EXHAUSTED: u32 = 1;
const CLASS_STATE_GENERATION_STEP: u32 = 2;

static TIMED_GROW_COUNT: AtomicU64 = AtomicU64::new(0);
static TIMED_GROW_FAILURES: AtomicU64 = AtomicU64::new(0);
static TIMED_GROW_TOTAL_US: AtomicU64 = AtomicU64::new(0);
static TIMED_GROW_USER_BYTES: AtomicU64 = AtomicU64::new(0);
static TIMED_GROW_METADATA_BYTES: AtomicU64 = AtomicU64::new(0);
static SLOWEST_GROW: AtomicU64 = AtomicU64::new(0);
static TIMED_INIT_COUNT: AtomicU64 = AtomicU64::new(0);
static TIMED_INIT_TOTAL_US: AtomicU64 = AtomicU64::new(0);
static SLOWEST_INIT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Default)]
pub struct PoolTimingSnapshot {
    pub grows: u64,
    pub grow_failures: u64,
    pub grow_total_us: u64,
    pub grow_max_us: u64,
    pub grow_user_bytes: u64,
    pub grow_metadata_bytes: u64,
    pub grow_slowest_pool: u8,
    pub grow_slowest_item_size: u16,
    pub initializations: u64,
    pub init_total_us: u64,
    pub init_max_us: u64,
    pub init_slowest_pool: u8,
    pub init_slowest_item_size: u16,
}

fn pack_timing(elapsed_us: u64, pool_index: u8, item_size: u32) -> u64 {
    let elapsed = elapsed_us.min(u32::MAX as u64);
    (elapsed << 32) | (u64::from(pool_index) << 16) | u64::from(item_size.min(u16::MAX as u32))
}

fn unpack_timing(value: u64) -> (u64, u8, u16) {
    (
        value >> 32,
        ((value >> 16) & 0xff) as u8,
        (value & 0xffff) as u16,
    )
}

fn record_grow_timing(
    timer: diagnostics::Stopwatch,
    pool_index: u8,
    item_size: u32,
    success: bool,
    user_bytes: usize,
    metadata_bytes: usize,
) {
    let Some(elapsed_us) = timer.elapsed_us() else {
        return;
    };

    TIMED_GROW_COUNT.fetch_add(1, Ordering::Relaxed);
    if !success {
        TIMED_GROW_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
    TIMED_GROW_TOTAL_US.fetch_add(elapsed_us, Ordering::Relaxed);
    TIMED_GROW_USER_BYTES.fetch_add(user_bytes as u64, Ordering::Relaxed);
    TIMED_GROW_METADATA_BYTES.fetch_add(metadata_bytes as u64, Ordering::Relaxed);
    SLOWEST_GROW.fetch_max(
        pack_timing(elapsed_us, pool_index, item_size),
        Ordering::Relaxed,
    );
}

fn record_init_timing(timer: diagnostics::Stopwatch, pool_index: u8, item_size: u32) {
    let Some(elapsed_us) = timer.elapsed_us() else {
        return;
    };

    TIMED_INIT_COUNT.fetch_add(1, Ordering::Relaxed);
    TIMED_INIT_TOTAL_US.fetch_add(elapsed_us, Ordering::Relaxed);
    SLOWEST_INIT.fetch_max(
        pack_timing(elapsed_us, pool_index, item_size),
        Ordering::Relaxed,
    );
}

pub fn take_timing_snapshot() -> PoolTimingSnapshot {
    let grow_slowest = SLOWEST_GROW.swap(0, Ordering::AcqRel);
    let init_slowest = SLOWEST_INIT.swap(0, Ordering::AcqRel);
    let (grow_max_us, grow_slowest_pool, grow_slowest_item_size) = unpack_timing(grow_slowest);
    let (init_max_us, init_slowest_pool, init_slowest_item_size) = unpack_timing(init_slowest);

    PoolTimingSnapshot {
        grows: TIMED_GROW_COUNT.swap(0, Ordering::AcqRel),
        grow_failures: TIMED_GROW_FAILURES.swap(0, Ordering::AcqRel),
        grow_total_us: TIMED_GROW_TOTAL_US.swap(0, Ordering::AcqRel),
        grow_max_us,
        grow_user_bytes: TIMED_GROW_USER_BYTES.swap(0, Ordering::AcqRel),
        grow_metadata_bytes: TIMED_GROW_METADATA_BYTES.swap(0, Ordering::AcqRel),
        grow_slowest_pool,
        grow_slowest_item_size,
        initializations: TIMED_INIT_COUNT.swap(0, Ordering::AcqRel),
        init_total_us: TIMED_INIT_TOTAL_US.swap(0, Ordering::AcqRel),
        init_max_us,
        init_slowest_pool,
        init_slowest_item_size,
    }
}

/// Growth unit. Each time a pool runs out of committed virgin cells and has
/// no returned cell to reuse, it commits one more block.
const POOL_BLOCK_SIZE: usize = 0x0010_0000; // 1 MB

/// Largest allocation the pool tier handles. Matches NVHR.
pub const POOL_MAX_SIZE: usize = 3584;

/// Size-to-pool lookup length. Index = `(size + 3) >> 2`.
const SIZE_LOOKUP_LEN: usize = (POOL_MAX_SIZE >> 2) + 1;

/// Address-to-pool lookup length. Covers 4 GB of user VA at 8 MB
/// granularity, more than the 3 GB LAA ceiling needs.
const ADDR_LOOKUP_LEN: usize = 512;

/// Sentinel in the lookup tables for "no pool here".
const NO_POOL: u8 = 0xff;

#[cold]
fn log_overflow_refusal(class_index: u8, item_size: u32, reason: &'static str, value_mb: usize) {
    let count = OVERFLOW_REFUSALS.fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        log::warn!(
            "[POOL] Exact-size overflow refused: class #{} {}B reason={} value={}MB count={}",
            class_index,
            item_size,
            reason,
            value_mb,
            count,
        );
    }
}

// ---------------------------------------------------------------------------
// Pool descriptors (static)
// ---------------------------------------------------------------------------

struct PoolDesc {
    item_size: u32,
    max_size: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReserveResult {
    Ready,
    Retryable,
    Permanent,
}

enum GrowResult {
    Grown,
    Full,
    CommitFailed,
}

enum PoolAllocResult {
    Allocated(*mut u8),
    Full,
    CommitFailed,
}

enum InitResult {
    Ready,
    Unavailable,
    ResourceFailure,
}

enum ClassAllocResult {
    Allocated(*mut c_void),
    Exhausted,
    ResourceFailure,
}

/// Per-class normal reservation sizes. Sum is 552 MB, but with lazy
/// reservation (see module docs) only classes that actually get used
/// consume VA -- total live VA scales to the workload. A class whose
/// `max_size` is 80 MB but which never receives an alloc reserves 0
/// bytes for the life of the process.
///
/// Historical context: the pre-lazy design reserved the entire 512 MB
/// sum at heap init, which stole VA from the game's own working budget.
/// Observed deferred-init largest-hole under heavy TTW modlists was
/// 13 MB with 640 MB pool / 8 MB with 512 MB pool -- the game's own
/// init + DirectX texture pools need a larger contiguous hole than
/// that for coc LOD textures (89 MB request). Lazy reservation
/// eliminates the eager VA cost so the game enters deferred-init with
/// full VA available, and our pools appear as the game's actual
/// working set crosses their size-class thresholds.
///
/// Layout (34 classes, 552 MB total):
///
///   Hot (TESForm/NiNode churn -- biggest reservations):
///     80 B:   80 MB   (Run B saw 8K fails at 64 MB; NVHR uses 128 MB,
///                      80 MB is the "just over observed peak" compromise)
///     96 B:   64 MB   (Run B saw 256 fails at 64 MB; borderline, not bumped)
///
///   Mid-size cascade hotspots:
///     1024 B:         16 MB
///     1280 B:         32 MB   (2026-05-25 run exhausted 1028-1224 B)
///      640 B:         16 MB
///     2048 B:         16 MB
///     2560 B:         16 MB   (2026-05-25 run exhausted 2286/2416 B)
///     3072, 3584 B:   24 MB each
///      512 B:         16 MB
///
///   Small high-frequency classes (Run B saw heavy fails):
///      8, 16 B:       16 MB each (bumped from 8; keep)
///      20, 56 B:      8 MB       (reverted from 16 to save VAS; Run B fails
///                                   were 2K-4K, cascades to 24/32/64 B
///                                   class acceptable)
///
///   Common subclasses:
///     32, 64, 128, 256, 320 B: 16 MB each
///
///   Baseline (never observed saturating): one 8 MB subpool.
///
/// Accepted exhaust risks on 552 MB budget:
///   - 80 B heavy load (Run B pattern): 80 MB vs 96 MB ideal -> expect
///     some exhausts under sustained stress + coc, not crashes
///   - 1024 B remains 16 MB. If any class fills, exact-size overflow grows
///     under a shared budget instead of consuming unrelated larger classes.
///
/// VAS accounting (the real constraint):
///   pool (552 MB normal + overflow, with a 256 MB diagnostic threshold) +
///   block tier on-demand + game +
///   DirectX textures = fits under 3 GB LAA with ~80-100 MB headroom for
///   contiguous texture allocs at deferred-init. Eagerly reserving this
///   much would be unsafe; lazy subpools keep startup cost at zero.
///   Going much above this budget
///   pool was proven to collapse that headroom to <15 MB and guarantee
///   coc-transition NULL on 89 MB texture VirtualAlloc.
const POOL_DESC: &[PoolDesc] = &[
    PoolDesc {
        item_size: 8,
        max_size: 16 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 12,
        max_size: 8 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 16,
        max_size: 16 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 20,
        max_size: 8 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 24,
        max_size: 8 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 28,
        max_size: 8 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 32,
        max_size: 16 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 40,
        max_size: 8 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 48,
        max_size: 8 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 56,
        max_size: 8 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 64,
        max_size: 16 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 80,
        max_size: 80 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 96,
        max_size: 64 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 112,
        max_size: 8 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 128,
        max_size: 16 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 160,
        max_size: 8 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 192,
        max_size: 8 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 224,
        max_size: 8 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 256,
        max_size: 16 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 320,
        max_size: 16 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 384,
        max_size: 8 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 448,
        max_size: 8 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 512,
        max_size: 16 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 640,
        max_size: 16 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 768,
        max_size: 8 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 896,
        max_size: 8 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 1024,
        max_size: 16 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 1280,
        max_size: 32 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 1536,
        max_size: 8 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 1792,
        max_size: 8 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 2048,
        max_size: 16 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 2560,
        max_size: 16 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 3072,
        max_size: 24 * 1024 * 1024,
    },
    PoolDesc {
        item_size: 3584,
        max_size: 24 * 1024 * 1024,
    },
];

const fn subpool_count_for(max_size: u32) -> usize {
    let full = max_size / POOL_SUBPOOL_SIZE;
    let extra = if max_size.is_multiple_of(POOL_SUBPOOL_SIZE) {
        0
    } else {
        1
    };
    (full + extra) as usize
}

/// Count the concrete subpools expanded from `POOL_DESC`.
const fn count_base_pools() -> usize {
    let mut n = 0usize;
    let mut i = 0;
    while i < POOL_DESC.len() {
        n += subpool_count_for(POOL_DESC[i].max_size);
        i += 1;
    }
    n
}

const NUM_BASE_POOLS: usize = POOL_DESC.len();
const NUM_BASE_SUBPOOLS: usize = count_base_pools();

const fn overflow_subpool_count(class_index: usize) -> usize {
    if class_index == 0 {
        TINY_CELL_OVERFLOW_SUBPOOLS
    } else {
        DEFAULT_OVERFLOW_SUBPOOLS
    }
}

const fn count_overflow_pools() -> usize {
    let mut count = 0usize;
    let mut class_index = 0usize;
    while class_index < NUM_BASE_POOLS {
        count += overflow_subpool_count(class_index);
        class_index += 1;
    }
    count
}

const NUM_OVERFLOW_SUBPOOLS: usize = count_overflow_pools();
const NUM_TOTAL_POOLS: usize = NUM_BASE_SUBPOOLS + NUM_OVERFLOW_SUBPOOLS;
const _: () = assert!(NUM_TOTAL_POOLS < NO_POOL as usize);

// ---------------------------------------------------------------------------
// FreeLink: out-of-band returned-cell list node
// ---------------------------------------------------------------------------

/// One entry in the pool's freed-cell array. Each cell position has a
/// corresponding `FreeLink`, but virgin cells are handed out by index and
/// never linked. The `next` field only forms a list of cells that were
/// actually returned by the game.
///
/// State encoding:
/// - `next == NULL`: issued and allocated, not on the free list
/// - `next == FREE_LINK_TAIL`: free and at the tail of the freelist
/// - otherwise: free and linked to the next freelist node
///
/// Virgin entries are also zero-filled, but `next_virgin_cell` excludes them
/// from live/free classification until the corresponding cell is issued.
///
/// The link array is completely disjoint from user cell memory, so
/// freeing a cell does not touch the cell's bytes.
#[repr(C)]
struct FreeLink {
    next: *mut FreeLink,
}

/// Invalid aligned pointer used as the freelist tail marker.
///
/// A NULL `next` marks an allocated cell. Without a distinct tail marker,
/// a double-free of the tail cell is indistinguishable from freeing an
/// allocated cell and can create a self-loop, eventually handing the same
/// cell out twice.
const FREE_LINK_TAIL: *mut FreeLink = std::ptr::dangling_mut::<FreeLink>();

#[derive(Copy, Clone, Debug)]
pub struct PoolPtrInfo {
    pub pool_index: u8,
    pub item_size: u32,
    pub cell_index: usize,
    pub cell_start: usize,
    pub offset: usize,
    pub committed: bool,
    pub issued: bool,
    pub is_free: bool,
}

#[derive(Clone, Copy, Default)]
pub struct PoolClassUsage {
    pub class_index: u8,
    pub item_size: u32,
    pub live_cells: usize,
    pub committed_bytes: usize,
    pub reserved_bytes: usize,
}

// ---------------------------------------------------------------------------
// Pool
// ---------------------------------------------------------------------------

struct Pool {
    item_size: u32,
    max_size: u32,
    max_cell_count: u32,
    class_index: u8,
    subpool_index: u8,
    subpool_count: u8,
    overflow: bool,

    /// VA reservation base (POOL_ALIGN-aligned). NULL until `state`
    /// reaches `POOL_STATE_INIT` (lazy reservation).
    base: *mut u8,
    /// End of the committed prefix within the reservation. NULL until lazy
    /// initialization completes.
    committed_end: *mut u8,
    /// End of reservation (base + max_size). NULL until lazy init.
    end: *mut u8,

    /// Reserved out-of-band link array (one `FreeLink` per possible cell).
    /// Pages are committed with the matching user-memory prefix. NULL until
    /// lazy initialization.
    cell_links: *mut FreeLink,
    /// Head of the list containing only cells returned by `free`.
    free_head: *mut FreeLink,
    /// First cell never returned to the game. All lower indices have been
    /// issued at least once and therefore have meaningful link state.
    next_virgin_cell: u32,
    /// Number of complete cells backed by committed user and metadata pages.
    committed_cell_count: u32,

    /// Diagnostics: live cell count.
    live_cells: AtomicU32,
    /// Commit high-water mark in bytes (distance from base to committed_end).
    committed_bytes: AtomicU32,
    /// Committed out-of-band `FreeLink` metadata.
    metadata_bytes: AtomicU32,

    /// Pool index (for diagnostics).
    index: u8,

    /// Per-pool lifecycle state. Start: `POOL_STATE_NOT_INIT`. First
    /// alloc flips NotInit -> Initing -> Init (or Failed). Checked
    /// on every alloc and on every `pool_from_addr` lookup so that
    /// not-yet-inited pools don't match spurious pointers.
    state: AtomicU8,

    /// Watchdog generation in which the most recent retryable reservation
    /// failure occurred. Prevents a failed class from rescanning VAS on every
    /// allocation request.
    retry_generation: AtomicU32,

    /// Per-pool spinlock. Normal alloc/free and pool refill are constant-work
    /// under this lock; refill performs bounded VirtualAlloc calls but never
    /// walks every cell in a committed chunk.
    /// Lazy-init winner also holds the global `INIT_LOCK` to serialise
    /// addr_to_pool claim + VirtualAlloc against other pools' init.
    lock: AtomicU32,
}

// Safety: Pool is protected by its own spinlock. Raw pointers inside
// are not shared with any Rust borrow checker.
unsafe impl Send for Pool {}
unsafe impl Sync for Pool {}

impl Pool {
    const fn empty() -> Self {
        Self {
            item_size: 0,
            max_size: 0,
            max_cell_count: 0,
            class_index: 0,
            subpool_index: 0,
            subpool_count: 0,
            overflow: false,
            base: ptr::null_mut(),
            committed_end: ptr::null_mut(),
            end: ptr::null_mut(),
            cell_links: ptr::null_mut(),
            free_head: ptr::null_mut(),
            next_virgin_cell: 0,
            committed_cell_count: 0,
            live_cells: AtomicU32::new(0),
            committed_bytes: AtomicU32::new(0),
            metadata_bytes: AtomicU32::new(0),
            index: 0,
            state: AtomicU8::new(POOL_STATE_NOT_INIT),
            retry_generation: AtomicU32::new(0),
            lock: AtomicU32::new(0),
        }
    }

    #[inline]
    fn is_inited(&self) -> bool {
        self.state.load(Ordering::Acquire) == POOL_STATE_INIT
    }

    #[inline]
    fn acquire(&self) {
        loop {
            if self
                .lock
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
            while self.lock.load(Ordering::Relaxed) != 0 {
                std::hint::spin_loop();
            }
        }
    }

    #[inline]
    fn release(&self) {
        self.lock.store(0, Ordering::Release);
    }

    /// Convert a FreeLink pointer (inside cell_links array) to the
    /// matching user cell address inside the pool's VA range.
    #[inline]
    fn link_to_cell(&self, link: *mut FreeLink) -> *mut u8 {
        let link_idx = (link as usize - self.cell_links as usize) / std::mem::size_of::<FreeLink>();
        unsafe { self.base.add(link_idx * self.item_size as usize) }
    }

    /// Convert a user cell address to the matching `FreeLink` pointer.
    #[inline]
    fn cell_to_link(&self, cell: *mut u8) -> *mut FreeLink {
        let cell_idx = (cell as usize - self.base as usize) / self.item_size as usize;
        unsafe { self.cell_links.add(cell_idx) }
    }

    /// Commit one more `POOL_BLOCK_SIZE` prefix from the reservation.
    /// Caller holds the pool lock.
    ///
    /// Metadata pages are committed before the matching user pages. State is
    /// published only after both commits succeed, so a failed user commit can
    /// be retried safely. Virgin cells need no initialization: committed
    /// metadata pages are zero-filled and a zero link becomes the live-cell
    /// state when its virgin cell is issued.
    unsafe fn grow(&mut self) -> GrowResult {
        if self.committed_end >= self.end {
            return GrowResult::Full;
        }

        let timer = diagnostics::Stopwatch::start_if_hitch_profiling();
        let mut metadata_committed_now = 0usize;

        let block_start = self.committed_end;
        let remaining = self.end as usize - block_start as usize;
        let commit_size = remaining.min(POOL_BLOCK_SIZE);
        let new_committed_end = unsafe { block_start.add(commit_size) };
        let committed_user_bytes = new_committed_end as usize - self.base as usize;
        let committed_cell_count =
            (committed_user_bytes / self.item_size as usize).min(self.max_cell_count as usize);
        let metadata_required =
            (committed_cell_count * std::mem::size_of::<FreeLink>()).div_ceil(0x1000) * 0x1000;
        let metadata_committed = self.metadata_bytes.load(Ordering::Relaxed) as usize;

        if metadata_required > metadata_committed {
            let metadata_delta = metadata_required - metadata_committed;
            let metadata_start =
                unsafe { (self.cell_links as *mut u8).add(metadata_committed) as *const c_void };
            let metadata_commit = unsafe {
                VirtualAlloc(
                    Some(metadata_start),
                    metadata_delta,
                    MEM_COMMIT,
                    PAGE_READWRITE,
                )
            };
            if metadata_commit.is_null() {
                record_grow_timing(timer, self.index, self.item_size, false, 0, 0);
                log::error!(
                    "[POOL] Metadata commit failed: pool={} item_size={} addr=0x{:08x} size={}",
                    self.index,
                    self.item_size,
                    metadata_start as usize,
                    metadata_delta,
                );
                return GrowResult::CommitFailed;
            }
            self.metadata_bytes
                .store(metadata_required as u32, Ordering::Relaxed);
            metadata_committed_now = metadata_delta;
        }

        let user_commit = unsafe {
            VirtualAlloc(
                Some(block_start as *const c_void),
                commit_size,
                MEM_COMMIT,
                PAGE_READWRITE,
            )
        };
        if user_commit.is_null() {
            record_grow_timing(
                timer,
                self.index,
                self.item_size,
                false,
                0,
                metadata_committed_now,
            );
            log::error!(
                "[POOL] Commit failed: pool={} item_size={} addr=0x{:08x} size={}",
                self.index,
                self.item_size,
                block_start as usize,
                commit_size,
            );
            return GrowResult::CommitFailed;
        }

        self.committed_end = new_committed_end;
        self.committed_cell_count = committed_cell_count as u32;
        self.committed_bytes
            .fetch_add(commit_size as u32, Ordering::Relaxed);
        record_grow_timing(
            timer,
            self.index,
            self.item_size,
            true,
            commit_size,
            metadata_committed_now,
        );

        GrowResult::Grown
    }

    /// Fast path allocation. Reuse returned cells first to preserve the
    /// allocator's existing LIFO and memory-pressure behavior; otherwise
    /// advance through the committed virgin-cell prefix.
    unsafe fn alloc(&mut self) -> PoolAllocResult {
        let cell = if !self.free_head.is_null() {
            let link = self.free_head;
            unsafe {
                let next = (*link).next;
                self.free_head = if next == FREE_LINK_TAIL {
                    null_mut()
                } else {
                    next
                };
                (*link).next = null_mut();
            }
            self.link_to_cell(link)
        } else {
            if self.next_virgin_cell >= self.committed_cell_count {
                match unsafe { self.grow() } {
                    GrowResult::Grown => {}
                    GrowResult::Full => return PoolAllocResult::Full,
                    GrowResult::CommitFailed => return PoolAllocResult::CommitFailed,
                }
            }
            if self.next_virgin_cell >= self.committed_cell_count {
                return PoolAllocResult::Full;
            }

            let cell_index = self.next_virgin_cell as usize;
            self.next_virgin_cell += 1;
            unsafe { self.base.add(cell_index * self.item_size as usize) }
        };

        self.live_cells.fetch_add(1, Ordering::Relaxed);
        PoolAllocResult::Allocated(cell)
    }

    /// Fast path free: push a cell onto the returned-cell list. No writes to
    /// cell data.
    ///
    /// # Known latent crash: BSTreeNode C0000417
    ///
    /// Immediate LIFO reuse is NVHR-style and matches vanilla SBM, but the
    /// game's PDD processing order does not match that assumption for
    /// BSTreeNode/NiRefObject chains. Observed crash chain (exactly the
    /// pattern in analysis/ghidra/output/memory/havok_gc_thread_analysis.txt
    /// and memory note project_bstreenode_crash_chain.md):
    ///
    ///   1. Cell transition queues BSTreeNode to PDD NiNode queue.
    ///   2. Per-frame PDD (10-20 entries/frame) plus our periodic Stage 4
    ///      (10 s cooldown) drain the queue. Stage 4 can free a child
    ///      NiRefObject before the parent BSTreeNode is processed within
    ///      the same Stage 4 call.
    ///   3. Because this freelist is LIFO with zero reuse cooldown, the
    ///      very next alloc for the same size class pops the just-freed
    ///      cell and the caller writes new content into it.
    ///   4. Parent BSTreeNode destructor (via FUN_00CFCC2C) walks its
    ///      child list, dereferences the overwritten cell -> RefCount:0
    ///      or garbage vtable -> CRT invalid-parameter fastfail (C0000417)
    ///      around 0x00EC7C62.
    ///
    /// Confirmed repro: 2026-04-18 18:22, Playtime 4:56 (~47 min real
    /// time), CrashLogger 2026-04-18-18-32-08.log. Stack classes:
    /// BSTreeNode (refcount=0), BSTreeModel, BSFadeNode "RockCanyon12".
    /// Model: "\WastelandUndergrowth01.spt". Trigger: [OOM] Stage 4 ->
    /// 5: done=1 freed=704KB at 15:32:07.240, crash 982 ms later at
    /// 15:32:08.222.
    ///
    /// # Why this was not caught sooner
    ///
    /// The latent bug dates from commit 35a326b ("grand allocator re-write")
    /// which replaced slab.rs with pool.rs and dropped the zombie-safety
    /// mechanism. The prior slab had a narrower DESTRUCTION_FREEZE flag
    /// that skipped cold-list reuse during Stage 5 (cell unload). Before
    /// the slab, an even older design used a 2-epoch quarantine that
    /// protected this exact chain (see memory note
    /// project_bstreenode_crash_chain.md and project_epoch_quarantine.md).
    ///
    /// The crash is probabilistic: it needs Stage 4 to free a child and
    /// the very next alloc (same size class, same thread) to land on
    /// that cell before the parent is processed. Earlier runs on this
    /// new pool either ran shorter in real time or crashed first on
    /// other paths (d3d9 coc texture-load, Havok watchdog UAF, Havok
    /// AI Linear Task Thread 2 UAF). Each of those masked this crash
    /// by killing the process first. Once the masking crashes were
    /// removed, this one surfaced on a 47-minute stress run.
    ///
    /// # Known latent crash 2: JIP DoQueuedReferenceHook ragdoll NULL-bone
    ///
    /// Second instance of the same zombie-reuse family, different game
    /// code path. Observed 2026-04-18 19:36, Playtime 1:29 (ragdoll-
    /// heavy cell burst), CrashLogger.2026-04-18-19-36-18.log. Thread:
    /// main. EIP=0x00A6DF48, ESI=0x00000034, read fault at 0x34.
    ///
    /// Call chain:
    ///   main loop -> 0x0086E89C -> 0x00C3DD8E
    ///     -> jip_nvse DoQueuedReferenceHook
    ///       -> 0x0045211D -> 0x0056F8D4 -> 0x00931443 -> 0x00C7D866
    ///         -> 0x00C796F7 (Havok quaternion setup)
    ///           -> 0x00A6DF48 (FLD float ptr [ESI] with ESI=0x34)
    ///
    /// Stack classes: bhkRagdollController, bhkWorldM, Character "Enclave
    /// Soldier" (FormID 06023376) with NEED_TO_CHANGE_PROCESS flag,
    /// QueuedCharacter for same FormID. Pre-existing Ghidra analysis at
    /// analysis/ghidra/output/crash/crash_00A6DF48_analysis.txt.
    ///
    /// Mechanism from the decompiled caller FUN_00c79680 at +0x77:
    ///
    ///   FUN_00c74dd0(&local_80,
    ///                (float *)(*(int *)(local_94 +
    ///                          *(int *)(local_90 + 0xa4)) + 0x34));
    ///
    /// The ragdoll's bone-array entry (`*(int *)(local_94 + base)`) was
    /// NULL -- freed by our pool and reused (cell overwritten with new
    /// content) while the parent queued-reference was still holding a
    /// pointer to the array slot. Adding 0x34 to NULL gave ESI=0x34;
    /// the downstream FLD [ESI] took the AV.
    ///
    /// Correlates with a 10-second cascade of mid-size pool exhausts
    /// (2048 B, 3072 B, 3584 B) that started ~10 s before the crash,
    /// increasing the reuse-rate for those classes. Ragdoll bone data
    /// lives in this size range.
    ///
    /// # Known latent crash 3: Process::LowProcess dead-actor
    ///
    /// Third instance. 2026-04-18 17:47, 2:22 play, Giant Soldier Ant
    /// with HAVOK_DEATH + NEED_TO_CHANGE_PROCESS. Crash inside a replaced
    /// LowProcess virtual while walking a process-migration pointer chain;
    /// same pattern (parent still referencing freed-and-reused child).
    /// CrashLogger.2026-04-18-17-47-55.log.
    ///
    /// # Current status
    ///
    /// A general reuse cooldown or epoch quarantine conflicts with the
    /// rest of this allocator's design (NVHR-style immediate reuse,
    /// bounded 512 MB budget, no epoch infrastructure). A scoped PDD
    /// freeze experiment was removed after playtesting showed it could
    /// hang the game faster. This path is back to immediate LIFO reuse;
    /// stale-pointer protection belongs in specific engine guards until
    /// we have a proven allocator-wide contract.
    unsafe fn free(&mut self, cell: *mut u8) -> bool {
        let link = self.cell_to_link(cell);
        unsafe {
            // Double-free guard: free cells always have either a real
            // next pointer or FREE_LINK_TAIL. Allocated cells are the
            // only cells with NULL next.
            if !(*link).next.is_null() {
                log::error!(
                    "[POOL] Double-free ignored: pool={} cell={:p}",
                    self.index,
                    cell,
                );
                return false;
            }
            (*link).next = if self.free_head.is_null() {
                FREE_LINK_TAIL
            } else {
                self.free_head
            };
            self.free_head = link;
        }
        self.live_cells.fetch_sub(1, Ordering::Relaxed);
        true
    }

    /// Return true if `addr` is inside this pool's reservation.
    #[inline]
    fn contains(&self, addr: *const c_void) -> bool {
        let a = addr as usize;
        a >= self.base as usize && a < self.end as usize
    }

    /// Inspect one pool cell while the caller holds `self.lock`.
    fn ptr_info_locked(&self, addr: *const c_void) -> Option<PoolPtrInfo> {
        if !self.contains(addr) {
            return None;
        }

        let addr = addr as usize;
        let cell_offset = addr - self.base as usize;
        let cell_index = cell_offset / self.item_size as usize;
        if cell_index >= self.max_cell_count as usize {
            return None;
        }

        let cell_start = self.base as usize + cell_index * self.item_size as usize;
        let committed = cell_index < self.committed_cell_count as usize;
        let issued = cell_index < self.next_virgin_cell as usize;
        let link = unsafe { self.cell_links.add(cell_index) };
        Some(PoolPtrInfo {
            pool_index: self.index,
            item_size: self.item_size,
            cell_index,
            cell_start,
            offset: addr - cell_start,
            committed,
            issued,
            // Never inspect metadata for an unissued cell. Its page is
            // committed, but it has not yet become allocator-visible state.
            is_free: issued && unsafe { !(*link).next.is_null() },
        })
    }

    unsafe fn tombstone_free_cell(
        &mut self,
        ptr: *mut c_void,
        vtable: usize,
        refcount: i32,
    ) -> Option<PoolPtrInfo> {
        let info = self.ptr_info_locked(ptr)?;
        if !info.committed || !info.issued || info.offset != 0 || info.item_size < 12 {
            return None;
        }
        if !info.is_free {
            return None;
        }

        unsafe {
            ptr::write_unaligned(info.cell_start as *mut usize, vtable);
            ptr::write_unaligned((info.cell_start + 8) as *mut i32, refcount);
        }

        Some(info)
    }
}

// ---------------------------------------------------------------------------
// PoolHeap: singleton
// ---------------------------------------------------------------------------

pub struct PoolHeap {
    pools: [Pool; NUM_TOTAL_POOLS],
    /// First concrete subpool index for each size class.
    class_start: [u8; NUM_BASE_POOLS],
    /// Number of concrete subpools for each size class.
    class_count: [u8; NUM_BASE_POOLS],
    /// Allocation starts here for each class. Updated on successful
    /// alloc/free so hot paths avoid walking full subpools.
    class_hint: [AtomicU8; NUM_BASE_POOLS],
    /// Per-class bounded-capacity refusals. Updated only on failure.
    class_exhaustions: [AtomicU64; NUM_BASE_POOLS],
    /// Versioned per-class exhaustion cache. Bit zero is the cached failure;
    /// upper bits change on every free or retry generation. A failure CAS can
    /// therefore never overwrite a concurrent free notification.
    class_state: [AtomicU32; NUM_BASE_POOLS],
    /// size_to_class[(size + 3) >> 2] = class index, or NO_POOL if size
    /// exceeds POOL_MAX_SIZE. Filled at heap create; independent of
    /// per-subpool reservation state.
    size_to_class: [u8; SIZE_LOOKUP_LEN],
    /// addr_to_pool[ptr >> POOL_ALIGN_BITS] = pool index, or NO_POOL
    /// if no pool actually reserved that slot. Populated lazily by
    /// `lazy_init_pool` as individual pools come online; entries are
    /// guarded by `INIT_LOCK`.
    ///
    /// Uses `AtomicU8` so readers on the alloc/free hot path can load
    /// without locking. Writers (lazy init) hold `INIT_LOCK` to
    /// serialise slot claims.
    addr_to_pool: [AtomicU8; ADDR_LOOKUP_LEN],
    /// Serialises the "scan free slots + VirtualAlloc + claim slots"
    /// sequence across concurrent lazy-init attempts on different
    /// pools. Not taken on the alloc/free hot paths -- only on the
    /// first alloc for a not-yet-inited size class.
    init_lock: Mutex<()>,
}

unsafe impl Send for PoolHeap {}
unsafe impl Sync for PoolHeap {}

/// Populate a concrete subpool descriptor. Called at heap-create time
/// so size dispatch works before any subpool has lazy-inited.
fn assign_pool_desc(
    pool: &mut Pool,
    pool_idx: u8,
    class_idx: u8,
    desc: &PoolDesc,
    subpool_idx: u8,
    subpool_count: u8,
    overflow: bool,
) {
    let max_size = if overflow {
        POOL_SUBPOOL_SIZE
    } else {
        let used_before = subpool_idx as u32 * POOL_SUBPOOL_SIZE;
        desc.max_size
            .saturating_sub(used_before)
            .min(POOL_SUBPOOL_SIZE)
    };
    let max_cell_count = max_size / desc.item_size;
    pool.item_size = desc.item_size;
    pool.max_size = max_size;
    pool.max_cell_count = max_cell_count;
    pool.class_index = class_idx;
    pool.subpool_index = subpool_idx;
    pool.subpool_count = subpool_count;
    pool.overflow = overflow;
    pool.index = pool_idx;
    // Address fields and cell_links stay NULL until lazy initialization.
}

impl PoolHeap {
    /// Create the heap shell. Assigns subpool descriptors and the
    /// size_to_class lookup, but does NOT reserve any VA. Individual
    /// subpools reserve their VA lazily on first alloc via
    /// `ensure_pool_inited` / `lazy_init_pool`. This keeps our startup
    /// VA footprint near zero, matching vanilla SBM's grow-on-demand
    /// behaviour instead of stealing the game's working budget.
    fn create() -> Option<Box<Self>> {
        let mut heap = Box::new(PoolHeap {
            pools: std::array::from_fn(|_| Pool::empty()),
            class_start: [NO_POOL; NUM_BASE_POOLS],
            class_count: [0; NUM_BASE_POOLS],
            class_hint: std::array::from_fn(|_| AtomicU8::new(0)),
            class_exhaustions: std::array::from_fn(|_| AtomicU64::new(0)),
            class_state: std::array::from_fn(|_| AtomicU32::new(0)),
            size_to_class: [NO_POOL; SIZE_LOOKUP_LEN],
            addr_to_pool: std::array::from_fn(|_| AtomicU8::new(NO_POOL)),
            init_lock: Mutex::new(()),
        });

        // Expand normal class capacity and append dormant overflow
        // descriptors. No descriptor reserves VA until first use.
        let mut pool_idx = 0usize;
        for (class_idx, desc) in POOL_DESC.iter().enumerate() {
            let base_count = subpool_count_for(desc.max_size);
            let count = base_count + overflow_subpool_count(class_idx);
            heap.class_start[class_idx] = pool_idx as u8;
            heap.class_count[class_idx] = count as u8;
            for subpool_idx in 0..count {
                let Some(pool) = heap.pools.get_mut(pool_idx) else {
                    log::error!(
                        "[POOL] Descriptor expansion exceeded {} configured pools",
                        NUM_TOTAL_POOLS
                    );
                    return None;
                };
                assign_pool_desc(
                    pool,
                    pool_idx as u8,
                    class_idx as u8,
                    desc,
                    subpool_idx as u8,
                    count as u8,
                    subpool_idx >= base_count,
                );
                pool_idx += 1;
            }
        }

        if pool_idx != NUM_TOTAL_POOLS {
            log::error!(
                "[POOL] Descriptor expansion produced {} pools, expected {}",
                pool_idx,
                NUM_TOTAL_POOLS
            );
            return None;
        }

        // Build size_to_class lookup.
        // Independent of reservation state; populated once at create().
        for (class_idx, desc) in POOL_DESC.iter().enumerate() {
            let upper = (desc.item_size as usize >> 2).min(SIZE_LOOKUP_LEN - 1);
            let mut i = upper;
            while i > 0 && heap.size_to_class[i] == NO_POOL {
                heap.size_to_class[i] = class_idx as u8;
                i -= 1;
            }
            if i == 0 && heap.size_to_class[0] == NO_POOL {
                heap.size_to_class[0] = class_idx as u8;
            }
        }

        log::info!(
            "[POOL] Ready (subpool lazy): {} classes -> {} base + {} overflow descriptors of up to {}MB (overflow soft limit={}MB), 0MB reserved upfront",
            NUM_BASE_POOLS,
            NUM_BASE_SUBPOOLS,
            NUM_OVERFLOW_SUBPOOLS,
            POOL_ALIGN / 1024 / 1024,
            OVERFLOW_RESERVATION_SOFT_LIMIT / 1024 / 1024,
        );

        Some(heap)
    }

    /// First-alloc hook. Ensures pool at `idx` is in `INIT` state.
    ///
    /// Fast path: a single `Acquire` load; no lock taken if already
    /// initialised. Slow path (first alloc for this subpool) takes the
    /// global `init_lock` while it scans slots + `VirtualAlloc`s +
    /// claims `addr_to_pool` entries. Concurrent initialisers on
    /// DIFFERENT pools spin-wait; after one pool finishes, the next
    /// proceeds.
    fn ensure_pool_inited(&self, idx: usize) -> InitResult {
        let state = self.pools[idx].state.load(Ordering::Acquire);
        match state {
            POOL_STATE_INIT => InitResult::Ready,
            POOL_STATE_PERMANENT => InitResult::Unavailable,
            POOL_STATE_RETRYABLE
                if self.pools[idx].retry_generation.load(Ordering::Relaxed)
                    == RESERVATION_RETRY_GENERATION.load(Ordering::Acquire) =>
            {
                InitResult::ResourceFailure
            }
            _ => self.lazy_init_pool(idx),
        }
    }

    #[cold]
    fn lazy_init_pool(&self, idx: usize) -> InitResult {
        loop {
            let state = self.pools[idx].state.load(Ordering::Acquire);
            let retry_generation = RESERVATION_RETRY_GENERATION.load(Ordering::Acquire);
            match state {
                POOL_STATE_INIT => return InitResult::Ready,
                POOL_STATE_PERMANENT => return InitResult::Unavailable,
                POOL_STATE_RETRYABLE
                    if self.pools[idx].retry_generation.load(Ordering::Relaxed)
                        == retry_generation =>
                {
                    return InitResult::ResourceFailure;
                }
                POOL_STATE_INITING => {
                    while self.pools[idx].state.load(Ordering::Acquire) == POOL_STATE_INITING {
                        std::hint::spin_loop();
                    }
                    continue;
                }
                POOL_STATE_NOT_INIT | POOL_STATE_RETRYABLE => {}
                _ => return InitResult::Unavailable,
            }

            match self.pools[idx].state.compare_exchange(
                state,
                POOL_STATE_INITING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }

        let result = self.do_reserve(idx);
        let state = match result {
            ReserveResult::Ready => POOL_STATE_INIT,
            ReserveResult::Retryable => {
                self.pools[idx].retry_generation.store(
                    RESERVATION_RETRY_GENERATION.load(Ordering::Acquire),
                    Ordering::Relaxed,
                );
                POOL_STATE_RETRYABLE
            }
            ReserveResult::Permanent => POOL_STATE_PERMANENT,
        };
        self.pools[idx].state.store(state, Ordering::Release);
        match result {
            ReserveResult::Ready => InitResult::Ready,
            ReserveResult::Retryable => InitResult::ResourceFailure,
            ReserveResult::Permanent => InitResult::Unavailable,
        }
    }

    /// Reserve user VA and freed-cell metadata for pool `idx`. Caller must
    /// have just transitioned the pool to `POOL_STATE_INITING`.
    /// Takes `init_lock` for addr_to_pool coordination.
    fn do_reserve(&self, idx: usize) -> ReserveResult {
        let timer = diagnostics::Stopwatch::start_if_hitch_profiling();
        let _guard = match self.init_lock.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        // We hold init_lock (serialises addr_to_pool writes) and own
        // the pool's INITING state (no other thread mutates this pool's
        // address or allocation state). Access via raw pointer to avoid the
        // invalid-reference-cast lint while still respecting the lock.
        let pool_ptr: *mut Pool = &self.pools[idx] as *const Pool as *mut Pool;

        let item_size = unsafe { (*pool_ptr).item_size };
        let max_size = unsafe { (*pool_ptr).max_size };
        let max_cell_count = unsafe { (*pool_ptr).max_cell_count };
        let class_index = unsafe { (*pool_ptr).class_index };
        let subpool_index = unsafe { (*pool_ptr).subpool_index };
        let subpool_count = unsafe { (*pool_ptr).subpool_count };
        let overflow = unsafe { (*pool_ptr).overflow };
        let metadata_reserved_bytes =
            (max_cell_count as usize * std::mem::size_of::<FreeLink>()).div_ceil(0x1000) * 0x1000;

        if overflow {
            let overflow_user = OVERFLOW_USER_RESERVED_BYTES.load(Ordering::Relaxed);
            let overflow_metadata = OVERFLOW_METADATA_RESERVED_BYTES.load(Ordering::Relaxed);
            let overflow_total = overflow_user.saturating_add(overflow_metadata);
            let reservation_bytes = (max_size as usize).saturating_add(metadata_reserved_bytes);
            if overflow_total < OVERFLOW_RESERVATION_SOFT_LIMIT
                && overflow_total.saturating_add(reservation_bytes)
                    >= OVERFLOW_RESERVATION_SOFT_LIMIT
            {
                log::warn!(
                    "[POOL] Exact-size overflow crossed soft reservation limit: current={}MB request={}MB limit={}MB",
                    overflow_total / 1024 / 1024,
                    reservation_bytes / 1024 / 1024,
                    OVERFLOW_RESERVATION_SOFT_LIMIT / 1024 / 1024,
                );
            }

            let free_vas = super::allocator::current_free_vas();
            if free_vas
                <= super::allocator::VAS_CRITICAL_REMAINING.saturating_add(reservation_bytes)
            {
                log_overflow_refusal(
                    class_index,
                    item_size,
                    "vas_pressure",
                    free_vas / 1024 / 1024,
                );
                return ReserveResult::Retryable;
            }
        }

        let slots_needed = (max_size as usize).div_ceil(POOL_ALIGN);
        if slots_needed == 0 {
            log::error!(
                "[POOL] #{} item_size={} max_size={} < POOL_ALIGN",
                idx,
                item_size,
                max_size,
            );
            return ReserveResult::Permanent;
        }

        let mut reserved_base: *mut u8 = ptr::null_mut();
        let mut claim_slot: usize = 0;
        let mut default_tail_backing = false;

        // High-fit scan. The game, Havok, and D3D still make their own
        // contiguous VA reservations during streaming. Keeping gheap's
        // pool slabs high avoids consuming low/mid holes first.
        //
        // Leave slot 0 unused (NULL-looking pointers) and leave the
        // top slot unused so `base + max_size` stays representable
        // on 32-bit targets instead of wrapping to zero.
        if slots_needed + 1 >= ADDR_LOOKUP_LEN {
            log::error!(
                "[POOL] #{} lazy reserve failed: item_size={} max_size={}MB (reservation too large)",
                idx,
                item_size,
                max_size / 1024 / 1024,
            );
            return ReserveResult::Permanent;
        }

        // Reserve metadata before consuming a user range. Metadata remains
        // uncommitted until grow() exposes the matching cells, avoiding the
        // multi-megabyte first-touch commit previously paid here.
        let metadata_ptr =
            unsafe { VirtualAlloc(None, metadata_reserved_bytes, MEM_RESERVE, PAGE_READWRITE) };
        if metadata_ptr.is_null() {
            log::error!(
                "[POOL] #{} link metadata reservation failed ({} KB)",
                idx,
                metadata_reserved_bytes / 1024,
            );
            return ReserveResult::Retryable;
        }

        let adopted = super::vanilla_large_heap::try_alloc_default_tail(
            max_size as usize,
            POOL_ALIGN,
            "pool",
            false,
        );
        if !adopted.is_null() {
            let adopted_addr = adopted as usize;
            let slot = adopted_addr >> POOL_ALIGN_BITS;
            let aligned = adopted_addr.is_multiple_of(POOL_ALIGN);
            let in_range = slot + slots_needed <= ADDR_LOOKUP_LEN;
            let mut clear = aligned && in_range;
            if clear {
                for s in slot..slot + slots_needed {
                    if self.addr_to_pool[s].load(Ordering::Relaxed) != NO_POOL {
                        clear = false;
                        break;
                    }
                }
            }
            if clear {
                reserved_base = adopted as *mut u8;
                claim_slot = slot;
                default_tail_backing = true;
            } else {
                log::error!(
                    "[POOL] #{} adopted Default-tail range rejected: base=0x{:08x} aligned={} slot={} slots_needed={} in_range={}",
                    idx,
                    adopted_addr,
                    aligned,
                    slot,
                    slots_needed,
                    in_range,
                );
            }
        }

        if reserved_base.is_null() {
            let mut slot: usize = ADDR_LOOKUP_LEN - slots_needed - 1;
            while slot > 0 {
                let mut clear = true;
                for s in slot..slot + slots_needed {
                    if self.addr_to_pool[s].load(Ordering::Relaxed) != NO_POOL {
                        clear = false;
                        break;
                    }
                }
                if clear {
                    let hint = (slot * POOL_ALIGN) as *mut c_void;
                    let ptr = unsafe {
                        VirtualAlloc(Some(hint), max_size as usize, MEM_RESERVE, PAGE_READWRITE)
                    };
                    if !ptr.is_null() && (ptr as usize) == slot * POOL_ALIGN {
                        reserved_base = ptr as *mut u8;
                        claim_slot = slot;
                        break;
                    }
                    if !ptr.is_null() {
                        let _ = unsafe {
                            windows::Win32::System::Memory::VirtualFree(
                                ptr,
                                0,
                                windows::Win32::System::Memory::MEM_RELEASE,
                            )
                        };
                    }
                }
                slot -= 1;
            }
        }

        if reserved_base.is_null() {
            log::error!(
                "[POOL] #{} lazy reserve failed: item_size={} max_size={}MB (all scanned slots taken)",
                idx,
                item_size,
                max_size / 1024 / 1024,
            );
            let _ = unsafe {
                windows::Win32::System::Memory::VirtualFree(
                    metadata_ptr,
                    0,
                    windows::Win32::System::Memory::MEM_RELEASE,
                )
            };
            return ReserveResult::Retryable;
        }

        // Commit the pool's state via raw pointer writes.
        unsafe {
            (*pool_ptr).base = reserved_base;
            (*pool_ptr).committed_end = reserved_base;
            (*pool_ptr).end = reserved_base.add(max_size as usize);
            (*pool_ptr).cell_links = metadata_ptr as *mut FreeLink;
            (*pool_ptr).free_head = ptr::null_mut();
            (*pool_ptr).next_virgin_cell = 0;
            (*pool_ptr).committed_cell_count = 0;
            (*pool_ptr).metadata_bytes.store(0, Ordering::Relaxed);
        }

        // Claim addr_to_pool slots. Readers on the hot path will see
        // our writes once state flips to INIT (Release pair in
        // `lazy_init_pool` with an Acquire load in `is_inited`).
        for s in claim_slot..claim_slot + slots_needed {
            self.addr_to_pool[s].store(idx as u8, Ordering::Relaxed);
        }

        if overflow {
            OVERFLOW_USER_RESERVED_BYTES.fetch_add(max_size as usize, Ordering::Relaxed);
            OVERFLOW_METADATA_RESERVED_BYTES.fetch_add(metadata_reserved_bytes, Ordering::Relaxed);
        }

        record_init_timing(timer, idx as u8, item_size);

        log::debug!(
            "[POOL] class #{} {}B initialized: subpool {}/{} (#{}) user={}MB at 0x{:08x}..0x{:08x} metadata={}KB source={} overflow={}",
            class_index,
            item_size,
            subpool_index + 1,
            subpool_count,
            idx,
            max_size / 1024 / 1024,
            reserved_base as usize,
            reserved_base as usize + max_size as usize,
            metadata_reserved_bytes / 1024,
            if default_tail_backing {
                "default-tail"
            } else {
                "virtualalloc"
            },
            overflow,
        );

        ReserveResult::Ready
    }

    #[inline]
    fn pool_from_addr(&self, addr: *const c_void) -> Option<&Pool> {
        let slot = (addr as usize) >> POOL_ALIGN_BITS;
        if slot >= ADDR_LOOKUP_LEN {
            return None;
        }
        let p = self.addr_to_pool[slot].load(Ordering::Acquire);
        if p == NO_POOL {
            return None;
        }
        if p as usize >= NUM_TOTAL_POOLS {
            return None;
        }
        let pool = &self.pools[p as usize];
        // addr_to_pool may be populated before state reaches INIT, but
        // we only want to match inited pools (otherwise base/end might
        // still be NULL).
        if !pool.is_inited() {
            return None;
        }
        // Slot ownership is a coarse filter; verify the address falls
        // inside the pool's actual reservation (the slot could also
        // straddle the last POOL_ALIGN boundary beyond pool->end).
        if pool.contains(addr) {
            Some(pool)
        } else {
            None
        }
    }

    fn alloc_from_pool(&self, pool_idx: usize) -> PoolAllocResult {
        match self.ensure_pool_inited(pool_idx) {
            InitResult::Ready => {}
            InitResult::Unavailable => return PoolAllocResult::Full,
            InitResult::ResourceFailure => return PoolAllocResult::CommitFailed,
        }
        let pool = &self.pools[pool_idx];
        unsafe {
            let p = pool as *const Pool as *mut Pool;
            (*p).acquire();
            let result = (*p).alloc();
            (*p).release();
            result
        }
    }

    fn alloc_from_class(&self, class_idx: usize) -> ClassAllocResult {
        let start = self.class_start[class_idx] as usize;
        let count = self.class_count[class_idx] as usize;
        if count == 0 {
            return ClassAllocResult::Exhausted;
        }

        let mut hint = self.class_hint[class_idx].load(Ordering::Relaxed) as usize;
        if hint >= count {
            hint = 0;
        }

        for step in 0..count {
            let subpool_idx = (hint + step) % count;
            match self.alloc_from_pool(start + subpool_idx) {
                PoolAllocResult::Allocated(ptr) => {
                    self.class_hint[class_idx].store(subpool_idx as u8, Ordering::Relaxed);
                    return ClassAllocResult::Allocated(ptr as *mut c_void);
                }
                PoolAllocResult::Full => {}
                PoolAllocResult::CommitFailed => return ClassAllocResult::ResourceFailure,
            }
        }

        ClassAllocResult::Exhausted
    }

    pub fn alloc(&self, size: usize) -> *mut c_void {
        let idx = (size + 3) >> 2;
        if idx >= SIZE_LOOKUP_LEN {
            return null_mut();
        }
        let class_idx = self.size_to_class[idx];
        if class_idx == NO_POOL {
            return null_mut();
        }

        let class_idx_u = class_idx as usize;
        let class_state = self.class_state[class_idx_u].load(Ordering::Acquire);
        if class_state & CLASS_STATE_EXHAUSTED != 0 {
            return self.record_class_failure(size, class_idx_u, "cached");
        }
        let reason = match self.alloc_from_class(class_idx_u) {
            ClassAllocResult::Allocated(ptr) => return ptr,
            ClassAllocResult::Exhausted => "capacity",
            ClassAllocResult::ResourceFailure => "resource",
        };
        let _ = self.class_state[class_idx_u].compare_exchange(
            class_state,
            class_state | CLASS_STATE_EXHAUSTED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.record_class_failure(size, class_idx_u, reason)
    }

    #[cold]
    fn record_class_failure(
        &self,
        size: usize,
        class_idx: usize,
        reason: &'static str,
    ) -> *mut c_void {
        let class_failures = self.class_exhaustions[class_idx].fetch_add(1, Ordering::Relaxed) + 1;
        if class_failures.is_power_of_two() {
            let total_failures = self.total_exhaustions();
            log::warn!(
                "[POOL] Allocation refused for size={} class #{}={}B reason={}: class_fails={} total_fails={}",
                size,
                class_idx,
                POOL_DESC[class_idx].item_size,
                reason,
                class_failures,
                total_failures,
            );
        }
        null_mut()
    }

    pub fn free(&self, ptr: *mut c_void) -> bool {
        let pool = match self.pool_from_addr(ptr as *const c_void) {
            Some(p) => p,
            None => return false,
        };
        let class_idx = pool.class_index as usize;
        let subpool_idx = pool.subpool_index;
        unsafe {
            let p = pool as *const Pool as *mut Pool;
            (*p).acquire();
            let freed = match (*p).ptr_info_locked(ptr) {
                Some(info) if info.committed && info.issued && info.offset == 0 => {
                    (*p).free(info.cell_start as *mut u8)
                }
                Some(info) => {
                    log::error!(
                        "[POOL] Invalid free ignored: pool={} ptr={:p} offset={} committed={} issued={}",
                        info.pool_index,
                        ptr,
                        info.offset,
                        info.committed,
                        info.issued,
                    );
                    false
                }
                None => false,
            };
            (*p).release();
            if !freed {
                return true;
            }
        }
        self.class_hint[class_idx].store(subpool_idx, Ordering::Relaxed);
        Self::mark_class_available(&self.class_state[class_idx]);
        true
    }

    fn allow_reservation_retries(&self) {
        RESERVATION_RETRY_GENERATION.fetch_add(1, Ordering::AcqRel);
        for state in &self.class_state {
            Self::mark_class_available(state);
        }
    }

    fn mark_class_available(state: &AtomicU32) {
        let mut current = state.load(Ordering::Relaxed);
        loop {
            let next = current.wrapping_add(CLASS_STATE_GENERATION_STEP) & !CLASS_STATE_EXHAUSTED;
            match state.compare_exchange_weak(current, next, Ordering::Release, Ordering::Relaxed) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }

    pub fn contains(&self, ptr: *const c_void) -> bool {
        self.pool_from_addr(ptr).is_some()
    }

    pub fn usable_size(&self, ptr: *const c_void) -> usize {
        self.pool_from_addr(ptr)
            .map(|p| p.item_size as usize)
            .unwrap_or(0)
    }

    pub fn ptr_info(&self, ptr: *const c_void) -> Option<PoolPtrInfo> {
        let pool = self.pool_from_addr(ptr)?;
        unsafe {
            let p = pool as *const Pool as *mut Pool;
            (*p).acquire();
            let result = (*p).ptr_info_locked(ptr);
            (*p).release();
            result
        }
    }

    pub fn tombstone_free_cell(
        &self,
        ptr: *mut c_void,
        vtable: usize,
        refcount: i32,
    ) -> Option<PoolPtrInfo> {
        let pool = self.pool_from_addr(ptr)?;
        unsafe {
            let p = pool as *const Pool as *mut Pool;
            (*p).acquire();
            let result = (*p).tombstone_free_cell(ptr, vtable, refcount);
            (*p).release();
            result
        }
    }

    pub fn committed_bytes(&self) -> usize {
        self.pools
            .iter()
            .map(|p| p.committed_bytes.load(Ordering::Relaxed) as usize)
            .sum()
    }

    pub fn reserved_bytes(&self) -> usize {
        self.pools
            .iter()
            .filter(|p| p.is_inited())
            .map(|p| p.max_size as usize)
            .sum()
    }

    pub fn metadata_bytes(&self) -> usize {
        self.pools
            .iter()
            .map(|p| p.metadata_bytes.load(Ordering::Relaxed) as usize)
            .sum()
    }

    pub fn metadata_reserved_bytes(&self) -> usize {
        self.pools
            .iter()
            .filter(|p| p.is_inited())
            .map(|p| {
                (p.max_cell_count as usize * std::mem::size_of::<FreeLink>()).div_ceil(0x1000)
                    * 0x1000
            })
            .sum()
    }

    pub fn live_cells(&self) -> usize {
        self.pools
            .iter()
            .map(|p| p.live_cells.load(Ordering::Relaxed) as usize)
            .sum()
    }

    pub fn class_usage(&self) -> [PoolClassUsage; NUM_BASE_POOLS] {
        let mut usage = std::array::from_fn(|class_index| PoolClassUsage {
            class_index: class_index as u8,
            item_size: POOL_DESC[class_index].item_size,
            ..PoolClassUsage::default()
        });
        for pool in &self.pools {
            if !pool.is_inited() {
                continue;
            }
            let class = &mut usage[pool.class_index as usize];
            class.live_cells += pool.live_cells.load(Ordering::Relaxed) as usize;
            class.committed_bytes += pool.committed_bytes.load(Ordering::Relaxed) as usize;
            class.reserved_bytes += pool.max_size as usize;
        }
        usage
    }

    fn total_exhaustions(&self) -> u64 {
        self.class_exhaustions
            .iter()
            .map(|count| count.load(Ordering::Relaxed))
            .sum()
    }
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

use std::sync::OnceLock;
static HEAP: OnceLock<Box<PoolHeap>> = OnceLock::new();

pub fn init() -> bool {
    match PoolHeap::create() {
        Some(h) => {
            let _ = HEAP.set(h);
            true
        }
        None => false,
    }
}

#[inline]
pub fn is_pool_ptr(ptr: *const c_void) -> bool {
    match HEAP.get() {
        Some(h) => h.contains(ptr),
        None => false,
    }
}

#[inline]
pub fn alloc(size: usize) -> *mut c_void {
    match HEAP.get() {
        Some(h) => h.alloc(size),
        None => null_mut(),
    }
}

#[inline]
pub fn free(ptr: *mut c_void) -> bool {
    match HEAP.get() {
        Some(h) => h.free(ptr),
        None => false,
    }
}

#[inline]
pub fn usable_size(ptr: *const c_void) -> usize {
    match HEAP.get() {
        Some(h) => h.usable_size(ptr),
        None => 0,
    }
}

#[inline]
pub fn ptr_info(ptr: *const c_void) -> Option<PoolPtrInfo> {
    HEAP.get().and_then(|h| h.ptr_info(ptr))
}

pub fn tombstone_free_cell(ptr: *mut c_void, vtable: usize, refcount: i32) -> Option<PoolPtrInfo> {
    HEAP.get()
        .and_then(|h| h.tombstone_free_cell(ptr, vtable, refcount))
}

pub fn committed_bytes() -> usize {
    HEAP.get().map(|h| h.committed_bytes()).unwrap_or(0)
}

pub fn reserved_bytes() -> usize {
    HEAP.get().map(|h| h.reserved_bytes()).unwrap_or(0)
}

pub fn metadata_bytes() -> usize {
    HEAP.get().map(|h| h.metadata_bytes()).unwrap_or(0)
}

pub fn metadata_reserved_bytes() -> usize {
    HEAP.get().map(|h| h.metadata_reserved_bytes()).unwrap_or(0)
}

pub fn live_cells() -> usize {
    HEAP.get().map(|h| h.live_cells()).unwrap_or(0)
}

pub fn class_usage() -> [PoolClassUsage; NUM_BASE_POOLS] {
    HEAP.get()
        .map(|heap| heap.class_usage())
        .unwrap_or_else(|| {
            std::array::from_fn(|class_index| PoolClassUsage {
                class_index: class_index as u8,
                item_size: POOL_DESC[class_index].item_size,
                ..PoolClassUsage::default()
            })
        })
}

pub fn exhaust_count() -> u64 {
    HEAP.get().map(|heap| heap.total_exhaustions()).unwrap_or(0)
}

/// Permit one retry of subpool reservations that failed from transient VAS
/// or commit pressure. Called by the low-frequency watchdog, never from the
/// allocation hot path.
pub fn allow_reservation_retries() {
    if let Some(heap) = HEAP.get() {
        heap.allow_reservation_retries();
    }
}

pub fn overflow_user_reserved_bytes() -> usize {
    OVERFLOW_USER_RESERVED_BYTES.load(Ordering::Relaxed)
}

pub fn overflow_metadata_reserved_bytes() -> usize {
    OVERFLOW_METADATA_RESERVED_BYTES.load(Ordering::Relaxed)
}
