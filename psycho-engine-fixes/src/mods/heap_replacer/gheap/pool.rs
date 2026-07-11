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
//!   subpools and builds the `size_to_class` lookup. It does not call
//!   `VirtualAlloc`.
//! - `PoolHeap::alloc(size)` dispatches to a size class, starts from a
//!   per-class hint, and tries that class's subpools. If the selected
//!   subpool is still `POOL_STATE_NOT_INIT`, a CAS transitions it to
//!   `POOL_STATE_INITING`, the winning thread scans `addr_to_pool` from
//!   high addresses downward for a free slot, reserves the VA via
//!   `VirtualAlloc(MEM_RESERVE)`, allocates the freelist metadata, and
//!   publishes `POOL_STATE_INIT`. Losers busy-wait.
//! - Subsequent allocs skip the ensure-init path (single Acquire load).
//!
//! # Zombie safety
//!
//! Unchanged from pre-lazy design: the freelist is stored out-of-band
//! in a separate array of link records. Freed cells are NOT written
//! to. Every byte of a freed allocation stays readable for stale
//! readers (AI, IO, Havok) until the cell is reused by a new alloc.
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
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use libc::c_void;
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc};

// Per-pool lifecycle states. Enables lazy VA reservation: the pool
// transitions NotInit -> Initing -> (Init | Failed) on its first alloc
// request, so each pool only consumes VA when something actually
// needs that subpool. Matches vanilla SBM's behaviour of growing on
// demand instead of reserving a bulk working set upfront.
const POOL_STATE_NOT_INIT: u8 = 0;
const POOL_STATE_INITING: u8 = 1;
const POOL_STATE_INIT: u8 = 2;
const POOL_STATE_FAILED: u8 = 3;

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

/// Growth unit. Each time a pool runs out of committed cells, it
/// commits one more block.
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

// ---------------------------------------------------------------------------
// Pool descriptors (static)
// ---------------------------------------------------------------------------

struct PoolDesc {
    item_size: u32,
    max_size: u32,
}

/// Per-class MAXIMUM reservation sizes. Sum is 512 MB, but with lazy
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
///   - 1024 B remains 16 MB, but >1024 B now has more headroom before
///     cascading through every larger class and into block fallback.
///
/// VAS accounting (the real constraint):
///   pool (552) + block tier (up to ~400 on-demand) + game (~1-2 GB) +
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
    let extra = if max_size % POOL_SUBPOOL_SIZE == 0 {
        0
    } else {
        1
    };
    (full + extra) as usize
}

/// Count the concrete subpools expanded from `POOL_DESC`.
const fn count_total_pools() -> usize {
    let mut n = 0usize;
    let mut i = 0;
    while i < POOL_DESC.len() {
        n += subpool_count_for(POOL_DESC[i].max_size);
        i += 1;
    }
    n
}

const NUM_BASE_POOLS: usize = POOL_DESC.len();
const NUM_TOTAL_POOLS: usize = count_total_pools();
const POOL_MAX_RESERVATION_MB: usize = (NUM_TOTAL_POOLS * POOL_ALIGN) / 1024 / 1024;

// ---------------------------------------------------------------------------
// FreeLink: out-of-band freelist node
// ---------------------------------------------------------------------------

/// One entry in the pool's freelist array. Each allocated cell position
/// has a corresponding FreeLink. The `next` field forms an intrusive
/// singly-linked list of free cells.
///
/// State encoding:
/// - `next == NULL`: allocated, not on any freelist
/// - `next == FREE_LINK_TAIL`: free and at the tail of the freelist
/// - otherwise: free and linked to the next freelist node
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
const FREE_LINK_TAIL: *mut FreeLink = 1usize as *mut FreeLink;

#[derive(Copy, Clone, Debug)]
pub struct PoolPtrInfo {
    pub pool_index: u8,
    pub item_size: u32,
    pub cell_index: usize,
    pub cell_start: usize,
    pub offset: usize,
    pub committed: bool,
    pub is_free: bool,
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

    /// VA reservation base (POOL_ALIGN-aligned). NULL until `state`
    /// reaches `POOL_STATE_INIT` (lazy reservation).
    base: *mut u8,
    /// Next uncommitted byte within the reservation. NULL until lazy
    /// init completes.
    cur: *mut u8,
    /// End of reservation (base + max_size). NULL until lazy init.
    end: *mut u8,

    /// Out-of-band freelist array (one FreeLink per max_cell_count).
    /// NULL until lazy init.
    free_cells: *mut FreeLink,
    /// Head of freelist. NULL when the pool is fully allocated (no
    /// free cells) AND there are no uncommitted blocks left. Also
    /// NULL before lazy init.
    next_free: *mut FreeLink,

    /// Diagnostics: live cell count.
    live_cells: AtomicU32,
    /// Commit high-water mark in bytes (distance from base to cur).
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

    /// Per-pool spinlock. Alloc/free are O(1) under this lock.
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
            base: ptr::null_mut(),
            cur: ptr::null_mut(),
            end: ptr::null_mut(),
            free_cells: ptr::null_mut(),
            next_free: ptr::null_mut(),
            live_cells: AtomicU32::new(0),
            committed_bytes: AtomicU32::new(0),
            metadata_bytes: AtomicU32::new(0),
            index: 0,
            state: AtomicU8::new(POOL_STATE_NOT_INIT),
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

    /// Convert a FreeLink pointer (inside free_cells array) to the
    /// matching user cell address inside the pool's VA range.
    #[inline]
    fn link_to_cell(&self, link: *mut FreeLink) -> *mut u8 {
        let link_idx = (link as usize - self.free_cells as usize) / std::mem::size_of::<FreeLink>();
        unsafe { self.base.add(link_idx * self.item_size as usize) }
    }

    /// Convert a user cell address to the matching FreeLink pointer in
    /// the free_cells array.
    #[inline]
    fn cell_to_link(&self, cell: *mut u8) -> *mut FreeLink {
        let cell_idx = (cell as usize - self.base as usize) / self.item_size as usize;
        unsafe { self.free_cells.add(cell_idx) }
    }

    /// Commit one more POOL_BLOCK_SIZE chunk from the reservation and
    /// splice its cells onto the freelist. Caller holds the pool lock.
    ///
    /// Returns true on success. On commit failure (OS refusal), returns
    /// false and leaves the pool untouched -- caller falls through.
    unsafe fn grow(&mut self) -> bool {
        if self.cur >= self.end {
            return false; // reservation exhausted
        }

        let block_start = self.cur;
        let commit = unsafe {
            VirtualAlloc(
                Some(block_start as *const c_void),
                POOL_BLOCK_SIZE,
                MEM_COMMIT,
                PAGE_READWRITE,
            )
        };
        if commit.is_null() {
            log::error!(
                "[POOL] Commit failed: pool={} item_size={} addr=0x{:08x} size={}",
                self.index,
                self.item_size,
                block_start as usize,
                POOL_BLOCK_SIZE,
            );
            return false;
        }

        // Advance cursor. Block is now committed.
        self.cur = unsafe { self.cur.add(POOL_BLOCK_SIZE) };
        self.committed_bytes
            .fetch_add(POOL_BLOCK_SIZE as u32, Ordering::Relaxed);

        // Compute which FreeLink slots correspond to this new block and
        // chain them onto the freelist. For pool item_size N, each 1 MB
        // block holds floor(1MB / N) cells. Partial-cell remainder is
        // ignored (inaccessible).
        let cells_per_block = POOL_BLOCK_SIZE / self.item_size as usize;
        let block_offset = block_start as usize - self.base as usize;
        let start_cell_idx = block_offset / self.item_size as usize;

        // Build a LIFO chain: new_head -> new_head-1 -> ... -> start_cell,
        // then splice on top of the existing freelist.
        let old_head = if self.next_free.is_null() {
            FREE_LINK_TAIL
        } else {
            self.next_free
        };
        unsafe {
            let first_link = self.free_cells.add(start_cell_idx);
            first_link.write(FreeLink { next: old_head });
            for i in 1..cells_per_block {
                let link = self.free_cells.add(start_cell_idx + i);
                let prev = self.free_cells.add(start_cell_idx + i - 1);
                link.write(FreeLink { next: prev });
            }
            self.next_free = self.free_cells.add(start_cell_idx + cells_per_block - 1);
        }

        true
    }

    /// Fast path alloc: pop one cell from the freelist. If the list is
    /// empty, commit one more block.
    unsafe fn alloc(&mut self) -> *mut u8 {
        if self.next_free.is_null() && unsafe { !self.grow() } {
            return null_mut();
        }

        let link = self.next_free;
        // Walk one step. A null next means end-of-chain; next alloc will
        // see next_free == null and trigger grow().
        unsafe {
            let next = (*link).next;
            self.next_free = if next == FREE_LINK_TAIL {
                null_mut()
            } else {
                next
            };
            (*link).next = null_mut(); // mark as allocated
        }

        self.live_cells.fetch_add(1, Ordering::Relaxed);
        self.link_to_cell(link)
    }

    /// Fast path free: push a cell onto the freelist. No writes to cell data.
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
    /// # Known latent crash 3: Stewie Tweaks Process::LowProcess dead-actor
    ///
    /// Third instance. 2026-04-18 17:47, 2:22 play, Giant Soldier Ant
    /// with HAVOK_DEATH + NEED_TO_CHANGE_PROCESS. Crash inside Stewie
    /// Tweaks' LowProcess hook walking a process-migration pointer
    /// chain; same pattern (parent still referencing freed-and-reused
    /// child). CrashLogger.2026-04-18-17-47-55.log.
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
            (*link).next = if self.next_free.is_null() {
                FREE_LINK_TAIL
            } else {
                self.next_free
            };
            self.next_free = link;
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
        let link = unsafe { self.free_cells.add(cell_index) };
        Some(PoolPtrInfo {
            pool_index: self.index,
            item_size: self.item_size,
            cell_index,
            cell_start,
            offset: addr - cell_start,
            committed: cell_start + self.item_size as usize <= self.cur as usize,
            // Allocated cells are the only entries whose link is NULL.
            is_free: unsafe { !(*link).next.is_null() },
        })
    }

    unsafe fn tombstone_free_cell(
        &mut self,
        ptr: *mut c_void,
        vtable: usize,
        refcount: i32,
    ) -> Option<PoolPtrInfo> {
        let info = self.ptr_info_locked(ptr)?;
        if !info.committed || info.offset != 0 || info.item_size < 12 {
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
) {
    let used_before = subpool_idx as u32 * POOL_SUBPOOL_SIZE;
    let remaining = desc.max_size.saturating_sub(used_before);
    let max_size = remaining.min(POOL_SUBPOOL_SIZE);
    let max_cell_count = max_size / desc.item_size;
    pool.item_size = desc.item_size;
    pool.max_size = max_size;
    pool.max_cell_count = max_cell_count;
    pool.class_index = class_idx;
    pool.subpool_index = subpool_idx;
    pool.subpool_count = subpool_count;
    pool.index = pool_idx;
    // base/cur/end/free_cells stay NULL until lazy init.
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
            size_to_class: [NO_POOL; SIZE_LOOKUP_LEN],
            addr_to_pool: std::array::from_fn(|_| AtomicU8::new(NO_POOL)),
            init_lock: Mutex::new(()),
        });

        // Expand each class cap into aligned subpools. The class cap is
        // unchanged; only first-touch reservation is split.
        let mut pool_idx = 0usize;
        for (class_idx, desc) in POOL_DESC.iter().enumerate() {
            let count = subpool_count_for(desc.max_size);
            heap.class_start[class_idx] = pool_idx as u8;
            heap.class_count[class_idx] = count as u8;
            for subpool_idx in 0..count {
                assign_pool_desc(
                    &mut heap.pools[pool_idx],
                    pool_idx as u8,
                    class_idx as u8,
                    desc,
                    subpool_idx as u8,
                    count as u8,
                );
                pool_idx += 1;
            }
        }

        debug_assert_eq!(pool_idx, NUM_TOTAL_POOLS);

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
            "[POOL] Ready (subpool lazy): {} classes -> {} subpools of up to {}MB ({}MB max), 0MB reserved upfront",
            NUM_BASE_POOLS,
            NUM_TOTAL_POOLS,
            POOL_ALIGN / 1024 / 1024,
            POOL_MAX_RESERVATION_MB,
        );

        Some(heap)
    }

    /// First-alloc hook. Ensures pool at `idx` is in `INIT` state.
    /// Returns true if the pool is usable; false if init failed or
    /// is still in progress (caller can retry on the next request).
    ///
    /// Fast path: a single `Acquire` load; no lock taken if already
    /// initialised. Slow path (first alloc for this subpool) takes the
    /// global `init_lock` while it scans slots + `VirtualAlloc`s +
    /// claims `addr_to_pool` entries. Concurrent initialisers on
    /// DIFFERENT pools spin-wait; after one pool finishes, the next
    /// proceeds.
    fn ensure_pool_inited(&self, idx: usize) -> bool {
        let state = self.pools[idx].state.load(Ordering::Acquire);
        if state == POOL_STATE_INIT {
            return true;
        }
        if state == POOL_STATE_FAILED {
            return false;
        }
        self.lazy_init_pool(idx)
    }

    #[allow(clippy::never_loop)]
    #[cold]
    fn lazy_init_pool(&self, idx: usize) -> bool {
        // Transition NotInit -> Initing. If another thread beat us to
        // it, wait for its outcome.
        loop {
            match self.pools[idx].state.compare_exchange(
                POOL_STATE_NOT_INIT,
                POOL_STATE_INITING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(POOL_STATE_INIT) => return true,
                Err(POOL_STATE_FAILED) => return false,
                Err(_) => {
                    // POOL_STATE_INITING on another thread; spin.
                    while self.pools[idx].state.load(Ordering::Acquire) == POOL_STATE_INITING {
                        std::hint::spin_loop();
                    }
                    let s = self.pools[idx].state.load(Ordering::Acquire);
                    return s == POOL_STATE_INIT;
                }
            }
        }

        // We own the Initing transition. Do the actual reservation
        // under init_lock (serialises slot scan against other pools).
        let ok = self.do_reserve(idx);
        self.pools[idx].state.store(
            if ok {
                POOL_STATE_INIT
            } else {
                POOL_STATE_FAILED
            },
            Ordering::Release,
        );
        ok
    }

    /// Reserve VA and freelist metadata for pool `idx`. Caller must
    /// have just transitioned the pool to `POOL_STATE_INITING`.
    /// Takes `init_lock` for addr_to_pool coordination.
    fn do_reserve(&self, idx: usize) -> bool {
        let _guard = match self.init_lock.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        // We hold init_lock (serialises addr_to_pool writes) and own
        // the pool's INITING state (no other thread mutates this pool's
        // base/cur/end fields). Access via raw pointer to avoid the
        // invalid-reference-cast lint while still respecting the lock.
        let pool_ptr: *mut Pool = &self.pools[idx] as *const Pool as *mut Pool;

        let item_size = unsafe { (*pool_ptr).item_size };
        let max_size = unsafe { (*pool_ptr).max_size };
        let max_cell_count = unsafe { (*pool_ptr).max_cell_count };
        let class_index = unsafe { (*pool_ptr).class_index };
        let subpool_index = unsafe { (*pool_ptr).subpool_index };
        let subpool_count = unsafe { (*pool_ptr).subpool_count };

        let slots_needed = (max_size as usize).div_ceil(POOL_ALIGN);
        if slots_needed == 0 {
            log::error!(
                "[POOL] #{} item_size={} max_size={} < POOL_ALIGN",
                idx,
                item_size,
                max_size,
            );
            return false;
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
            return false;
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
            let aligned = adopted_addr % POOL_ALIGN == 0;
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
            return false;
        }

        // Freelist metadata -- out-of-band from user cells, allocated
        // from the OS directly (not from ourselves) to avoid recursion.
        let meta_bytes = max_cell_count as usize * std::mem::size_of::<FreeLink>();
        let meta_commit_bytes = meta_bytes.div_ceil(0x1000) * 0x1000;
        let meta_ptr =
            unsafe { VirtualAlloc(None, meta_bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };
        if meta_ptr.is_null() {
            log::error!(
                "[POOL] #{} freelist metadata alloc failed ({} KB)",
                idx,
                meta_bytes / 1024,
            );
            if !default_tail_backing {
                let _ = unsafe {
                    windows::Win32::System::Memory::VirtualFree(
                        reserved_base as *mut c_void,
                        0,
                        windows::Win32::System::Memory::MEM_RELEASE,
                    )
                };
            }
            return false;
        }
        // VirtualAlloc returns zero-filled pages. Each entry is initialized by
        // grow() before it is linked into the freelist.

        // Commit the pool's state via raw pointer writes.
        unsafe {
            (*pool_ptr).base = reserved_base;
            (*pool_ptr).cur = reserved_base;
            (*pool_ptr).end = reserved_base.add(max_size as usize);
            (*pool_ptr).free_cells = meta_ptr as *mut FreeLink;
            (*pool_ptr).next_free = ptr::null_mut();
            (*pool_ptr)
                .metadata_bytes
                .store(meta_commit_bytes as u32, Ordering::Relaxed);
        }

        // Claim addr_to_pool slots. Readers on the hot path will see
        // our writes once state flips to INIT (Release pair in
        // `lazy_init_pool` with an Acquire load in `is_inited`).
        for s in claim_slot..claim_slot + slots_needed {
            self.addr_to_pool[s].store(idx as u8, Ordering::Relaxed);
        }

        log::debug!(
            "[POOL] class #{} {}B grew: subpool {}/{} (#{}) reserved {}MB at 0x{:08x}..0x{:08x} source={}",
            class_index,
            item_size,
            subpool_index + 1,
            subpool_count,
            idx,
            max_size / 1024 / 1024,
            reserved_base as usize,
            reserved_base as usize + max_size as usize,
            if default_tail_backing {
                "default-tail"
            } else {
                "virtualalloc"
            },
        );

        true
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

    fn alloc_from_pool(&self, pool_idx: usize) -> *mut u8 {
        if !self.ensure_pool_inited(pool_idx) {
            return null_mut();
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

    fn alloc_from_class(&self, class_idx: usize) -> *mut c_void {
        let start = self.class_start[class_idx] as usize;
        let count = self.class_count[class_idx] as usize;
        if count == 0 {
            return null_mut();
        }

        let mut hint = self.class_hint[class_idx].load(Ordering::Relaxed) as usize;
        if hint >= count {
            hint = 0;
        }

        for step in 0..count {
            let subpool_idx = (hint + step) % count;
            let ptr = self.alloc_from_pool(start + subpool_idx);
            if !ptr.is_null() {
                self.class_hint[class_idx].store(subpool_idx as u8, Ordering::Relaxed);
                return ptr as *mut c_void;
            }
        }

        null_mut()
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
        let ptr = self.alloc_from_class(class_idx_u);
        if !ptr.is_null() {
            return ptr;
        }

        // Exhausted: walk to larger classes. Each class grows one aligned
        // subpool at a time instead of claiming the whole class cap.
        for i in (class_idx_u + 1)..NUM_BASE_POOLS {
            let ptr = self.alloc_from_class(i);
            if !ptr.is_null() {
                return ptr;
            }
        }

        // All classes from `class_idx` up to the largest size class refused.
        // Caller's fallthrough is block / va_alloc / NULL. Rate-limited
        // warn so a sudden burst of exhaustion is visible without
        // flooding the log.
        let n = POOL_EXHAUST_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        if n.is_power_of_two() {
            log::warn!(
                "[POOL] Exhausted for size={} (started at class #{} = {}B): total_fails={}",
                size,
                class_idx_u,
                POOL_DESC[class_idx_u].item_size,
                n,
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
                Some(info) if info.committed && info.offset == 0 => {
                    (*p).free(info.cell_start as *mut u8)
                }
                Some(info) => {
                    log::error!(
                        "[POOL] Invalid free ignored: pool={} ptr={:p} offset={} committed={}",
                        info.pool_index,
                        ptr,
                        info.offset,
                        info.committed,
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
        true
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

    pub fn live_cells(&self) -> usize {
        self.pools
            .iter()
            .map(|p| p.live_cells.load(Ordering::Relaxed) as usize)
            .sum()
    }
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

use std::sync::OnceLock;
static HEAP: OnceLock<Box<PoolHeap>> = OnceLock::new();

/// Total number of times `alloc` walked the full fallthrough chain
/// and every pool refused. Power-of-two gated for log visibility.
static POOL_EXHAUST_COUNT: AtomicU64 = AtomicU64::new(0);

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

pub fn live_cells() -> usize {
    HEAP.get().map(|h| h.live_cells()).unwrap_or(0)
}

pub fn exhaust_count() -> u64 {
    POOL_EXHAUST_COUNT.load(Ordering::Relaxed)
}
