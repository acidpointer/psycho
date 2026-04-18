//! Size-class pool allocator for small allocations.
//!
//! Adapted from NVHR's mheap. One pool per size class; each pool
//! reserves a VA range aligned to `POOL_ALIGN` (16 MB) so free dispatch
//! is `(ptr >> 24) & 0xFF` into a 256-entry table. Pools grow by
//! committing `POOL_BLOCK_SIZE` (1 MB) blocks on demand and never
//! decommit -- this matches vanilla SBM's memory contract and avoids
//! VirtualFree stutter.
//!
//! The freelist is stored out-of-band in a separate array of link
//! records. Freed cells are NOT written to: every byte of a freed
//! allocation stays readable for stale readers (AI, IO, Havok). This
//! is the zombie-safe property.
//!
//! On pool exhaustion (reached max reserve) the allocator returns NULL,
//! letting the caller fall through to the next tier (`block` or
//! `va_alloc`).

use std::cell::Cell;
use std::ptr::{self, null_mut};
use std::sync::atomic::{AtomicU32, Ordering};

use libc::c_void;
use windows::Win32::System::Memory::{
    VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Reservation alignment. Every pool is placed at `i * POOL_ALIGN` for
/// some `i`, and the free path uses `ptr >> POOL_ALIGN_BITS` to reach
/// the pool. 8 MB lets cold pools be as small as 8 MB instead of being
/// locked to the previous 16 MB minimum, cutting total VAS reservation
/// roughly in half without touching hot pools.
pub const POOL_ALIGN: usize = 0x0080_0000; // 8 MB
const POOL_ALIGN_BITS: u32 = 23; // log2(POOL_ALIGN)

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
    /// When true, a second pool of the same size is created and the
    /// allocator hashes the thread id to pick a shard. Halves spinlock
    /// contention for the hottest classes.
    sharded: bool,
}

/// Number of shards per sharded class.
const SHARDS_PER_CLASS: usize = 2;

thread_local! {
    /// Cached shard index for this thread (0 or 1). Lazily initialised
    /// from the OS thread id. u8::MAX means "not yet computed".
    static SHARD_IDX: Cell<u8> = const { Cell::new(u8::MAX) };
}

#[inline]
fn get_shard() -> usize {
    SHARD_IDX.with(|c| {
        let v = c.get();
        if v != u8::MAX {
            return v as usize;
        }
        let tid = libpsycho::os::windows::winapi::get_current_thread_id();
        let shard = (tid as usize) % SHARDS_PER_CLASS;
        c.set(shard as u8);
        shard
    })
}

/// Per-class reservation sizes. Strict 512 MB total (matches vanilla
/// SBM's pool budget). Rebalanced again after a TTW Capital Wasteland
/// AI-thread NULL-deref crash (READ at 0x40, EIP=0x008D6F30) driven
/// by cascade exhaustion:
///   - 1024 B (#26): 131072 fails at 8 MB -> 24 MB (+16, 3x cells)
///   - 1280 B (#27):  65536 fails at 16 MB -> 24 MB (+8)
///   -  640 B (#23):  16384 fails at 16 MB -> 24 MB (+8)
///   - 3584 B (#33):  32768 fails at 8 MB -> 16 MB (+8)
///   -  512 B (#22):   1024 fails at 8 MB -> 16 MB (+8)
///   - 2048 B (#30): early exhaust at 8 MB -> 16 MB (+8)
///   - 3072 B (#32): early exhaust at 8 MB -> 16 MB (+8)
///
/// Budget recovered from 80/96 B: 96 -> 64 MB each (saves 64 MB).
/// 64 MB of 80 B = 838K cells, 64 MB of 96 B = 699K cells -- still
/// comfortably above observed hot-class peak usage (~500K each for
/// this modlist).
///
/// Layout summary:
///   - 80, 96 B: 64 MB each (hot TESForm churn, headroom for modlist)
///   - 16, 32, 64, 128 B: 16 MB each (high-freq small)
///   - 256, 320: 16 MB each (observed cascade hotspots)
///   - 512, 2048, 3072, 3584: 16 MB each (new: previously exhausted)
///   - 640, 1024, 1280: 24 MB each (heavy-exhaust classes)
///   - Everything else: 8 MB (POOL_ALIGN minimum).
///
/// Total: 512 MB reserved.
const POOL_DESC: &[PoolDesc] = &[
    PoolDesc { item_size: 8,    max_size: 8   * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 12,   max_size: 8   * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 16,   max_size: 16  * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 20,   max_size: 8   * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 24,   max_size: 8   * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 28,   max_size: 8   * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 32,   max_size: 16  * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 40,   max_size: 8   * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 48,   max_size: 8   * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 56,   max_size: 8   * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 64,   max_size: 16  * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 80,   max_size: 64  * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 96,   max_size: 64  * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 112,  max_size: 8   * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 128,  max_size: 16  * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 160,  max_size: 8   * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 192,  max_size: 8   * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 224,  max_size: 8   * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 256,  max_size: 16  * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 320,  max_size: 16  * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 384,  max_size: 8   * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 448,  max_size: 8   * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 512,  max_size: 16  * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 640,  max_size: 24  * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 768,  max_size: 8   * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 896,  max_size: 8   * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 1024, max_size: 24  * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 1280, max_size: 24  * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 1536, max_size: 8   * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 1792, max_size: 8   * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 2048, max_size: 16  * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 2560, max_size: 8   * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 3072, max_size: 16  * 1024 * 1024, sharded: false },
    PoolDesc { item_size: 3584, max_size: 16  * 1024 * 1024, sharded: false },
];

/// Count the sharded entries in `POOL_DESC` at compile time.
const fn count_sharded() -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < POOL_DESC.len() {
        if POOL_DESC[i].sharded {
            n += 1;
        }
        i += 1;
    }
    n
}

const NUM_BASE_POOLS: usize = POOL_DESC.len();
const NUM_SHARDED: usize = count_sharded();
/// Extra pool slots used for shard-1 copies of sharded classes.
const NUM_SHARD1_POOLS: usize = NUM_SHARDED * (SHARDS_PER_CLASS - 1);
const NUM_TOTAL_POOLS: usize = NUM_BASE_POOLS + NUM_SHARD1_POOLS;

// NUM_BASE_POOLS, NUM_SHARDED, NUM_SHARD1_POOLS, NUM_TOTAL_POOLS are
// defined above after `count_sharded()`.

// ---------------------------------------------------------------------------
// FreeLink: out-of-band freelist node
// ---------------------------------------------------------------------------

/// One entry in the pool's freelist array. Each allocated cell position
/// has a corresponding FreeLink. The `next` field forms an intrusive
/// singly-linked list of free cells. A non-null `next` means "this cell
/// is free"; a null `next` distinguishes the tail of the chain from an
/// allocated cell (allocated = not on any list).
///
/// The link array is completely disjoint from user cell memory, so
/// freeing a cell does not touch the cell's bytes.
#[repr(C)]
struct FreeLink {
    next: *mut FreeLink,
}

// ---------------------------------------------------------------------------
// Pool
// ---------------------------------------------------------------------------

struct Pool {
    item_size: u32,
    max_size: u32,
    max_cell_count: u32,

    /// VA reservation base (POOL_ALIGN-aligned).
    base: *mut u8,
    /// Next uncommitted byte within the reservation.
    cur: *mut u8,
    /// End of reservation (base + max_size).
    end: *mut u8,

    /// Out-of-band freelist array (one FreeLink per max_cell_count).
    free_cells: *mut FreeLink,
    /// Head of freelist. NULL when the pool is fully allocated (no
    /// free cells) AND there are no uncommitted blocks left.
    next_free: *mut FreeLink,

    /// Diagnostics: live cell count.
    live_cells: AtomicU32,
    /// Commit high-water mark in bytes (distance from base to cur).
    committed_bytes: AtomicU32,

    /// Pool index (for diagnostics).
    index: u8,

    /// Per-pool spinlock. Alloc/free are O(1) under this lock.
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
            base: ptr::null_mut(),
            cur: ptr::null_mut(),
            end: ptr::null_mut(),
            free_cells: ptr::null_mut(),
            next_free: ptr::null_mut(),
            live_cells: AtomicU32::new(0),
            committed_bytes: AtomicU32::new(0),
            index: 0,
            lock: AtomicU32::new(0),
        }
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
        let link_idx = (link as usize - self.free_cells as usize)
            / std::mem::size_of::<FreeLink>();
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
                self.index, self.item_size, block_start as usize, POOL_BLOCK_SIZE,
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
        let old_head = self.next_free;
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
        if self.next_free.is_null()
            && unsafe { !self.grow() } {
                return null_mut();
            }

        let link = self.next_free;
        // Walk one step. A null next means end-of-chain; next alloc will
        // see next_free == null and trigger grow().
        unsafe {
            self.next_free = (*link).next;
            (*link).next = null_mut(); // mark as "off the freelist"
        }

        self.live_cells.fetch_add(1, Ordering::Relaxed);
        self.link_to_cell(link)
    }

    /// Fast path free: push a cell onto the freelist. No writes to cell data.
    unsafe fn free(&mut self, cell: *mut u8) {
        let link = self.cell_to_link(cell);
        unsafe {
            // Double-free guard: if next is non-null, the cell is already
            // on the freelist. Ignore to keep the chain consistent.
            if !(*link).next.is_null() {
                log::error!(
                    "[POOL] Double-free ignored: pool={} cell={:p}",
                    self.index, cell,
                );
                return;
            }
            (*link).next = self.next_free;
            self.next_free = link;
        }
        self.live_cells.fetch_sub(1, Ordering::Relaxed);
    }

    /// Return true if `addr` is inside this pool's reservation.
    #[inline]
    fn contains(&self, addr: *const c_void) -> bool {
        let a = addr as usize;
        a >= self.base as usize && a < self.end as usize
    }

    #[inline]
    fn committed_mb(&self) -> usize {
        self.committed_bytes.load(Ordering::Relaxed) as usize / 1024 / 1024
    }
}

// ---------------------------------------------------------------------------
// PoolHeap: singleton
// ---------------------------------------------------------------------------

pub struct PoolHeap {
    pools: [Pool; NUM_TOTAL_POOLS],
    /// For base pool index `b`, `shard1_of[b]` is the pool index of its
    /// shard-1 copy, or `NO_POOL` if the class is not sharded. Filled
    /// at init. Indexed by `base_idx as usize`.
    shard1_of: [u8; NUM_BASE_POOLS],
    /// size_to_pool[(size + 3) >> 2] = pool index, or NO_POOL if size
    /// exceeds POOL_MAX_SIZE.
    size_to_pool: [u8; SIZE_LOOKUP_LEN],
    /// addr_to_pool[ptr >> 24] = pool index, or NO_POOL if the slot is
    /// not owned by any pool.
    addr_to_pool: [u8; ADDR_LOOKUP_LEN],
}

unsafe impl Send for PoolHeap {}
unsafe impl Sync for PoolHeap {}

/// Reserve VA and initialise a single `Pool` slot at `pools[pool_idx]`.
/// `next_slot` is advanced past the reservation so consecutive pools
/// don't rescan claimed slots. Returns the bytes reserved on success.
fn init_one_pool(
    heap: &mut PoolHeap,
    pool_idx: u8,
    desc: &PoolDesc,
    next_slot: &mut usize,
) -> Option<usize> {
    let slots_needed = desc.max_size as usize / POOL_ALIGN;
    if slots_needed == 0 {
        log::error!("[POOL] Bad descriptor: max_size {} < POOL_ALIGN", desc.max_size);
        return None;
    }

    let mut reserved_base: *mut u8 = ptr::null_mut();
    let mut claim_slot: usize = 0;

    let mut slot = *next_slot;
    while slot + slots_needed <= ADDR_LOOKUP_LEN {
        let mut clear = true;
        for s in slot..slot + slots_needed {
            if heap.addr_to_pool[s] != NO_POOL {
                clear = false;
                break;
            }
        }
        if clear {
            let hint = (slot * POOL_ALIGN) as *mut c_void;
            let ptr = unsafe {
                VirtualAlloc(
                    Some(hint),
                    desc.max_size as usize,
                    MEM_RESERVE,
                    PAGE_READWRITE,
                )
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
        slot += 1;
    }

    if reserved_base.is_null() {
        log::error!(
            "[POOL] Could not reserve pool {}: item_size={} max_size={}MB",
            pool_idx, desc.item_size, desc.max_size / 1024 / 1024,
        );
        return None;
    }

    let max_cell_count = desc.max_size / desc.item_size;
    let meta_bytes = max_cell_count as usize * std::mem::size_of::<FreeLink>();
    let meta_ptr = unsafe {
        VirtualAlloc(
            None,
            meta_bytes,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    if meta_ptr.is_null() {
        log::error!(
            "[POOL] Failed to allocate freelist metadata for pool {} ({} KB)",
            pool_idx, meta_bytes / 1024,
        );
        return None;
    }
    unsafe {
        std::ptr::write_bytes(meta_ptr as *mut u8, 0, meta_bytes);
    }

    {
        let pool = &mut heap.pools[pool_idx as usize];
        pool.item_size = desc.item_size;
        pool.max_size = desc.max_size;
        pool.max_cell_count = max_cell_count;
        pool.base = reserved_base;
        pool.cur = reserved_base;
        pool.end = unsafe { reserved_base.add(desc.max_size as usize) };
        pool.free_cells = meta_ptr as *mut FreeLink;
        pool.next_free = ptr::null_mut();
        pool.index = pool_idx;
    }

    for s in claim_slot..claim_slot + slots_needed {
        heap.addr_to_pool[s] = pool_idx;
    }
    *next_slot = claim_slot + slots_needed;

    log::info!(
        "[POOL] #{} item_size={} reserved {}MB at 0x{:08x}..0x{:08x}",
        pool_idx,
        desc.item_size,
        desc.max_size / 1024 / 1024,
        reserved_base as usize,
        reserved_base as usize + desc.max_size as usize,
    );

    Some(desc.max_size as usize)
}

impl PoolHeap {
    /// Create a fresh heap with all pools initialised and reserved.
    /// Returns None if even a single pool could not reserve its VA --
    /// the allocator is unusable without its full set.
    fn create() -> Option<Box<Self>> {
        let mut heap = Box::new(PoolHeap {
            pools: std::array::from_fn(|_| Pool::empty()),
            size_to_pool: [NO_POOL; SIZE_LOOKUP_LEN],
            addr_to_pool: [NO_POOL; ADDR_LOOKUP_LEN],
            shard1_of: [NO_POOL; NUM_BASE_POOLS],
        });

        let mut next_slot: usize = 1;
        let mut total_reserved: usize = 0;
        let mut shard1_cursor: usize = NUM_BASE_POOLS;

        for (p, desc) in POOL_DESC.iter().enumerate() {
            // Reserve the base pool (shard 0).
            match init_one_pool(&mut heap, p as u8, desc, &mut next_slot) {
                Some(reserved) => total_reserved += reserved,
                None => return None,
            }

            // If sharded, reserve a second independent pool of the same
            // item_size / max_size at the next available slot. Record
            // the mapping so the hot alloc path can route shard 1 there.
            if desc.sharded {
                let shard1_idx = shard1_cursor;
                shard1_cursor += 1;
                match init_one_pool(&mut heap, shard1_idx as u8, desc, &mut next_slot) {
                    Some(reserved) => total_reserved += reserved,
                    None => return None,
                }
                heap.shard1_of[p] = shard1_idx as u8;
            }
        }

        // Build size_to_pool lookup (points at the shard-0 / base index).
        for (p, desc) in POOL_DESC.iter().enumerate() {
            let upper = (desc.item_size as usize >> 2).min(SIZE_LOOKUP_LEN - 1);
            let mut i = upper;
            while i > 0 && heap.size_to_pool[i] == NO_POOL {
                heap.size_to_pool[i] = p as u8;
                i -= 1;
            }
            if i == 0 && heap.size_to_pool[0] == NO_POOL {
                heap.size_to_pool[0] = p as u8;
            }
        }

        log::info!(
            "[POOL] Init complete: {} base + {} shard pools = {} total, {}MB VA reserved",
            NUM_BASE_POOLS,
            NUM_SHARD1_POOLS,
            NUM_TOTAL_POOLS,
            total_reserved / 1024 / 1024,
        );

        Some(heap)
    }

    #[inline]
    fn pool_from_addr(&self, addr: *const c_void) -> Option<&Pool> {
        let slot = (addr as usize) >> POOL_ALIGN_BITS;
        if slot >= ADDR_LOOKUP_LEN {
            return None;
        }
        let p = self.addr_to_pool[slot];
        if p == NO_POOL {
            return None;
        }
        let pool = &self.pools[p as usize];
        // Slot ownership is a coarse filter; verify the address falls
        // inside the pool's actual reservation (the slot could also
        // straddle the last POOL_ALIGN boundary beyond pool->end).
        if pool.contains(addr) {
            Some(pool)
        } else {
            None
        }
    }

    pub fn alloc(&self, size: usize) -> *mut c_void {
        let idx = (size + 3) >> 2;
        if idx >= SIZE_LOOKUP_LEN {
            return null_mut();
        }
        let base_idx = self.size_to_pool[idx];
        if base_idx == NO_POOL {
            return null_mut();
        }

        // Sharded classes route shard 1 to the shard-1 pool. Shard 0
        // falls through to the base pool index unchanged.
        let base_idx_u = base_idx as usize;
        let shard1 = self.shard1_of[base_idx_u];
        let primary_idx = if shard1 != NO_POOL && get_shard() != 0 {
            shard1 as usize
        } else {
            base_idx_u
        };

        // First try: chosen shard.
        let primary = &self.pools[primary_idx];
        let ptr = unsafe {
            let p = primary as *const Pool as *mut Pool;
            (*p).acquire();
            let result = (*p).alloc();
            (*p).release();
            result
        };
        if !ptr.is_null() {
            return ptr as *mut c_void;
        }

        // If this was a sharded class, try the other shard before
        // walking to larger classes. Keeps the hot path in the correct
        // size class.
        if shard1 != NO_POOL {
            let other_idx = if primary_idx == base_idx_u {
                shard1 as usize
            } else {
                base_idx_u
            };
            let other = &self.pools[other_idx];
            let ptr = unsafe {
                let p = other as *const Pool as *mut Pool;
                (*p).acquire();
                let result = (*p).alloc();
                (*p).release();
                result
            };
            if !ptr.is_null() {
                return ptr as *mut c_void;
            }
        }

        // Exhausted: walk to larger base classes.
        for i in (base_idx_u + 1)..NUM_BASE_POOLS {
            let next = &self.pools[i];
            let ptr = unsafe {
                let p = next as *const Pool as *mut Pool;
                (*p).acquire();
                let result = (*p).alloc();
                (*p).release();
                result
            };
            if !ptr.is_null() {
                return ptr as *mut c_void;
            }
        }

        // All pools from `base_idx` up to the largest size class refused.
        // Caller's fallthrough is block / va_alloc / NULL. Rate-limited
        // warn so a sudden burst of exhaustion is visible without
        // flooding the log.
        let n = POOL_EXHAUST_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        if n.is_power_of_two() {
            log::warn!(
                "[POOL] Exhausted for size={} (started at class #{} = {}B): total_fails={}",
                size,
                base_idx_u,
                POOL_DESC[base_idx_u].item_size,
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
        unsafe {
            let p = pool as *const Pool as *mut Pool;
            (*p).acquire();
            (*p).free(ptr as *mut u8);
            (*p).release();
        }
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

    pub fn committed_bytes(&self) -> usize {
        self.pools
            .iter()
            .map(|p| p.committed_bytes.load(Ordering::Relaxed) as usize)
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

use std::sync::atomic::AtomicU64;
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

pub fn committed_bytes() -> usize {
    HEAP.get().map(|h| h.committed_bytes()).unwrap_or(0)
}

pub fn live_cells() -> usize {
    HEAP.get().map(|h| h.live_cells()).unwrap_or(0)
}

/// Crash diagnostic: describe the pool cell that owns `fault_addr`.
pub fn diagnose_ptr_buf(fault_addr: usize, r: &mut String) {
    use core::fmt::Write;
    let heap = match HEAP.get() {
        Some(h) => h,
        None => return,
    };
    let pool = match heap.pool_from_addr(fault_addr as *const c_void) {
        Some(p) => p,
        None => return,
    };
    let cell_offset = fault_addr - pool.base as usize;
    let cell_idx = cell_offset / pool.item_size as usize;
    let cell_start = pool.base as usize + cell_idx * pool.item_size as usize;
    let in_cell_offset = fault_addr - cell_start;

    // Peek the link entry to determine free/live state.
    let link = unsafe { pool.free_cells.add(cell_idx) };
    let is_free = unsafe { !(*link).next.is_null() }
        || std::ptr::eq(link, pool.next_free);

    let _ = writeln!(r, "\n  Pool Cell Detail");
    let _ = writeln!(r, "  ----------------");
    let _ = writeln!(
        r,
        "  Pool:       #{} (item_size={} max={}MB)",
        pool.index, pool.item_size, pool.max_size / 1024 / 1024,
    );
    let _ = writeln!(r, "  Cell:       {} at 0x{:08x}", cell_idx, cell_start);
    let _ = writeln!(r, "  Offset:     +0x{:X} of {}", in_cell_offset, pool.item_size);
    let _ = writeln!(
        r,
        "  Committed:  {}MB / {}MB",
        pool.committed_mb(),
        pool.max_size / 1024 / 1024,
    );
    let _ = writeln!(r, "  State:      {}", if is_free { "FREE" } else { "LIVE" });
}
