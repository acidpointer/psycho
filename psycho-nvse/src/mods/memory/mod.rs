mod crt_iat;

pub mod heap_replacer;
pub use crt_iat::*;
pub use heap_replacer::mem_stats;
use libmimalloc::{
    mi_arena_id_t, mi_option_set, mi_option_set_enabled, mi_reserve_os_memory_ex,
    mi_option_arena_eager_commit,
    mi_option_arena_purge_mult,
    mi_option_arena_reserve,
    mi_option_destroy_on_exit,
    mi_option_page_cross_thread_max_reclaim,
    mi_option_page_full_retain,
    mi_option_page_reclaim_on_free,
    mi_option_purge_decommits,
    mi_option_purge_delay,
    mi_option_retry_on_oom,
};
use parking_lot::Once;

static CONFIG_MIMALLOC: Once = Once::new();

const MB: usize = 1024 * 1024;

pub fn configure_mimalloc() {
    CONFIG_MIMALLOC.call_once(|| unsafe {
        // ---------------------------------------------------------------
        // Mimalloc is the GLOBAL allocator for the entire game process
        // (via IAT hooks on all loaded DLLs, inline CRT hooks, and
        // GameHeap hooks). Tuned for 32-bit FNV with ~4GB VA (LAA).
        // ---------------------------------------------------------------

        // PRE-RESERVE ARENA -- try sizes from largest to smallest.
        // Uses mi_reserve_os_memory_ex for explicit error reporting.
        // commit=false -> demand-page (zero physical RAM upfront).
        let arena_sizes = [512 * MB, 384 * MB, 256 * MB, 128 * MB];
        let mut reserved = 0usize;
        for &size in &arena_sizes {
            let mut arena_id: mi_arena_id_t = 0;
            let result = mi_reserve_os_memory_ex(
                size,
                false, // commit: false = demand-page
                false, // allow_large: no huge pages on 32-bit
                false, // exclusive: allow fallback arenas too
                &mut arena_id,
            );
            if result == 0 {
                reserved = size;
                log::info!("[MIMALLOC] Reserved {}MB arena (id={:?})", size / MB, arena_id);
                break;
            }
            log::warn!("[MIMALLOC] Failed to reserve {}MB (err={}), trying smaller...", size / MB, result);
        }
        if reserved == 0 {
            log::error!("[MIMALLOC] Could not reserve ANY arena! Falling back to dynamic arenas.");
        }

        // UAF bitmap removed: slab allocator writes FreeNode header on ALL
        // freed cells, providing universal UAF protection without per-segment tracking.

        // 32MB overflow arenas if pre-reserved block fills up.
        mi_option_set(mi_option_arena_reserve, 32 * 1024); // KiB

        // Demand-page: reserve VA, commit on first touch.
        mi_option_set(mi_option_arena_eager_commit, 0);

        // PURGE DELAY = 15000ms (15 seconds)
        //
        // Freed pages stay committed (readable) for 15s before mimalloc
        // decommits them. This matches the slab's REUSE_COOLDOWN_MS and
        // DECOMMIT_DELAY_MS, providing uniform zombie memory protection
        // across all allocation tiers.
        //
        // With slab only handling <= 2KB, mimalloc now serves 2KB-1MB
        // objects (NPC sub-objects, ExtraData, scripts, Havok shapes).
        // These are the UAF-sensitive types stale readers access:
        //   Havok world rebuild:      2000-3000ms  (5x margin)
        //   AI raycasting (unloaded): 1000-2000ms  (7.5x margin)
        //   Ragdoll controller bone:  3000-5000ms  (3x margin)
        //   jip_nvse CellChange:      ~200ms       (75x margin)
        //   BSTaskManagerThread IO:    ~100ms       (150x margin)
        //
        // Within the pre-reserved arena, decommit is just a page table flip
        // -- cheap. Physical RAM is freed after 15s; only VA persists.
        mi_option_set(mi_option_purge_delay, 15000);

        // Decommit on purge (not full release) -- keeps VA reservation.
        mi_option_set(mi_option_purge_decommits, 1);

        // RETRY ON OOM = 0 (disabled)
        //
        // Default: 400ms. When OOM, mimalloc retries for 400ms -- that's a
        // 400ms freeze on the calling thread! The game runs at 60fps
        // (16ms/frame). A 400ms stall = 25 dropped frames = "crazy stutters".
        // Disable: if we can't allocate, fail immediately. The hook has its
        // own mi_collect + retry logic.
        mi_option_set(mi_option_retry_on_oom, 0);

        // Cross-thread reclaim: essential for FNV's multi-threaded alloc/free pattern.
        // Reduced from 32 to 16 to limit page bouncing between threads during
        // VAS crisis. The game has 2 AI threads + BSTaskManagerThread; 16 is
        // sufficient for normal operation while preventing excessive reclaim
        // that fragments VAS during cell transitions.
        mi_option_set(mi_option_page_reclaim_on_free, 1);
        mi_option_set(mi_option_page_cross_thread_max_reclaim, 16);

        // Arena purge mult: with 15s delay, arena purge = 30s.
        // Arena pages are shared across threads and should be purged slower
        // than thread-local pages. 2x multiplier = 15s * 2 = 30s.
        mi_option_set(mi_option_arena_purge_mult, 2);

        // Retain 1 full page per size class in free page queues.
        // Reduces VAS fragmentation during repeated cell transitions where
        // the same sizes are allocated and freed repeatedly (e.g., cell data,
        // actor refs, script objects). Changed from 0 to 1 to improve
        // allocation performance during cell transitions without significant
        // VAS cost (1 page per size class = ~4KB × 256 size classes = ~1MB).
        mi_option_set(mi_option_page_full_retain, 1);

        // Bulk-release on exit -- avoid slow teardown.
        mi_option_set_enabled(mi_option_destroy_on_exit, true);

        log::info!("[MIMALLOC] Configuration complete (reserved={}MB)", reserved / MB);
    });
}
