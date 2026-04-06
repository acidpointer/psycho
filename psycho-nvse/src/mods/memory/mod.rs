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

        // Initialize UAF bitmap for allocation-time object tracking.
        // The bitmap tracks which arena segments contain UAF-sensitive objects.
        crate::mods::memory::heap_replacer::gheap::uaf_bitmap::init(reserved);

        // 32MB overflow arenas if pre-reserved block fills up.
        mi_option_set(mi_option_arena_reserve, 32 * 1024); // KiB
        log::info!("[MIMALLOC] arena_reserve = 32MB");

        // Demand-page: reserve VA, commit on first touch.
        mi_option_set(mi_option_arena_eager_commit, 0);

        // PURGE DELAY = 100ms
        //
        // Freed pages stay committed (readable) for 100ms before mimalloc
        // decommits them. This provides a safety window for:
        // - AI thread raycasts against terrain: 10-30ms typical, up to 50ms
        // - BSTaskManagerThread texture loading: up to 100ms for large textures
        // - Havok broadphase queries: < 10ms typical
        //
        // 100ms was chosen based on crash analysis: the hkBSHeightFieldShape
        // UAF crash occurred at 50ms because the AI thread was mid-raycast
        // when the shape was freed. 100ms provides 2x safety margin.
        //
        // Within the pre-reserved arena, decommit is just a page table flip
        // -- cheap. Physical RAM is freed after 100ms; only VA persists.
        mi_option_set(mi_option_purge_delay, 100);
        log::info!("[MIMALLOC] purge_delay = 100ms (stale reader protection window)");

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
        log::info!("[MIMALLOC] retry_on_oom = 0 (disabled, we handle OOM ourselves)");

        // Cross-thread reclaim: essential for FNV's multi-threaded alloc/free pattern.
        // Reduced from 32 to 16 to limit page bouncing between threads during
        // VAS crisis. The game has 2 AI threads + BSTaskManagerThread; 16 is
        // sufficient for normal operation while preventing excessive reclaim
        // that fragments VAS during cell transitions.
        mi_option_set(mi_option_page_reclaim_on_free, 1);
        mi_option_set(mi_option_page_cross_thread_max_reclaim, 16);

        // Arena purge mult: with 50ms delay, arena purge = 100ms.
        // Arena purge should be faster than thread-local purge since arenas
        // are shared across threads. 2x multiplier = 50ms * 2 = 100ms.
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
