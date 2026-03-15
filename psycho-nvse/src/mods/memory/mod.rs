mod crt_iat;

mod heap_replacer;
pub use crt_iat::*;
pub use heap_replacer::*;
use libmimalloc::{
    mi_option_set, mi_option_set_enabled,
    mi_option_arena_eager_commit,
    mi_option_purge_delay,
    mi_option_page_reclaim_on_free,
    mi_option_page_cross_thread_max_reclaim,
    mi_option_arena_purge_mult,
    mi_option_destroy_on_exit,
};
use parking_lot::Once;

static CONFIG_MIMALLOC: Once = Once::new();

pub(super) fn configure_mimalloc() {
    CONFIG_MIMALLOC.call_once(|| unsafe {
        // ---------------------------------------------------------------
        // Mimalloc is the GLOBAL allocator for the entire game process
        // (via IAT hooks on all loaded DLLs) AND backs scrap heap regions
        // (via mi_malloc_aligned). These options are tuned for:
        //   - Fallout: New Vegas (32-bit, multi-threaded game)
        //   - Running on Windows, Proton, and Steam Deck
        //   - Bursty alloc/free patterns with cross-thread memory access
        // ---------------------------------------------------------------

        // ARENA EAGER COMMIT (option 4) = always eager
        //
        // Default: 2 (auto-detect overcommit)
        // Set to:  1 (always eager commit)
        //
        // On Proton/Wine, overcommit detection is unreliable. Eager commit
        // ensures memory is physically backed on allocation, not on first
        // page fault. This eliminates page fault stutters during gameplay
        // that manifest as micro-freezes — especially noticeable because
        // every single malloc/free in the game goes through mimalloc.
        mi_option_set(mi_option_arena_eager_commit, 1);
        log::info!("[MIMALLOC] arena_eager_commit = 1 (always eager)");

        // PURGE DELAY (option 15) = immediate
        //
        // Default: 10ms
        // Set to:  0 (immediate purge)
        //
        // When scrap heap GC drops 256KB regions (via mi_free), mimalloc
        // should decommit those pages immediately rather than holding them
        // for 10ms. Also helps the general allocator return memory faster.
        // Critical for Steam Deck where 16GB RAM is shared with GPU —
        // every MB of stale allocator pages is a MB less VRAM.
        mi_option_set(mi_option_purge_delay, 0);
        log::info!("[MIMALLOC] purge_delay = 0ms (immediate)");

        // PAGE RECLAIM ON FREE (option 35) = always allow
        //
        // Default: 0 (only reclaim pages from own theap)
        // Set to:  1 (allow reclaiming from any theap)
        //
        // The game's sheap_ptr crosses thread boundaries — thread A
        // allocates, thread B frees. With IAT hooks, this pattern applies
        // to ALL game allocations too. Without this option, freed pages
        // pile up as "abandoned" in mimalloc's internal bookkeeping and
        // never get reclaimed by the freeing thread. With =1, any thread
        // can immediately reclaim abandoned pages on free, preventing
        // memory bloat and fragmentation.
        mi_option_set(mi_option_page_reclaim_on_free, 1);
        log::info!("[MIMALLOC] page_reclaim_on_free = 1 (always)");

        // PAGE CROSS-THREAD MAX RECLAIM (option 42) = higher limit
        //
        // Default: 16
        // Set to:  32
        //
        // Controls how many pages a thread will reclaim from other threads'
        // abandoned pools (per size class). Higher limit is beneficial
        // because the game has 10+ threads all routing malloc/free through
        // mimalloc. Default 16 can leave abandoned pages unreclaimed when
        // cross-thread free is heavy (which it is in FNV).
        mi_option_set(mi_option_page_cross_thread_max_reclaim, 32);
        log::info!("[MIMALLOC] page_cross_thread_max_reclaim = 32");

        // ARENA PURGE MULTIPLIER (option 24) = faster arena purge
        //
        // Default: 10 (arena purge delay = purge_delay * 10)
        // Set to:  2  (arena purge delay = purge_delay * 2 = 0ms)
        //
        // Since purge_delay is 0, this multiplier has minimal effect, but
        // lowering it ensures arena-level memory is also returned to the OS
        // without unnecessary delay if purge_delay is ever changed.
        mi_option_set(mi_option_arena_purge_mult, 2);
        log::info!("[MIMALLOC] arena_purge_mult = 2");

        // DESTROY ON EXIT (option 22) = enabled
        //
        // Default: 0 (disabled)
        // Set to:  1 (release all memory on exit)
        //
        // We are a DLL injected into a game process. On game exit, there is
        // no benefit to walking every allocation and freeing individually —
        // the process is terminating. This tells mimalloc to bulk-release
        // everything, avoiding slow shutdown that can cause the game to
        // hang on exit (especially with hundreds of MBs allocated).
        mi_option_set_enabled(mi_option_destroy_on_exit, true);
        log::info!("[MIMALLOC] destroy_on_exit = true");
    });
}
