use libmimalloc::{
    mi_arena_id_t, mi_manage_os_memory_ex, mi_option_arena_eager_commit,
    mi_option_arena_purge_mult, mi_option_arena_reserve, mi_option_destroy_on_exit,
    mi_option_page_cross_thread_max_reclaim, mi_option_page_full_retain,
    mi_option_page_reclaim_on_free, mi_option_purge_decommits, mi_option_purge_delay,
    mi_option_retry_on_oom, mi_option_set, mi_option_set_enabled,
};
use parking_lot::Once;

static CONFIG_MIMALLOC: Once = Once::new();

const MB: usize = 1024 * 1024;

/// Configure mimalloc with a pre-reserved arena range from the unified
/// reservation. The range must be MEM_RESERVE'd (not committed) and
/// must be at least MI_SEGMENT_ALIGN aligned (4MB on i686).
pub fn configure_mimalloc_with_arena(start: *const u8, size: usize) {
    CONFIG_MIMALLOC.call_once(|| unsafe {
        let mut arena_id: mi_arena_id_t = 0;
        let ok = mi_manage_os_memory_ex(
            start as *const std::ffi::c_void,
            size,
            false, // is_committed: false = demand-page
            false, // is_large: no huge pages on 32-bit
            false, // is_zero
            -1,    // numa_node
            false, // exclusive
            &mut arena_id,
        );
        if ok {
            log::info!(
                "[MIMALLOC] Managing pre-reserved arena: {}MB at 0x{:08x} (id={:?})",
                size / MB,
                start as usize,
                arena_id,
            );
        } else {
            log::error!(
                "[MIMALLOC] mi_manage_os_memory_ex FAILED for {}MB at 0x{:08x}",
                size / MB,
                start as usize,
            );
        }

        configure_options();
    });
}

/// Configure mimalloc with dynamic arena reservation (original behavior).
/// Falls back to this if the unified reservation is not available.
#[allow(dead_code)]
pub fn configure_mimalloc() {
    CONFIG_MIMALLOC.call_once(|| unsafe {
        let arena_sizes = [512 * MB, 384 * MB, 256 * MB];
        let mut reserved = 0usize;
        for &size in &arena_sizes {
            let mut arena_id: mi_arena_id_t = 0;
            let result = libmimalloc::mi_reserve_os_memory_ex(
                size,
                false, // commit: false = demand-page
                false, // allow_large: no huge pages on 32-bit
                false, // exclusive: allow fallback arenas too
                &mut arena_id,
            );
            if result == 0 {
                reserved = size;
                log::info!(
                    "[MIMALLOC] Reserved {}MB arena (id={:?})",
                    size / MB,
                    arena_id
                );
                break;
            }
            log::warn!(
                "[MIMALLOC] Failed to reserve {}MB (err={}), trying smaller...",
                size / MB,
                result
            );
        }
        if reserved == 0 {
            log::error!("[MIMALLOC] Could not reserve ANY arena! Falling back to dynamic arenas.");
        }

        configure_options();
        log::info!(
            "[MIMALLOC] Configuration complete (reserved={}MB)",
            reserved / MB
        );
    });
}

/// Apply mimalloc runtime options. Called after arena setup.
unsafe fn configure_options() {
    unsafe {
        // 128 MB overflow arenas if the pre-reserved block fills up.
        mi_option_set(mi_option_arena_reserve, 128 * 1024); // KiB

        // Demand-page: reserve VA, commit on first touch.
        mi_option_set(mi_option_arena_eager_commit, 0);

        // PURGE DELAY = -1 (never purge during gameplay)
        mi_option_set(mi_option_purge_delay, -1);

        // Decommit on purge (not full release) -- keeps VA reservation.
        mi_option_set(mi_option_purge_decommits, 1);

        // RETRY ON OOM = 0 (disabled)
        mi_option_set(mi_option_retry_on_oom, 0);

        // Cross-thread reclaim
        mi_option_set(mi_option_page_reclaim_on_free, 1);
        mi_option_set(mi_option_page_cross_thread_max_reclaim, 16);

        // Arena purge mult
        mi_option_set(mi_option_arena_purge_mult, 2);

        // Retain 1 full page per size class
        mi_option_set(mi_option_page_full_retain, 1);

        // Bulk-release on exit
        mi_option_set_enabled(mi_option_destroy_on_exit, true);
    }
}
