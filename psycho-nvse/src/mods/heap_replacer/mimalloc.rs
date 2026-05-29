use libc::c_long;
use libmimalloc::{
    mi_arena_id_t, mi_option_arena_eager_commit, mi_option_arena_max_object_size,
    mi_option_arena_purge_mult, mi_option_arena_reserve, mi_option_destroy_on_exit, mi_option_get,
    mi_option_page_cross_thread_max_reclaim, mi_option_page_full_retain,
    mi_option_page_reclaim_on_free, mi_option_purge_decommits, mi_option_purge_delay,
    mi_option_retry_on_oom, mi_option_set, mi_option_set_enabled,
};
use parking_lot::Once;

static CONFIG_MIMALLOC: Once = Once::new();

const MB: usize = 1024 * 1024;
const MIMALLOC_ARENA_RESERVE_KIB: c_long = 8 * 1024;
const MIMALLOC_ARENA_MAX_OBJECT_KIB: c_long = 64;

/// Configure mimalloc with dynamic arena reservation (original behavior).
/// Falls back to this if the unified reservation is not available.
pub fn configure_mimalloc() {
    CONFIG_MIMALLOC.call_once(|| unsafe {
        // let arena_sizes = [512 * MB, 384 * MB, 256 * MB];
        let arena_sizes = [16 * MB, 8 * MB];

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
        // Keep future arenas small. Mimalloc defaults to 128 MB on
        // 32-bit, which can steal the same contiguous VAS D3D needs.
        mi_option_set(mi_option_arena_reserve, MIMALLOC_ARENA_RESERVE_KIB);

        // Objects above 64 KB bypass arenas and use mimalloc's direct
        // OS path. This keeps 128 KB scrap regions from growing hidden
        // mimalloc arenas during VAS pressure.
        mi_option_set(
            mi_option_arena_max_object_size,
            MIMALLOC_ARENA_MAX_OBJECT_KIB,
        );

        // Demand-page: reserve VA, commit on first touch.
        mi_option_set(mi_option_arena_eager_commit, 0);

        // Keep delayed purging enabled, but make purge reset pages
        // instead of decommitting them. Decommit splits VAS into many
        // tiny regions on 32-bit and worsens largest-hole collapse.
        mi_option_set(mi_option_purge_delay, 1000);

        // Reset on purge, not decommit.
        mi_option_set(mi_option_purge_decommits, 0);

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

        log::info!(
            "[MIMALLOC] Tuned: arena_reserve={}MB arena_max_object={}KB purge_delay={}ms purge_decommits={} retry_on_oom={} page_reclaim_on_free={} full_retain={} cross_thread_reclaim={}",
            MIMALLOC_ARENA_RESERVE_KIB / 1024,
            MIMALLOC_ARENA_MAX_OBJECT_KIB,
            mi_option_get(mi_option_purge_delay),
            mi_option_get(mi_option_purge_decommits),
            mi_option_get(mi_option_retry_on_oom),
            mi_option_get(mi_option_page_reclaim_on_free),
            mi_option_get(mi_option_page_full_retain),
            mi_option_get(mi_option_page_cross_thread_max_reclaim),
        );
    }
}
