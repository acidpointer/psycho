//! Heap replacer initialization and activation.
//!
//! Every hook is prepared first, allocator state is initialized second, and
//! related JMPs and raw patches are activated as one transaction. Generic
//! rollback behavior lives in `libpsycho`; this module defines only the
//! Fallout-specific order.

use libc::c_void;

use libpsycho::os::windows::hook::transaction::ModificationTransaction;

use super::{gheap, manifest, scrap_heap};

// ---------------------------------------------------------------------------
// GHEAP -- prepare trampolines
// ---------------------------------------------------------------------------

/// Prepare every gheap-related trampoline without redirecting game code or
/// reserving allocator tiers.
pub fn prepare_gheap_hooks(hook_realloc_1: bool) -> anyhow::Result<bool> {
    let realloc_1_ready;

    // Prepare every trampoline before reserving allocator VAS. InlineHook
    // validates the live instruction stream and rejects targets it cannot
    // relocate safely without requiring vanilla byte-for-byte prologues.

    // These address/signature pairs are the audited Fallout executable
    // contract recorded by the corresponding typed statics. Preparing every
    // hook under one unsafe boundary keeps that native ABI assumption here.
    unsafe {
        // game heap alloc/free/msize/realloc
        {
            use gheap::hooks::*;
            use gheap::statics::*;

            GHEAP_ALLOC_HOOK.init(
                "gheap_alloc",
                GHEAP_ALLOC_ADDR as *mut c_void,
                hook_gheap_alloc,
            )?;
            GHEAP_FREE_HOOK.init(
                "gheap_free",
                GHEAP_FREE_ADDR as *mut c_void,
                hook_gheap_free,
            )?;
            GHEAP_MSIZE_HOOK.init(
                "gheap_msize",
                GHEAP_MSIZE_ADDR as *mut c_void,
                hook_gheap_msize,
            )?;
            realloc_1_ready = if hook_realloc_1 {
                match GHEAP_REALLOC_HOOK_1.init(
                    "gheap_realloc1",
                    GHEAP_REALLOC_ADDR_1 as *mut c_void,
                    hook_gheap_realloc,
                ) {
                    Ok(()) => true,
                    Err(error) => {
                        log::warn!(
                            "[GHEAP] Optional realloc entry 1 could not be prepared: {}. Continuing with realloc entry 2",
                            error,
                        );
                        false
                    }
                }
            } else {
                false
            };
            GHEAP_REALLOC_HOOK_2.init(
                "gheap_realloc2",
                GHEAP_REALLOC_ADDR_2 as *mut c_void,
                hook_gheap_realloc,
            )?;
        }

        // main loop frame hooks
        {
            use gheap::statics::*;

            MAIN_LOOP_MAINTENANCE_HOOK.init(
                "main_loop_maintenance",
                MAIN_LOOP_MAINTENANCE_ADDR as *mut c_void,
                gheap::hooks::hook_main_loop_maintenance,
            )?;
            PHASE10_PRE_HOOK.init(
                "phase10_pre",
                PHASE10_PRE_ADDR as *mut c_void,
                gheap::hooks::hook_phase10_pre,
            )?;
            PHASE10_AUDIO_UPDATE_HOOK.init(
                "phase10_audio_update",
                PHASE10_AUDIO_UPDATE_ADDR as *mut c_void,
                gheap::hooks::hook_phase10_audio_update,
            )?;
            PHASE10_AUDIO_WORKER_HOOK.init(
                "phase10_audio_worker",
                PHASE10_AUDIO_WORKER_ADDR as *mut c_void,
                gheap::hooks::hook_phase10_audio_worker,
            )?;
            RADIO_SIGNAL_SCAN_HOOK.init(
                "radio_signal_scan",
                RADIO_SIGNAL_SCAN_ADDR as *mut c_void,
                gheap::hooks::hook_radio_signal_scan,
            )?;
            RADIO_STATION_UPDATE_HOOK.init(
                "radio_station_update",
                RADIO_STATION_UPDATE_ADDR as *mut c_void,
                gheap::hooks::hook_radio_station_update,
            )?;
            PHASE10_PRE_TAIL_HOOK.init(
                "phase10_pre_tail",
                PHASE10_PRE_TAIL_ADDR as *mut c_void,
                gheap::hooks::hook_phase10_pre_tail,
            )?;
            PHASE10_WORLD_UPDATE_HOOK.init(
                "phase10_world_update",
                PHASE10_WORLD_UPDATE_ADDR as *mut c_void,
                gheap::hooks::hook_phase10_world_update,
            )?;
            PHASE10_MID_HOOK.init(
                "phase10_mid",
                PHASE10_MID_ADDR as *mut c_void,
                gheap::hooks::hook_phase10_mid,
            )?;
            PHASE10_QUEUE_DRAIN_HOOK.init(
                "phase10_queue_drain",
                PHASE10_QUEUE_DRAIN_ADDR as *mut c_void,
                gheap::hooks::hook_phase10_queue_drain,
            )?;
            PHASE10_POST_HOOK.init(
                "phase10_post",
                PHASE10_POST_ADDR as *mut c_void,
                gheap::hooks::hook_phase10_post,
            )?;
            PER_FRAME_QUEUE_DRAIN_HOOK.init(
                "per_frame_queue_drain",
                PER_FRAME_QUEUE_DRAIN_ADDR as *mut c_void,
                gheap::hooks::hook_per_frame_queue_drain,
            )?;
        }

        // ai thread sync
        {
            use gheap::statics::*;

            AI_THREAD_START_HOOK.init(
                "ai_thread_start",
                AI_THREAD_START_ADDR as *mut c_void,
                gheap::hooks::hook_ai_thread_start,
            )?;
            AI_THREAD_JOIN_HOOK.init(
                "ai_thread_join",
                AI_THREAD_JOIN_ADDR as *mut c_void,
                gheap::hooks::hook_ai_thread_join,
            )?;
        }

        // OOM Stage 8 (HeapCompact) -- safe BSTaskManagerThread semaphore release
        {
            use gheap::statics::*;

            OOM_STAGE_EXEC_HOOK.init(
                "oom_stage_exec",
                OOM_STAGE_EXEC_HOOK_ADDR as *mut c_void,
                gheap::hooks::hook_oom_stage_exec,
            )?;
        }

        // texture cache dead set
        {
            use gheap::statics::*;

            TEXTURE_CACHE_FIND_HOOK.init(
                "texture_cache_find",
                TEXTURE_CACHE_FIND_ADDR as *mut c_void,
                gheap::texture_cache::hook_texture_cache_find,
            )?;
            NISOURCETEXTURE_DTOR_HOOK.init(
                "nisourcetexture_dtor",
                NISOURCETEXTURE_DTOR_ADDR as *mut c_void,
                gheap::texture_cache::hook_nisourcetexture_dtor,
            )?;
        }

        // gheap-only model task destructor guard
        {
            use gheap::statics::*;
            MODEL_TASK_DTOR_HOOK.init(
                "model_task_dtor_guard",
                MODEL_TASK_DTOR_ADDR as *mut c_void,
                gheap::model_task_fix::hook_model_task_dtor,
            )?;
        }

        // CRT inline hooks
        {
            use super::crt_inline::*;

            MALLOC_HOOK_1.init("malloc1", MALLOC_ADDR_1 as *mut c_void, hook_malloc)?;
            MALLOC_HOOK_2.init("malloc2", MALLOC_ADDR_2 as *mut c_void, hook_malloc)?;
            CALLOC_HOOK_1.init("calloc1", CALLOC_ADDR_1 as *mut c_void, hook_calloc)?;
            CALLOC_HOOK_2.init("calloc2", CALLOC_ADDR_2 as *mut c_void, hook_calloc)?;
            REALLOC_HOOK_1.init("realloc1", REALLOC_ADDR_1 as *mut c_void, hook_realloc)?;
            REALLOC_HOOK_2.init("realloc2", REALLOC_ADDR_2 as *mut c_void, hook_realloc)?;
            RECALLOC_HOOK_1.init("recalloc1", RECALLOC_ADDR_1 as *mut c_void, hook_recalloc)?;
            RECALLOC_HOOK_2.init("recalloc2", RECALLOC_ADDR_2 as *mut c_void, hook_recalloc)?;
            FREE_HOOK.init("free", FREE_ADDR as *mut c_void, hook_free)?;
            MSIZE_HOOK.init("msize", MSIZE_ADDR as *mut c_void, hook_msize)?;
        }

        // havok world lock tracking
        {
            use gheap::hooks::{hook_hkworld_lock, hook_hkworld_unlock};
            use gheap::statics::*;

            HAVOK_STOP_START_HOOK.init(
                "havok_stop_start",
                HAVOK_STOP_START_ADDR as *mut c_void,
                gheap::hooks::hook_havok_stop_start,
            )?;
            HKWORLD_LOCK_HOOK.init(
                "hkworld_lock",
                HKWORLD_LOCK_ADDR as *mut c_void,
                hook_hkworld_lock,
            )?;
            HKWORLD_UNLOCK_HOOK.init(
                "hkworld_unlock",
                HKWORLD_UNLOCK_ADDR as *mut c_void,
                hook_hkworld_unlock,
            )?;
        }
    }

    log::info!("[GHEAP] Hook trampolines prepared");
    Ok(realloc_1_ready)
}

/// Initialize allocator state after every required hook target is proven.
///
/// This ordering avoids reserving allocator address space when a later hook
/// turns out to be incompatible. Game code is still not redirected here.
pub fn initialize_gheap_runtime() -> anyhow::Result<()> {
    // Pool allocator: each class reserves its own VA aligned to POOL_ALIGN.
    if !gheap::pool::init() {
        return Err(anyhow::anyhow!("Pool allocator initialization failed"));
    }

    // Block allocator: single contiguous tier reservation. Keeps all
    // medium allocations in one VA island instead of scattering
    // 16 MB reservations across free VAS per save-load burst.
    if !gheap::block::init() {
        log::warn!(
            "[HEAP REPLACER] Block tier reservation failed; medium \
             allocations will fall through to va_alloc"
        );
    }

    // Cache process heap handles so free/msize/realloc can route pre-hook
    // pointers back to the correct Windows heap after hooks go live.
    super::heap_validate::init_heap_cache();

    // Trigger LazyLock construction for pressure relief singleton.
    gheap::pressure::PressureRelief::instance();

    log::info!("[GHEAP] Allocator runtime initialized");
    Ok(())
}

// ---------------------------------------------------------------------------
// GHEAP -- enable hooks and patches
// ---------------------------------------------------------------------------

/// Transactionally enable the complete gheap + CRT + scrap-heap surface.
pub fn install_gheap_and_sheap_hooks(hook_realloc_1: bool) -> anyhow::Result<()> {
    let mut transaction = ModificationTransaction::new();
    // All replacement entrypoints must be live before their vanilla providers
    // are disabled. A raw-patch failure then rolls the hooks back in reverse.
    enable_gheap_hooks(&mut transaction, hook_realloc_1)?;
    enable_sheap_hooks(&mut transaction)?;
    for patch in manifest::GHEAP_PATCHES {
        transaction.apply_patch(patch)?;
    }
    for patch in manifest::SHEAP_PATCHES {
        transaction.apply_patch(patch)?;
    }
    transaction.commit();
    start_deferred_threads();
    log::info!("[GHEAP] Gheap + CRT + scrap_heap transaction committed");
    Ok(())
}

// ---------------------------------------------------------------------------
// scrap_heap -- prepare trampolines and runtime
// ---------------------------------------------------------------------------

/// Prepare all six scrap-heap hooks without redirecting game code.
pub fn prepare_sheap_hooks() -> anyhow::Result<()> {
    use scrap_heap::*;

    // Each typed hook signature is the audited ABI for its fixed game address.
    unsafe {
        GET_THREAD_LOCAL_HOOK.init(
            "sheap_get_thread_local",
            SHEAP_GET_THREAD_LOCAL_ADDR as *mut c_void,
            hook_get_thread_local,
        )?;
        INIT_FIX_HOOK.init(
            "sheap_init_fix",
            SHEAP_INIT_FIX_ADDR as *mut c_void,
            hook_init_fix,
        )?;
        INIT_VAR_HOOK.init(
            "sheap_init_var",
            SHEAP_INIT_VAR_ADDR as *mut c_void,
            hook_init_var,
        )?;
        ALLOC_HOOK.init("sheap_alloc", SHEAP_ALLOC_ADDR as *mut c_void, hook_alloc)?;
        FREE_HOOK.init("sheap_free", SHEAP_FREE_ADDR as *mut c_void, hook_free)?;
        PURGE_HOOK.init("sheap_purge", SHEAP_PURGE_ADDR as *mut c_void, hook_purge)?;
    }

    log::info!("[scrap_heap] Hook trampolines prepared");
    Ok(())
}

/// Initialize the scrap-heap runtime after all hook targets are proven.
pub fn initialize_sheap_runtime() {
    scrap_heap::initialize_runtime();
    log::info!("[scrap_heap] Allocator runtime initialized");
}

// ---------------------------------------------------------------------------
// scrap_heap -- enable hooks and patches
// ---------------------------------------------------------------------------

/// Enable scrap-heap JMPs and apply the embedded-sheap constructor
/// NOP patch. Both are required whenever scrap-heap replacement is active.
pub fn install_sheap_hooks() -> anyhow::Result<()> {
    let mut transaction = ModificationTransaction::new();
    enable_sheap_hooks(&mut transaction)?;
    for patch in manifest::SHEAP_PATCHES {
        transaction.apply_patch(patch)?;
    }
    transaction.commit();
    log::info!("[scrap_heap] Hook transaction committed");
    Ok(())
}

fn enable_gheap_hooks(
    transaction: &mut ModificationTransaction,
    hook_realloc_1: bool,
) -> anyhow::Result<()> {
    use gheap::statics::*;

    // Publish release/size/resize ownership before allocation. Even though the
    // pre-CRT barrier keeps engine threads out, this order prevents any future
    // caller from receiving a gheap pointer before matching consumers exist.
    transaction.enable_inline(&GHEAP_FREE_HOOK)?;
    transaction.enable_inline(&GHEAP_MSIZE_HOOK)?;
    transaction.enable_inline(&GHEAP_REALLOC_HOOK_2)?;
    if hook_realloc_1 && let Err(error) = transaction.enable_inline(&GHEAP_REALLOC_HOOK_1) {
        // A clean failure means another component changed this optional entry
        // between preparation and activation. A still-enabled hook means its
        // immediate rollback failed, so the whole transaction must unwind.
        if GHEAP_REALLOC_HOOK_1.is_enabled() {
            return Err(error.into());
        }
        log::warn!(
            "[GHEAP] Optional realloc entry 1 could not be activated: {}. Continuing with realloc entry 2",
            error,
        );
    }
    transaction.enable_inline(&GHEAP_ALLOC_HOOK)?;

    transaction.enable_inline(&MAIN_LOOP_MAINTENANCE_HOOK)?;
    transaction.enable_inline(&PHASE10_PRE_HOOK)?;
    transaction.enable_inline(&PHASE10_AUDIO_UPDATE_HOOK)?;
    transaction.enable_inline(&PHASE10_AUDIO_WORKER_HOOK)?;
    transaction.enable_inline(&RADIO_SIGNAL_SCAN_HOOK)?;
    transaction.enable_inline(&RADIO_STATION_UPDATE_HOOK)?;
    transaction.enable_inline(&PHASE10_PRE_TAIL_HOOK)?;
    transaction.enable_inline(&PHASE10_WORLD_UPDATE_HOOK)?;
    transaction.enable_inline(&PHASE10_MID_HOOK)?;
    transaction.enable_inline(&PHASE10_QUEUE_DRAIN_HOOK)?;
    transaction.enable_inline(&PHASE10_POST_HOOK)?;
    transaction.enable_inline(&PER_FRAME_QUEUE_DRAIN_HOOK)?;
    transaction.enable_inline(&AI_THREAD_START_HOOK)?;
    transaction.enable_inline(&AI_THREAD_JOIN_HOOK)?;
    transaction.enable_inline(&OOM_STAGE_EXEC_HOOK)?;
    transaction.enable_inline(&TEXTURE_CACHE_FIND_HOOK)?;
    transaction.enable_inline(&NISOURCETEXTURE_DTOR_HOOK)?;
    transaction.enable_inline(&MODEL_TASK_DTOR_HOOK)?;
    transaction.enable_inline(&HAVOK_STOP_START_HOOK)?;
    transaction.enable_inline(&HKWORLD_LOCK_HOOK)?;
    transaction.enable_inline(&HKWORLD_UNLOCK_HOOK)?;

    transaction.enable_inline(&super::crt_inline::FREE_HOOK)?;
    transaction.enable_inline(&super::crt_inline::MSIZE_HOOK)?;
    transaction.enable_inline(&super::crt_inline::REALLOC_HOOK_1)?;
    transaction.enable_inline(&super::crt_inline::REALLOC_HOOK_2)?;
    transaction.enable_inline(&super::crt_inline::RECALLOC_HOOK_1)?;
    transaction.enable_inline(&super::crt_inline::RECALLOC_HOOK_2)?;
    transaction.enable_inline(&super::crt_inline::MALLOC_HOOK_1)?;
    transaction.enable_inline(&super::crt_inline::MALLOC_HOOK_2)?;
    transaction.enable_inline(&super::crt_inline::CALLOC_HOOK_1)?;
    transaction.enable_inline(&super::crt_inline::CALLOC_HOOK_2)?;
    Ok(())
}

fn enable_sheap_hooks(transaction: &mut ModificationTransaction) -> anyhow::Result<()> {
    use scrap_heap::*;

    // The TLS provider is a direct replacement, not a chain. It must become
    // live only after every operation it can return is ready; allocation is
    // last for the same producer-before-consumer reason as gheap.
    transaction.enable_inline(&FREE_HOOK)?;
    transaction.enable_inline(&PURGE_HOOK)?;
    transaction.enable_inline(&INIT_FIX_HOOK)?;
    transaction.enable_inline(&INIT_VAR_HOOK)?;
    transaction.enable_replacement(&GET_THREAD_LOCAL_HOOK)?;
    transaction.enable_inline(&ALLOC_HOOK)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Deferred thread startup
// ---------------------------------------------------------------------------

/// Start background monitoring threads. Must be called outside DllMain
/// (loader lock prevents thread creation).
fn start_deferred_threads() {
    let watchdog = gheap::watchdog::Watchdog::start();
    if watchdog.is_running() {
        // Allocator services live for the process lifetime. Dropping the handle
        // would stop and join the thread immediately.
        std::mem::forget(watchdog);
    }
}
