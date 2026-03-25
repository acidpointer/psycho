//! Hook installation orchestrator.
//!
//! Initializes and enables all heap replacement hooks in a single
//! transaction. If any hook fails to install, all previously-enabled
//! hooks are rolled back to prevent split-heap corruption.

use libc::c_void;
use std::sync::LazyLock;

use libpsycho::os::windows::winapi::{patch_nop_call, patch_ret};
use libpsycho::os::windows::hook::inline::inlinehook::InlineHookContainer;

use super::{crt, game_heap, scrap_heap};

// ---- HookGuard: transactional hook installation ----

type DisableFn = Box<dyn Fn() + Send + Sync>;

/// Collects enabled hooks and rolls them all back if the guard is dropped
/// without calling commit(). Prevents split-heap corruption when a later
/// hook in the sequence fails to install.
struct HookGuard {
    rollbacks: Vec<(&'static str, DisableFn)>,
    committed: bool,
}

impl HookGuard {
    fn new() -> Self {
        Self {
            rollbacks: Vec::new(),
            committed: false,
        }
    }

    fn enable_hook<T: Copy + 'static>(
        &mut self,
        name: &'static str,
        hook: &'static LazyLock<InlineHookContainer<T>>,
    ) -> anyhow::Result<()> {
        let container: &InlineHookContainer<T> = hook;
        container.enable().map_err(|e| anyhow::anyhow!("{}: {:?}", name, e))?;
        self.rollbacks.push((name, Box::new(move || {
            let container: &InlineHookContainer<T> = hook;
            let _ = container.disable();
        })));
        Ok(())
    }

    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        log::error!(
            "[HEAP REPLACER] Rolling back {} hooks due to installation failure",
            self.rollbacks.len()
        );
        for (name, disable) in self.rollbacks.iter().rev() {
            disable();
            log::warn!("[ROLLBACK] Disabled {}", name);
        }
    }
}

// ---- Installation ----

/// Applies patches and installs all heap replacement hooks.
/// mimalloc is already configured by the time this runs.
pub fn install_game_heap_hooks() -> anyhow::Result<()> {
    // Main thread detection uses OS thread ID comparison (is_main_thread_by_tid).
    // Always correct — no initialization needed. Before TES object is available,
    // returns false → frees go to mi_free directly (safe, zero quarantine).

    // Initialize heap validation cache for routing pre-hook pointers.
    super::heap_validate::init_heap_cache();

    // Initialize memory pressure relief (triggers LazyLock construction).
    game_heap::pressure::PressureRelief::instance();

    let mut guard = HookGuard::new();

    // ---- Game heap: replace GameHeap::Allocate/Free/Msize/Realloc ----
    {
        use game_heap::statics::*;
        use game_heap::hooks::*;

        GHEAP_ALLOC_HOOK.init("gheap_alloc", GHEAP_ALLOC_ADDR as *mut c_void, hook_gheap_alloc)?;
        GHEAP_FREE_HOOK.init("gheap_free", GHEAP_FREE_ADDR as *mut c_void, hook_gheap_free)?;
        GHEAP_MSIZE_HOOK.init("gheap_msize", GHEAP_MSIZE_ADDR as *mut c_void, hook_gheap_msize)?;
        GHEAP_REALLOC_HOOK_1.init("gheap_realloc1", GHEAP_REALLOC_ADDR_1 as *mut c_void, hook_gheap_realloc)?;
        GHEAP_REALLOC_HOOK_2.init("gheap_realloc2", GHEAP_REALLOC_ADDR_2 as *mut c_void, hook_gheap_realloc)?;

        guard.enable_hook("gheap_alloc", &GHEAP_ALLOC_HOOK)?;
        guard.enable_hook("gheap_free", &GHEAP_FREE_HOOK)?;
        guard.enable_hook("gheap_msize", &GHEAP_MSIZE_HOOK)?;
        guard.enable_hook("gheap_realloc1", &GHEAP_REALLOC_HOOK_1)?;
        guard.enable_hook("gheap_realloc2", &GHEAP_REALLOC_HOOK_2)?;

        log::info!("[GHEAP] GameHeap fully replaced with mimalloc (alloc/free/realloc/msize)");
    }

    // ---- Main loop: post-render pressure relief ----
    {
        use game_heap::statics::*;
        use game_heap::hooks::*;

        MAIN_LOOP_MAINTENANCE_HOOK.init(
            "main_loop_maintenance",
            MAIN_LOOP_MAINTENANCE_ADDR as *mut c_void,
            hook_main_loop_maintenance,
        )?;
        guard.enable_hook("main_loop_maintenance", &MAIN_LOOP_MAINTENANCE_HOOK)?;
        log::info!("[PRESSURE] Post-render hook installed at 0x{:08X}", MAIN_LOOP_MAINTENANCE_ADDR);
    }

    // ---- Per-frame queue drain: boost NiNode drain under pressure ----
    {
        use game_heap::statics::*;
        use game_heap::hooks::*;

        PER_FRAME_QUEUE_DRAIN_HOOK.init(
            "per_frame_queue_drain",
            PER_FRAME_QUEUE_DRAIN_ADDR as *mut c_void,
            hook_per_frame_queue_drain,
        )?;
        guard.enable_hook("per_frame_queue_drain", &PER_FRAME_QUEUE_DRAIN_HOOK)?;
        log::info!("[PRESSURE] Per-frame queue drain hook installed at 0x{:08X}", PER_FRAME_QUEUE_DRAIN_ADDR);
    }

    // NOTE: CellTransitionHandler (FUN_008774a0) is NOT hooked.
    // The original already calls FUN_008324e0(0) which stops Havok simulation
    // and drains all AI task queues BEFORE running PDD. Adding hkWorld_Lock
    // before the original causes deadlock: AI threads can't finish their
    // current physics work because they need Havok world access, but we hold
    // the lock. The loading state counter is also redundant -- cell transitions
    // run during loading screens where DAT_01202d6c is already > 0.

    // NOTE: IOManager Phase 3 (FUN_00c3dbf0) is NOT hooked.
    // IOManager and PDD are both on the main thread — read lock on IOManager
    // deadlocks when task processing internally triggers PDD (write lock).
    // Same-thread read + write = deadlock. BSTaskManagerThread frees go
    // directly to mi_free (no write lock), so no cross-thread protection needed.

    // ---- AI thread synchronization: set/clear AI_ACTIVE flag ----
    {
        use game_heap::statics::*;
        use game_heap::hooks::*;

        AI_THREAD_START_HOOK.init(
            "ai_thread_start",
            AI_THREAD_START_ADDR as *mut c_void,
            hook_ai_thread_start,
        )?;
        guard.enable_hook("ai_thread_start", &AI_THREAD_START_HOOK)?;
        log::info!("[SYNC] AI start flag at 0x{:08X}", AI_THREAD_START_ADDR);

        AI_THREAD_JOIN_HOOK.init(
            "ai_thread_join",
            AI_THREAD_JOIN_ADDR as *mut c_void,
            hook_ai_thread_join,
        )?;
        guard.enable_hook("ai_thread_join", &AI_THREAD_JOIN_HOOK)?;
        log::info!("[SYNC] AI join flag at 0x{:08X}", AI_THREAD_JOIN_ADDR);
    }

    // ---- PDD: destruction guard around ProcessDeferredDestruction ----
    {
        use game_heap::statics::*;

        PDD_HOOK.init(
            "pdd",
            PDD_ADDR as *mut c_void,
            game_heap::pdd_hook::hook_pdd,
        )?;
        guard.enable_hook("pdd", &PDD_HOOK)?;
        log::info!("[SYNC] PDD hook installed at 0x{:08X}", PDD_ADDR);
    }

    // ---- Texture cache: dead set hooks ----
    {
        use game_heap::statics::*;

        TEXTURE_CACHE_FIND_HOOK.init(
            "texture_cache_find",
            TEXTURE_CACHE_FIND_ADDR as *mut c_void,
            game_heap::texture_cache::hook_texture_cache_find,
        )?;
        guard.enable_hook("texture_cache_find", &TEXTURE_CACHE_FIND_HOOK)?;

        NISOURCETEXTURE_DTOR_HOOK.init(
            "nisourcetexture_dtor",
            NISOURCETEXTURE_DTOR_ADDR as *mut c_void,
            game_heap::texture_cache::hook_nisourcetexture_dtor,
        )?;
        guard.enable_hook("nisourcetexture_dtor", &NISOURCETEXTURE_DTOR_HOOK)?;
        log::info!(
            "[TEXTURE] Dead set hooks installed (find=0x{:08X}, dtor=0x{:08X})",
            TEXTURE_CACHE_FIND_ADDR, NISOURCETEXTURE_DTOR_ADDR,
        );
    }

    // ---- IO task release: prevent double-release on recycled memory ----
    {
        use game_heap::statics::*;

        TASK_RELEASE_HOOK.init(
            "task_release",
            TASK_RELEASE_ADDR as *mut c_void,
            game_heap::io_task::hook_task_release,
        )?;
        guard.enable_hook("task_release", &TASK_RELEASE_HOOK)?;
        log::info!("[IO_TASK] Release hook installed at 0x{:08X}", TASK_RELEASE_ADDR);
    }

    // ---- Skeleton update: validate ragdoll bone data before access ----
    {
        use game_heap::statics::*;

        SKELETON_UPDATE_HOOK.init(
            "skeleton_update",
            SKELETON_UPDATE_ADDR as *mut c_void,
            game_heap::skeleton_update::hook_skeleton_update,
        )?;
        guard.enable_hook("skeleton_update", &SKELETON_UPDATE_HOOK)?;
        log::info!("[ENGINE FIX] Skeleton update validation hook at 0x{:08X}", SKELETON_UPDATE_ADDR);
    }

    // ---- Queued reference processing: skip HAVOK_DEATH ragdoll UAF ----
    {
        use game_heap::statics::*;

        // REMOVED: queued_ref HAVOK_DEATH filter.
        //
        // The filter skipped ALL queued reference processing for refs with
        // flag 0x10000 (HAVOK_DEATH). This prevented actor initialization
        // for references loaded from saves → frozen mannequin enemies,
        // no physics, no AI, no collision.
        //
        // The filter was redundant: FUN_0056f700 runs on the main thread,
        // quarantine drain (tick_flush) also runs on the main thread.
        // They're sequential — freed Havok data stays as readable zombie
        // data in quarantine. No UAF possible.
        log::info!("[ENGINE FIX] Queued ref processing: no filter (quarantine protects)");
    }

    // ---- Havok broadphase synchronization ----
    //
    // Worker threads hold game_guard read lock during Havok operations.
    // This prevents quarantine drain from recycling collision/physics data.
    {
        use game_heap::statics::*;

        HAVOK_ADD_ENTITY_HOOK.init(
            "havok_add_entity",
            HAVOK_ADD_ENTITY_ADDR as *mut c_void,
            game_heap::havok_hooks::hook_havok_add_entity,
        )?;
        guard.enable_hook("havok_add_entity", &HAVOK_ADD_ENTITY_HOOK)?;
        log::info!("[HAVOK SYNC] addEntity hook at 0x{:08X}", HAVOK_ADD_ENTITY_ADDR);

        HAVOK_COLL_OBJ_DTOR_HOOK.init(
            "havok_coll_obj_dtor",
            HAVOK_COLL_OBJ_DTOR_ADDR as *mut c_void,
            game_heap::havok_hooks::hook_havok_coll_obj_dtor,
        )?;
        guard.enable_hook("havok_coll_obj_dtor", &HAVOK_COLL_OBJ_DTOR_HOOK)?;
        log::info!("[HAVOK SYNC] collisionObject dtor hook at 0x{:08X}", HAVOK_COLL_OBJ_DTOR_ADDR);

        HAVOK_RAYCAST_HOOK.init(
            "havok_raycast",
            HAVOK_RAYCAST_ADDR as *mut c_void,
            game_heap::havok_hooks::hook_havok_raycast,
        )?;
        guard.enable_hook("havok_raycast", &HAVOK_RAYCAST_HOOK)?;
        log::info!("[HAVOK SYNC] raycast hook at 0x{:08X}", HAVOK_RAYCAST_ADDR);
    }

    // ---- Actor process synchronization ----
    //
    // Worker threads hold game_guard read lock during AI processing.
    // actor_downgrade is pass-through (main thread, already under PDD lock).
    {
        use game_heap::statics::*;

        ACTOR_DOWNGRADE_HOOK.init(
            "actor_downgrade",
            ACTOR_DOWNGRADE_ADDR as *mut c_void,
            game_heap::actor_process_hooks::hook_actor_downgrade,
        )?;
        guard.enable_hook("actor_downgrade", &ACTOR_DOWNGRADE_HOOK)?;
        log::info!("[ACTOR SYNC] downgrade hook at 0x{:08X}", ACTOR_DOWNGRADE_ADDR);

        PROCESS_MGR_UPDATE_HOOK.init(
            "process_mgr_update",
            PROCESS_MGR_UPDATE_ADDR as *mut c_void,
            game_heap::actor_process_hooks::hook_process_mgr_update,
        )?;
        guard.enable_hook("process_mgr_update", &PROCESS_MGR_UPDATE_HOOK)?;
        log::info!("[ACTOR SYNC] process update hook at 0x{:08X}", PROCESS_MGR_UPDATE_ADDR);

        AI_PROCESS1_HOOK.init(
            "ai_process1",
            AI_PROCESS1_ADDR as *mut c_void,
            game_heap::actor_process_hooks::hook_ai_process1,
        )?;
        guard.enable_hook("ai_process1", &AI_PROCESS1_HOOK)?;
        log::info!("[ACTOR SYNC] AI process 1 hook at 0x{:08X}", AI_PROCESS1_ADDR);

        AI_PROCESS2_HOOK.init(
            "ai_process2",
            AI_PROCESS2_ADDR as *mut c_void,
            game_heap::actor_process_hooks::hook_ai_process2,
        )?;
        guard.enable_hook("ai_process2", &AI_PROCESS2_HOOK)?;
        log::info!("[ACTOR SYNC] AI process 2 hook at 0x{:08X}", AI_PROCESS2_ADDR);

        CELL_MGMT_UPDATE_HOOK.init(
            "cell_mgmt_update",
            CELL_MGMT_UPDATE_ADDR as *mut c_void,
            game_heap::actor_process_hooks::hook_cell_mgmt_update,
        )?;
        guard.enable_hook("cell_mgmt_update", &CELL_MGMT_UPDATE_HOOK)?;
        log::info!("[ACTOR SYNC] cell mgmt hook at 0x{:08X}", CELL_MGMT_UPDATE_ADDR);
    }

    // ---- CRT: malloc/calloc/realloc/recalloc/msize/free ----
    {
        use crt::*;

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

        guard.enable_hook("malloc1", &MALLOC_HOOK_1)?;
        guard.enable_hook("malloc2", &MALLOC_HOOK_2)?;
        guard.enable_hook("calloc1", &CALLOC_HOOK_1)?;
        guard.enable_hook("calloc2", &CALLOC_HOOK_2)?;
        guard.enable_hook("realloc1", &REALLOC_HOOK_1)?;
        guard.enable_hook("realloc2", &REALLOC_HOOK_2)?;
        guard.enable_hook("recalloc1", &RECALLOC_HOOK_1)?;
        guard.enable_hook("recalloc2", &RECALLOC_HOOK_2)?;
        guard.enable_hook("free", &FREE_HOOK)?;
        guard.enable_hook("msize", &MSIZE_HOOK)?;

        log::info!("[CRT] All CRT hooks initialized and enabled");
    }

    // ---- Scrap heap ----
    {
        use scrap_heap::*;

        GET_THREAD_LOCAL_HOOK.init("sheap_get_thread_local", SHEAP_GET_THREAD_LOCAL_ADDR as *mut c_void, hook_get_thread_local)?;
        INIT_FIX_HOOK.init("sheap_init_fix", SHEAP_INIT_FIX_ADDR as *mut c_void, hook_init_fix)?;
        INIT_VAR_HOOK.init("sheap_init_var", SHEAP_INIT_VAR_ADDR as *mut c_void, hook_init_var)?;
        ALLOC_HOOK.init("sheap_alloc", SHEAP_ALLOC_ADDR as *mut c_void, hook_alloc)?;
        FREE_HOOK.init("sheap_free", SHEAP_FREE_ADDR as *mut c_void, hook_free)?;
        PURGE_HOOK.init("sheap_purge", SHEAP_PURGE_ADDR as *mut c_void, hook_purge)?;

        guard.enable_hook("sheap_get_thread_local", &GET_THREAD_LOCAL_HOOK)?;
        guard.enable_hook("sheap_init_fix", &INIT_FIX_HOOK)?;
        guard.enable_hook("sheap_init_var", &INIT_VAR_HOOK)?;
        guard.enable_hook("sheap_alloc", &ALLOC_HOOK)?;
        guard.enable_hook("sheap_free", &FREE_HOOK)?;
        guard.enable_hook("sheap_purge", &PURGE_HOOK)?;

        log::info!("[SBM] All scrap heap hooks initialized and enabled");
    }

    // All hooks installed -- commit (no rollback on drop).
    guard.commit();

    // ---- SBM disable patches ----
    //
    // Applied AFTER hooks are committed. With mimalloc handling ALL
    // GameHeap allocations, the SBM is completely bypassed. Its maintenance
    // routines now operate on stale pre-hook arena state and must be disabled.
    unsafe {
        // RET patches: disable SBM functions that are pure overhead
        patch_ret(0x00AA6840 as *mut c_void)?; // SBM stats reset
        patch_ret(0x00866770 as *mut c_void)?; // SBM config table init
        patch_ret(0x00866E00 as *mut c_void)?; // SBM-related init
        patch_ret(0x00866D10 as *mut c_void)?; // Get SBM singleton
        patch_ret(0x00AA7030 as *mut c_void)?; // GlobalCleanup (shutdown only)
        patch_ret(0x00AA5C80 as *mut c_void)?; // DeallocateAllArenas (shutdown only)
        patch_ret(0x00AA58D0 as *mut c_void)?; // Sheap SBM cleanup

        // KEEP ALIVE: PurgeUnusedArenas (0x00AA6F90), DecrementArenaRef (0x00AA7290),
        // ReleaseArenaByPtr (0x00AA7300) -- pre-hook allocations need these to
        // free empty arenas back to the OS.

        // NOP patches: skip redundant heap construction/init calls
        patch_nop_call(0x0086C56F as *mut c_void)?;
        patch_nop_call(0x00C42EB1 as *mut c_void)?;
        patch_nop_call(0x00EC1701 as *mut c_void)?;

        log::info!("[SBM] Patched SBM (7 RET + 3 NOP, arena cleanup kept alive)");
    }

    log::info!("[HEAP REPLACER] All hooks and patches applied successfully");

    Ok(())
}

/// Start background threads deferred from install_game_heap_hooks()
/// because DllMain holds the Windows loader lock (thread::spawn deadlocks).
///
/// Must be called OUTSIDE DllMain, e.g. from NVSEPlugin_Load.
pub fn start_deferred_threads() {
    std::mem::forget(game_heap::monitor::Monitor::start());
    log::info!("[HEAP REPLACER] Deferred threads started");
}
