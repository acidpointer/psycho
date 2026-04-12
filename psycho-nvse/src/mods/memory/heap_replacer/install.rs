//! Hook installation orchestrator.
//!
//! Initializes and enables all heap replacement hooks in a single
//! transaction. If any hook fails to install, all previously-enabled
//! hooks are rolled back to prevent split-heap corruption.

use libc::c_void;
use std::sync::LazyLock;

use libpsycho::os::windows::winapi::{patch_bytes, patch_nop_call, patch_ret};
use libpsycho::os::windows::hook::inline::inlinehook::InlineHookContainer;

use super::{crt, gheap, scrap_heap};

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
/// Walk the SBM pool table and decommit arena pages with zero live blocks.
/// Must be called BEFORE hooks are installed (SBM state is fully consistent).
///
/// The SBM tracks per-page reference counts (i16 array at pool+0x48).
/// Pages with refcount == 0 have no live allocations and can be safely
/// decommitted. The VAS reservation stays (ptr>>24 free path still works).
fn cleanup_sbm_arenas() {
    use windows::Win32::System::Memory::{MEM_DECOMMIT, VirtualFree};

    let pool_table = gheap::engine::addr::SBM_POOL_TABLE;
    let mut total_pages: usize = 0;
    let mut decommitted_pages: usize = 0;
    let mut pools_found: usize = 0;

    for slot in 0..256usize {
        let pool_ptr = unsafe { *((pool_table + slot * 4) as *const usize) };
        if pool_ptr == 0 {
            continue;
        }
        pools_found += 1;

        let arena_base = unsafe { *((pool_ptr + 0x04) as *const usize) };
        let refcounts_ptr = unsafe { *((pool_ptr + 0x48) as *const usize) };
        let page_count = unsafe { *((pool_ptr + 0x4C) as *const u32) } as usize;

        if arena_base == 0 || refcounts_ptr == 0 || page_count == 0 {
            continue;
        }

        for page_idx in 0..page_count {
            total_pages += 1;
            let refcount = unsafe { *((refcounts_ptr + page_idx * 2) as *const i16) };
            if refcount == 0 {
                let page_addr = arena_base + page_idx * 0x1000;
                let ok = unsafe {
                    VirtualFree(page_addr as *mut c_void, 0x1000, MEM_DECOMMIT)
                };
                if ok.is_ok() {
                    decommitted_pages += 1;
                }
            }
        }
    }

    let freed_mb = (decommitted_pages * 0x1000) / 1024 / 1024;
    log::debug!(
        "[SBM] Arena cleanup: {} pools, {} total pages, {} decommitted ({}MB freed)",
        pools_found, total_pages, decommitted_pages, freed_mb,
    );
}

pub fn install_game_heap_hooks() -> anyhow::Result<()> {
    // Initialize slab allocator (reserves VAS for all arenas).
    // Must be done before hooks are enabled so the slab is ready to serve allocs.
    if !gheap::slab::init() {
        log::error!("[SLAB] Failed to initialize slab allocator!");
        return Err(anyhow::anyhow!("Slab allocator initialization failed"));
    }

    gheap::crash_diag::install();

    // Main thread detection uses OS thread ID comparison (is_main_thread_by_tid).
    // Always correct -- no initialization needed. Before TES object is available,
    // returns false --> frees go to mi_free directly (safe, zero quarantine).

    // Clean up SBM arena pages with zero live blocks BEFORE installing hooks.
    // At this point the SBM is fully operational and its page refcounts are
    // accurate. Decommitting empty pages returns pre-plugin committed memory
    // to the OS while keeping VAS reservations intact (ptr>>24 free path).
    cleanup_sbm_arenas();

    // Initialize heap validation cache for routing pre-hook pointers.
    super::heap_validate::init_heap_cache();

    // Main thread ID is set from on_pre_ai (first frame tick) -- the ONE
    // place we're 100% certain is the game's main thread. NOT here,
    // because install may run on a loader thread.

    // Initialize memory pressure relief (triggers LazyLock construction).
    gheap::pressure::PressureRelief::instance();

    let mut guard = HookGuard::new();

    // ---- Game heap: replace GameHeap::Allocate/Free/Msize/Realloc ----
    //
    // Routes through gheap::allocator which uses deferred-free GC.
    // Main-thread frees go to a pending buffer; background GC thread
    // calls mi_free after N frames. Workers call mi_free directly.
    {
        use gheap::statics::*;
        use gheap::hooks::*;

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

        log::info!("[GHEAP] GameHeap replaced with mimalloc + deferred-free GC");
    }

    // ---- Main loop: post-render pressure relief ----
    {
        use gheap::statics::*;

        MAIN_LOOP_MAINTENANCE_HOOK.init(
            "main_loop_maintenance",
            MAIN_LOOP_MAINTENANCE_ADDR as *mut c_void,
            gheap::hooks::hook_main_loop_maintenance,
        )?;
        guard.enable_hook("main_loop_maintenance", &MAIN_LOOP_MAINTENANCE_HOOK)?;
        log::info!("[PRESSURE] Post-render hook at 0x{:08X}", MAIN_LOOP_MAINTENANCE_ADDR);
    }

    // ---- Per-frame queue drain: deferred-free frame tick + PDD boost ----
    {
        use gheap::statics::*;

        PER_FRAME_QUEUE_DRAIN_HOOK.init(
            "per_frame_queue_drain",
            PER_FRAME_QUEUE_DRAIN_ADDR as *mut c_void,
            gheap::hooks::hook_per_frame_queue_drain,
        )?;
        guard.enable_hook("per_frame_queue_drain", &PER_FRAME_QUEUE_DRAIN_HOOK)?;
        log::info!("[GC] Per-frame tick hook at 0x{:08X}", PER_FRAME_QUEUE_DRAIN_ADDR);
    }

    // NOTE: CellTransitionHandler (FUN_008774a0) is NOT hooked.
    // The original already calls FUN_008324e0(0) which stops Havok simulation
    // and drains all AI task queues BEFORE running PDD. Adding hkWorld_Lock
    // before the original causes deadlock: AI threads can't finish their
    // current physics work because they need Havok world access, but we hold
    // the lock. The loading state counter is also redundant -- cell transitions
    // run during loading screens where DAT_01202d6c is already > 0.

    // NOTE: IOManager Phase 3 (FUN_00c3dbf0) is NOT hooked.
    // IOManager and PDD are both on the main thread -- read lock on IOManager
    // deadlocks when task processing internally triggers PDD (write lock).
    // Same-thread read + write = deadlock. BSTaskManagerThread frees go
    // directly to mi_free (no write lock), so no cross-thread protection needed.

    // ---- AI thread synchronization: set/clear AI_ACTIVE flag ----
    {
        use gheap::statics::*;

        AI_THREAD_START_HOOK.init(
            "ai_thread_start",
            AI_THREAD_START_ADDR as *mut c_void,
            gheap::hooks::hook_ai_thread_start,
        )?;
        guard.enable_hook("ai_thread_start", &AI_THREAD_START_HOOK)?;

        AI_THREAD_JOIN_HOOK.init(
            "ai_thread_join",
            AI_THREAD_JOIN_ADDR as *mut c_void,
            gheap::hooks::hook_ai_thread_join,
        )?;
        guard.enable_hook("ai_thread_join", &AI_THREAD_JOIN_HOOK)?;
        log::info!("[SYNC] AI start/join hooks installed");
    }

    // ---- PDD: destruction guard around ProcessDeferredDestruction ----
    {
        use gheap::statics::*;

        PDD_HOOK.init(
            "pdd",
            PDD_ADDR as *mut c_void,
            gheap::pdd_hook::hook_pdd,
        )?;
        guard.enable_hook("pdd", &PDD_HOOK)?;
        log::info!("[SYNC] PDD hook installed at 0x{:08X}", PDD_ADDR);
    }

    // ---- Texture cache: dead set hooks ----
    {
        use gheap::statics::*;

        TEXTURE_CACHE_FIND_HOOK.init(
            "texture_cache_find",
            TEXTURE_CACHE_FIND_ADDR as *mut c_void,
            gheap::texture_cache::hook_texture_cache_find,
        )?;
        guard.enable_hook("texture_cache_find", &TEXTURE_CACHE_FIND_HOOK)?;

        NISOURCETEXTURE_DTOR_HOOK.init(
            "nisourcetexture_dtor",
            NISOURCETEXTURE_DTOR_ADDR as *mut c_void,
            gheap::texture_cache::hook_nisourcetexture_dtor,
        )?;
        guard.enable_hook("nisourcetexture_dtor", &NISOURCETEXTURE_DTOR_HOOK)?;
        log::info!(
            "[TEXTURE] Dead set hooks installed (find=0x{:08X}, dtor=0x{:08X})",
            TEXTURE_CACHE_FIND_ADDR, NISOURCETEXTURE_DTOR_ADDR,
        );
    }

    // ---- IO task release + Skeleton update: DISABLED ----
    //
    // With GC deferred-free (N=5 frame survival), freed memory stays
    // allocated in mimalloc for ~83ms. These hooks validated vtable/refcount
    // before accessing freed objects. Now unnecessary -- objects are valid
    // for 5 full frames, longer than any BST task or AI physics update.
    // Removing these eliminates per-call try_read atomic overhead on worker
    // threads (thousands of calls per frame).

    // ---- Queued reference processing ----
    //
    // HAVOK_DEATH filter was removed previously. With deferred-free GC,
    // freed Havok data stays readable for N frames. No filter needed.
    log::info!("[ENGINE FIX] Queued ref: deferred-free GC protects stale reads");

    // ---- Havok broadphase + actor process hooks: REMOVED ----
    //
    // These 8 hooks wrapped game functions with game_guard::try_read to
    // block during quarantine drain. With GC-based deferred free, freed
    // memory survives N frames as zombies. No main-thread mi_free burst
    // means no concurrent recycling while workers read. Hooks unnecessary.
    //
    // Removing them recovers ~1-2ms/frame of worker thread overhead
    // (thousands of try_read atomic operations per frame).

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

        // sheap_get_thread_local is optional -- another mod may have already
        // hooked 0xAA42E0 (e.g. Heap Replacer), leaving only a JMP that's
        // too short for our inline hook. Non-critical: scrap heap works
        // without this hook, it just uses the game's original TLS lookup.
        let sheap_tls_ok = GET_THREAD_LOCAL_HOOK.init("sheap_get_thread_local", SHEAP_GET_THREAD_LOCAL_ADDR as *mut c_void, hook_get_thread_local).is_ok();
        if !sheap_tls_ok {
            log::warn!("[SBM] sheap_get_thread_local hook skipped (already patched by another mod?)");
        }
        INIT_FIX_HOOK.init("sheap_init_fix", SHEAP_INIT_FIX_ADDR as *mut c_void, hook_init_fix)?;
        INIT_VAR_HOOK.init("sheap_init_var", SHEAP_INIT_VAR_ADDR as *mut c_void, hook_init_var)?;
        ALLOC_HOOK.init("sheap_alloc", SHEAP_ALLOC_ADDR as *mut c_void, hook_alloc)?;
        FREE_HOOK.init("sheap_free", SHEAP_FREE_ADDR as *mut c_void, hook_free)?;
        PURGE_HOOK.init("sheap_purge", SHEAP_PURGE_ADDR as *mut c_void, hook_purge)?;

        if sheap_tls_ok {
            guard.enable_hook("sheap_get_thread_local", &GET_THREAD_LOCAL_HOOK)?;
        }
        guard.enable_hook("sheap_init_fix", &INIT_FIX_HOOK)?;
        guard.enable_hook("sheap_init_var", &INIT_VAR_HOOK)?;
        guard.enable_hook("sheap_alloc", &ALLOC_HOOK)?;
        guard.enable_hook("sheap_free", &FREE_HOOK)?;
        guard.enable_hook("sheap_purge", &PURGE_HOOK)?;

        log::info!("[SBM] All scrap heap hooks initialized and enabled");
    }

    // ---- Havok world synchronization ----
    //
    // Hooks hkWorld_Lock/Unlock to track when Havok physics is stepping.
    // This allows cell unload to wait for physics to complete before
    // destroying physics objects, preventing AI thread crashes on freed data.
    {
        use super::gheap::statics::*;
        use super::gheap::hooks::{hook_hkworld_lock, hook_hkworld_unlock};

        HKWORLD_LOCK_HOOK.init("hkworld_lock", HKWORLD_LOCK_ADDR as *mut c_void, hook_hkworld_lock)?;
        HKWORLD_UNLOCK_HOOK.init("hkworld_unlock", HKWORLD_UNLOCK_ADDR as *mut c_void, hook_hkworld_unlock)?;

        guard.enable_hook("hkworld_lock", &HKWORLD_LOCK_HOOK)?;
        guard.enable_hook("hkworld_unlock", &HKWORLD_UNLOCK_HOOK)?;

        log::info!(
            "[HAVOK] World lock hooks installed (lock=0x{:08X}, unlock=0x{:08X})",
            HKWORLD_LOCK_ADDR, HKWORLD_UNLOCK_ADDR
        );
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

        // SBM arena management -- patch to ret.
        //
        // Explanation:
        //   - PurgeUnusedArenas (0xAA6F90): only called from GlobalCleanup
        //     (0xAA7030) which is already ret-patched. Dead code.
        //   - DecrementArenaRef (0xAA7290) / ReleaseArenaByPtr (0xAA7300):
        //     decrement arena refcounts, but the consumers of those
        //     refcounts (GlobalCleanup, DeallocAllArenas) are ret-patched.
        //     The bookkeeping is never consumed.
        // Keeping them alive just iterates stale SBM data structures
        // during pre-hook frees, for no benefit.
        patch_ret(0x00AA6F90 as *mut c_void)?; // PurgeUnusedArenas
        patch_ret(0x00AA7290 as *mut c_void)?; // DecrementArenaRef
        patch_ret(0x00AA7300 as *mut c_void)?; // ReleaseArenaByPtr

        // Disable SBM small alloc fast path flag (FUN_00aa3e40 offset 0x129).
        //
        // NOTE: Our inline hook at FUN_00aa3e40 entry already bypasses the
        // fast path (JMP at function entry --> our hook). This flag clear is
        // belt-and-suspenders for any code that reads the flag directly.
        let fast_path_flag = (gheap::engine::addr::HEAP_SINGLETON + 0x129) as *mut u8;
        fast_path_flag.write_volatile(0);
        log::info!(
            "[SBM] Disabled small alloc fast path flag at 0x{:08X}",
            gheap::engine::addr::HEAP_SINGLETON + 0x129,
        );

        // NOP patches: skip redundant heap construction/init calls
        patch_nop_call(0x0086C56F as *mut c_void)?;
        patch_nop_call(0x00C42EB1 as *mut c_void)?;
        patch_nop_call(0x00EC1701 as *mut c_void)?;

        // Skip per-frame SBM arena management in main loop.
        //
        // At 0x0086EED4 (in the per-frame function FUN_0086e650), the game
        // cycles through 256 SBM pool slots, calling FUN_00aa7290
        // (DecrementArenaRef) once per frame with a rotating index:
        //
        //   if (condition || timer_elapsed) {
        //       timer = 0;
        //       FUN_00aa7290(index++);      // SBM arena refcount decrement
        //       if (index == 256) index = 0;
        //   }
        //
        // We ret-patched FUN_00aa7290, so the call is a no-op. But the
        // condition check, timer accumulation, and index rotation still run
        // on stale SBM state every frame. NVHR skips this entire block
        // with a JMP +0x55 (EB 55). Match that.
        patch_bytes(0x0086EED4 as *mut c_void, &[0xEB, 0x55])?;

        log::info!("[SBM] Patched SBM (10 RET + 3 NOP + 1 JMP + fast path disabled)");
    }

    log::info!("[HEAP REPLACER] All hooks and patches applied successfully");

    Ok(())
}

/// Start background threads deferred from install_game_heap_hooks()
/// because DllMain holds the Windows loader lock (thread::spawn deadlocks).
///
/// Must be called OUTSIDE DllMain, e.g. from NVSEPlugin_Load.
pub fn start_deferred_threads() {
    // NOTE: Large allocation pool reservation DISABLED — causes VAS pressure
    // during startup. Large allocations use individual VirtualAlloc instead,
    // which returns pages to OS immediately via VirtualFree(MEM_RELEASE).
    // This avoids VAS fragmentation from scattered allocations while
    // keeping startup memory footprint minimal.

    std::mem::forget(gheap::watchdog::Watchdog::start());
    log::info!("[HEAP REPLACER] Watchdog thread started");
}
