//! Heap replacer: replaces GameHeap + CRT + ScrapHeap with mimalloc.

use libc::c_void;
use std::sync::LazyLock;

use libpsycho::os::windows::winapi::{patch_nop_call, patch_ret};
use libpsycho::os::windows::{
    hook::inline::inlinehook::InlineHookContainer,
    types::{CallocFn, FreeFn, MallocFn, MsizeFn, ReallocFn, RecallocFn},
};

use super::hooks::*;
use super::types::*;

// ---------------------------------------------------------------------------
// Hook rollback guard — disables all enabled hooks on drop unless committed.
// ---------------------------------------------------------------------------

/// Type-erased disable function for any InlineHookContainer.
type DisableFn = Box<dyn Fn() + Send + Sync>;

/// Collects enabled hooks and rolls them all back if the guard is dropped
/// without calling `commit()`. Prevents split-heap corruption when a later
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

    /// Enable a hook and register it for rollback. Returns error if enable fails.
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

    /// Mark all hooks as committed — drop will NOT roll back.
    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        log::error!("[HEAP REPLACER] Rolling back {} hooks due to installation failure", self.rollbacks.len());
        for (name, disable) in self.rollbacks.iter().rev() {
            disable();
            log::warn!("[ROLLBACK] Disabled {}", name);
        }
    }
}

// CRT allocator
const CRT_MALLOC_ADDR_1: usize = 0x00ECD1C7;
const CRT_MALLOC_ADDR_2: usize = 0x00ED0CDF;
const CRT_CALLOC_ADDR_1: usize = 0x00EDDD7D;
const CRT_CALLOC_ADDR_2: usize = 0x00ED0D24;
const CRT_REALLOC_ADDR_1: usize = 0x00ECCF5D;
const CRT_REALLOC_ADDR_2: usize = 0x00ED0D70;
const CRT_RECALLOC_ADDR_1: usize = 0x00EE1700;
const CRT_RECALLOC_ADDR_2: usize = 0x00ED0DBE;
const CRT_MSIZE_ADDR: usize = 0x00ECD31F;
const CRT_FREE_ADDR: usize = 0x00ECD291;

/// Scrap heap function addresses (Fallout New Vegas)
const SHEAP_INIT_FIX_ADDR: usize = 0x00AA53F0;
const SHEAP_INIT_VAR_ADDR: usize = 0x00AA5410;
const SHEAP_ALLOC_ADDR: usize = 0x00AA54A0;
const SHEAP_FREE_ADDR: usize = 0x00AA5610;
const SHEAP_PURGE_ADDR: usize = 0x00AA5460;
const SHEAP_GET_THREAD_LOCAL_ADDR: usize = 0x00AA42E0;

// Gheap

/// Game heap function addresses (Fallout New Vegas)
const GHEAP_ALLOC_ADDR: usize = 0x00AA3E40;
const GHEAP_REALLOC_ADDR_1: usize = 0x00AA4150;
const GHEAP_REALLOC_ADDR_2: usize = 0x00AA4200;
const GHEAP_MSIZE_ADDR: usize = 0x00AA44C0;
const GHEAP_FREE_ADDR: usize = 0x00AA4060;

pub static CRT_INLINE_MALLOC_HOOK_1: LazyLock<InlineHookContainer<MallocFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static CRT_INLINE_MALLOC_HOOK_2: LazyLock<InlineHookContainer<MallocFn>> =
    LazyLock::new(InlineHookContainer::new);

pub static CRT_INLINE_CALLOC_HOOK_1: LazyLock<InlineHookContainer<CallocFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static CRT_INLINE_CALLOC_HOOK_2: LazyLock<InlineHookContainer<CallocFn>> =
    LazyLock::new(InlineHookContainer::new);

pub static CRT_INLINE_REALLOC_HOOK_1: LazyLock<InlineHookContainer<ReallocFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static CRT_INLINE_REALLOC_HOOK_2: LazyLock<InlineHookContainer<ReallocFn>> =
    LazyLock::new(InlineHookContainer::new);

pub static CRT_INLINE_RECALLOC_HOOK_1: LazyLock<InlineHookContainer<RecallocFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static CRT_INLINE_RECALLOC_HOOK_2: LazyLock<InlineHookContainer<RecallocFn>> =
    LazyLock::new(InlineHookContainer::new);

pub static CRT_INLINE_MSIZE_HOOK: LazyLock<InlineHookContainer<MsizeFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static CRT_INLINE_FREE_HOOK: LazyLock<InlineHookContainer<FreeFn>> =
    LazyLock::new(InlineHookContainer::new);

// Gheap
pub static GHEAP_MSIZE_HOOK: LazyLock<InlineHookContainer<GameHeapMsizeFn>> =
    LazyLock::new(InlineHookContainer::new);

pub static GHEAP_ALLOC_HOOK: LazyLock<InlineHookContainer<GameHeapAllocateFn>> =
    LazyLock::new(InlineHookContainer::new);

pub static GHEAP_FREE_HOOK: LazyLock<InlineHookContainer<GameHeapFreeFn>> =
    LazyLock::new(InlineHookContainer::new);

pub static GHEAP_REALLOC_HOOK_1: LazyLock<InlineHookContainer<GameHeapReallocateFn>> =
    LazyLock::new(InlineHookContainer::new);

pub static GHEAP_REALLOC_HOOK_2: LazyLock<InlineHookContainer<GameHeapReallocateFn>> =
    LazyLock::new(InlineHookContainer::new);

// Main loop hook for pressure relief.
// FUN_008705d0: the render/update function, called at main loop line 486.
// We hook it to run pressure relief AFTER the render completes (post-render).
// After the original function returns, the render pipeline is done with all
// scene graph data (BSTreeNodes, NiTriShapes, etc.) — safe to unload cells.
//
// Previous hook positions and why they failed:
// - FUN_0086f940 (line 273, pre-AI): Trees freed before render → BSTreeNode crash
// - FUN_0086ff70 (line 485, pre-render): Same issue, render uses cached tree lists
// - FUN_008705d0 (line 486, POST-render): Render done, tree lists consumed → SAFE
const MAIN_LOOP_MAINTENANCE_ADDR: usize = 0x008705D0;

// Per-frame queue processor (FUN_00868850).
// Runs at main loop line ~802, BEFORE AI dispatch (line ~855) and render (line ~904).
// Processes deferred destruction queues with limited batch sizes (10-20 items).
// We hook this to boost NiNode (queue 0x08) drain rate under memory pressure.
const PER_FRAME_QUEUE_DRAIN_ADDR: usize = 0x00868850;

// CellTransitionHandler (FUN_008774a0).
// ENGINE BUG FIX: wraps the game's own cell transition with hkWorld_Lock
// to prevent AI thread physics crashes during BLOCKING PDD.
const CELL_TRANSITION_HANDLER_ADDR: usize = 0x008774A0;

pub static MAIN_LOOP_MAINTENANCE_HOOK: LazyLock<InlineHookContainer<MainLoopMaintenanceFn>> =
    LazyLock::new(InlineHookContainer::new);

pub static PER_FRAME_QUEUE_DRAIN_HOOK: LazyLock<InlineHookContainer<PerFrameQueueDrainFn>> =
    LazyLock::new(InlineHookContainer::new);

pub static CELL_TRANSITION_HANDLER_HOOK: LazyLock<InlineHookContainer<CellTransitionHandlerFn>> =
    LazyLock::new(InlineHookContainer::new);

/// Scrap heap hooks
pub static SHEAP_INIT_FIX_HOOK: LazyLock<InlineHookContainer<SheapInitFixFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static SHEAP_INIT_VAR_HOOK: LazyLock<InlineHookContainer<SheapInitVarFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static SHEAP_ALLOC_HOOK: LazyLock<InlineHookContainer<SheapAllocFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static SHEAP_FREE_HOOK: LazyLock<InlineHookContainer<SheapFreeFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static SHEAP_PURGE_HOOK: LazyLock<InlineHookContainer<SheapPurgeFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static SHEAP_GET_THREAD_LOCAL_HOOK: LazyLock<InlineHookContainer<SheapGetThreadLocalFn>> =
    LazyLock::new(InlineHookContainer::new);

/// Applies patches and installs heap replacement hooks.
/// mimalloc is already configured by the time this runs (mod.rs configure_mimalloc).
pub fn install_game_heap_hooks() -> anyhow::Result<()> {
    // Initialize heap validation cache for routing pre-hook pointers
    // (allocated by the original GameHeap before our hooks were installed).
    super::heap_validate::init_heap_cache();

    // Initialize memory pressure relief (triggers LazyLock construction + logging).
    // Returns None if game function pointers are invalid — logged internally.
    super::gheap::pressure::PressureRelief::instance();

    // NOTE: Monitor thread is NOT started here — DllMain holds the Windows
    // loader lock, and thread::spawn can deadlock under loader lock.
    // Call start_deferred_threads() from NVSEPlugin_Load instead.

    // ===========================
    //   HOOKS (with rollback guard)
    // ===========================
    //
    // All hooks are enabled through HookGuard. If ANY enable fails, all
    // previously-enabled hooks are rolled back (disabled) to prevent
    // split-heap corruption (e.g. alloc→mimalloc but free→original).

    let mut guard = HookGuard::new();

    // GHEAP hooks: fully replace GameHeap::Allocate/Free/Msize with mimalloc.
    // This eliminates the game's heap accounting, SBM, and 500MB budget.
    // Pre-hook allocations are handled via original trampoline + HeapValidate.
    {
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

        GHEAP_REALLOC_HOOK_1.init(
            "gheap_realloc1",
            GHEAP_REALLOC_ADDR_1 as *mut c_void,
            hook_gheap_realloc,
        )?;
        GHEAP_REALLOC_HOOK_2.init(
            "gheap_realloc2",
            GHEAP_REALLOC_ADDR_2 as *mut c_void,
            hook_gheap_realloc,
        )?;

        guard.enable_hook("gheap_alloc", &GHEAP_ALLOC_HOOK)?;
        guard.enable_hook("gheap_free", &GHEAP_FREE_HOOK)?;
        guard.enable_hook("gheap_msize", &GHEAP_MSIZE_HOOK)?;
        guard.enable_hook("gheap_realloc1", &GHEAP_REALLOC_HOOK_1)?;
        guard.enable_hook("gheap_realloc2", &GHEAP_REALLOC_HOOK_2)?;

        log::info!("[GHEAP] GameHeap fully replaced with mimalloc (alloc/free/realloc/msize)");
    }

    // Main-loop hook for deferred pressure relief (runs between frames, safe context)
    {
        MAIN_LOOP_MAINTENANCE_HOOK.init(
            "main_loop_maintenance",
            MAIN_LOOP_MAINTENANCE_ADDR as *mut c_void,
            hook_main_loop_maintenance,
        )?;
        guard.enable_hook("main_loop_maintenance", &MAIN_LOOP_MAINTENANCE_HOOK)?;
        log::info!("[PRESSURE] Post-render hook installed at 0x{:08X}", MAIN_LOOP_MAINTENANCE_ADDR);
    }

    // Per-frame queue drain hook: boosts NiNode drain rate under pressure.
    // FUN_00868850 runs every frame pre-AI, pre-render. It drains 10-20 NiNodes
    // per call. Under pressure we call it additional times to drain faster.
    {
        PER_FRAME_QUEUE_DRAIN_HOOK.init(
            "per_frame_queue_drain",
            PER_FRAME_QUEUE_DRAIN_ADDR as *mut c_void,
            hook_per_frame_queue_drain,
        )?;
        guard.enable_hook("per_frame_queue_drain", &PER_FRAME_QUEUE_DRAIN_HOOK)?;
        log::info!("[PRESSURE] Per-frame queue drain hook installed at 0x{:08X}", PER_FRAME_QUEUE_DRAIN_ADDR);
    }

    // ENGINE BUG FIX: CellTransitionHandler does BLOCKING PDD without
    // hkWorld_Lock. AI threads from previous frame's post-render signal
    // crash on freed hkpSimulationIsland data. We wrap it with the same
    // protections used by the 5 normal PDD callers.
    {
        CELL_TRANSITION_HANDLER_HOOK.init(
            "cell_transition_handler",
            CELL_TRANSITION_HANDLER_ADDR as *mut c_void,
            hook_cell_transition_handler,
        )?;
        guard.enable_hook("cell_transition_handler", &CELL_TRANSITION_HANDLER_HOOK)?;
        log::info!("[ENGINE FIX] CellTransitionHandler hook installed at 0x{:08X}", CELL_TRANSITION_HANDLER_ADDR);
    }

    {
        CRT_INLINE_MALLOC_HOOK_1.init("malloc1", CRT_MALLOC_ADDR_1 as *mut c_void, hook_malloc)?;
        CRT_INLINE_MALLOC_HOOK_2.init("malloc2", CRT_MALLOC_ADDR_2 as *mut c_void, hook_malloc)?;

        CRT_INLINE_CALLOC_HOOK_1.init("calloc1", CRT_CALLOC_ADDR_1 as *mut c_void, hook_calloc)?;
        CRT_INLINE_CALLOC_HOOK_2.init("calloc2", CRT_CALLOC_ADDR_2 as *mut c_void, hook_calloc)?;

        CRT_INLINE_REALLOC_HOOK_1.init(
            "realloc1",
            CRT_REALLOC_ADDR_1 as *mut c_void,
            hook_realloc,
        )?;
        CRT_INLINE_REALLOC_HOOK_2.init(
            "realloc2",
            CRT_REALLOC_ADDR_2 as *mut c_void,
            hook_realloc,
        )?;

        CRT_INLINE_RECALLOC_HOOK_1.init(
            "recalloc1",
            CRT_RECALLOC_ADDR_1 as *mut c_void,
            hook_recalloc,
        )?;
        CRT_INLINE_RECALLOC_HOOK_2.init(
            "recalloc2",
            CRT_RECALLOC_ADDR_2 as *mut c_void,
            hook_recalloc,
        )?;
        CRT_INLINE_FREE_HOOK.init("free", CRT_FREE_ADDR as *mut c_void, hook_free)?;
        CRT_INLINE_MSIZE_HOOK.init("msize", CRT_MSIZE_ADDR as *mut c_void, hook_msize)?;

        guard.enable_hook("malloc1", &CRT_INLINE_MALLOC_HOOK_1)?;
        guard.enable_hook("malloc2", &CRT_INLINE_MALLOC_HOOK_2)?;
        guard.enable_hook("calloc1", &CRT_INLINE_CALLOC_HOOK_1)?;
        guard.enable_hook("calloc2", &CRT_INLINE_CALLOC_HOOK_2)?;
        guard.enable_hook("realloc1", &CRT_INLINE_REALLOC_HOOK_1)?;
        guard.enable_hook("realloc2", &CRT_INLINE_REALLOC_HOOK_2)?;
        guard.enable_hook("recalloc1", &CRT_INLINE_RECALLOC_HOOK_1)?;
        guard.enable_hook("recalloc2", &CRT_INLINE_RECALLOC_HOOK_2)?;
        guard.enable_hook("free", &CRT_INLINE_FREE_HOOK)?;
        guard.enable_hook("msize", &CRT_INLINE_MSIZE_HOOK)?;

        log::info!("[INLINE] All CRT hooks initialized and enabled!");
    }

    // Initialize and enable sheap inline hooks
    {
        SHEAP_GET_THREAD_LOCAL_HOOK.init(
            "sheap_get_thread_local",
            SHEAP_GET_THREAD_LOCAL_ADDR as *mut c_void,
            sheap_get_thread_local,
        )?;

        SHEAP_INIT_FIX_HOOK.init(
            "sheap_init_fix",
            SHEAP_INIT_FIX_ADDR as *mut c_void,
            sheap_init_fix,
        )?;

        SHEAP_INIT_VAR_HOOK.init(
            "sheap_init_var",
            SHEAP_INIT_VAR_ADDR as *mut c_void,
            sheap_init_var,
        )?;

        SHEAP_ALLOC_HOOK.init("sheap_alloc", SHEAP_ALLOC_ADDR as *mut c_void, sheap_alloc)?;
        SHEAP_FREE_HOOK.init("sheap_free", SHEAP_FREE_ADDR as *mut c_void, sheap_free)?;
        SHEAP_PURGE_HOOK.init("sheap_purge", SHEAP_PURGE_ADDR as *mut c_void, sheap_purge)?;

        guard.enable_hook("sheap_get_thread_local", &SHEAP_GET_THREAD_LOCAL_HOOK)?;
        guard.enable_hook("sheap_init_fix", &SHEAP_INIT_FIX_HOOK)?;
        guard.enable_hook("sheap_init_var", &SHEAP_INIT_VAR_HOOK)?;
        guard.enable_hook("sheap_alloc", &SHEAP_ALLOC_HOOK)?;
        guard.enable_hook("sheap_free", &SHEAP_FREE_HOOK)?;
        guard.enable_hook("sheap_purge", &SHEAP_PURGE_HOOK)?;
    }

    // All hooks installed successfully — commit the guard (no rollback on drop).
    guard.commit();

    // ===========================
    //   SBM DISABLE PATCHES
    // ===========================
    //
    // Applied AFTER all hooks are committed. If hooks failed, the guard would
    // have rolled them back and returned Err before reaching this point.
    // Disabling SBM without active hooks would leave the heap in a split state.
    //
    // With mimalloc handling ALL GameHeap allocations, the SBM is completely
    // bypassed for new allocations. Its maintenance routines now operate on
    // stale pre-hook arena state -- purging, cleanup, and refcount ops on
    // arenas that mimalloc doesn't manage. This causes crashes and wastes CPU.
    //
    // NOTE: Earlier testing found 0x00AA7030/0x00AA5C80 RET patches caused
    // "heap fills to 98%" -- but that was when we USED the original GameHeap.
    // Now mimalloc owns everything, so there's nothing to compact. Disabling
    // these prevents stale arena corruption.
    unsafe {
        // --- RET patches: disable SBM functions that are pure overhead ---

        // SBM statistics/global state reset -- just resets counters
        patch_ret(0x00AA6840 as *mut c_void)?;
        // SBM config table init -- unused with mimalloc ownership
        patch_ret(0x00866770 as *mut c_void)?;
        // SBM-related init
        patch_ret(0x00866E00 as *mut c_void)?;
        // Get SBM singleton -- callers are sheap ops, all hooked by our Runtime
        patch_ret(0x00866D10 as *mut c_void)?;
        // GlobalCleanup -- shutdown only, process frees everything
        patch_ret(0x00AA7030 as *mut c_void)?;
        // DeallocateAllArenas -- bulk deallocation, only on shutdown
        patch_ret(0x00AA5C80 as *mut c_void)?;
        // Sheap SBM cleanup -- sheap fully hooked via Runtime
        patch_ret(0x00AA58D0 as *mut c_void)?;

        // --- KEEP ALIVE: SBM arena cleanup functions ---
        // Pre-hook allocations are freed via original trampoline -> SBM arenas
        // empty out over time. These functions MUST work so empty arenas get
        // released back to the OS, freeing committed memory.
        //
        // NOT patched (left functional):
        //   0x00AA6F90 -- PurgeUnusedArenas (frees empty arenas)
        //   0x00AA7290 -- DecrementArenaRef (tracks arena occupancy)
        //   0x00AA7300 -- ReleaseArenaByPtr (releases individual arenas)

        // --- Main loop: KEEP SBM maintenance running ---
        // The main loop maintenance block calls PurgeUnusedArenas.
        // We NEED this to run so empty SBM arenas are periodically freed.
        // Previously we JMP'd over it (0x0086EED4) -- now we let it execute.

        // Heap construction double-check -- safe to skip
        patch_nop_call(0x0086C56F as *mut c_void)?;
        // CRT heap init calls -- safe to skip
        patch_nop_call(0x00C42EB1 as *mut c_void)?;
        patch_nop_call(0x00EC1701 as *mut c_void)?;

        log::info!("[SBM] Patched SBM (10 patches: 7 RET + 3 NOP, arena cleanup kept alive)");
    }

    log::info!("[HEAP REPLACER] All hooks and patches applied successfully");

    Ok(())
}

/// Start background threads that were deferred from `install_game_heap_hooks()`
/// because DllMain holds the Windows loader lock (thread::spawn can deadlock).
///
/// Must be called OUTSIDE DllMain — e.g. from NVSEPlugin_Load.
pub fn start_deferred_threads() {
    // Monitor thread (mimalloc stats + pressure logging).
    // Leaked intentionally — runs for the entire process lifetime.
    std::mem::forget(super::gheap::monitor::Monitor::start());
    log::info!("[HEAP REPLACER] Deferred threads started");
}
