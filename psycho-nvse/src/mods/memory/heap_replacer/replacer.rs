//! Heap replacer mod

use libc::c_void;
use std::sync::LazyLock;

use libpsycho::os::windows::winapi::{patch_bytes, patch_nop_call};
use libpsycho::os::windows::winapi::{patch_memory_nop, patch_ret};
use libpsycho::os::windows::{
    hook::inline::inlinehook::InlineHookContainer,
    types::{CallocFn, FreeFn, MallocFn, MsizeFn, ReallocFn, RecallocFn},
};

use super::hooks::*;
use super::types::*;

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

    // ===========================
    //   SBM DISABLE PATCHES
    // ===========================
    //
    // With mimalloc handling ALL GameHeap allocations, the SBM is completely
    // bypassed for new allocations. Its maintenance routines now operate on
    // stale pre-hook arena state — purging, cleanup, and refcount ops on
    // arenas that mimalloc doesn't manage. This causes crashes and wastes CPU.
    //
    // NOTE: Earlier testing found 0x00AA7030/0x00AA5C80 RET patches caused
    // "heap fills to 98%" — but that was when we USED the original GameHeap.
    // Now mimalloc owns everything, so there's nothing to compact. Disabling
    // these prevents stale arena corruption.
    unsafe {
        // --- RET patches: SBM functions return immediately ---

        // SBM statistics/global state reset — just resets counters
        patch_ret(0x00AA6840 as *mut c_void)?;
        // --- RET patches: disable SBM functions that are pure overhead ---
        // Statistics/global state reset — just resets counters
        patch_ret(0x00AA6840 as *mut c_void)?;
        // SBM config table init — unused with mimalloc ownership
        patch_ret(0x00866770 as *mut c_void)?;
        // SBM-related init
        patch_ret(0x00866E00 as *mut c_void)?;
        // Get SBM singleton — callers are sheap ops, all hooked by our Runtime
        patch_ret(0x00866D10 as *mut c_void)?;
        // GlobalCleanup — shutdown only, process frees everything
        patch_ret(0x00AA7030 as *mut c_void)?;
        // DeallocateAllArenas — bulk deallocation, only on shutdown
        patch_ret(0x00AA5C80 as *mut c_void)?;
        // Sheap SBM cleanup — sheap fully hooked via Runtime
        patch_ret(0x00AA58D0 as *mut c_void)?;

        // --- KEEP ALIVE: SBM arena cleanup functions ---
        // Pre-hook allocations are freed via original trampoline → SBM arenas
        // empty out over time. These functions MUST work so empty arenas get
        // released back to the OS, freeing committed memory.
        //
        // NOT patched (left functional):
        //   0x00AA6F90 — PurgeUnusedArenas (frees empty arenas)
        //   0x00AA7290 — DecrementArenaRef (tracks arena occupancy)
        //   0x00AA7300 — ReleaseArenaByPtr (releases individual arenas)

        // --- Main loop: KEEP SBM maintenance running ---
        // The main loop maintenance block calls PurgeUnusedArenas.
        // We NEED this to run so empty SBM arenas are periodically freed.
        // Previously we JMP'd over it (0x0086EED4) — now we let it execute.

        // Heap construction double-check — safe to skip
        patch_nop_call(0x0086C56F as *mut c_void)?;
        // CRT heap init calls — safe to skip
        patch_nop_call(0x00C42EB1 as *mut c_void)?;
        patch_nop_call(0x00EC1701 as *mut c_void)?;

        log::info!("[SBM] Patched SBM (10 patches: 7 RET + 3 NOP, arena cleanup kept alive)");
    }

    // ===========================
    //   HOOKS
    // ===========================

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

        GHEAP_ALLOC_HOOK.enable()?;
        GHEAP_FREE_HOOK.enable()?;
        GHEAP_MSIZE_HOOK.enable()?;
        GHEAP_REALLOC_HOOK_1.enable()?;
        GHEAP_REALLOC_HOOK_2.enable()?;

        log::info!("[GHEAP] GameHeap fully replaced with mimalloc (alloc/free/realloc/msize)");
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

        CRT_INLINE_MALLOC_HOOK_1.enable()?;
        CRT_INLINE_MALLOC_HOOK_2.enable()?;
        CRT_INLINE_CALLOC_HOOK_1.enable()?;
        CRT_INLINE_CALLOC_HOOK_2.enable()?;
        CRT_INLINE_REALLOC_HOOK_1.enable()?;
        CRT_INLINE_REALLOC_HOOK_2.enable()?;
        CRT_INLINE_RECALLOC_HOOK_1.enable()?;
        CRT_INLINE_RECALLOC_HOOK_2.enable()?;
        CRT_INLINE_FREE_HOOK.enable()?;
        CRT_INLINE_MSIZE_HOOK.enable()?;

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

        // Enable sheap hooks
        SHEAP_GET_THREAD_LOCAL_HOOK.enable()?;
        SHEAP_INIT_FIX_HOOK.enable()?;
        SHEAP_INIT_VAR_HOOK.enable()?;
        SHEAP_ALLOC_HOOK.enable()?;
        SHEAP_FREE_HOOK.enable()?;
        SHEAP_PURGE_HOOK.enable()?;
    }

    log::info!("[HEAP REPLACER] All hooks and patches applied successfully");

    // Spawn background thread to log memory stats every 30 seconds.
    // This gives us clear visibility into memory growth patterns.
    std::thread::Builder::new()
        .name("psycho-mem-stats".into())
        .spawn(|| {
            use libmimalloc::{mi_collect, process_info::MiMallocProcessInfo};

            // Wait for game to fully load before first report
            std::thread::sleep(std::time::Duration::from_secs(30));

            loop {
                let info = MiMallocProcessInfo::get();
                log::info!(
                    "[MEM] RSS: {} | Peak: {} | Commit: {} | PeakCommit: {} | Faults: {:.1}/s | CPU eff: {:.0}%",
                    info.memory_usage_human(),
                    info.peak_memory_usage_human(),
                    info.virtual_memory_usage_human(),
                    libpsycho::common::helpers::format_bytes(info.get_peak_commit()),
                    info.page_fault_rate_per_second(),
                    info.cpu_efficiency_percent(),
                );
                // Force mimalloc to reclaim empty segments and abandoned heaps.
                // true = aggressive collection (walks all segments).
                unsafe { mi_collect(true) };

                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        })
        .ok();

    Ok(())
}
