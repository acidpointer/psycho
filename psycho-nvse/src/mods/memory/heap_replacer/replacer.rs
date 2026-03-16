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

// RNG
const RNG_ADDRESS: usize = 0x00AA5230;

// Gheap

/// Game heap function addresses (Fallout New Vegas)
const GHEAP_ALLOC_ADDR: usize = 0x00AA3E40;
//const GHEAP_REALLOC_ADDR_1: usize = 0x00AA4150;
//const GHEAP_REALLOC_ADDR_2: usize = 0x00AA4200;
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

pub static RNG_HOOK: LazyLock<InlineHookContainer<RngFn>> = LazyLock::new(InlineHookContainer::new);

/// Applies patches and installs heap replacement hooks
pub fn install_game_heap_hooks() -> anyhow::Result<()> {
    // unsafe {
    //     // That address is the Statistics and Global State Reset function for the Small Block Manager (SBM).
    //     patch_ret(0x00AA6840 as *mut c_void)?;

    //     // Small Block Manager (SBM) Configuration Table
    //     patch_ret(0x00866770 as *mut c_void)?;
    // }

    // ===========================
    //   SBM PATCHES
    // ===========================
    //
    // The game's Small Block Manager (SBM) is shared between ScrapHeap and
    // GameHeap. We fully replace the ScrapHeap side via hooks. To complete
    // the picture, we also disconnect the GameHeap from the SBM allocation
    // path by patching its conditional branch to an unconditional jump.
    // This forces all NEW GameHeap allocations through the HeapAllocator
    // vtable / CRT fallback paths (no SBM arenas touched).
    //
    // GameHeap::Free still does the SBM arena lookup (ptr >> 24) for
    // pointers that were allocated from the SBM before our patches.
    // SBM_free (0x00AA6C70) is NOT patched -- it correctly frees those
    // pre-existing blocks. New pointers (from HeapAllocator/CRT) won't
    // match any SBM arena and fall through to the correct free path.
    //
    // With no new SBM allocations happening, the maintenance routines
    // are pure overhead and can be safely disabled.

    // Disconnect GameHeap::Allocate from the SBM fast path.
    //
    // Original:  JZ 0x00aa3f39  (0x74 = skip SBM if flag == 0)
    // Patched:   JMP 0x00aa3f39 (0xEB = always skip SBM)
    //
    // This is at the check: MOVZX ECX, byte ptr [EAX + 0x129]; TEST; JZ
    // By making the jump unconditional, the SBM path is never taken
    // regardless of the flag's runtime value.
    unsafe {
        patch_bytes(0x00AA3ED7 as *mut c_void, &[0xEB])?;
    }

    // Disable SBM maintenance -- no new arenas are created after the
    // GameHeap disconnect above.
    unsafe {
        // SBM::PurgeUnusedArenas
        patch_ret(0x00AA6F90 as *mut c_void)?;

        // SBM Global Cleanup Dispatcher
        patch_ret(0x00AA7030 as *mut c_void)?;

        // SBM::DecrementArenaReference
        patch_ret(0x00AA7290 as *mut c_void)?;

        // SBM::ReleaseArenaByPointer
        patch_ret(0x00AA7300 as *mut c_void)?;

        // SBM::DeallocateAllArenas
        patch_ret(0x00AA5C80 as *mut c_void)?;
    }

    // Prevent the engine from allocating ScrapHeap backing regions via the SBM.
    unsafe {
        patch_ret(0x00AA57B0 as *mut c_void)?;
    }

    unsafe {
        // NOP the GlobalMemoryStatusEx check that gates SBM creation.
        patch_memory_nop(0x00AA38CA as *mut c_void, 0x00AA38E8 - 0x00AA38CA)?;

        // Kill the frame-based maintenance trigger in the Main Loop.
        // DecrementArenaRef is already RET'd above, but NOPing the call site
        // avoids the overhead of calling into a RET stub every frame.
        patch_memory_nop(0x0086EF0E as *mut c_void, 5)?;

        // Belt-and-suspenders: also write RET at the function entry.
        patch_bytes(0x00AA7290 as *mut c_void, &[0xC3])?;
    }

    unsafe {
        patch_nop_call(0x00AA3060 as *mut c_void)?;

        // stops the game from "double-checking" its heaps during construction
        patch_nop_call(0x0086C56F as *mut c_void)?;

        // These prevent exception raising during cleanup/transitions
        patch_nop_call(0x00C42EB1 as *mut c_void)?;
        patch_nop_call(0x00EC1701 as *mut c_void)?;
    }

    // ===========================
    //   HOOKS
    // ===========================

    // Patch RNG
    {
        RNG_HOOK.init("rng", RNG_ADDRESS as *mut c_void, hook_rng)?;
        RNG_HOOK.enable()?;
    }

    // GHEAP_* hooks are very unstable and potentially requires additional patching

    // {
    //     GHEAP_ALLOC_HOOK.init(
    //         "gheap_alloc",
    //         GHEAP_ALLOC_ADDR as *mut c_void,
    //         hook_gheap_alloc,
    //     )?;
    //     GHEAP_FREE_HOOK.init(
    //         "gheap_alloc",
    //         GHEAP_FREE_ADDR as *mut c_void,
    //         hook_gheap_free,
    //     )?;
    //     GHEAP_MSIZE_HOOK.init(
    //         "gheap_msize",
    //         GHEAP_MSIZE_ADDR as *mut c_void,
    //         hook_gheap_msize,
    //     )?;

    //     GHEAP_ALLOC_HOOK.enable()?;
    //     GHEAP_FREE_HOOK.enable()?;
    //     GHEAP_MSIZE_HOOK.enable()?;
    // }

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

    Ok(())
}
