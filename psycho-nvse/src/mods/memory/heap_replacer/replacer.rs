use std::sync::LazyLock;

use libpsycho::os::windows::winapi::{patch_bytes, patch_nop_call};
use libpsycho::os::windows::winapi::{patch_memory_nop, patch_ret};
use libpsycho::os::windows::{
    hook::inline::inlinehook::InlineHookContainer,
    types::{CallocFn, FreeFn, MallocFn, MsizeFn, ReallocFn, RecallocFn},
};

use super::hooks::*;
use super::types::*;
use crate::mods::memory::configure_mimalloc;
use libc::c_void;

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
const SHEAP_MAINTENANCE_ADDR: usize = 0x00AA7260;

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
pub static SHEAP_MAINTENANCE_HOOK: LazyLock<InlineHookContainer<SheapMaintenanceFn>> =
    LazyLock::new(InlineHookContainer::new);

/// Installs all heap and scrap heap replacement hooks.
///
/// Replaces the game's allocators with MiMalloc (game heap) and bump allocators (scrap heap).
/// Also applies memory patches to disable original heap initialization and cleanup code.
pub fn install_game_heap_hooks() -> anyhow::Result<()> {
    configure_mimalloc();

    unsafe {
        // That address is the Statistics and Global State Reset function for the Small Block Manager (SBM).
        patch_ret(0x00AA6840 as *mut c_void)?;

        // NiMemoryManager Initializer.
        // patch_ret(0x00866E00 as *mut c_void)?;

        // Small Block Manager (SBM) Configuration Table
        patch_ret(0x00866770 as *mut c_void)?;

        // SBM::PurgeUnusedArenas
        patch_ret(0x00AA6F90 as *mut c_void)?;

        // SBM Global Cleanup Dispatcher
        patch_ret(0x00AA7030 as *mut c_void)?;

        // SBM::DecrementArenaReference
        patch_ret(0x00AA7290 as *mut c_void)?;

        // SBM::ReleaseArenaByPointer
        patch_ret(0x00AA7300 as *mut c_void)?;

        // SBM Master Constructor
        // patch_ret(0x00AA58D0 as *mut c_void)?;

        // SBM Singleton Accessor (Getter/Initializor)
        // patch_ret(0x00866D10 as *mut c_void)?;

        // SBM::DeallocateAllArenas
        patch_ret(0x00AA5C80 as *mut c_void)?;

        // Prevent the engine from trying to allocate its own "Backing Regions"
        patch_ret(0x00AA57B0 as *mut c_void)?;
    }

    //     This patch performs a surgical bypass at the engine's "Decision Point" (0x00AA3EE0).
    // The Gaslight (The Bypass):
    // When the engine needs to store a tiny piece of data (like a UI button's name), it asks:
    // "Is this small enough for the Scrap Heap?" Normally, the answer is "Yes," and it enters the buggy SBM code.
    // Our Patch (EB 12) forces the answer to always be "No."
    // It tells the engine: "Everything is too big for the Scrap Heap. Use the System Heap instead."
    // The Upgrade (The Hook):
    // Now that all those tiny objects are diverted to the "System Heap" path (0x00AA4290),
    // we intercept that path. Instead of letting the game use the old, slow Windows allocator, we hand the request to MiMalloc.
    // unsafe {
    //     // --- BYPASS SBM LOGIC ---
    //     // Divert all small allocations to the System Heap path.
    //     // Address 0x00AA3EE0: JA (77 12) -> JMP (EB 12)

    //     let target_addr = 0x00AA3EE0 as *mut c_void;
    //     let patch_bytes: [u8; 2] = [0xEB, 0x12];

    //     with_virtual_protect(target_addr, PAGE_EXECUTE_READWRITE, 2, || {
    //         core::ptr::copy_nonoverlapping(patch_bytes.as_ptr(), target_addr as *mut u8, 2);
    //     })?;
    //     log::info!("[SBM] Divergence patch applied successfully at 0x00AA3EE0");
    // }

    CRT_INLINE_MALLOC_HOOK_1.init("malloc1", CRT_MALLOC_ADDR_1 as *mut c_void, hook_malloc)?;
    CRT_INLINE_MALLOC_HOOK_2.init("malloc2", CRT_MALLOC_ADDR_2 as *mut c_void, hook_malloc)?;

    CRT_INLINE_CALLOC_HOOK_1.init("calloc1", CRT_CALLOC_ADDR_1 as *mut c_void, hook_calloc)?;
    CRT_INLINE_CALLOC_HOOK_2.init("calloc2", CRT_CALLOC_ADDR_2 as *mut c_void, hook_calloc)?;

    CRT_INLINE_REALLOC_HOOK_1.init("realloc1", CRT_REALLOC_ADDR_1 as *mut c_void, hook_realloc)?;
    CRT_INLINE_REALLOC_HOOK_2.init("realloc2", CRT_REALLOC_ADDR_2 as *mut c_void, hook_realloc)?;

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
    log::info!("[INLINE] Hooked malloc_1");

    CRT_INLINE_MALLOC_HOOK_2.enable()?;
    log::info!("[INLINE] Hooked malloc_2");

    CRT_INLINE_CALLOC_HOOK_1.enable()?;
    log::info!("[INLINE] Hooked calloc_1");

    CRT_INLINE_CALLOC_HOOK_2.enable()?;
    log::info!("[INLINE] Hooked calloc_2");

    CRT_INLINE_REALLOC_HOOK_1.enable()?;
    log::info!("[INLINE] Hooked realloc_1");

    CRT_INLINE_REALLOC_HOOK_2.enable()?;
    log::info!("[INLINE] Hooked realloc_2");

    CRT_INLINE_RECALLOC_HOOK_1.enable()?;
    log::info!("[INLINE] Hooked recalloc_1");

    CRT_INLINE_RECALLOC_HOOK_2.enable()?;
    log::info!("[INLINE] Hooked recalloc_2");

    CRT_INLINE_FREE_HOOK.enable()?;
    log::info!("[INLINE] Hooked free");

    CRT_INLINE_MSIZE_HOOK.enable()?;
    log::info!("[INLINE] Hooked msize");

    log::info!("[INLINE] All CRT hooks installed!");

    // Initialize and enable sheap inline hooks
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

    SHEAP_MAINTENANCE_HOOK.init(
        "sheap_maintenance",
        SHEAP_MAINTENANCE_ADDR as *mut c_void,
        sheap_maintenance,
    )?;

    // // Enable sheap hooks
    SHEAP_INIT_FIX_HOOK.enable()?;
    log::info!(
        "[INLINE] Hooked sheap_init_fix at {:#x}",
        SHEAP_INIT_FIX_ADDR
    );

    SHEAP_INIT_VAR_HOOK.enable()?;
    log::info!(
        "[INLINE] Hooked sheap_init_var at {:#x}",
        SHEAP_INIT_VAR_ADDR
    );

    SHEAP_ALLOC_HOOK.enable()?;
    log::info!("[INLINE] Hooked sheap_alloc at {:#x}", SHEAP_ALLOC_ADDR);

    SHEAP_FREE_HOOK.enable()?;
    log::info!("[INLINE] Hooked sheap_free at {:#x}", SHEAP_FREE_ADDR);

    SHEAP_PURGE_HOOK.enable()?;
    log::info!("[INLINE] Hooked sheap_purge at {:#x}", SHEAP_PURGE_ADDR);

    SHEAP_MAINTENANCE_HOOK.enable()?;
    log::info!(
        "[INLINE] Hooked sheap_maintenance at {:#x}",
        SHEAP_MAINTENANCE_ADDR
    );

    // This is where the engine takes the data from GlobalMemoryStatusEx and decides if the SBM is allowed to exist.
    unsafe {
        patch_memory_nop(0x00AA38CA as *mut c_void, 0x00AA38E8 - 0x00AA38CA)?;

        // Kill the entire maintenance routine inside FUN_00aa7290
        // By putting a RET (0xC3) at the very start, we skip the locks, the sort, and the counter updates.
        patch_bytes(0x00AA7290 as *mut c_void, &[0xC3])?;
    }

    // Initialize and enable sheap_get_thread_local hook
    SHEAP_GET_THREAD_LOCAL_HOOK.init(
        "sheap_get_thread_local",
        SHEAP_GET_THREAD_LOCAL_ADDR as *mut c_void,
        sheap_get_thread_local,
    )?;

    SHEAP_GET_THREAD_LOCAL_HOOK.enable()?;
    log::info!(
        "[INLINE] Hooked sheap_get_thread_local at {:#x}",
        SHEAP_GET_THREAD_LOCAL_ADDR
    );

    unsafe {
        patch_nop_call(0x00AA3060 as *mut c_void)?;

        // stops the game from "double-checking" its heaps during construction
        patch_nop_call(0x0086C56F as *mut c_void)?;

        // These prevent exception raising during cleanup/transitions
        patch_nop_call(0x00C42EB1 as *mut c_void)?;
        patch_nop_call(0x00EC1701 as *mut c_void)?;

        //patch_bytes(0x0086EED4 as *mut c_void, &[0xEB, 0x55])?;

        // Disables the frame-based ScrapHeap maintenance trigger in the Main Loop.
        // 
        // This patch NOPs the call to the periodic maintenance routine (FUN_00aa7290).
        // By silencing this, we prevent the engine from attempting to perform 
        // background pointer re-linking (Merge Sort) and reference counter updates 
        // on our custom-managed memory, ensuring our Rust allocator remains the 
        // sole owner of the heap state and improving frame-time consistency.
        patch_memory_nop(0x0086EF0E as *mut c_void, 5)?;
    }
    log::info!("[HEAP REPLACER] All hooks and patches applied successfully");

    Ok(())
}
