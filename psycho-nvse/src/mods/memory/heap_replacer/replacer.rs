use libpsycho::os::windows::winapi;
use libpsycho::os::windows::winapi::patch_nop_call;

use super::*;
use crate::mods::memory::configure_mimalloc;
use libc::c_void;

use game_heap::hooks::*;
use scrap_heap::hooks::*;

/// Installs all heap and scrap heap replacement hooks.
///
/// Replaces the game's allocators with MiMalloc (game heap) and bump allocators (scrap heap).
/// Also applies memory patches to disable original heap initialization and cleanup code.
pub fn install_game_heap_hooks() -> anyhow::Result<()> {
    let is_laa = winapi::is_large_address_aware()?;

    if !is_laa {
        log::warn!("[LAA] Game executable does NOT have Large Address Aware flag set!");
        log::warn!("[LAA] This limits address space to ~2GB instead of 4GB");
    } else {
        log::info!("[LAA] Large Address Aware flag is set");
    }

    scrap_heap::spawn_scavenger_thread();

    configure_mimalloc();

    // Game heap is in very eraly stage! Dont even try this out!

    GAME_HEAP_ALLOCATE_HOOK.init(
        "game_heap_allocate",
        GAME_HEAP_ALLOCATE_ADDR as *mut c_void,
        game_heap_allocate,
    )?;

    GAME_HEAP_REALLOCATE_HOOK_1.init(
        "game_heap_reallocate_1",
        GAME_HEAP_REALLOCATE_ADDR_1 as *mut c_void,
        game_heap_reallocate,
    )?;

    GAME_HEAP_REALLOCATE_HOOK_2.init(
        "game_heap_reallocate_2",
        GAME_HEAP_REALLOCATE_ADDR_2 as *mut c_void,
        game_heap_reallocate,
    )?;

    GAME_HEAP_MSIZE_HOOK.init(
        "game_heap_msize",
        GAME_HEAP_MSIZE_ADDR as *mut c_void,
        game_heap_msize,
    )?;

    GAME_HEAP_FREE_HOOK.init(
        "game_heap_free",
        GAME_HEAP_FREE_ADDR as *mut c_void,
        game_heap_free,
    )?;

    // Enable game heap hooks
    GAME_HEAP_ALLOCATE_HOOK.enable()?;
    log::info!(
        "[INLINE] Hooked game_heap_allocate at {:#x}",
        GAME_HEAP_ALLOCATE_ADDR
    );

    GAME_HEAP_REALLOCATE_HOOK_1.enable()?;
    log::info!(
        "[INLINE] Hooked game_heap_reallocate_1 at {:#x}",
        GAME_HEAP_REALLOCATE_ADDR_1
    );

    GAME_HEAP_REALLOCATE_HOOK_2.enable()?;
    log::info!(
        "[INLINE] Hooked game_heap_reallocate_2 at {:#x}",
        GAME_HEAP_REALLOCATE_ADDR_2
    );

    GAME_HEAP_MSIZE_HOOK.enable()?;
    log::info!(
        "[INLINE] Hooked game_heap_msize at {:#x}",
        GAME_HEAP_MSIZE_ADDR
    );

    GAME_HEAP_FREE_HOOK.enable()?;
    log::info!(
        "[INLINE] Hooked game_heap_free at {:#x}",
        GAME_HEAP_FREE_ADDR
    );

    // unsafe {
    //     patch_ret(0x00AA6840 as *mut c_void)?;
    //     patch_ret(0x00866E00 as *mut c_void)?;
    //     patch_ret(0x00866770 as *mut c_void)?;
    //     patch_ret(0x00AA6F90 as *mut c_void)?;
    //     patch_ret(0x00AA7030 as *mut c_void)?;
    //     patch_ret(0x00AA7290 as *mut c_void)?;
    //     patch_ret(0x00AA7300 as *mut c_void)?;
    //     patch_ret(0x00AA58D0 as *mut c_void)?;
    //     patch_ret(0x00866D10 as *mut c_void)?;
    //     patch_ret(0x00AA5C80 as *mut c_void)?;
    // }

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

    // Enable sheap hooks
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

    // NOP out game's sheap initialization - we handle it in our hooks
    // 
    // unsafe {
    //     patch_memory_nop(0x00AA38CA as *mut c_void, 0x00AA38E8 - 0x00AA38CA)?;
    // }

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
        patch_nop_call(0x0086C56F as *mut c_void)?;

        // These prevent exception raising during cleanup/transitions
        patch_nop_call(0x00C42EB1 as *mut c_void)?;
        patch_nop_call(0x00EC1701 as *mut c_void)?;

        //patch_bytes(0x0086EED4 as *mut c_void, &[0xEB, 0x55])?;
    }
    log::info!("[HEAP REPLACER] All hooks and patches applied successfully");

    Ok(())
}
