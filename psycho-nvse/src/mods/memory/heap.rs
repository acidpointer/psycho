//! This set of patches heavily based on awesome project: https://github.com/iranrmrf/Heap-Replacer
//! I heavily rely on reverse engineering work and re-use general approach.
//! This project is source of all addresses and memory patches, applied here.

use std::sync::LazyLock;

use libc::c_void;
use libmimalloc::{mi_calloc, mi_free, mi_is_in_heap_region, mi_malloc, mi_realloc, mi_usable_size};

use libpsycho::os::windows::{
    hook::inline::inlinehook::InlineHookContainer,
    types::{GameHeapAllocateFn, GameHeapFreeFn, GameHeapMsizeFn, GameHeapReallocateFn, SheapAllocFn, SheapFreeFn, SheapGetThreadLocalFn, SheapInitFixFn, SheapInitVarFn, SheapPurgeFn},
    winapi::{patch_bytes, patch_memory_nop, patch_nop_call, patch_ret},
};

// ======================================================================================================================
// Addresses
// ======================================================================================================================

// Game Heap API addresses (Fallout New Vegas engine heap)
// Source: https://github.com/iranrmrf/Heap-Replacer/blob/master/heap_replacer/main/heap_replacer.h
const GAME_HEAP_ALLOCATE_ADDR: usize = 0x00AA3E40;
const GAME_HEAP_REALLOCATE_ADDR_1: usize = 0x00AA4150;
const GAME_HEAP_REALLOCATE_ADDR_2: usize = 0x00AA4200;
const GAME_HEAP_MSIZE_ADDR: usize = 0x00AA44C0;
const GAME_HEAP_FREE_ADDR: usize = 0x00AA4060;

// Scrap Heap (sheap) API addresses (FNV engine stack-like heap)
const SHEAP_INIT_FIX_ADDR: usize = 0x00AA53F0;
const SHEAP_INIT_VAR_ADDR: usize = 0x00AA5410;
const SHEAP_ALLOC_ADDR: usize = 0x00AA54A0;
const SHEAP_FREE_ADDR: usize = 0x00AA5610;
const SHEAP_PURGE_ADDR: usize = 0x00AA5460;
const SHEAP_GET_THREAD_LOCAL_ADDR: usize = 0x00AA42E0;

// ======================================================================================================================
// Statics
// ======================================================================================================================

// InlineHook containers for game heap functions
pub static GAME_HEAP_ALLOCATE_HOOK: LazyLock<InlineHookContainer<GameHeapAllocateFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static GAME_HEAP_REALLOCATE_HOOK_1: LazyLock<InlineHookContainer<GameHeapReallocateFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static GAME_HEAP_REALLOCATE_HOOK_2: LazyLock<InlineHookContainer<GameHeapReallocateFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static GAME_HEAP_MSIZE_HOOK: LazyLock<InlineHookContainer<GameHeapMsizeFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static GAME_HEAP_FREE_HOOK: LazyLock<InlineHookContainer<GameHeapFreeFn>> =
    LazyLock::new(InlineHookContainer::new);

// InlineHook containers for sheap functions
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


// ======================================================================================================================
// Game heap detours
// ======================================================================================================================

unsafe extern "fastcall" fn game_heap_allocate(
    _self: *mut c_void,
    _edx: *mut c_void,
    size: usize,
) -> *mut c_void {
    unsafe { mi_malloc(size) }
}

unsafe extern "fastcall" fn game_heap_reallocate(
    self_ptr: *mut c_void,
    edx: *mut c_void,
    addr: *mut c_void,
    size: usize,
) -> *mut c_void {
    if addr.is_null() {
        return unsafe { mi_malloc(size) };
    }

    let is_mimalloc = unsafe { mi_is_in_heap_region(addr) };
    
    if is_mimalloc {
        if size == 0 {
            unsafe { mi_free(addr) };
            return std::ptr::null_mut();
        }
        
        return unsafe { mi_realloc(addr, size) };
    }

    match GAME_HEAP_REALLOCATE_HOOK_1.original() {
        Ok(orig_realloc) => unsafe { orig_realloc(self_ptr, edx, addr, size) },
        Err(err) => {
            log::error!(
                "[game_heap_reallocate] Failed to call original game_heap_reallocate for {:p}: {:?}",
                addr,
                err
            );
            std::ptr::null_mut()
        }
    }
}

unsafe extern "fastcall" fn game_heap_msize(
    self_ptr: *mut c_void,
    edx: *mut c_void,
    addr: *mut c_void,
) -> usize {
    if addr.is_null() {
        return 0;
    }

    if unsafe { mi_is_in_heap_region(addr) } {
        return unsafe { mi_usable_size(addr) };
    }

    match GAME_HEAP_MSIZE_HOOK.original() {
        Ok(orig_msize) => unsafe { orig_msize(self_ptr, edx, addr) },
        Err(err) => {
            log::error!(
                "[game_heap_msize] Failed to call original game_heap_msize for {:p}: {:?}",
                addr,
                err
            );
            0
        }
    }
}

unsafe extern "fastcall" fn game_heap_free(
    self_ptr: *mut c_void,
    edx: *mut c_void,
    addr: *mut c_void,
) {
    if addr.is_null() {
        return;
    }

    let is_mimalloc = unsafe { mi_is_in_heap_region(addr) };
    
    if is_mimalloc {
        unsafe { mi_free(addr) };
        return;
    }

    match GAME_HEAP_FREE_HOOK.original() {
        Ok(orig_free) => {
            unsafe { orig_free(self_ptr, edx, addr) };
        }
        Err(err) => {
            log::error!(
                "[game_heap_free] Failed to call original game_heap_free for {:p}: {:?}",
                addr,
                err
            );
        }
    }
}

// ======================================================================================================================
// Scrap heap detours
// ======================================================================================================================

// Scrap Heap (sheap) structure
// The game allocates this structure and passes it to init functions.
// The game code may directly access these fields, so we must maintain a valid structure.
// Even though we use mimalloc for actual allocations, we need to keep this structure
// properly initialized to prevent the game from reading garbage/null pointers.
#[repr(C)]
struct SheapStruct {
    blocks: *mut *mut c_void, // Pointer to array of block pointers
    cur: *mut c_void,         // Current allocation pointer within active block
    last: *mut c_void,        // Pointer to last allocated chunk header
}

const SHEAP_MAX_BLOCKS: usize = 32;
const SHEAP_BUFF_SIZE: usize = 512 * 1024; // 512 KB


/// Sheap fixed-size initialization replacement
///
/// Allocates the blocks array and first block, matching C++ implementation.
/// Even though we redirect actual allocations to mimalloc, the game may
/// read these fields, so we must initialize them properly.
unsafe extern "fastcall" fn sheap_init_fix(heap: *mut c_void, _edx: *mut c_void) {
    if heap.is_null() {
        return;
    }

    let sheap = heap as *mut SheapStruct;

    // Allocate array of block pointers (matches C++ sheap_init)
    let blocks = unsafe {
        mi_calloc(SHEAP_MAX_BLOCKS, std::mem::size_of::<*mut c_void>())
    } as *mut *mut c_void;

    if blocks.is_null() {
        return;
    }

    // Allocate first block (matches C++ sheap_init)
    let first_block = unsafe { mi_malloc(SHEAP_BUFF_SIZE) };

    if first_block.is_null() {
        unsafe { mi_free(blocks as *mut c_void) };
        return;
    }

    // Initialize the sheap structure (matches C++ sheap_init)
    unsafe {
        (*sheap).blocks = blocks;
        *blocks = first_block; // blocks[0] = first_block
        (*sheap).cur = first_block;
        (*sheap).last = std::ptr::null_mut();
    }
}

/// Sheap variable-size initialization replacement
///
/// Allocates the blocks array and first block, matching C++ implementation.
unsafe extern "fastcall" fn sheap_init_var(
    heap: *mut c_void,
    _edx: *mut c_void,
    _size: usize,
) {
    if heap.is_null() {
        return;
    }

    let sheap = heap as *mut SheapStruct;

    // Allocate array of block pointers (matches C++ sheap_init)
    let blocks = unsafe {
        mi_calloc(SHEAP_MAX_BLOCKS, std::mem::size_of::<*mut c_void>())
    } as *mut *mut c_void;

    if blocks.is_null() {
        return;
    }

    // Allocate first block (matches C++ sheap_init)
    let first_block = unsafe { mi_malloc(SHEAP_BUFF_SIZE) };

    if first_block.is_null() {
        unsafe { mi_free(blocks as *mut c_void) };
        return;
    }

    // Initialize the sheap structure (matches C++ sheap_init)
    unsafe {
        (*sheap).blocks = blocks;
        *blocks = first_block; // blocks[0] = first_block
        (*sheap).cur = first_block;
        (*sheap).last = std::ptr::null_mut();
    }
}

/// Sheap allocation replacement
///
/// Just use mimalloc directly. Do NOT zero - C++ version doesn't zero either.
unsafe extern "fastcall" fn sheap_alloc(
    _heap: *mut c_void,
    _edx: *mut c_void,
    size: usize,
    _align: usize,
) -> *mut c_void {
    unsafe { mi_malloc(size) }
}

/// Sheap free replacement
///
/// Frees memory allocated by sheap_alloc.
unsafe extern "fastcall" fn sheap_free(
    heap: *mut c_void,
    edx: *mut c_void,
    addr: *mut c_void,
) {
    if addr.is_null() {
        return;
    }

    // Check if this pointer belongs to mimalloc
    if unsafe { mi_is_in_heap_region(addr) } {
        unsafe { mi_free(addr) };
        return;
    }

    // Foreign pointer - call original sheap free
    match SHEAP_FREE_HOOK.original() {
        Ok(orig_free) => {
            unsafe { orig_free(heap, edx, addr) };
        }
        Err(err) => {
            log::error!(
                "Failed to call original sheap_free for {:p}: {:?}",
                addr,
                err
            );
        }
    }
}

/// Sheap purge replacement
///
/// Frees all allocated blocks and the blocks array, matching C++ implementation.
/// After purge, the game must call init again before using the sheap.
unsafe extern "fastcall" fn sheap_purge(heap: *mut c_void, _edx: *mut c_void) {
    if heap.is_null() {
        return;
    }

    let sheap = heap as *mut SheapStruct;

    unsafe {
        let blocks = (*sheap).blocks;
        if blocks.is_null() {
            return;
        }

        // Free all allocated blocks (matches C++ sheap_purge)
        for i in 0..SHEAP_MAX_BLOCKS {
            let block = *blocks.add(i);
            if !block.is_null() {
                mi_free(block);
            }
        }

        // Free the blocks array itself
        mi_free(blocks as *mut c_void);

        // Zero out the sheap structure
        (*sheap).blocks = std::ptr::null_mut();
        (*sheap).cur = std::ptr::null_mut();
        (*sheap).last = std::ptr::null_mut();
    }
}

/// Sheap thread-local storage replacement
///
/// Original returns a thread-local sheap structure that is initialized on first access.
/// Matches C++ implementation: allocates the sheap struct, then calls sheap_init on it.
unsafe extern "C" fn sheap_get_thread_local() -> *mut c_void {
    use std::cell::RefCell;

    // Thread-local storage for sheap structure
    thread_local! {
        static THREAD_SHEAP: RefCell<Option<*mut SheapStruct>> = const { RefCell::new(None) };
    }

    THREAD_SHEAP.with(|cell| {
        let mut opt = cell.borrow_mut();
        if opt.is_none() {
            // Allocate sheap structure for this thread (matches C++ sheap_get_thread_local)
            let sheap =
                unsafe { mi_malloc(std::mem::size_of::<SheapStruct>()) } as *mut SheapStruct;

            if sheap.is_null() {
                return std::ptr::null_mut();
            }

            // Initialize the sheap structure by calling our init function
            // This matches C++ which calls sheap_init(heap)
            unsafe {
                sheap_init_fix(sheap as *mut c_void, std::ptr::null_mut());
            }

            *opt = Some(sheap);
        }

        let sheap = opt.unwrap();
        sheap as *mut c_void
    })
}

/// Install all heap replacement patches
///
/// This function completely replaces the game's heap and sheap systems with mimalloc.
/// Uses patch_jmp to overwrite function entry points with jumps to our replacements.
///
/// IMPORTANT: Unlike inline hooks, patch_jmp completely overwrites the original functions.
/// There is no original function to call back to - all allocations go through mimalloc.
///
/// Early game allocations (before this function is called) will leak, but this is
/// acceptable for a plugin loaded early in the game lifecycle.
pub fn install_game_heap_hooks() -> anyhow::Result<()> {
    super::configure_mimalloc();

    unsafe {
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
    }

    // Enable game heap hooks
    GAME_HEAP_ALLOCATE_HOOK.enable()?;
    log::info!("[INLINE] Hooked game_heap_allocate at {:#x}", GAME_HEAP_ALLOCATE_ADDR);

    GAME_HEAP_REALLOCATE_HOOK_1.enable()?;
    log::info!("[INLINE] Hooked game_heap_reallocate_1 at {:#x}", GAME_HEAP_REALLOCATE_ADDR_1);

    GAME_HEAP_REALLOCATE_HOOK_2.enable()?;
    log::info!("[INLINE] Hooked game_heap_reallocate_2 at {:#x}", GAME_HEAP_REALLOCATE_ADDR_2);

    GAME_HEAP_MSIZE_HOOK.enable()?;
    log::info!("[INLINE] Hooked game_heap_msize at {:#x}", GAME_HEAP_MSIZE_ADDR);

    GAME_HEAP_FREE_HOOK.enable()?;
    log::info!("[INLINE] Hooked game_heap_free at {:#x}", GAME_HEAP_FREE_ADDR);

    log::info!("[GAME HEAP] All game heap functions hooked with mimalloc!");

    unsafe {
        // Apply first group of RET patches
        patch_ret(0x00AA6840 as *mut c_void)?;
        patch_ret(0x00866E00 as *mut c_void)?;
        patch_ret(0x00866770 as *mut c_void)?;
        log::info!("[PATCHES] Applied RET patches: 0x00AA6840, 0x00866E00, 0x00866770");

        // Apply second group of RET patches
        patch_ret(0x00AA6F90 as *mut c_void)?;
        patch_ret(0x00AA7030 as *mut c_void)?;
        patch_ret(0x00AA7290 as *mut c_void)?;
        patch_ret(0x00AA7300 as *mut c_void)?;
        log::info!("[PATCHES] Applied RET patches: 0x00AA6F90, 0x00AA7030, 0x00AA7290, 0x00AA7300");

        // Apply third group of RET patches
        patch_ret(0x00AA58D0 as *mut c_void)?;
        patch_ret(0x00866D10 as *mut c_void)?;
        patch_ret(0x00AA5C80 as *mut c_void)?;
        log::info!("[PATCHES] Applied RET patches: 0x00AA58D0, 0x00866D10, 0x00AA5C80");

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

        SHEAP_ALLOC_HOOK.init(
            "sheap_alloc",
            SHEAP_ALLOC_ADDR as *mut c_void,
            sheap_alloc,
        )?;

        SHEAP_FREE_HOOK.init(
            "sheap_free",
            SHEAP_FREE_ADDR as *mut c_void,
            sheap_free,
        )?;

        SHEAP_PURGE_HOOK.init(
            "sheap_purge",
            SHEAP_PURGE_ADDR as *mut c_void,
            sheap_purge,
        )?;
    }

    // Enable sheap hooks
    SHEAP_INIT_FIX_HOOK.enable()?;
    log::info!("[INLINE] Hooked sheap_init_fix at {:#x}", SHEAP_INIT_FIX_ADDR);

    SHEAP_INIT_VAR_HOOK.enable()?;
    log::info!("[INLINE] Hooked sheap_init_var at {:#x}", SHEAP_INIT_VAR_ADDR);

    SHEAP_ALLOC_HOOK.enable()?;
    log::info!("[INLINE] Hooked sheap_alloc at {:#x}", SHEAP_ALLOC_ADDR);

    SHEAP_FREE_HOOK.enable()?;
    log::info!("[INLINE] Hooked sheap_free at {:#x}", SHEAP_FREE_ADDR);

    SHEAP_PURGE_HOOK.enable()?;
    log::info!("[INLINE] Hooked sheap_purge at {:#x}", SHEAP_PURGE_ADDR);

    log::info!("[SHEAP] All scrap heap functions hooked with mimalloc!");

    unsafe {
        // Apply 30-byte NOP patch
        patch_memory_nop(0x00AA38CA as *mut c_void, 0x00AA38E8 - 0x00AA38CA)?;
        log::info!("[PATCHES] Applied 30-byte NOP patch at 0x00AA38CA");

        // Initialize and enable sheap_get_thread_local hook
        SHEAP_GET_THREAD_LOCAL_HOOK.init(
            "sheap_get_thread_local",
            SHEAP_GET_THREAD_LOCAL_ADDR as *mut c_void,
            sheap_get_thread_local,
        )?;
    }

    SHEAP_GET_THREAD_LOCAL_HOOK.enable()?;
    log::info!("[INLINE] Hooked sheap_get_thread_local at {:#x}", SHEAP_GET_THREAD_LOCAL_ADDR);

    unsafe {
        // Apply NOP call patches
        patch_nop_call(0x00AA3060 as *mut c_void)?;
        log::info!("[PATCHES] Applied NOP call patch at 0x00AA3060");

        patch_nop_call(0x0086C56F as *mut c_void)?;
        patch_nop_call(0x00C42EB1 as *mut c_void)?;
        patch_nop_call(0x00EC1701 as *mut c_void)?;
        log::info!("[PATCHES] Applied NOP call patches: 0x0086C56F, 0x00C42EB1, 0x00EC1701");

        // Apply byte patch to change conditional jump
        patch_bytes(0x0086EED4 as *mut c_void, &[0xEB, 0x55])?;
        log::info!("[PATCHES] Applied byte patch at 0x0086EED4 (conditional jump modification)");

        log::info!("[HEAP REPLACER] All patches applied successfully - game heap fully replaced with mimalloc!");
    }

    Ok(())
}
