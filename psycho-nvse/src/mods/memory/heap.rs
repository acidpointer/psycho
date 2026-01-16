use libc::c_void;
use libmimalloc::{mi_calloc, mi_free, mi_is_in_heap_region, mi_malloc, mi_realloc, mi_usable_size};

use libpsycho::os::windows::winapi::{
    patch_bytes, patch_jmp, patch_memory_nop, patch_nop_call, patch_ret,
};

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

// Additional patch addresses
const PATCH_RET_ADDRS: [usize; 10] = [
    0x00AA6840, 0x00866E00, 0x00866770, 0x00AA6F90, 0x00AA7030, 0x00AA7290, 0x00AA7300, 0x00AA58D0,
    0x00866D10, 0x00AA5C80,
];

const PATCH_NOP_CALL_ADDRS: [usize; 4] = [0x00AA3060, 0x0086C56F, 0x00C42EB1, 0x00EC1701];

// Game Heap API replacement functions (Fallout New Vegas engine)
// These functions use __fastcall convention where:
// - 'self' (heap pointer) is passed in ECX
// - 'edx' is passed in EDX (usually unused)
// We completely replace the game's heap allocator with mimalloc

/// Game heap allocation replacement
///
/// Replaces the game's heap allocator with mimalloc. Since we use patch_jmp,
/// this completely overwrites the original function - there is no original to call.
pub unsafe extern "fastcall" fn game_heap_allocate(
    _self: *mut c_void,
    _edx: *mut c_void,
    size: usize,
) -> *mut c_void {
    unsafe { mi_malloc(size) }
}

/// Game heap reallocation replacement
///
/// Handles:
/// - null pointer case (acts like malloc)
/// - zero size case (acts like free, with foreign pointer check)
/// - normal reallocation (with foreign pointer handling)
///
/// CRITICAL: This function uses mi_is_in_heap_region to detect "foreign" pointers.
/// For foreign pointers during realloc, we allocate new memory and copy data.
pub unsafe extern "fastcall" fn game_heap_reallocate(
    _self: *mut c_void,
    _edx: *mut c_void,
    addr: *mut c_void,
    size: usize,
) -> *mut c_void {
    if addr.is_null() {
        return unsafe { mi_malloc(size) };
    }

    if size == 0 {
        // Free case - check if pointer is ours before freeing
        if unsafe { mi_is_in_heap_region(addr) } {
            unsafe { mi_free(addr) };
        }
        // If not in heap region, ignore the free (leak rather than crash)
        return std::ptr::null_mut();
    }

    // Check if the pointer belongs to mimalloc
    if unsafe { mi_is_in_heap_region(addr) } {
        // Our pointer - can safely realloc
        unsafe { mi_realloc(addr, size) }
    } else {
        // Foreign pointer - allocate new memory and copy what we can
        // We don't know the original size, so use mi_usable_size as best effort
        let old_size = unsafe { mi_usable_size(addr) };
        let new_addr = unsafe { mi_malloc(size) };
        if !new_addr.is_null() && old_size > 0 {
            let copy_size = if old_size < size { old_size } else { size };
            unsafe { std::ptr::copy_nonoverlapping(addr as *const u8, new_addr as *mut u8, copy_size) };
        }
        // Don't free the old foreign pointer - let it leak
        new_addr
    }
}

/// Game heap memory size query replacement
///
/// Returns the usable size of an allocated block.
/// Returns 0 for null pointers.
///
/// CRITICAL: This function uses mi_is_in_heap_region to detect "foreign" pointers.
/// For foreign pointers, returns 0 (similar to C++ Heap-Replacer behavior).
pub unsafe extern "fastcall" fn game_heap_msize(
    _self: *mut c_void,
    _edx: *mut c_void,
    addr: *mut c_void,
) -> usize {
    if addr.is_null() {
        return 0;
    }
    // Check if this pointer belongs to mimalloc before querying size
    if unsafe { mi_is_in_heap_region(addr) } {
        unsafe { mi_usable_size(addr) }
    } else {
        // Foreign pointer - return 0 (matches C++ hr_mem_size behavior)
        0
    }
}

/// Game heap free replacement
///
/// Frees memory allocated by game_heap_allocate or game_heap_reallocate.
/// Ignores null pointers (standard free behavior).
///
/// CRITICAL: This function uses mi_is_in_heap_region to detect "foreign" pointers
/// (allocated before our patches were installed or by other allocators).
/// Foreign pointers are ignored to prevent crashes - we leak them rather than crash.
pub unsafe extern "fastcall" fn game_heap_free(
    _self: *mut c_void,
    _edx: *mut c_void,
    addr: *mut c_void,
) {
    if !addr.is_null() {
        // Check if this pointer belongs to mimalloc before freeing
        // This prevents crashes when trying to free memory allocated before our patches
        if unsafe { mi_is_in_heap_region(addr) } {
            unsafe { mi_free(addr) };
        }
        // If not in heap region, it's a foreign pointer - ignore it (leak rather than crash)
    }
}

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

// Constants matching the C++ implementation
const SHEAP_MAX_BLOCKS: usize = 32;
const SHEAP_BUFF_SIZE: usize = 512 * 1024; // 512 KB

// Scrap Heap (sheap) API replacement functions (Fallout New Vegas engine)
// The sheap is a stack-like heap used for temporary allocations.
//
// CRITICAL: The game allocates the SheapStruct and may access its fields directly.
// We MUST properly initialize these fields even though we're redirecting actual
// allocations to mimalloc. This prevents crashes from null pointer dereferences.

/// Sheap fixed-size initialization replacement
///
/// Allocates the blocks array and first block, matching C++ implementation.
/// Even though we redirect actual allocations to mimalloc, the game may
/// read these fields, so we must initialize them properly.
pub unsafe extern "fastcall" fn sheap_init_fix(heap: *mut c_void, _edx: *mut c_void) {
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
pub unsafe extern "fastcall" fn sheap_init_var(
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
pub unsafe extern "fastcall" fn sheap_alloc(
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
///
/// CRITICAL: This function uses mi_is_in_heap_region to detect "foreign" pointers.
/// Foreign pointers are ignored to prevent crashes - we leak them rather than crash.
pub unsafe extern "fastcall" fn sheap_free(
    _heap: *mut c_void,
    _edx: *mut c_void,
    addr: *mut c_void,
) {
    if !addr.is_null() {
        // Check if this pointer belongs to mimalloc before freeing
        if unsafe { mi_is_in_heap_region(addr) } {
            unsafe { mi_free(addr) };
        }
        // If not in heap region, it's a foreign pointer - ignore it (leak rather than crash)
    }
}

/// Sheap purge replacement
///
/// Frees all allocated blocks and the blocks array, matching C++ implementation.
/// After purge, the game must call init again before using the sheap.
pub unsafe extern "fastcall" fn sheap_purge(heap: *mut c_void, _edx: *mut c_void) {
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
pub unsafe extern "C" fn sheap_get_thread_local() -> *mut c_void {
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
    unsafe {
        // STEP 1: Replace game heap functions with mimalloc wrappers
        // C++ lines 258-262
        patch_jmp(
            GAME_HEAP_ALLOCATE_ADDR as *mut c_void,
            game_heap_allocate as *mut c_void,
        )?;
        log::info!(
            "[PATCH_JMP] Replaced game_heap_allocate at {:#x}",
            GAME_HEAP_ALLOCATE_ADDR
        );

        patch_jmp(
            GAME_HEAP_REALLOCATE_ADDR_1 as *mut c_void,
            game_heap_reallocate as *mut c_void,
        )?;
        log::info!(
            "[PATCH_JMP] Replaced game_heap_reallocate_1 at {:#x}",
            GAME_HEAP_REALLOCATE_ADDR_1
        );

        patch_jmp(
            GAME_HEAP_REALLOCATE_ADDR_2 as *mut c_void,
            game_heap_reallocate as *mut c_void,
        )?;
        log::info!(
            "[PATCH_JMP] Replaced game_heap_reallocate_2 at {:#x}",
            GAME_HEAP_REALLOCATE_ADDR_2
        );

        patch_jmp(
            GAME_HEAP_MSIZE_ADDR as *mut c_void,
            game_heap_msize as *mut c_void,
        )?;
        log::info!(
            "[PATCH_JMP] Replaced game_heap_msize at {:#x}",
            GAME_HEAP_MSIZE_ADDR
        );

        patch_jmp(
            GAME_HEAP_FREE_ADDR as *mut c_void,
            game_heap_free as *mut c_void,
        )?;
        log::info!(
            "[PATCH_JMP] Replaced game_heap_free at {:#x}",
            GAME_HEAP_FREE_ADDR
        );

        log::info!("[GAME HEAP] All game heap functions replaced with mimalloc!");

        // STEP 2: Apply first group of RET patches
        // C++ lines 264-267
        patch_ret(0x00AA6840 as *mut c_void)?;
        patch_ret(0x00866E00 as *mut c_void)?;
        patch_ret(0x00866770 as *mut c_void)?;
        log::info!("[PATCHES] Applied RET patches: 0x00AA6840, 0x00866E00, 0x00866770");

        // STEP 3: Apply second group of RET patches
        // C++ lines 268-271
        patch_ret(0x00AA6F90 as *mut c_void)?;
        patch_ret(0x00AA7030 as *mut c_void)?;
        patch_ret(0x00AA7290 as *mut c_void)?;
        patch_ret(0x00AA7300 as *mut c_void)?;
        log::info!("[PATCHES] Applied RET patches: 0x00AA6F90, 0x00AA7030, 0x00AA7290, 0x00AA7300");

        // STEP 4: Apply third group of RET patches
        // C++ lines 273-275
        patch_ret(0x00AA58D0 as *mut c_void)?;
        patch_ret(0x00866D10 as *mut c_void)?;
        patch_ret(0x00AA5C80 as *mut c_void)?;
        log::info!("[PATCHES] Applied RET patches: 0x00AA58D0, 0x00866D10, 0x00AA5C80");

        // STEP 5: Replace sheap functions with mimalloc wrappers
        // C++ lines 277-281
        patch_jmp(
            SHEAP_INIT_FIX_ADDR as *mut c_void,
            sheap_init_fix as *mut c_void,
        )?;
        log::info!(
            "[PATCH_JMP] Replaced sheap_init_fix at {:#x}",
            SHEAP_INIT_FIX_ADDR
        );

        patch_jmp(
            SHEAP_INIT_VAR_ADDR as *mut c_void,
            sheap_init_var as *mut c_void,
        )?;
        log::info!(
            "[PATCH_JMP] Replaced sheap_init_var at {:#x}",
            SHEAP_INIT_VAR_ADDR
        );

        patch_jmp(
            SHEAP_ALLOC_ADDR as *mut c_void,
            sheap_alloc as *mut c_void,
        )?;
        log::info!(
            "[PATCH_JMP] Replaced sheap_alloc at {:#x}",
            SHEAP_ALLOC_ADDR
        );

        patch_jmp(
            SHEAP_FREE_ADDR as *mut c_void,
            sheap_free as *mut c_void,
        )?;
        log::info!(
            "[PATCH_JMP] Replaced sheap_free at {:#x}",
            SHEAP_FREE_ADDR
        );

        patch_jmp(
            SHEAP_PURGE_ADDR as *mut c_void,
            sheap_purge as *mut c_void,
        )?;
        log::info!(
            "[PATCH_JMP] Replaced sheap_purge at {:#x}",
            SHEAP_PURGE_ADDR
        );

        log::info!("[SHEAP] All scrap heap functions replaced with mimalloc!");

        // STEP 6: Apply 30-byte NOP patch
        // C++ line 283
        patch_memory_nop(0x00AA38CA as *mut c_void, 0x00AA38E8 - 0x00AA38CA)?;
        log::info!("[PATCHES] Applied 30-byte NOP patch at 0x00AA38CA");

        // STEP 7: Replace sheap_get_thread_local
        // C++ line 284
        patch_jmp(
            SHEAP_GET_THREAD_LOCAL_ADDR as *mut c_void,
            sheap_get_thread_local as *mut c_void,
        )?;
        log::info!(
            "[PATCH_JMP] Replaced sheap_get_thread_local at {:#x}",
            SHEAP_GET_THREAD_LOCAL_ADDR
        );

        // STEP 8: Apply NOP call patches
        // C++ lines 286-290
        patch_nop_call(0x00AA3060 as *mut c_void)?;
        log::info!("[PATCHES] Applied NOP call patch at 0x00AA3060");

        patch_nop_call(0x0086C56F as *mut c_void)?;
        patch_nop_call(0x00C42EB1 as *mut c_void)?;
        patch_nop_call(0x00EC1701 as *mut c_void)?;
        log::info!("[PATCHES] Applied NOP call patches: 0x0086C56F, 0x00C42EB1, 0x00EC1701");

        // STEP 9: Apply byte patch to change conditional jump
        // C++ line 292
        patch_bytes(0x0086EED4 as *mut c_void, &[0xEB, 0x55])?;
        log::info!("[PATCHES] Applied byte patch at 0x0086EED4 (conditional jump modification)");

        log::info!("[HEAP REPLACER] All patches applied successfully - game heap fully replaced with mimalloc!");
    }

    Ok(())
}
