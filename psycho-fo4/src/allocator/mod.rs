use std::{os::raw::c_void, sync::OnceLock};

use libf4se::prelude::{
    BGSMemoryManagerAllocFn, BGSMemoryManagerDeallocFn, BGSMemoryManagerMsizeFn,
    BGSScrapHeapAllocFn, BGSScrapHeapDeallocFn,
};
use libpsycho::{
    hook::{JMPHook, iat::IATHook},
    winapi::{
        CallocFn, FreeAlignFn, FreeFn, MallocAlignFn, MallocFn, MemcmpFn, MemcpyFn, MemcpySFn,
        MemmoveFn, MemmoveSFn, MemsetFn, MsizeFn, ReallocFn, RecallocFn, get_module_handle_a,
    },
};
use parking_lot::Mutex;

mod hooks;

use hooks::*;

pub static PATCH_ALLOC_MALLOC: OnceLock<Mutex<IATHook<MallocFn>>> = OnceLock::new();
pub static PATCH_ALLOC_MALLOC_ALIGN: OnceLock<Mutex<IATHook<MallocAlignFn>>> = OnceLock::new();

pub static PATCH_ALLOC_MSIZE: OnceLock<Mutex<IATHook<MsizeFn>>> = OnceLock::new();

pub static PATCH_ALLOC_FREE: OnceLock<Mutex<IATHook<FreeFn>>> = OnceLock::new();
pub static PATCH_ALLOC_FREE_ALIGN: OnceLock<Mutex<IATHook<FreeAlignFn>>> = OnceLock::new();

pub static PATCH_ALLOC_MEMCMP: OnceLock<Mutex<IATHook<MemcmpFn>>> = OnceLock::new();
pub static PATCH_ALLOC_MEMCPY: OnceLock<Mutex<IATHook<MemcpyFn>>> = OnceLock::new();
pub static PATCH_ALLOC_MEMSET: OnceLock<Mutex<IATHook<MemsetFn>>> = OnceLock::new();
pub static PATCH_ALLOC_MEMMOVE: OnceLock<Mutex<IATHook<MemmoveFn>>> = OnceLock::new();
pub static PATCH_ALLOC_MEMMOVE_S: OnceLock<Mutex<IATHook<MemmoveSFn>>> = OnceLock::new();
pub static PATCH_ALLOC_MEMCPY_S: OnceLock<Mutex<IATHook<MemcpySFn>>> = OnceLock::new();

/*
        REL::Impl::DetourJump(REL::ID(30), (UInt64)&detail::BGSMemoryManager::alloc);
        REL::Impl::DetourJump(REL::ID(40), (UInt64)&detail::BGSMemoryManager::dealloc);
        REL::Impl::DetourJump(REL::ID(41), (UInt64)&detail::BGSMemoryManager::realloc);			// NG ONLY
        REL::Impl::DetourJump(REL::ID(50), (UInt64)&detail::BGSMemoryManager::msize);
        REL::Impl::DetourJump(REL::ID(60), (UInt64)&detail::BGSScrapHeap::alloc);
        REL::Impl::DetourJump(REL::ID(70), (UInt64)&detail::BGSScrapHeap::dealloc);
        REL::Impl::DetourJump(REL::ID(80), (UInt64)&detail::bhkThreadMemorySource::__ctor__);	// bhkThreadMemorySource init

*/

/*
const REFERENCE_ENTRIES_163: [(usize, usize); 39] = [
    // LISTENER DX11
    (0, 0x1D18A57),
    (10, 0x61E0910),
    (20, 0x1D4FE40),
    (21, 0xAE6C70), // 0x2043A80
    (22, 0x28571FC),
    // MEMORY
    (30, 0x1B0EFD0),
    (40, 0x1B0F2E0),
    (50, 0x1B0E7D0),
    (60, 0x1B13F70),
    (70, 0x1B14580),
    (80, 0x1E21B10),
    (90, 0x211214B),
    (100, 0x2112151),
    (110, 0xD0C160),
    (120, 0x1B0EDB0),
    (130, 0x1B13DF0),
    (140, 0x1B14740),
    (150, 0x2EB92C8),
    // LIBDEFLATE
    (160, 0x13267D),
    (165, 0x1326AF),
    // LOADSCREEN
    (170, 0x12989E0),
    // FACEGEN
    (200, 0x5B57F0),
    (205, 0x679910),
    (210, 0x59DADD0),
    (215, 0x679B20),
    (220, 0x679BB2),
    (225, 0x1C97190),
    // UPSCALER
    (230, 0x384FBF0), // Size W : Display
    (231, 0x384FC08), // Size H : Display
    (232, 0x384FC20), // Location X : Display
    (233, 0x384FC38), // Location Y : Display
    (240, 0x1B4EC90), // Before first use read ^ data
    (245, 0x38C51B0), // TAA or FXAA
    // INIT TINTS
    (250, 0x5AF94D),
    (251, 0x5AFB60),
    (252, 0x292BBE0),
    (253, 0x11E4F1),
    (254, 0x5BDC49),
    (255, 0x120504),
];
*/

pub static PATCH_MM_ALLOC: OnceLock<Mutex<JMPHook<BGSMemoryManagerAllocFn>>> = OnceLock::new();
pub static PATCH_MM_DEALLOC: OnceLock<Mutex<JMPHook<BGSMemoryManagerDeallocFn>>> = OnceLock::new();
pub static PATCH_MM_MSIZE: OnceLock<Mutex<JMPHook<BGSMemoryManagerMsizeFn>>> = OnceLock::new();

pub static PATCH_SH_ALLOC: OnceLock<Mutex<JMPHook<BGSScrapHeapAllocFn>>> = OnceLock::new();
pub static PATCH_SH_DEALLOC: OnceLock<Mutex<JMPHook<BGSScrapHeapDeallocFn>>> = OnceLock::new();

/// Initializes and enables all allocator related patches
/// In addition this function tunes couple of MiMalloc options
pub fn init_allocator_patch() -> anyhow::Result<()> {
    let module_base = get_module_handle_a(None)?;

    let malloc = IATHook::<MallocFn>::new(module_base, "msvcr110.dll", "malloc", hook_malloc)?;
    let malloc_align = IATHook::<MallocAlignFn>::new(
        module_base,
        "msvcr110.dll",
        "_aligned_malloc",
        hook_malloc_aligned,
    )?;

    let free = IATHook::<FreeFn>::new(module_base, "msvcr110.dll", "free", hook_free)?;
    let free_align = IATHook::<FreeAlignFn>::new(
        module_base,
        "msvcr110.dll",
        "_aligned_free",
        hook_free_aligned,
    )?;

    let msize = IATHook::<MsizeFn>::new(module_base, "msvcr110.dll", "_msize", hook_msize)?;

    let memcmp = IATHook::<MemcmpFn>::new(module_base, "msvcr110.dll", "memcmp", hook_memcmp)?;
    let memcpy = IATHook::<MemcpyFn>::new(module_base, "msvcr110.dll", "memcpy", hook_memcpy)?;
    let memset = IATHook::<MemsetFn>::new(module_base, "msvcr110.dll", "memset", hook_memset)?;
    let memmove = IATHook::<MemmoveFn>::new(module_base, "msvcr110.dll", "memmove", hook_memmove)?;
    let memmove_s =
        IATHook::<MemmoveSFn>::new(module_base, "msvcr110.dll", "memmove_s", hook_memmove_s)?;
    let memcpy_s =
        IATHook::<MemcpySFn>::new(module_base, "msvcr110.dll", "memcpy_s", hook_memcpy_s)?;

    let mm_alloc = JMPHook::<BGSMemoryManagerAllocFn>::new(
        module_base,
        0x1B0EFD0,
        hook_bgsmemorymanager_alloc,
    )?;
    let mm_dealloc = JMPHook::<BGSMemoryManagerDeallocFn>::new(
        module_base,
        0x1B0F2E0,
        hook_bgsmemorymanager_dealloc,
    )?;
    let mm_msize = JMPHook::<BGSMemoryManagerMsizeFn>::new(
        module_base,
        0x1B0E7D0,
        hook_bgsmemorymanager_msize,
    )?;

    let sh_alloc =
        JMPHook::<BGSScrapHeapAllocFn>::new(module_base, 0x1B13F70, hook_bgsscrapheap_alloc)?;

    let sh_dealloc =
        JMPHook::<BGSScrapHeapDeallocFn>::new(module_base, 0x1B14580, hook_bgsscrapheap_dealloc)?;

    PATCH_ALLOC_MALLOC
        .get_or_init(move || Mutex::new(malloc))
        .lock()
        .enable()?;
    PATCH_ALLOC_MALLOC_ALIGN
        .get_or_init(move || Mutex::new(malloc_align))
        .lock()
        .enable()?;
    PATCH_ALLOC_FREE
        .get_or_init(move || Mutex::new(free))
        .lock()
        .enable()?;
    PATCH_ALLOC_FREE_ALIGN
        .get_or_init(move || Mutex::new(free_align))
        .lock()
        .enable()?;
    PATCH_ALLOC_MSIZE
        .get_or_init(move || Mutex::new(msize))
        .lock()
        .enable()?;

    PATCH_ALLOC_MEMCMP
        .get_or_init(move || Mutex::new(memcmp))
        .lock()
        .enable()?;

    PATCH_ALLOC_MEMCPY
        .get_or_init(move || Mutex::new(memcpy))
        .lock()
        .enable()?;

    PATCH_ALLOC_MEMSET
        .get_or_init(move || Mutex::new(memset))
        .lock()
        .enable()?;

    PATCH_ALLOC_MEMMOVE
        .get_or_init(move || Mutex::new(memmove))
        .lock()
        .enable()?;

    PATCH_ALLOC_MEMMOVE_S
        .get_or_init(move || Mutex::new(memmove_s))
        .lock()
        .enable()?;

    PATCH_ALLOC_MEMCPY_S
        .get_or_init(move || Mutex::new(memcpy_s))
        .lock()
        .enable()?;

    PATCH_MM_ALLOC
        .get_or_init(move || Mutex::new(mm_alloc))
        .lock()
        .enable()?;
    PATCH_MM_DEALLOC
        .get_or_init(move || Mutex::new(mm_dealloc))
        .lock()
        .enable()?;
    PATCH_MM_MSIZE
        .get_or_init(move || Mutex::new(mm_msize))
        .lock()
        .enable()?;

    PATCH_SH_ALLOC
        .get_or_init(move || Mutex::new(sh_alloc))
        .lock()
        .enable()?;
    PATCH_SH_DEALLOC
        .get_or_init(move || Mutex::new(sh_dealloc))
        .lock()
        .enable()?;

    configure_mimalloc_for_fo4();

    Ok(())
}

pub fn configure_mimalloc_for_fo4() {
    use libmimalloc::*;
    unsafe {
        // Large OS pages: 2-4MB pages for better texture streaming
        // Significantly improves performance for large allocations
        mi_option_set(mi_option_large_os_pages, 1);

        // Reserve huge OS pages: 1GB pages for maximum performance
        // Adjust based on system RAM (4GB = 4 huge pages)
        mi_option_set(mi_option_reserve_huge_os_pages, 4);

        // Eager commit delay: Delay initial segments to not use huge pages
        // Prevents short-lived threads from wasting huge page space
        mi_option_set(mi_option_eager_commit_delay, 2);
    }

    log::info!("MiMalloc configured for Fallout 4 with documented options");
}
