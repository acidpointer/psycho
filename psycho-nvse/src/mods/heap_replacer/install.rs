//! Two-phase hook installation for the heap replacer, split into
//! independent gheap and sheap install paths.
//!
//! Phase 1 (Preload): initialize infrastructure and prepare hook
//! trampolines. No JMPs are written -- the game's original code paths
//! remain active. Any allocations between Preload and Load go through
//! the original game heap and are routed correctly on free via the
//! heap_validate fallback.
//!
//! Phase 2 (Load): enable the prepared hooks (write JMPs) and apply
//! the matching patches. After this point every hooked game operation
//! routes through our code.
//!
//! Gheap and sheap are installed independently so the caller can pick
//! "full" (both) or "light" (sheap only, for heavy modlists whose
//! baseline commit can't survive gheap's full footprint).

use libc::c_void;

use libpsycho::os::windows::winapi::{get_module_handle_a, patch_bytes, patch_nop_call, patch_ret};

use super::{gheap, scrap_heap};

// ---------------------------------------------------------------------------
// GHEAP -- Phase 1: initialize (NVSEPlugin_Preload)
// ---------------------------------------------------------------------------

/// Reserves gheap tier VAS, caches process heap handles, and prepares
/// all gheap-related hook trampolines. No game code is redirected yet.
///
/// NOTE: cleanup_sbm_arenas() is intentionally NOT called from here.
/// The premise "SBM state is fully consistent at this point" was true
/// when install ran inside DllMain (loader lock held -- no other thread
/// could touch the SBM). With install moved to NVSEPlugin_Preload the
/// loader lock is released, BSTaskManager / IO worker threads are
/// already alive, and walking the SBM_POOL_TABLE racing the SBM's own
/// refcount tracker decommits pages the SBM still has on its freelist.
/// Next SBM allocation that pops one of those pages returns memory we
/// already MEM_DECOMMIT'd -- first store into the cell faults, often
/// visible as a memcpy with a freshly-NULLed source against a static
/// BSTCommonMessageQueue<BSPackedTask> slot. The function is left in
/// place for a future correctly-sequenced reclamation pass.
pub fn install_gheap_initialize() -> anyhow::Result<()> {
    // Pool allocator: each class reserves its own VA aligned to POOL_ALIGN.
    if !gheap::pool::init() {
        return Err(anyhow::anyhow!("Pool allocator initialization failed"));
    }

    // Block allocator: single contiguous tier reservation. Keeps all
    // medium allocations in one VA island instead of scattering
    // 16 MB reservations across free VAS per save-load burst.
    if !gheap::block::init() {
        log::warn!(
            "[HEAP REPLACER] Block tier reservation failed; medium \
             allocations will fall through to va_alloc"
        );
    }

    gheap::crash_diag::install();

    // Cache process heap handles so free/msize/realloc can route pre-hook
    // pointers back to the correct Windows heap after hooks go live.
    super::heap_validate::init_heap_cache();

    // Trigger LazyLock construction for pressure relief singleton.
    gheap::pressure::PressureRelief::instance();

    // -- prepare hook trampolines (saves original bytes, allocates JMP stubs) --

    // game heap alloc/free/msize/realloc
    {
        use gheap::hooks::*;
        use gheap::statics::*;

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
    }

    // main loop frame hooks
    {
        use gheap::statics::*;

        MAIN_LOOP_MAINTENANCE_HOOK.init(
            "main_loop_maintenance",
            MAIN_LOOP_MAINTENANCE_ADDR as *mut c_void,
            gheap::hooks::hook_main_loop_maintenance,
        )?;
        PER_FRAME_QUEUE_DRAIN_HOOK.init(
            "per_frame_queue_drain",
            PER_FRAME_QUEUE_DRAIN_ADDR as *mut c_void,
            gheap::hooks::hook_per_frame_queue_drain,
        )?;
    }

    // ai thread sync
    {
        use gheap::statics::*;

        AI_THREAD_START_HOOK.init(
            "ai_thread_start",
            AI_THREAD_START_ADDR as *mut c_void,
            gheap::hooks::hook_ai_thread_start,
        )?;
        AI_THREAD_JOIN_HOOK.init(
            "ai_thread_join",
            AI_THREAD_JOIN_ADDR as *mut c_void,
            gheap::hooks::hook_ai_thread_join,
        )?;
    }

    // OOM Stage 8 (HeapCompact) -- safe BSTaskManagerThread semaphore release
    {
        use gheap::statics::*;

        OOM_STAGE_EXEC_HOOK.init(
            "oom_stage_exec",
            OOM_STAGE_EXEC_HOOK_ADDR as *mut c_void,
            gheap::hooks::hook_oom_stage_exec,
        )?;
    }

    // texture cache dead set
    {
        use gheap::statics::*;

        TEXTURE_CACHE_FIND_HOOK.init(
            "texture_cache_find",
            TEXTURE_CACHE_FIND_ADDR as *mut c_void,
            gheap::texture_cache::hook_texture_cache_find,
        )?;
        NISOURCETEXTURE_DTOR_HOOK.init(
            "nisourcetexture_dtor",
            NISOURCETEXTURE_DTOR_ADDR as *mut c_void,
            gheap::texture_cache::hook_nisourcetexture_dtor,
        )?;
    }

    // CRT inline hooks
    {
        use super::crt_inline::*;

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
    }

    // CRT IAT hooks
    {
        use super::crt_iat::*;
        let module_base = get_module_handle_a(None)?.as_ptr();

        unsafe {
            MALLOC_IAT_HOOK.init("malloc", module_base, None, "malloc", hook_malloc)?;
            CALLOC_IAT_HOOK.init("calloc", module_base, None, "calloc", hook_calloc)?;
            REALLOC_IAT_HOOK.init("realloc", module_base, None, "realloc", hook_realloc)?;
            RECALLOC_IAT_HOOK.init("_recalloc", module_base, None, "_recalloc", hook_recalloc)?;
            FREE_IAT_HOOK.init("free", module_base, None, "free", hook_free)?;
            MSIZE_IAT_HOOK.init("_msize", module_base, None, "_msize", hook_msize)?;
        }
    }

    // havok world lock tracking
    {
        use gheap::hooks::{hook_hkworld_lock, hook_hkworld_unlock};
        use gheap::statics::*;

        HKWORLD_LOCK_HOOK.init(
            "hkworld_lock",
            HKWORLD_LOCK_ADDR as *mut c_void,
            hook_hkworld_lock,
        )?;
        HKWORLD_UNLOCK_HOOK.init(
            "hkworld_unlock",
            HKWORLD_UNLOCK_ADDR as *mut c_void,
            hook_hkworld_unlock,
        )?;
    }

    // havok vanilla-bug shim (NULL hkpEntity in addEntityBatch result array)
    {
        use gheap::statics::*;

        HAVOK_ENTITY_POST_ADD_HOOK.init(
            "havok_entity_post_add",
            HAVOK_ENTITY_POST_ADD_ADDR as *mut c_void,
            gheap::havok_fix::hook_havok_entity_post_add,
        )?;
    }

    // game-inlined _memset NULL-dst defensive shim
    {
        use gheap::statics::*;

        MEMSET_HOOK.init(
            "memset_null_guard",
            MEMSET_ADDR as *mut c_void,
            gheap::memset_fix::hook_memset,
        )?;
    }

    log::info!("[GHEAP] Infrastructure initialized, trampolines prepared");
    Ok(())
}

// ---------------------------------------------------------------------------
// GHEAP -- Phase 2: activate (NVSEPlugin_Load)
// ---------------------------------------------------------------------------

/// Writes JMPs at all gheap hook targets, applies SBM-disable patches,
/// and starts background monitoring threads. After this returns, every
/// game heap operation routes through gheap.
pub fn install_gheap_activate() -> anyhow::Result<()> {
    // game heap
    {
        use super::gheap::statics::*;

        GHEAP_ALLOC_HOOK.enable()?;
        GHEAP_FREE_HOOK.enable()?;
        GHEAP_MSIZE_HOOK.enable()?;
        GHEAP_REALLOC_HOOK_1.enable()?;
        GHEAP_REALLOC_HOOK_2.enable()?;
        log::info!("[GHEAP] GameHeap hooks active");
    }

    // frame hooks
    {
        use gheap::statics::*;

        MAIN_LOOP_MAINTENANCE_HOOK.enable()?;
        PER_FRAME_QUEUE_DRAIN_HOOK.enable()?;
        log::info!("[HOOKS] Frame hooks active");
    }

    // ai sync
    {
        use gheap::statics::*;

        AI_THREAD_START_HOOK.enable()?;
        AI_THREAD_JOIN_HOOK.enable()?;
        log::info!("[SYNC] AI start/join hooks active");
    }

    // OOM Stage 8
    {
        use gheap::statics::*;

        OOM_STAGE_EXEC_HOOK.enable()?;
        log::info!("[OOM] Stage 8 safe handler active");
    }

    // texture cache
    {
        use super::gheap::statics::*;

        TEXTURE_CACHE_FIND_HOOK.enable()?;
        NISOURCETEXTURE_DTOR_HOOK.enable()?;
        log::info!("[TEXTURE] Dead set hooks active");
    }

    // CRT IAT
    {
        use super::crt_iat::*;

        MALLOC_IAT_HOOK.enable()?;
        CALLOC_IAT_HOOK.enable()?;
        REALLOC_IAT_HOOK.enable()?;
        RECALLOC_IAT_HOOK.enable()?;
        FREE_IAT_HOOK.enable()?;
        MSIZE_IAT_HOOK.enable()?;

        log::info!("[CRT] IAT hooks active");
    }

    // CRT inline
    {
        use super::crt_inline::*;

        MALLOC_HOOK_1.enable()?;
        MALLOC_HOOK_2.enable()?;
        CALLOC_HOOK_1.enable()?;
        CALLOC_HOOK_2.enable()?;
        REALLOC_HOOK_1.enable()?;
        REALLOC_HOOK_2.enable()?;
        RECALLOC_HOOK_1.enable()?;
        RECALLOC_HOOK_2.enable()?;
        FREE_HOOK.enable()?;
        MSIZE_HOOK.enable()?;
        log::info!("[CRT] Inline CRT hooks active");
    }

    // havok world lock
    {
        use gheap::statics::*;

        HKWORLD_LOCK_HOOK.enable()?;
        HKWORLD_UNLOCK_HOOK.enable()?;
        log::info!("[HAVOK] World lock hooks active");
    }

    // havok vanilla-bug shim
    {
        use gheap::statics::*;

        HAVOK_ENTITY_POST_ADD_HOOK.enable()?;
        log::info!("[HAVOK] FUN_00CFFA00 NULL-entity guard active");
    }

    // _memset NULL-dst defensive shim
    {
        use gheap::statics::*;

        MEMSET_HOOK.enable()?;
        log::info!("[CRT] _memset NULL-dst guard active");
    }

    // SBM disable patches (must be after hooks are active)
    apply_gheap_patches()?;

    start_deferred_threads();

    log::info!("[GHEAP] All hooks and patches applied");
    Ok(())
}

// ---------------------------------------------------------------------------
// SHEAP -- Phase 1: initialize (NVSEPlugin_Preload)
// ---------------------------------------------------------------------------

/// Prepare scrap-heap hook trampolines. Cheap and independent from
/// gheap: six hooks, no VA reservation, no auxiliary threads.
pub fn install_sheap_initialize() -> anyhow::Result<()> {
    use scrap_heap::*;

    // optional -- another mod may have already patched 0xAA42E0
    if let Err(e) = GET_THREAD_LOCAL_HOOK.init(
        "sheap_get_thread_local",
        SHEAP_GET_THREAD_LOCAL_ADDR as *mut c_void,
        hook_get_thread_local,
    ) {
        log::warn!("[SHEAP] sheap_get_thread_local init skipped: {:?}", e);
    }
    INIT_FIX_HOOK.init(
        "sheap_init_fix",
        SHEAP_INIT_FIX_ADDR as *mut c_void,
        hook_init_fix,
    )?;
    INIT_VAR_HOOK.init(
        "sheap_init_var",
        SHEAP_INIT_VAR_ADDR as *mut c_void,
        hook_init_var,
    )?;
    ALLOC_HOOK.init("sheap_alloc", SHEAP_ALLOC_ADDR as *mut c_void, hook_alloc)?;
    FREE_HOOK.init("sheap_free", SHEAP_FREE_ADDR as *mut c_void, hook_free)?;
    PURGE_HOOK.init("sheap_purge", SHEAP_PURGE_ADDR as *mut c_void, hook_purge)?;

    log::info!("[SHEAP] Infrastructure initialized, trampolines prepared");
    Ok(())
}

// ---------------------------------------------------------------------------
// SHEAP -- Phase 2: activate (NVSEPlugin_Load)
// ---------------------------------------------------------------------------

/// Enable scrap-heap JMPs and apply the embedded-sheap constructor
/// NOP patch. Required whenever the sheap hooks are active -- see
/// `apply_sheap_patches` for the rationale.
pub fn install_sheap_activate() -> anyhow::Result<()> {
    use scrap_heap::*;

    // optional -- skip if init failed (another mod patched the address)
    if GET_THREAD_LOCAL_HOOK.enable().is_err() {
        log::warn!("[SHEAP] sheap_get_thread_local enable skipped");
    }
    INIT_FIX_HOOK.enable()?;
    INIT_VAR_HOOK.enable()?;
    ALLOC_HOOK.enable()?;
    FREE_HOOK.enable()?;
    PURGE_HOOK.enable()?;
    log::info!("[SHEAP] Scrap heap hooks active");

    apply_sheap_patches()?;

    log::info!("[SHEAP] All hooks and patches applied");
    Ok(())
}

// ---------------------------------------------------------------------------
// Deferred thread startup
// ---------------------------------------------------------------------------

/// Start background monitoring threads. Must be called outside DllMain
/// (loader lock prevents thread creation).
fn start_deferred_threads() {
    std::mem::forget(gheap::watchdog::Watchdog::start());
    log::info!("[HEAP REPLACER] Watchdog thread started");
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Decommit SBM arena pages with zero live blocks.
///
/// HISTORICAL NOTE: this used to be called from `heap_replacer_initialize`
/// when install ran inside DllMain. With install moved to Preload it races
/// against live worker threads still allocating from the SBM, so the call
/// was removed (see comment in `install_gheap_initialize`). The function
/// is kept for a future correctly-sequenced reclamation pass.
#[allow(dead_code)]
fn cleanup_sbm_arenas() {
    use windows::Win32::System::Memory::{VirtualFree, MEM_DECOMMIT};

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
                let ok = unsafe { VirtualFree(page_addr as *mut c_void, 0x1000, MEM_DECOMMIT) };
                if ok.is_ok() {
                    decommitted_pages += 1;
                }
            }
        }
    }

    let freed_mb = (decommitted_pages * 0x1000) / 1024 / 1024;
    log::debug!(
        "[SBM] Arena cleanup: {} pools, {} total pages, {} decommitted ({}MB freed)",
        pools_found,
        total_pages,
        decommitted_pages,
        freed_mb,
    );
}

/// Disable the SBM small-block allocator. Only safe to apply when
/// gheap is active, because gheap owns the replacement allocation path
/// these patches remove.
fn apply_gheap_patches() -> anyhow::Result<()> {
    unsafe {
        // RET patches: disable SBM functions that are pure overhead
        patch_ret(0x00AA6840 as *mut c_void)?; // SBM stats reset
        patch_ret(0x00866770 as *mut c_void)?; // SBM config table init
        patch_ret(0x00866E00 as *mut c_void)?; // SBM-related init
        patch_ret(0x00866D10 as *mut c_void)?; // Get SBM singleton
        patch_ret(0x00AA7030 as *mut c_void)?; // GlobalCleanup (shutdown only)
        patch_ret(0x00AA5C80 as *mut c_void)?; // DeallocateAllArenas (shutdown only)
        patch_ret(0x00AA58D0 as *mut c_void)?; // Sheap SBM cleanup

        // SBM arena management -- dead code with GlobalCleanup ret-patched.
        patch_ret(0x00AA6F90 as *mut c_void)?; // PurgeUnusedArenas
        patch_ret(0x00AA7290 as *mut c_void)?; // DecrementArenaRef
        patch_ret(0x00AA7300 as *mut c_void)?; // ReleaseArenaByPtr

        // Disable SBM small alloc fast path flag.
        // Belt-and-suspenders: our hook at function entry already bypasses it.
        let fast_path_flag = (gheap::engine::addr::HEAP_SINGLETON + 0x129) as *mut u8;
        fast_path_flag.write_volatile(0);

        // NOP patches: skip redundant heap construction/init calls
        patch_nop_call(0x0086C56F as *mut c_void)?;
        patch_nop_call(0x00C42EB1 as *mut c_void)?;
        patch_nop_call(0x00EC1701 as *mut c_void)?;

        // Skip the late-init singleton allocation in FUN_00aa3050.
        //
        // FUN_00aa3050 is a one-time-init gate that calls FUN_00aa2020,
        // which does `DAT_011f6080 = game_heap_allocate(&DAT_011f6238, 4)`
        // and then fills the 4-byte slot with a singleton pointer + invokes
        // a virtual method through it. `FUN_00aa2020` has a second
        // caller at 0x00866734 that runs during HeapSingleton startup
        // (before our hooks are fully active) -- that call we leave alone
        // so the singleton gets initialised once with vanilla-SBM memory.
        // The 0x00AA3060 call would re-run the allocation through our
        // pool and expose the long-lived `*DAT_011f6080` pointer to
        // pool-reuse races if the 4-byte cell ever gets freed.
        //
        // Matches NVHR `patch_nop_call((void *)0x00AA3060)` in
        // Heap-Replacer/main/heap_replacer.h. Verified via Ghidra in
        // analysis/ghidra/output/memory/verify_nvhr_patch_0x00AA3060.txt.
        patch_nop_call(0x00AA3060 as *mut c_void)?;

        // Skip per-frame SBM arena management (JMP +0x55 over the stale loop).
        patch_bytes(0x0086EED4 as *mut c_void, &[0xEB, 0x55])?;
    }

    log::info!("[GHEAP] SBM patches applied (10 RET + 4 NOP-call + 1 JMP + fast path disabled)");
    Ok(())
}

/// Patches required whenever scrap-heap hooks are active, regardless
/// of gheap. The embedded scrap-heap constructor lives inside the
/// HeapSingleton constructor and is independent of the SBM tier.
fn apply_sheap_patches() -> anyhow::Result<()> {
    unsafe {
        // Skip the embedded scrap-heap constructor at HeapSingleton+0x114.
        //
        // The HeapSingleton constructor (FUN_00aa3880, called once from
        // a CRT global initialiser at 0x00fb66a8) contains a 30-byte
        // sequence that constructs a secondary scrap-heap instance at
        // offset +0x114 of the HeapSingleton and installs its vtable.
        // Our sheap_alloc/sheap_free hooks (0x00AA54A0 / 0x00AA5610)
        // replace the primary sheap but not this embedded secondary one.
        // If it's constructed, game paths that dereference
        // `*(HeapSingleton+0x114)` touch state outside our allocator's
        // awareness. The surrounding `_memset(param_1+0xc, 0, 0x108)`
        // already zeros the HeapSingleton up to +0x114, so replacing
        // the constructor with NOPs leaves the embedded sheap field
        // at its clean zero-init state.
        //
        // Matches NVHR `patch_nops((void *)0x00AA38CA, 0x00AA38E8 -
        // 0x00AA38CA)`. Verified via Ghidra in
        // analysis/ghidra/output/memory/verify_nvhr_patch_0x00AA38CA.txt.
        patch_bytes(0x00AA38CA as *mut c_void, &[0x90u8; 30])?;
    }

    log::info!("[SHEAP] Embedded scrap-heap constructor NOP applied");
    Ok(())
}
