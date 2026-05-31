//! `psycho_engine_fixes.dll` entry point and helper-facing service ABI.
//!
//! `PsychoLoader_ModInit` is the only setup entrypoint. The xNVSE helper may
//! call the service API later for commands and messages, but it must not own or
//! trigger core initialization.

use core::{
    cell::UnsafeCell,
    mem::size_of,
    sync::atomic::{AtomicU8, Ordering},
};

use shadow_rs::shadow;

use crate::{
    config::{DiagnosticsConfig, MemoryConfig, PerformanceConfig, load_config},
    mods::{
        display::{install_display_hooks, observe_event as observe_display_event},
        heap_replacer::{
            AllocatorMode, decide_mode, initialize_mimalloc, install_gheap_hooks,
            install_gheap_initialize, install_sheap_hooks, install_sheap_initialize,
        },
        perf::{install_rng_hook, mark_init_start, observe_event as observe_perf_event},
        zlib::install_zlib_hooks,
    },
};
use libpsycho::{
    common::exe_version::ExeVersion,
    logger::Logger,
    os::windows::winapi::{HModule, alloc_console, disable_thread_library_calls},
};
use psycho_engine_fixes_api::{
    PSYCHO_CHUNK_CLAIMED, PSYCHO_EVENT_DEFERRED_INIT, PSYCHO_MAX_CHUNKS, PSYCHO_STATE_READY,
    PsychoApi, PsychoClaim, PsychoEvent, PsychoState,
};
use psycho_loader_api::{PSYCHO_LOADER_API_VERSION, PSYCHO_LOADER_MAGIC, PsychoLoaderInfo};

shadow!(build_info);

const MB: usize = 1024 * 1024;
const INIT_NOT_STARTED: u8 = 0;
const INIT_RUNNING: u8 = 1;
const INIT_DONE: u8 = 2;
const INIT_FAILED: u8 = 3;
const FNV_RUNTIME_VERSION_1_4_0_525: u32 = 0x0400_20D0;

struct Shared<T>(UnsafeCell<T>);

unsafe impl<T> Sync for Shared<T> {}

static STATE: Shared<PsychoState> = Shared(UnsafeCell::new(PsychoState::new()));
static INIT_STATE: AtomicU8 = AtomicU8::new(INIT_NOT_STARTED);
static API: PsychoApi = PsychoApi::new(
    PsychoEngineFixes_GetState,
    psycho_claim_chunk,
    psycho_notify,
    crate::command_api::run_command,
);

#[unsafe(no_mangle)]
pub unsafe extern "system" fn PsychoEngineFixes_GetApi() -> *const PsychoApi {
    &API
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn PsychoEngineFixes_GetState() -> *const PsychoState {
    STATE.0.get()
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn PsychoLoader_ModInit(info: *const PsychoLoaderInfo) -> i32 {
    let Some(module) = validate_loader_info(info) else {
        return 0;
    };

    let _ = disable_thread_library_calls(module);
    unsafe { mark_loader_ready() };

    initialize_engine_fixes_once()
}

fn validate_loader_info(info: *const PsychoLoaderInfo) -> Option<HModule> {
    let info = unsafe { info.as_ref() }?;
    if info.magic != PSYCHO_LOADER_MAGIC
        || info.version != PSYCHO_LOADER_API_VERSION
        || info.size < size_of::<PsychoLoaderInfo>() as u32
        || info.mod_module == 0
    {
        return None;
    }

    unsafe { HModule::new(info.mod_module as *mut core::ffi::c_void) }.ok()
}

unsafe fn mark_loader_ready() {
    let state = unsafe { &mut *STATE.0.get() };
    state.flags |= PSYCHO_STATE_READY;
}

fn initialize_engine_fixes_once() -> i32 {
    match INIT_STATE.load(Ordering::Acquire) {
        INIT_DONE => return 1,
        INIT_FAILED => return 0,
        INIT_RUNNING => return wait_for_init(),
        _ => {}
    }

    if INIT_STATE
        .compare_exchange(
            INIT_NOT_STARTED,
            INIT_RUNNING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return wait_for_init();
    }

    match initialize_engine_fixes() {
        Ok(()) => {
            INIT_STATE.store(INIT_DONE, Ordering::Release);
            1
        }
        Err(err) => {
            eprintln!("psycho: Failed to initialize engine fixes: {:?}", err);
            INIT_STATE.store(INIT_FAILED, Ordering::Release);
            0
        }
    }
}

fn wait_for_init() -> i32 {
    while INIT_STATE.load(Ordering::Acquire) == INIT_RUNNING {
        std::thread::yield_now();
    }

    if INIT_STATE.load(Ordering::Acquire) == INIT_DONE {
        1
    } else {
        0
    }
}

fn initialize_engine_fixes() -> anyhow::Result<()> {
    let cfg = load_config();

    initialize_logging(&cfg.diagnostics)?;
    mark_init_start();

    log::info!("[INIT] Engine fixes startup");
    log_early_state();

    initialize_diagnostics(&cfg.diagnostics)?;
    initialize_memory(&cfg.memory)?;
    install_runtime_hooks(&cfg.performance)?;

    log::info!(
        "Runtime {}",
        ExeVersion::from_u32(FNV_RUNTIME_VERSION_1_4_0_525)
    );
    log_build_info();
    log::info!("[INIT] Engine fixes initialized");

    Ok(())
}

fn initialize_logging(diagnostics: &DiagnosticsConfig) -> anyhow::Result<()> {
    let log_level = if diagnostics.debug_log {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    if let Err(err) = Logger::new()
        .with_file_rotating("./psycho-engine-fixes-latest.log")
        .with_level(log_level)
        .init()
    {
        anyhow::bail!("logger init failed: {:?}", err);
    }

    Logger::start_deferred();
    Ok(())
}

fn initialize_diagnostics(diagnostics: &DiagnosticsConfig) -> anyhow::Result<()> {
    if diagnostics.console {
        alloc_console()?;
    }

    Ok(())
}

fn initialize_memory(memory: &MemoryConfig) -> anyhow::Result<()> {
    match decide_mode(memory) {
        AllocatorMode::GheapAndScrapHeap => initialize_gheap_and_scrap_heap(),
        AllocatorMode::ScrapHeap => initialize_scrap_heap(),
        AllocatorMode::Disabled => {
            log::info!("[MEMORY] Heap allocator replacement disabled");
            Ok(())
        }
    }
}

fn initialize_gheap_and_scrap_heap() -> anyhow::Result<()> {
    // Mimalloc handles CRT allocations. Game objects stay in gheap/scrap_heap.
    initialize_mimalloc();

    install_gheap_initialize()?;
    install_sheap_initialize()?;
    install_gheap_hooks()?;
    install_sheap_hooks()?;

    Ok(())
}

fn initialize_scrap_heap() -> anyhow::Result<()> {
    initialize_mimalloc();

    install_sheap_initialize()?;
    install_sheap_hooks()?;

    Ok(())
}

fn install_runtime_hooks(performance: &PerformanceConfig) -> anyhow::Result<()> {
    if performance.rng {
        install_rng_hook()?;
    }

    if performance.zlib {
        install_zlib_hooks(false)?;
    }

    if performance.display_tweaks
        && let Err(err) = install_display_hooks()
    {
        log::warn!("[DISPLAY] Alt-tab fix disabled: {}", err);
    }

    Ok(())
}

unsafe extern "system" fn psycho_claim_chunk(
    min_size: usize,
    align: usize,
    out: *mut PsychoClaim,
) -> i32 {
    if out.is_null() {
        return 0;
    }

    let state = unsafe { &mut *STATE.0.get() };
    let align = align.max(1);
    let count = (state.chunk_count as usize).min(PSYCHO_MAX_CHUNKS);

    for index in 0..count {
        let chunk = &mut state.chunks[index];
        if chunk.base == 0 || chunk.size < min_size {
            continue;
        }

        if chunk.flags & PSYCHO_CHUNK_CLAIMED != 0 {
            continue;
        }

        if chunk.base % align != 0 {
            continue;
        }

        chunk.flags |= PSYCHO_CHUNK_CLAIMED;
        unsafe {
            *out = PsychoClaim {
                base: chunk.base,
                size: chunk.size,
                index: index as u32,
                flags: chunk.flags,
            };
        }

        return 1;
    }

    0
}

unsafe extern "system" fn psycho_notify(event: *const PsychoEvent) -> i32 {
    let Some(event) = (unsafe { event.as_ref() }) else {
        return 0;
    };

    let data = event_data(event);
    observe_perf_event(event.kind, data, event.bool_value);
    observe_display_event(event.kind);

    if event.kind == PSYCHO_EVENT_DEFERRED_INIT {
        log::info!("[EVENT] Game engine ready");
    }

    1
}

fn event_data(event: &PsychoEvent) -> Option<&str> {
    if event.data.is_null() || event.data_len == 0 {
        return None;
    }

    let bytes = unsafe { std::slice::from_raw_parts(event.data, event.data_len) };
    std::str::from_utf8(bytes).ok()
}

fn log_early_state() {
    let state = unsafe { &*STATE.0.get() };
    log::info!(
        "[EARLY] psycho_engine_fixes.dll ready: chunks={} reserved={}MB flags=0x{:x} last_error={}",
        state.chunk_count,
        state.total_reserved / MB,
        state.flags,
        state.last_error
    );
}

fn log_build_info() {
    log::info!("========================================================");
    log::info!("");
    log::info!("   P S Y C H O");
    log::info!("");
    log::info!("========================================================");
    log::info!("        Commit: {}", build_info::COMMIT_HASH);
    log::info!("        Branch: {}", build_info::BRANCH);
    log::info!("    Build date: {}", build_info::BUILD_TIME);
    log::info!("  Rust version: {}", build_info::RUST_VERSION);
    log::info!("  Rust channel: {}", build_info::RUST_CHANNEL);
    log::info!("  Build target: {}", build_info::BUILD_TARGET);
    log::info!("      Build OS: {}", build_info::BUILD_OS);
    log::info!("========================================================");
}
