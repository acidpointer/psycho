//! Startup/loading latency patches and attribution.

use std::{
    cell::RefCell,
    ffi::CStr,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
};

use libc::{c_char, c_void};
use libpsycho::ffi::fnptr::FnPtr;
use libpsycho::os::windows::hook::iat::iathook::IatHookContainer;
use libpsycho::os::windows::hook::inline::inlinehook::InlineHookContainer;
use libpsycho::os::windows::winapi::{
    flush_instructions_cache, get_module_handle_a, get_proc_address_in_dll, safe_write_8,
    safe_write_32,
};
use parking_lot::Mutex;
use psycho_engine_fixes_api::{
    PSYCHO_EVENT_DEFERRED_INIT, PSYCHO_EVENT_LOAD_GAME, PSYCHO_EVENT_MAIN_GAME_LOOP,
    PSYCHO_EVENT_ON_FRAME_PRESENT, PSYCHO_EVENT_POST_LOAD_GAME, PSYCHO_EVENT_PRE_LOAD_GAME,
};
use windows::Win32::{
    Foundation::FILETIME,
    System::{
        SystemInformation::GetSystemTimeAsFileTime,
        Threading::{GetCurrentProcess, GetProcessTimes},
    },
};

const MODEL_LOADER_SLEEP_PUSH_ADDR: usize = 0x00C3E105;
const MODEL_LOADER_SLEEP_IMM_ADDR: usize = 0x00C3E106;
const PUSH_IMM8_OPCODE: u8 = 0x6A;
const VANILLA_SLEEP_MS: u8 = 50;
const FAST_SLEEP_MS: u8 = 10;

const COMPLETION_DRAIN_BUDGET_MOV_ADDR: usize = 0x00C3DCA9;
const COMPLETION_DRAIN_BUDGET_PTR_IMM_ADDR: usize = 0x00C3DCAF;
const MOV_DWORD_EBP_DISP_IMM_OPCODE: u8 = 0xC7;
const MOV_DWORD_EBP_DISP_IMM_MODRM: u8 = 0x85;
const COMPLETION_DRAIN_BUDGET_LOCAL_DISP: u32 = 0xFFFFFF68;
const VANILLA_COMPLETION_DRAIN_BUDGET_PTR: u32 = 0x01202800;
const COMPLETION_DRAIN_BUDGET_MS: u32 = 2;

const ENGINE_PROGRESS_FN_ADDR: usize = 0x0040FBE0;
const REL_CALL_OPCODE: u8 = 0xE8;
const STATIC_TEXT_START: usize = 0x01000000;
const STATIC_TEXT_END: usize = 0x01200000;

const STARTUP_PHASE_MARKERS: &[(usize, &str)] = &[
    (0x0086B01A, "Initializing Renderer"),
    (0x0086BF78, "Initializing Shader System"),
    (0x0086CFFC, "Initializing TES"),
    (0x0086D080, "Initializing TreeManager"),
    (0x0086D097, "Activating Tasklet Threads"),
    (0x0086D294, "Loading Files"),
    (0x0086D2F5, "Initializing Player"),
    (0x0086D400, "Initializing Scripts"),
    (0x0086B1E1, "Initializing Actor Locations"),
    (0x0086B210, "Loading initial area"),
    (0x0086B230, "Placing player"),
    (0x0086B2D1, "Begin Idle loop"),
];
const STARTUP_PHASE_UNKNOWN: u32 = u32::MAX;
const SLOW_TEXTURE_SAMPLES: usize = 5;

const START_MENU_CHECK_ADDR: usize = 0x0070EDF0;
const MENU_VISIBILITY_ARRAY: usize = 0x011F308F;
const TILE_MENU_ARRAY_DATA_PTR: usize = 0x011F350C;
const MENU_TYPE_MIN: usize = 0x3E9;
const MENU_TYPE_START: usize = 0x3F5;

type IsInStartMenuFn = unsafe extern "C" fn() -> u8;
type EngineProgressFn = unsafe extern "C" fn(*const i8);
type StartupFastcall1Fn = unsafe extern "fastcall" fn(*mut c_void);
type StartupCdecl0Fn = unsafe extern "C" fn();
type StartupThiscall1Fn = unsafe extern "thiscall" fn(*mut c_void);
type VertexShaderFn = unsafe extern "C" fn(*mut c_char, *mut c_void, u32, u32);
type PixelShaderFn = unsafe extern "C" fn(*mut c_char, *mut c_void, *mut c_char, u32);
type TextureLoadFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_char, *mut c_void, u32, *mut c_void);
type BsFileReadBufferFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void, u32) -> u32;
type TextureOpenFn = unsafe extern "C" fn(*mut c_char, u32, u32) -> *mut c_void;
type TextureTempAllocFn = unsafe extern "C" fn(u32) -> *mut c_void;
type TextureTempFreeFn = unsafe extern "C" fn(*mut c_void);

const INIT_RENDERER_ADDR: usize = 0x0086D500;
const SHADER_SYSTEM_INIT_ADDR: usize = 0x0086BF70;
const WORLD_RENDER_SETUP_ADDR: usize = 0x0086D590;
const IDLE_ANIM_SCAN_ADDR: usize = 0x0095EE80;
const CREATE_VERTEX_SHADER_ADDR: usize = 0x00BE0FE0;
const CREATE_PIXEL_SHADER_ADDR: usize = 0x00BE1750;
const TEXTURE_LOAD_ADDR: usize = 0x00E68A80;
const TEXTURE_OPEN_CALL_ADDR: usize = 0x00E68B62;
const TEXTURE_TEMP_ALLOC_CALL_ADDR: usize = 0x00E68BA9;
const TEXTURE_TEMP_FREE_FAIL_CALL_ADDR: usize = 0x00E68C13;
const TEXTURE_TEMP_FREE_FINAL_CALL_ADDR: usize = 0x00E68E2B;
const BSFILE_READ_BUFFER_ADDR: usize = 0x00462D80;
const D3DX_TEXTURE_CREATE_CALL_ADDR: usize = 0x00E68DCD;
const D3DX_CUBE_TEXTURE_CREATE_CALL_ADDR: usize = 0x00E68DF3;
const D3DX_VOLUME_TEXTURE_CREATE_CALL_ADDR: usize = 0x00E68E18;
const D3DX_TEXTURE_CREATE_IMPORT_THUNK: usize = 0x00EE6E1C;

type D3dxGetImageInfoFromMemoryFn =
    unsafe extern "stdcall" fn(*const c_void, u32, *mut c_void) -> i32;
type D3dxCreateTextureFromMemoryFn =
    unsafe extern "stdcall" fn(*mut c_void, *const c_void, u32, *mut *mut c_void) -> i32;
type D3dxCreateTextureFromMemoryExFn = unsafe extern "stdcall" fn(
    *mut c_void,
    *const c_void,
    u32,
    i32,
    i32,
    i32,
    u32,
    i32,
    i32,
    i32,
    i32,
    u32,
    *mut c_void,
    *mut c_void,
    *mut *mut c_void,
) -> i32;

static COMPLETION_DRAIN_BUDGET: u32 = COMPLETION_DRAIN_BUDGET_MS;

static INIT_TICK_MS: AtomicU32 = AtomicU32::new(0);
static DEFERRED_INIT_TICK_MS: AtomicU32 = AtomicU32::new(0);
static START_MENU_ACTIVE_TICK_MS: AtomicU32 = AtomicU32::new(0);
static PRESENT_FRAME_COUNT: AtomicU32 = AtomicU32::new(0);
static MAIN_MENU_VISIBLE_LOGGED: AtomicBool = AtomicBool::new(false);
static STARTUP_PHASE_MARKERS_INSTALLED: AtomicBool = AtomicBool::new(false);
static STARTUP_PROFILE_HOOKS_INSTALLED: AtomicBool = AtomicBool::new(false);
static TEXTURE_PIPELINE_PROBES_INSTALLED: AtomicBool = AtomicBool::new(false);
static TEXTURE_OPEN_PROBE_INSTALLED: AtomicBool = AtomicBool::new(false);
static TEXTURE_CALLSITE_PROBES_INSTALLED: AtomicBool = AtomicBool::new(false);
static LAST_STARTUP_PHASE_TICK_MS: AtomicU32 = AtomicU32::new(0);
static CURRENT_STARTUP_PHASE: AtomicU32 = AtomicU32::new(STARTUP_PHASE_UNKNOWN);
static SAVE_LOAD_PRE_TICK_MS: AtomicU32 = AtomicU32::new(0);
static SAVE_LOAD_GAME_TICK_MS: AtomicU32 = AtomicU32::new(0);
static TEXTURE_OPEN_TARGET: AtomicUsize = AtomicUsize::new(0);
static TEXTURE_TEMP_ALLOC_TARGET: AtomicUsize = AtomicUsize::new(0);
static TEXTURE_TEMP_FREE_TARGET: AtomicUsize = AtomicUsize::new(0);
static D3DX_TEXTURE_CREATE_TARGET: AtomicUsize = AtomicUsize::new(0);
static D3DX_CUBE_TEXTURE_CREATE_TARGET: AtomicUsize = AtomicUsize::new(0);
static D3DX_VOLUME_TEXTURE_CREATE_TARGET: AtomicUsize = AtomicUsize::new(0);

static INIT_RENDERER_HOOK: LazyLock<InlineHookContainer<StartupFastcall1Fn>> =
    LazyLock::new(InlineHookContainer::new);
static SHADER_SYSTEM_INIT_HOOK: LazyLock<InlineHookContainer<StartupCdecl0Fn>> =
    LazyLock::new(InlineHookContainer::new);
static WORLD_RENDER_SETUP_HOOK: LazyLock<InlineHookContainer<StartupThiscall1Fn>> =
    LazyLock::new(InlineHookContainer::new);
static IDLE_ANIM_SCAN_HOOK: LazyLock<InlineHookContainer<StartupThiscall1Fn>> =
    LazyLock::new(InlineHookContainer::new);
static CREATE_VERTEX_SHADER_HOOK: LazyLock<InlineHookContainer<VertexShaderFn>> =
    LazyLock::new(InlineHookContainer::new);
static CREATE_PIXEL_SHADER_HOOK: LazyLock<InlineHookContainer<PixelShaderFn>> =
    LazyLock::new(InlineHookContainer::new);
static TEXTURE_LOAD_HOOK: LazyLock<InlineHookContainer<TextureLoadFn>> =
    LazyLock::new(InlineHookContainer::new);
static BSFILE_READ_BUFFER_HOOK: LazyLock<InlineHookContainer<BsFileReadBufferFn>> =
    LazyLock::new(InlineHookContainer::new);
static D3DX_GET_IMAGE_INFO_IAT_HOOK: LazyLock<IatHookContainer<D3dxGetImageInfoFromMemoryFn>> =
    LazyLock::new(IatHookContainer::new);
static D3DX_CREATE_TEXTURE_IAT_HOOK: LazyLock<IatHookContainer<D3dxCreateTextureFromMemoryFn>> =
    LazyLock::new(IatHookContainer::new);
static D3DX_CREATE_TEXTURE_EX_HOOK: LazyLock<InlineHookContainer<D3dxCreateTextureFromMemoryExFn>> =
    LazyLock::new(InlineHookContainer::new);

struct StartupProbe {
    count: AtomicU32,
    total_ms: AtomicU32,
    max_ms: AtomicU32,
}

impl StartupProbe {
    const fn new() -> Self {
        Self {
            count: AtomicU32::new(0),
            total_ms: AtomicU32::new(0),
            max_ms: AtomicU32::new(0),
        }
    }

    fn record(&self, elapsed_ms: u32) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.total_ms.fetch_add(elapsed_ms, Ordering::Relaxed);
        update_max(&self.max_ms, elapsed_ms);
    }

    fn snapshot(&self) -> ProbeSnapshot {
        ProbeSnapshot {
            count: self.count.load(Ordering::Acquire),
            total_ms: self.total_ms.load(Ordering::Acquire),
            max_ms: self.max_ms.load(Ordering::Acquire),
        }
    }
}

#[derive(Clone, Copy)]
struct ProbeSnapshot {
    count: u32,
    total_ms: u32,
    max_ms: u32,
}

static INIT_RENDERER_PROBE: StartupProbe = StartupProbe::new();
static SHADER_SYSTEM_INIT_PROBE: StartupProbe = StartupProbe::new();
static WORLD_RENDER_SETUP_PROBE: StartupProbe = StartupProbe::new();
static IDLE_ANIM_SCAN_PROBE: StartupProbe = StartupProbe::new();
static CREATE_VERTEX_SHADER_PROBE: StartupProbe = StartupProbe::new();
static CREATE_PIXEL_SHADER_PROBE: StartupProbe = StartupProbe::new();
static TEXTURE_LOAD_PROBE: StartupProbe = StartupProbe::new();
static TEXTURE_OPEN_PROBE: StartupProbe = StartupProbe::new();
static TEXTURE_TEMP_ALLOC_PROBE: StartupProbe = StartupProbe::new();
static TEXTURE_TEMP_FREE_PROBE: StartupProbe = StartupProbe::new();
static TEXTURE_READ_BUFFER_PROBE: StartupProbe = StartupProbe::new();
static D3DX_IMAGE_INFO_PROBE: StartupProbe = StartupProbe::new();
static D3DX_CREATE_TEXTURE_PROBE: StartupProbe = StartupProbe::new();
static D3DX_CREATE_TEXTURE_EX_PROBE: StartupProbe = StartupProbe::new();
static D3DX_CREATE_TEXTURE_CALLSITE_PROBE: StartupProbe = StartupProbe::new();
static D3DX_CREATE_CUBE_TEXTURE_CALLSITE_PROBE: StartupProbe = StartupProbe::new();
static D3DX_CREATE_VOLUME_TEXTURE_CALLSITE_PROBE: StartupProbe = StartupProbe::new();

#[derive(Clone)]
struct TextureSample {
    elapsed_ms: u32,
    phase: u32,
    path: String,
}

#[derive(Clone)]
struct TextureContext {
    phase: u32,
    path: String,
}

#[derive(Clone)]
struct DdsSummary {
    width: u32,
    height: u32,
    mips: u32,
    format: String,
}

#[derive(Clone)]
struct TextureStageSample {
    stage: &'static str,
    elapsed_ms: u32,
    size: u32,
    phase: u32,
    path: String,
    dds: Option<DdsSummary>,
}

static SLOW_TEXTURE_LOADS: LazyLock<Mutex<Vec<TextureSample>>> =
    LazyLock::new(|| Mutex::new(Vec::with_capacity(SLOW_TEXTURE_SAMPLES)));
static SLOW_TEXTURE_STAGES: LazyLock<Mutex<Vec<TextureStageSample>>> =
    LazyLock::new(|| Mutex::new(Vec::with_capacity(SLOW_TEXTURE_SAMPLES)));

thread_local! {
    static CURRENT_TEXTURE_CONTEXT: RefCell<Option<TextureContext>> = const { RefCell::new(None) };
}

fn read_u8(addr: usize) -> u8 {
    unsafe { (addr as *const u8).read_volatile() }
}

fn read_u32(addr: usize) -> u32 {
    unsafe { (addr as *const u32).read_unaligned() }
}

fn read_i32(addr: usize) -> i32 {
    unsafe { (addr as *const i32).read_unaligned() }
}

fn relative_call_target(call_addr: usize) -> Option<usize> {
    if read_u8(call_addr) != REL_CALL_OPCODE {
        return None;
    }

    let rel = read_i32(call_addr + 1) as isize;
    Some(((call_addr + 5) as isize).wrapping_add(rel) as usize)
}

fn patch_relative_call(call_addr: usize, target_addr: usize) -> anyhow::Result<()> {
    let rel = (target_addr as isize).wrapping_sub((call_addr + 5) as isize) as u32;
    safe_write_32((call_addr + 1) as *mut c_void, rel)?;
    flush_instructions_cache(call_addr as *mut c_void, 5)?;
    Ok(())
}

fn patch_model_loader_wait() -> anyhow::Result<()> {
    let opcode = read_u8(MODEL_LOADER_SLEEP_PUSH_ADDR);
    let current_sleep = read_u8(MODEL_LOADER_SLEEP_IMM_ADDR);

    if opcode != PUSH_IMM8_OPCODE {
        log::warn!(
            "[LOADING] ModelLoader wait patch skipped: unexpected opcode 0x{:02X} at 0x{:08X}",
            opcode,
            MODEL_LOADER_SLEEP_PUSH_ADDR
        );
        return Ok(());
    }

    match current_sleep {
        VANILLA_SLEEP_MS => {
            safe_write_8(MODEL_LOADER_SLEEP_IMM_ADDR as *mut c_void, FAST_SLEEP_MS)?;
            flush_instructions_cache(MODEL_LOADER_SLEEP_PUSH_ADDR as *mut c_void, 2)?;
            log::info!(
                "[LOADING] ModelLoader wait reduced: {}ms -> {}ms",
                VANILLA_SLEEP_MS,
                FAST_SLEEP_MS
            );
        }
        FAST_SLEEP_MS => {
            log::info!(
                "[LOADING] ModelLoader wait already reduced: {}ms",
                FAST_SLEEP_MS
            );
        }
        other => {
            log::warn!(
                "[LOADING] ModelLoader wait patch skipped: unexpected value {}ms at 0x{:08X}",
                other,
                MODEL_LOADER_SLEEP_IMM_ADDR
            );
        }
    }

    Ok(())
}

fn patch_completion_drain_budget() -> anyhow::Result<()> {
    let opcode = read_u8(COMPLETION_DRAIN_BUDGET_MOV_ADDR);
    let modrm = read_u8(COMPLETION_DRAIN_BUDGET_MOV_ADDR + 1);
    let local_disp = read_u32(COMPLETION_DRAIN_BUDGET_MOV_ADDR + 2);
    let current_ptr = read_u32(COMPLETION_DRAIN_BUDGET_PTR_IMM_ADDR);
    let budget_ptr = (&raw const COMPLETION_DRAIN_BUDGET) as u32;

    if opcode != MOV_DWORD_EBP_DISP_IMM_OPCODE
        || modrm != MOV_DWORD_EBP_DISP_IMM_MODRM
        || local_disp != COMPLETION_DRAIN_BUDGET_LOCAL_DISP
    {
        log::warn!(
            "[LOADING] completion drain budget patch skipped: unexpected instruction at 0x{:08X}",
            COMPLETION_DRAIN_BUDGET_MOV_ADDR
        );
        return Ok(());
    }

    match current_ptr {
        VANILLA_COMPLETION_DRAIN_BUDGET_PTR => {
            safe_write_32(
                COMPLETION_DRAIN_BUDGET_PTR_IMM_ADDR as *mut c_void,
                budget_ptr,
            )?;
            flush_instructions_cache(COMPLETION_DRAIN_BUDGET_MOV_ADDR as *mut c_void, 10)?;
            log::info!(
                "[LOADING] completion drain budget set: fallback 0ms -> {}ms",
                COMPLETION_DRAIN_BUDGET_MS
            );
        }
        ptr if ptr == budget_ptr => {
            log::info!(
                "[LOADING] completion drain budget already set: {}ms",
                COMPLETION_DRAIN_BUDGET_MS
            );
        }
        other => {
            log::warn!(
                "[LOADING] completion drain budget patch skipped: unexpected pointer 0x{:08X} at 0x{:08X}",
                other,
                COMPLETION_DRAIN_BUDGET_PTR_IMM_ADDR
            );
        }
    }

    Ok(())
}

fn update_max(slot: &AtomicU32, value: u32) {
    let mut current = slot.load(Ordering::Relaxed);
    while value > current {
        match slot.compare_exchange_weak(current, value, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return,
            Err(next) => current = next,
        }
    }
}

fn should_profile_startup() -> bool {
    !MAIN_MENU_VISIBLE_LOGGED.load(Ordering::Acquire)
}

fn time_startup_call<R>(probe: &StartupProbe, call: impl FnOnce() -> R) -> R {
    if !should_profile_startup() {
        return call();
    }

    let start = now_tick_ms();
    let result = call();
    let elapsed = now_tick_ms().wrapping_sub(start);
    probe.record(elapsed);
    result
}

fn format_probe(snapshot: ProbeSnapshot) -> String {
    if snapshot.count == 0 {
        return "0".to_string();
    }

    format!(
        "{} calls, total={}, max={}",
        snapshot.count,
        format_duration(Some(snapshot.total_ms as u64)),
        format_duration(Some(snapshot.max_ms as u64))
    )
}

fn phase_id_from_message(message: &str) -> u32 {
    let message = message.trim_end_matches('.');
    for (index, &(_, name)) in STARTUP_PHASE_MARKERS.iter().enumerate() {
        if message == name {
            return index as u32;
        }
    }
    STARTUP_PHASE_UNKNOWN
}

fn phase_name(phase: u32) -> &'static str {
    if phase == STARTUP_PHASE_UNKNOWN {
        return "unknown";
    }

    STARTUP_PHASE_MARKERS
        .get(phase as usize)
        .map(|(_, name)| *name)
        .unwrap_or("unknown")
}

fn path_from_cstr(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return "<null>".to_string();
    }

    let raw = unsafe { CStr::from_ptr(ptr) }.to_string_lossy();
    let mut path = String::with_capacity(raw.len().min(180));

    for ch in raw.chars().take(180) {
        if ch.is_control() {
            path.push('?');
        } else {
            path.push(ch);
        }
    }

    if raw.len() > path.len() {
        path.push_str("...");
    }

    path
}

fn record_slow_texture(path: *const c_char, elapsed_ms: u32) {
    let mut samples = SLOW_TEXTURE_LOADS.lock();
    if samples.len() == SLOW_TEXTURE_SAMPLES {
        let Some((min_index, min_sample)) = samples
            .iter()
            .enumerate()
            .min_by_key(|(_, sample)| sample.elapsed_ms)
        else {
            return;
        };

        if elapsed_ms <= min_sample.elapsed_ms {
            return;
        }

        samples.remove(min_index);
    }

    samples.push(TextureSample {
        elapsed_ms,
        phase: CURRENT_STARTUP_PHASE.load(Ordering::Acquire),
        path: path_from_cstr(path),
    });
}

fn format_slow_textures() -> String {
    let mut samples = SLOW_TEXTURE_LOADS.lock().clone();
    if samples.is_empty() {
        return "none".to_string();
    }

    samples.sort_by(|left, right| right.elapsed_ms.cmp(&left.elapsed_ms));

    samples
        .iter()
        .enumerate()
        .map(|(index, sample)| {
            format!(
                "#{} {} @ {} '{}'",
                index + 1,
                format_duration(Some(sample.elapsed_ms as u64)),
                phase_name(sample.phase),
                sample.path
            )
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

unsafe fn read_u32_from_ptr(base: *const c_void, offset: usize) -> u32 {
    unsafe { (base.cast::<u8>().add(offset) as *const u32).read_unaligned() }
}

fn fourcc_to_string(fourcc: u32) -> String {
    let bytes = fourcc.to_le_bytes();
    if bytes
        .iter()
        .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
    {
        String::from_utf8_lossy(&bytes).trim_end().to_string()
    } else {
        format!("0x{fourcc:08X}")
    }
}

fn parse_dds_summary(data: *const c_void, size: u32) -> Option<DdsSummary> {
    const DDS_MAGIC: u32 = 0x2053_4444;
    const DDS_HEADER_SIZE: u32 = 124;
    const DDPF_FOURCC: u32 = 0x0000_0004;

    if data.is_null() || size < 128 {
        return None;
    }

    let magic = unsafe { read_u32_from_ptr(data, 0) };
    let header_size = unsafe { read_u32_from_ptr(data, 4) };
    if magic != DDS_MAGIC || header_size != DDS_HEADER_SIZE {
        return None;
    }

    let height = unsafe { read_u32_from_ptr(data, 12) };
    let width = unsafe { read_u32_from_ptr(data, 16) };
    let mips = unsafe { read_u32_from_ptr(data, 28) }.max(1);
    let pixel_flags = unsafe { read_u32_from_ptr(data, 80) };
    let format = if pixel_flags & DDPF_FOURCC != 0 {
        fourcc_to_string(unsafe { read_u32_from_ptr(data, 84) })
    } else {
        format!("rgb:0x{:08X}", unsafe { read_u32_from_ptr(data, 88) })
    };

    Some(DdsSummary {
        width,
        height,
        mips,
        format,
    })
}

fn record_slow_texture_stage(stage: &'static str, data: *const c_void, size: u32, elapsed_ms: u32) {
    let context = CURRENT_TEXTURE_CONTEXT.with(|slot| slot.borrow().clone());
    let Some(context) = context else {
        return;
    };

    let mut samples = SLOW_TEXTURE_STAGES.lock();
    if samples.len() == SLOW_TEXTURE_SAMPLES {
        let Some((min_index, min_sample)) = samples
            .iter()
            .enumerate()
            .min_by_key(|(_, sample)| sample.elapsed_ms)
        else {
            return;
        };

        if elapsed_ms <= min_sample.elapsed_ms {
            return;
        }

        samples.remove(min_index);
    }

    samples.push(TextureStageSample {
        stage,
        elapsed_ms,
        size,
        phase: context.phase,
        path: context.path,
        dds: parse_dds_summary(data, size),
    });
}

fn format_slow_texture_stages() -> String {
    let mut samples = SLOW_TEXTURE_STAGES.lock().clone();
    if samples.is_empty() {
        return "none".to_string();
    }

    samples.sort_by(|left, right| right.elapsed_ms.cmp(&left.elapsed_ms));

    samples
        .iter()
        .enumerate()
        .map(|(index, sample)| {
            let image = match &sample.dds {
                Some(dds) => format!(
                    " {}x{} {} mips={}",
                    dds.width, dds.height, dds.format, dds.mips
                ),
                None => String::new(),
            };
            format!(
                "#{} {} {} {}KB{} @ {} '{}'",
                index + 1,
                sample.stage,
                format_duration(Some(sample.elapsed_ms as u64)),
                sample.size / 1024,
                image,
                phase_name(sample.phase),
                sample.path
            )
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

fn texture_create_target_summary() -> String {
    match relative_call_target(D3DX_TEXTURE_CREATE_CALL_ADDR) {
        Some(D3DX_TEXTURE_CREATE_IMPORT_THUNK) => {
            format!("0x{D3DX_TEXTURE_CREATE_IMPORT_THUNK:08X} vanilla-d3dx")
        }
        Some(target) => format!("0x{target:08X} patched-existing"),
        None => "unknown".to_string(),
    }
}

fn log_startup_probe_summary() {
    log::info!(
        "[LOADING] startup profile phases: init_renderer=({}) shader_system=({}) world_render_setup=({}) idle_anim_scan=({})",
        format_probe(INIT_RENDERER_PROBE.snapshot()),
        format_probe(SHADER_SYSTEM_INIT_PROBE.snapshot()),
        format_probe(WORLD_RENDER_SETUP_PROBE.snapshot()),
        format_probe(IDLE_ANIM_SCAN_PROBE.snapshot())
    );
    log::info!(
        "[LOADING] startup profile resources: vertex_shader=({}) pixel_shader=({}) texture_load=({})",
        format_probe(CREATE_VERTEX_SHADER_PROBE.snapshot()),
        format_probe(CREATE_PIXEL_SHADER_PROBE.snapshot()),
        format_probe(TEXTURE_LOAD_PROBE.snapshot())
    );
    log::info!(
        "[LOADING] startup slow textures: {}",
        format_slow_textures()
    );
    log::info!(
        "[LOADING] texture pipeline: image_info=({}) create_in_memory=({}) create_ex=({}) create_target={}",
        format_probe(D3DX_IMAGE_INFO_PROBE.snapshot()),
        format_probe(D3DX_CREATE_TEXTURE_PROBE.snapshot()),
        format_probe(D3DX_CREATE_TEXTURE_EX_PROBE.snapshot()),
        texture_create_target_summary()
    );
    log::info!(
        "[LOADING] texture open/resolve: open=({})",
        format_probe(TEXTURE_OPEN_PROBE.snapshot())
    );
    log::info!(
        "[LOADING] texture memory stages: alloc_zero=({}) temp_free=({})",
        format_probe(TEXTURE_TEMP_ALLOC_PROBE.snapshot()),
        format_probe(TEXTURE_TEMP_FREE_PROBE.snapshot())
    );
    log::info!(
        "[LOADING] texture file reads: read_buffer=({})",
        format_probe(TEXTURE_READ_BUFFER_PROBE.snapshot())
    );
    log::info!(
        "[LOADING] texture create callsites: tex2d=({}) cube=({}) volume=({})",
        format_probe(D3DX_CREATE_TEXTURE_CALLSITE_PROBE.snapshot()),
        format_probe(D3DX_CREATE_CUBE_TEXTURE_CALLSITE_PROBE.snapshot()),
        format_probe(D3DX_CREATE_VOLUME_TEXTURE_CALLSITE_PROBE.snapshot())
    );
    log::info!(
        "[LOADING] startup slow texture stages: {}",
        format_slow_texture_stages()
    );
}

fn install_profile_hook<T: Copy + 'static>(
    hook: &InlineHookContainer<T>,
    name: &str,
    addr: usize,
    detour: T,
) -> bool {
    match hook.init(name, addr as *mut c_void, detour) {
        Ok(()) => {}
        Err(err) => {
            log::warn!(
                "[LOADING] startup profiler hook skipped: {} at 0x{:08X}: {}",
                name,
                addr,
                err
            );
            return false;
        }
    }

    match hook.enable() {
        Ok(()) => true,
        Err(err) => {
            log::warn!(
                "[LOADING] startup profiler hook skipped: {} at 0x{:08X}: {}",
                name,
                addr,
                err
            );
            false
        }
    }
}

unsafe extern "stdcall" fn hook_d3dx_get_image_info(
    data: *const c_void,
    size: u32,
    info: *mut c_void,
) -> i32 {
    let Ok(original) = D3DX_GET_IMAGE_INFO_IAT_HOOK.original() else {
        return -1;
    };

    if !should_profile_startup() {
        return unsafe { original(data, size, info) };
    }

    let start = now_tick_ms();
    let result = unsafe { original(data, size, info) };
    let elapsed = now_tick_ms().wrapping_sub(start);
    D3DX_IMAGE_INFO_PROBE.record(elapsed);
    result
}

unsafe extern "C" fn hook_texture_open(path: *mut c_char, arg2: u32, flags: u32) -> *mut c_void {
    let target = TEXTURE_OPEN_TARGET.load(Ordering::Acquire);
    if target == 0 {
        return std::ptr::null_mut();
    }

    let Ok(original) = (unsafe { FnPtr::<TextureOpenFn>::from_raw(target as *mut c_void) }) else {
        return std::ptr::null_mut();
    };
    let Ok(original) = (unsafe { original.as_fn() }) else {
        return std::ptr::null_mut();
    };

    if !should_profile_startup() {
        return unsafe { original(path, arg2, flags) };
    }

    let has_texture_context = CURRENT_TEXTURE_CONTEXT.with(|slot| slot.borrow().is_some());
    if !has_texture_context {
        return unsafe { original(path, arg2, flags) };
    }

    let start = now_tick_ms();
    let result = unsafe { original(path, arg2, flags) };
    let elapsed = now_tick_ms().wrapping_sub(start);
    TEXTURE_OPEN_PROBE.record(elapsed);
    record_slow_texture_stage("open", std::ptr::null(), 0, elapsed);
    result
}

unsafe extern "C" fn hook_texture_temp_alloc(size: u32) -> *mut c_void {
    let target = TEXTURE_TEMP_ALLOC_TARGET.load(Ordering::Acquire);
    if target == 0 {
        return std::ptr::null_mut();
    }

    let Ok(original) = (unsafe { FnPtr::<TextureTempAllocFn>::from_raw(target as *mut c_void) })
    else {
        return std::ptr::null_mut();
    };
    let Ok(original) = (unsafe { original.as_fn() }) else {
        return std::ptr::null_mut();
    };

    if !should_profile_startup() {
        return unsafe { original(size) };
    }

    let has_texture_context = CURRENT_TEXTURE_CONTEXT.with(|slot| slot.borrow().is_some());
    if !has_texture_context {
        return unsafe { original(size) };
    }

    let start = now_tick_ms();
    let result = unsafe { original(size) };
    let elapsed = now_tick_ms().wrapping_sub(start);
    TEXTURE_TEMP_ALLOC_PROBE.record(elapsed);
    record_slow_texture_stage("alloc_zero", std::ptr::null(), size, elapsed);
    result
}

unsafe extern "C" fn hook_texture_temp_free(ptr: *mut c_void) {
    let target = TEXTURE_TEMP_FREE_TARGET.load(Ordering::Acquire);
    if target == 0 {
        return;
    }

    let Ok(original) = (unsafe { FnPtr::<TextureTempFreeFn>::from_raw(target as *mut c_void) })
    else {
        return;
    };
    let Ok(original) = (unsafe { original.as_fn() }) else {
        return;
    };

    if !should_profile_startup() {
        unsafe { original(ptr) };
        return;
    }

    let has_texture_context = CURRENT_TEXTURE_CONTEXT.with(|slot| slot.borrow().is_some());
    if !has_texture_context {
        unsafe { original(ptr) };
        return;
    }

    let start = now_tick_ms();
    unsafe { original(ptr) };
    let elapsed = now_tick_ms().wrapping_sub(start);
    TEXTURE_TEMP_FREE_PROBE.record(elapsed);
    record_slow_texture_stage("temp_free", std::ptr::null(), 0, elapsed);
}

unsafe extern "thiscall" fn hook_bsfile_read_buffer(
    this: *mut c_void,
    dst: *mut c_void,
    size: u32,
) -> u32 {
    let Ok(original) = BSFILE_READ_BUFFER_HOOK.original() else {
        return 0;
    };

    if !should_profile_startup() {
        return unsafe { original(this, dst, size) };
    }

    let has_texture_context = CURRENT_TEXTURE_CONTEXT.with(|slot| slot.borrow().is_some());
    if !has_texture_context {
        return unsafe { original(this, dst, size) };
    }

    let start = now_tick_ms();
    let result = unsafe { original(this, dst, size) };
    let elapsed = now_tick_ms().wrapping_sub(start);
    TEXTURE_READ_BUFFER_PROBE.record(elapsed);
    record_slow_texture_stage("read", dst, size, elapsed);
    result
}

unsafe extern "stdcall" fn hook_d3dx_create_texture(
    device: *mut c_void,
    data: *const c_void,
    size: u32,
    texture: *mut *mut c_void,
) -> i32 {
    let Ok(original) = D3DX_CREATE_TEXTURE_IAT_HOOK.original() else {
        return -1;
    };

    if !should_profile_startup() {
        return unsafe { original(device, data, size, texture) };
    }

    let start = now_tick_ms();
    let result = unsafe { original(device, data, size, texture) };
    let elapsed = now_tick_ms().wrapping_sub(start);
    D3DX_CREATE_TEXTURE_PROBE.record(elapsed);
    record_slow_texture_stage("create", data, size, elapsed);
    result
}

#[allow(clippy::too_many_arguments)]
unsafe extern "stdcall" fn hook_d3dx_create_texture_ex(
    device: *mut c_void,
    data: *const c_void,
    size: u32,
    width: i32,
    height: i32,
    mip_levels: i32,
    usage: u32,
    format: i32,
    pool: i32,
    filter: i32,
    mip_filter: i32,
    color_key: u32,
    src_info: *mut c_void,
    palette: *mut c_void,
    texture: *mut *mut c_void,
) -> i32 {
    let Ok(original) = D3DX_CREATE_TEXTURE_EX_HOOK.original() else {
        return -1;
    };

    if !should_profile_startup() {
        return unsafe {
            original(
                device, data, size, width, height, mip_levels, usage, format, pool, filter,
                mip_filter, color_key, src_info, palette, texture,
            )
        };
    }

    let start = now_tick_ms();
    let result = unsafe {
        original(
            device, data, size, width, height, mip_levels, usage, format, pool, filter, mip_filter,
            color_key, src_info, palette, texture,
        )
    };
    let elapsed = now_tick_ms().wrapping_sub(start);
    D3DX_CREATE_TEXTURE_EX_PROBE.record(elapsed);
    record_slow_texture_stage("create_ex", data, size, elapsed);
    result
}

unsafe extern "stdcall" fn hook_d3dx_create_texture_callsite(
    device: *mut c_void,
    data: *const c_void,
    size: u32,
    texture: *mut *mut c_void,
) -> i32 {
    let target = D3DX_TEXTURE_CREATE_TARGET.load(Ordering::Acquire);
    if target == 0 {
        return -1;
    }

    let Ok(original) =
        (unsafe { FnPtr::<D3dxCreateTextureFromMemoryFn>::from_raw(target as *mut c_void) })
    else {
        return -1;
    };
    let Ok(original) = (unsafe { original.as_fn() }) else {
        return -1;
    };

    if !should_profile_startup() {
        return unsafe { original(device, data, size, texture) };
    }

    let start = now_tick_ms();
    let result = unsafe { original(device, data, size, texture) };
    let elapsed = now_tick_ms().wrapping_sub(start);
    D3DX_CREATE_TEXTURE_CALLSITE_PROBE.record(elapsed);
    record_slow_texture_stage("create_2d_call", data, size, elapsed);
    result
}

unsafe extern "stdcall" fn hook_d3dx_create_cube_texture_callsite(
    device: *mut c_void,
    data: *const c_void,
    size: u32,
    texture: *mut *mut c_void,
) -> i32 {
    let target = D3DX_CUBE_TEXTURE_CREATE_TARGET.load(Ordering::Acquire);
    if target == 0 {
        return -1;
    }

    let Ok(original) =
        (unsafe { FnPtr::<D3dxCreateTextureFromMemoryFn>::from_raw(target as *mut c_void) })
    else {
        return -1;
    };
    let Ok(original) = (unsafe { original.as_fn() }) else {
        return -1;
    };

    if !should_profile_startup() {
        return unsafe { original(device, data, size, texture) };
    }

    let start = now_tick_ms();
    let result = unsafe { original(device, data, size, texture) };
    let elapsed = now_tick_ms().wrapping_sub(start);
    D3DX_CREATE_CUBE_TEXTURE_CALLSITE_PROBE.record(elapsed);
    record_slow_texture_stage("create_cube_call", data, size, elapsed);
    result
}

unsafe extern "stdcall" fn hook_d3dx_create_volume_texture_callsite(
    device: *mut c_void,
    data: *const c_void,
    size: u32,
    texture: *mut *mut c_void,
) -> i32 {
    let target = D3DX_VOLUME_TEXTURE_CREATE_TARGET.load(Ordering::Acquire);
    if target == 0 {
        return -1;
    }

    let Ok(original) =
        (unsafe { FnPtr::<D3dxCreateTextureFromMemoryFn>::from_raw(target as *mut c_void) })
    else {
        return -1;
    };
    let Ok(original) = (unsafe { original.as_fn() }) else {
        return -1;
    };

    if !should_profile_startup() {
        return unsafe { original(device, data, size, texture) };
    }

    let start = now_tick_ms();
    let result = unsafe { original(device, data, size, texture) };
    let elapsed = now_tick_ms().wrapping_sub(start);
    D3DX_CREATE_VOLUME_TEXTURE_CALLSITE_PROBE.record(elapsed);
    record_slow_texture_stage("create_volume_call", data, size, elapsed);
    result
}

fn install_texture_pipeline_probes() {
    if TEXTURE_PIPELINE_PROBES_INSTALLED.swap(true, Ordering::AcqRel) {
        return;
    }

    let mut installed = 0u32;
    let mut skipped = 0u32;

    let module_base = match get_module_handle_a(None) {
        Ok(module) => module.as_ptr(),
        Err(err) => {
            log::info!("[LOADING] texture pipeline probes skipped: module base unavailable: {err}");
            return;
        }
    };

    unsafe {
        match D3DX_GET_IMAGE_INFO_IAT_HOOK.init(
            "d3dx_get_image_info",
            module_base,
            Some("d3dx9_38.dll"),
            "D3DXGetImageInfoFromFileInMemory",
            hook_d3dx_get_image_info,
        ) {
            Ok(()) if D3DX_GET_IMAGE_INFO_IAT_HOOK.is_initialized() => {
                match D3DX_GET_IMAGE_INFO_IAT_HOOK.enable() {
                    Ok(()) => installed += 1,
                    Err(err) => {
                        skipped += 1;
                        log::info!(
                            "[LOADING] texture pipeline probe skipped: D3DXGetImageInfoFromFileInMemory: {err}"
                        );
                    }
                }
            }
            Ok(()) => {
                skipped += 1;
                log::info!(
                    "[LOADING] texture pipeline probe skipped: D3DXGetImageInfoFromFileInMemory import not found"
                );
            }
            Err(err) => {
                skipped += 1;
                log::info!(
                    "[LOADING] texture pipeline probe skipped: D3DXGetImageInfoFromFileInMemory: {err}"
                );
            }
        }

        match D3DX_CREATE_TEXTURE_IAT_HOOK.init(
            "d3dx_create_texture",
            module_base,
            Some("d3dx9_38.dll"),
            "D3DXCreateTextureFromFileInMemory",
            hook_d3dx_create_texture,
        ) {
            Ok(()) if D3DX_CREATE_TEXTURE_IAT_HOOK.is_initialized() => {
                match D3DX_CREATE_TEXTURE_IAT_HOOK.enable() {
                    Ok(()) => installed += 1,
                    Err(err) => {
                        skipped += 1;
                        log::info!(
                            "[LOADING] texture pipeline probe skipped: D3DXCreateTextureFromFileInMemory: {err}"
                        );
                    }
                }
            }
            Ok(()) => {
                skipped += 1;
                log::info!(
                    "[LOADING] texture pipeline probe skipped: D3DXCreateTextureFromFileInMemory import not found"
                );
            }
            Err(err) => {
                skipped += 1;
                log::info!(
                    "[LOADING] texture pipeline probe skipped: D3DXCreateTextureFromFileInMemory: {err}"
                );
            }
        }
    }

    match get_proc_address_in_dll("d3dx9_38.dll", "D3DXCreateTextureFromFileInMemoryEx") {
        Ok(proc) => match D3DX_CREATE_TEXTURE_EX_HOOK.init(
            "d3dx_create_texture_ex",
            proc,
            hook_d3dx_create_texture_ex,
        ) {
            Ok(()) => match D3DX_CREATE_TEXTURE_EX_HOOK.enable() {
                Ok(()) => installed += 1,
                Err(err) => {
                    skipped += 1;
                    log::info!(
                        "[LOADING] texture pipeline probe skipped: D3DXCreateTextureFromFileInMemoryEx: {err}"
                    );
                }
            },
            Err(err) => {
                skipped += 1;
                log::info!(
                    "[LOADING] texture pipeline probe skipped: D3DXCreateTextureFromFileInMemoryEx: {err}"
                );
            }
        },
        Err(err) => {
            skipped += 1;
            log::info!(
                "[LOADING] texture pipeline probe skipped: D3DXCreateTextureFromFileInMemoryEx export unavailable: {err}"
            );
        }
    }

    log::info!(
        "[LOADING] texture pipeline probes active: {} installed, {} skipped, create_target={}",
        installed,
        skipped,
        texture_create_target_summary()
    );
}

fn install_texture_open_probe() {
    if TEXTURE_OPEN_PROBE_INSTALLED.swap(true, Ordering::AcqRel) {
        return;
    }

    let hook_addr = hook_texture_open as *const () as usize;
    match relative_call_target(TEXTURE_OPEN_CALL_ADDR) {
        Some(target) if target == hook_addr => {
            log::info!("[LOADING] texture open/resolve probe already active");
        }
        Some(target) => {
            TEXTURE_OPEN_TARGET.store(target, Ordering::Release);
            match patch_relative_call(TEXTURE_OPEN_CALL_ADDR, hook_addr) {
                Ok(()) => log::info!(
                    "[LOADING] texture open/resolve probe active: callsite=0x{:08X} target=0x{:08X}",
                    TEXTURE_OPEN_CALL_ADDR,
                    target
                ),
                Err(err) => log::info!(
                    "[LOADING] texture open/resolve probe skipped: callsite=0x{:08X}: {}",
                    TEXTURE_OPEN_CALL_ADDR,
                    err
                ),
            }
        }
        None => log::info!(
            "[LOADING] texture open/resolve probe skipped: callsite=0x{:08X} is not a relative call",
            TEXTURE_OPEN_CALL_ADDR
        ),
    }
}

fn install_relative_call_probe(
    name: &str,
    call_addr: usize,
    hook_addr: usize,
    target_slot: &AtomicUsize,
) -> bool {
    match relative_call_target(call_addr) {
        Some(target) if target == hook_addr => {
            log::info!(
                "[LOADING] texture callsite probe already active: {} at 0x{:08X}",
                name,
                call_addr
            );
            true
        }
        Some(target) => {
            let stored = target_slot.load(Ordering::Acquire);
            if stored != 0 && stored != target {
                log::info!(
                    "[LOADING] texture callsite probe skipped: {} at 0x{:08X}: target changed 0x{:08X}->0x{:08X}",
                    name,
                    call_addr,
                    stored,
                    target
                );
                return false;
            }

            target_slot.store(target, Ordering::Release);
            match patch_relative_call(call_addr, hook_addr) {
                Ok(()) => {
                    log::info!(
                        "[LOADING] texture callsite probe active: {} callsite=0x{:08X} target=0x{:08X}",
                        name,
                        call_addr,
                        target
                    );
                    true
                }
                Err(err) => {
                    log::info!(
                        "[LOADING] texture callsite probe skipped: {} at 0x{:08X}: {}",
                        name,
                        call_addr,
                        err
                    );
                    false
                }
            }
        }
        None => {
            log::info!(
                "[LOADING] texture callsite probe skipped: {} at 0x{:08X} is not a relative call",
                name,
                call_addr
            );
            false
        }
    }
}

fn install_texture_callsite_probes() {
    if TEXTURE_CALLSITE_PROBES_INSTALLED.swap(true, Ordering::AcqRel) {
        return;
    }

    let probes = [
        (
            "temp_alloc_zero",
            TEXTURE_TEMP_ALLOC_CALL_ADDR,
            hook_texture_temp_alloc as *const () as usize,
            &TEXTURE_TEMP_ALLOC_TARGET,
        ),
        (
            "temp_free_fail",
            TEXTURE_TEMP_FREE_FAIL_CALL_ADDR,
            hook_texture_temp_free as *const () as usize,
            &TEXTURE_TEMP_FREE_TARGET,
        ),
        (
            "temp_free_final",
            TEXTURE_TEMP_FREE_FINAL_CALL_ADDR,
            hook_texture_temp_free as *const () as usize,
            &TEXTURE_TEMP_FREE_TARGET,
        ),
        (
            "d3dx_create_2d",
            D3DX_TEXTURE_CREATE_CALL_ADDR,
            hook_d3dx_create_texture_callsite as *const () as usize,
            &D3DX_TEXTURE_CREATE_TARGET,
        ),
        (
            "d3dx_create_cube",
            D3DX_CUBE_TEXTURE_CREATE_CALL_ADDR,
            hook_d3dx_create_cube_texture_callsite as *const () as usize,
            &D3DX_CUBE_TEXTURE_CREATE_TARGET,
        ),
        (
            "d3dx_create_volume",
            D3DX_VOLUME_TEXTURE_CREATE_CALL_ADDR,
            hook_d3dx_create_volume_texture_callsite as *const () as usize,
            &D3DX_VOLUME_TEXTURE_CREATE_TARGET,
        ),
    ];

    let installed = probes
        .iter()
        .filter(|probe| install_relative_call_probe(probe.0, probe.1, probe.2, probe.3))
        .count();

    log::info!(
        "[LOADING] texture callsite probes active: {} installed, {} skipped",
        installed,
        probes.len() - installed
    );
}

unsafe extern "fastcall" fn hook_init_renderer(this: *mut c_void) {
    if let Ok(original) = INIT_RENDERER_HOOK.original() {
        time_startup_call(&INIT_RENDERER_PROBE, || unsafe { original(this) });
    }
}

unsafe extern "C" fn hook_shader_system_init() {
    if let Ok(original) = SHADER_SYSTEM_INIT_HOOK.original() {
        time_startup_call(&SHADER_SYSTEM_INIT_PROBE, || unsafe { original() });
    }
}

unsafe extern "thiscall" fn hook_world_render_setup(this: *mut c_void) {
    if let Ok(original) = WORLD_RENDER_SETUP_HOOK.original() {
        time_startup_call(&WORLD_RENDER_SETUP_PROBE, || unsafe { original(this) });
    }
}

unsafe extern "thiscall" fn hook_idle_anim_scan(this: *mut c_void) {
    if let Ok(original) = IDLE_ANIM_SCAN_HOOK.original() {
        time_startup_call(&IDLE_ANIM_SCAN_PROBE, || unsafe { original(this) });
    }
}

unsafe extern "C" fn hook_create_vertex_shader(
    path: *mut c_char,
    output: *mut c_void,
    arg3: u32,
    arg4: u32,
) {
    if let Ok(original) = CREATE_VERTEX_SHADER_HOOK.original() {
        time_startup_call(&CREATE_VERTEX_SHADER_PROBE, || unsafe {
            original(path, output, arg3, arg4)
        });
    }
}

unsafe extern "C" fn hook_create_pixel_shader(
    path: *mut c_char,
    output: *mut c_void,
    shader_type: *mut c_char,
    arg4: u32,
) {
    if let Ok(original) = CREATE_PIXEL_SHADER_HOOK.original() {
        time_startup_call(&CREATE_PIXEL_SHADER_PROBE, || unsafe {
            original(path, output, shader_type, arg4)
        });
    }
}

unsafe extern "thiscall" fn hook_texture_load(
    this: *mut c_void,
    path: *mut c_char,
    source: *mut c_void,
    arg4: u32,
    file: *mut c_void,
) {
    if let Ok(original) = TEXTURE_LOAD_HOOK.original() {
        if !should_profile_startup() {
            unsafe { original(this, path, source, arg4, file) };
            return;
        }

        let start = now_tick_ms();
        let context = TextureContext {
            phase: CURRENT_STARTUP_PHASE.load(Ordering::Acquire),
            path: path_from_cstr(path),
        };
        let previous = CURRENT_TEXTURE_CONTEXT.with(|slot| slot.borrow_mut().replace(context));
        unsafe { original(this, path, source, arg4, file) };
        CURRENT_TEXTURE_CONTEXT.with(|slot| {
            *slot.borrow_mut() = previous;
        });
        let elapsed = now_tick_ms().wrapping_sub(start);

        TEXTURE_LOAD_PROBE.record(elapsed);
        record_slow_texture(path, elapsed);
    }
}

fn install_startup_profile_hooks() {
    if STARTUP_PROFILE_HOOKS_INSTALLED.swap(true, Ordering::AcqRel) {
        return;
    }

    let mut installed = 0u32;

    installed += install_profile_hook(
        &INIT_RENDERER_HOOK,
        "init_renderer",
        INIT_RENDERER_ADDR,
        hook_init_renderer,
    ) as u32;
    installed += install_profile_hook(
        &SHADER_SYSTEM_INIT_HOOK,
        "shader_system_init",
        SHADER_SYSTEM_INIT_ADDR,
        hook_shader_system_init,
    ) as u32;
    installed += install_profile_hook(
        &WORLD_RENDER_SETUP_HOOK,
        "world_render_setup",
        WORLD_RENDER_SETUP_ADDR,
        hook_world_render_setup,
    ) as u32;
    installed += install_profile_hook(
        &IDLE_ANIM_SCAN_HOOK,
        "idle_anim_scan",
        IDLE_ANIM_SCAN_ADDR,
        hook_idle_anim_scan,
    ) as u32;
    installed += install_profile_hook(
        &CREATE_VERTEX_SHADER_HOOK,
        "create_vertex_shader",
        CREATE_VERTEX_SHADER_ADDR,
        hook_create_vertex_shader,
    ) as u32;
    installed += install_profile_hook(
        &CREATE_PIXEL_SHADER_HOOK,
        "create_pixel_shader",
        CREATE_PIXEL_SHADER_ADDR,
        hook_create_pixel_shader,
    ) as u32;
    installed += install_profile_hook(
        &TEXTURE_LOAD_HOOK,
        "texture_load",
        TEXTURE_LOAD_ADDR,
        hook_texture_load,
    ) as u32;
    installed += install_profile_hook(
        &BSFILE_READ_BUFFER_HOOK,
        "bsfile_read_buffer",
        BSFILE_READ_BUFFER_ADDR,
        hook_bsfile_read_buffer,
    ) as u32;

    log::info!(
        "[LOADING] startup profiler hooks active: {} installed, {} skipped",
        installed,
        8 - installed
    );

    install_texture_pipeline_probes();
    install_texture_open_probe();
}

fn message_from_static_ptr(msg: *const i8) -> Option<String> {
    let addr = msg as usize;
    if msg.is_null() || !(STATIC_TEXT_START..STATIC_TEXT_END).contains(&addr) {
        return None;
    }

    unsafe { CStr::from_ptr(msg) }
        .to_str()
        .ok()
        .map(str::to_string)
}

fn observe_startup_phase(msg: *const i8) {
    let Some(message) = message_from_static_ptr(msg) else {
        return;
    };

    let now = now_tick_ms();
    let last = LAST_STARTUP_PHASE_TICK_MS.swap(now, Ordering::AcqRel);
    CURRENT_STARTUP_PHASE.store(phase_id_from_message(&message), Ordering::Release);
    install_texture_callsite_probes();

    log::info!(
        "[LOADING] startup phase: '{}' process={} since_previous={}",
        message,
        format_duration(process_elapsed_ms_now()),
        format_duration(elapsed_from_tick(last, now))
    );
}

unsafe extern "C" fn engine_progress_hook(msg: *const i8) {
    observe_startup_phase(msg);

    let func = match unsafe {
        FnPtr::<EngineProgressFn>::from_raw(ENGINE_PROGRESS_FN_ADDR as *mut c_void)
    } {
        Ok(func) => func,
        Err(err) => {
            log::warn!("[LOADING] engine progress fallback unavailable: {}", err);
            return;
        }
    };

    let func = match unsafe { func.as_fn() } {
        Ok(func) => func,
        Err(err) => {
            log::warn!("[LOADING] engine progress fallback invalid: {}", err);
            return;
        }
    };

    unsafe { func(msg) };
}

fn install_startup_phase_markers() -> anyhow::Result<()> {
    if STARTUP_PHASE_MARKERS_INSTALLED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }

    let hook_addr = engine_progress_hook as *const () as usize;
    let mut installed = 0u32;
    let mut skipped = 0u32;

    for &(call_addr, name) in STARTUP_PHASE_MARKERS {
        match relative_call_target(call_addr) {
            Some(target) if target == ENGINE_PROGRESS_FN_ADDR => {
                patch_relative_call(call_addr, hook_addr)?;
                installed += 1;
            }
            Some(target) if target == hook_addr => {
                installed += 1;
            }
            Some(target) => {
                skipped += 1;
                log::info!(
                    "[LOADING] startup phase marker skipped: '{}' at 0x{:08X} already targets 0x{:08X}",
                    name,
                    call_addr,
                    target
                );
            }
            None => {
                skipped += 1;
                log::info!(
                    "[LOADING] startup phase marker skipped: '{}' at 0x{:08X} is not a relative call",
                    name,
                    call_addr
                );
            }
        }
    }

    log::info!(
        "[LOADING] startup phase profiler active: {} markers, {} skipped",
        installed,
        skipped
    );

    Ok(())
}

fn now_tick_ms() -> u32 {
    libpsycho::os::windows::winapi::get_tick_count()
}

fn store_first_tick(slot: &AtomicU32) {
    let now = now_tick_ms();
    let _ = slot.compare_exchange(0, now, Ordering::AcqRel, Ordering::Acquire);
}

fn elapsed_from_tick(start: u32, now: u32) -> Option<u64> {
    if start == 0 {
        None
    } else {
        Some(now.wrapping_sub(start) as u64)
    }
}

fn filetime_to_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64
}

fn process_elapsed_ms_now() -> Option<u64> {
    let process = unsafe { GetCurrentProcess() };
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();

    unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user).ok()? };

    let now = unsafe { GetSystemTimeAsFileTime() };

    let creation = filetime_to_u64(creation);
    let now = filetime_to_u64(now);
    now.checked_sub(creation)
        .map(|ticks_100ns| ticks_100ns / 10_000)
}

fn format_duration(ms: Option<u64>) -> String {
    match ms {
        Some(ms) => format!("{}.{:03}s", ms / 1000, ms % 1000),
        None => "n/a".to_string(),
    }
}

fn is_start_menu_by_engine() -> bool {
    let func =
        match unsafe { FnPtr::<IsInStartMenuFn>::from_raw(START_MENU_CHECK_ADDR as *mut c_void) } {
            Ok(func) => func,
            Err(_) => return false,
        };
    let func = match unsafe { func.as_fn() } {
        Ok(func) => func,
        Err(_) => return false,
    };
    unsafe { func() != 0 }
}

fn is_start_menu_tile_present() -> bool {
    let visible = unsafe { *((MENU_VISIBILITY_ARRAY + MENU_TYPE_START) as *const u8) != 0 };
    if !visible {
        return false;
    }

    let index = MENU_TYPE_START - MENU_TYPE_MIN;
    let entries = unsafe { *(TILE_MENU_ARRAY_DATA_PTR as *const *const *const c_void) };
    if entries.is_null() {
        return false;
    }

    let tile_menu = unsafe { *entries.add(index) };
    !tile_menu.is_null()
}

fn is_start_menu_visible() -> bool {
    is_start_menu_by_engine() || is_start_menu_tile_present()
}

fn observe_main_loop() {
    if MAIN_MENU_VISIBLE_LOGGED.load(Ordering::Acquire) {
        return;
    }
    if is_start_menu_visible() {
        store_first_tick(&START_MENU_ACTIVE_TICK_MS);
    }
}

fn observe_frame_present() {
    if MAIN_MENU_VISIBLE_LOGGED.load(Ordering::Acquire) {
        return;
    }

    let frame = PRESENT_FRAME_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if !is_start_menu_visible() {
        return;
    }

    let now = now_tick_ms();
    let _ = START_MENU_ACTIVE_TICK_MS.compare_exchange(0, now, Ordering::AcqRel, Ordering::Acquire);
    if MAIN_MENU_VISIBLE_LOGGED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    let init = INIT_TICK_MS.load(Ordering::Acquire);
    let deferred = DEFERRED_INIT_TICK_MS.load(Ordering::Acquire);
    let menu_active = START_MENU_ACTIVE_TICK_MS.load(Ordering::Acquire);

    log::info!(
        "[LOADING] main menu visible: process={} init={} deferred={} start_menu_active_to_present={} present_frames={}",
        format_duration(process_elapsed_ms_now()),
        format_duration(elapsed_from_tick(init, now)),
        format_duration(elapsed_from_tick(deferred, now)),
        format_duration(elapsed_from_tick(menu_active, now)),
        frame
    );
    log_startup_probe_summary();
}

pub fn mark_init_start() {
    store_first_tick(&INIT_TICK_MS);
    store_first_tick(&LAST_STARTUP_PHASE_TICK_MS);
}

pub fn observe_event(kind: u32, path: Option<&str>, bool_value: i32) {
    match kind {
        PSYCHO_EVENT_DEFERRED_INIT => store_first_tick(&DEFERRED_INIT_TICK_MS),
        PSYCHO_EVENT_PRE_LOAD_GAME => {
            let now = now_tick_ms();
            SAVE_LOAD_PRE_TICK_MS.store(now, Ordering::Release);
            SAVE_LOAD_GAME_TICK_MS.store(0, Ordering::Release);
            log::info!(
                "[LOADING] save load begin: path={}",
                path.unwrap_or("<unknown>")
            );
        }
        PSYCHO_EVENT_LOAD_GAME => {
            let now = now_tick_ms();
            SAVE_LOAD_GAME_TICK_MS.store(now, Ordering::Release);
            let pre = SAVE_LOAD_PRE_TICK_MS.load(Ordering::Acquire);
            log::info!(
                "[LOADING] save data read: path={} since_begin={}",
                path.unwrap_or("<unknown>"),
                format_duration(elapsed_from_tick(pre, now))
            );
        }
        PSYCHO_EVENT_POST_LOAD_GAME => {
            let now = now_tick_ms();
            let pre = SAVE_LOAD_PRE_TICK_MS.swap(0, Ordering::AcqRel);
            let game = SAVE_LOAD_GAME_TICK_MS.swap(0, Ordering::AcqRel);
            log::info!(
                "[LOADING] save load end: success={} total={} after_data_read={}",
                bool_event_text(bool_value),
                format_duration(elapsed_from_tick(pre, now)),
                format_duration(elapsed_from_tick(game, now))
            );
        }
        PSYCHO_EVENT_MAIN_GAME_LOOP => observe_main_loop(),
        PSYCHO_EVENT_ON_FRAME_PRESENT => observe_frame_present(),
        _ => {}
    }
}

fn bool_event_text(value: i32) -> &'static str {
    match value {
        0 => "false",
        1 => "true",
        _ => "unknown",
    }
}

pub fn install_loading_speed_patches() -> anyhow::Result<()> {
    patch_model_loader_wait()?;
    patch_completion_drain_budget()?;
    install_startup_phase_markers()?;
    install_startup_profile_hooks();
    Ok(())
}
