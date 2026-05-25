//! Startup/loading latency patches.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use libc::c_void;
use libnvse::api::messaging::{NVSEMessage, NVSEMessageType};
use libpsycho::ffi::fnptr::FnPtr;
use libpsycho::os::windows::winapi::{flush_instructions_cache, safe_write_8, safe_write_32};
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

const START_MENU_CHECK_ADDR: usize = 0x0070EDF0;
const MENU_VISIBILITY_ARRAY: usize = 0x011F308F;
const TILE_MENU_ARRAY_DATA_PTR: usize = 0x011F350C;
const MENU_TYPE_MIN: usize = 0x3E9;
const MENU_TYPE_START: usize = 0x3F5;

type IsInStartMenuFn = unsafe extern "C" fn() -> u8;

static COMPLETION_DRAIN_BUDGET: u32 = COMPLETION_DRAIN_BUDGET_MS;

static PRELOAD_TICK_MS: AtomicU32 = AtomicU32::new(0);
static NVSE_LOAD_TICK_MS: AtomicU32 = AtomicU32::new(0);
static DEFERRED_INIT_TICK_MS: AtomicU32 = AtomicU32::new(0);
static START_MENU_ACTIVE_TICK_MS: AtomicU32 = AtomicU32::new(0);
static PRESENT_FRAME_COUNT: AtomicU32 = AtomicU32::new(0);
static MAIN_MENU_VISIBLE_LOGGED: AtomicBool = AtomicBool::new(false);

fn read_u8(addr: usize) -> u8 {
    unsafe { (addr as *const u8).read_volatile() }
}

fn read_u32(addr: usize) -> u32 {
    unsafe { (addr as *const u32).read_unaligned() }
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

    let preload = PRELOAD_TICK_MS.load(Ordering::Acquire);
    let nvse_load = NVSE_LOAD_TICK_MS.load(Ordering::Acquire);
    let deferred = DEFERRED_INIT_TICK_MS.load(Ordering::Acquire);
    let menu_active = START_MENU_ACTIVE_TICK_MS.load(Ordering::Acquire);

    log::info!(
        "[LOADING] main menu visible: process={} preload={} nvse_load={} deferred={} start_menu_active_to_present={} present_frames={}",
        format_duration(process_elapsed_ms_now()),
        format_duration(elapsed_from_tick(preload, now)),
        format_duration(elapsed_from_tick(nvse_load, now)),
        format_duration(elapsed_from_tick(deferred, now)),
        format_duration(elapsed_from_tick(menu_active, now)),
        frame
    );
}

pub fn mark_preload_start() {
    store_first_tick(&PRELOAD_TICK_MS);
}

pub fn mark_nvse_load_start() {
    store_first_tick(&NVSE_LOAD_TICK_MS);
}

pub fn observe_nvse_message(msg: &NVSEMessage) {
    match msg.get_type() {
        NVSEMessageType::DeferredInit => store_first_tick(&DEFERRED_INIT_TICK_MS),
        NVSEMessageType::MainGameLoop => observe_main_loop(),
        NVSEMessageType::OnFramePresent => observe_frame_present(),
        _ => {}
    }
}

pub fn install_loading_speed_patches() -> anyhow::Result<()> {
    patch_model_loader_wait()?;
    patch_completion_drain_budget()?;
    Ok(())
}
