//! Main-loop hang telemetry.
//!
//! This does not change game behavior. Hot hooks only write atomics; the
//! watchdog thread turns stale heartbeats into diagnostics.

use std::{
    mem::size_of,
    sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
};

use crate::mods::{diagnostics, engine_fixes};
use libc::c_void;
use libpsycho::os::windows::winapi::is_readable_ptr;

use super::engine::globals::{self, PddQueue};
use super::game_guard;

const STALE_MAIN_MS: u32 = 10_000;
const STALE_REPORT_MS: u32 = 10_000;

#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Site {
    Phase7Enter = 1,
    Phase7BeforePdd,
    Phase7AfterPdd,
    Phase7Exit,
    Phase10Enter,
    Phase10AfterOriginal,
    Phase10AfterPressure,
    Phase10Exit,
    AiStartEnter,
    AiStartExit,
    AiJoinEnter,
    AiJoinExit,
    HavokLockEnter,
    HavokLockExit,
    HavokUnlockEnter,
    HavokUnlockExit,
}

static LAST_MAIN_TICK_MS: AtomicU32 = AtomicU32::new(0);
static LAST_MAIN_SITE: AtomicUsize = AtomicUsize::new(0);
static LAST_MAIN_THREAD_ID: AtomicU32 = AtomicU32::new(0);
static MAIN_HEARTBEATS: AtomicU64 = AtomicU64::new(0);
static PHASE7_FRAMES: AtomicU64 = AtomicU64::new(0);
static PHASE10_FRAMES: AtomicU64 = AtomicU64::new(0);

static LAST_EVENT_TICK_MS: AtomicU32 = AtomicU32::new(0);
static LAST_EVENT_SITE: AtomicUsize = AtomicUsize::new(0);
static LAST_EVENT_THREAD_ID: AtomicU32 = AtomicU32::new(0);

static AI_START_CALLS: AtomicU64 = AtomicU64::new(0);
static AI_JOIN_CALLS: AtomicU64 = AtomicU64::new(0);
static HAVOK_LOCK_CALLS: AtomicU64 = AtomicU64::new(0);
static HAVOK_UNLOCK_CALLS: AtomicU64 = AtomicU64::new(0);
static LAST_STALE_REPORT_MS: AtomicU32 = AtomicU32::new(0);

const IO_MANAGER_PTR_ADDR: usize = 0x01202D98;
const IO_DRAIN_COMPLETE_ADDR: usize = 0x011AF70C;
const IO_COMPLETION_ACTIVE_ADDR: usize = 0x01202DD8;

struct ModelLoaderSnapshot {
    manager: usize,
    state: u32,
    active: u32,
    accepted_total: u32,
    counts: [u32; 24],
    completed_queues: usize,
    external_count: usize,
    completion_gate: usize,
    progress_callback: usize,
    drain_complete: u8,
    completion_active: u8,
}

#[inline]
pub fn mark_main(site: Site) {
    let now = libpsycho::os::windows::winapi::get_tick_count();
    let mut tid = LAST_MAIN_THREAD_ID.load(Ordering::Relaxed);
    if tid == 0 {
        tid = libpsycho::os::windows::winapi::get_current_thread_id();
        LAST_MAIN_THREAD_ID.store(tid, Ordering::Release);
    }
    LAST_MAIN_TICK_MS.store(now, Ordering::Release);
    LAST_MAIN_SITE.store(site as usize, Ordering::Release);
    MAIN_HEARTBEATS.fetch_add(1, Ordering::Relaxed);
    if crate::mods::diagnostics::hitch_profiling_enabled() {
        mark_event_at(site, now, tid);
    }
}

#[inline]
pub fn mark_main_detail(site: Site) {
    if crate::mods::diagnostics::hitch_profiling_enabled() {
        mark_main(site);
    }
}

#[inline]
pub fn phase7_enter() {
    PHASE7_FRAMES.fetch_add(1, Ordering::Relaxed);
    mark_main(Site::Phase7Enter);
}

#[inline]
pub fn phase10_enter() {
    PHASE10_FRAMES.fetch_add(1, Ordering::Relaxed);
    mark_main(Site::Phase10Enter);
}

#[inline]
pub fn ai_start_enter() {
    AI_START_CALLS.fetch_add(1, Ordering::Relaxed);
    mark_event(Site::AiStartEnter);
}

#[inline]
pub fn ai_start_exit() {
    mark_event(Site::AiStartExit);
}

#[inline]
pub fn ai_join_enter() {
    AI_JOIN_CALLS.fetch_add(1, Ordering::Relaxed);
    mark_event(Site::AiJoinEnter);
}

#[inline]
pub fn ai_join_exit() {
    mark_event(Site::AiJoinExit);
}

#[inline]
pub fn havok_lock_enter() {
    HAVOK_LOCK_CALLS.fetch_add(1, Ordering::Relaxed);
    mark_event(Site::HavokLockEnter);
}

#[inline]
pub fn havok_lock_exit() {
    mark_event(Site::HavokLockExit);
}

#[inline]
pub fn havok_unlock_enter() {
    HAVOK_UNLOCK_CALLS.fetch_add(1, Ordering::Relaxed);
    mark_event(Site::HavokUnlockEnter);
}

#[inline]
pub fn havok_unlock_exit() {
    mark_event(Site::HavokUnlockExit);
}

pub fn log_if_main_stale() {
    let now = libpsycho::os::windows::winapi::get_tick_count();
    let last_main = LAST_MAIN_TICK_MS.load(Ordering::Acquire);
    if last_main == 0 {
        return;
    }

    let main_age = now.wrapping_sub(last_main);
    if main_age < STALE_MAIN_MS {
        return;
    }

    let last_report = LAST_STALE_REPORT_MS.load(Ordering::Acquire);
    if last_report != 0 && now.wrapping_sub(last_report) < STALE_REPORT_MS {
        return;
    }
    LAST_STALE_REPORT_MS.store(now, Ordering::Release);

    let event_tick = LAST_EVENT_TICK_MS.load(Ordering::Acquire);
    let event_age = if event_tick == 0 {
        0
    } else {
        now.wrapping_sub(event_tick)
    };
    let display = engine_fixes::display_diagnostic_snapshot();
    let load = diagnostics::load_snapshot();
    let display_age = if display.last_transition_ms != 0 {
        now.wrapping_sub(display.last_transition_ms)
    } else {
        0
    };

    log::warn!(
        "[HANG] main-loop heartbeat stale: age={}ms main_site={} main_seq={} main_tid={} event_site={} event_age={}ms event_tid={} phase7={} phase10={} load_seq={} load_depth={} load_site={} load_tid={} ai_start={} ai_join={} hk_lock={} hk_unlock={} ai_active={} havok_active={} loading={} heap_trigger={} pddq={}/{}/{}/{}/{} display=create:{}/{}/{}/{} setpos:{} sites:{}/{}/{}/{}/{}/{} windowed:{} reset:{}/{} catchup:{}/{}/{} loss:{} regain:{} lifecycle:{} mismatches:{} failures:{} last_age:{}ms last_ok:{} last_error:{}",
        main_age,
        site_name(LAST_MAIN_SITE.load(Ordering::Acquire)),
        MAIN_HEARTBEATS.load(Ordering::Relaxed),
        LAST_MAIN_THREAD_ID.load(Ordering::Acquire),
        site_name(LAST_EVENT_SITE.load(Ordering::Acquire)),
        event_age,
        LAST_EVENT_THREAD_ID.load(Ordering::Acquire),
        PHASE7_FRAMES.load(Ordering::Relaxed),
        PHASE10_FRAMES.load(Ordering::Relaxed),
        load.sequence,
        load.depth,
        load.site,
        load.thread_id,
        AI_START_CALLS.load(Ordering::Relaxed),
        AI_JOIN_CALLS.load(Ordering::Relaxed),
        HAVOK_LOCK_CALLS.load(Ordering::Relaxed),
        HAVOK_UNLOCK_CALLS.load(Ordering::Relaxed),
        game_guard::is_ai_active(),
        game_guard::is_havok_active(),
        globals::is_loading(),
        globals::heap_compact_trigger_value(),
        globals::pdd_queue_count(PddQueue::NiNode),
        globals::pdd_queue_count(PddQueue::Form),
        globals::pdd_queue_count(PddQueue::Generic),
        globals::pdd_queue_count(PddQueue::Anim),
        globals::pdd_queue_count(PddQueue::Texture),
        display.create_window_installed,
        display.bootstrap_create_state.name(),
        display.bootstrap_create_observations,
        display.bootstrap_create_corrections,
        display.installed,
        display.site_states[0].name(),
        display.site_states[1].name(),
        display.site_states[2].name(),
        display.site_states[3].name(),
        display.site_states[4].name(),
        display.site_states[5].name(),
        display.windowed_parent_passthroughs,
        display.device_reset_observations,
        display.device_reset_corrections,
        display.catch_up_attempts,
        display.catch_up_successes,
        display.catch_up_failures,
        display.loss_suppressions,
        display.regain_normalizations,
        display.lifecycle_normalizations,
        display.contract_mismatches,
        display.predecessor_failures,
        display_age,
        display.last_result,
        display.last_error,
    );

    if load.depth != 0
        && let Some(model) = model_loader_snapshot()
    {
        log::warn!(
            "[HANG_LOAD] manager=0x{:08X} state={} active={} accepted_total={} counts={:?} completed_queues=0x{:08X} external_count=0x{:08X} completion_gate=0x{:08X} progress=0x{:08X} drain_complete={} completion_active={}",
            model.manager,
            model.state,
            model.active,
            model.accepted_total,
            model.counts,
            model.completed_queues,
            model.external_count,
            model.completion_gate,
            model.progress_callback,
            model.drain_complete,
            model.completion_active,
        );
    }
}

fn model_loader_snapshot() -> Option<ModelLoaderSnapshot> {
    let manager = unsafe { (IO_MANAGER_PTR_ADDR as *const usize).read_volatile() };
    if !unsafe { is_readable_ptr(manager as *const c_void, 0x84) } {
        return None;
    }

    let counts_ptr = unsafe { ((manager + 0x54) as *const usize).read_volatile() };
    if !unsafe { is_readable_ptr(counts_ptr as *const c_void, 24 * size_of::<u32>()) } {
        return None;
    }

    let mut counts = [0; 24];
    for (index, value) in counts.iter_mut().enumerate() {
        *value = unsafe { ((counts_ptr + index * size_of::<u32>()) as *const u32).read_volatile() };
    }

    Some(ModelLoaderSnapshot {
        manager,
        active: unsafe { ((manager + 0x18) as *const u32).read_volatile() },
        accepted_total: unsafe { ((manager + 0x58) as *const u32).read_volatile() },
        completed_queues: unsafe { ((manager + 0x64) as *const usize).read_volatile() },
        state: unsafe { ((manager + 0x68) as *const u32).read_volatile() },
        external_count: unsafe { ((manager + 0x6C) as *const usize).read_volatile() },
        completion_gate: unsafe { ((manager + 0x74) as *const usize).read_volatile() },
        progress_callback: unsafe { ((manager + 0x78) as *const usize).read_volatile() },
        drain_complete: unsafe { (IO_DRAIN_COMPLETE_ADDR as *const u8).read_volatile() },
        completion_active: unsafe { (IO_COMPLETION_ACTIVE_ADDR as *const u8).read_volatile() },
        counts,
    })
}

#[inline]
fn mark_event(site: Site) {
    if !crate::mods::diagnostics::hitch_profiling_enabled() {
        return;
    }
    let now = libpsycho::os::windows::winapi::get_tick_count();
    let tid = libpsycho::os::windows::winapi::get_current_thread_id();
    mark_event_at(site, now, tid);
}

#[inline]
fn mark_event_at(site: Site, now: u32, tid: u32) {
    LAST_EVENT_TICK_MS.store(now, Ordering::Release);
    LAST_EVENT_SITE.store(site as usize, Ordering::Release);
    LAST_EVENT_THREAD_ID.store(tid, Ordering::Release);
}

fn site_name(site: usize) -> &'static str {
    match site {
        x if x == Site::Phase7Enter as usize => "phase7-enter",
        x if x == Site::Phase7BeforePdd as usize => "phase7-before-pdd",
        x if x == Site::Phase7AfterPdd as usize => "phase7-after-pdd",
        x if x == Site::Phase7Exit as usize => "phase7-exit",
        x if x == Site::Phase10Enter as usize => "phase10-enter",
        x if x == Site::Phase10AfterOriginal as usize => "phase10-after-original",
        x if x == Site::Phase10AfterPressure as usize => "phase10-after-pressure",
        x if x == Site::Phase10Exit as usize => "phase10-exit",
        x if x == Site::AiStartEnter as usize => "ai-start-enter",
        x if x == Site::AiStartExit as usize => "ai-start-exit",
        x if x == Site::AiJoinEnter as usize => "ai-join-enter",
        x if x == Site::AiJoinExit as usize => "ai-join-exit",
        x if x == Site::HavokLockEnter as usize => "havok-lock-enter",
        x if x == Site::HavokLockExit as usize => "havok-lock-exit",
        x if x == Site::HavokUnlockEnter as usize => "havok-unlock-enter",
        x if x == Site::HavokUnlockExit as usize => "havok-unlock-exit",
        _ => "none",
    }
}
