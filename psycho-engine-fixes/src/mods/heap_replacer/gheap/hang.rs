//! Main-loop hang telemetry.
//!
//! This does not change game behavior. Hot hooks only write atomics; the
//! watchdog thread turns stale heartbeats into diagnostics.

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use super::engine::globals::{self, PddQueue};
use super::game_guard;

const STALE_MAIN_MS: u32 = 10_000;
const STALE_REPORT_MS: u32 = 10_000;

#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Site {
    Phase7Enter = 1,
    Phase7BeforeDeadSet,
    Phase7AfterDeadSet,
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

#[inline]
pub fn mark_main(site: Site) {
    let now = libpsycho::os::windows::winapi::get_tick_count();
    let tid = libpsycho::os::windows::winapi::get_current_thread_id();
    LAST_MAIN_TICK_MS.store(now, Ordering::Release);
    LAST_MAIN_SITE.store(site as usize, Ordering::Release);
    LAST_MAIN_THREAD_ID.store(tid, Ordering::Release);
    MAIN_HEARTBEATS.fetch_add(1, Ordering::Relaxed);
    mark_event_at(site, now, tid);
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

    log::warn!(
        "[HANG] main-loop heartbeat stale: age={}ms main_site={} main_seq={} main_tid={} event_site={} event_age={}ms event_tid={} phase7={} phase10={} ai_start={} ai_join={} hk_lock={} hk_unlock={} ai_active={} havok_active={} loading={} heap_trigger={} pddq={}/{}/{}/{}/{}",
        main_age,
        site_name(LAST_MAIN_SITE.load(Ordering::Acquire)),
        MAIN_HEARTBEATS.load(Ordering::Relaxed),
        LAST_MAIN_THREAD_ID.load(Ordering::Acquire),
        site_name(LAST_EVENT_SITE.load(Ordering::Acquire)),
        event_age,
        LAST_EVENT_THREAD_ID.load(Ordering::Acquire),
        PHASE7_FRAMES.load(Ordering::Relaxed),
        PHASE10_FRAMES.load(Ordering::Relaxed),
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
    );
}

#[inline]
fn mark_event(site: Site) {
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
        x if x == Site::Phase7BeforeDeadSet as usize => "phase7-before-dead-set",
        x if x == Site::Phase7AfterDeadSet as usize => "phase7-after-dead-set",
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
