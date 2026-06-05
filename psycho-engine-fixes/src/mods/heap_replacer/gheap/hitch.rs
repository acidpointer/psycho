//! Frame hitch telemetry.
//!
//! This is diagnostic only. It samples Phase 10 spacing and emits a compact
//! summary when a frame interval jumps above the recent baseline.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::mods::{engine_fixes, heap_replacer::scrap_heap};

use super::engine::globals::{self, PddQueue};
use super::{block, pool, task_release, va_alloc};

const REPORT_MS: u32 = 1_000;
const ABSOLUTE_HITCH_US: u64 = 20_000;
const RELATIVE_HITCH_US: u64 = 2_000;
const SPAN_COUNT: usize = 21;

#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Span {
    Phase7DeadSet = 0,
    Phase7Pdd,
    Phase7OptionalPdd,
    Phase10Original,
    Phase10Pre,
    Phase10AudioUpdate,
    Phase10AudioWorker,
    RadioSignalScan,
    RadioStationUpdate,
    Phase10PreTail,
    Phase10WorldUpdate,
    Phase10Mid,
    Phase10QueueDrain,
    Phase10Post,
    Phase10Pressure,
    Phase10Tail,
    AiStartOriginal,
    AiJoinOriginal,
    HavokStopStartOriginal,
    HavokLockOriginal,
    HavokUnlockOriginal,
}

static LAST_PHASE10_TICKS: AtomicU64 = AtomicU64::new(0);
static FRAME_EMA_US: AtomicU64 = AtomicU64::new(0);
static WINDOW_HITCHES: AtomicU64 = AtomicU64::new(0);
static WINDOW_TOTAL_US: AtomicU64 = AtomicU64::new(0);
static WINDOW_MAX_US: AtomicU64 = AtomicU64::new(0);
static LAST_REPORT_MS: AtomicU32 = AtomicU32::new(0);
static PERF_FREQUENCY: AtomicU64 = AtomicU64::new(0);
static SPAN_CALLS: [AtomicU64; SPAN_COUNT] = [const { AtomicU64::new(0) }; SPAN_COUNT];
static SPAN_TOTAL_US: [AtomicU64; SPAN_COUNT] = [const { AtomicU64::new(0) }; SPAN_COUNT];
static SPAN_MAX_US: [AtomicU64; SPAN_COUNT] = [const { AtomicU64::new(0) }; SPAN_COUNT];

#[derive(Default)]
struct SpanSnapshot {
    calls: [u64; SPAN_COUNT],
    total_us: [u64; SPAN_COUNT],
    max_us: [u64; SPAN_COUNT],
}

impl SpanSnapshot {
    #[inline]
    fn calls(&self, span: Span) -> u64 {
        self.calls[span as usize]
    }

    #[inline]
    fn total_us(&self, span: Span) -> u64 {
        self.total_us[span as usize]
    }

    #[inline]
    fn max_us(&self, span: Span) -> u64 {
        self.max_us[span as usize]
    }
}

pub fn measure_span<R>(span: Span, f: impl FnOnce() -> R) -> R {
    let start = perf_counter();
    let result = f();
    record_span(span, start);
    result
}

pub fn on_phase10_enter() {
    let now = perf_counter();
    if now == 0 {
        return;
    }

    let last = LAST_PHASE10_TICKS.swap(now, Ordering::AcqRel);
    if last != 0 && now > last {
        let frame_us = ticks_to_us(now - last);
        if frame_us != 0 {
            observe_frame(frame_us);
        }
    }

    maybe_log_window();
}

fn observe_frame(frame_us: u64) {
    let prev_ema = FRAME_EMA_US.load(Ordering::Acquire);
    if prev_ema == 0 {
        FRAME_EMA_US.store(frame_us, Ordering::Release);
        return;
    }

    let relative_hitch = frame_us >= prev_ema.saturating_add(RELATIVE_HITCH_US)
        && frame_us >= prev_ema.saturating_mul(3) / 2;
    if frame_us >= ABSOLUTE_HITCH_US || relative_hitch {
        WINDOW_HITCHES.fetch_add(1, Ordering::Relaxed);
        WINDOW_TOTAL_US.fetch_add(frame_us, Ordering::Relaxed);
        update_max(&WINDOW_MAX_US, frame_us);
    }

    let next_ema = (prev_ema.saturating_mul(7)).saturating_add(frame_us.saturating_mul(3)) / 10;
    FRAME_EMA_US.store(next_ema.max(1), Ordering::Release);
}

fn maybe_log_window() {
    let now = libpsycho::os::windows::winapi::get_tick_count();
    let last = LAST_REPORT_MS.load(Ordering::Acquire);
    if last == 0 {
        let _ = LAST_REPORT_MS.compare_exchange(0, now, Ordering::AcqRel, Ordering::Relaxed);
        drain_external_counters();
        return;
    }
    if now.wrapping_sub(last) < REPORT_MS {
        return;
    }
    if LAST_REPORT_MS
        .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return;
    }

    let engine = engine_fixes::take_hitch_counters();
    let task = task_release::take_hitch_counters();
    let spans = take_span_snapshot();
    let hitches = WINDOW_HITCHES.swap(0, Ordering::AcqRel);
    let total_us = WINDOW_TOTAL_US.swap(0, Ordering::AcqRel);
    let max_us = WINDOW_MAX_US.swap(0, Ordering::AcqRel);
    if hitches == 0 {
        return;
    }

    let scrap = scrap_heap::snapshot();
    log::debug!(
        "[HITCH] events={} max_us={} avg_us={} ema_us={} loading={} pddq={}/{}/{}/{}/{} ragdoll={}/{} extra_owner=load:{} access:{} unreadable:{} task=qt_final:{} guard:{} tombstone:{} pool={}/{}MB live={} blocks={} block_mb={} va={}MB scrap={}KB ids={} active_ids={} regions={} allocs={} spans=calls/max/total 7ds:{}/{}/{} 7pdd:{}/{}/{} 7opt:{}/{}/{} 10orig:{}/{}/{} 10pre:{}/{}/{} pre32:{}/{}/{} pre33:{}/{}/{} radScan:{}/{}/{} radUpd:{}/{}/{} prefb:{}/{}/{} pred7:{}/{}/{} 10mid:{}/{}/{} 10q:{}/{}/{} 10post:{}/{}/{} 10prs:{}/{}/{} 10tail:{}/{}/{} aiS:{}/{}/{} aiJ:{}/{}/{} hSS:{}/{}/{} hkL:{}/{}/{} hkU:{}/{}/{}",
        hitches,
        max_us,
        total_us / hitches.max(1),
        FRAME_EMA_US.load(Ordering::Acquire),
        globals::is_loading(),
        globals::pdd_queue_count(PddQueue::NiNode),
        globals::pdd_queue_count(PddQueue::Form),
        globals::pdd_queue_count(PddQueue::Generic),
        globals::pdd_queue_count(PddQueue::Anim),
        globals::pdd_queue_count(PddQueue::Texture),
        engine.ragdoll_calls,
        engine.ragdoll_skips,
        engine.extra_owner_load_scrubs,
        engine.extra_owner_access_scrubs,
        engine.extra_owner_unreadable,
        task.queued_texture_finals,
        task.guards,
        task.tombstones,
        pool::committed_bytes() / 1024 / 1024,
        pool::reserved_bytes() / 1024 / 1024,
        pool::live_cells(),
        block::block_count(),
        block::committed_bytes() / 1024 / 1024,
        va_alloc::live_bytes() / 1024 / 1024,
        scrap.live_bytes / 1024,
        scrap.identities,
        scrap.active_identities,
        scrap.regions,
        scrap.live_allocs,
        spans.calls(Span::Phase7DeadSet),
        spans.max_us(Span::Phase7DeadSet),
        spans.total_us(Span::Phase7DeadSet),
        spans.calls(Span::Phase7Pdd),
        spans.max_us(Span::Phase7Pdd),
        spans.total_us(Span::Phase7Pdd),
        spans.calls(Span::Phase7OptionalPdd),
        spans.max_us(Span::Phase7OptionalPdd),
        spans.total_us(Span::Phase7OptionalPdd),
        spans.calls(Span::Phase10Original),
        spans.max_us(Span::Phase10Original),
        spans.total_us(Span::Phase10Original),
        spans.calls(Span::Phase10Pre),
        spans.max_us(Span::Phase10Pre),
        spans.total_us(Span::Phase10Pre),
        spans.calls(Span::Phase10AudioUpdate),
        spans.max_us(Span::Phase10AudioUpdate),
        spans.total_us(Span::Phase10AudioUpdate),
        spans.calls(Span::Phase10AudioWorker),
        spans.max_us(Span::Phase10AudioWorker),
        spans.total_us(Span::Phase10AudioWorker),
        spans.calls(Span::RadioSignalScan),
        spans.max_us(Span::RadioSignalScan),
        spans.total_us(Span::RadioSignalScan),
        spans.calls(Span::RadioStationUpdate),
        spans.max_us(Span::RadioStationUpdate),
        spans.total_us(Span::RadioStationUpdate),
        spans.calls(Span::Phase10PreTail),
        spans.max_us(Span::Phase10PreTail),
        spans.total_us(Span::Phase10PreTail),
        spans.calls(Span::Phase10WorldUpdate),
        spans.max_us(Span::Phase10WorldUpdate),
        spans.total_us(Span::Phase10WorldUpdate),
        spans.calls(Span::Phase10Mid),
        spans.max_us(Span::Phase10Mid),
        spans.total_us(Span::Phase10Mid),
        spans.calls(Span::Phase10QueueDrain),
        spans.max_us(Span::Phase10QueueDrain),
        spans.total_us(Span::Phase10QueueDrain),
        spans.calls(Span::Phase10Post),
        spans.max_us(Span::Phase10Post),
        spans.total_us(Span::Phase10Post),
        spans.calls(Span::Phase10Pressure),
        spans.max_us(Span::Phase10Pressure),
        spans.total_us(Span::Phase10Pressure),
        spans.calls(Span::Phase10Tail),
        spans.max_us(Span::Phase10Tail),
        spans.total_us(Span::Phase10Tail),
        spans.calls(Span::AiStartOriginal),
        spans.max_us(Span::AiStartOriginal),
        spans.total_us(Span::AiStartOriginal),
        spans.calls(Span::AiJoinOriginal),
        spans.max_us(Span::AiJoinOriginal),
        spans.total_us(Span::AiJoinOriginal),
        spans.calls(Span::HavokStopStartOriginal),
        spans.max_us(Span::HavokStopStartOriginal),
        spans.total_us(Span::HavokStopStartOriginal),
        spans.calls(Span::HavokLockOriginal),
        spans.max_us(Span::HavokLockOriginal),
        spans.total_us(Span::HavokLockOriginal),
        spans.calls(Span::HavokUnlockOriginal),
        spans.max_us(Span::HavokUnlockOriginal),
        spans.total_us(Span::HavokUnlockOriginal),
    );
}

fn drain_external_counters() {
    let _ = engine_fixes::take_hitch_counters();
    let _ = task_release::take_hitch_counters();
    let _ = take_span_snapshot();
}

fn perf_counter() -> u64 {
    libpsycho::os::windows::winapi::query_performance_counter()
        .ok()
        .and_then(|v| u64::try_from(v).ok())
        .unwrap_or(0)
}

fn ticks_to_us(ticks: u64) -> u64 {
    let freq = perf_frequency();
    if freq == 0 {
        return 0;
    }
    ticks.saturating_mul(1_000_000) / freq
}

fn perf_frequency() -> u64 {
    let current = PERF_FREQUENCY.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }

    let freq = libpsycho::os::windows::winapi::query_performance_frequency()
        .ok()
        .and_then(|v| u64::try_from(v).ok())
        .unwrap_or(0);
    if freq != 0 {
        PERF_FREQUENCY.store(freq, Ordering::Release);
    }
    freq
}

fn update_max(slot: &AtomicU64, value: u64) {
    let mut old = slot.load(Ordering::Relaxed);
    while value > old {
        match slot.compare_exchange_weak(old, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(next) => old = next,
        }
    }
}

fn record_span(span: Span, start_ticks: u64) {
    if start_ticks == 0 {
        return;
    }

    let end_ticks = perf_counter();
    if end_ticks <= start_ticks {
        return;
    }

    let elapsed_us = ticks_to_us(end_ticks - start_ticks);
    let index = span as usize;
    SPAN_CALLS[index].fetch_add(1, Ordering::Relaxed);
    SPAN_TOTAL_US[index].fetch_add(elapsed_us, Ordering::Relaxed);
    update_max(&SPAN_MAX_US[index], elapsed_us);
}

fn take_span_snapshot() -> SpanSnapshot {
    let mut snapshot = SpanSnapshot::default();
    for index in 0..SPAN_COUNT {
        snapshot.calls[index] = SPAN_CALLS[index].swap(0, Ordering::AcqRel);
        snapshot.total_us[index] = SPAN_TOTAL_US[index].swap(0, Ordering::AcqRel);
        snapshot.max_us[index] = SPAN_MAX_US[index].swap(0, Ordering::AcqRel);
    }
    snapshot
}
