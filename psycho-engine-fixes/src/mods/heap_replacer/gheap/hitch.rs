//! Frame hitch telemetry.
//!
//! This is diagnostic only. It samples Phase 10 spacing and emits a compact
//! summary when a frame interval jumps above the recent baseline.

use std::{
    fmt::Write as _,
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
};

use crate::mods::{diagnostics, engine_fixes, heap_replacer::scrap_heap};

use super::engine::globals::{self, PddQueue};
use super::{block, pool, va_alloc};

const REPORT_MS: u32 = 1_000;
const ABSOLUTE_HITCH_US: u64 = 20_000;
const RELATIVE_HITCH_US: u64 = 2_000;
const SPAN_COUNT: usize = 22;

#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Span {
    Phase7Pdd = 0,
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
    MemoryWatchdog,
    ScrapGc,
}

static LAST_PHASE10_TICKS: AtomicU64 = AtomicU64::new(0);
static FRAME_EMA_US: AtomicU64 = AtomicU64::new(0);
static WINDOW_HITCHES: AtomicU64 = AtomicU64::new(0);
static WINDOW_TOTAL_US: AtomicU64 = AtomicU64::new(0);
static WINDOW_MAX_US: AtomicU64 = AtomicU64::new(0);
static LAST_REPORT_MS: AtomicU32 = AtomicU32::new(0);
static SPAN_CALLS: [AtomicU64; SPAN_COUNT] = [const { AtomicU64::new(0) }; SPAN_COUNT];
static SPAN_TOTAL_US: [AtomicU64; SPAN_COUNT] = [const { AtomicU64::new(0) }; SPAN_COUNT];
static SPAN_MAX_US: [AtomicU64; SPAN_COUNT] = [const { AtomicU64::new(0) }; SPAN_COUNT];

#[derive(Clone, Copy, Default)]
struct SpanStats {
    calls: u64,
    total_us: u64,
    max_us: u64,
}

#[derive(Clone, Copy)]
struct SpanDescriptor {
    span: Span,
    name: &'static str,
}

const SPAN_DESCRIPTORS: [SpanDescriptor; SPAN_COUNT] = [
    SpanDescriptor {
        span: Span::Phase7Pdd,
        name: "7pdd",
    },
    SpanDescriptor {
        span: Span::Phase7OptionalPdd,
        name: "7opt",
    },
    SpanDescriptor {
        span: Span::Phase10Original,
        name: "10orig",
    },
    SpanDescriptor {
        span: Span::Phase10Pre,
        name: "10pre",
    },
    SpanDescriptor {
        span: Span::Phase10AudioUpdate,
        name: "pre32",
    },
    SpanDescriptor {
        span: Span::Phase10AudioWorker,
        name: "pre33",
    },
    SpanDescriptor {
        span: Span::RadioSignalScan,
        name: "radScan",
    },
    SpanDescriptor {
        span: Span::RadioStationUpdate,
        name: "radUpd",
    },
    SpanDescriptor {
        span: Span::Phase10PreTail,
        name: "prefb",
    },
    SpanDescriptor {
        span: Span::Phase10WorldUpdate,
        name: "pred7",
    },
    SpanDescriptor {
        span: Span::Phase10Mid,
        name: "10mid",
    },
    SpanDescriptor {
        span: Span::Phase10QueueDrain,
        name: "10q",
    },
    SpanDescriptor {
        span: Span::Phase10Post,
        name: "10post",
    },
    SpanDescriptor {
        span: Span::Phase10Pressure,
        name: "10prs",
    },
    SpanDescriptor {
        span: Span::Phase10Tail,
        name: "10tail",
    },
    SpanDescriptor {
        span: Span::AiStartOriginal,
        name: "aiS",
    },
    SpanDescriptor {
        span: Span::AiJoinOriginal,
        name: "aiJ",
    },
    SpanDescriptor {
        span: Span::HavokStopStartOriginal,
        name: "hSS",
    },
    SpanDescriptor {
        span: Span::HavokLockOriginal,
        name: "hkL",
    },
    SpanDescriptor {
        span: Span::HavokUnlockOriginal,
        name: "hkU",
    },
    SpanDescriptor {
        span: Span::MemoryWatchdog,
        name: "memWd",
    },
    SpanDescriptor {
        span: Span::ScrapGc,
        name: "scrapGc",
    },
];

#[derive(Default)]
struct SpanSnapshot {
    spans: [SpanStats; SPAN_COUNT],
}

impl SpanSnapshot {
    #[inline]
    fn get(&self, span: Span) -> SpanStats {
        self.spans[span as usize]
    }

    fn format_compact(&self) -> String {
        let mut output = String::with_capacity(240);

        for (index, descriptor) in SPAN_DESCRIPTORS.iter().enumerate() {
            if index != 0 {
                output.push(' ');
            }

            let stats = self.get(descriptor.span);
            let _ = write!(
                output,
                "{}:{}/{}/{}",
                descriptor.name, stats.calls, stats.max_us, stats.total_us
            );
        }

        output
    }
}

pub fn measure_span<R>(span: Span, f: impl FnOnce() -> R) -> R {
    if !diagnostics::hitch_profiling_enabled() {
        return f();
    }

    let timer = diagnostics::Stopwatch::start();
    let result = f();
    record_span(span, timer);
    result
}

pub fn on_phase10_enter() {
    if !diagnostics::hitch_profiling_enabled() {
        return;
    }

    let now = diagnostics::perf_counter();
    if now == 0 {
        return;
    }

    let last = LAST_PHASE10_TICKS.swap(now, Ordering::AcqRel);
    if last != 0 && now > last {
        let frame_us = diagnostics::ticks_to_us(now - last);
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
        diagnostics::update_max_u64(&WINDOW_MAX_US, frame_us);
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

    let engine = engine_fixes::take_diagnostic_counters();
    let spans = take_span_snapshot();
    let pool_timing = pool::take_timing_snapshot();
    let block_timing = block::take_timing_snapshot();
    let hitches = WINDOW_HITCHES.swap(0, Ordering::AcqRel);
    let total_us = WINDOW_TOTAL_US.swap(0, Ordering::AcqRel);
    let max_us = WINDOW_MAX_US.swap(0, Ordering::AcqRel);
    if hitches == 0 {
        return;
    }

    let scrap = scrap_heap::snapshot();
    let blocks = block::try_snapshot();
    let block_sample = if blocks.is_some() { "fresh" } else { "miss" };
    let blocks = blocks.unwrap_or_default();
    log::debug!(
        "[HITCH] events={} max_us={} avg_us={} ema_us={} loading={} pddq={}/{}/{}/{}/{} ragdoll={}/{} extra_owner=load:{} access:{} unreadable:{} task=dispatch:{}/{} pin_fail:{} invalid:{} guard:{} tombstone:{} pool={}+{}/{}/{}MB live={} pgrow={}/{} max/total={}/{}us user/meta={}/{}KB slow={}:{}B pinit={} max/total={}/{}us slow={}:{}B blocks={} block_mb={} sample={} block_ops={}/{}/{} wait={}/{}us op={}/{}us reserve={} fail={} max/total={}/{}us commit={} fail={} max/total={}/{}us new={} va={}MB scrap={}KB ids={} active_ids={} regions={} allocs={} spans=calls/max/total {}",
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
        engine.task_dispatch_calls,
        engine.task_dispatch_attempts,
        engine.task_pin_failures,
        engine.task_invalid_dispatches,
        engine.task_release_guards,
        engine.task_tombstones,
        pool::committed_bytes() / 1024 / 1024,
        pool::metadata_bytes() / 1024 / 1024,
        pool::metadata_reserved_bytes() / 1024 / 1024,
        pool::reserved_bytes() / 1024 / 1024,
        pool::live_cells(),
        pool_timing.grows,
        pool_timing.grow_failures,
        pool_timing.grow_max_us,
        pool_timing.grow_total_us,
        pool_timing.grow_user_bytes / 1024,
        pool_timing.grow_metadata_bytes / 1024,
        pool_timing.grow_slowest_pool,
        pool_timing.grow_slowest_item_size,
        pool_timing.initializations,
        pool_timing.init_max_us,
        pool_timing.init_total_us,
        pool_timing.init_slowest_pool,
        pool_timing.init_slowest_item_size,
        blocks.slots,
        blocks.committed_bytes / 1024 / 1024,
        block_sample,
        block_timing.alloc_calls,
        block_timing.free_calls,
        block_timing.size_calls,
        block_timing.lock_wait_max_us,
        block_timing.lock_wait_total_us,
        block_timing.operation_max_us,
        block_timing.operation_total_us,
        block_timing.reserve_calls,
        block_timing.reserve_failures,
        block_timing.reserve_max_us,
        block_timing.reserve_total_us,
        block_timing.commit_calls,
        block_timing.commit_failures,
        block_timing.commit_max_us,
        block_timing.commit_total_us,
        block_timing.new_blocks,
        va_alloc::live_bytes() / 1024 / 1024,
        scrap.live_bytes / 1024,
        scrap.identities,
        scrap.active_identities,
        scrap.regions,
        scrap.live_allocs,
        spans.format_compact(),
    );
}

fn drain_external_counters() {
    let _ = engine_fixes::take_diagnostic_counters();
    let _ = take_span_snapshot();
    let _ = pool::take_timing_snapshot();
    let _ = block::take_timing_snapshot();
}

fn record_span(span: Span, timer: diagnostics::Stopwatch) {
    let Some(elapsed_us) = timer.elapsed_us() else {
        return;
    };
    let index = span as usize;
    SPAN_CALLS[index].fetch_add(1, Ordering::Relaxed);
    SPAN_TOTAL_US[index].fetch_add(elapsed_us, Ordering::Relaxed);
    diagnostics::update_max_u64(&SPAN_MAX_US[index], elapsed_us);
}

fn take_span_snapshot() -> SpanSnapshot {
    let mut snapshot = SpanSnapshot::default();
    for index in 0..SPAN_COUNT {
        snapshot.spans[index] = SpanStats {
            calls: SPAN_CALLS[index].swap(0, Ordering::AcqRel),
            total_us: SPAN_TOTAL_US[index].swap(0, Ordering::AcqRel),
            max_us: SPAN_MAX_US[index].swap(0, Ordering::AcqRel),
        };
    }
    snapshot
}
