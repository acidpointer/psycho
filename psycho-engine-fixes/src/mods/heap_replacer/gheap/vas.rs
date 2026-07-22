//! Runtime VAS telemetry for gheap.
//!
//! `GlobalMemoryStatusEx` nominally reports process VAS, but under Proton/Wine
//! it can disagree with the regions that `VirtualAlloc` can actually use. The
//! crashes we care about are also often fragmentation failures: DirectX or a
//! texture load needs one large contiguous hole. This module walks the process
//! with `VirtualQuery` to measure both total free VAS and the largest holes.

use libc::c_void;

use std::sync::atomic::{AtomicBool, Ordering};

use libpsycho::os::windows::winapi::{MemoryState, get_tick_count, virtual_query};
use parking_lot::RwLock;

pub const MB: usize = 1024 * 1024;
pub const CRITICAL_LARGEST_HOLE: usize = 128 * MB;

const VA_START: usize = 0x0001_0000;
const VA_LIMIT: usize = 0xffff_0000;

static LAST_SAMPLE: RwLock<Option<CachedSummary>> = RwLock::new(None);
static DASHBOARD_REFRESHING: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Default)]
pub struct Summary {
    pub total_free: usize,
    pub total_reserve: usize,
    pub total_commit: usize,
    pub largest_base: usize,
    pub largest_free: usize,
    pub second_base: usize,
    pub second_free: usize,
    pub regions: u32,
    pub holes: u32,
}

#[derive(Clone, Copy)]
struct CachedSummary {
    summary: Summary,
    sampled_at_ms: u32,
}

pub fn sample() -> Option<Summary> {
    let mut summary = Summary::default();
    let mut addr = VA_START;

    while addr < VA_LIMIT {
        let info = virtual_query(addr as *mut c_void).ok()?;
        summary.regions = summary.regions.saturating_add(1);

        let base = info.base_address as usize;
        let size = info.region_size;
        match info.memory_state() {
            MemoryState::Free => {
                summary.total_free = summary.total_free.saturating_add(size);
                summary.holes = summary.holes.saturating_add(1);
                if size > summary.largest_free {
                    summary.second_free = summary.largest_free;
                    summary.second_base = summary.largest_base;
                    summary.largest_free = size;
                    summary.largest_base = base;
                } else if size > summary.second_free {
                    summary.second_free = size;
                    summary.second_base = base;
                }
            }
            MemoryState::Reserve => {
                summary.total_reserve = summary.total_reserve.saturating_add(size);
            }
            MemoryState::Commit => {
                summary.total_commit = summary.total_commit.saturating_add(size);
            }
            _ => {}
        }

        let next = base.saturating_add(size.max(0x1000));
        if next <= addr {
            break;
        }
        addr = next;
    }

    *LAST_SAMPLE.write() = Some(CachedSummary {
        summary,
        sampled_at_ms: get_tick_count(),
    });
    Some(summary)
}

/// Return the latest completed VAS walk without waiting or refreshing it.
pub fn cached() -> Option<(Summary, u32)> {
    let cached = *LAST_SAMPLE.try_read()?;
    cached.map(|sample| (sample.summary, sample.sampled_at_ms))
}

/// Perform the dashboard's explicitly requested VAS refresh.
pub fn refresh_for_dashboard() -> Option<Summary> {
    if DASHBOARD_REFRESHING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return cached().map(|(summary, _)| summary);
    }

    let refreshed = sample();
    DASHBOARD_REFRESHING.store(false, Ordering::Release);
    refreshed.or_else(|| cached().map(|(summary, _)| summary))
}
