//! Runtime VAS telemetry for gheap.
//!
//! `GlobalMemoryStatusEx` nominally reports process VAS, but under Proton/Wine
//! it can disagree with the regions that `VirtualAlloc` can actually use. The
//! crashes we care about are also often fragmentation failures: DirectX or a
//! texture load needs one large contiguous hole. This module walks the process
//! with `VirtualQuery` to measure both total free VAS and the largest holes.
//!
//! A sample is all-or-nothing: any failed query aborts the walk and leaves the
//! previous cached sample intact. Publishing a partial map would make
//! admission and diagnostics report false headroom. Committed ranges are also
//! partitioned by Win32 memory type so allocator-private growth can be
//! distinguished from mapped files and loaded images.
//!
//! The full walk is intentionally cold. The watchdog runs it at its detailed
//! cadence, allocation failure telemetry is power-of-two gated, and dashboard
//! refresh uses a single-flight flag. Consumers needing frame-safe telemetry
//! should use [`cached`] rather than [`sample`].

use libc::c_void;

use std::sync::atomic::{AtomicBool, Ordering};

use libpsycho::os::windows::winapi::{MemoryState, MemoryType, get_tick_count, virtual_query};
use parking_lot::RwLock;

/// Bytes in one mebibyte, used for VAS thresholds and log formatting.
pub const MB: usize = 1024 * 1024;

/// Largest-hole size below which large asset loads receive a warning.
///
/// This is a diagnostic threshold, not an allocation-admission guarantee.
pub const CRITICAL_LARGEST_HOLE: usize = 128 * MB;

// Skip the permanently invalid low page range and the top 64 KiB sentinel
// area. These bounds cover the usable 32-bit process map without wrapping the
// final VirtualQuery step.
const VA_START: usize = 0x0001_0000;
const VA_LIMIT: usize = 0xffff_0000;

static LAST_SAMPLE: RwLock<Option<CachedSummary>> = RwLock::new(None);
static DASHBOARD_REFRESHING: AtomicBool = AtomicBool::new(false);

/// Complete classification of one successful 32-bit process VAS walk.
#[derive(Clone, Copy, Debug, Default)]
pub struct Summary {
    /// Sum of all `MEM_FREE` ranges.
    pub total_free: usize,
    /// Sum of all `MEM_RESERVE` ranges.
    pub total_reserve: usize,
    /// Sum of all `MEM_COMMIT` ranges.
    pub total_commit: usize,
    /// Committed `MEM_PRIVATE` bytes, including allocator-owned mappings.
    pub commit_private: usize,
    /// Committed `MEM_MAPPED` bytes, such as mapped files or shared sections.
    pub commit_mapped: usize,
    /// Committed `MEM_IMAGE` bytes occupied by executable images.
    pub commit_image: usize,
    /// Committed bytes with an unrecognized Win32 memory type.
    pub commit_unknown: usize,
    /// Base address of the largest free range.
    pub largest_base: usize,
    /// Size of the largest free range.
    pub largest_free: usize,
    /// Base address of the second-largest free range.
    pub second_base: usize,
    /// Size of the second-largest free range.
    pub second_free: usize,
    /// Number of `VirtualQuery` regions visited.
    pub regions: u32,
    /// Number of regions classified as free holes.
    pub holes: u32,
}

#[derive(Clone, Copy)]
struct CachedSummary {
    summary: Summary,
    sampled_at_ms: u32,
}

fn next_region_address(current: usize, base: usize, size: usize) -> Option<usize> {
    let next = base.saturating_add(size.max(0x1000));
    (next > current).then_some(next)
}

/// Walk and classify the usable 32-bit process address space.
///
/// Returns `None` if a `VirtualQuery` call fails or reports no forward
/// progress. A failed walk does not overwrite the last complete cached sample.
pub fn sample() -> Option<Summary> {
    let mut summary = Summary::default();
    let mut addr = VA_START;

    while addr < VA_LIMIT {
        // Do not publish partial totals: they could admit a reservation based
        // on free VAS that was never actually enumerated.
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
                match info.memory_type() {
                    MemoryType::Private => {
                        summary.commit_private = summary.commit_private.saturating_add(size);
                    }
                    MemoryType::Mapped => {
                        summary.commit_mapped = summary.commit_mapped.saturating_add(size);
                    }
                    MemoryType::Image => {
                        summary.commit_image = summary.commit_image.saturating_add(size);
                    }
                    MemoryType::Unknown(_) => {
                        summary.commit_unknown = summary.commit_unknown.saturating_add(size);
                    }
                }
            }
            // Preserve forward progress for future Windows states while
            // excluding unknown bytes from trusted free/commit totals.
            MemoryState::Unknown(_) => {}
        }

        // A defensive page-size step prevents malformed or emulated zero-size
        // results from hanging the watchdog. Non-increasing addresses end the
        // sample without publishing wrapped data.
        addr = next_region_address(addr, base, size)?;
    }

    *LAST_SAMPLE.write() = Some(CachedSummary {
        summary,
        sampled_at_ms: get_tick_count(),
    });
    Some(summary)
}

/// Return the latest completed VAS walk without waiting or refreshing it.
///
/// The second value is the wrapping `GetTickCount` timestamp at publication.
/// Returns `None` rather than blocking when a writer currently owns the cache.
pub fn cached() -> Option<(Summary, u32)> {
    let cached = *LAST_SAMPLE.try_read()?;
    cached.map(|sample| (sample.summary, sample.sampled_at_ms))
}

/// Perform the dashboard's explicitly requested VAS refresh.
///
/// Concurrent refresh requests share the cached result instead of starting
/// parallel process-map walks. If the new walk fails, the last complete sample
/// is returned when available.
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

#[cfg(test)]
mod tests {
    use super::next_region_address;

    #[test]
    fn query_walk_requires_forward_progress() {
        assert_eq!(next_region_address(0x1000, 0x1000, 0), Some(0x2000));
        assert_eq!(next_region_address(0x3000, 0x1000, 0x1000), None);
    }
}
