//! Runtime VAS telemetry for gheap.
//!
//! GlobalMemoryStatusEx tells us total available virtual memory, but the
//! crashes we care about are usually fragmentation failures: DirectX or
//! a texture load needs one large contiguous hole. This module samples
//! that largest-hole signal with VirtualQuery.

use libc::c_void;
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_FREE, MEM_RESERVE};

use libpsycho::os::windows::winapi::virtual_query;

pub const MB: usize = 1024 * 1024;
pub const CRITICAL_LARGEST_HOLE: usize = 128 * MB;

const VA_START: usize = 0x0001_0000;
const VA_LIMIT: usize = 0xffff_0000;

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

pub fn sample() -> Option<Summary> {
    let mut summary = Summary::default();
    let mut addr = VA_START;

    while addr < VA_LIMIT {
        let info = virtual_query(addr as *mut c_void).ok()?;
        summary.regions = summary.regions.saturating_add(1);

        let base = info.base_address as usize;
        let size = info.region_size;
        match info.state {
            s if s == MEM_FREE.0 => {
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
            s if s == MEM_RESERVE.0 => {
                summary.total_reserve = summary.total_reserve.saturating_add(size);
            }
            s if s == MEM_COMMIT.0 => {
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

    Some(summary)
}
