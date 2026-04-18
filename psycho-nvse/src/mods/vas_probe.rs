//! VAS measurement probes for allocator / reservation tuning.
//!
//! Gated on `debug.vas_scan` and `debug.vas_probe` config flags. Both
//! default to `false` and should be off during normal play -- they are
//! only useful when the author is tuning mimalloc / slab reservation
//! sizes or investigating a VAS-pressure bug.
//!
//! Two functions:
//!
//! - `scan_vas(label)` -- walks `VirtualQuery` across the full 32-bit
//!   user address space and emits ONE compact INFO line:
//!   [VAS label] free=<total>MB largest=<base>+<size>MB second=<base>+<size>MB reserve=<total>MB commit=<total>MB regions=<count> holes=<count>
//!
//! - `probe_reserve_sizes()` -- tries `VirtualAlloc(NULL, size, MEM_RESERVE)`
//!   for a ladder of sizes and immediately releases each. Emits ONE
//!   compact INFO line with the largest successful size and its base:
//!   [VAS-PROBE] max=<size>MB base=<base> (tried <first>..<last>, first-fail=<size>MB err=<code>)
//!
//! No per-region output at any log level. No DEBUG fan-out. The goal is
//! a log you can actually read.

use libc::c_void;

use windows::Win32::System::Memory::{
	MEM_COMMIT, MEM_FREE, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
};

use libpsycho::os::windows::winapi::virtual_query;

const MB: usize = 1024 * 1024;

/// Upper bound of the user-mode address space we walk.
const VA_LIMIT: usize = 0xffff_0000;

/// Probe sizes (MB). Ascending.
const PROBE_SIZES_MB: &[usize] = &[
	16, 32, 64, 128, 192, 256, 320, 384, 448, 512, 640, 768, 896, 1024, 1280, 1536, 1792, 2048,
];

// ---------------------------------------------------------------------------
// VAS scan -- one INFO line, no DEBUG noise.
// ---------------------------------------------------------------------------

/// Walk VirtualQuery across the user VA range and log a single summary
/// line. Intended as a rare, targeted probe (preload + DeferredInit),
/// not a continuous monitor.
pub fn scan_vas(label: &str) {
    let cfg = match crate::config::get_config() {
        Ok(c) => c,
        Err(_) => return,
    };
    if !cfg.debug.vas_scan {
        return;
    }

	let mut addr: usize = 0x10000; // skip the NULL page
	let mut total_free: u64 = 0;
	let mut total_reserve: u64 = 0;
	let mut total_commit: u64 = 0;
	let mut hole_count: u32 = 0;
	let mut region_count: u32 = 0;
	let mut largest_hole: usize = 0;
	let mut largest_hole_base: usize = 0;
	let mut second_hole: usize = 0;
	let mut second_hole_base: usize = 0;

	while addr < VA_LIMIT {
		let info = match virtual_query(addr as *mut c_void) {
			Ok(i) => i,
			Err(_) => break,
		};
		region_count += 1;

		let base = info.base_address as usize;
		let size = info.region_size;
		let state = info.state;

		if state == MEM_FREE.0 {
			total_free += size as u64;
			hole_count += 1;
			if size > largest_hole {
				second_hole = largest_hole;
				second_hole_base = largest_hole_base;
				largest_hole = size;
				largest_hole_base = base;
			} else if size > second_hole {
				second_hole = size;
				second_hole_base = base;
			}
		} else if state == MEM_RESERVE.0 {
			total_reserve += size as u64;
		} else if state == MEM_COMMIT.0 {
			total_commit += size as u64;
		}

		let next = base.saturating_add(size.max(0x1000));
		if next <= addr {
			break;
		}
		addr = next;
	}

	log::info!(
		"[VAS {}] free={}MB largest=0x{:08x}+{}MB second=0x{:08x}+{}MB \
		 reserve={}MB commit={}MB regions={} holes={}",
		label,
		total_free / MB as u64,
		largest_hole_base,
		largest_hole / MB,
		second_hole_base,
		second_hole / MB,
		total_reserve / MB as u64,
		total_commit / MB as u64,
		region_count,
		hole_count,
	);
}

// ---------------------------------------------------------------------------
// Reserve probe -- one INFO line summary.
// ---------------------------------------------------------------------------

/// Try `VirtualAlloc(NULL, N, MEM_RESERVE)` for ascending N. Release
/// each success before the next attempt. Emits one summary line with
/// the largest size that succeeded and the first failure.
pub fn probe_reserve_sizes() {
    let cfg = match crate::config::get_config() {
        Ok(c) => c,
        Err(_) => return,
    };
    if !cfg.debug.vas_probe {
        return;
    }

	let mut max_ok_mb: usize = 0;
	let mut max_ok_base: usize = 0;
	let mut first_fail_mb: usize = 0;
	let mut first_fail_err: u32 = 0;

	for &mb in PROBE_SIZES_MB {
		let bytes = mb * MB;
		let ptr = unsafe { VirtualAlloc(None, bytes, MEM_RESERVE, PAGE_READWRITE) };
		if ptr.is_null() {
			let err = unsafe { windows::Win32::Foundation::GetLastError().0 };
			if first_fail_mb == 0 {
				first_fail_mb = mb;
				first_fail_err = err;
			}
			continue;
		}

		max_ok_mb = mb;
		max_ok_base = ptr as usize;

		let rel = unsafe { VirtualFree(ptr, 0, MEM_RELEASE) };
		if rel.is_err() {
			let err = unsafe { windows::Win32::Foundation::GetLastError().0 };
			log::error!(
				"[VAS-PROBE] RELEASE FAILED size={}MB base=0x{:08x} err=0x{:08x} \
				 -- stopping probe to avoid leak",
				mb,
				max_ok_base,
				err,
			);
			return;
		}
	}

	if first_fail_mb == 0 {
		log::info!(
			"[VAS-PROBE] max={}MB base=0x{:08x} (all sizes {}..{} MB succeeded)",
			max_ok_mb,
			max_ok_base,
			PROBE_SIZES_MB.first().copied().unwrap_or(0),
			PROBE_SIZES_MB.last().copied().unwrap_or(0),
		);
	} else {
		log::info!(
			"[VAS-PROBE] max={}MB base=0x{:08x} first-fail={}MB err=0x{:08x}",
			max_ok_mb, max_ok_base, first_fail_mb, first_fail_err,
		);
	}
}
