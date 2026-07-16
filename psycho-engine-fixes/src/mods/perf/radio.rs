//! Radio pathfinder yield optimization.
//!
//! TTW Capital Wasteland can expand enough path nodes during a periodic radio
//! scan to call Sleep(0) repeatedly. The scan and path algorithm stay vanilla;
//! only that scheduler yield is suppressed while the periodic scan is active.

use std::{
    cell::Cell,
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
};

use libc::c_void;

use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::winapi::{get_tick_count, replace_call},
};

use crate::mods::diagnostics;

const PERIODIC_RADIO_SCAN_CALL_ADDR: usize = 0x00833D86;
const RADIO_SIGNAL_SCAN_ADDR: usize = 0x004FF1A0;
const PATHFINDER_YIELD_CALL_ADDR: usize = 0x006F41C5;
const SLEEP_WRAPPER_ADDR: usize = 0x0040FCA0;
const SUMMARY_INTERVAL_MS: u32 = 10_000;

type RadioSignalScanFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void);
type SleepFn = unsafe extern "C" fn(u32);

thread_local! {
    static RADIO_SCAN_DEPTH: Cell<u32> = const { Cell::new(0) };
}

static SCANS: AtomicU64 = AtomicU64::new(0);
static SUPPRESSED_YIELDS: AtomicU64 = AtomicU64::new(0);
static SCAN_TOTAL_US: AtomicU64 = AtomicU64::new(0);
static SCAN_MAX_US: AtomicU64 = AtomicU64::new(0);
static LAST_SUMMARY_MS: AtomicU32 = AtomicU32::new(0);

struct RadioScanScope;

impl RadioScanScope {
    fn enter() -> Self {
        RADIO_SCAN_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
        Self
    }

    fn is_active() -> bool {
        RADIO_SCAN_DEPTH.with(|depth| depth.get() != 0)
    }
}

impl Drop for RadioScanScope {
    fn drop(&mut self) {
        RADIO_SCAN_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

pub fn install_radio_pathfinder_yield_fix() -> anyhow::Result<()> {
    verify_rel_call(PERIODIC_RADIO_SCAN_CALL_ADDR, RADIO_SIGNAL_SCAN_ADDR)?;
    verify_rel_call(PATHFINDER_YIELD_CALL_ADDR, SLEEP_WRAPPER_ADDR)?;

    unsafe {
        replace_call(
            PATHFINDER_YIELD_CALL_ADDR as *mut c_void,
            hook_pathfinder_yield as *mut c_void,
        )?;
        replace_call(
            PERIODIC_RADIO_SCAN_CALL_ADDR as *mut c_void,
            hook_periodic_radio_signal_scan as *mut c_void,
        )?;
    }

    log::info!(
        "[RADIO] Pathfinder yield fix active: scan_call=0x{:08X} yield_call=0x{:08X}",
        PERIODIC_RADIO_SCAN_CALL_ADDR,
        PATHFINDER_YIELD_CALL_ADDR,
    );
    Ok(())
}

unsafe extern "C" fn hook_periodic_radio_signal_scan(
    current_ref: *mut c_void,
    out_stations: *mut c_void,
    out_meta: *mut c_void,
) {
    let timer = diagnostics::Stopwatch::start_if_hitch_profiling();
    let scope = RadioScanScope::enter();
    let scan =
        unsafe { FnPtr::<RadioSignalScanFn>::from_address_unchecked(RADIO_SIGNAL_SCAN_ADDR) }
            .as_fn();
    unsafe { scan(current_ref, out_stations, out_meta) };
    drop(scope);

    SCANS.fetch_add(1, Ordering::Relaxed);
    if let Some(elapsed_us) = timer.elapsed_us() {
        SCAN_TOTAL_US.fetch_add(elapsed_us, Ordering::Relaxed);
        diagnostics::update_max_u64(&SCAN_MAX_US, elapsed_us);
    }
    maybe_log_summary();
}

unsafe extern "C" fn hook_pathfinder_yield(milliseconds: u32) {
    if milliseconds == 0 && RadioScanScope::is_active() {
        SUPPRESSED_YIELDS.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let sleep = unsafe { FnPtr::<SleepFn>::from_address_unchecked(SLEEP_WRAPPER_ADDR) }.as_fn();
    unsafe { sleep(milliseconds) };
}

fn verify_rel_call(call_addr: usize, expected_target: usize) -> anyhow::Result<()> {
    let opcode = unsafe { core::ptr::read_volatile(call_addr as *const u8) };
    if opcode != 0xE8 {
        return Err(anyhow::anyhow!(
            "callsite mismatch at 0x{call_addr:08X}: expected CALL opcode 0xE8, found 0x{opcode:02X}"
        ));
    }

    let displacement = unsafe { core::ptr::read_unaligned((call_addr + 1) as *const i32) };
    let observed_target = call_addr
        .wrapping_add(5)
        .wrapping_add_signed(displacement as isize);
    if observed_target != expected_target {
        return Err(anyhow::anyhow!(
            "callsite mismatch at 0x{call_addr:08X}: expected target 0x{expected_target:08X}, found 0x{observed_target:08X}"
        ));
    }

    Ok(())
}

fn maybe_log_summary() {
    if !diagnostics::hitch_profiling_enabled() || !log::log_enabled!(log::Level::Debug) {
        return;
    }

    let now = get_tick_count();
    let last = LAST_SUMMARY_MS.load(Ordering::Acquire);
    if now.wrapping_sub(last) < SUMMARY_INTERVAL_MS
        || LAST_SUMMARY_MS
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
    {
        return;
    }

    log::debug!(
        "[RADIO] scans={} suppressed_yields={} scan_us={}/{}",
        SCANS.load(Ordering::Relaxed),
        SUPPRESSED_YIELDS.load(Ordering::Relaxed),
        SCAN_MAX_US.load(Ordering::Relaxed),
        SCAN_TOTAL_US.load(Ordering::Relaxed),
    );
}
