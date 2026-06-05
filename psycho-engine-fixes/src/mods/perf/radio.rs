//! Radio nearby-station scan cache.
//!
//! TTW Capital Wasteland can make the periodic radio worker spend tens of
//! milliseconds in Radio::GetNearbyStations. Ghidra shows the hot recurring
//! caller is one callsite in FUN_00833d00; cold station-selection/menu callers
//! must stay vanilla.

use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use libc::c_void;
use parking_lot::Mutex;

use libpsycho::os::windows::winapi::{get_tick_count, replace_call};

const PERIODIC_RADIO_SCAN_CALL_ADDR: usize = 0x00833D86;
const RADIO_SIGNAL_SCAN_ADDR: usize = 0x004FF1A0;
const STATION_LIST_APPEND_ADDR: usize = 0x005AE3D0;
const META_LIST_APPEND_ADDR: usize = 0x004FF980;

const LOADING_FLAG_ADDR: usize = 0x011DEA2B;
const RADIO_CURRENT_ENTRY_ADDR: usize = 0x011DD42C;
const RADIO_LOST_ENTRY_ADDR: usize = 0x011DD430;
const RADIO_ENABLED_ADDR: usize = 0x011DD434;
const RADIO_DISABLED_GATE_ADDR: usize = 0x011DD436;
const RADIO_TRANSITION_GATE_ADDR: usize = 0x011DD437;
const RADIO_SCAN_LIST_ADDR: usize = 0x011C8264;
const RADIO_REGISTERED_LIST_ADDR: usize = 0x011DD554;
const FLOAT_LIST_EMPTY_SENTINEL_ADDR: usize = 0x01012060;

const MIN_CACHE_TTL_MS: u32 = 500;
const DEFAULT_CACHE_TTL_MS: u32 = 2_000;
const MAX_CACHE_TTL_MS: u32 = 10_000;
const SUMMARY_INTERVAL_MS: u32 = 10_000;
const MAX_CACHED_STATIONS: usize = 256;
const REL_CALL_OPCODE: u8 = 0xE8;

type RadioSignalScanFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void);
type StationListAppendFn = unsafe extern "thiscall" fn(*mut PointerList, *const *mut c_void);
type MetaListAppendFn = unsafe extern "thiscall" fn(*mut FloatList, *const f32);

#[repr(C)]
struct PointerList {
    value: *mut c_void,
    next: *mut PointerList,
}

#[repr(C)]
struct FloatList {
    value: f32,
    next: *mut FloatList,
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
struct CacheKey {
    current_ref: usize,
    radio_current_entry: usize,
    radio_lost_entry: usize,
    radio_scan_head: usize,
    radio_scan_next: usize,
    registered_head: usize,
    registered_next: usize,
    loading: u8,
    radio_enabled: u8,
    disabled_gate: u8,
    transition_gate: u8,
}

#[derive(Clone, Copy)]
struct CacheSnapshot {
    count: usize,
    stations: [usize; MAX_CACHED_STATIONS],
    meta_bits: [u32; MAX_CACHED_STATIONS],
}

impl CacheSnapshot {
    const fn empty() -> Self {
        Self {
            count: 0,
            stations: [0; MAX_CACHED_STATIONS],
            meta_bits: [0; MAX_CACHED_STATIONS],
        }
    }
}

struct RadioScanCache {
    valid: bool,
    filled_at_ms: u32,
    key: CacheKey,
    snapshot: CacheSnapshot,
}

impl RadioScanCache {
    const fn new() -> Self {
        Self {
            valid: false,
            filled_at_ms: 0,
            key: CacheKey {
                current_ref: 0,
                radio_current_entry: 0,
                radio_lost_entry: 0,
                radio_scan_head: 0,
                radio_scan_next: 0,
                registered_head: 0,
                registered_next: 0,
                loading: 0,
                radio_enabled: 0,
                disabled_gate: 0,
                transition_gate: 0,
            },
            snapshot: CacheSnapshot::empty(),
        }
    }

    fn get(&self, key: CacheKey, now_ms: u32, ttl_ms: u32) -> Option<CacheSnapshot> {
        if !self.valid {
            return None;
        }
        if self.key != key {
            return None;
        }
        if now_ms.wrapping_sub(self.filled_at_ms) >= ttl_ms {
            return None;
        }
        Some(self.snapshot)
    }

    fn replace(&mut self, key: CacheKey, now_ms: u32, snapshot: CacheSnapshot) {
        self.valid = true;
        self.filled_at_ms = now_ms;
        self.key = key;
        self.snapshot = snapshot;
    }

    fn invalidate(&mut self) {
        self.valid = false;
        self.snapshot.count = 0;
    }
}

static CACHE: Mutex<RadioScanCache> = Mutex::new(RadioScanCache::new());

static HITS: AtomicUsize = AtomicUsize::new(0);
static MISSES: AtomicUsize = AtomicUsize::new(0);
static BYPASSES: AtomicUsize = AtomicUsize::new(0);
static CAPTURE_FAILS: AtomicUsize = AtomicUsize::new(0);
static LAST_ENTRY_COUNT: AtomicUsize = AtomicUsize::new(0);
static LAST_SUMMARY_MS: AtomicU32 = AtomicU32::new(0);
static CACHE_TTL_MS: AtomicU32 = AtomicU32::new(DEFAULT_CACHE_TTL_MS);

pub fn install_radio_signal_scan_cache(ttl_ms: u32) -> anyhow::Result<()> {
    let opcode = read_u8(PERIODIC_RADIO_SCAN_CALL_ADDR);
    if opcode != REL_CALL_OPCODE {
        return Err(anyhow::anyhow!(
            "radio scan cache callsite mismatch at 0x{:08x}: expected CALL 0x{:02x}, found 0x{:02x}",
            PERIODIC_RADIO_SCAN_CALL_ADDR,
            REL_CALL_OPCODE,
            opcode
        ));
    }

    let effective_ttl_ms = ttl_ms.clamp(MIN_CACHE_TTL_MS, MAX_CACHE_TTL_MS);
    if effective_ttl_ms != ttl_ms {
        log::warn!(
            "[RADIO] radio_signal_scan_cache_ttl_ms={} is outside supported range {}..={}ms; using {}ms",
            ttl_ms,
            MIN_CACHE_TTL_MS,
            MAX_CACHE_TTL_MS,
            effective_ttl_ms
        );
    }
    CACHE_TTL_MS.store(effective_ttl_ms, Ordering::Relaxed);

    unsafe {
        replace_call(
            PERIODIC_RADIO_SCAN_CALL_ADDR as *mut c_void,
            hook_periodic_radio_signal_scan as *mut c_void,
        )?;
    }

    log::info!(
        "[RADIO] Periodic nearby-station scan cache active: callsite=0x{:08x} ttl={}ms",
        PERIODIC_RADIO_SCAN_CALL_ADDR,
        effective_ttl_ms
    );
    Ok(())
}

pub unsafe extern "C" fn hook_periodic_radio_signal_scan(
    current_ref: *mut c_void,
    out_stations: *mut c_void,
    out_meta: *mut c_void,
) {
    let now_ms = get_tick_count();
    maybe_log_summary(now_ms);

    if current_ref.is_null() || out_stations.is_null() || out_meta.is_null() {
        BYPASSES.fetch_add(1, Ordering::Relaxed);
        invalidate_cache();
        unsafe { call_vanilla_radio_scan(current_ref, out_stations, out_meta) };
        return;
    }

    let key = read_key(current_ref);
    if key.loading != 0 || key.disabled_gate != 0 || key.transition_gate != 0 {
        BYPASSES.fetch_add(1, Ordering::Relaxed);
        invalidate_cache();
        unsafe { call_vanilla_radio_scan(current_ref, out_stations, out_meta) };
        return;
    }

    let ttl_ms = CACHE_TTL_MS.load(Ordering::Relaxed);
    let cached = CACHE.lock().get(key, now_ms, ttl_ms);

    if let Some(snapshot) = cached {
        HITS.fetch_add(1, Ordering::Relaxed);
        LAST_ENTRY_COUNT.store(snapshot.count, Ordering::Relaxed);
        unsafe { replay_snapshot(snapshot, out_stations.cast(), out_meta.cast()) };
        return;
    }

    MISSES.fetch_add(1, Ordering::Relaxed);
    unsafe { call_vanilla_radio_scan(current_ref, out_stations, out_meta) };

    match unsafe { capture_snapshot(out_stations.cast(), out_meta.cast()) } {
        Some(snapshot) => {
            LAST_ENTRY_COUNT.store(snapshot.count, Ordering::Relaxed);
            CACHE.lock().replace(key, now_ms, snapshot);
        }
        None => {
            CAPTURE_FAILS.fetch_add(1, Ordering::Relaxed);
            invalidate_cache();
        }
    }
}

fn invalidate_cache() {
    CACHE.lock().invalidate();
}

fn read_key(current_ref: *mut c_void) -> CacheKey {
    CacheKey {
        current_ref: current_ref as usize,
        radio_current_entry: read_usize(RADIO_CURRENT_ENTRY_ADDR),
        radio_lost_entry: read_usize(RADIO_LOST_ENTRY_ADDR),
        radio_scan_head: read_usize(RADIO_SCAN_LIST_ADDR),
        radio_scan_next: read_usize(RADIO_SCAN_LIST_ADDR + 4),
        registered_head: read_usize(RADIO_REGISTERED_LIST_ADDR),
        registered_next: read_usize(RADIO_REGISTERED_LIST_ADDR + 4),
        loading: read_u8(LOADING_FLAG_ADDR),
        radio_enabled: read_u8(RADIO_ENABLED_ADDR),
        disabled_gate: read_u8(RADIO_DISABLED_GATE_ADDR),
        transition_gate: read_u8(RADIO_TRANSITION_GATE_ADDR),
    }
}

unsafe fn call_vanilla_radio_scan(
    current_ref: *mut c_void,
    out_stations: *mut c_void,
    out_meta: *mut c_void,
) {
    let f: RadioSignalScanFn = unsafe { core::mem::transmute(RADIO_SIGNAL_SCAN_ADDR) };
    unsafe { f(current_ref, out_stations, out_meta) };
}

unsafe fn replay_snapshot(
    snapshot: CacheSnapshot,
    out_stations: *mut PointerList,
    out_meta: *mut FloatList,
) {
    let append_station: StationListAppendFn =
        unsafe { core::mem::transmute(STATION_LIST_APPEND_ADDR) };
    let append_meta: MetaListAppendFn = unsafe { core::mem::transmute(META_LIST_APPEND_ADDR) };

    for i in (0..snapshot.count).rev() {
        let station = snapshot.stations[i] as *mut c_void;
        let meta = f32::from_bits(snapshot.meta_bits[i]);

        unsafe { append_station(out_stations, &station) };
        unsafe { append_meta(out_meta, &meta) };
    }
}

unsafe fn capture_snapshot(
    out_stations: *const PointerList,
    out_meta: *const FloatList,
) -> Option<CacheSnapshot> {
    let sentinel = read_f32_bits(FLOAT_LIST_EMPTY_SENTINEL_ADDR);
    let mut snapshot = CacheSnapshot::empty();
    let mut station_node = out_stations;
    let mut meta_node = out_meta;

    loop {
        if station_node.is_null() || meta_node.is_null() {
            return None;
        }

        let station =
            unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*station_node).value)) };
        if station.is_null() {
            if snapshot.count == 0 {
                return Some(snapshot);
            }
            return None;
        }

        if snapshot.count >= MAX_CACHED_STATIONS {
            return None;
        }

        let meta = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*meta_node).value)) };
        let meta_bits = meta.to_bits();
        if meta_bits == sentinel {
            return None;
        }

        snapshot.stations[snapshot.count] = station as usize;
        snapshot.meta_bits[snapshot.count] = meta_bits;
        snapshot.count += 1;

        let next_station =
            unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*station_node).next)) };
        let next_meta =
            unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*meta_node).next)) };
        if next_station.is_null() && next_meta.is_null() {
            return Some(snapshot);
        }
        if next_station.is_null() || next_meta.is_null() {
            return None;
        }

        station_node = next_station;
        meta_node = next_meta;
    }
}

fn maybe_log_summary(now_ms: u32) {
    if !log::log_enabled!(log::Level::Debug) {
        return;
    }

    let last = LAST_SUMMARY_MS.load(Ordering::Relaxed);
    if now_ms.wrapping_sub(last) < SUMMARY_INTERVAL_MS {
        return;
    }
    if LAST_SUMMARY_MS
        .compare_exchange(last, now_ms, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return;
    }

    log::debug!(
        "[RADIO] scan_cache hits={} misses={} bypasses={} capture_fails={} last_entries={} ttl_ms={}",
        HITS.load(Ordering::Relaxed),
        MISSES.load(Ordering::Relaxed),
        BYPASSES.load(Ordering::Relaxed),
        CAPTURE_FAILS.load(Ordering::Relaxed),
        LAST_ENTRY_COUNT.load(Ordering::Relaxed),
        CACHE_TTL_MS.load(Ordering::Relaxed)
    );
}

fn read_u8(addr: usize) -> u8 {
    unsafe { core::ptr::read_volatile(addr as *const u8) }
}

fn read_usize(addr: usize) -> usize {
    unsafe { core::ptr::read_volatile(addr as *const usize) }
}

fn read_f32_bits(addr: usize) -> u32 {
    unsafe { core::ptr::read_volatile(addr as *const f32).to_bits() }
}
