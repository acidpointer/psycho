//! Radio scan dead door-policy bypass and hot-path attribution.
//!
//! TTW's cross-worldspace mode-0 radio fix runs synchronous teleport-door
//! searches. Radio queries use disposition 3 without actor data, making the
//! provider's door-policy setup and accessibility result irrelevant.

use std::{
    cell::{Cell, RefCell},
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use anyhow::{Context, ensure};
use libc::c_void;

use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::{
        hook::{inline::inlinehook::InlineHookContainer, transaction::ModificationTransaction},
        memory::read_bytes,
        patch::module_address,
        winapi::replace_call,
    },
};

use crate::mods::diagnostics;

const PERIODIC_RADIO_SCAN_CALL_ADDR: usize = 0x00833D86;
const RADIO_SIGNAL_SCAN_ADDR: usize = 0x004FF1A0;
const PATH_QUERY_ADDR: usize = 0x006D4D20;
const PATH_TRAVERSAL_ADDR: usize = 0x006F3FB0;
const STATION_MODE_ADDR: usize = 0x0056B210;
const RADIO_QUERY_VTABLE: usize = 0x0106D8FC;
const TELEPORT_DOOR_PROVIDER_SLOT: usize = 0x0106D900;
const DOOR_ACCESSIBILITY_ADDR: usize = 0x00502450;
const STEWIE_POLICY_SETUP_CALL_OFFSET: usize = 0x12B;
const STEWIE_POLICY_BLOCK_OFFSET: usize = 0x118;
const STEWIE_ACCESSIBILITY_CALL_OFFSET: usize = 0x140;
const STEWIE_ACCESSIBILITY_RESULT_OFFSET: usize = 0x153;
const STEWIE_DISPOSITION_BRANCH_OFFSET: usize = 0x174;
const STEWIE_MIN_USE_BRANCH_OFFSET: usize = 0x199;
const STEWIE_LOCK_CLEANUP_OFFSET: usize = 0x2C4;
const PRIORITY_BUCKET_COUNT: usize = 20;
const SLOW_SCAN_US: u64 = 5_000;

const STEWIE_PROVIDER_SIGNATURE: &[u8] = &[
    0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF8, 0x83, 0xEC, 0x34, 0x53, 0x56, 0x57, 0x8B, 0xF9, 0x8B, 0x4D,
    0x08,
];
const STEWIE_POLICY_BLOCK_SIGNATURE: &[u8] = &[
    0x8B, 0x4C, 0x24, 0x18, 0x33, 0xD2, 0x51, 0x8D, 0x4C, 0x24, 0x2C, 0xC7, 0x44, 0x24, 0x34, 0x00,
    0x00, 0x00, 0x00, 0xE8,
];
const STEWIE_ACCESSIBILITY_CALL_SIGNATURE: &[u8] = &[
    0xF3, 0x0F, 0x11, 0x44, 0x24, 0x24, 0xFF, 0xB7, 0xA0, 0x20, 0x00, 0x00, 0xB8, 0x50, 0x24, 0x50,
    0x00, 0xFF, 0xD0,
];
const STEWIE_ACCESSIBILITY_RESULT_SIGNATURE: &[u8] = &[
    0x84, 0xC0, 0x74, 0x07, 0x80, 0x7C, 0x24, 0x13, 0x00, 0x74, 0x23, 0x8B, 0x87, 0xB4, 0x20, 0x00,
    0x00, 0x85, 0xC0, 0x0F, 0x84, 0x58, 0x01, 0x00, 0x00,
];
const STEWIE_DISPOSITION_BRANCH_SIGNATURE: &[u8] = &[
    0x83, 0xF8, 0x02, 0x75, 0x10, 0xF3, 0x0F, 0x11, 0x44, 0x24, 0x1C, 0xEB, 0x08,
];
const STEWIE_MIN_USE_BRANCH_SIGNATURE: &[u8] = &[
    0xA8, 0x01, 0x74, 0x0F, 0x83, 0xBF, 0xB4, 0x20, 0x00, 0x00, 0x03, 0x74, 0x06, 0xF3, 0x0F, 0x11,
    0x44, 0x24, 0x1C,
];
const STEWIE_LOCK_CLEANUP_SIGNATURE: &[u8] = &[
    0x8B, 0x44, 0x24, 0x30, 0x85, 0xC0, 0x74, 0x0D, 0x50, 0xB9, 0x38, 0x62, 0x1F, 0x01, 0xB8, 0x60,
    0x40, 0xAA, 0x00, 0xFF, 0xD0,
];
const STEWIE_POLICY_SETUP_SIGNATURE: &[u8] = &[
    0x53, 0x55, 0x8B, 0x6C, 0x24, 0x0C, 0xBA, 0x20, 0x02, 0x41, 0x00, 0x56, 0x57, 0x8B, 0xF9, 0x33,
    0xF6, 0x8B, 0x45, 0x40,
];
const DOOR_ACCESSIBILITY_SIGNATURE: &[u8] = &[
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x0C, 0x89, 0x4D, 0xF4, 0xC6, 0x45, 0xFF, 0x00, 0xC7, 0x45, 0xF8,
    0x00, 0x00, 0x00, 0x00,
];

type RadioSignalScanFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void);
type PathQueryFn = unsafe extern "C" fn(usize, usize, *mut c_void, u32, u32, u32, u32) -> u8;
type PathTraversalFn = unsafe extern "fastcall" fn(*mut c_void) -> usize;
type StationModeFn = unsafe extern "fastcall" fn(*mut c_void) -> u32;
type DoorPolicySetupFn = unsafe extern "fastcall" fn(*mut c_void, *mut c_void, *mut c_void);
type DoorAccessibilityFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, *mut c_void, *mut u8) -> u8;

static PATH_QUERY_HOOK: LazyLock<InlineHookContainer<PathQueryFn>> =
    LazyLock::new(InlineHookContainer::new);
static PATH_TRAVERSAL_HOOK: LazyLock<InlineHookContainer<PathTraversalFn>> =
    LazyLock::new(InlineHookContainer::new);
static STATION_MODE_HOOK: LazyLock<InlineHookContainer<StationModeFn>> =
    LazyLock::new(InlineHookContainer::new);
static DOOR_POLICY_SETUP_HOOK: LazyLock<InlineHookContainer<DoorPolicySetupFn>> =
    LazyLock::new(InlineHookContainer::new);
static DOOR_ACCESSIBILITY_HOOK: LazyLock<InlineHookContainer<DoorAccessibilityFn>> =
    LazyLock::new(InlineHookContainer::new);
static SCAN_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static POLICY_INSTALL_ATTEMPTED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Default)]
struct Timing {
    calls: u32,
    total_us: u64,
    max_us: u64,
}

impl Timing {
    fn record(&mut self, elapsed_us: Option<u64>) {
        self.calls = self.calls.saturating_add(1);
        let Some(elapsed_us) = elapsed_us else {
            return;
        };
        self.total_us = self.total_us.saturating_add(elapsed_us);
        self.max_us = self.max_us.max(elapsed_us);
    }
}

#[derive(Clone, Copy)]
struct ScanStats {
    mode_queries: [Timing; 3],
    other_queries: Timing,
    traversals: Timing,
    station_modes: [u32; 5],
    other_station_modes: u32,
    mode0_traversals: u32,
    expected_query_vtable: u32,
    queue_empty_before_traversal: u32,
    source_missing: u32,
    source_first: u32,
    source_goal_match: u32,
    source_parent_null: u32,
    result_null: u32,
    result_source: u32,
    result_other: u32,
    policy_queries: u32,
    policy_setup_bypasses: u32,
    policy_access_bypasses: u32,
}

impl Default for ScanStats {
    fn default() -> Self {
        Self {
            mode_queries: [Timing::default(); 3],
            other_queries: Timing::default(),
            traversals: Timing::default(),
            station_modes: [0; 5],
            other_station_modes: 0,
            mode0_traversals: 0,
            expected_query_vtable: 0,
            queue_empty_before_traversal: 0,
            source_missing: 0,
            source_first: 0,
            source_goal_match: 0,
            source_parent_null: 0,
            result_null: 0,
            result_source: 0,
            result_other: 0,
            policy_queries: 0,
            policy_setup_bypasses: 0,
            policy_access_bypasses: 0,
        }
    }
}

#[derive(Default)]
struct RadioScanState {
    stats: ScanStats,
}

thread_local! {
    static RADIO_SCAN_DEPTH: Cell<u32> = const { Cell::new(0) };
    static POLICY_BYPASS_DEPTH: Cell<u32> = const { Cell::new(0) };
    static PENDING_POLICY_ACCESS: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    static RADIO_SCAN_STATE: RefCell<RadioScanState> = RefCell::new(RadioScanState::default());
}

struct RadioScanScope;

impl RadioScanScope {
    fn enter() -> Self {
        let outermost = RADIO_SCAN_DEPTH.with(|depth| {
            let current = depth.get();
            depth.set(current.saturating_add(1));
            current == 0
        });
        if outermost {
            RADIO_SCAN_STATE.with(|state| {
                let mut state = state.borrow_mut();
                state.stats = ScanStats::default();
            });
        }
        Self
    }
}

impl Drop for RadioScanScope {
    fn drop(&mut self) {
        let outermost = RADIO_SCAN_DEPTH.with(|depth| {
            let current = depth.get();
            depth.set(current.saturating_sub(1));
            current == 1
        });
        if outermost {
            PENDING_POLICY_ACCESS.with(|pending| pending.set((0, 0)));
        }
    }
}

struct DoorPolicyBypassScope {
    active: bool,
}

impl DoorPolicyBypassScope {
    unsafe fn enter(query: *const u8) -> Self {
        let active = unsafe { is_exact_radio_policy_query(query) };
        if active {
            POLICY_BYPASS_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
            PENDING_POLICY_ACCESS.with(|pending| pending.set((0, 0)));
            with_active_stats(|stats| {
                stats.policy_queries = stats.policy_queries.saturating_add(1);
            });
        }
        Self { active }
    }
}

impl Drop for DoorPolicyBypassScope {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        PENDING_POLICY_ACCESS.with(|pending| pending.set((0, 0)));
        POLICY_BYPASS_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

pub fn install_radio_scan_fix() -> anyhow::Result<()> {
    verify_rel_call(PERIODIC_RADIO_SCAN_CALL_ADDR, RADIO_SIGNAL_SCAN_ADDR)?;
    unsafe {
        replace_call(
            PERIODIC_RADIO_SCAN_CALL_ADDR as *mut c_void,
            hook_periodic_radio_signal_scan as *mut c_void,
        )?;
    }

    log::info!(
        "[RADIO] Exact radio door-policy scope active: scan=0x{:08X}",
        PERIODIC_RADIO_SCAN_CALL_ADDR,
    );

    let profiling = diagnostics::hitch_profiling_enabled();

    unsafe {
        PATH_TRAVERSAL_HOOK.init(
            "radio_path_traversal_policy_scope",
            PATH_TRAVERSAL_ADDR as *mut c_void,
            hook_path_traversal,
        )?;
        if profiling {
            PATH_QUERY_HOOK.init(
                "radio_path_query_profile",
                PATH_QUERY_ADDR as *mut c_void,
                hook_path_query,
            )?;
            STATION_MODE_HOOK.init(
                "radio_station_mode_profile",
                STATION_MODE_ADDR as *mut c_void,
                hook_station_mode,
            )?;
        }
    }

    let mut transaction = ModificationTransaction::new();
    transaction.enable_inline(&PATH_TRAVERSAL_HOOK)?;
    if profiling {
        transaction.enable_inline(&PATH_QUERY_HOOK)?;
        transaction.enable_inline(&STATION_MODE_HOOK)?;
    }
    transaction.commit();

    if profiling {
        log::info!(
            "[RADIO] Scan hot-path profiling active: modes=0x{:08X} query=0x{:08X} traversal=0x{:08X}",
            STATION_MODE_ADDR,
            PATH_QUERY_ADDR,
            PATH_TRAVERSAL_ADDR,
        );
    }
    Ok(())
}

pub(crate) fn observe_event(kind: u32) {
    if kind != crate::events::DEFERRED_INIT || POLICY_INSTALL_ATTEMPTED.swap(true, Ordering::AcqRel)
    {
        return;
    }

    if let Err(error) = install_door_policy_bypass_hooks() {
        log::warn!(
            "[RADIO] Dead door-policy bypass unavailable; original provider retained: {error:#}"
        );
    }
}

fn install_door_policy_bypass_hooks() -> anyhow::Result<()> {
    let provider = unsafe { read_u32(TELEPORT_DOOR_PROVIDER_SLOT as *const u8, 0) } as usize;
    let provider_label =
        module_address(provider).unwrap_or_else(|| format!("unknown!0x{provider:08X}"));

    ensure!(
        module_name(provider)
            .is_some_and(|name| name.eq_ignore_ascii_case("nvse_stewie_tweaks.dll")),
        "unsupported teleport-door provider {provider_label}"
    );
    verify_signature(
        provider,
        STEWIE_PROVIDER_SIGNATURE,
        "Stewie TeleportDoorSearch provider",
    )?;
    verify_signature(
        provider + STEWIE_POLICY_BLOCK_OFFSET,
        STEWIE_POLICY_BLOCK_SIGNATURE,
        "Stewie door-policy block",
    )?;
    verify_signature(
        provider + STEWIE_ACCESSIBILITY_CALL_OFFSET,
        STEWIE_ACCESSIBILITY_CALL_SIGNATURE,
        "Stewie accessibility call",
    )?;
    verify_signature(
        provider + STEWIE_ACCESSIBILITY_RESULT_OFFSET,
        STEWIE_ACCESSIBILITY_RESULT_SIGNATURE,
        "Stewie accessibility result branch",
    )?;
    verify_signature(
        provider + STEWIE_DISPOSITION_BRANCH_OFFSET,
        STEWIE_DISPOSITION_BRANCH_SIGNATURE,
        "Stewie disposition penalty branch",
    )?;
    verify_signature(
        provider + STEWIE_MIN_USE_BRANCH_OFFSET,
        STEWIE_MIN_USE_BRANCH_SIGNATURE,
        "Stewie minimum-use penalty branch",
    )?;
    verify_signature(
        provider + STEWIE_LOCK_CLEANUP_OFFSET,
        STEWIE_LOCK_CLEANUP_SIGNATURE,
        "Stewie temporary lock-data cleanup",
    )?;

    let setup_target = relative_call_target(provider + STEWIE_POLICY_SETUP_CALL_OFFSET)
        .context("resolve Stewie door-policy setup call")?;
    ensure!(
        module_name(setup_target)
            .is_some_and(|name| name.eq_ignore_ascii_case("nvse_stewie_tweaks.dll")),
        "unsupported Stewie door-policy setup target {}",
        module_address(setup_target).unwrap_or_else(|| format!("unknown!0x{setup_target:08X}"))
    );
    verify_signature(
        setup_target,
        STEWIE_POLICY_SETUP_SIGNATURE,
        "Stewie TeleportDoorData setup",
    )?;
    verify_signature(
        DOOR_ACCESSIBILITY_ADDR,
        DOOR_ACCESSIBILITY_SIGNATURE,
        "game teleport-door accessibility predicate",
    )?;

    unsafe {
        DOOR_POLICY_SETUP_HOOK.init(
            "radio_dead_door_policy_setup",
            setup_target as *mut c_void,
            hook_door_policy_setup,
        )?;
        DOOR_ACCESSIBILITY_HOOK.init(
            "radio_dead_door_accessibility",
            DOOR_ACCESSIBILITY_ADDR as *mut c_void,
            hook_door_accessibility,
        )?;
    }
    let mut transaction = ModificationTransaction::new();
    transaction.enable_inline(&DOOR_POLICY_SETUP_HOOK)?;
    transaction.enable_inline(&DOOR_ACCESSIBILITY_HOOK)?;
    transaction.commit();

    log::info!(
        "[RADIO] Exact mode-0 dead door-policy bypass active: provider={} setup={} accessibility=0x{:08X}",
        provider_label,
        module_address(setup_target).unwrap_or_else(|| format!("unknown!0x{setup_target:08X}")),
        DOOR_ACCESSIBILITY_ADDR,
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

    let Some(elapsed_us) = timer.elapsed_us() else {
        return;
    };
    if elapsed_us < SLOW_SCAN_US || !log::log_enabled!(log::Level::Debug) {
        return;
    }

    let sequence = SCAN_SEQUENCE.fetch_add(1, Ordering::Relaxed) + 1;
    let stats = RADIO_SCAN_STATE.with(|state| state.borrow().stats);
    log::debug!(
        "[RADIO_SCAN] seq={} total_us={} station_modes={}/{}/{}/{}/{}+{} query0={}/{}/{} query1={}/{}/{} query2={}/{}/{} other={}/{}/{} traversal={}/{}/{} branch=m0:{}/vtable:{}/empty:{}/missing:{}/first:{}/goal:{}/parent0:{}/result0:{}/source:{}/other:{} policy=query:{}/setup:{}/access:{} residual_us={}",
        sequence,
        elapsed_us,
        stats.station_modes[0],
        stats.station_modes[1],
        stats.station_modes[2],
        stats.station_modes[3],
        stats.station_modes[4],
        stats.other_station_modes,
        stats.mode_queries[0].calls,
        stats.mode_queries[0].total_us,
        stats.mode_queries[0].max_us,
        stats.mode_queries[1].calls,
        stats.mode_queries[1].total_us,
        stats.mode_queries[1].max_us,
        stats.mode_queries[2].calls,
        stats.mode_queries[2].total_us,
        stats.mode_queries[2].max_us,
        stats.other_queries.calls,
        stats.other_queries.total_us,
        stats.other_queries.max_us,
        stats.traversals.calls,
        stats.traversals.total_us,
        stats.traversals.max_us,
        stats.mode0_traversals,
        stats.expected_query_vtable,
        stats.queue_empty_before_traversal,
        stats.source_missing,
        stats.source_first,
        stats.source_goal_match,
        stats.source_parent_null,
        stats.result_null,
        stats.result_source,
        stats.result_other,
        stats.policy_queries,
        stats.policy_setup_bypasses,
        stats.policy_access_bypasses,
        elapsed_us.saturating_sub(
            stats
                .mode_queries
                .iter()
                .map(|timing| timing.total_us)
                .sum()
        ),
    );
}

unsafe extern "C" fn hook_path_query(
    from: usize,
    to: usize,
    result: *mut c_void,
    mode: u32,
    max_cost: u32,
    filter: u32,
    behavior: u32,
) -> u8 {
    let Ok(original) = PATH_QUERY_HOOK.original() else {
        return 0;
    };
    if !radio_scan_active() {
        return unsafe { original(from, to, result, mode, max_cost, filter, behavior) };
    }

    let timer = diagnostics::Stopwatch::start();
    let result_value = unsafe { original(from, to, result, mode, max_cost, filter, behavior) };
    let elapsed_us = timer.elapsed_us();
    with_active_stats(|stats| {
        if let Some(timing) = stats.mode_queries.get_mut(mode as usize) {
            timing.record(elapsed_us);
        } else {
            stats.other_queries.record(elapsed_us);
        }
    });
    result_value
}

unsafe extern "fastcall" fn hook_path_traversal(query: *mut c_void) -> usize {
    let Ok(original) = PATH_TRAVERSAL_HOOK.original() else {
        return 0;
    };
    if !radio_scan_active() {
        return unsafe { original(query) };
    }

    let policy_scope = unsafe { DoorPolicyBypassScope::enter(query.cast()) };
    if !diagnostics::hitch_profiling_enabled() {
        let result = unsafe { original(query) };
        drop(policy_scope);
        return result;
    }

    let probe = unsafe { TraversalProbe::capture(query.cast()) };
    let timer = diagnostics::Stopwatch::start();
    let result = unsafe { original(query) };
    drop(policy_scope);
    let elapsed_us = timer.elapsed_us();
    with_active_stats(|stats| {
        stats.traversals.record(elapsed_us);
        probe.record(result, stats);
    });
    result
}

#[derive(Clone, Copy, Default)]
struct TraversalProbe {
    mode0: bool,
    expected_vtable: bool,
    queue_empty: bool,
    source: usize,
    source_first: bool,
    source_goal_match: bool,
    source_parent_null: bool,
}

impl TraversalProbe {
    unsafe fn capture(query: *const u8) -> Self {
        if query.is_null() {
            return Self::default();
        }

        let mode = unsafe { read_u32(query, 0x2098) };
        if mode != 0 {
            return Self::default();
        }

        let source = unsafe { read_u32(query, 0x2050) } as usize;
        let first_queued = unsafe { first_queued_node(query) };
        let source_goal_match = source != 0
            && unsafe { core::ptr::read_unaligned((source + 0x08) as *const u8) }
                == unsafe { core::ptr::read_unaligned(query.add(0x208C)) }
            && unsafe { core::ptr::read_unaligned((source + 0x0C) as *const u32) }
                == unsafe { read_u32(query, 0x2090) }
            && unsafe { core::ptr::read_unaligned((source + 0x10) as *const u32) }
                == unsafe { read_u32(query, 0x2094) };

        Self {
            mode0: true,
            expected_vtable: unsafe { read_u32(query, 0) } as usize == RADIO_QUERY_VTABLE,
            queue_empty: first_queued == 0,
            source,
            source_first: source != 0 && first_queued == source,
            source_goal_match,
            source_parent_null: source != 0
                && unsafe { core::ptr::read_unaligned((source + 0x24) as *const u32) } == 0,
        }
    }

    fn record(self, result: usize, stats: &mut ScanStats) {
        if !self.mode0 {
            return;
        }

        stats.mode0_traversals = stats.mode0_traversals.saturating_add(1);
        stats.expected_query_vtable = stats
            .expected_query_vtable
            .saturating_add(u32::from(self.expected_vtable));
        stats.queue_empty_before_traversal = stats
            .queue_empty_before_traversal
            .saturating_add(u32::from(self.queue_empty));
        stats.source_missing = stats
            .source_missing
            .saturating_add(u32::from(self.source == 0));
        stats.source_first = stats
            .source_first
            .saturating_add(u32::from(self.source_first));
        stats.source_goal_match = stats
            .source_goal_match
            .saturating_add(u32::from(self.source_goal_match));
        stats.source_parent_null = stats
            .source_parent_null
            .saturating_add(u32::from(self.source_parent_null));
        if result == 0 {
            stats.result_null = stats.result_null.saturating_add(1);
        } else if result == self.source {
            stats.result_source = stats.result_source.saturating_add(1);
        } else {
            stats.result_other = stats.result_other.saturating_add(1);
        }
    }
}

unsafe extern "fastcall" fn hook_door_policy_setup(
    data: *mut c_void,
    edx: *mut c_void,
    door: *mut c_void,
) {
    let Ok(original) = DOOR_POLICY_SETUP_HOOK.original() else {
        return;
    };
    if !policy_bypass_active() || data.is_null() || door.is_null() {
        unsafe { original(data, edx, door) };
        return;
    }

    PENDING_POLICY_ACCESS.with(|pending| pending.set((data as usize, door as usize)));
    with_active_stats(|stats| {
        stats.policy_setup_bypasses = stats.policy_setup_bypasses.saturating_add(1);
    });
}

unsafe extern "thiscall" fn hook_door_accessibility(
    data: *mut c_void,
    actor_data: *mut c_void,
    door: *mut c_void,
    out_flag: *mut u8,
) -> u8 {
    let Ok(original) = DOOR_ACCESSIBILITY_HOOK.original() else {
        return 0;
    };

    let expected = (data as usize, door as usize);
    let paired = policy_bypass_active()
        && actor_data.is_null()
        && !out_flag.is_null()
        && PENDING_POLICY_ACCESS.with(|pending| pending.get() == expected);
    if !paired {
        return unsafe { original(data, actor_data, door, out_flag) };
    }

    PENDING_POLICY_ACCESS.with(|pending| pending.set((0, 0)));
    unsafe { out_flag.write(0) };
    with_active_stats(|stats| {
        stats.policy_access_bypasses = stats.policy_access_bypasses.saturating_add(1);
    });
    1
}

unsafe extern "fastcall" fn hook_station_mode(station: *mut c_void) -> u32 {
    let Ok(original) = STATION_MODE_HOOK.original() else {
        return 0;
    };
    let mode = unsafe { original(station) };
    if radio_scan_active() {
        with_active_stats(|stats| {
            if let Some(count) = stats.station_modes.get_mut(mode as usize) {
                *count = count.saturating_add(1);
            } else {
                stats.other_station_modes = stats.other_station_modes.saturating_add(1);
            }
        });
    }
    mode
}

fn radio_scan_active() -> bool {
    RADIO_SCAN_DEPTH.with(|depth| depth.get() != 0)
}

fn policy_bypass_active() -> bool {
    POLICY_BYPASS_DEPTH.with(|depth| depth.get() != 0)
}

unsafe fn is_exact_radio_policy_query(query: *const u8) -> bool {
    !query.is_null()
        && radio_scan_active()
        && unsafe { read_u32(query, 0) } as usize == RADIO_QUERY_VTABLE
        && unsafe { read_u32(query, 0x2098) } == 0
        && unsafe { read_u32(query, 0x20A0) } == 0
        && unsafe { read_u32(query, 0x20B4) } == 3
}

fn with_active_stats(f: impl FnOnce(&mut ScanStats)) {
    RADIO_SCAN_STATE.with(|state| {
        if let Ok(mut state) = state.try_borrow_mut() {
            f(&mut state.stats)
        }
    });
}

fn relative_call_target(call_addr: usize) -> anyhow::Result<usize> {
    let bytes = read_bytes(call_addr as *const c_void, 5)?;
    ensure!(
        bytes[0] == 0xE8,
        "expected CALL at 0x{call_addr:08X}, found opcode 0x{:02X}",
        bytes[0]
    );
    let displacement = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    Ok(call_addr
        .wrapping_add(5)
        .wrapping_add_signed(displacement as isize))
}

fn verify_signature(address: usize, expected: &[u8], label: &str) -> anyhow::Result<()> {
    let observed = read_bytes(address as *const c_void, expected.len())?;
    ensure!(
        observed == expected,
        "{label} signature mismatch at 0x{address:08X}: expected {expected:02X?}, found {observed:02X?}"
    );
    Ok(())
}

fn module_name(address: usize) -> Option<String> {
    module_address(address).and_then(|label| label.split_once('!').map(|item| item.0.to_owned()))
}

unsafe fn first_queued_node(query: *const u8) -> usize {
    for bucket in 0..PRIORITY_BUCKET_COUNT {
        let node = unsafe { read_u32(query, 0x1FF8 + bucket * 4) } as usize;
        if node != 0 {
            return node;
        }
    }
    0
}

unsafe fn read_u32(base: *const u8, offset: usize) -> u32 {
    unsafe { core::ptr::read_unaligned(base.add(offset).cast()) }
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
