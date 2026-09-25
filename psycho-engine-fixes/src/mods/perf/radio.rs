//! Synchronous radio availability, native station maintenance, and hitch attribution.
//!
//! The periodic engine scanner owns all query inputs, results, and station lists
//! until it returns. This module never defers an answer or substitutes a pending
//! query for signal loss: distance and connected queries retain their native
//! callsites, post-filters, and destruction order.
//!
//! A scoped marker admits the three proven actor-free radio query tuples.
//! Native policy calls keep caller-owned cleanup; a verified inlined expansion
//! uses the game-owned dispatcher and original enumeration/math helpers. No
//! provider DLL is patched. Unknown providers retain dynamic native dispatch.
//! The station bridge skips only the native empty/inactive no-effect branch.
//!
//! All code bridges install transactionally at the quiescent pre-CRT boundary;
//! DeferredInit verifies ownership and publishes optional capabilities. No job,
//! result, or engine pointer survives a scan. Profiling stays opt-in; normal
//! expansion admission allocates nothing and reads no timers or diagnostics.

mod provider;

use std::{
    cell::{Cell, RefCell},
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use anyhow::ensure;
use libc::c_void;
use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::{
        hook::{
            callsite::Rel32CallHookContainer, inline::inlinehook::InlineHookContainer,
            transaction::ModificationTransaction,
        },
        memory::read_bytes,
    },
};

use crate::mods::diagnostics;

const PERIODIC_RADIO_SCAN_CALL_ADDR: usize = 0x00833D86;
const RADIO_SIGNAL_SCAN_ADDR: usize = 0x004FF1A0;
const PERIODIC_RADIO_STATION_UPDATE_CALL_ADDR: usize = 0x008341B4;
const RADIO_STATION_UPDATE_ADDR: usize = 0x00834260;
const CURRENT_RADIO_STATION_ADDR: usize = 0x011DD42C;
const RADIO_LIST_RESETTING_ADDR: usize = 0x011DD436;
const RADIO_ENTRY_AUDIO_LIST_HEAD_OFFSET: usize = 0x1C;
const RADIO_ENTRY_AUDIO_LIST_NEXT_OFFSET: usize = 0x20;
const PATH_QUERY_ADDR: usize = 0x006D4D20;
const PATH_TRAVERSAL_ADDR: usize = 0x006F3FB0;
const STATION_MODE_ADDR: usize = 0x0056B210;
const RADIO_QUERY_VTABLE: usize = 0x0106D8FC;
const DOOR_ACCESSIBILITY_ADDR: usize = 0x00502450;
const VANILLA_PROVIDER_ADDR: usize = 0x006F36D0;
const VANILLA_POLICY_SETUP_ADDR: usize = 0x00501D20;
const VANILLA_POLICY_CLEANUP_ADDR: usize = 0x00501E50;
const VANILLA_DISPOSITION_ADMISSION_OFFSET: usize = 0x72;
const VANILLA_POLICY_SETUP_CALL_OFFSET: usize = 0x1A9;
const VANILLA_ACCESSIBILITY_CALL_OFFSET: usize = 0x1CA;
const VANILLA_ACCESSIBILITY_RESULT_OFFSET: usize = 0x1CF;
const VANILLA_DISPOSITION_BRANCH_OFFSET: usize = 0x1E7;
const VANILLA_MIN_USE_BRANCH_OFFSET: usize = 0x22B;
const VANILLA_POLICY_CLEANUP_CALL_OFFSETS: [usize; 3] = [0x221, 0x307, 0x412];
const PRIORITY_BUCKET_COUNT: usize = 20;
const SLOW_SCAN_US: u64 = 5_000;
const SCAN_REPORT_MS: u32 = 1_000;
const STATION_UPDATE_CALL_PREFIX_SIGNATURE: &[u8] = &[0x8B, 0x4D, 0xA4, 0x51, 0xE8];
const STATION_UPDATE_CALL_SUFFIX_SIGNATURE: &[u8] = &[0x83, 0xC4, 0x04, 0x8B, 0x4D, 0xC4, 0xE8];
const VANILLA_PROVIDER_SIGNATURE: &[u8] = &[
    0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0xA8, 0x6B, 0xF0, 0x00, 0x64, 0xA1, 0x00, 0x00, 0x00, 0x00,
    0x50, 0x81, 0xEC, 0x84, 0x00, 0x00, 0x00,
];
const VANILLA_DISPOSITION_ADMISSION_SIGNATURE: &[u8] = &[
    0x8B, 0x45, 0x80, 0x83, 0xB8, 0xB4, 0x20, 0x00, 0x00, 0x01, 0x74, 0x1C, 0x8B, 0x4D, 0x80, 0x83,
    0xB9, 0xB4, 0x20, 0x00, 0x00, 0x03, 0x74, 0x10, 0x8B, 0x55, 0x80, 0x83, 0xBA, 0xA0, 0x20, 0x00,
    0x00, 0x00,
];
const VANILLA_ACCESSIBILITY_RESULT_SIGNATURE: &[u8] = &[
    0x88, 0x45, 0xCF, 0xD9, 0xEE, 0xD9, 0x5D, 0xEC, 0x0F, 0xB6, 0x4D, 0xCF, 0x85, 0xC9, 0x74, 0x08,
    0x0F, 0xB6, 0x55, 0xDF, 0x85, 0xD2, 0x74, 0x44,
];
const VANILLA_DISPOSITION_BRANCH_SIGNATURE: &[u8] = &[
    0x8B, 0x45, 0x80, 0x8B, 0x88, 0xB4, 0x20, 0x00, 0x00, 0x89, 0x8D, 0x74, 0xFF, 0xFF, 0xFF, 0x83,
    0xBD, 0x74, 0xFF, 0xFF, 0xFF, 0x00, 0x74, 0x18, 0x83, 0xBD, 0x74, 0xFF, 0xFF, 0xFF, 0x02, 0x74,
    0x04, 0xEB, 0x21,
];
const VANILLA_MIN_USE_BRANCH_SIGNATURE: &[u8] = &[
    0x8B, 0x4D, 0xE8, 0xE8, 0x2D, 0xBB, 0x0B, 0x00, 0x8B, 0xC8, 0xE8, 0xF6, 0x46, 0xE2, 0xFF, 0x0F,
    0xB6, 0xD0, 0x85, 0xD2, 0x74, 0x15, 0x8B, 0x45, 0x80, 0x83, 0xB8, 0xB4, 0x20, 0x00, 0x00, 0x03,
    0x74, 0x09,
];
const VANILLA_POLICY_SETUP_SIGNATURE: &[u8] = &[
    0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x3B, 0xB2, 0xF0, 0x00, 0x64, 0xA1, 0x00, 0x00, 0x00, 0x00,
    0x50, 0x83, 0xEC, 0x18,
];
const VANILLA_POLICY_CLEANUP_SIGNATURE: &[u8] = &[
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0x89, 0x4D, 0xF8, 0x8B, 0x45, 0xF8, 0x83, 0x78, 0x08, 0x00,
    0x74, 0x15, 0x8B, 0x4D, 0xF8, 0x8B, 0x51, 0x08, 0x89, 0x55, 0xFC, 0x8B, 0x45, 0xFC, 0x50,
];
const DOOR_ACCESSIBILITY_SIGNATURE: &[u8] = &[
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x0C, 0x89, 0x4D, 0xF4, 0xC6, 0x45, 0xFF, 0x00, 0xC7, 0x45, 0xF8,
    0x00, 0x00, 0x00, 0x00,
];

type RadioSignalScanFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void);
type RadioStationUpdateFn = unsafe extern "C" fn(*mut c_void);
type PathQueryFn = unsafe extern "C" fn(usize, usize, *mut c_void, u32, f32, u32, u32) -> u8;
type PathTraversalFn = unsafe extern "fastcall" fn(*mut c_void) -> usize;
type StationModeFn = unsafe extern "fastcall" fn(*mut c_void) -> u32;
type DoorPolicySetupFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void) -> *mut c_void;
type DoorAccessibilityFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, *mut c_void, *mut u8) -> u8;

static PATH_QUERY_HOOK: LazyLock<InlineHookContainer<PathQueryFn>> =
    LazyLock::new(InlineHookContainer::new);
static PATH_TRAVERSAL_HOOK: LazyLock<InlineHookContainer<PathTraversalFn>> =
    LazyLock::new(InlineHookContainer::new);
static STATION_MODE_HOOK: LazyLock<InlineHookContainer<StationModeFn>> =
    LazyLock::new(InlineHookContainer::new);
static SCAN_HOOK: Rel32CallHookContainer<RadioSignalScanFn> = Rel32CallHookContainer::new();
static STATION_UPDATE_HOOK: Rel32CallHookContainer<RadioStationUpdateFn> =
    Rel32CallHookContainer::new();
static DOOR_POLICY_SETUP_HOOK: Rel32CallHookContainer<DoorPolicySetupFn> =
    Rel32CallHookContainer::new();
static DOOR_ACCESSIBILITY_HOOK: Rel32CallHookContainer<DoorAccessibilityFn> =
    Rel32CallHookContainer::new();
static SCAN_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static POLICY_INSTALL_ATTEMPTED: AtomicBool = AtomicBool::new(false);
static POLICY_INSTALLED: AtomicBool = AtomicBool::new(false);
static POLICY_READY: AtomicBool = AtomicBool::new(false);

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

    fn merge(&mut self, other: Self) {
        self.calls = self.calls.saturating_add(other.calls);
        self.total_us = self.total_us.saturating_add(other.total_us);
        self.max_us = self.max_us.max(other.max_us);
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

impl ScanStats {
    fn merge(&mut self, other: Self) {
        for (timing, other) in self.mode_queries.iter_mut().zip(other.mode_queries) {
            timing.merge(other);
        }
        self.other_queries.merge(other.other_queries);
        self.traversals.merge(other.traversals);
        for (count, other) in self.station_modes.iter_mut().zip(other.station_modes) {
            *count = count.saturating_add(other);
        }
        self.other_station_modes = self
            .other_station_modes
            .saturating_add(other.other_station_modes);
        self.mode0_traversals = self.mode0_traversals.saturating_add(other.mode0_traversals);
        self.expected_query_vtable = self
            .expected_query_vtable
            .saturating_add(other.expected_query_vtable);
        self.queue_empty_before_traversal = self
            .queue_empty_before_traversal
            .saturating_add(other.queue_empty_before_traversal);
        self.source_missing = self.source_missing.saturating_add(other.source_missing);
        self.source_first = self.source_first.saturating_add(other.source_first);
        self.source_goal_match = self
            .source_goal_match
            .saturating_add(other.source_goal_match);
        self.source_parent_null = self
            .source_parent_null
            .saturating_add(other.source_parent_null);
        self.result_null = self.result_null.saturating_add(other.result_null);
        self.result_source = self.result_source.saturating_add(other.result_source);
        self.result_other = self.result_other.saturating_add(other.result_other);
        self.policy_queries = self.policy_queries.saturating_add(other.policy_queries);
        self.policy_setup_bypasses = self
            .policy_setup_bypasses
            .saturating_add(other.policy_setup_bypasses);
        self.policy_access_bypasses = self
            .policy_access_bypasses
            .saturating_add(other.policy_access_bypasses);
    }
}

#[derive(Clone, Copy, Default)]
struct ScanAggregate {
    slow_scans: u32,
    total_us: u64,
    max_us: u64,
    residual_us: u64,
    residual_max_us: u64,
    stats: ScanStats,
}

#[derive(Default)]
struct ScanReporter {
    aggregate: ScanAggregate,
    last_report_ms: Option<u32>,
}

impl ScanReporter {
    fn observe(
        &mut self,
        now_ms: u32,
        slow_sample: Option<(u64, u64, ScanStats)>,
    ) -> Option<ScanAggregate> {
        if let Some((elapsed_us, residual_us, stats)) = slow_sample {
            self.aggregate.slow_scans = self.aggregate.slow_scans.saturating_add(1);
            self.aggregate.total_us = self.aggregate.total_us.saturating_add(elapsed_us);
            self.aggregate.max_us = self.aggregate.max_us.max(elapsed_us);
            self.aggregate.residual_us = self.aggregate.residual_us.saturating_add(residual_us);
            self.aggregate.residual_max_us = self.aggregate.residual_max_us.max(residual_us);
            self.aggregate.stats.merge(stats);
        }

        if self.aggregate.slow_scans == 0 {
            return None;
        }

        let Some(last_report_ms) = self.last_report_ms else {
            self.last_report_ms = Some(now_ms);
            return None;
        };
        if now_ms.wrapping_sub(last_report_ms) < SCAN_REPORT_MS {
            return None;
        }

        self.last_report_ms = Some(now_ms);
        Some(std::mem::take(&mut self.aggregate))
    }
}

#[derive(Default)]
struct RadioScanState {
    stats: ScanStats,
    reporter: ScanReporter,
}

thread_local! {
    static RADIO_SCAN_CONTEXT: Cell<ScanContext> = const { Cell::new(ScanContext::EMPTY) };
    static PENDING_POLICY_ACCESS: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    static RADIO_SCAN_STATE: RefCell<RadioScanState> = RefCell::new(RadioScanState::default());
}

#[derive(Clone, Copy)]
struct ScanContext {
    depth: u32,
    provider: Option<provider::Bindings>,
    native_policy: bool,
}

impl ScanContext {
    const EMPTY: Self = Self {
        depth: 0,
        provider: None,
        native_policy: false,
    };
}

struct RadioScanScope {
    previous: ScanContext,
    previous_pending: (usize, usize),
}

impl RadioScanScope {
    fn enter() -> Self {
        let previous = RADIO_SCAN_CONTEXT.with(Cell::get);
        let current = if previous.depth == 0 {
            ScanContext {
                depth: 1,
                provider: provider::for_scan(),
                native_policy: POLICY_READY.load(Ordering::Acquire) && native_policy_owned(),
            }
        } else {
            ScanContext {
                depth: previous.depth.saturating_add(1),
                ..previous
            }
        };
        RADIO_SCAN_CONTEXT.with(|context| context.set(current));
        if previous.depth == 0 && diagnostics::hitch_profiling_enabled() {
            RADIO_SCAN_STATE.with(|state| state.borrow_mut().stats = ScanStats::default());
        }
        let previous_pending = PENDING_POLICY_ACCESS.with(|pending| pending.replace((0, 0)));
        Self {
            previous,
            previous_pending,
        }
    }
}

impl Drop for RadioScanScope {
    fn drop(&mut self) {
        RADIO_SCAN_CONTEXT.with(|context| context.set(self.previous));
        PENDING_POLICY_ACCESS.with(|pending| pending.set(self.previous_pending));
    }
}

/// Installs synchronous scan/station bridges at the quiescent core startup boundary.
///
/// Native query and destructor calls remain untouched. Related activations roll
/// back on failure without overwriting another component's later hook. Returns
/// an error if the supported caller signatures or hook ownership do not match.
/// This must run once before gameplay; it does not support live reinstallation.
pub fn install_radio_scan_fix() -> anyhow::Result<()> {
    verify_call_target(
        PERIODIC_RADIO_SCAN_CALL_ADDR,
        RADIO_SIGNAL_SCAN_ADDR,
        "periodic radio scan",
    )?;
    verify_call_target(
        PERIODIC_RADIO_STATION_UPDATE_CALL_ADDR,
        RADIO_STATION_UPDATE_ADDR,
        "periodic station update",
    )?;
    verify_signature(
        PERIODIC_RADIO_STATION_UPDATE_CALL_ADDR - 4,
        STATION_UPDATE_CALL_PREFIX_SIGNATURE,
        "periodic station update prefix",
    )?;
    verify_signature(
        PERIODIC_RADIO_STATION_UPDATE_CALL_ADDR + 5,
        STATION_UPDATE_CALL_SUFFIX_SIGNATURE,
        "periodic station update suffix",
    )?;
    // SAFETY: the verified game callers have exactly these cdecl signatures.
    // Preparation publishes predecessors before any detour becomes reachable.
    unsafe {
        SCAN_HOOK.init(
            "radio_signal_scan",
            PERIODIC_RADIO_SCAN_CALL_ADDR as *mut c_void,
            hook_periodic_radio_signal_scan,
        )?;
        STATION_UPDATE_HOOK.init(
            "radio_station_update",
            PERIODIC_RADIO_STATION_UPDATE_CALL_ADDR as *mut c_void,
            skip_empty_inactive_station_update,
        )?;
    }
    let mut transaction = ModificationTransaction::new();
    transaction.enable_callsite(&SCAN_HOOK)?;
    transaction.enable_callsite(&STATION_UPDATE_HOOK)?;
    transaction.commit();
    log::info!(
        "[RADIO] Synchronous availability active; native query results and station playback retained"
    );

    // Optional bridges start inert. No gameplay traversal exists at this
    // pre-CRT boundary; DeferredInit performs no executable-memory writes.
    if let Err(error) = install_door_policy_bypass_hooks() {
        log::warn!(
            "[RADIO] Native policy bridge unavailable; original queries retained: {error:#}"
        );
    }
    if let Err(error) = provider::install() {
        log::warn!("[RADIO] Expansion bridge unavailable; original provider retained: {error:#}");
    }

    // Profiling is independent: its failure cannot invalidate the synchronous
    // scan/station bridges or replace a query result with an invented failure.
    if diagnostics::hitch_profiling_enabled() {
        if let Err(error) = install_query_profiling() {
            log::warn!(
                "[RADIO] Query profiling unavailable; native radio behavior retained: {error:#}"
            );
        }
    }
    Ok(())
}

fn install_query_profiling() -> anyhow::Result<()> {
    // SAFETY: these existing engine entries and their ABIs are unchanged.
    unsafe {
        PATH_QUERY_HOOK.init(
            "radio_path_query_profile",
            PATH_QUERY_ADDR as *mut c_void,
            hook_path_query,
        )?;
        PATH_TRAVERSAL_HOOK.init(
            "radio_path_traversal_profile",
            PATH_TRAVERSAL_ADDR as *mut c_void,
            hook_path_traversal,
        )?;
        STATION_MODE_HOOK.init(
            "radio_station_mode_profile",
            STATION_MODE_ADDR as *mut c_void,
            hook_station_mode,
        )?;
    }
    let mut transaction = ModificationTransaction::new();
    transaction.enable_inline(&PATH_QUERY_HOOK)?;
    transaction.enable_inline(&PATH_TRAVERSAL_HOOK)?;
    transaction.enable_inline(&STATION_MODE_HOOK)?;
    transaction.commit();
    Ok(())
}

/// Verifies and publishes optional optimization once after plugin loading.
/// No executable code is written here; world/frame events need no radio work.
pub(crate) fn observe_event(kind: u32) {
    if kind != crate::events::DEFERRED_INIT || POLICY_INSTALL_ATTEMPTED.swap(true, Ordering::AcqRel)
    {
        return;
    }
    if native_policy_owned() {
        POLICY_READY.store(true, Ordering::Release);
        log::info!("[RADIO] Native policy optimization active for radio query modes 0/1/2");
    } else {
        log::warn!("[RADIO] Native policy contract changed; complete native computation retained");
    }
    if let Err(error) = provider::publish() {
        log::warn!("[RADIO] Optional expansion unavailable: {error:#}");
    }
}

fn install_door_policy_bypass_hooks() -> anyhow::Result<()> {
    verify_vanilla_policy_provider()?;
    verify_signature(
        DOOR_ACCESSIBILITY_ADDR,
        DOOR_ACCESSIBILITY_SIGNATURE,
        "game teleport-door accessibility predicate",
    )?;
    // SAFETY: both calls belong to the verified native provider. Setup is
    // thiscall(data, door), returning data; accessibility is thiscall with
    // three stack arguments. No replacement provider is inspected or patched.
    unsafe {
        DOOR_POLICY_SETUP_HOOK.init(
            "radio_native_door_policy_setup",
            (VANILLA_PROVIDER_ADDR + VANILLA_POLICY_SETUP_CALL_OFFSET) as *mut c_void,
            hook_door_policy_setup,
        )?;
        DOOR_ACCESSIBILITY_HOOK.init(
            "radio_native_door_accessibility",
            (VANILLA_PROVIDER_ADDR + VANILLA_ACCESSIBILITY_CALL_OFFSET) as *mut c_void,
            hook_door_accessibility,
        )?;
    }
    let mut transaction = ModificationTransaction::new();
    transaction.enable_callsite(&DOOR_ACCESSIBILITY_HOOK)?;
    transaction.enable_callsite(&DOOR_POLICY_SETUP_HOOK)?;
    transaction.commit();
    POLICY_INSTALLED.store(true, Ordering::Release);
    Ok(())
}

fn verify_vanilla_policy_provider() -> anyhow::Result<()> {
    verify_signature(
        VANILLA_PROVIDER_ADDR,
        VANILLA_PROVIDER_SIGNATURE,
        "vanilla TeleportDoorSearch provider",
    )?;
    verify_signature(
        0x006F36F8,
        &[0x89, 0x4D, 0x80],
        "native provider query frame",
    )?;
    verify_signature(
        0x006F3872,
        &[0x8B, 0x55, 0xE8, 0x52, 0x8D, 0x4D, 0xB0, 0xE8],
        "native policy setup arguments",
    )?;
    verify_signature(
        VANILLA_PROVIDER_ADDR + VANILLA_DISPOSITION_ADMISSION_OFFSET,
        VANILLA_DISPOSITION_ADMISSION_SIGNATURE,
        "vanilla disposition admission branch",
    )?;
    verify_signature(
        VANILLA_PROVIDER_ADDR + VANILLA_ACCESSIBILITY_RESULT_OFFSET,
        VANILLA_ACCESSIBILITY_RESULT_SIGNATURE,
        "vanilla accessibility result branch",
    )?;
    verify_signature(
        VANILLA_PROVIDER_ADDR + VANILLA_DISPOSITION_BRANCH_OFFSET,
        VANILLA_DISPOSITION_BRANCH_SIGNATURE,
        "vanilla disposition penalty branch",
    )?;
    verify_signature(
        VANILLA_PROVIDER_ADDR + VANILLA_MIN_USE_BRANCH_OFFSET,
        VANILLA_MIN_USE_BRANCH_SIGNATURE,
        "vanilla minimum-use penalty branch",
    )?;
    verify_call_target(
        VANILLA_PROVIDER_ADDR + VANILLA_POLICY_SETUP_CALL_OFFSET,
        VANILLA_POLICY_SETUP_ADDR,
        "vanilla door-policy setup call",
    )?;
    verify_call_target(
        VANILLA_PROVIDER_ADDR + VANILLA_ACCESSIBILITY_CALL_OFFSET,
        DOOR_ACCESSIBILITY_ADDR,
        "vanilla accessibility call",
    )?;
    for offset in VANILLA_POLICY_CLEANUP_CALL_OFFSETS {
        verify_call_target(
            VANILLA_PROVIDER_ADDR + offset,
            VANILLA_POLICY_CLEANUP_ADDR,
            "vanilla temporary policy cleanup call",
        )?;
    }
    verify_signature(
        VANILLA_POLICY_SETUP_ADDR,
        VANILLA_POLICY_SETUP_SIGNATURE,
        "vanilla TeleportDoorData setup",
    )?;
    verify_signature(
        VANILLA_POLICY_CLEANUP_ADDR,
        VANILLA_POLICY_CLEANUP_SIGNATURE,
        "vanilla TeleportDoorData cleanup",
    )?;
    Ok(())
}

/// Recheck the native omission/cleanup contract and both owned callsites.
/// Fixed game ranges are process-lifetime mappings verified before activation.
/// This recurring check does not allocate, log, or read timing counters.
fn native_policy_owned() -> bool {
    use provider::{game_bytes_equal as bytes, game_call_matches as call};
    // SAFETY: these fixed process-lifetime executable ranges were validated at
    // the pre-CRT install boundary. Native traversal never races code writes.
    unsafe {
        POLICY_INSTALLED.load(Ordering::Acquire)
            && DOOR_POLICY_SETUP_HOOK.is_enabled()
            && DOOR_ACCESSIBILITY_HOOK.is_enabled()
            && bytes(VANILLA_PROVIDER_ADDR, VANILLA_PROVIDER_SIGNATURE)
            && bytes(0x006F36F8, &[0x89, 0x4D, 0x80])
            && bytes(
                0x006F3872,
                &[0x8B, 0x55, 0xE8, 0x52, 0x8D, 0x4D, 0xB0, 0xE8],
            )
            && bytes(
                VANILLA_PROVIDER_ADDR + VANILLA_DISPOSITION_ADMISSION_OFFSET,
                VANILLA_DISPOSITION_ADMISSION_SIGNATURE,
            )
            && bytes(
                VANILLA_PROVIDER_ADDR + VANILLA_ACCESSIBILITY_RESULT_OFFSET,
                VANILLA_ACCESSIBILITY_RESULT_SIGNATURE,
            )
            && bytes(
                VANILLA_PROVIDER_ADDR + VANILLA_DISPOSITION_BRANCH_OFFSET,
                VANILLA_DISPOSITION_BRANCH_SIGNATURE,
            )
            && bytes(
                VANILLA_PROVIDER_ADDR + VANILLA_MIN_USE_BRANCH_OFFSET,
                VANILLA_MIN_USE_BRANCH_SIGNATURE,
            )
            && bytes(VANILLA_POLICY_SETUP_ADDR, VANILLA_POLICY_SETUP_SIGNATURE)
            && bytes(
                VANILLA_POLICY_CLEANUP_ADDR,
                VANILLA_POLICY_CLEANUP_SIGNATURE,
            )
            && bytes(DOOR_ACCESSIBILITY_ADDR, DOOR_ACCESSIBILITY_SIGNATURE)
            && call(
                VANILLA_PROVIDER_ADDR + VANILLA_POLICY_SETUP_CALL_OFFSET,
                hook_door_policy_setup as *const () as usize,
            )
            && call(
                VANILLA_PROVIDER_ADDR + VANILLA_ACCESSIBILITY_CALL_OFFSET,
                hook_door_accessibility as *const () as usize,
            )
            && VANILLA_POLICY_CLEANUP_CALL_OFFSETS
                .iter()
                .all(|&offset| call(VANILLA_PROVIDER_ADDR + offset, VANILLA_POLICY_CLEANUP_ADDR))
    }
}

unsafe extern "C" fn skip_empty_inactive_station_update(station: *mut c_void) {
    if station.is_null() {
        return;
    }
    let station_form = unsafe { core::ptr::read_unaligned(station.cast::<u32>()) };
    if station_form == 0 {
        return;
    }

    let current =
        unsafe { core::ptr::read_volatile(CURRENT_RADIO_STATION_ADDR as *const u32) } as usize;
    let resetting =
        unsafe { core::ptr::read_volatile(RADIO_LIST_RESETTING_ADDR as *const u8) } != 0;
    let audio_list_head = unsafe {
        core::ptr::read_unaligned(
            station
                .cast::<u8>()
                .add(RADIO_ENTRY_AUDIO_LIST_HEAD_OFFSET)
                .cast::<u32>(),
        )
    };
    let audio_list_next = unsafe {
        core::ptr::read_unaligned(
            station
                .cast::<u8>()
                .add(RADIO_ENTRY_AUDIO_LIST_NEXT_OFFSET)
                .cast::<u32>(),
        )
    };
    if should_skip_empty_inactive_station_update(
        station as usize,
        current,
        resetting,
        audio_list_head,
        audio_list_next,
    ) {
        return;
    }

    // The predecessor is published before activation. The native address also
    // preserves behavior if this function is ever reached before preparation.
    let original = STATION_UPDATE_HOOK.original().unwrap_or_else(|_| unsafe {
        FnPtr::<RadioStationUpdateFn>::from_address_unchecked(RADIO_STATION_UPDATE_ADDR).as_fn()
    });
    unsafe { original(station) };
}

fn should_skip_empty_inactive_station_update(
    station: usize,
    current: usize,
    resetting: bool,
    audio_list_head: u32,
    audio_list_next: u32,
) -> bool {
    station != current && !resetting && audio_list_head == 0 && audio_list_next == 0
}

unsafe extern "C" fn hook_periodic_radio_signal_scan(
    current_ref: *mut c_void,
    out_stations: *mut c_void,
    out_meta: *mut c_void,
) {
    // SAFETY: this exact caller owns all three engine arguments until return.
    // The bridge does not inspect, retain, or recreate its output containers.
    let scan = SCAN_HOOK.original().unwrap_or_else(|_| unsafe {
        FnPtr::<RadioSignalScanFn>::from_address_unchecked(RADIO_SIGNAL_SCAN_ADDR).as_fn()
    });
    let scope = RadioScanScope::enter();
    let outermost = scope.previous.depth == 0;
    let timer = diagnostics::Stopwatch::start_if_hitch_profiling();
    unsafe { scan(current_ref, out_stations, out_meta) };
    drop(scope);
    if !outermost {
        return;
    }

    let Some(elapsed_us) = timer.elapsed_us() else {
        return;
    };
    if !log::log_enabled!(log::Level::Debug) {
        return;
    }

    let slow_sample = (elapsed_us >= SLOW_SCAN_US).then(|| {
        let stats = RADIO_SCAN_STATE.with(|state| state.borrow().stats);
        let residual_us = elapsed_us.saturating_sub(
            stats
                .mode_queries
                .iter()
                .map(|timing| timing.total_us)
                .sum(),
        );
        SCAN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        (elapsed_us, residual_us, stats)
    });
    let Some(aggregate) = RADIO_SCAN_STATE.with(|state| {
        state.borrow_mut().reporter.observe(
            libpsycho::os::windows::winapi::get_tick_count(),
            slow_sample,
        )
    }) else {
        return;
    };
    let sequence = SCAN_SEQUENCE.load(Ordering::Relaxed);
    let stats = aggregate.stats;
    log::debug!(
        "[RADIO_SCAN] seq={} slow={} total_avg/max={}/{}us station_modes={}/{}/{}/{}/{}+{} query0={}/{}/{} query1={}/{}/{} query2={}/{}/{} other={}/{}/{} traversal={}/{}/{} branch=m0:{}/vtable:{}/empty:{}/missing:{}/first:{}/goal:{}/parent0:{}/result0:{}/source:{}/other:{} policy=query:{}/setup:{}/access:{} residual_avg/max={}/{}us",
        sequence,
        aggregate.slow_scans,
        aggregate.total_us / u64::from(aggregate.slow_scans.max(1)),
        aggregate.max_us,
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
        aggregate.residual_us / u64::from(aggregate.slow_scans.max(1)),
        aggregate.residual_max_us,
    );
}

unsafe extern "C" fn hook_path_query(
    from: usize,
    to: usize,
    result: *mut c_void,
    mode: u32,
    max_cost: f32,
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
    let policy_query = unsafe { is_exact_radio_policy_query(query.cast()) };

    let probe = unsafe { TraversalProbe::capture(query.cast()) };
    let timer = diagnostics::Stopwatch::start();
    let result = unsafe { original(query) };
    let elapsed_us = timer.elapsed_us();
    with_active_stats(|stats| {
        stats.traversals.record(elapsed_us);
        stats.policy_queries = stats.policy_queries.saturating_add(u32::from(policy_query));
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

/// Adapts the verified native constructor call without changing its ABI.
///
/// The provider keeps its live query at caller EBP-0x80. Pass that frame as a
/// third internal argument; preserve the native thiscall return and ret 4.
#[unsafe(naked)]
unsafe extern "thiscall" fn hook_door_policy_setup(
    _data: *mut c_void,
    _door: *mut c_void,
) -> *mut c_void {
    core::arch::naked_asm!(
        "mov eax, ebp",
        "push ebp",
        "mov ebp, esp",
        "and esp, -16",
        "sub esp, 4",
        "push eax",
        "push dword ptr [ebp + 8]",
        "push ecx",
        "call {body}",
        "mov esp, ebp",
        "pop ebp",
        "ret 4",
        body = sym native_door_policy_setup,
    );
}

unsafe extern "C" fn native_door_policy_setup(
    data: *mut c_void,
    door: *mut c_void,
    caller_ebp: usize,
) -> *mut c_void {
    let original = DOOR_POLICY_SETUP_HOOK
        .original()
        .unwrap_or_else(|_| unsafe {
            FnPtr::<DoorPolicySetupFn>::from_address_unchecked(VANILLA_POLICY_SETUP_ADDR).as_fn()
        });
    PENDING_POLICY_ACCESS.with(|pending| pending.set((0, 0)));
    let context = RADIO_SCAN_CONTEXT.with(Cell::get);
    if !context.native_policy
        || context.depth == 0
        || data.is_null()
        || door.is_null()
        || caller_ebp == 0
    {
        return unsafe { original(data, door) };
    }
    // SAFETY: the verified native provider saves ECX at EBP-0x80 before
    // reaching this call. That query remains live on this thread throughout
    // enumeration. Read the actual caller's query rather than inheriting an
    // outer traversal's policy when a provider performs nested path work.
    let query = unsafe { core::ptr::read_unaligned((caller_ebp - 0x80) as *const *const u8) };
    if !unsafe { radio_query_fields_match(query) } {
        return unsafe { original(data, door) };
    }
    // SAFETY: the verified caller reserves this 0x18-byte object on its stack.
    // Only the paired accessibility call and native destructor consume it.
    // The bypass skips the former; the latter reads only its +0x08 pointer.
    unsafe { core::ptr::write_unaligned(data.cast::<u8>().add(8).cast::<usize>(), 0) };
    PENDING_POLICY_ACCESS.with(|pending| pending.set((data as usize, door as usize)));
    with_active_stats(|stats| {
        stats.policy_setup_bypasses = stats.policy_setup_bypasses.saturating_add(1)
    });
    data
}

/// Align the native thiscall stack before entering the Rust accessibility body.
/// ECX and three stack arguments are unchanged; the native caller expects RET 12.
#[unsafe(naked)]
unsafe extern "thiscall" fn hook_door_accessibility(
    _data: *mut c_void,
    _actor: *mut c_void,
    _door: *mut c_void,
    _flag: *mut u8,
) -> u8 {
    core::arch::naked_asm!(
        "push ebp", "mov ebp, esp", "and esp, -16",
        "push dword ptr [ebp + 16]", "push dword ptr [ebp + 12]",
        "push dword ptr [ebp + 8]", "push ecx",
        "call {body}", "mov esp, ebp", "pop ebp", "ret 12",
        body = sym native_door_accessibility,
    );
}

unsafe extern "C" fn native_door_accessibility(
    data: *mut c_void,
    actor_data: *mut c_void,
    door: *mut c_void,
    out_flag: *mut u8,
) -> u8 {
    let original = DOOR_ACCESSIBILITY_HOOK
        .original()
        .unwrap_or_else(|_| unsafe {
            FnPtr::<DoorAccessibilityFn>::from_address_unchecked(DOOR_ACCESSIBILITY_ADDR).as_fn()
        });
    let paired = PENDING_POLICY_ACCESS.with(|pending| {
        let expected = (data as usize, door as usize);
        if expected.0 != 0 && pending.get() == expected {
            pending.set((0, 0));
            true
        } else {
            false
        }
    });
    if paired && actor_data.is_null() && !out_flag.is_null() {
        // SAFETY: the verified native caller supplies one writable flag byte.
        // All three admitted tuples discard accessibility policy. Return the
        // exact native null-actor result; minimum-use handling remains native.
        unsafe { out_flag.write(0) };
        with_active_stats(|stats| {
            stats.policy_access_bypasses = stats.policy_access_bypasses.saturating_add(1)
        });
        return 0;
    }
    if paired {
        // Setup was skipped, but admission changed: construct the object before
        // the original predicate can read any of its otherwise uninitialized
        // fields. Its +0x08 cleanup pointer is still null, so nothing is leaked.
        let setup = DOOR_POLICY_SETUP_HOOK
            .original()
            .unwrap_or_else(|_| unsafe {
                FnPtr::<DoorPolicySetupFn>::from_address_unchecked(VANILLA_POLICY_SETUP_ADDR)
                    .as_fn()
            });
        unsafe { setup(data, door) };
    }
    unsafe { original(data, actor_data, door, out_flag) }
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
    RADIO_SCAN_CONTEXT.with(|context| context.get().depth != 0)
}

unsafe fn is_exact_radio_policy_query(query: *const u8) -> bool {
    radio_scan_active() && unsafe { radio_query_fields_match(query) }
}

/// Match the native query tuple after the caller has checked its scan scope.
/// Keeping field admission separate avoids repeated TLS lookups per expansion.
/// The pointer must name the current native query if it is non-null.
unsafe fn radio_query_fields_match(query: *const u8) -> bool {
    if query.is_null()
        || unsafe { read_u32(query, 0) } as usize != RADIO_QUERY_VTABLE
        || unsafe { read_u32(query, 0x20A0) } != 0
    {
        return false;
    }
    // SAFETY: this is the live native query from the verified provider frame.
    // These are the exact tuples constructed by the three radio query callers.
    matches!(
        unsafe { (read_u32(query, 0x2098), read_u32(query, 0x20B4)) },
        (0, 3) | (1, 1) | (2, 1)
    )
}

fn with_active_stats(f: impl FnOnce(&mut ScanStats)) {
    if !diagnostics::hitch_profiling_enabled() {
        return;
    }
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

fn verify_call_target(call_addr: usize, expected_target: usize, label: &str) -> anyhow::Result<()> {
    let observed_target = relative_call_target(call_addr)?;
    ensure!(
        observed_target == expected_target,
        "{label} mismatch at 0x{call_addr:08X}: expected 0x{expected_target:08X}, found 0x{observed_target:08X}"
    );
    Ok(())
}

fn verify_signature(address: usize, expected: &[u8], label: &str) -> anyhow::Result<()> {
    let observed = read_bytes(address as *const c_void, expected.len())?;
    ensure!(
        observed == expected,
        "{label} signature mismatch at 0x{address:08X}: expected {expected:02X?}, found {observed:02X?}"
    );
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periodic_station_update_skips_only_the_original_empty_inactive_branch() {
        let station = 0x1234;
        assert!(should_skip_empty_inactive_station_update(
            station, 0x5678, false, 0, 0
        ));
        assert!(!should_skip_empty_inactive_station_update(
            station, station, false, 0, 0
        ));
        assert!(!should_skip_empty_inactive_station_update(
            station, 0x5678, true, 0, 0
        ));
        assert!(!should_skip_empty_inactive_station_update(
            station, 0x5678, false, 1, 0
        ));
        assert!(!should_skip_empty_inactive_station_update(
            station, 0x5678, false, 0, 1
        ));
    }

    #[test]
    fn slow_scan_reports_are_aggregated_to_one_second_windows() {
        let mut reporter = ScanReporter::default();
        let mut first = ScanStats::default();
        first.mode_queries[0] = Timing {
            calls: 2,
            total_us: 3_000,
            max_us: 2_000,
        };
        assert!(reporter.observe(100, Some((6_000, 3_000, first))).is_none());

        let mut second = ScanStats::default();
        second.mode_queries[0] = Timing {
            calls: 1,
            total_us: 2_000,
            max_us: 2_000,
        };
        assert!(
            reporter
                .observe(900, Some((7_000, 5_000, second)))
                .is_none()
        );

        let report = reporter
            .observe(1_100, None)
            .expect("one report after a complete window");
        assert_eq!(report.slow_scans, 2);
        assert_eq!(report.total_us, 13_000);
        assert_eq!(report.max_us, 7_000);
        assert_eq!(report.residual_us, 8_000);
        assert_eq!(report.stats.mode_queries[0].calls, 3);
        assert_eq!(report.stats.mode_queries[0].total_us, 5_000);
    }
}
