//! Mod-independent LowProcess generic-location ownership enforcement.
//!
//! # Problem
//!
//! Every `HighProcess`, `LowProcess`, `MiddleHighProcess`, and
//! `MiddleLowProcess` object embeds a `tList<TESObjectREFR>` head at process
//! offset `+0x6C`. The payloads are borrowed engine references; list ownership
//! extends only to successor nodes. A bad cleanup owner can therefore leave a
//! dangling or scalar payload in the list, and vanilla later dereferences it
//! while removing a form ID or serializing the process.
//!
//! # Native contracts
//!
//! The supported FalloutNV.exe exposes two adjacent virtual contracts in all
//! four process vtables:
//!
//! - slot `+0x47C`: `thiscall(process, removed_ref)`, vanilla `0x0090CC10`;
//! - slot `+0x480`: `thiscall(process, form_id)`, vanilla `0x0090CDC0`.
//!
//! The save serializer is owned by `0x00910450`. Its list-data, form-encoding,
//! and list-next calls are at `0x009105A6`, `0x009105BF`, and `0x009105D0`.
//! Address evidence and the executable identity are maintained in
//! `docs/crash_20260717_lowprocess_save_structural_containment_plan.md`.
//!
//! # Runtime design
//!
//! This module contains corruption at three boundaries:
//!
//! 1. Cleanup wrappers sanitize `process + 0x6C`, remove every occurrence of
//!    `removed_ref`, and then invoke the captured cleanup owner.
//! 2. Reference-scan wrappers sanitize the same list without removing a valid
//!    payload, then invoke the captured form-ID scan owner.
//! 3. Save-only callsite wrappers terminate corrupt traversal and encode an
//!    unreadable form as NULL without mutating uncertain memory.
//!
//! Vtable installation is capability based. During a bounded startup window,
//! each slot captures any executable current target independently and places a
//! distinct wrapper above it. No module name, version, hash, or third-party
//! address participates in the decision. A later hook is left in place because
//! it may already chain the Psycho wrapper; wrapping it again could create
//! `Psycho -> later hook -> Psycho` recursion. After 120 observations the
//! temporary main-loop boundary restores its predecessor.
//!
//! # Safety, allocation, and failure policy
//!
//! All live and save traversals are allocation-free, lock-free, and bounded to
//! 256 nodes. Small stack-local `VirtualQuery` caches avoid a system call for
//! every node. Invalid payloads and uncertain tails are detached but never
//! freed. The live reference-scan guard passes a NULL `removed_ref`, so it
//! cannot call even the proven native node-removal helpers. The added behavior
//! is therefore independent of vanilla heap, scrap-heap-only, and
//! gheap-plus-scrap-heap modes.
//!
//! The embedded head is trusted only because entry through a process virtual
//! establishes a live process object. Every successor and payload is validated
//! before dereference. If a patch target is non-executable or ownership changes
//! during installation, the site is left untouched and diagnostics report the
//! unsupported state. Corruption logging is power-of-two sampled.

use std::{
    cell::UnsafeCell,
    ffi::c_void,
    mem::size_of,
    ptr,
    sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicUsize, Ordering},
};

use anyhow::{Context, ensure};
use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::winapi::{get_current_thread_id, safe_write_32, virtual_query},
};

use crate::{events, mods::diagnostics};

use super::{
    patching, statics,
    types::{AppendRefIdFn, MainTaskDrainFn},
};

const SLOT_PENDING: u8 = 0;
const SLOT_WRAPPED: u8 = 1;
const SLOT_UNSUPPORTED: u8 = 2;
const SLOT_DISABLED: u8 = 3;
const SLOT_CHAINED: u8 = 4;
// Long enough to observe normal xNVSE plugin hook installation, but finite so
// the main task-drain call has no steady-state wrapper.
const OBSERVATION_WINDOW: u32 = 120;
// Bounds stack storage, corrupt-list work, and cycle handling in every path.
const MAX_GENERIC_LOCATION_NODES: usize = 256;
// Four recent mappings cover the common node/form/vtable locality without
// adding allocation or an unbounded cache to cold engine paths.
const REGION_CACHE_CAPACITY: usize = 4;
// Saves are normally serialized by one thread. Four fixed slots permit nested
// or auxiliary serializers without first-use TLS allocation.
const SAVE_CONTEXT_SLOT_COUNT: usize = 4;

const LIST_DATA_ADDR: usize = 0x0068_15C0;
const LIST_HEAD_REMOVE_ADDR: usize = 0x0063_F7B0;
const LIST_REMOVE_ADDR: usize = 0x0090_5330;
const LIST_NEXT_ADDR: usize = 0x0072_6070;
const GENERIC_LOCATIONS_OFFSET: usize = 0x6C;

type ProcessCleanupFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);
type ProcessReferenceScanFn = unsafe extern "thiscall" fn(*mut c_void, u32);
type ListDataFn = unsafe extern "fastcall" fn(*mut ListNode) -> *mut ListNode;
type ListHeadRemoveFn = unsafe extern "fastcall" fn(*mut ListNode);
type ListRemoveFn = unsafe extern "thiscall" fn(*mut ListNode, *mut *mut c_void);
type ListNextFn = unsafe extern "fastcall" fn(*mut ListNode) -> *mut ListNode;

// Bethesda's tList stores the first element in an embedded head and allocates
// only successor nodes. Head removal must therefore copy/clear fields rather
// than free the embedded address.
#[repr(C)]
struct ListNode {
    data: *mut c_void,
    next: *mut ListNode,
}

#[derive(Clone, Copy)]
struct CachedRegion {
    start: usize,
    end: usize,
}

impl CachedRegion {
    const EMPTY: Self = Self { start: 0, end: 0 };

    fn contains(self, address: usize, len: usize) -> bool {
        address >= self.start && address.saturating_add(len) <= self.end
    }
}

#[derive(Clone, Copy)]
struct RegionCache {
    regions: [CachedRegion; REGION_CACHE_CAPACITY],
    next: usize,
}

impl RegionCache {
    const fn new() -> Self {
        Self {
            regions: [CachedRegion::EMPTY; REGION_CACHE_CAPACITY],
            next: 0,
        }
    }

    fn contains(&self, address: usize, len: usize) -> bool {
        self.regions
            .iter()
            .any(|region| region.contains(address, len))
    }

    fn remember(&mut self, start: usize, end: usize) {
        // A ring is sufficient: losing an old mapping costs one VirtualQuery,
        // while an LRU policy would add work without changing correctness.
        self.regions[self.next] = CachedRegion { start, end };
        self.next = (self.next + 1) % REGION_CACHE_CAPACITY;
    }

    fn readable(&mut self, address: usize, len: usize) -> bool {
        if address < 0x10000 || address.checked_add(len).is_none() {
            return false;
        }
        if self.contains(address, len) {
            return true;
        }
        let Ok(info) = virtual_query(address as *mut c_void) else {
            return false;
        };
        let start = info.base_address as usize;
        let end = start.saturating_add(info.region_size);
        if !info.is_accessible() || address.saturating_add(len) > end {
            return false;
        }
        self.remember(start, end);
        true
    }

    fn writable(&mut self, address: usize, len: usize) -> bool {
        if address < 0x10000 || address.checked_add(len).is_none() {
            return false;
        }
        if self.contains(address, len) {
            return true;
        }
        let Ok(info) = virtual_query(address as *mut c_void) else {
            return false;
        };
        let start = info.base_address as usize;
        let end = start.saturating_add(info.region_size);
        if !info.is_writable() || address.saturating_add(len) > end {
            return false;
        }
        self.remember(start, end);
        true
    }

    fn executable(&mut self, address: usize) -> bool {
        if address < 0x10000 {
            return false;
        }
        if self.contains(address, 1) {
            return true;
        }
        let Ok(info) = virtual_query(address as *mut c_void) else {
            return false;
        };
        if !info.is_executable() {
            return false;
        }
        let start = info.base_address as usize;
        self.remember(start, start.saturating_add(info.region_size));
        true
    }
}

#[derive(Clone, Copy)]
struct SaveTraversalContext {
    active: bool,
    blocked: bool,
    visited: usize,
    embedded_head: usize,
    cycle_tortoise: usize,
    cycle_power: usize,
    cycle_length: usize,
    readable_regions: RegionCache,
    executable_regions: RegionCache,
}

impl SaveTraversalContext {
    const fn inactive() -> Self {
        Self {
            active: false,
            blocked: false,
            visited: 0,
            embedded_head: 0,
            cycle_tortoise: 0,
            cycle_power: 1,
            cycle_length: 0,
            readable_regions: RegionCache::new(),
            executable_regions: RegionCache::new(),
        }
    }

    fn active(process: *mut c_void) -> Self {
        Self {
            active: true,
            blocked: false,
            visited: 0,
            embedded_head: if process.is_null() {
                0
            } else {
                (process as usize)
                    .checked_add(GENERIC_LOCATIONS_OFFSET)
                    .unwrap_or(0)
            },
            cycle_tortoise: 0,
            cycle_power: 1,
            cycle_length: 0,
            readable_regions: RegionCache::new(),
            executable_regions: RegionCache::new(),
        }
    }
}

struct SaveTraversalSlot {
    owner_thread: AtomicU32,
    context: UnsafeCell<SaveTraversalContext>,
}

impl SaveTraversalSlot {
    const fn new() -> Self {
        Self {
            owner_thread: AtomicU32::new(0),
            context: UnsafeCell::new(SaveTraversalContext::inactive()),
        }
    }
}

// SAFETY: owner_thread is the publication barrier. Only the matching thread
// accesses context, and it restores nested state before publishing owner=0.
unsafe impl Sync for SaveTraversalSlot {}

// Fixed storage avoids Rust TLS first-use allocation inside a save transaction.
static SAVE_TRAVERSAL_SLOTS: [SaveTraversalSlot; SAVE_CONTEXT_SLOT_COUNT] =
    [const { SaveTraversalSlot::new() }; SAVE_CONTEXT_SLOT_COUNT];

// checked_list_data must return a readable pointer because the native caller
// dereferences the returned cell even when traversal is being terminated.
static NULL_LIST_DATA: usize = 0;

static ENABLED: AtomicBool = AtomicBool::new(true);
static OBSERVATIONS: AtomicU32 = AtomicU32::new(0);
// Predecessors are release-published before their wrapper becomes reachable
// from an engine callsite or vtable. Wrappers acquire-load before dispatch.
static PREVIOUS_APPEND_REF_ID: AtomicUsize = AtomicUsize::new(statics::APPEND_REF_ID_ADDR);
static PREVIOUS_LIST_DATA: AtomicUsize = AtomicUsize::new(LIST_DATA_ADDR);
static PREVIOUS_LIST_NEXT: AtomicUsize = AtomicUsize::new(LIST_NEXT_ADDR);
static PREVIOUS_MAIN_TASK_DRAIN: AtomicUsize = AtomicUsize::new(statics::MAIN_TASK_DRAIN_ADDR);
static PREDECESSORS: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
static SLOT_STATES: [AtomicU8; 4] = [const { AtomicU8::new(SLOT_PENDING) }; 4];
static REFERENCE_SCAN_PREDECESSORS: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
static REFERENCE_SCAN_SLOT_STATES: [AtomicU8; 4] = [const { AtomicU8::new(SLOT_PENDING) }; 4];
static MAIN_BOUNDARY_INSTALLED: AtomicBool = AtomicBool::new(false);
static MAIN_BOUNDARY_RESTORED: AtomicBool = AtomicBool::new(false);
static MAIN_BOUNDARY_RESTORE_ATTEMPTED: AtomicBool = AtomicBool::new(false);

// These counters are diagnostics only. Relaxed ordering is sufficient because
// no safety or ownership decision depends on their values.
static WRAPS: AtomicU32 = AtomicU32::new(0);
static REWRAPS: AtomicU32 = AtomicU32::new(0);
static UNSUPPORTED: AtomicU32 = AtomicU32::new(0);
static REFERENCE_SCAN_WRAPS: AtomicU32 = AtomicU32::new(0);
static REFERENCE_SCAN_REWRAPS: AtomicU32 = AtomicU32::new(0);
static REFERENCE_SCAN_UNSUPPORTED: AtomicU32 = AtomicU32::new(0);
static SANITIZED_ENTRIES: AtomicU32 = AtomicU32::new(0);
static INVALID_CLEANUP_FORMS: AtomicU32 = AtomicU32::new(0);
static TRUNCATED_CLEANUP_LINKS: AtomicU32 = AtomicU32::new(0);
static INVALID_SAVE_FORMS: AtomicU32 = AtomicU32::new(0);
static INVALID_SAVE_NODES: AtomicU32 = AtomicU32::new(0);
static INVALID_SAVE_LINKS: AtomicU32 = AtomicU32::new(0);
static SAVE_CYCLES: AtomicU32 = AtomicU32::new(0);
static SAVE_TRAVERSAL_LIMITS: AtomicU32 = AtomicU32::new(0);
static PREDECESSOR_CALLS: AtomicU32 = AtomicU32::new(0);
static PREDECESSOR_FALLBACKS: AtomicU32 = AtomicU32::new(0);
static REFERENCE_SCAN_PREDECESSOR_CALLS: AtomicU32 = AtomicU32::new(0);
static REFERENCE_SCAN_PREDECESSOR_FALLBACKS: AtomicU32 = AtomicU32::new(0);
static MAIN_BOUNDARY_RESTORES: AtomicU32 = AtomicU32::new(0);
static MAIN_BOUNDARY_RESTORE_FAILURES: AtomicU32 = AtomicU32::new(0);
static PATCH_FAILURES: AtomicU32 = AtomicU32::new(0);

/// Point-in-time LowProcess state consumed by the engine diagnostics report.
///
/// Counters are monotonic for the process lifetime. Slot arrays use the
/// HighProcess, LowProcess, MiddleHighProcess, MiddleLowProcess order declared
/// by [`statics::LOWPROCESS_VTABLE_BASES`].
pub(super) struct DiagnosticSnapshot {
    /// Whether live slot observation and wrapping remain enabled.
    pub enabled: bool,
    /// Number of startup-boundary observations completed.
    pub observations: u32,
    /// Cleanup-slot state codes for the four process classes.
    pub slot_states: [u8; 4],
    /// Captured cleanup predecessors for the four process classes.
    pub predecessors: [usize; 4],
    /// Reference-scan-slot state codes for the four process classes.
    pub reference_scan_slot_states: [u8; 4],
    /// Captured reference-scan predecessors for the four process classes.
    pub reference_scan_predecessors: [usize; 4],
    /// Cleanup slots wrapped for the first time.
    pub wraps: u32,
    /// Cleanup slots restored after reverting to the same predecessor.
    pub rewraps: u32,
    /// Cleanup slots rejected because their target was unsafe to call.
    pub unsupported: u32,
    /// Reference-scan slots wrapped for the first time.
    pub reference_scan_wraps: u32,
    /// Reference-scan slots restored after reverting to the same predecessor.
    pub reference_scan_rewraps: u32,
    /// Reference-scan slots rejected because their target was unsafe to call.
    pub reference_scan_unsupported: u32,
    /// Valid matching cleanup entries removed before a predecessor call.
    pub sanitized_entries: u32,
    /// Invalid form payloads detached during live sanitation.
    pub invalid_cleanup_forms: u32,
    /// Invalid, cyclic, or over-budget live list tails truncated.
    pub truncated_cleanup_links: u32,
    /// Invalid save payloads encoded as NULL.
    pub invalid_save_forms: u32,
    /// Invalid current nodes that stopped save traversal.
    pub invalid_save_nodes: u32,
    /// Invalid next links that stopped save traversal.
    pub invalid_save_links: u32,
    /// Save traversals stopped after detecting a cycle.
    pub save_cycles: u32,
    /// Save traversals stopped at the fixed node budget.
    pub save_traversal_limits: u32,
    /// Calls forwarded to a cleanup predecessor.
    pub predecessor_calls: u32,
    /// Cleanup calls that used the audited vanilla fallback.
    pub predecessor_fallbacks: u32,
    /// Calls forwarded to a reference-scan predecessor.
    pub reference_scan_predecessor_calls: u32,
    /// Reference-scan calls that used the audited vanilla fallback.
    pub reference_scan_predecessor_fallbacks: u32,
    /// Whether the save-owner context hook is active.
    pub save_owner_hook: bool,
    /// Whether the temporary startup boundary was restored successfully.
    pub main_boundary_restored: bool,
    /// Successful startup-boundary restorations.
    pub main_boundary_restores: u32,
    /// Failed startup-boundary restoration attempts.
    pub main_boundary_restore_failures: u32,
    /// Failed or raced patch operations across all LowProcess sites.
    pub patch_failures: u32,
}

/// Captures non-blocking diagnostic state for dashboard/report generation.
///
/// This function reads atomics only; it does not inspect engine memory.
pub(super) fn diagnostic_snapshot() -> DiagnosticSnapshot {
    DiagnosticSnapshot {
        enabled: ENABLED.load(Ordering::Acquire),
        observations: OBSERVATIONS.load(Ordering::Relaxed),
        slot_states: std::array::from_fn(|index| SLOT_STATES[index].load(Ordering::Acquire)),
        predecessors: std::array::from_fn(|index| PREDECESSORS[index].load(Ordering::Acquire)),
        reference_scan_slot_states: std::array::from_fn(|index| {
            REFERENCE_SCAN_SLOT_STATES[index].load(Ordering::Acquire)
        }),
        reference_scan_predecessors: std::array::from_fn(|index| {
            REFERENCE_SCAN_PREDECESSORS[index].load(Ordering::Acquire)
        }),
        wraps: WRAPS.load(Ordering::Relaxed),
        rewraps: REWRAPS.load(Ordering::Relaxed),
        unsupported: UNSUPPORTED.load(Ordering::Relaxed),
        reference_scan_wraps: REFERENCE_SCAN_WRAPS.load(Ordering::Relaxed),
        reference_scan_rewraps: REFERENCE_SCAN_REWRAPS.load(Ordering::Relaxed),
        reference_scan_unsupported: REFERENCE_SCAN_UNSUPPORTED.load(Ordering::Relaxed),
        sanitized_entries: SANITIZED_ENTRIES.load(Ordering::Relaxed),
        invalid_cleanup_forms: INVALID_CLEANUP_FORMS.load(Ordering::Relaxed),
        truncated_cleanup_links: TRUNCATED_CLEANUP_LINKS.load(Ordering::Relaxed),
        invalid_save_forms: INVALID_SAVE_FORMS.load(Ordering::Relaxed),
        invalid_save_nodes: INVALID_SAVE_NODES.load(Ordering::Relaxed),
        invalid_save_links: INVALID_SAVE_LINKS.load(Ordering::Relaxed),
        save_cycles: SAVE_CYCLES.load(Ordering::Relaxed),
        save_traversal_limits: SAVE_TRAVERSAL_LIMITS.load(Ordering::Relaxed),
        predecessor_calls: PREDECESSOR_CALLS.load(Ordering::Relaxed),
        predecessor_fallbacks: PREDECESSOR_FALLBACKS.load(Ordering::Relaxed),
        reference_scan_predecessor_calls: REFERENCE_SCAN_PREDECESSOR_CALLS.load(Ordering::Relaxed),
        reference_scan_predecessor_fallbacks: REFERENCE_SCAN_PREDECESSOR_FALLBACKS
            .load(Ordering::Relaxed),
        save_owner_hook: statics::LOWPROCESS_SAVE_OWNER_HOOK.is_enabled(),
        main_boundary_restored: MAIN_BOUNDARY_RESTORED.load(Ordering::Acquire),
        main_boundary_restores: MAIN_BOUNDARY_RESTORES.load(Ordering::Relaxed),
        main_boundary_restore_failures: MAIN_BOUNDARY_RESTORE_FAILURES.load(Ordering::Relaxed),
        patch_failures: PATCH_FAILURES.load(Ordering::Relaxed),
    }
}

/// Converts an internal slot-state code into its stable diagnostic label.
pub(super) fn slot_state_name(state: u8) -> &'static str {
    match state {
        SLOT_PENDING => "pending",
        SLOT_WRAPPED => "wrapped",
        SLOT_UNSUPPORTED => "unsupported",
        SLOT_DISABLED => "disabled",
        SLOT_CHAINED => "chained",
        _ => "unknown",
    }
}

/// Disables live slot wrapping and publishes disabled diagnostic states.
///
/// Save callsite hooks that were already installed remain fail-closed; this
/// function does not attempt unsafe runtime unpatching.
pub(super) fn disable() {
    ENABLED.store(false, Ordering::Release);
    for state in &SLOT_STATES {
        state.store(SLOT_DISABLED, Ordering::Release);
    }
    for state in &REFERENCE_SCAN_SLOT_STATES {
        state.store(SLOT_DISABLED, Ordering::Release);
    }
}

/// Installs save traversal and payload containment at the audited serializer.
///
/// Structural traversal containment is best effort so payload containment can
/// still protect readable nodes. An error is returned only when the payload
/// callsite cannot be installed.
pub(super) fn install_save_containment() -> anyhow::Result<()> {
    if let Err(err) = install_save_traversal_containment() {
        PATCH_FAILURES.fetch_add(1, Ordering::Relaxed);
        log::warn!(
            "[LOWPROCESS] Structural save traversal containment unavailable: {:#}",
            err,
        );
    }

    install_save_payload_containment().inspect_err(|_| {
        PATCH_FAILURES.fetch_add(1, Ordering::Relaxed);
    })
}

fn install_save_payload_containment() -> anyhow::Result<()> {
    let previous = unsafe { patching::relative_call_target(statics::LOWPROCESS_SAVE_CALL_ADDR) }?;
    if previous == checked_append_ref_id as *const () as usize {
        return Ok(());
    }
    ensure!(
        is_executable(previous),
        "save serializer target 0x{previous:08X} is not executable"
    );
    // Publish the captured owner only after redirect_relative_call proves that
    // this transaction replaced the target it observed. A racing patch is
    // rolled back only while the callsite still belongs to this wrapper.
    let redirected = unsafe {
        patching::redirect_relative_call(
            statics::LOWPROCESS_SAVE_CALL_ADDR,
            checked_append_ref_id as *mut c_void,
        )
    };
    let redirected = match redirected {
        Ok(target) => target,
        Err(err) => {
            restore_relative_call_if_owned(
                statics::LOWPROCESS_SAVE_CALL_ADDR,
                checked_append_ref_id as *const () as usize,
                previous,
            );
            return Err(err).context("install LowProcess save containment");
        }
    };
    if redirected != previous {
        restore_relative_call_if_owned(
            statics::LOWPROCESS_SAVE_CALL_ADDR,
            checked_append_ref_id as *const () as usize,
            redirected,
        );
        anyhow::bail!("save call target changed during install");
    }
    PREVIOUS_APPEND_REF_ID.store(previous, Ordering::Release);
    log::info!(
        "[LOWPROCESS] Generic-location save containment active predecessor=0x{:08X}",
        previous
    );
    Ok(())
}

fn install_save_traversal_containment() -> anyhow::Result<()> {
    if statics::LOWPROCESS_SAVE_OWNER_HOOK.is_enabled() {
        return Ok(());
    }

    // The two accessors share state established by the owner hook. Capture all
    // targets before mutation so failure can restore one coherent native path.
    let previous_data =
        unsafe { patching::relative_call_target(statics::LOWPROCESS_SAVE_DATA_CALL_ADDR) }?;
    let previous_next =
        unsafe { patching::relative_call_target(statics::LOWPROCESS_SAVE_NEXT_CALL_ADDR) }?;
    ensure!(
        previous_data != checked_list_data as *const () as usize && is_executable(previous_data),
        "save data accessor target 0x{previous_data:08X} is unsupported"
    );
    ensure!(
        previous_next != checked_list_next as *const () as usize && is_executable(previous_next),
        "save next accessor target 0x{previous_next:08X} is unsupported"
    );

    unsafe {
        statics::LOWPROCESS_SAVE_OWNER_HOOK.init(
            "LowProcess save traversal owner",
            statics::LOWPROCESS_SAVE_OWNER_ADDR as *mut c_void,
            lowprocess_save_with_traversal_context,
        )
    }
    .context("prepare LowProcess save traversal owner")?;

    // Accessor wrappers can run as soon as their callsites are redirected, so
    // their predecessors must be visible first.
    PREVIOUS_LIST_DATA.store(previous_data, Ordering::Release);
    PREVIOUS_LIST_NEXT.store(previous_next, Ordering::Release);

    let redirected_data = unsafe {
        patching::redirect_relative_call(
            statics::LOWPROCESS_SAVE_DATA_CALL_ADDR,
            checked_list_data as *mut c_void,
        )
    };
    let redirected_data = match redirected_data {
        Ok(target) => target,
        Err(err) => {
            restore_relative_call_if_owned(
                statics::LOWPROCESS_SAVE_DATA_CALL_ADDR,
                checked_list_data as *const () as usize,
                previous_data,
            );
            return Err(err).context("install LowProcess save data guard");
        }
    };
    if redirected_data != previous_data {
        restore_relative_call_if_owned(
            statics::LOWPROCESS_SAVE_DATA_CALL_ADDR,
            checked_list_data as *const () as usize,
            redirected_data,
        );
        anyhow::bail!("save data call target changed during install");
    }

    let redirected_next = unsafe {
        patching::redirect_relative_call(
            statics::LOWPROCESS_SAVE_NEXT_CALL_ADDR,
            checked_list_next as *mut c_void,
        )
    };
    let redirected_next = match redirected_next {
        Ok(target) if target == previous_next => target,
        Ok(target) => {
            restore_relative_call_if_owned(
                statics::LOWPROCESS_SAVE_NEXT_CALL_ADDR,
                checked_list_next as *const () as usize,
                target,
            );
            restore_relative_call_if_owned(
                statics::LOWPROCESS_SAVE_DATA_CALL_ADDR,
                checked_list_data as *const () as usize,
                previous_data,
            );
            anyhow::bail!("save next call target changed during install");
        }
        Err(err) => {
            restore_relative_call_if_owned(
                statics::LOWPROCESS_SAVE_NEXT_CALL_ADDR,
                checked_list_next as *const () as usize,
                previous_next,
            );
            restore_relative_call_if_owned(
                statics::LOWPROCESS_SAVE_DATA_CALL_ADDR,
                checked_list_data as *const () as usize,
                previous_data,
            );
            return Err(err).context("install LowProcess save next guard");
        }
    };
    debug_assert_eq!(redirected_next, previous_next);

    // Enable the owner last. Before it is active, checked accessors find no
    // traversal context and fail closed.
    if let Err(err) = statics::LOWPROCESS_SAVE_OWNER_HOOK.enable() {
        restore_relative_call_if_owned(
            statics::LOWPROCESS_SAVE_NEXT_CALL_ADDR,
            checked_list_next as *const () as usize,
            previous_next,
        );
        restore_relative_call_if_owned(
            statics::LOWPROCESS_SAVE_DATA_CALL_ADDR,
            checked_list_data as *const () as usize,
            previous_data,
        );
        return Err(err).context("enable LowProcess save traversal owner");
    }

    log::info!(
        "[LOWPROCESS] Save traversal containment active data=0x{:08X} next=0x{:08X}",
        previous_data,
        previous_next,
    );
    Ok(())
}

/// Installs the temporary main-task boundary used to observe final vtable owners.
///
/// The boundary chains the current executable task-drain target and removes
/// itself after [`OBSERVATION_WINDOW`] calls. It is not a permanent frame hook.
pub(super) fn install_late_boundary() -> anyhow::Result<()> {
    let previous = unsafe { patching::relative_call_target(statics::MAIN_TASK_DRAIN_CALL_ADDR) }?;
    if previous == main_task_drain_with_slot_wrapping as *const () as usize {
        MAIN_BOUNDARY_INSTALLED.store(true, Ordering::Release);
        return Ok(());
    }
    ensure!(
        is_executable(previous),
        "main task-drain target 0x{previous:08X} is not executable"
    );
    // The task drain is only a late, loader-lock-free observation boundary. It
    // does not own or initialize any process object.
    let redirected = unsafe {
        patching::redirect_relative_call(
            statics::MAIN_TASK_DRAIN_CALL_ADDR,
            main_task_drain_with_slot_wrapping as *mut c_void,
        )
    };
    let redirected = match redirected {
        Ok(target) => target,
        Err(err) => {
            restore_relative_call_if_owned(
                statics::MAIN_TASK_DRAIN_CALL_ADDR,
                main_task_drain_with_slot_wrapping as *const () as usize,
                previous,
            );
            return Err(err).context("install LowProcess late wrapping boundary");
        }
    };
    if redirected != previous {
        restore_relative_call_if_owned(
            statics::MAIN_TASK_DRAIN_CALL_ADDR,
            main_task_drain_with_slot_wrapping as *const () as usize,
            redirected,
        );
        anyhow::bail!("main-drain target changed during install");
    }
    PREVIOUS_MAIN_TASK_DRAIN.store(previous, Ordering::Release);
    MAIN_BOUNDARY_INSTALLED.store(true, Ordering::Release);
    log::info!(
        "[LOWPROCESS] Late slot-wrapping boundary active predecessor=0x{:08X}",
        previous
    );
    Ok(())
}

/// Gives the LowProcess fix an engine lifecycle event.
///
/// `DEFERRED_INIT` performs an immediate observation so protection is present
/// before the first wrapped task-drain call.
pub(super) fn observe_event(kind: u32) {
    if kind == events::DEFERRED_INIT {
        ensure_slots_wrapped();
    }
}

unsafe extern "thiscall" fn lowprocess_save_with_traversal_context(
    process: *mut c_void,
    writer: *mut c_void,
) {
    let thread_id = get_current_thread_id();
    let slot = claim_save_traversal_slot(thread_id);
    // Save can be nested on one thread. Restore the previous context rather
    // than clearing it so an outer serializer resumes its original cycle and
    // page-validation state.
    let previous = slot.map(|slot| unsafe {
        ptr::replace(slot.context.get(), SaveTraversalContext::active(process))
    });
    if let Ok(original) = statics::LOWPROCESS_SAVE_OWNER_HOOK.original() {
        unsafe { original(process, writer) };
    }
    if let (Some(slot), Some(previous)) = (slot, previous) {
        unsafe { ptr::write(slot.context.get(), previous) };
        if !previous.active {
            slot.owner_thread.store(0, Ordering::Release);
        }
    }
}

unsafe extern "fastcall" fn checked_list_data(current: *mut ListNode) -> *mut ListNode {
    if !begin_save_node(current) {
        // Native immediately dereferences the accessor result. A stable NULL
        // cell terminates this element without exposing an invalid pointer.
        return null_list_data();
    }

    let predecessor = PREVIOUS_LIST_DATA.load(Ordering::Acquire);
    let target = if predecessor != 0 && predecessor != checked_list_data as *const () as usize {
        predecessor
    } else {
        LIST_DATA_ADDR
    };
    let Ok(original) = (unsafe { FnPtr::<ListDataFn>::from_raw(target as *mut c_void) }) else {
        block_save_traversal();
        return null_list_data();
    };
    let result = unsafe { original.as_fn()(current) };
    if result.is_null() || !save_pointer_is_readable(result as usize, size_of::<usize>()) {
        mark_invalid_save_node(result as usize);
        block_save_traversal();
        // A predecessor result is not trusted until its returned data cell is
        // independently checked against the active save context.
        return null_list_data();
    }
    result
}

unsafe extern "fastcall" fn checked_list_next(current: *mut ListNode) -> *mut ListNode {
    if save_traversal_is_blocked() {
        return ptr::null_mut();
    }
    if !save_pointer_is_readable(current as usize, size_of::<ListNode>()) {
        if !current.is_null() {
            mark_invalid_save_node(current as usize);
        }
        block_save_traversal();
        return ptr::null_mut();
    }

    let predecessor = PREVIOUS_LIST_NEXT.load(Ordering::Acquire);
    let target = if predecessor != 0 && predecessor != checked_list_next as *const () as usize {
        predecessor
    } else {
        LIST_NEXT_ADDR
    };
    let Ok(original) = (unsafe { FnPtr::<ListNextFn>::from_raw(target as *mut c_void) }) else {
        block_save_traversal();
        return ptr::null_mut();
    };
    let next = unsafe { original.as_fn()(current) };
    if next.is_null() {
        return next;
    }
    if !save_pointer_is_readable(next as usize, size_of::<ListNode>()) {
        mark_invalid_save_link(current as usize, next as usize);
        block_save_traversal();
        return ptr::null_mut();
    }
    if save_link_completes_cycle(current as usize, next as usize) {
        mark_save_cycle(current as usize, next as usize);
        block_save_traversal();
        return ptr::null_mut();
    }
    // Returning NULL on failure preserves the serializer's own element-count
    // patch-up logic while omitting only the uncertain suffix.
    next
}

unsafe extern "thiscall" fn checked_append_ref_id(
    writer: *mut c_void,
    form: *mut c_void,
    flags: u32,
) {
    // The save format already represents a missing reference as NULL. Preserve
    // stream structure without repairing or freeing an unknown payload.
    let checked = if form.is_null() || is_valid_tes_form(form) {
        form
    } else {
        let n = INVALID_SAVE_FORMS.fetch_add(1, Ordering::Relaxed) + 1;
        if diagnostics::should_log_power_of_two(u64::from(n)) {
            log::warn!(
                "[LOWPROCESS] invalid generic-location form encoded as NULL total={} form=0x{:08X} writer=0x{:08X} flags=0x{:X} tid={}",
                n,
                form as usize,
                writer as usize,
                flags,
                get_current_thread_id(),
            );
        }
        ptr::null_mut()
    };

    let predecessor = PREVIOUS_APPEND_REF_ID.load(Ordering::Acquire);
    let target = if predecessor != 0 && predecessor != checked_append_ref_id as *const () as usize {
        predecessor
    } else {
        statics::APPEND_REF_ID_ADDR
    };
    let Ok(original) = (unsafe { FnPtr::<AppendRefIdFn>::from_raw(target as *mut c_void) }) else {
        return;
    };
    let original = original.as_fn();
    unsafe { original(writer, checked, flags) };
}

unsafe extern "thiscall" fn main_task_drain_with_slot_wrapping(manager: *mut c_void, arg: u32) {
    // Observe first so tasks drained by this call see current safe ownership.
    // The captured task-drain owner still executes exactly once.
    ensure_slots_wrapped();
    let predecessor = PREVIOUS_MAIN_TASK_DRAIN.load(Ordering::Acquire);
    let target = if predecessor != 0 {
        predecessor
    } else {
        statics::MAIN_TASK_DRAIN_ADDR
    };
    let Ok(original) = (unsafe { FnPtr::<MainTaskDrainFn>::from_raw(target as *mut c_void) })
    else {
        return;
    };
    let original = original.as_fn();
    unsafe { original(manager, arg) };
}

// Each vtable slot needs a distinct entrypoint. The slot index selects the
// matching predecessor atomically without scraping the process vtable at call
// time, where another hook may already sit above this wrapper.
unsafe extern "thiscall" fn process_cleanup_wrapper_0(
    process: *mut c_void,
    removed_ref: *mut c_void,
) {
    unsafe { process_cleanup_for_slot(0, process, removed_ref) };
}

unsafe extern "thiscall" fn process_cleanup_wrapper_1(
    process: *mut c_void,
    removed_ref: *mut c_void,
) {
    unsafe { process_cleanup_for_slot(1, process, removed_ref) };
}

unsafe extern "thiscall" fn process_cleanup_wrapper_2(
    process: *mut c_void,
    removed_ref: *mut c_void,
) {
    unsafe { process_cleanup_for_slot(2, process, removed_ref) };
}

unsafe extern "thiscall" fn process_cleanup_wrapper_3(
    process: *mut c_void,
    removed_ref: *mut c_void,
) {
    unsafe { process_cleanup_for_slot(3, process, removed_ref) };
}

// Keep the native thiscall ABI explicit: process arrives in ECX, form_id is the
// single callee-popped stack argument, and the generated wrapper returns ret 4.
unsafe extern "thiscall" fn process_reference_scan_wrapper_0(process: *mut c_void, form_id: u32) {
    unsafe { process_reference_scan_for_slot(0, process, form_id) };
}

unsafe extern "thiscall" fn process_reference_scan_wrapper_1(process: *mut c_void, form_id: u32) {
    unsafe { process_reference_scan_for_slot(1, process, form_id) };
}

unsafe extern "thiscall" fn process_reference_scan_wrapper_2(process: *mut c_void, form_id: u32) {
    unsafe { process_reference_scan_for_slot(2, process, form_id) };
}

unsafe extern "thiscall" fn process_reference_scan_wrapper_3(process: *mut c_void, form_id: u32) {
    unsafe { process_reference_scan_for_slot(3, process, form_id) };
}

unsafe fn process_cleanup_for_slot(index: usize, process: *mut c_void, removed_ref: *mut c_void) {
    let predecessor = PREDECESSORS[index].load(Ordering::Acquire);
    // Sanitize before any third-party owner sees the list. In particular, this
    // removes the borrowed removed_ref so an unsafe owner cannot free it.
    sanitize_generic_locations(process, removed_ref);

    let wrapper = wrapper_for_slot(index);
    let use_fallback = predecessor == 0 || predecessor == wrapper;
    let target = if !use_fallback {
        predecessor
    } else {
        statics::VANILLA_LOWPROCESS_FUNC011F
    };
    PREDECESSOR_CALLS.fetch_add(1, Ordering::Relaxed);
    if use_fallback {
        PREDECESSOR_FALLBACKS.fetch_add(1, Ordering::Relaxed);
    }
    let Ok(original) = (unsafe { FnPtr::<ProcessCleanupFn>::from_raw(target as *mut c_void) })
    else {
        return;
    };
    let original = original.as_fn();
    diagnostics::mark_load_site(diagnostics::LoadSite::LowProcessPredecessorEnter);
    unsafe { original(process, removed_ref) };
    diagnostics::mark_load_site(diagnostics::LoadSite::LowProcessPredecessorExit);
}

unsafe fn process_reference_scan_for_slot(index: usize, process: *mut c_void, form_id: u32) {
    // Keep ordering in one testable primitive: the crash occurs inside the
    // predecessor's form-ID dereference, so chaining first is never safe.
    run_live_reference_scan_guard(
        process,
        form_id,
        |process| sanitize_generic_locations(process, ptr::null_mut()),
        |process, form_id| {
            let predecessor = REFERENCE_SCAN_PREDECESSORS[index].load(Ordering::Acquire);
            let wrapper = reference_scan_wrapper_for_slot(index);
            let use_fallback = predecessor == 0 || predecessor == wrapper;
            // A recursive or unpublished predecessor would re-enter this
            // wrapper. The audited vanilla function is the only safe fallback.
            let target = if !use_fallback {
                predecessor
            } else {
                statics::VANILLA_LOWPROCESS_REFERENCE_SCAN
            };
            REFERENCE_SCAN_PREDECESSOR_CALLS.fetch_add(1, Ordering::Relaxed);
            if use_fallback {
                REFERENCE_SCAN_PREDECESSOR_FALLBACKS.fetch_add(1, Ordering::Relaxed);
            }
            let Ok(original) =
                (unsafe { FnPtr::<ProcessReferenceScanFn>::from_raw(target as *mut c_void) })
            else {
                return;
            };
            diagnostics::mark_load_site(diagnostics::LoadSite::LowProcessPredecessorEnter);
            unsafe { original.as_fn()(process, form_id) };
            diagnostics::mark_load_site(diagnostics::LoadSite::LowProcessPredecessorExit);
        },
    );
}

#[inline(always)]
fn run_live_reference_scan_guard(
    process: *mut c_void,
    form_id: u32,
    sanitize: impl FnOnce(*mut c_void),
    chain: impl FnOnce(*mut c_void, u32),
) {
    // This abstraction exists to make the safety-critical ordering and ABI
    // argument preservation independently regression-testable.
    sanitize(process);
    chain(process, form_id);
}

fn wrapper_for_slot(index: usize) -> usize {
    match index {
        0 => process_cleanup_wrapper_0 as *const () as usize,
        1 => process_cleanup_wrapper_1 as *const () as usize,
        2 => process_cleanup_wrapper_2 as *const () as usize,
        3 => process_cleanup_wrapper_3 as *const () as usize,
        _ => 0,
    }
}

fn reference_scan_wrapper_for_slot(index: usize) -> usize {
    match index {
        0 => process_reference_scan_wrapper_0 as *const () as usize,
        1 => process_reference_scan_wrapper_1 as *const () as usize,
        2 => process_reference_scan_wrapper_2 as *const () as usize,
        3 => process_reference_scan_wrapper_3 as *const () as usize,
        _ => 0,
    }
}

fn ensure_slots_wrapped() {
    if !ENABLED.load(Ordering::Acquire) {
        return;
    }
    let observation = OBSERVATIONS.load(Ordering::Relaxed);
    if observation >= OBSERVATION_WINDOW {
        restore_main_task_boundary();
        return;
    }
    let next_observation = observation + 1;
    OBSERVATIONS.store(next_observation, Ordering::Relaxed);

    // The two contracts are adjacent but independent; a mod may own any subset
    // of the eight slots, so never infer one family's owner from another.
    for index in 0..statics::LOWPROCESS_FUNC011F_SLOTS.len() {
        wrap_cleanup_slot(index);
        wrap_reference_scan_slot(index);
    }

    if next_observation >= OBSERVATION_WINDOW {
        restore_main_task_boundary();
    }
}

fn restore_main_task_boundary() {
    // A single attempt prevents repeated writes from a main-loop hot path.
    // Ownership is checked again below before changing the callsite.
    if !MAIN_BOUNDARY_INSTALLED.load(Ordering::Acquire)
        || MAIN_BOUNDARY_RESTORED.load(Ordering::Acquire)
        || MAIN_BOUNDARY_RESTORE_ATTEMPTED.swap(true, Ordering::AcqRel)
    {
        return;
    }

    let wrapper = main_task_drain_with_slot_wrapping as *const () as usize;
    let predecessor = PREVIOUS_MAIN_TASK_DRAIN.load(Ordering::Acquire);
    let result = unsafe { patching::relative_call_target(statics::MAIN_TASK_DRAIN_CALL_ADDR) };
    let result = match result {
        Ok(current) if current == wrapper && predecessor != 0 => unsafe {
            patching::redirect_relative_call(
                statics::MAIN_TASK_DRAIN_CALL_ADDR,
                predecessor as *mut c_void,
            )
        },
        Ok(current) if current != wrapper => {
            // Another owner replaced the observation boundary. Do not overwrite
            // it: it may already chain this wrapper and owns further teardown.
            MAIN_BOUNDARY_INSTALLED.store(false, Ordering::Release);
            log::info!(
                "[LOWPROCESS] Startup observer no longer owns main boundary target=0x{:08X}",
                current,
            );
            return;
        }
        Ok(_) => Err(anyhow::anyhow!("main boundary predecessor is null")),
        Err(err) => Err(err),
    };

    match result {
        Ok(previous) if previous == wrapper => {
            MAIN_BOUNDARY_RESTORED.store(true, Ordering::Release);
            MAIN_BOUNDARY_INSTALLED.store(false, Ordering::Release);
            MAIN_BOUNDARY_RESTORES.fetch_add(1, Ordering::Relaxed);
            log::info!(
                "[LOWPROCESS] Startup observer removed after {} observations",
                OBSERVATIONS.load(Ordering::Relaxed),
            );
        }
        Ok(previous) => {
            mark_main_boundary_restore_failure(&format!(
                "call target changed during restore: 0x{previous:08X}"
            ));
        }
        Err(err) => mark_main_boundary_restore_failure(&err.to_string()),
    }
}

fn mark_main_boundary_restore_failure(reason: &str) {
    MAIN_BOUNDARY_RESTORE_FAILURES.fetch_add(1, Ordering::Relaxed);
    PATCH_FAILURES.fetch_add(1, Ordering::Relaxed);
    log::error!("[LOWPROCESS] Startup observer restore failed: {}", reason);
}

fn wrap_cleanup_slot(index: usize) {
    wrap_slot(
        index,
        "cleanup",
        &statics::LOWPROCESS_FUNC011F_SLOTS,
        wrapper_for_slot(index),
        statics::VANILLA_LOWPROCESS_FUNC011F,
        &PREDECESSORS,
        &SLOT_STATES,
        &WRAPS,
        &REWRAPS,
        &UNSUPPORTED,
    );
}

fn wrap_reference_scan_slot(index: usize) {
    wrap_slot(
        index,
        "reference-scan",
        &statics::LOWPROCESS_REFERENCE_SCAN_SLOTS,
        reference_scan_wrapper_for_slot(index),
        statics::VANILLA_LOWPROCESS_REFERENCE_SCAN,
        &REFERENCE_SCAN_PREDECESSORS,
        &REFERENCE_SCAN_SLOT_STATES,
        &REFERENCE_SCAN_WRAPS,
        &REFERENCE_SCAN_REWRAPS,
        &REFERENCE_SCAN_UNSUPPORTED,
    );
}

#[allow(clippy::too_many_arguments)]
fn wrap_slot(
    index: usize,
    kind: &'static str,
    slots: &[usize; 4],
    wrapper: usize,
    vanilla: usize,
    predecessors: &[AtomicUsize; 4],
    states: &[AtomicU8; 4],
    wraps: &AtomicU32,
    rewraps: &AtomicU32,
    unsupported: &AtomicU32,
) {
    let slot = slots[index];
    let current = unsafe { ptr::read_unaligned(slot as *const u32) as usize };

    if current == wrapper {
        // This can occur after re-entry or when a prior activation installed
        // the wrapper before atomics were initialized. Vanilla is a safe,
        // non-recursive recovery predecessor for the latter case.
        if predecessors[index].load(Ordering::Acquire) == 0 {
            predecessors[index].store(vanilla, Ordering::Release);
        }
        states[index].store(SLOT_WRAPPED, Ordering::Release);
        return;
    }
    if !is_executable(current) {
        mark_slot_unsupported(
            index,
            current,
            "non-executable-predecessor",
            kind,
            slots,
            states,
            unsupported,
        );
        return;
    }

    let previous_predecessor = predecessors[index].load(Ordering::Acquire);
    if previous_predecessor != 0 && current != previous_predecessor {
        // A later hook may call the wrapper it replaced. Making that hook our
        // new predecessor could produce wrapper -> hook -> wrapper recursion,
        // so retain the observed chain and never fight for the slot.
        mark_slot_chained(index, current, kind, slots, states);
        return;
    }

    if previous_predecessor == 0 {
        // Release-publish before the vtable write: another game thread can call
        // the wrapper immediately after safe_write_32 makes it visible.
        predecessors[index].store(current, Ordering::Release);
    }
    // Recheck after publication to avoid chaining a target that raced with the
    // initial read. A first observation can safely withdraw its publication.
    if unsafe { ptr::read_unaligned(slot as *const u32) as usize } != current {
        if previous_predecessor == 0 {
            predecessors[index].store(0, Ordering::Release);
        }
        return;
    }

    if let Err(err) = safe_write_32(slot as *mut c_void, wrapper as u32) {
        if previous_predecessor == 0 {
            predecessors[index].store(0, Ordering::Release);
        }
        PATCH_FAILURES.fetch_add(1, Ordering::Relaxed);
        states[index].store(SLOT_UNSUPPORTED, Ordering::Release);
        log::error!(
            "[LOWPROCESS] {} slot wrap failed index={} slot=0x{:08X}: {}",
            kind,
            index,
            slot,
            err,
        );
        return;
    }

    if unsafe { ptr::read_unaligned(slot as *const u32) as usize } != wrapper {
        // safe_write_32 returning success is not enough when another patcher can
        // run concurrently; diagnostic state must reflect actual ownership.
        PATCH_FAILURES.fetch_add(1, Ordering::Relaxed);
        states[index].store(SLOT_UNSUPPORTED, Ordering::Release);
        return;
    }

    states[index].store(SLOT_WRAPPED, Ordering::Release);
    let count = if previous_predecessor == 0 {
        wraps.fetch_add(1, Ordering::Relaxed) + 1
    } else {
        rewraps.fetch_add(1, Ordering::Relaxed) + 1
    };
    log::info!(
        "[LOWPROCESS] {} slot wrapped index={} base=0x{:08X} slot=0x{:08X} predecessor=0x{:08X} count={}",
        kind,
        index,
        statics::LOWPROCESS_VTABLE_BASES[index],
        slot,
        current,
        count,
    );
}

fn mark_slot_chained(
    index: usize,
    target: usize,
    kind: &'static str,
    slots: &[usize; 4],
    states: &[AtomicU8; 4],
) {
    let previous = states[index].swap(SLOT_CHAINED, Ordering::AcqRel);
    if previous == SLOT_CHAINED {
        return;
    }
    log::info!(
        "[LOWPROCESS] later {} hook retained above wrapper index={} slot=0x{:08X} target=0x{:08X}",
        kind,
        index,
        slots[index],
        target,
    );
}

fn sanitize_generic_locations(process: *mut c_void, removed_ref: *mut c_void) {
    if process.is_null() {
        return;
    }

    // Entry through a process virtual proves that the object and its embedded
    // head exist. Only native helpers audited to free list nodes, never payload
    // TESObjectREFRs, are permitted for a known matching removed_ref.
    let remove_head =
        unsafe { FnPtr::<ListHeadRemoveFn>::from_address_unchecked(LIST_HEAD_REMOVE_ADDR) }.as_fn();
    let remove = unsafe { FnPtr::<ListRemoveFn>::from_address_unchecked(LIST_REMOVE_ADDR) }.as_fn();
    let head = unsafe { (process as *mut u8).add(GENERIC_LOCATIONS_OFFSET) as *mut ListNode };
    let head_data = unsafe { ptr::read_unaligned(ptr::addr_of!((*head).data)) };
    let head_next = unsafe { ptr::read_unaligned(ptr::addr_of!((*head).next)) };
    // Empty is overwhelmingly common. Return before VirtualQuery, stack cycle
    // initialization, or any native helper call.
    if head_data.is_null() && head_next.is_null() {
        return;
    }

    // Keep capability caches separate. A readable form page is not necessarily
    // writable node storage, and an accessible vtable page is not necessarily
    // executable code.
    let mut writable_node_regions = RegionCache::new();
    let mut readable_form_regions = RegionCache::new();
    let mut executable_regions = RegionCache::new();
    let mut seen = [0usize; MAX_GENERIC_LOCATION_NODES];
    let mut seen_count = 0usize;
    let mut steps = 0usize;
    let mut current = head;
    let mut previous: *mut ListNode = ptr::null_mut();

    while !current.is_null() {
        if steps >= MAX_GENERIC_LOCATION_NODES {
            truncate_cleanup_tail(head, previous);
            mark_cleanup_truncation(previous as usize, current as usize, "budget");
            break;
        }
        steps += 1;

        let current_address = current as usize;
        // The embedded head is covered by the live process contract. Every
        // allocated successor must be writable because containment may relink
        // it; readable-only validation would make later mutation unsafe.
        if current != head
            && (!current_address.is_multiple_of(4)
                || !writable_node_regions.writable(current_address, size_of::<ListNode>()))
        {
            truncate_cleanup_tail(head, previous);
            mark_cleanup_truncation(previous as usize, current_address, "invalid-current");
            break;
        }
        if seen[..seen_count].contains(&current_address) {
            truncate_cleanup_tail(head, previous);
            mark_cleanup_truncation(previous as usize, current_address, "cycle");
            break;
        }
        seen[seen_count] = current_address;
        seen_count += 1;

        let payload = unsafe { ptr::read_unaligned(ptr::addr_of!((*current).data)) };
        let mut next = unsafe { ptr::read_unaligned(ptr::addr_of!((*current).next)) };
        if !next.is_null() {
            let next_address = next as usize;
            if !next_address.is_multiple_of(4)
                || !writable_node_regions.writable(next_address, size_of::<ListNode>())
                || seen[..seen_count].contains(&next_address)
            {
                // The current node is proven writable. Sever its link without
                // dereferencing or freeing the uncertain successor.
                unsafe {
                    ptr::write_unaligned(ptr::addr_of_mut!((*current).next), ptr::null_mut())
                };
                mark_cleanup_truncation(current_address, next_address, "invalid-next");
                next = ptr::null_mut();
            }
        }

        if !removed_ref.is_null() && payload == removed_ref {
            SANITIZED_ENTRIES.fetch_add(1, Ordering::Relaxed);
            if previous.is_null() {
                // Native head removal understands the embedded-head layout and
                // frees only a known successor node when one exists.
                unsafe { remove_head(current) };
                current = head;
                seen_count = 0;
            } else {
                // Pass the exact payload cell expected by the native predecessor
                // removal helper; the TESObjectREFR itself remains borrowed.
                let mut item = payload;
                unsafe { remove(previous, &mut item) };
                current = unsafe { ptr::read_unaligned(ptr::addr_of!((*previous).next)) };
            }
            continue;
        }

        if payload.is_null()
            || !is_valid_tes_form_cached(
                payload,
                &mut readable_form_regions,
                &mut executable_regions,
            )
        {
            mark_invalid_cleanup_form(current_address, payload as usize);
            if previous.is_null() {
                if next.is_null() {
                    // The embedded head cannot be freed. Clearing both words is
                    // the canonical empty tList representation.
                    unsafe {
                        ptr::write_unaligned(ptr::addr_of_mut!((*head).data), ptr::null_mut());
                        ptr::write_unaligned(ptr::addr_of_mut!((*head).next), ptr::null_mut());
                    }
                    break;
                }
                // Promote the proven successor into the embedded head. Do not
                // free its old node: corruption destroyed allocator ownership
                // evidence, and leaking eight bytes is safer than a wrong free.
                unsafe {
                    let next_data = ptr::read_unaligned(ptr::addr_of!((*next).data));
                    let next_next = ptr::read_unaligned(ptr::addr_of!((*next).next));
                    ptr::write_unaligned(ptr::addr_of_mut!((*head).data), next_data);
                    ptr::write_unaligned(ptr::addr_of_mut!((*head).next), next_next);
                }
                current = head;
                seen_count = 0;
            } else {
                // Relink around an invalid payload without freeing either the
                // payload or node whose allocator provenance is uncertain.
                unsafe { ptr::write_unaligned(ptr::addr_of_mut!((*previous).next), next) };
                current = next;
            }
            continue;
        }

        previous = current;
        current = next;
    }
}

fn restore_relative_call_if_owned(address: usize, wrapper: usize, predecessor: usize) {
    let current = unsafe { patching::relative_call_target(address) };
    let Ok(current) = current else {
        PATCH_FAILURES.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if current != wrapper {
        // Another component owns the callsite now. Restoring our predecessor
        // would erase its hook and violate mod-independent composition.
        return;
    }
    let restored = unsafe { patching::redirect_relative_call(address, predecessor as *mut c_void) };
    if !matches!(restored, Ok(previous) if previous == wrapper) {
        PATCH_FAILURES.fetch_add(1, Ordering::Relaxed);
        log::error!(
            "[LOWPROCESS] Failed to roll back callsite 0x{:08X} to 0x{:08X}",
            address,
            predecessor,
        );
    }
}

fn claim_save_traversal_slot(thread_id: u32) -> Option<&'static SaveTraversalSlot> {
    if thread_id == 0 {
        return None;
    }
    for slot in &SAVE_TRAVERSAL_SLOTS {
        let owner = slot.owner_thread.load(Ordering::Acquire);
        if owner == thread_id {
            // Same-thread nesting reuses the slot; the owner wrapper saves and
            // restores the previous context around the nested native call.
            return Some(slot);
        }
        if owner == 0
            && slot
                .owner_thread
                .compare_exchange(0, thread_id, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            // CAS is the only synchronization. The save hot path never blocks
            // and never allocates if all fixed slots are occupied.
            return Some(slot);
        }
    }
    None
}

fn with_save_traversal_context<T>(
    operation: impl FnOnce(&mut SaveTraversalContext) -> T,
) -> Option<T> {
    let thread_id = get_current_thread_id();
    for slot in &SAVE_TRAVERSAL_SLOTS {
        if slot.owner_thread.load(Ordering::Acquire) != thread_id {
            continue;
        }
        // SAFETY: claim_save_traversal_slot grants this thread exclusive access
        // until the owner wrapper release-publishes owner_thread=0.
        let context = unsafe { &mut *slot.context.get() };
        return Some(operation(context));
    }
    None
}

fn begin_save_node(current: *mut ListNode) -> bool {
    enum SaveNodeStatus {
        Valid,
        Blocked,
        Limit,
        Invalid,
    }

    let result = with_save_traversal_context(|context| {
        if context.blocked {
            return SaveNodeStatus::Blocked;
        }
        if context.visited >= MAX_GENERIC_LOCATION_NODES {
            context.blocked = true;
            return SaveNodeStatus::Limit;
        }

        let address = current as usize;
        // The embedded head is part of the already-live process allocation and
        // can be unaligned from Rust's perspective. Successors have no such
        // lifetime proof and require an aligned readable mapping.
        let embedded_head =
            context.visited == 0 && address >= 0x10000 && address == context.embedded_head;
        if !embedded_head
            && (address & 3 != 0
                || !context
                    .readable_regions
                    .readable(address, size_of::<ListNode>()))
        {
            context.blocked = true;
            return SaveNodeStatus::Invalid;
        }

        if context.visited == 0 {
            context.cycle_tortoise = address;
            context.cycle_power = 1;
            context.cycle_length = 0;
        }
        context.visited += 1;
        SaveNodeStatus::Valid
    });
    match result {
        Some(SaveNodeStatus::Valid) => true,
        Some(SaveNodeStatus::Blocked) => false,
        Some(SaveNodeStatus::Limit) => {
            mark_save_traversal_limit(current as usize);
            false
        }
        Some(SaveNodeStatus::Invalid) | None => {
            mark_invalid_save_node(current as usize);
            false
        }
    }
}

fn save_pointer_is_readable(address: usize, len: usize) -> bool {
    if address < 0x10000 || address & 3 != 0 {
        return false;
    }
    with_save_traversal_context(|context| {
        (address == context.embedded_head && len <= size_of::<ListNode>())
            || context.readable_regions.readable(address, len)
    })
    .unwrap_or(false)
}

fn save_traversal_is_blocked() -> bool {
    with_save_traversal_context(|context| context.blocked).unwrap_or(true)
}

fn save_link_completes_cycle(current: usize, next: usize) -> bool {
    with_save_traversal_context(|context| {
        // Brent's algorithm needs constant storage, unlike a visited-node
        // array, and fits the save wrapper's allocation-free contract.
        if context.cycle_power == context.cycle_length {
            context.cycle_tortoise = current;
            context.cycle_power = context.cycle_power.saturating_mul(2);
            context.cycle_length = 0;
        }
        context.cycle_length = context.cycle_length.saturating_add(1);
        context.cycle_tortoise == next
    })
    .unwrap_or(true)
}

fn block_save_traversal() {
    let _ = with_save_traversal_context(|context| {
        context.blocked = true;
    });
}

fn null_list_data() -> *mut ListNode {
    // The native data helper returns a pointer to a payload cell, not the
    // payload itself. Match that ABI with a permanent zero-valued cell.
    ptr::addr_of!(NULL_LIST_DATA).cast_mut().cast()
}

// Corruption logs below are power-of-two sampled so a persistent bad save
// cannot turn synchronous serialization or cleanup into an I/O storm.
fn mark_invalid_save_node(node: usize) {
    let count = INVALID_SAVE_NODES.fetch_add(1, Ordering::Relaxed) + 1;
    if diagnostics::should_log_power_of_two(u64::from(count)) {
        log::warn!(
            "[LOWPROCESS] Save traversal stopped at invalid node=0x{:08X} tid={} total={}",
            node,
            get_current_thread_id(),
            count,
        );
    }
}

fn mark_invalid_save_link(current: usize, next: usize) {
    let count = INVALID_SAVE_LINKS.fetch_add(1, Ordering::Relaxed) + 1;
    if diagnostics::should_log_power_of_two(u64::from(count)) {
        log::warn!(
            "[LOWPROCESS] Save traversal truncated current=0x{:08X} next=0x{:08X} tid={} total={}",
            current,
            next,
            get_current_thread_id(),
            count,
        );
    }
}

fn mark_save_cycle(current: usize, next: usize) {
    let count = SAVE_CYCLES.fetch_add(1, Ordering::Relaxed) + 1;
    if diagnostics::should_log_power_of_two(u64::from(count)) {
        log::warn!(
            "[LOWPROCESS] Save traversal cycle stopped current=0x{:08X} next=0x{:08X} tid={} total={}",
            current,
            next,
            get_current_thread_id(),
            count,
        );
    }
}

fn mark_save_traversal_limit(current: usize) {
    let count = SAVE_TRAVERSAL_LIMITS.fetch_add(1, Ordering::Relaxed) + 1;
    if diagnostics::should_log_power_of_two(u64::from(count)) {
        log::warn!(
            "[LOWPROCESS] Save traversal node budget reached current=0x{:08X} tid={} total={}",
            current,
            get_current_thread_id(),
            count,
        );
    }
}

fn truncate_cleanup_tail(head: *mut ListNode, previous: *mut ListNode) {
    unsafe {
        if previous.is_null() {
            // No successor was proven safe, so reset the embedded head itself.
            ptr::write_unaligned(ptr::addr_of_mut!((*head).data), ptr::null_mut());
            ptr::write_unaligned(ptr::addr_of_mut!((*head).next), ptr::null_mut());
        } else {
            // Keep the validated prefix and orphan the uncertain suffix.
            ptr::write_unaligned(ptr::addr_of_mut!((*previous).next), ptr::null_mut());
        }
    }
}

fn mark_cleanup_truncation(current: usize, next: usize, reason: &'static str) {
    let count = TRUNCATED_CLEANUP_LINKS.fetch_add(1, Ordering::Relaxed) + 1;
    if diagnostics::should_log_power_of_two(u64::from(count)) {
        log::warn!(
            "[LOWPROCESS] Cleanup list truncated current=0x{:08X} next=0x{:08X} reason={} tid={} total={}",
            current,
            next,
            reason,
            get_current_thread_id(),
            count,
        );
    }
}

fn mark_invalid_cleanup_form(node: usize, payload: usize) {
    let count = INVALID_CLEANUP_FORMS.fetch_add(1, Ordering::Relaxed) + 1;
    if diagnostics::should_log_power_of_two(u64::from(count)) {
        log::warn!(
            "[LOWPROCESS] Cleanup unlinked invalid payload node=0x{:08X} payload=0x{:08X} tid={} total={}",
            node,
            payload,
            get_current_thread_id(),
            count,
        );
    }
}

fn mark_slot_unsupported(
    index: usize,
    target: usize,
    reason: &'static str,
    kind: &'static str,
    slots: &[usize; 4],
    states: &[AtomicU8; 4],
    unsupported: &AtomicU32,
) {
    let previous = states[index].swap(SLOT_UNSUPPORTED, Ordering::AcqRel);
    if previous == SLOT_UNSUPPORTED {
        return;
    }
    unsupported.fetch_add(1, Ordering::Relaxed);
    log::warn!(
        "[LOWPROCESS] {} slot left untouched index={} slot=0x{:08X} target=0x{:08X} reason={}",
        kind,
        index,
        slots[index],
        target,
        reason,
    );
}

fn is_valid_tes_form(form: *mut c_void) -> bool {
    with_save_traversal_context(|context| {
        is_valid_tes_form_cached(
            form,
            &mut context.readable_regions,
            &mut context.executable_regions,
        )
    })
    .unwrap_or_else(|| {
        let mut readable_regions = RegionCache::new();
        let mut executable_regions = RegionCache::new();
        is_valid_tes_form_cached(form, &mut readable_regions, &mut executable_regions)
    })
}

fn is_valid_tes_form_cached(
    form: *mut c_void,
    readable_regions: &mut RegionCache,
    executable_regions: &mut RegionCache,
) -> bool {
    let address = form as usize;
    // Validate only the TESForm contract consumed here: readable leading
    // fields, a readable aligned vtable, and an executable first virtual. Form
    // registration is not required for transient engine references.
    if address & 3 != 0 || !readable_regions.readable(address, 0x10) {
        return false;
    }
    let vtable = unsafe { ptr::read_unaligned(form as *const usize) };
    if vtable & 3 != 0 || !readable_regions.readable(vtable, size_of::<usize>()) {
        return false;
    }
    let first_method = unsafe { ptr::read_unaligned(vtable as *const usize) };
    executable_regions.executable(first_method)
}

fn is_executable(address: usize) -> bool {
    if address < 0x10000 {
        return false;
    }
    let Ok(info) = virtual_query(address as *mut c_void) else {
        return false;
    };
    info.is_executable()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[test]
    fn live_reference_scan_slots_cover_every_lowprocess_vtable() {
        assert_eq!(
            statics::LOWPROCESS_REFERENCE_SCAN_SLOTS,
            statics::LOWPROCESS_VTABLE_BASES.map(|base| base + 0x480),
        );
        assert_eq!(statics::VANILLA_LOWPROCESS_REFERENCE_SCAN, 0x0090_CDC0);
        for index in 0..statics::LOWPROCESS_VTABLE_BASES.len() {
            assert_ne!(reference_scan_wrapper_for_slot(index), 0);
        }
    }

    #[test]
    fn live_reference_scan_sanitizes_before_chaining() {
        let sanitized = Cell::new(false);
        let process = 0x1234_0000usize as *mut c_void;
        let form_id = 0xFF00_1234;

        run_live_reference_scan_guard(
            process,
            form_id,
            |seen_process| {
                assert_eq!(seen_process, process);
                sanitized.set(true);
            },
            |seen_process, seen_form_id| {
                assert!(sanitized.get());
                assert_eq!(seen_process, process);
                assert_eq!(seen_form_id, form_id);
            },
        );
    }

    #[test]
    fn live_reference_scan_sanitizer_detaches_low_scalar_payload() {
        let mut process = [0u8; GENERIC_LOCATIONS_OFFSET + size_of::<ListNode>()];
        let head = unsafe { process.as_mut_ptr().add(GENERIC_LOCATIONS_OFFSET) as *mut ListNode };
        unsafe {
            ptr::write_unaligned(ptr::addr_of_mut!((*head).data), 0x0Dusize as *mut c_void);
            ptr::write_unaligned(ptr::addr_of_mut!((*head).next), ptr::null_mut());
        }

        sanitize_generic_locations(process.as_mut_ptr().cast(), ptr::null_mut());

        assert!(unsafe { ptr::read_unaligned(ptr::addr_of!((*head).data)) }.is_null());
        assert!(unsafe { ptr::read_unaligned(ptr::addr_of!((*head).next)) }.is_null());
    }
}
