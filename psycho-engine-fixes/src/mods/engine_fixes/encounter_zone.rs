//! Invalid `ExtraEncounterZone` form containment.
//!
//! FalloutNV resolves an optional encounter zone from a reference, its parent
//! cell, or its worldspace in `FUN_00567D20`. The nine direct callers all
//! accept NULL, but they trust every non-NULL result to be a live
//! `BGSEncounterZone`. The reported load crash violated that contract:
//! `FUN_00567D20` returned `0x00035AAA`, and `FUN_00567EC0` immediately read a
//! 16-bit field at `zone + 0x2C`.
//!
//! This module contains the defect at two boundaries:
//!
//! - The ExtraEncounterZone load call at `0x00429F24` rejects an invalid form
//!   before vanilla's RTTI cast and store. The changed-form reader can retain
//!   a NULL extra, but its serializer writes FormID zero without dereferencing
//!   the slot; the runtime repair removes such extras through the native API.
//! - The shared runtime resolver at `0x00567D20` rejects invalid reference,
//!   cell, and worldspace results before any consumer dereferences them.
//!
//! On an access rejection, the guard repairs storage only when it can prove a
//! typed ExtraEncounterZone slot or the worldspace encounter-zone field still
//! contains the exact rejected value. Reference and cell extras are removed
//! through the engine's native NULL setter; the terminal worldspace field is
//! cleared directly. The guard then re-runs the side-effect-free native
//! resolver so an invalid higher-priority source cannot hide a valid cell or
//! worldspace fallback. Re-resolution is bounded by the three native sources.
//!
//! The valid path performs no allocation, locking, or logging. It uses one
//! `VirtualQuery` for the candidate form, validates the exact native vtable,
//! and confirms pointer identity in the engine's live-form registry.
//! Extra-list and owner diagnostics run only after a rejection.

use std::{
    ptr,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};

use anyhow::{Context, ensure};
use libc::c_void;
use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::winapi::{PointerExchange, compare_exchange_pointer, virtual_query},
};

use crate::mods::diagnostics;

use super::{
    patching, statics,
    types::{BaseExtraListGetByTypeFn, BaseExtraListSetEncounterZoneFn},
};

const EXTRA_ENCOUNTER_ZONE_TYPE: u8 = 0x74;
const BGS_ENCOUNTER_ZONE_FORM_TYPE: u8 = 0x61;

const TES_FORM_TYPE_OFFSET: usize = 0x04;
const TES_FORM_REF_ID_OFFSET: usize = 0x0C;
const TES_FORM_MIN_SIZE: usize = 0x10;

const BASE_EXTRA_LIST_MIN_SIZE: usize = 0x1D;
const BS_EXTRA_DATA_VALUE_OFFSET: usize = 0x0C;
const EXTRA_ENCOUNTER_ZONE_SIZE: usize = 0x10;

const TES_OBJECT_REFR_CELL_OFFSET: usize = 0x40;
const TES_OBJECT_REFR_EXTRA_LIST_OFFSET: usize = 0x44;
const TES_OBJECT_REFR_MIN_SIZE: usize =
    TES_OBJECT_REFR_EXTRA_LIST_OFFSET + BASE_EXTRA_LIST_MIN_SIZE;
const TES_OBJECT_CELL_EXTRA_LIST_OFFSET: usize = 0x28;
const TES_OBJECT_CELL_MIN_SIZE: usize =
    TES_OBJECT_CELL_EXTRA_LIST_OFFSET + BASE_EXTRA_LIST_MIN_SIZE;
const TES_OBJECT_CELL_INTERIOR_FLAG_OFFSET: usize = 0x24;
const TES_OBJECT_CELL_WORLDSPACE_OFFSET: usize = 0xC0;
const TES_OBJECT_CELL_WORLDSPACE_MIN_SIZE: usize = TES_OBJECT_CELL_WORLDSPACE_OFFSET + 4;
const TES_WORLDSPACE_ENCOUNTER_ZONE_OFFSET: usize = 0xD0;
const TES_WORLDSPACE_MIN_SIZE: usize = TES_WORLDSPACE_ENCOUNTER_ZONE_OFFSET + 4;

const BASE_EXTRA_LIST_GET_BY_TYPE_ADDR: usize = 0x00410220;
const EXTRA_LIST_LOCK_ACQUIRE_ADDR: usize = 0x0040FBF0;
const EXTRA_LIST_LOCK_RELEASE_ADDR: usize = 0x0040FBA0;
const EXTRA_LIST_LOCK_OBJECT_ADDR: usize = 0x011C3920;
const EXTRA_LIST_LOCK_LABEL: &[u8] = b"Psycho encounter-zone repair\0";
const LOADED_FORM_RESOLVER_ADDR: usize = 0x004839C0;

// The supported executable has a single primary BGSEncounterZone vtable. An
// exact identity check is stronger than accepting any vptr in a broad .rdata
// interval, and it avoids dereferencing an attacker-controlled vtable slot.
const BGS_ENCOUNTER_ZONE_VTABLE: usize = 0x0102_CBBC;
const LOW_POINTER_LIMIT: usize = 0x1_0000;
const DETAILED_LOG_LIMIT: u64 = 16;
const ENCOUNTER_ZONE_SOURCE_COUNT: usize = 3;

// These bytes identify the changed-form case around the chainable CALL. The
// CALL's own displacement is deliberately excluded because another plugin is
// allowed to own an ABI-compatible predecessor that this guard must preserve.
const LOAD_SITE_PREFIX_ADDR: usize = 0x0042_9F1B;
const LOAD_SITE_PREFIX: &[u8] = &[0x8B, 0x4D, 0x08, 0xE8, 0x7D, 0xA9, 0x43, 0x00, 0x50];
const LOAD_SITE_SUFFIX_ADDR: usize = 0x0042_9F29;
const LOAD_SITE_SUFFIX: &[u8] = &[
    0x83, 0xC4, 0x04, 0x6A, 0x00, 0x50, 0xE8, 0xC7, 0xA4, 0xA9, 0x00, 0x83, 0xC4, 0x14, 0x8B, 0x95,
    0x3C, 0xFE, 0xFF, 0xFF, 0x89, 0x42, 0x0C,
];

type LoadedFormResolverFn = unsafe extern "C" fn(u32) -> *mut c_void;
type ExtraListLockAcquireFn = unsafe extern "thiscall" fn(*mut c_void, diagnostic_label: *const u8);
type ExtraListLockReleaseFn = unsafe extern "thiscall" fn(*mut c_void);

static LOAD_RESOLVER_PREDECESSOR: AtomicUsize = AtomicUsize::new(LOADED_FORM_RESOLVER_ADDR);
static LOAD_REJECTION_COUNT: AtomicU64 = AtomicU64::new(0);
static ACCESS_REJECTION_COUNT: AtomicU64 = AtomicU64::new(0);
static ACCESS_REPAIR_COUNT: AtomicU64 = AtomicU64::new(0);
static INSTALLED: AtomicBool = AtomicBool::new(false);
static ORIGINAL_MISSING_LOGGED: AtomicBool = AtomicBool::new(false);
static LOAD_PREDECESSOR_FALLBACK_LOGGED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Rejection {
    reason: &'static str,
    observed_type: Option<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FormIdentity {
    vtable: usize,
    type_id: u8,
    ref_id: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotRepair {
    NoMatch,
    Removed,
    Cleared,
    Unwritable,
}

impl SlotRepair {
    fn permits_reresolution(self) -> bool {
        matches!(self, Self::Removed | Self::Cleared)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RepairOutcome {
    source: &'static str,
    cell: *mut c_void,
    repair: SlotRepair,
}

struct ExtraListLockGuard;

/// Read-only encounter-zone telemetry for the late-bound helper dashboard.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct DashboardSnapshot {
    /// Whether the required shared resolver hook currently owns its entry.
    pub installed: bool,
    /// Invalid forms rejected before the changed-form RTTI boundary.
    pub load_rejections: u64,
    /// Invalid results rejected at the shared runtime resolver boundary.
    pub access_rejections: u64,
    /// Exact reference, cell, or worldspace sources repaired at runtime.
    pub repairs: u64,
}

/// Capture cumulative telemetry without draining producer counters.
pub(super) fn dashboard_snapshot() -> DashboardSnapshot {
    DashboardSnapshot {
        installed: INSTALLED.load(Ordering::Acquire),
        load_rejections: LOAD_REJECTION_COUNT.load(Ordering::Relaxed),
        access_rejections: ACCESS_REJECTION_COUNT.load(Ordering::Relaxed),
        repairs: ACCESS_REPAIR_COUNT.load(Ordering::Relaxed),
    }
}

impl ExtraListLockGuard {
    fn acquire() -> Self {
        let acquire = unsafe {
            FnPtr::<ExtraListLockAcquireFn>::from_address_unchecked(EXTRA_LIST_LOCK_ACQUIRE_ADDR)
        }
        .as_fn();
        unsafe {
            acquire(
                EXTRA_LIST_LOCK_OBJECT_ADDR as *mut c_void,
                EXTRA_LIST_LOCK_LABEL.as_ptr(),
            )
        };
        Self
    }
}

impl Drop for ExtraListLockGuard {
    fn drop(&mut self) {
        let release = unsafe {
            FnPtr::<ExtraListLockReleaseFn>::from_address_unchecked(EXTRA_LIST_LOCK_RELEASE_ADDR)
        }
        .as_fn();
        unsafe { release(EXTRA_LIST_LOCK_OBJECT_ADDR as *mut c_void) };
    }
}

/// Install the required shared resolver guard and the load-time defense.
///
/// The shared resolver is the reported crash boundary and is therefore
/// required. The load call is defense in depth: if another plugin leaves an
/// unsafe or incompatible call-site replacement, the runtime guard remains
/// active and startup continues with a warning instead of disabling unrelated
/// engine fixes.
pub(super) fn install() -> anyhow::Result<()> {
    unsafe {
        statics::ENCOUNTER_ZONE_RESOLVER_HOOK.init(
            "encounter_zone_invalid_form_guard",
            statics::ENCOUNTER_ZONE_RESOLVER_ADDR as *mut c_void,
            hook_encounter_zone_resolver,
        )?;
    }
    statics::ENCOUNTER_ZONE_RESOLVER_HOOK.enable()?;
    INSTALLED.store(true, Ordering::Release);

    if let Err(error) = install_load_guard() {
        log::warn!(
            "[ENCOUNTER_ZONE] Load-boundary guard unavailable; shared resolver guard remains active: {error:#}"
        );
    }

    Ok(())
}

/// Resolve through the native precedence chain and contain invalid sources.
///
/// # Safety
///
/// `owner_ref` must satisfy the native `FUN_00567D20` TESObjectREFR contract.
/// The inline hook preserves the original thiscall ABI and forwards the same
/// pointer unchanged.
pub(super) unsafe extern "thiscall" fn hook_encounter_zone_resolver(
    owner_ref: *mut c_void,
) -> *mut c_void {
    let original = match statics::ENCOUNTER_ZONE_RESOLVER_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            if !ORIGINAL_MISSING_LOGGED.swap(true, Ordering::Relaxed) {
                log::error!(
                    "[ENCOUNTER_ZONE] Resolver trampoline unavailable; returning NULL: {error:?}"
                );
            }
            return ptr::null_mut();
        }
    };

    resolve_validated_with(
        || unsafe { original(owner_ref) },
        validate_encounter_zone,
        |zone, rejection| {
            // FUN_00567D20 is a pure reference -> cell -> worldspace lookup.
            // When an exact source repair succeeds, calling it again is what
            // preserves that native precedence instead of collapsing a bad
            // reference-level value directly to the global NULL fallback.
            let outcome = repair_rejected_storage(owner_ref, zone);
            let repaired = outcome.repair.permits_reresolution();
            if repaired {
                ACCESS_REPAIR_COUNT.fetch_add(1, Ordering::Relaxed);
            }
            log_access_rejection(owner_ref, outcome.cell, zone, outcome.source, rejection);
            repaired
        },
    )
}

fn resolve_validated_with(
    mut resolve: impl FnMut() -> *mut c_void,
    mut validate: impl FnMut(*mut c_void) -> Result<(), Rejection>,
    mut repair: impl FnMut(*mut c_void, Rejection) -> bool,
) -> *mut c_void {
    // There are exactly three native sources. A successful repair can reveal
    // the next one, so the exceptional path may resolve once per source but
    // can never spin on storage that a plugin keeps repopulating.
    for source_index in 0..ENCOUNTER_ZONE_SOURCE_COUNT {
        let zone = resolve();
        if zone.is_null() {
            return zone;
        }

        let Err(rejection) = validate(zone) else {
            return zone;
        };
        if !repair(zone, rejection) || source_index + 1 == ENCOUNTER_ZONE_SOURCE_COUNT {
            return ptr::null_mut();
        }
    }

    ptr::null_mut()
}

/// Redirect the type-0x74 load call while preserving an existing provider.
///
/// The call site's cdecl ABI is fixed by the surrounding changed-form reader.
/// Any executable direct-call target is therefore chainable without tying the
/// guard to a plugin name or version.
fn install_load_guard() -> anyhow::Result<()> {
    let call_site = statics::EXTRA_ENCOUNTER_ZONE_LOAD_RESOLVE_CALL_ADDR;
    unsafe { patching::verify_bytes(LOAD_SITE_PREFIX_ADDR, LOAD_SITE_PREFIX) }
        .context("verify ExtraEncounterZone load prefix")?;
    unsafe { patching::verify_bytes(LOAD_SITE_SUFFIX_ADDR, LOAD_SITE_SUFFIX) }
        .context("verify ExtraEncounterZone load suffix")?;
    let predecessor = unsafe { patching::relative_call_target(call_site) }
        .context("read ExtraEncounterZone load resolver call")?;
    let replacement = resolve_loaded_encounter_zone_checked as *mut c_void;

    if predecessor == replacement as usize {
        return Ok(());
    }
    ensure!(
        is_executable(predecessor),
        "ExtraEncounterZone load resolver target 0x{predecessor:08X} is not executable"
    );

    // Publish before redirecting the call. Installation runs on the startup
    // thread before changed-form loading, so no game caller can observe the
    // replacement without also observing its predecessor.
    LOAD_RESOLVER_PREDECESSOR.store(predecessor, Ordering::Release);
    let redirected = unsafe { patching::redirect_relative_call(call_site, replacement) }
        .context("redirect ExtraEncounterZone load resolver call")?;
    if redirected != predecessor {
        // The startup transaction makes this race unexpected, but the patch
        // helper necessarily re-reads the CALL before writing it. If another
        // installer won that interval, publish the target we actually
        // displaced; never leave the now-active wrapper with a stale chain.
        let actual_chain = select_safe_load_chain(redirected, replacement as usize, is_executable);
        LOAD_RESOLVER_PREDECESSOR.store(actual_chain, Ordering::Release);
        log::warn!(
            "[ENCOUNTER_ZONE] Load resolver changed during installation; chaining actual target 0x{actual_chain:08X}"
        );
    }
    Ok(())
}

fn select_safe_load_chain(
    displaced: usize,
    replacement: usize,
    executable: impl FnOnce(usize) -> bool,
) -> usize {
    if displaced != replacement && executable(displaced) {
        displaced
    } else {
        LOADED_FORM_RESOLVER_ADDR
    }
}

/// Resolve one saved FormID and reject it before vanilla's RTTI dereference.
///
/// # Safety
///
/// This function is entered only from the audited cdecl call at `0x00429F24`.
/// The captured predecessor must retain that exact `u32 -> TESForm*` ABI.
unsafe extern "C" fn resolve_loaded_encounter_zone_checked(saved_ref: u32) -> *mut c_void {
    let mut target = LOAD_RESOLVER_PREDECESSOR.load(Ordering::Acquire);
    if target == resolve_loaded_encounter_zone_checked as *const () as usize
        || !is_executable(target)
    {
        // A chained provider can disappear during shutdown or an unusual live
        // reconfiguration. The audited native resolver is a safe ABI-identical
        // fallback and prevents recursion through our own call-site wrapper.
        if !LOAD_PREDECESSOR_FALLBACK_LOGGED.swap(true, Ordering::Relaxed) {
            log::warn!(
                "[ENCOUNTER_ZONE] Load resolver predecessor unavailable; using native resolver"
            );
        }
        target = LOADED_FORM_RESOLVER_ADDR;
    }

    let resolve = unsafe { FnPtr::<LoadedFormResolverFn>::from_address_unchecked(target) }.as_fn();
    let zone = unsafe { resolve(saved_ref) };
    if zone.is_null() {
        return zone;
    }

    let Err(rejection) = validate_encounter_zone(zone) else {
        return zone;
    };

    log_load_rejection(saved_ref, zone, rejection);
    ptr::null_mut()
}

fn validate_encounter_zone(zone: *mut c_void) -> Result<(), Rejection> {
    validate_candidate_with(zone, inspect_live_form, |ref_id| {
        let resolve = unsafe {
            FnPtr::<LoadedFormResolverFn>::from_address_unchecked(LOADED_FORM_RESOLVER_ADDR)
        }
        .as_fn();
        unsafe { resolve(ref_id) }
    })
}

fn validate_candidate_with(
    zone: *mut c_void,
    inspect: impl FnOnce(usize) -> Result<FormIdentity, Rejection>,
    resolve_form: impl FnOnce(u32) -> *mut c_void,
) -> Result<(), Rejection> {
    let address = zone as usize;
    if address == 0 {
        return Err(Rejection {
            reason: "null",
            observed_type: None,
        });
    }
    if address & 3 != 0 {
        return Err(Rejection {
            reason: "unaligned",
            observed_type: None,
        });
    }

    let identity = inspect(address)?;
    if identity.vtable != BGS_ENCOUNTER_ZONE_VTABLE {
        return Err(Rejection {
            reason: "wrong-vtable",
            observed_type: Some(identity.type_id),
        });
    }
    if identity.type_id != BGS_ENCOUNTER_ZONE_FORM_TYPE {
        return Err(Rejection {
            reason: "wrong-form-type",
            observed_type: Some(identity.type_id),
        });
    }
    if resolve_form(identity.ref_id) != zone {
        return Err(Rejection {
            reason: "not-live-form",
            observed_type: Some(identity.type_id),
        });
    }
    Ok(())
}

fn inspect_live_form(address: usize) -> Result<FormIdentity, Rejection> {
    if !is_readable(address, TES_FORM_MIN_SIZE) {
        return Err(Rejection {
            reason: "unreadable-form",
            observed_type: None,
        });
    }

    Ok(FormIdentity {
        vtable: unsafe { ptr::read_unaligned(address as *const usize) },
        type_id: unsafe { ptr::read_unaligned((address + TES_FORM_TYPE_OFFSET) as *const u8) },
        ref_id: unsafe { ptr::read_unaligned((address + TES_FORM_REF_ID_OFFSET) as *const u32) },
    })
}

fn repair_rejected_storage(owner_ref: *mut c_void, rejected: *mut c_void) -> RepairOutcome {
    if !is_readable(owner_ref as usize, TES_OBJECT_REFR_MIN_SIZE) {
        return RepairOutcome {
            source: "unreadable-owner",
            cell: ptr::null_mut(),
            repair: SlotRepair::NoMatch,
        };
    }

    let cell = unsafe {
        ptr::read_unaligned(
            (owner_ref as *const u8).add(TES_OBJECT_REFR_CELL_OFFSET) as *const *mut c_void
        )
    };

    let ref_list =
        unsafe { (owner_ref as *mut u8).add(TES_OBJECT_REFR_EXTRA_LIST_OFFSET) as *mut c_void };
    match scrub_extra_encounter_zone(ref_list, rejected) {
        SlotRepair::Removed => {
            return RepairOutcome {
                source: "reference-extra-removed",
                cell,
                repair: SlotRepair::Removed,
            };
        }
        SlotRepair::Cleared => {
            return RepairOutcome {
                source: "reference-extra-cleared",
                cell,
                repair: SlotRepair::Cleared,
            };
        }
        SlotRepair::Unwritable => {
            return RepairOutcome {
                source: "reference-extra-unwritable",
                cell,
                repair: SlotRepair::Unwritable,
            };
        }
        SlotRepair::NoMatch => {}
    }

    if !cell.is_null() {
        if !is_readable(cell as usize, TES_OBJECT_CELL_MIN_SIZE) {
            return RepairOutcome {
                source: "unreadable-cell",
                cell,
                repair: SlotRepair::NoMatch,
            };
        }

        let cell_list =
            unsafe { (cell as *mut u8).add(TES_OBJECT_CELL_EXTRA_LIST_OFFSET) as *mut c_void };
        match scrub_extra_encounter_zone(cell_list, rejected) {
            SlotRepair::Removed => {
                return RepairOutcome {
                    source: "cell-extra-removed",
                    cell,
                    repair: SlotRepair::Removed,
                };
            }
            SlotRepair::Cleared => {
                return RepairOutcome {
                    source: "cell-extra-cleared",
                    cell,
                    repair: SlotRepair::Cleared,
                };
            }
            SlotRepair::Unwritable => {
                return RepairOutcome {
                    source: "cell-extra-unwritable",
                    cell,
                    repair: SlotRepair::Unwritable,
                };
            }
            SlotRepair::NoMatch => {}
        }

        // ReferenceWorldspaceResolver reads the exterior worldspace pointer at
        // cell + 0xC0. A shorter page proof is insufficient even though it was
        // enough for the cell's BaseExtraList at +0x28.
        if !is_readable(cell as usize, TES_OBJECT_CELL_WORLDSPACE_MIN_SIZE) {
            return RepairOutcome {
                source: "incomplete-cell",
                cell,
                repair: SlotRepair::NoMatch,
            };
        }
    }

    let repair = scrub_worldspace_encounter_zone(cell, rejected);
    let source = match repair {
        SlotRepair::Cleared => "worldspace-cleared",
        SlotRepair::Unwritable => "worldspace-unwritable",
        SlotRepair::NoMatch => "source-not-recovered",
        SlotRepair::Removed => "worldspace-removed",
    };
    RepairOutcome {
        source,
        cell,
        repair,
    }
}

fn scrub_extra_encounter_zone(list: *mut c_void, rejected: *mut c_void) -> SlotRepair {
    if !is_readable(list as usize, BASE_EXTRA_LIST_MIN_SIZE) {
        return SlotRepair::NoMatch;
    }

    // GetByType and the NULL setter each lock independently. Holding the same
    // audited reentrant engine lock around both calls closes the check/remove
    // race: a conforming writer cannot replace the slot after our equality
    // proof but before the setter removes type 0x74.
    let _lock = ExtraListLockGuard::acquire();
    let get_by_type = unsafe {
        FnPtr::<BaseExtraListGetByTypeFn>::from_address_unchecked(BASE_EXTRA_LIST_GET_BY_TYPE_ADDR)
    }
    .as_fn();
    let extra = unsafe { get_by_type(list, EXTRA_ENCOUNTER_ZONE_TYPE) };
    if !is_readable(extra as usize, EXTRA_ENCOUNTER_ZONE_SIZE) {
        return SlotRepair::NoMatch;
    }

    let slot = unsafe { (extra as *mut u8).add(BS_EXTRA_DATA_VALUE_OFFSET) as *mut *mut c_void };
    if unsafe { ptr::read_unaligned(slot) } != rejected {
        return SlotRepair::NoMatch;
    }

    // Passing NULL to the audited native setter removes and destroys the
    // ExtraEncounterZone instead of leaving a zero-valued extra to propagate
    // into later changed-form serialization. The equality check above is the
    // ownership proof that authorizes removing this typed extra.
    let set_encounter_zone = unsafe {
        FnPtr::<BaseExtraListSetEncounterZoneFn>::from_address_unchecked(
            statics::BASE_EXTRA_LIST_SET_ENCOUNTER_ZONE_ADDR,
        )
    }
    .as_fn();
    unsafe { set_encounter_zone(list, ptr::null_mut()) };
    SlotRepair::Removed
}

fn scrub_worldspace_encounter_zone(cell: *mut c_void, rejected: *mut c_void) -> SlotRepair {
    if cell.is_null() {
        return SlotRepair::NoMatch;
    }

    // FUN_0054DDD0 uses bit 0 at cell+0x24 to identify an interior and reads
    // the exterior worldspace at +0xC0. Use the captured, validated cell
    // instead of FUN_00575D70, which would re-read owner+0x40 after our proof
    // and could traverse a different or incomplete cell during load handoff.
    let cell_flags = unsafe {
        ptr::read_unaligned((cell as *const u8).add(TES_OBJECT_CELL_INTERIOR_FLAG_OFFSET))
    };
    if cell_flags & 1 != 0 {
        return SlotRepair::NoMatch;
    }
    let worldspace = unsafe {
        ptr::read_unaligned(
            (cell as *const u8).add(TES_OBJECT_CELL_WORLDSPACE_OFFSET) as *const *mut c_void
        )
    };
    if !is_readable(worldspace as usize, TES_WORLDSPACE_MIN_SIZE) {
        return SlotRepair::NoMatch;
    }

    let slot = unsafe {
        (worldspace as *mut u8).add(TES_WORLDSPACE_ENCOUNTER_ZONE_OFFSET) as *mut *mut c_void
    };
    if !is_writable(slot as usize, 4) {
        return SlotRepair::Unwritable;
    }

    // The native worldspace setter is itself only a direct store. Use the
    // wrapper's aligned compare-exchange so equality and mutation are one
    // operation; a concurrent legitimate replacement is never overwritten.
    match compare_exchange_pointer(slot, rejected, ptr::null_mut()) {
        Ok(PointerExchange::Exchanged) => SlotRepair::Cleared,
        Ok(PointerExchange::Mismatch(_)) => SlotRepair::NoMatch,
        Err(_) => SlotRepair::Unwritable,
    }
}

fn read_form_id_for_log(form: *mut c_void) -> u32 {
    if !is_readable(form as usize, TES_FORM_MIN_SIZE) {
        return 0;
    }
    unsafe { ptr::read_unaligned((form as *const u8).add(TES_FORM_REF_ID_OFFSET) as *const u32) }
}

fn log_load_rejection(saved_ref: u32, zone: *mut c_void, rejection: Rejection) {
    let total = LOAD_REJECTION_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if !should_log_detail(total) {
        return;
    }

    log::warn!(
        "[ENCOUNTER_ZONE] invalid loaded zone rejected: total={} saved_ref=0x{:08X} zone=0x{:08X} reason={} observed_type={}",
        total,
        saved_ref,
        zone as usize,
        rejection.reason,
        format_observed_type(rejection.observed_type),
    );
}

fn log_access_rejection(
    owner_ref: *mut c_void,
    cell: *mut c_void,
    zone: *mut c_void,
    source: &'static str,
    rejection: Rejection,
) {
    let total = ACCESS_REJECTION_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if !should_log_detail(total) {
        return;
    }

    log::warn!(
        "[ENCOUNTER_ZONE] invalid resolved zone rejected: total={} owner=0x{:08X} owner_form=0x{:08X} cell=0x{:08X} cell_form=0x{:08X} zone=0x{:08X} source={} reason={} observed_type={}",
        total,
        owner_ref as usize,
        read_form_id_for_log(owner_ref),
        cell as usize,
        read_form_id_for_log(cell),
        zone as usize,
        source,
        rejection.reason,
        format_observed_type(rejection.observed_type),
    );
}

fn should_log_detail(total: u64) -> bool {
    total <= DETAILED_LOG_LIMIT || diagnostics::should_log_power_of_two(total)
}

fn format_observed_type(type_id: Option<u8>) -> String {
    type_id.map_or_else(|| "n/a".to_owned(), |value| format!("0x{value:02X}"))
}

fn is_readable(address: usize, len: usize) -> bool {
    if address < LOW_POINTER_LIMIT || len == 0 || address.checked_add(len).is_none() {
        return false;
    }
    let Ok(info) = virtual_query(address as *mut c_void) else {
        return false;
    };
    let region_end = (info.base_address as usize).saturating_add(info.region_size);
    info.is_accessible() && address.saturating_add(len) <= region_end
}

fn is_writable(address: usize, len: usize) -> bool {
    if !is_readable(address, len) {
        return false;
    }
    virtual_query(address as *mut c_void).is_ok_and(|info| info.is_writable())
}

fn is_executable(address: usize) -> bool {
    if address < LOW_POINTER_LIMIT {
        return false;
    }
    virtual_query(address as *mut c_void).is_ok_and(|info| info.is_executable())
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        sync::atomic::{AtomicU32, Ordering},
    };

    use super::*;

    static LOAD_CALLS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn null_load_predecessor(_saved_ref: u32) -> *mut c_void {
        LOAD_CALLS.fetch_add(1, Ordering::Relaxed);
        ptr::null_mut()
    }

    fn identity(type_id: u8, ref_id: u32) -> FormIdentity {
        FormIdentity {
            vtable: BGS_ENCOUNTER_ZONE_VTABLE,
            type_id,
            ref_id,
        }
    }

    fn test_rejection() -> Rejection {
        Rejection {
            reason: "test-invalid",
            observed_type: None,
        }
    }

    #[test]
    fn reported_unaligned_value_is_rejected_without_inspection() {
        let inspected = Cell::new(false);
        let result = validate_candidate_with(
            0x0003_5AAAusize as *mut c_void,
            |_| {
                inspected.set(true);
                Ok(identity(BGS_ENCOUNTER_ZONE_FORM_TYPE, 0x0100_1234))
            },
            |_| panic!("unaligned candidates must not reach the registry"),
        );

        assert_eq!(
            result,
            Err(Rejection {
                reason: "unaligned",
                observed_type: None,
            })
        );
        assert!(!inspected.get());
    }

    #[test]
    fn inaccessible_aligned_value_is_rejected() {
        let result = validate_candidate_with(
            0x0003_5AACusize as *mut c_void,
            |_| {
                Err(Rejection {
                    reason: "unreadable-form",
                    observed_type: None,
                })
            },
            |_| panic!("unreadable candidates must not reach the registry"),
        );

        assert_eq!(
            result,
            Err(Rejection {
                reason: "unreadable-form",
                observed_type: None,
            })
        );
    }

    #[test]
    fn readable_wrong_vtable_is_rejected_before_registry_lookup() {
        let result = validate_candidate_with(
            0x1000_0000usize as *mut c_void,
            |_| {
                Ok(FormIdentity {
                    vtable: BGS_ENCOUNTER_ZONE_VTABLE + 4,
                    type_id: BGS_ENCOUNTER_ZONE_FORM_TYPE,
                    ref_id: 0x0100_1234,
                })
            },
            |_| panic!("wrong-vtable candidates must not reach the registry"),
        );

        assert_eq!(
            result,
            Err(Rejection {
                reason: "wrong-vtable",
                observed_type: Some(BGS_ENCOUNTER_ZONE_FORM_TYPE),
            })
        );
    }

    #[test]
    fn readable_wrong_form_type_is_rejected() {
        let result = validate_candidate_with(
            0x1000_0000usize as *mut c_void,
            |_| Ok(identity(0x3A, 0x0100_1234)),
            |_| panic!("wrong-type candidates must not reach the registry"),
        );

        assert_eq!(
            result,
            Err(Rejection {
                reason: "wrong-form-type",
                observed_type: Some(0x3A),
            })
        );
    }

    #[test]
    fn unregistered_encounter_zone_is_rejected() {
        let zone = 0x1000_0000usize as *mut c_void;
        let result = validate_candidate_with(
            zone,
            |_| Ok(identity(BGS_ENCOUNTER_ZONE_FORM_TYPE, 0x0100_1234)),
            |_| 0x1000_1000usize as *mut c_void,
        );

        assert_eq!(
            result,
            Err(Rejection {
                reason: "not-live-form",
                observed_type: Some(BGS_ENCOUNTER_ZONE_FORM_TYPE),
            })
        );
    }

    #[test]
    fn registered_encounter_zone_is_accepted() {
        let zone = 0x1000_0000usize as *mut c_void;
        let result = validate_candidate_with(
            zone,
            |_| Ok(identity(BGS_ENCOUNTER_ZONE_FORM_TYPE, 0x0100_1234)),
            |_| zone,
        );

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn repaired_reference_source_reveals_valid_cell_fallback() {
        let invalid = 0x1000_0000usize as *mut c_void;
        let valid = 0x1000_1000usize as *mut c_void;
        let calls = Cell::new(0usize);
        let repairs = Cell::new(0usize);

        let result = resolve_validated_with(
            || {
                let call = calls.get();
                calls.set(call + 1);
                [invalid, valid][call]
            },
            |zone| (zone == valid).then_some(()).ok_or_else(test_rejection),
            |zone, rejection| {
                assert_eq!(zone, invalid);
                assert_eq!(rejection, test_rejection());
                repairs.set(repairs.get() + 1);
                true
            },
        );

        assert_eq!(result, valid);
        assert_eq!(calls.get(), 2);
        assert_eq!(repairs.get(), 1);
    }

    #[test]
    fn unrepaired_source_returns_null_without_hiding_repeated_corruption() {
        let invalid = 0x1000_0000usize as *mut c_void;
        let calls = Cell::new(0usize);
        let repairs = Cell::new(0usize);

        let result = resolve_validated_with(
            || {
                calls.set(calls.get() + 1);
                invalid
            },
            |_| Err(test_rejection()),
            |_, _| {
                repairs.set(repairs.get() + 1);
                false
            },
        );

        assert!(result.is_null());
        assert_eq!(calls.get(), 1);
        assert_eq!(repairs.get(), 1);
    }

    #[test]
    fn repeated_invalid_sources_are_bounded_to_native_source_count() {
        let calls = Cell::new(0usize);
        let repairs = Cell::new(0usize);

        let result = resolve_validated_with(
            || {
                calls.set(calls.get() + 1);
                0x1000_0000usize as *mut c_void
            },
            |_| Err(test_rejection()),
            |_, _| {
                repairs.set(repairs.get() + 1);
                true
            },
        );

        assert!(result.is_null());
        assert_eq!(calls.get(), ENCOUNTER_ZONE_SOURCE_COUNT);
        assert_eq!(repairs.get(), ENCOUNTER_ZONE_SOURCE_COUNT);
    }

    #[test]
    fn worldspace_repair_uses_captured_cell_and_exact_pointer_ownership() {
        #[repr(C, align(4))]
        struct CellStorage([u8; TES_OBJECT_CELL_WORLDSPACE_MIN_SIZE]);
        #[repr(C, align(4))]
        struct WorldspaceStorage([u8; TES_WORLDSPACE_MIN_SIZE]);

        let mut cell = Box::new(CellStorage([0; TES_OBJECT_CELL_WORLDSPACE_MIN_SIZE]));
        let mut worldspace = Box::new(WorldspaceStorage([0; TES_WORLDSPACE_MIN_SIZE]));
        let cell_ptr = cell.0.as_mut_ptr().cast::<c_void>();
        let worldspace_ptr = worldspace.0.as_mut_ptr().cast::<c_void>();
        let rejected = 0x0603_5ABBusize as *mut c_void;
        let replacement = 0x0100_2000usize as *mut c_void;
        let cell_worldspace_slot = unsafe {
            cell.0
                .as_mut_ptr()
                .add(TES_OBJECT_CELL_WORLDSPACE_OFFSET)
                .cast::<*mut c_void>()
        };
        let zone_slot = unsafe {
            worldspace
                .0
                .as_mut_ptr()
                .add(TES_WORLDSPACE_ENCOUNTER_ZONE_OFFSET)
                .cast::<*mut c_void>()
        };

        unsafe {
            ptr::write_unaligned(cell_worldspace_slot, worldspace_ptr);
            ptr::write_unaligned(zone_slot, rejected);
        }
        assert_eq!(
            scrub_worldspace_encounter_zone(cell_ptr, rejected),
            SlotRepair::Cleared
        );
        assert!(unsafe { ptr::read_unaligned(zone_slot) }.is_null());

        unsafe { ptr::write_unaligned(zone_slot, replacement) };
        assert_eq!(
            scrub_worldspace_encounter_zone(cell_ptr, rejected),
            SlotRepair::NoMatch
        );
        assert_eq!(unsafe { ptr::read_unaligned(zone_slot) }, replacement);
        assert_eq!(
            scrub_worldspace_encounter_zone(ptr::null_mut(), rejected),
            SlotRepair::NoMatch
        );
    }

    #[test]
    fn raced_load_install_never_chains_recursively_or_to_non_code() {
        let replacement = 0x2000_0000;

        assert_eq!(
            select_safe_load_chain(0x3000_0000, replacement, |_| true),
            0x3000_0000
        );
        assert_eq!(
            select_safe_load_chain(replacement, replacement, |_| {
                panic!("our replacement must not be tested as a predecessor")
            }),
            LOADED_FORM_RESOLVER_ADDR
        );
        assert_eq!(
            select_safe_load_chain(0x3000_0000, replacement, |_| false),
            LOADED_FORM_RESOLVER_ADDR
        );
    }

    #[test]
    fn load_wrapper_calls_its_predecessor_once_and_preserves_null() {
        LOAD_CALLS.store(0, Ordering::Relaxed);
        let old = LOAD_RESOLVER_PREDECESSOR.swap(
            null_load_predecessor as *const () as usize,
            Ordering::AcqRel,
        );

        let result = unsafe { resolve_loaded_encounter_zone_checked(0x0003_5AAA) };

        LOAD_RESOLVER_PREDECESSOR.store(old, Ordering::Release);
        assert!(result.is_null());
        assert_eq!(LOAD_CALLS.load(Ordering::Relaxed), 1);
    }
}
