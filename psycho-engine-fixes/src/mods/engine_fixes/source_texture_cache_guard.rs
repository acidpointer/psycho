//! Defensive validation at the shared source-texture cache publication boundary.
//!
//! # Purpose and ownership
//!
//! A reported BSTaskManagerThread crash entered the native cache publisher at
//! `0x00A61C50` with an object whose first required virtual callback resolved
//! to non-executable address `0x00009500`. The supplied evidence does not
//! identify which owner invalidated the object. This module therefore owns
//! only a containment boundary: it rejects candidates that cannot satisfy the
//! native publisher's immediate dispatch contract and otherwise chains the
//! complete provider already installed at that entry.
//!
//! # Lifecycle and invariants
//!
//! Installation runs at the core's existing quiescent startup boundary when
//! `engine_fixes.source_texture_cache_publication_guard` is enabled. One entry
//! hook covers all eight verified native callers. A candidate is admitted only
//! when its vtable and the `+0x94`, `+0x98`, and `+0x9C` callbacks can be copied
//! safely, every distinct callback currently occupies executable committed
//! memory, and the object still names the same vtable immediately before the
//! predecessor is called. Valid candidates and both original arguments are
//! forwarded unchanged.
//!
//! # Failure and performance policy
//!
//! Rejection returns before the publisher acquires its cache lock or performs
//! a virtual call. Every native caller accepts the publisher's void result, and
//! the publisher already has a cache-unavailable no-op path. The guard never
//! retains, releases, frees, repairs, substitutes, or classifies an allocation
//! or module. The admitted path performs three bounded process-memory copies
//! and at most three page queries, with no allocation, file IO, logging, or
//! Psycho lock. Rejection logging is limited to the first and power-of-two
//! occurrences.

use std::{
    ffi::c_void,
    mem::{align_of, size_of},
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
};

use anyhow::Context;
use libpsycho::os::windows::{
    guarded_memory::{prepare_current_process_memory_reader, read_current_process_memory},
    hook::transaction::ModificationTransaction,
    winapi::virtual_query,
};

use super::statics;

const MIN_USER_ADDRESS: usize = 0x0001_0000;
const OBJECT_VTABLE_SIZE: usize = size_of::<u32>();
const FIRST_REQUIRED_CALLBACK_OFFSET: usize = 0x94;
const REQUIRED_CALLBACK_BYTES: usize = 0x0C;

static REJECTIONS: AtomicU32 = AtomicU32::new(0);
static MALFORMED_OBJECT_REJECTIONS: AtomicU32 = AtomicU32::new(0);
static UNREADABLE_OBJECT_REJECTIONS: AtomicU32 = AtomicU32::new(0);
static UNREADABLE_VTABLE_REJECTIONS: AtomicU32 = AtomicU32::new(0);
static NON_EXECUTABLE_CALLBACK_REJECTIONS: AtomicU32 = AtomicU32::new(0);
static CHANGED_DISPATCH_REJECTIONS: AtomicU32 = AtomicU32::new(0);
// Upper word: object address. Lower word: Rejection discriminant. One atomic
// publication keeps the support-report pair coherent across loading threads.
static LAST_REJECTION: AtomicU64 = AtomicU64::new(0);
static MISSING_PREDECESSOR_LOGGED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
enum Rejection {
    MalformedObject = 1,
    UnreadableObject = 2,
    UnreadableVtable = 3,
    NonExecutableCallback = 4,
    ChangedDispatch = 5,
}

impl Rejection {
    fn label(self) -> &'static str {
        match self {
            Self::MalformedObject => "malformed object address",
            Self::UnreadableObject => "unreadable object vtable",
            Self::UnreadableVtable => "unreadable vtable callbacks",
            Self::NonExecutableCallback => "non-executable callback",
            Self::ChangedDispatch => "dispatch changed during validation",
        }
    }

    fn from_raw(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::MalformedObject),
            2 => Some(Self::UnreadableObject),
            3 => Some(Self::UnreadableVtable),
            4 => Some(Self::NonExecutableCallback),
            5 => Some(Self::ChangedDispatch),
            _ => None,
        }
    }
}

/// Read-only installation ownership and rejection state for support reports.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct DiagnosticSnapshot {
    /// Whether hook activation completed.
    pub installed: bool,
    /// Whether Psycho's jump currently occupies the shared publisher entry.
    pub entry_owned: bool,
    /// Live entry state: inactive, owned, displaced, or unknown.
    pub entry_status: &'static str,
    /// Total invalid cache publications contained this session.
    pub rejections: u64,
    /// Rejections before any object memory was inspected.
    pub malformed_objects: u64,
    /// Rejections because the object vtable could not be copied.
    pub unreadable_objects: u64,
    /// Rejections because the complete required vtable range was unavailable.
    pub unreadable_vtables: u64,
    /// Rejections because at least one required callback was not executable.
    pub non_executable_callbacks: u64,
    /// Rejections because the source vtable changed during admission.
    pub changed_dispatches: u64,
    /// Most recently rejected 32-bit object address.
    pub last_object: u32,
    /// Human-readable category for the most recent rejection.
    pub last_reason: &'static str,
}

/// Return a non-draining snapshot and compare the live publisher entry bytes.
pub(super) fn diagnostic_snapshot() -> DiagnosticSnapshot {
    let installed = statics::SOURCE_TEXTURE_CACHE_PUBLISH_HOOK.is_enabled();
    let (entry_owned, entry_status) = if !installed {
        (false, "inactive")
    } else {
        match statics::SOURCE_TEXTURE_CACHE_PUBLISH_HOOK.owns_entry() {
            Ok(true) => (true, "owned"),
            Ok(false) => (false, "displaced"),
            Err(_) => (false, "unknown"),
        }
    };
    let last = LAST_REJECTION.load(Ordering::Relaxed);

    DiagnosticSnapshot {
        installed,
        entry_owned,
        entry_status,
        rejections: u64::from(REJECTIONS.load(Ordering::Relaxed)),
        malformed_objects: u64::from(MALFORMED_OBJECT_REJECTIONS.load(Ordering::Relaxed)),
        unreadable_objects: u64::from(UNREADABLE_OBJECT_REJECTIONS.load(Ordering::Relaxed)),
        unreadable_vtables: u64::from(UNREADABLE_VTABLE_REJECTIONS.load(Ordering::Relaxed)),
        non_executable_callbacks: u64::from(
            NON_EXECUTABLE_CALLBACK_REJECTIONS.load(Ordering::Relaxed),
        ),
        changed_dispatches: u64::from(CHANGED_DISPATCH_REJECTIONS.load(Ordering::Relaxed)),
        last_object: (last >> u32::BITS) as u32,
        last_reason: Rejection::from_raw(last as u32).map_or("none", Rejection::label),
    }
}

/// Install the shared cache-publication guard.
///
/// The caller must own the core's quiescent startup boundary. Initialization
/// resolves the memory reader before enabling the hook, keeping symbol lookup
/// out of texture-loading threads. A failed activation is rolled back.
pub(super) fn install() -> anyhow::Result<()> {
    prepare_current_process_memory_reader().context("resolve guarded engine-memory reader")?;
    let mut reader_probe = [0_u8; 1];
    read_current_process_memory(
        statics::SOURCE_TEXTURE_CACHE_PUBLISH_ADDR,
        &mut reader_probe,
    )
    .context("verify guarded engine-memory reader")?;
    unsafe {
        statics::SOURCE_TEXTURE_CACHE_PUBLISH_HOOK.init(
            "source_texture_cache_publication_guard",
            statics::SOURCE_TEXTURE_CACHE_PUBLISH_ADDR as *mut c_void,
            guard_source_texture_cache_publication,
        )?;
    }

    let mut transaction = ModificationTransaction::new();
    transaction
        .enable_inline(&statics::SOURCE_TEXTURE_CACHE_PUBLISH_HOOK)
        .context("activate shared source-texture cache guard")?;
    transaction.commit();

    log::info!(
        "[SOURCE_TEXTURE_CACHE] Publication guard active at 0x{:08X}",
        statics::SOURCE_TEXTURE_CACHE_PUBLISH_ADDR,
    );
    Ok(())
}

/// Validate one native cache candidate and forward only an admitted object.
///
/// # Safety
///
/// The inline hook preserves the verified cdecl call shape used by every
/// native caller. `source` is treated only as an address until guarded copies
/// prove the immediate object fields; the hook never directly dereferences it.
unsafe extern "C" fn guard_source_texture_cache_publication(
    source: *mut c_void,
    native_context: *mut c_void,
) {
    if let Err(rejection) = validate_candidate(source as usize) {
        record_rejection(source as usize, rejection);
        return;
    }

    let original = match statics::SOURCE_TEXTURE_CACHE_PUBLISH_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            // A detour cannot execute before init has stored its trampoline.
            // If that invariant is ever broken, the publisher's established
            // no-op result is safer than recursing through its patched entry.
            if !MISSING_PREDECESSOR_LOGGED.swap(true, Ordering::Relaxed) {
                log::error!(
                    "[SOURCE_TEXTURE_CACHE] Publisher trampoline unavailable; cache publication is disabled: {error:?}"
                );
            }
            return;
        }
    };
    unsafe { original(source, native_context) };
}

fn validate_candidate(source: usize) -> Result<(), Rejection> {
    if source < MIN_USER_ADDRESS || !source.is_multiple_of(align_of::<u32>()) {
        return Err(Rejection::MalformedObject);
    }

    let mut object_vtable = [0_u8; OBJECT_VTABLE_SIZE];
    read_current_process_memory(source, &mut object_vtable)
        .map_err(|_| Rejection::UnreadableObject)?;
    let vtable = u32::from_ne_bytes(object_vtable) as usize;
    if vtable < MIN_USER_ADDRESS || !vtable.is_multiple_of(align_of::<u32>()) {
        return Err(Rejection::UnreadableVtable);
    }

    let callback_base = vtable
        .checked_add(FIRST_REQUIRED_CALLBACK_OFFSET)
        .ok_or(Rejection::UnreadableVtable)?;
    let mut callback_bytes = [0_u8; REQUIRED_CALLBACK_BYTES];
    read_current_process_memory(callback_base, &mut callback_bytes)
        .map_err(|_| Rejection::UnreadableVtable)?;
    let callbacks = [
        u32::from_ne_bytes([
            callback_bytes[0],
            callback_bytes[1],
            callback_bytes[2],
            callback_bytes[3],
        ]) as usize,
        u32::from_ne_bytes([
            callback_bytes[4],
            callback_bytes[5],
            callback_bytes[6],
            callback_bytes[7],
        ]) as usize,
        u32::from_ne_bytes([
            callback_bytes[8],
            callback_bytes[9],
            callback_bytes[10],
            callback_bytes[11],
        ]) as usize,
    ];

    // VirtualQuery describes a complete run of equally protected pages. Most
    // native vtable methods share one executable image region, so retaining
    // those three bounded ranges avoids redundant Win32 crossings without
    // caching a capability across separate publication calls.
    let mut executable_regions = [(0_usize, 0_usize); 3];
    let mut executable_region_count = 0;
    for callback in callbacks {
        if callback < MIN_USER_ADDRESS {
            return Err(Rejection::NonExecutableCallback);
        }
        if executable_regions[..executable_region_count]
            .iter()
            .any(|(start, end)| callback >= *start && callback < *end)
        {
            continue;
        }
        let info =
            virtual_query(callback as *mut c_void).map_err(|_| Rejection::NonExecutableCallback)?;
        if !info.is_executable() {
            return Err(Rejection::NonExecutableCallback);
        }
        let start = info.base_address as usize;
        let end = start
            .checked_add(info.region_size)
            .ok_or(Rejection::NonExecutableCallback)?;
        if callback < start || callback >= end {
            return Err(Rejection::NonExecutableCallback);
        }
        executable_regions[executable_region_count] = (start, end);
        executable_region_count += 1;
    }

    // This does not pin allocation identity, but it rejects an object whose
    // dispatch owner changed while the guarded snapshots and page queries ran.
    // A transition after this final copy remains outside the proof available
    // from the supplied report.
    let mut current_vtable = [0_u8; OBJECT_VTABLE_SIZE];
    read_current_process_memory(source, &mut current_vtable)
        .map_err(|_| Rejection::ChangedDispatch)?;
    if current_vtable != object_vtable {
        return Err(Rejection::ChangedDispatch);
    }

    Ok(())
}

fn record_rejection(source: usize, rejection: Rejection) {
    let coherent_last = (u64::from(source as u32) << u32::BITS) | u64::from(rejection as u32);
    LAST_REJECTION.store(coherent_last, Ordering::Relaxed);
    increment_saturating(match rejection {
        Rejection::MalformedObject => &MALFORMED_OBJECT_REJECTIONS,
        Rejection::UnreadableObject => &UNREADABLE_OBJECT_REJECTIONS,
        Rejection::UnreadableVtable => &UNREADABLE_VTABLE_REJECTIONS,
        Rejection::NonExecutableCallback => &NON_EXECUTABLE_CALLBACK_REJECTIONS,
        Rejection::ChangedDispatch => &CHANGED_DISPATCH_REJECTIONS,
    });
    let occurrence = increment_saturating(&REJECTIONS);

    if occurrence == 1 || occurrence.is_power_of_two() {
        log::warn!(
            "[SOURCE_TEXTURE_CACHE] Rejected publication #{occurrence}: object=0x{source:08X}, reason={}; cache update skipped",
            rejection.label(),
        );
    }
}

fn increment_saturating(counter: &AtomicU32) -> u32 {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_or(u32::MAX, |previous| previous + 1)
}
