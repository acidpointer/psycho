//! Synchronous radio availability, native station maintenance, and native radio policy.
//!
//! The periodic engine scanner owns all query inputs, results, and station lists
//! until it returns. This module never defers an answer or substitutes a pending
//! query for signal loss: distance and connected queries retain their native
//! callsites, post-filters, and destruction order.
//!
//! A scoped marker admits the three proven actor-free radio query tuples.
//! Native policy calls keep caller-owned cleanup; a verified inlined expansion
//! uses the game-owned dispatcher, audited candidate enumeration and the
//! original math helper. Missing bases are rejected before their type read.
//! No provider DLL is patched. Unknown providers retain dynamic native dispatch.
//! The station bridge skips only the native empty/inactive no-effect branch.
//! The music module separately repairs native request durations, media results,
//! and playback-offset synchronization.
//!
//! All code bridges install transactionally at the quiescent pre-CRT boundary;
//! DeferredInit verifies ownership and publishes optional capabilities. No job,
//! result, or engine pointer survives a scan. Expansion admission allocates
//! nothing and reads no timers or diagnostics.

mod music;
mod provider;

use std::{
    cell::Cell,
    sync::atomic::{AtomicBool, Ordering},
};

use anyhow::ensure;
use libc::c_void;
use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::{
        hook::{callsite::Rel32CallHookContainer, transaction::ModificationTransaction},
        memory::read_bytes,
    },
};

const PERIODIC_RADIO_SCAN_CALL_ADDR: usize = 0x00833D86;
const RADIO_SIGNAL_SCAN_ADDR: usize = 0x004FF1A0;
const PERIODIC_RADIO_STATION_UPDATE_CALL_ADDR: usize = 0x008341B4;
const RADIO_STATION_UPDATE_ADDR: usize = 0x00834260;
const CURRENT_RADIO_STATION_ADDR: usize = 0x011DD42C;
const RADIO_LIST_RESETTING_ADDR: usize = 0x011DD436;
const RADIO_ENTRY_AUDIO_LIST_HEAD_OFFSET: usize = 0x1C;
const RADIO_ENTRY_AUDIO_LIST_NEXT_OFFSET: usize = 0x20;
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
type DoorPolicySetupFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void) -> *mut c_void;
type DoorAccessibilityFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, *mut c_void, *mut u8) -> u8;

static SCAN_HOOK: Rel32CallHookContainer<RadioSignalScanFn> = Rel32CallHookContainer::new();
static STATION_UPDATE_HOOK: Rel32CallHookContainer<RadioStationUpdateFn> =
    Rel32CallHookContainer::new();
static DOOR_POLICY_SETUP_HOOK: Rel32CallHookContainer<DoorPolicySetupFn> =
    Rel32CallHookContainer::new();
static DOOR_ACCESSIBILITY_HOOK: Rel32CallHookContainer<DoorAccessibilityFn> =
    Rel32CallHookContainer::new();
static POLICY_INSTALL_ATTEMPTED: AtomicBool = AtomicBool::new(false);
static POLICY_INSTALLED: AtomicBool = AtomicBool::new(false);
static POLICY_READY: AtomicBool = AtomicBool::new(false);

thread_local! {
    static RADIO_SCAN_CONTEXT: Cell<ScanContext> = const { Cell::new(ScanContext::EMPTY) };
    static PENDING_POLICY_ACCESS: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
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

/// Installs the native music request repair and synchronous scan/station bridges
/// at the quiescent core startup boundary.
///
/// Native query and destructor calls remain untouched. Related activations roll
/// back on failure without overwriting another component's later hook. Returns
/// an error if the supported caller signatures or hook ownership do not match.
/// This must run once before gameplay; it does not support live reinstallation.
pub fn install_radio_scan_fix() -> anyhow::Result<()> {
    if let Err(error) = music::install() {
        log::error!(
            "[RADIO] Music request repair unavailable; native playback retained: {error:#}"
        );
    }
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
        "[RADIO] Radio availability handled synchronously; native query results and playback kept"
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
        log::info!("[RADIO] Native policy optimization active for query modes 0/1/2");
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
    unsafe { scan(current_ref, out_stations, out_meta) };
    drop(scope);
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
}
