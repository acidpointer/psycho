//! Native radio music request and position repair.
//!
//! FalloutAudioMedia publishes one of two asynchronous request slots. A new
//! ID used to expose its previous duration until the worker was scheduled;
//! station code could latch that stale positive value permanently. The queue
//! bridge clears the reused duration before wakeup and records only the native
//! station music caller's generation, entry, and start tick. Every native
//! worker duration write also checks that the slot still owns that generation.
//!
//! DirectShow output is checked before the worker converts it to milliseconds.
//! A completed request retains its last valid duration until the station can
//! consume it. Graph completion permits one native next-entry transition for
//! the matching current request, even if the station timer is still positive.
//! Native media reset invalidates all cached request state. Workers do not
//! dereference station pointers; graph ownership and cleanup remain native.
//!
//! The bounded offset patch preserves the native inclusive endpoint. With no
//! duration it enters native playback without seeking to an unbounded elapsed
//! offset. The native worker owns seek and Run results; neither can be used
//! to conclude that a station entry has ended. All code changes install
//! together at the quiescent pre-CRT boundary with exact supported-executable
//! signatures.

use core::ffi::c_void;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use parking_lot::Mutex;

use libpsycho::os::windows::{
    hook::transaction::ModificationTransaction,
    patch::{CodeSignature, OwnedCodePatch},
};

const WRAP_ADDR: usize = 0x00831790;
const NATIVE_RESET_ADDR: usize = 0x0082FA30;
const NATIVE_QUEUE_ADDR: usize = 0x0082F760;
const NATIVE_DURATION_QUERY_ADDR: usize = 0x008308C0;
const CURRENT_STATION_ADDR: usize = 0x011DD42C;
const FIRST_DURATION_ADDR: usize = 0x011DD320;
const SECOND_DURATION_ADDR: usize = 0x011DD354;
const FIRST_GENERATION_ADDR: usize = 0x011DD334;
const SECOND_GENERATION_ADDR: usize = 0x011DD368;
const STATION_MUSIC_RETURN_ADDR: u32 = 0x00833992;

// A request identity is published under the native media lock before its
// worker is signaled. Station wrappers are touched only on the game thread;
// workers retain integer identities and never follow a station pointer.
#[derive(Clone, Copy)]
struct MusicRequest {
    generation: u32,
    station: usize,
    entry: u32,
    start: u32,
    duration: u32,
    terminal_event: u32,
}

impl MusicRequest {
    const EMPTY: Self = Self {
        generation: 0,
        station: 0,
        entry: 0,
        start: 0,
        duration: 0,
        terminal_event: 0,
    };
}

static MUSIC_REQUESTS: Mutex<[MusicRequest; 2]> = Mutex::new([MusicRequest::EMPTY; 2]);
static CURRENT_MUSIC_GENERATION: AtomicU32 = AtomicU32::new(0);
static COMPLETED_REQUEST_SLOTS: AtomicU32 = AtomicU32::new(0);
// Each word packs (generation, duration). A late old-worker result cannot
// replace a new request even when the initial COM query runs without the
// native media lock.
static LAST_VALID_DURATION: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

type QueueFn = unsafe extern "thiscall" fn(*mut c_void, *const u32);
type ResetFn = unsafe extern "C" fn();
type MediaPositionGetFn = unsafe extern "system" fn(*mut c_void, *mut f64) -> i32;

fn slot_duration_address(slot: u32) -> Option<usize> {
    match slot {
        0 => Some(FIRST_DURATION_ADDR),
        1 => Some(SECOND_DURATION_ADDR),
        _ => None,
    }
}

unsafe fn active_native_slot(native_frame: *const u8) -> Option<(usize, u32)> {
    let slot = unsafe { native_frame.sub(0x15C).cast::<u32>().read_unaligned() };
    let generation = unsafe { native_frame.sub(0x158).cast::<u32>().read_unaligned() };
    let generation_address = match slot {
        0 => FIRST_GENERATION_ADDR,
        1 => SECOND_GENERATION_ADDR,
        _ => return None,
    };
    if generation != 0
        && unsafe { (generation_address as *const u32).read_volatile() } == generation
    {
        Some((slot as usize, generation))
    } else {
        None
    }
}

fn remembered_duration(slot: usize, generation: u32) -> u32 {
    let packed = LAST_VALID_DURATION[slot].load(Ordering::Acquire);
    if (packed >> 32) as u32 == generation {
        packed as u32
    } else {
        0
    }
}

fn remember_duration(slot: usize, generation: u32, duration: u32) {
    let word = &LAST_VALID_DURATION[slot];
    let replacement = ((generation as u64) << 32) | duration as u64;
    let mut previous = word.load(Ordering::Acquire);
    while (previous >> 32) as u32 == generation {
        match word.compare_exchange_weak(previous, replacement, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => return,
            Err(observed) => previous = observed,
        }
    }
}

// All three direct callers of 0x0082FA30 pass through this bridge. Clear our
// request identity before the native reset clears both slot generations, so a
// worker completing an old graph cannot publish a station end after reset.
unsafe extern "C" fn reset_media_requests() {
    {
        let mut requests = MUSIC_REQUESTS.lock();
        *requests = [MusicRequest::EMPTY; 2];
        CURRENT_MUSIC_GENERATION.store(0, Ordering::Release);
        COMPLETED_REQUEST_SLOTS.store(0, Ordering::Release);
        for duration in &LAST_VALID_DURATION {
            duration.store(0, Ordering::Release);
        }
    }
    // SAFETY: the three original calls target this cdecl no-argument function.
    let native_reset: ResetFn = unsafe { core::mem::transmute(NATIVE_RESET_ADDR) };
    unsafe { native_reset() };
}

// SAFETY: The native 0x008300C0 frame is live throughout both queue calls.
// The callsite bridge passes that frame, preserving the thiscall ABI. All
// native globals are process-lifetime mappings; the station is read only for
// the verified 0x0083398D caller, which already dereferenced it on this thread.
unsafe extern "C" fn queue_request(
    worker: *mut c_void,
    request: *const u32,
    native_frame: *const u8,
) {
    let slot = unsafe { request.add(1).read_unaligned() };
    if let Some(duration_address) = slot_duration_address(slot) {
        // This runs inside 0x008300C0's media lock, after its new ID is set
        // and before SetEvent. The worker's duration writes are also guarded
        // below, since an older worker may run after this lock is released.
        unsafe { (duration_address as *mut u32).write_volatile(0) };
        let generation = unsafe { request.read_unaligned() };
        let origin = unsafe { native_frame.add(4).cast::<u32>().read_unaligned() };
        let mut next = MusicRequest::EMPTY;
        if origin == STATION_MUSIC_RETURN_ADDR {
            let station = unsafe { (CURRENT_STATION_ADDR as *const usize).read_volatile() };
            if station != 0 {
                let station_start = unsafe {
                    (station as *const u8)
                        .add(0xC)
                        .cast::<u32>()
                        .read_unaligned()
                };
                let submitted_start =
                    unsafe { native_frame.add(0x20).cast::<u32>().read_unaligned() };
                if station_start == submitted_start {
                    next = MusicRequest {
                        generation,
                        station,
                        entry: unsafe {
                            (station as *const u8).add(4).cast::<u32>().read_unaligned()
                        },
                        start: station_start,
                        duration: 0,
                        terminal_event: 0,
                    };
                }
            }
        }
        {
            let mut requests = MUSIC_REQUESTS.lock();
            requests[slot as usize] = next;
            LAST_VALID_DURATION[slot as usize].store((generation as u64) << 32, Ordering::Release);
            COMPLETED_REQUEST_SLOTS.fetch_and(!(1 << slot), Ordering::Release);
            if origin == STATION_MUSIC_RETURN_ADDR {
                CURRENT_MUSIC_GENERATION.store(next.generation, Ordering::Release);
            }
        }
    }
    // SAFETY: the exact native thiscall target and its ret 4 were verified.
    let native_queue: QueueFn = unsafe { core::mem::transmute(NATIVE_QUEUE_ADDR) };
    unsafe { native_queue(worker, request) };
}

// The bridge is entered by two native calls with ECX=worker and one stack
// argument. EBP is the caller's 0x008300C0 frame, whose saved return address
// distinguishes the generic station music caller from other media requests.
#[unsafe(naked)]
unsafe extern "thiscall" fn queue_bridge(_worker: *mut c_void, _request: *const u32) {
    core::arch::naked_asm!(
        "push ebp",
        "mov ebp, esp",
        "push dword ptr [ebp]",
        "push dword ptr [ebp + 8]",
        "push ecx",
        "call {dispatch}",
        "add esp, 12",
        "pop ebp",
        "ret 4",
        dispatch = sym queue_request,
    );
}

// SAFETY: the COM vtable and interface are the same live values used by the
// original indirect call. A local initialized output prevents a failed call
// from reusing the previous position stored in the native stack qword.
unsafe extern "C" fn checked_media_duration(
    interface: *mut c_void,
    output: *mut f64,
    native_frame: *const u8,
) -> i32 {
    let vtable = unsafe { (interface as *const *const usize).read() };
    let method: MediaPositionGetFn = unsafe { core::mem::transmute(vtable.add(7).read()) };
    let mut seconds = 0.0;
    let result = unsafe { method(interface, &mut seconds) };
    let millis = seconds * 1000.0;
    // The frame is the same live worker frame used by the original vcall.
    // Retaining a previous positive duration is radio-specific. Other native
    // audio requests still get a sanitized COM result, without substituting
    // a prior value from a stream whose duration may legitimately change.
    let radio_slot = unsafe { active_native_slot(native_frame) }
        .filter(|(_, generation)| *generation == CURRENT_MUSIC_GENERATION.load(Ordering::Acquire));
    let output_seconds =
        if result == 0 && millis.is_finite() && millis >= 1.0 && millis <= i32::MAX as f64 {
            if let Some((slot, generation)) = radio_slot {
                remember_duration(slot, generation, millis.trunc() as u32);
            }
            seconds
        } else {
            radio_slot.map_or(0.0, |(slot, generation)| {
                let duration = remembered_duration(slot, generation);
                if duration == 0 {
                    0.0
                } else {
                    // Native truncates seconds*1000 with x87. The half
                    // millisecond midpoint reconstructs the exact prior
                    // integer without crossing its next whole millisecond.
                    (duration as f64 + 0.5) / 1000.0
                }
            })
        };
    unsafe { output.write(output_seconds) };
    result
}

// Each replaced virtual call had already pushed (interface, output). The
// wrapper returns with the original stdcall ret 8; native x87 conversion uses
// the latest validated value from this generation, or zero if none exists.
#[unsafe(naked)]
unsafe extern "system" fn duration_bridge(_interface: *mut c_void, _output: *mut f64) -> i32 {
    core::arch::naked_asm!(
        "push ebp",
        "mov ebp, esp",
        "push dword ptr [ebp]",
        "push dword ptr [ebp + 12]",
        "push dword ptr [ebp + 8]",
        "call {dispatch}",
        "add esp, 12",
        "pop ebp",
        "ret 8",
        dispatch = sym checked_media_duration,
    );
}

// The worker also reuses the same qword for GetCurrentPosition. A failed
// position query must not turn the previous duration into a position.
unsafe extern "system" fn checked_media_position(interface: *mut c_void, output: *mut f64) -> i32 {
    let vtable = unsafe { (interface as *const *const usize).read() };
    let method: MediaPositionGetFn = unsafe { core::mem::transmute(vtable.add(9).read()) };
    let mut seconds = 0.0;
    let result = unsafe { method(interface, &mut seconds) };
    let millis = seconds * 1000.0;
    unsafe {
        output.write(
            if result == 0 && millis.is_finite() && millis >= 0.0 && millis <= i32::MAX as f64 {
                seconds
            } else {
                0.0
            },
        );
    }
    result
}

// SAFETY: the worker's frame and COM event code are live at 0x00831A6D.
// Only graph completion for the exact request generation is recorded; errors,
// user abort, and a superseded request cannot advance the playlist.
unsafe extern "C" fn record_terminal(native_frame: *const u8) {
    let event_code = unsafe { native_frame.sub(0x1EC).cast::<u32>().read_unaligned() };
    if event_code != 1 {
        return;
    }
    // The native reset clears slot generations before an old worker's event
    // can be allowed to affect a station again.
    let Some((slot, generation)) = (unsafe { active_native_slot(native_frame) }) else {
        return;
    };
    let duration = unsafe { native_frame.sub(0x14).cast::<u32>().read_unaligned() };
    let mut requests = MUSIC_REQUESTS.lock();
    let state = &mut requests[slot];
    if state.generation == generation
        && state.station != 0
        && CURRENT_MUSIC_GENERATION.load(Ordering::Acquire) == generation
    {
        state.duration = if duration > 0 && duration <= i32::MAX as u32 {
            duration
        } else {
            remembered_duration(slot, generation)
        };
        state.terminal_event = event_code;
        COMPLETED_REQUEST_SLOTS.fetch_or(1 << slot, Ordering::Release);
    }
}

// SAFETY: all four native duration stores occur under the media lock. The
// worker frame holds the request generation and slot copied from its wakeup
// packet. Only that generation may publish into the currently owned slot.
unsafe extern "C" fn publish_matching_duration(native_frame: *const u8, duration: u32) {
    let slot = unsafe { native_frame.sub(0x15C).cast::<u32>().read_unaligned() };
    let (generation_address, duration_address) = match slot {
        0 => (FIRST_GENERATION_ADDR, FIRST_DURATION_ADDR),
        1 => (SECOND_GENERATION_ADDR, SECOND_DURATION_ADDR),
        _ => return,
    };
    let generation = unsafe { native_frame.sub(0x158).cast::<u32>().read_unaligned() };
    if generation != 0
        && unsafe { (generation_address as *const u32).read_volatile() } == generation
    {
        unsafe { (duration_address as *mut u32).write_volatile(duration) };
        if duration > 0
            && duration <= i32::MAX as u32
            && generation == CURRENT_MUSIC_GENERATION.load(Ordering::Acquire)
        {
            remember_duration(slot as usize, generation, duration);
        }
    }
}

// The three bridges preserve the original store's registers and flags. The
// current duration resides in EAX, ECX, or EDX at the four audited sites.
#[unsafe(naked)]
unsafe extern "C" fn publish_duration_eax_bridge() {
    core::arch::naked_asm!(
        "pushfd", "pushad", "push eax", "push ebp",
        "call {dispatch}", "add esp, 8", "popad", "popfd", "ret",
        dispatch = sym publish_matching_duration,
    );
}

#[unsafe(naked)]
unsafe extern "C" fn publish_duration_ecx_bridge() {
    core::arch::naked_asm!(
        "pushfd", "pushad", "push ecx", "push ebp",
        "call {dispatch}", "add esp, 8", "popad", "popfd", "ret",
        dispatch = sym publish_matching_duration,
    );
}

#[unsafe(naked)]
unsafe extern "C" fn publish_duration_edx_bridge() {
    core::arch::naked_asm!(
        "pushfd", "pushad", "push edx", "push ebp",
        "call {dispatch}", "add esp, 8", "popad", "popfd", "ret",
        dispatch = sym publish_matching_duration,
    );
}

// Restores the displaced native store after preserving flags and registers.
#[unsafe(naked)]
unsafe extern "C" fn terminal_bridge() {
    core::arch::naked_asm!(
        "pushfd",
        "pushad",
        "push ebp",
        "call {dispatch}",
        "add esp, 4",
        "popad",
        "popfd",
        "mov byte ptr [ebp - 0x17d], 0",
        "ret",
        dispatch = sym record_terminal,
    );
}

fn matching_request(station: usize, state: &MusicRequest) -> bool {
    if station == 0
        || state.station != station
        || state.generation == 0
        || state.generation != CURRENT_MUSIC_GENERATION.load(Ordering::Acquire)
    {
        return false;
    }
    // This is called only on native station-query/update paths, where the
    // station argument and current-station global are live engine objects.
    unsafe {
        (CURRENT_STATION_ADDR as *const usize).read_volatile() == station
            && (station as *const u8).add(4).cast::<u32>().read_unaligned() == state.entry
            && (station as *const u8)
                .add(0xC)
                .cast::<u32>()
                .read_unaligned()
                == state.start
    }
}

// All four hooked calls originate in native music-start or station-refresh.
// If a fast worker completed and cleared its native slot, retain its final
// validated duration long enough for the game thread to latch it.
unsafe extern "C" fn station_duration_query(priority: u32) -> u32 {
    let native_query: unsafe extern "C" fn(u32) -> u32 =
        unsafe { core::mem::transmute(NATIVE_DURATION_QUERY_ADDR) };
    let native = unsafe { native_query(priority) };
    if priority != 7 || native != 0 {
        return native;
    }
    let station = unsafe { (CURRENT_STATION_ADDR as *const usize).read_volatile() };
    let requests = MUSIC_REQUESTS.lock();
    requests
        .iter()
        .find(|state| {
            state.terminal_event == 1 && state.duration > 0 && matching_request(station, state)
        })
        .map_or(0, |state| state.duration)
}

// SAFETY: the station is the live argument of 0x00834260. Its current entry
// and start tick are compared with the captured request before consuming a
// completion event. A completed request may use the native expiry branch once
// even when the station retained an overlong positive duration. A seek/Run
// HRESULT or graph error is not a completion event.
unsafe extern "C" fn station_expiry_admission(station: usize, native_frame: *const u8) -> i32 {
    let duration = unsafe {
        (station as *const u8)
            .add(0x10)
            .cast::<i32>()
            .read_unaligned()
    };
    let now = unsafe { native_frame.sub(0x14).cast::<u32>().read_unaligned() };
    if duration > 0 && COMPLETED_REQUEST_SLOTS.load(Ordering::Acquire) == 0 {
        return duration;
    }
    let mut requests = MUSIC_REQUESTS.lock();
    let current_station = unsafe { (CURRENT_STATION_ADDR as *const usize).read_volatile() };
    let current_generation = CURRENT_MUSIC_GENERATION.load(Ordering::Acquire);
    for (slot, state) in requests.iter_mut().enumerate() {
        if state.terminal_event != 1 {
            COMPLETED_REQUEST_SLOTS.fetch_and(!(1 << slot), Ordering::Release);
            continue;
        }
        if state.station != current_station || state.generation != current_generation {
            state.terminal_event = 0;
            COMPLETED_REQUEST_SLOTS.fetch_and(!(1 << slot), Ordering::Release);
            continue;
        }
        if matching_request(station, state) && now > state.start {
            if duration > 0 {
                // Native expiry reads station +0x10 again after this bridge.
                // Zeroing a completed entry makes its already elapsed start
                // tick pass the original timer comparison exactly once.
                unsafe {
                    (station as *mut u8)
                        .add(0x10)
                        .cast::<i32>()
                        .write_unaligned(0)
                };
            }
            state.terminal_event = 0;
            COMPLETED_REQUEST_SLOTS.fetch_and(!(1 << slot), Ordering::Release);
            return 1;
        }
    }
    duration
}

// Replaces only the station's duration admission. The following native JLE
// still handles nonpositive results and the original timer/playlist code runs.
#[unsafe(naked)]
unsafe extern "C" fn station_expiry_bridge() {
    core::arch::naked_asm!(
        "push ecx",
        "push edx",
        "push ebp",
        "push dword ptr [ebp + 8]",
        "call {dispatch}",
        "add esp, 8",
        "pop edx",
        "pop ecx",
        "ret",
        dispatch = sym station_expiry_admission,
    );
}

// Exact supported-executable instructions, including the timestamp check.
const ORIGINAL: [u8; 39] = [
    0x8B, 0x85, 0x0C, 0xFE, 0xFF, 0xFF, 0x3B, 0x45, 0xEC, 0x76, 0x11, 0x8B, 0x8D, 0x0C, 0xFE, 0xFF,
    0xFF, 0x2B, 0x4D, 0xEC, 0x89, 0x8D, 0x0C, 0xFE, 0xFF, 0xFF, 0xEB, 0xE4, 0x8B, 0x95, 0x08, 0xFE,
    0xFF, 0xFF, 0x3B, 0x55, 0xC0, 0x73, 0x22,
];

// Entry: EAX = current native tick, EDX = wrapping tick - start. EBP belongs
// to 0x00830B30; duration is [EBP-14], start [EBP-40], offset [EBP-1F4].
// All exits reload scratch registers/flags before consuming them. No stack,
// nonvolatile register, x87, or SSE state is changed here.
// Unknown duration cannot be used as a divisor or wrap bound. Its raw elapsed
// offset is not a valid seek bound, so enter the native playback/event path.
// For offset > duration > 0, (offset - 1) % duration + 1 is exactly the
// native while(offset > duration) result. Plain modulo would incorrectly
// turn an exact track-end offset into the beginning of the track.
const REPLACEMENT: [u8; 39] = [
    0x8B, 0x4D, 0xEC, // mov ecx, [ebp-14]
    0x85, 0xC9, // test ecx, ecx
    0x0F, 0x84, 0x27, 0x01, 0x00, 0x00, // jz 8318C2: native playback/events
    0x3B, 0x45, 0xC0, // cmp eax, [ebp-40]
    0x72, 0x17, // jb 8317B7: native future clamp
    0x39, 0xCA, // cmp edx, ecx
    0x76, 0x35, // jbe 8317D9: already in range
    0x8D, 0x42, 0xFF, // lea eax, [edx-1]
    0x31, 0xD2, // xor edx, edx
    0xF7, 0xF1, // div ecx (proven nonzero)
    0x42, // inc edx
    0x89, 0x95, 0x0C, 0xFE, 0xFF, 0xFF, // mov [ebp-1F4], edx
    0xEB, 0x25, // jmp 8317D9: native seek policy
    0x90, 0x90, 0x90,
];

static WRAP_PATCH: OwnedCodePatch = OwnedCodePatch::new(
    "radio_music_bounded_position_sync",
    WRAP_ADDR,
    &ORIGINAL,
    &REPLACEMENT,
);

// These are the complete direct callsites of the shared two-slot reset in the
// supported executable, including the priority-9 and global teardown paths.
const RESET_CALLS: [(usize, &[u8]); 3] = [
    (0x007D0ACD, &[0xE8, 0x5E, 0xEF, 0x05, 0x00]),
    (0x008300F6, &[0xE8, 0x35, 0xF9, 0xFF, 0xFF]),
    (0x008304A8, &[0xE8, 0x83, 0xF5, 0xFF, 0xFF]),
];
const QUEUE_CALLS: [(usize, &[u8]); 2] = [
    (0x008302E7, &[0xE8, 0x74, 0xF4, 0xFF, 0xFF]),
    (0x00830409, &[0xE8, 0x52, 0xF3, 0xFF, 0xFF]),
];
const DURATION_CALLS: [(usize, &[u8]); 2] = [
    (0x008311E6, &[0x8B, 0x50, 0x1C, 0xFF, 0xD2]),
    (0x008312EA, &[0x8B, 0x4A, 0x1C, 0xFF, 0xD1]),
];
const DURATION_STORES: [(usize, &[u8], usize); 4] = [
    (0x00830C97, &[0xA3, 0x20, 0xD3, 0x1D, 0x01], 0),
    (0x00830D2C, &[0x89, 0x0D, 0x54, 0xD3, 0x1D, 0x01], 1),
    (0x0083135D, &[0x89, 0x15, 0x20, 0xD3, 0x1D, 0x01], 2),
    (0x008313D7, &[0x89, 0x15, 0x54, 0xD3, 0x1D, 0x01], 2),
];
const POSITION_CALLS: [(usize, &[u8]); 2] = [
    (0x00831284, &[0x8B, 0x4A, 0x24, 0xFF, 0xD1]),
    (0x0083171F, &[0x8B, 0x41, 0x24, 0xFF, 0xD0]),
];
const STATION_DURATION_CALLS: [(usize, &[u8]); 4] = [
    (0x008339CC, &[0xE8, 0xEF, 0xCE, 0xFF, 0xFF]),
    (0x008339DA, &[0xE8, 0xE1, 0xCE, 0xFF, 0xFF]),
    (0x00834634, &[0xE8, 0x87, 0xC2, 0xFF, 0xFF]),
    (0x00834642, &[0xE8, 0x79, 0xC2, 0xFF, 0xFF]),
];
const TERMINAL_SITE: usize = 0x00831A6D;
const TERMINAL_ORIGINAL: &[u8] = &[0xC6, 0x85, 0x83, 0xFE, 0xFF, 0xFF, 0x00];
const EXPIRY_SITE: usize = 0x00834680;
const EXPIRY_ORIGINAL: &[u8] = &[0x8B, 0x45, 0x08, 0x83, 0x78, 0x10, 0x00];

// A rel32 call is available from every address in one 32-bit process. The
// replacement and its ownership descriptor live until DLL unload; installation
// is one-shot at the quiescent pre-CRT boundary.
fn call_patch(
    name: &'static str,
    address: usize,
    original: &'static [u8],
    target: usize,
    tail: &[u8],
) -> anyhow::Result<&'static OwnedCodePatch> {
    anyhow::ensure!(
        original.len() == 5 + tail.len(),
        "invalid radio music patch span"
    );
    let displacement = (target as u32).wrapping_sub((address + 5) as u32);
    let mut replacement = Vec::with_capacity(original.len());
    replacement.push(0xE8);
    replacement.extend_from_slice(&displacement.to_le_bytes());
    replacement.extend_from_slice(tail);
    let replacement = Box::leak(replacement.into_boxed_slice());
    Ok(Box::leak(Box::new(OwnedCodePatch::new(
        name,
        address,
        original,
        replacement,
    ))))
}

/// Install once before native audio workers exist. No live patching is allowed.
/// An incompatible instruction window returns an error without overwriting it.
pub(super) fn install() -> anyhow::Result<()> {
    CodeSignature::new(
        "native media reset ABI",
        NATIVE_RESET_ADDR,
        &[0x55, 0x8B, 0xEC, 0xD9, 0xEE],
    )
    .verify()?;
    CodeSignature::new(
        "native first generation reset",
        0x0082FAC1,
        &[0xC7, 0x05, 0x34, 0xD3, 0x1D, 0x01, 0, 0, 0, 0],
    )
    .verify()?;
    CodeSignature::new(
        "native second generation reset",
        0x0082FB59,
        &[0xC7, 0x05, 0x68, 0xD3, 0x1D, 0x01, 0, 0, 0, 0],
    )
    .verify()?;
    CodeSignature::new(
        "native media queue ABI",
        NATIVE_QUEUE_ADDR,
        &[0x55, 0x8B, 0xEC, 0x51, 0x89, 0x4D, 0xFC],
    )
    .verify()?;
    CodeSignature::new(
        "native media queue return",
        0x0082F78B,
        &[0x5D, 0xC2, 0x04, 0x00],
    )
    .verify()?;
    CodeSignature::new(
        "native media request frame",
        0x008300C0,
        &[0x55, 0x8B, 0xEC],
    )
    .verify()?;
    CodeSignature::new(
        "native worker request identity",
        0x00830B5B,
        &[
            0x8B, 0x45, 0x08, 0x8B, 0x48, 0x04, 0x89, 0x8D, 0xA4, 0xFE, 0xFF, 0xFF, 0x8B, 0x55,
            0x08, 0x8B, 0x02, 0x89, 0x85, 0xA8, 0xFE, 0xFF, 0xFF,
        ],
    )
    .verify()?;
    CodeSignature::new(
        "station music request source",
        0x0083396C,
        &[0xA1, 0x2C, 0xD4, 0x1D, 0x01, 0x8B, 0x48, 0x0C, 0x51],
    )
    .verify()?;
    CodeSignature::new(
        "native station expiry continuation",
        0x00834687,
        &[0x0F, 0x8E, 0xC0, 0x03, 0x00, 0x00],
    )
    .verify()?;
    CodeSignature::new(
        "native station clock",
        0x0083465C,
        &[0x89, 0x45, 0xEC, 0x8B, 0x55, 0xEC],
    )
    .verify()?;
    CodeSignature::new(
        "native event completion branch",
        0x008319EB,
        &[0x0F, 0xBE, 0x55, 0xE3, 0x83, 0xE2, 0x20, 0x74, 0x79],
    )
    .verify()?;
    // This prefix proves the live register values, not just the frame offsets.
    CodeSignature::new(
        "music sync input",
        0x0083176F,
        &[
            0xE8, 0xFC, 0x22, 0xC2, 0xFF, 0x8B, 0xC8, 0xE8, 0xC5, 0xB8, 0xE0, 0xFF, 0x89, 0x85,
            0x08, 0xFE, 0xFF, 0xFF, 0x8B, 0x95, 0x08, 0xFE, 0xFF, 0xFF, 0x2B, 0x55, 0xC0, 0x89,
            0x95, 0x0C, 0xFE, 0xFF, 0xFF,
        ],
    )
    .verify()?;
    CodeSignature::new(
        "music future-offset clamp",
        0x008317B7,
        &[0xC7, 0x85, 0x0C, 0xFE, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
    )
    .verify()?;
    CodeSignature::new(
        "music seek continuation",
        0x008317D9,
        &[
            0xC7, 0x85, 0x04, 0xFE, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x95, 0x00, 0xFE,
            0xFF, 0xFF,
        ],
    )
    .verify()?;
    CodeSignature::new(
        "music playback continuation",
        0x008318C2,
        &[0x0F, 0xBE, 0x4D, 0xE3, 0x83, 0xE1, 0x02, 0x74, 0x28],
    )
    .verify()?;
    let mut transaction = ModificationTransaction::new();
    transaction.apply_patch(&WRAP_PATCH)?;
    for (address, original) in RESET_CALLS {
        transaction.apply_patch(call_patch(
            "radio_music_native_reset",
            address,
            original,
            reset_media_requests as *const () as usize,
            &[],
        )?)?;
    }
    for (address, original) in QUEUE_CALLS {
        transaction.apply_patch(call_patch(
            "radio_music_new_request",
            address,
            original,
            queue_bridge as *const () as usize,
            &[],
        )?)?;
    }
    for (address, original) in DURATION_CALLS {
        transaction.apply_patch(call_patch(
            "radio_music_checked_duration",
            address,
            original,
            duration_bridge as *const () as usize,
            &[],
        )?)?;
    }
    for (address, original, register) in DURATION_STORES {
        let bridge = match register {
            0 => publish_duration_eax_bridge as *const () as usize,
            1 => publish_duration_ecx_bridge as *const () as usize,
            _ => publish_duration_edx_bridge as *const () as usize,
        };
        transaction.apply_patch(call_patch(
            "radio_music_generation_duration",
            address,
            original,
            bridge,
            if original.len() == 6 { &[0x90] } else { &[] },
        )?)?;
    }
    for (address, original) in POSITION_CALLS {
        transaction.apply_patch(call_patch(
            "radio_music_checked_position",
            address,
            original,
            checked_media_position as *const () as usize,
            &[],
        )?)?;
    }
    for (address, original) in STATION_DURATION_CALLS {
        transaction.apply_patch(call_patch(
            "radio_music_station_duration",
            address,
            original,
            station_duration_query as *const () as usize,
            &[],
        )?)?;
    }
    transaction.apply_patch(call_patch(
        "radio_music_terminal_event",
        TERMINAL_SITE,
        TERMINAL_ORIGINAL,
        terminal_bridge as *const () as usize,
        &[0x90, 0x90],
    )?)?;
    transaction.apply_patch(call_patch(
        "radio_music_station_expiry",
        EXPIRY_SITE,
        EXPIRY_ORIGINAL,
        station_expiry_bridge as *const () as usize,
        &[0x85, 0xC0],
    )?)?;
    transaction.commit();
    log::info!(
        "[RADIO] Music request durations isolated; media positions validated; completed songs retain native progression"
    );
    Ok(())
}

#[cfg(test)]
#[path = "music_tests.rs"]
mod tests;
