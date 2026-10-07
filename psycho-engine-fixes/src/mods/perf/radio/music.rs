//! Native radio entry admission, media outcomes, and position repair.
//!
//! FalloutAudioMedia publishes one of two asynchronous request slots. A new
//! ID used to expose its previous duration until the worker was scheduled;
//! station code could latch that stale positive value permanently. The queue
//! bridge clears the reused duration before wakeup and records only the native
//! station music caller's generation and selected entry identity.
//! Every native worker duration write also checks that the slot still owns
//! that generation.
//!
//! DirectShow output is checked before the worker converts it to milliseconds.
//! The station reads only the current request's validated duration. Both
//! station starter callers admit a selected entry once, while native volume
//! work continues on later calls. Graph completion, graph failure, worker
//! retirement, missing-file rejection, and the game sound handle are
//! reconciled before native cursor progression. A pending media generation
//! prevents the station timer from expiring a track before its worker ends.
//! Native reset and list cursor mutations delimit entry lifetimes. Workers
//! retain scalar identities and never dereference station pointers.
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
    winapi::get_current_thread_id,
};

const WRAP_ADDR: usize = 0x00831790;
const NATIVE_RESET_ADDR: usize = 0x0082FA30;
const NATIVE_QUEUE_ADDR: usize = 0x0082F760;
const NATIVE_DURATION_QUERY_ADDR: usize = 0x008308C0;
const NATIVE_ACTIVE_QUERY_ADDR: usize = 0x00830750;
const CURRENT_STATION_ADDR: usize = 0x011DD42C;
const FIRST_DURATION_ADDR: usize = 0x011DD320;
const SECOND_DURATION_ADDR: usize = 0x011DD354;
const FIRST_GENERATION_ADDR: usize = 0x011DD334;
const SECOND_GENERATION_ADDR: usize = 0x011DD368;
const NATIVE_STATION_START_ADDR: usize = 0x008331C0;
const NATIVE_RADIO_QUEUE_ADDR: usize = 0x008300C0;
const NATIVE_SOUND_START_ADDR: usize = 0x00AD8830;
const NATIVE_SOUND_ACTIVE_ADDR: usize = 0x00AD8CE0;
const NATIVE_LIST_END_ADDR: usize = 0x008256D0;
const NATIVE_LIST_ITEM_ADDR: usize = 0x006815C0;
const NATIVE_LIST_NEXT_ADDR: usize = 0x00726070;
const GLOBAL_MUSIC_SOUND_ADDR: usize = 0x011DD5BC;
const MEDIA_DISABLED_ADDR: usize = 0x011DCFA5;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct EntryKey {
    station: usize,
    station_list: usize,
    selected_node: usize,
    selected_music_node: usize,
    start: u32,
    epoch: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MediaOutcome {
    Pending,
    Complete,
    Failed,
    Interrupted,
}

#[derive(Clone, Copy)]
struct EntryState {
    key: Option<EntryKey>,
    admitted: bool,
    media_attempted: bool,
    sound_attempted: bool,
    accepted_generation: u32,
    rejected: bool,
}

impl EntryState {
    const EMPTY: Self = Self {
        key: None,
        admitted: false,
        media_attempted: false,
        sound_attempted: false,
        accepted_generation: 0,
        rejected: false,
    };

    fn select(&mut self, key: EntryKey) {
        if self.key != Some(key) {
            *self = Self {
                key: Some(key),
                ..Self::EMPTY
            };
        }
    }

    fn start_is_duplicate(&mut self, key: EntryKey) -> bool {
        self.select(key);
        self.admitted
    }

    fn expiry(
        &mut self,
        outcome: Option<MediaOutcome>,
        sound_active: bool,
        duration: i32,
    ) -> ExpiryAction {
        if self.accepted_generation != 0 {
            return match outcome {
                Some(MediaOutcome::Pending) => ExpiryAction::Hold,
                Some(MediaOutcome::Complete | MediaOutcome::Failed) => {
                    if sound_active {
                        ExpiryAction::Native
                    } else {
                        ExpiryAction::Advance
                    }
                }
                Some(MediaOutcome::Interrupted) | None => {
                    if self.sound_attempted {
                        if sound_active {
                            ExpiryAction::Native
                        } else if duration <= 0 {
                            ExpiryAction::Advance
                        } else {
                            ExpiryAction::Native
                        }
                    } else {
                        self.admitted = false;
                        ExpiryAction::Hold
                    }
                }
            };
        }
        if self.rejected {
            return if sound_active {
                ExpiryAction::Native
            } else {
                ExpiryAction::Advance
            };
        }
        if self.media_attempted && !self.sound_attempted {
            // Media was disabled before publication. Preserve the entry until
            // a later starter can retry after the native pause is lifted.
            return ExpiryAction::Hold;
        }
        if self.sound_attempted && !sound_active && duration <= 0 {
            // A failed sound start may never deliver a callback or duration.
            return ExpiryAction::Advance;
        }
        ExpiryAction::Native
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ExpiryAction {
    Native,
    Hold,
    Advance,
}

static ENTRY: Mutex<EntryState> = Mutex::new(EntryState::EMPTY);
// Only native cursor mutations and restoration advance this identity. It
// distinguishes a rebuilt or wrapped one-track list from the old entry.
static ENTRY_EPOCH: AtomicU64 = AtomicU64::new(1);
// The radio queue wrapper changes the return address visible to 0x008300C0.
// Identify that call by its executing thread; accepted publication still
// verifies priority, station selection, and the submitted start tick.
static RADIO_QUEUE_THREAD: AtomicU32 = AtomicU32::new(0);
static RADIO_QUEUE_FILENAME: AtomicU32 = AtomicU32::new(0);
static RADIO_QUEUE_START: AtomicU32 = AtomicU32::new(0);

// A request identity is published under the native media lock before its
// worker is signaled. Station wrappers are touched only on the game thread;
// workers retain integer identities and never follow a station pointer.
#[derive(Clone, Copy)]
struct MusicRequest {
    generation: u32,
    epoch: u64,
    station: usize,
    station_list: usize,
    selected_node: usize,
    selected_music_node: usize,
    start: u32,
    outcome: MediaOutcome,
}

impl MusicRequest {
    const EMPTY: Self = Self {
        generation: 0,
        epoch: 0,
        station: 0,
        station_list: 0,
        selected_node: 0,
        selected_music_node: 0,
        start: 0,
        outcome: MediaOutcome::Pending,
    };

    fn matches(&self, key: EntryKey) -> bool {
        self.generation != 0
            && self.epoch == key.epoch
            && self.station == key.station
            && self.station_list == key.station_list
            && self.selected_node == key.selected_node
            && self.selected_music_node == key.selected_music_node
            && self.start == key.start
    }

    fn key(&self) -> EntryKey {
        EntryKey {
            station: self.station,
            station_list: self.station_list,
            selected_node: self.selected_node,
            selected_music_node: self.selected_music_node,
            start: self.start,
            epoch: self.epoch,
        }
    }
}

static MUSIC_REQUESTS: Mutex<[MusicRequest; 2]> = Mutex::new([MusicRequest::EMPTY; 2]);
// A completed slot can be reused before the station gets its next update.
static LAST_TERMINAL_REQUEST: Mutex<MusicRequest> = Mutex::new(MusicRequest::EMPTY);
static CURRENT_MUSIC_GENERATION: AtomicU32 = AtomicU32::new(0);
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

// The station's +4 list selects a nested music list. Each list's +8 field is
// its cursor node; either cursor can change the file played by 0x008331C0.
// Only the game thread calls this helper.
unsafe fn station_selection(station: usize) -> Option<(usize, usize, usize, u32)> {
    if station == 0 {
        return None;
    }
    let list = unsafe {
        (station as *const u8)
            .add(4)
            .cast::<usize>()
            .read_unaligned()
    };
    if list == 0 {
        return None;
    }
    let selected_node = unsafe { (list as *const u8).add(8).cast::<usize>().read_unaligned() };
    if selected_node == 0 {
        return None;
    }
    let selected_list = unsafe { (selected_node as *const usize).read_unaligned() };
    if selected_list == 0 {
        return None;
    }
    let selected_music_node = unsafe {
        (selected_list as *const u8)
            .add(8)
            .cast::<usize>()
            .read_unaligned()
    };
    if selected_music_node == 0 {
        return None;
    }
    let start = unsafe {
        (station as *const u8)
            .add(0xC)
            .cast::<u32>()
            .read_unaligned()
    };
    Some((list, selected_node, selected_music_node, start))
}

// These reads occur only on the live native station/game thread. Workers
// receive the copied scalar key and never follow list or station pointers.
unsafe fn current_entry_key() -> Option<EntryKey> {
    let station = unsafe { (CURRENT_STATION_ADDR as *const usize).read_volatile() };
    let (station_list, selected_node, selected_music_node, start) =
        unsafe { station_selection(station) }?;
    Some(EntryKey {
        station,
        station_list,
        selected_node,
        selected_music_node,
        start,
        epoch: ENTRY_EPOCH.load(Ordering::Acquire),
    })
}

unsafe fn current_inner_list() -> Option<usize> {
    let station = unsafe { (CURRENT_STATION_ADDR as *const usize).read_volatile() };
    if station == 0 {
        return None;
    }
    let list = unsafe {
        (station as *const u8)
            .add(4)
            .cast::<usize>()
            .read_unaligned()
    };
    if list == 0 {
        return None;
    }
    let node = unsafe { (list as *const u8).add(8).cast::<usize>().read_unaligned() };
    if node == 0 {
        return None;
    }
    Some(unsafe { (node as *const usize).read_unaligned() })
}

// The station update itself iterates the embedded +0x1C sound-object list
// with these three methods. Its objects own BSound handles at +4 and +0x10.
// Only the live game-side expiry path calls this when an outcome could
// accelerate progression; a graph result cannot retire another sound.
unsafe fn station_object_sound_active(station: usize) -> bool {
    type ListEnd = unsafe extern "thiscall" fn(*mut c_void) -> u8;
    type ListItem = unsafe extern "thiscall" fn(*mut c_void) -> *const usize;
    type ListNext = unsafe extern "thiscall" fn(*mut c_void) -> *mut c_void;
    type SoundActive = unsafe extern "thiscall" fn(*mut c_void) -> u8;
    let is_end: ListEnd = unsafe { core::mem::transmute(NATIVE_LIST_END_ADDR) };
    let item: ListItem = unsafe { core::mem::transmute(NATIVE_LIST_ITEM_ADDR) };
    let next: ListNext = unsafe { core::mem::transmute(NATIVE_LIST_NEXT_ADDR) };
    let active: SoundActive = unsafe { core::mem::transmute(NATIVE_SOUND_ACTIVE_ADDR) };
    let mut cursor = (station + 0x1C) as *mut c_void;
    while unsafe { is_end(cursor) } == 0 {
        let cell = unsafe { item(cursor) };
        if !cell.is_null() {
            let object = unsafe { cell.read_unaligned() };
            if object != 0 && unsafe { ((object + 0x1C) as *const u8).read() } != 0 {
                if unsafe { active((object + 4) as *mut c_void) } != 0
                    || unsafe { active((object + 0x10) as *mut c_void) } != 0
                {
                    return true;
                }
            }
        }
        cursor = unsafe { next(cursor) };
        if cursor.is_null() {
            return false;
        }
    }
    false
}

fn new_entry_epoch() {
    ENTRY_EPOCH.fetch_add(1, Ordering::AcqRel);
}

// The only native station-list rebuild calls are cdecl with two arguments.
unsafe extern "C" fn rebuild_station_list(station: usize, argument: u32) {
    if station == unsafe { (CURRENT_STATION_ADDR as *const usize).read_volatile() } {
        new_entry_epoch();
    }
    let native: unsafe extern "C" fn(usize, u32) = unsafe { core::mem::transmute(0x00837060usize) };
    unsafe { native(station, argument) };
}

// These callsite bridges target only native radio cursor operations. Compare
// the live list owner before bumping the epoch: noncurrent stations also tick.
unsafe extern "thiscall" fn advance_outer_list(list: *mut c_void) -> u8 {
    let station = unsafe { (CURRENT_STATION_ADDR as *const usize).read_volatile() };
    if station != 0
        && unsafe {
            (station as *const u8)
                .add(4)
                .cast::<usize>()
                .read_unaligned()
        } == list as usize
    {
        new_entry_epoch();
    }
    let native: unsafe extern "thiscall" fn(*mut c_void) -> u8 =
        unsafe { core::mem::transmute(0x0083B9F0usize) };
    unsafe { native(list) }
}

unsafe extern "thiscall" fn advance_inner_list(list: *mut c_void) -> u8 {
    if unsafe { current_inner_list() } == Some(list as usize) {
        new_entry_epoch();
    }
    let native: unsafe extern "thiscall" fn(*mut c_void) -> u8 =
        unsafe { core::mem::transmute(0x0083C7E0usize) };
    unsafe { native(list) }
}

unsafe extern "thiscall" fn reset_inner_list(list: *mut c_void) -> u8 {
    if unsafe { current_inner_list() } == Some(list as usize) {
        new_entry_epoch();
    }
    let native: unsafe extern "thiscall" fn(*mut c_void) -> u8 =
        unsafe { core::mem::transmute(0x0083C7B0usize) };
    unsafe { native(list) }
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
        *LAST_TERMINAL_REQUEST.lock() = MusicRequest::EMPTY;
        CURRENT_MUSIC_GENERATION.store(0, Ordering::Release);
        for duration in &LAST_VALID_DURATION {
            duration.store(0, Ordering::Release);
        }
    }
    // The selected entry can survive a native media reset (for example when
    // resuming radio). It must be eligible for a fresh start afterward.
    *ENTRY.lock() = EntryState::EMPTY;
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
        let priority = unsafe { native_frame.add(8).cast::<u32>().read_unaligned() };
        let radio_call = RADIO_QUEUE_THREAD.load(Ordering::Acquire) == get_current_thread_id()
            && RADIO_QUEUE_FILENAME.load(Ordering::Acquire)
                == unsafe { native_frame.add(0xC).cast::<u32>().read_unaligned() }
            && RADIO_QUEUE_START.load(Ordering::Acquire)
                == unsafe { native_frame.add(0x20).cast::<u32>().read_unaligned() };
        let mut next = MusicRequest::EMPTY;
        if radio_call && priority == 7 {
            let station = unsafe { (CURRENT_STATION_ADDR as *const usize).read_volatile() };
            if let Some((station_list, selected_node, selected_music_node, station_start)) =
                unsafe { station_selection(station) }
            {
                let submitted_start =
                    unsafe { native_frame.add(0x20).cast::<u32>().read_unaligned() };
                if station_start == submitted_start {
                    next = MusicRequest {
                        generation,
                        epoch: ENTRY_EPOCH.load(Ordering::Acquire),
                        station,
                        station_list,
                        selected_node,
                        selected_music_node,
                        start: station_start,
                        outcome: MediaOutcome::Pending,
                    };
                }
            }
        }
        {
            let mut requests = MUSIC_REQUESTS.lock();
            requests[slot as usize] = next;
            LAST_VALID_DURATION[slot as usize].store((generation as u64) << 32, Ordering::Release);
            if radio_call || priority == 7 {
                // Another priority-7 request supersedes the station graph
                // even when it is queued into the other native slot.
                CURRENT_MUSIC_GENERATION.store(next.generation, Ordering::Release);
            }
        }
        if next.generation != 0 {
            let mut entry = ENTRY.lock();
            if entry.key == Some(next.key()) {
                entry.accepted_generation = next.generation;
                entry.admitted = true;
                entry.rejected = false;
            }
        }
    }
    // SAFETY: the exact native thiscall target and its ret 4 were verified.
    let native_queue: QueueFn = unsafe { core::mem::transmute(NATIVE_QUEUE_ADDR) };
    unsafe { native_queue(worker, request) };
}

// The bridge is entered by two native calls with ECX=worker and one stack
// argument. EBP is the caller's 0x008300C0 frame; the published request is
// matched to the synchronous radio queue wrapper by thread and arguments.
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

// The radio request call has seven cdecl dwords. Observe the attempted entry
// before native admission. Accepted publication records its generation before
// native releases the media lock; the shared queue has no success return and
// can reject a missing modded file before that publication hook.
unsafe extern "C" fn radio_queue(
    priority: u32,
    filename: u32,
    fade: u32,
    offset: u32,
    bypass: u32,
    volume: u32,
    start: u32,
) {
    let before = unsafe { current_entry_key() };
    if let Some(key) = before {
        let mut entry = ENTRY.lock();
        entry.select(key);
        entry.media_attempted = true;
        entry.admitted = true;
    }
    let native: unsafe extern "C" fn(u32, u32, u32, u32, u32, u32, u32) =
        unsafe { core::mem::transmute(NATIVE_RADIO_QUEUE_ADDR) };
    RADIO_QUEUE_FILENAME.store(filename, Ordering::Release);
    RADIO_QUEUE_START.store(start, Ordering::Release);
    RADIO_QUEUE_THREAD.store(get_current_thread_id(), Ordering::Release);
    unsafe { native(priority, filename, fade, offset, bypass, volume, start) };
    RADIO_QUEUE_THREAD.store(0, Ordering::Release);
    RADIO_QUEUE_FILENAME.store(0, Ordering::Release);
    RADIO_QUEUE_START.store(0, Ordering::Release);
    if let Some(key) = before.filter(|key| unsafe { current_entry_key() } == Some(*key)) {
        let disabled = unsafe { (MEDIA_DISABLED_ADDR as *const u8).read_volatile() != 0 };
        let mut entry = ENTRY.lock();
        if entry.key == Some(key) {
            if entry.accepted_generation == 0 {
                entry.rejected = !disabled;
                entry.admitted = !disabled || entry.sound_attempted;
            }
        }
    }
}

// The caller's selected cursor is live. Admission closes only after the
// native starter actually tries a media request or starts its sound handle.
// A duplicate forced (argument-1) start is sent through the argument-0
// volume path, with the active query below supplying the matching entry bit.
unsafe extern "C" fn station_start(argument: u32) {
    let duplicate =
        unsafe { current_entry_key() }.is_some_and(|key| ENTRY.lock().start_is_duplicate(key));
    let native: unsafe extern "C" fn(u32) =
        unsafe { core::mem::transmute(NATIVE_STATION_START_ADDR) };
    unsafe { native(if duplicate { 0 } else { argument }) };
}

unsafe extern "C" fn restored_station_start(argument: u32) {
    new_entry_epoch();
    *ENTRY.lock() = EntryState::EMPTY;
    unsafe { station_start(argument) };
}

// This exact starter callsite starts the global music BSound. Its synchronous
// native call precedes the optional DirectShow request for the same entry.
unsafe extern "thiscall" fn music_sound_start(sound: *mut c_void, argument: u32) {
    let native: unsafe extern "thiscall" fn(*mut c_void, u32) =
        unsafe { core::mem::transmute(NATIVE_SOUND_START_ADDR) };
    unsafe { native(sound, argument) };
    if let Some(key) = unsafe { current_entry_key() } {
        let mut entry = ENTRY.lock();
        entry.select(key);
        entry.sound_attempted = true;
        entry.admitted = true;
    }
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
// Only the exact request generation can publish a terminal outcome.
unsafe extern "C" fn record_terminal(native_frame: *const u8) {
    let event_code = unsafe { native_frame.sub(0x1EC).cast::<u32>().read_unaligned() };
    let event_status = unsafe { native_frame.sub(0x1E0).cast::<i32>().read_unaligned() };
    let outcome = match event_code {
        1 if event_status == 0 => MediaOutcome::Complete,
        1..=3 => MediaOutcome::Failed,
        _ => return,
    };
    // The native reset clears slot generations before an old worker's event
    // can be allowed to affect a station again.
    let Some((slot, generation)) = (unsafe { active_native_slot(native_frame) }) else {
        return;
    };
    let mut requests = MUSIC_REQUESTS.lock();
    let state = &mut requests[slot];
    if state.generation == generation
        && state.station != 0
        && CURRENT_MUSIC_GENERATION.load(Ordering::Acquire) == generation
    {
        state.outcome = outcome;
        *LAST_TERMINAL_REQUEST.lock() = *state;
    }
}

// Entered after native 0x00830470 acquired the media lock and before the
// worker clears its slot generation. A failed file/COM setup has no graph
// event; a paused or superseded generation is resumable, not a bad track.
unsafe extern "C" fn record_worker_retirement(native_frame: *const u8) {
    let Some((slot, generation)) = (unsafe { active_native_slot(native_frame) }) else {
        return;
    };
    let flag_address = if slot == 0 { 0x011DD310 } else { 0x011DD311 };
    let paused = unsafe { (flag_address as *const u8).read_volatile() & 2 != 0 };
    let mut requests = MUSIC_REQUESTS.lock();
    let request = &mut requests[slot];
    if request.generation == generation
        && request.station != 0
        && request.outcome == MediaOutcome::Pending
    {
        request.outcome =
            if paused || CURRENT_MUSIC_GENERATION.load(Ordering::Acquire) != generation {
                MediaOutcome::Interrupted
            } else {
                MediaOutcome::Failed
            };
        if request.outcome == MediaOutcome::Failed {
            *LAST_TERMINAL_REQUEST.lock() = *request;
        }
    }
}

// The displaced compare supplies flags to the native JNE at 0x00831B0D.
#[unsafe(naked)]
unsafe extern "C" fn worker_retirement_bridge() {
    core::arch::naked_asm!(
        "pushad", "push ebp", "call {dispatch}", "add esp, 4", "popad",
        "cmp dword ptr [ebp - 0x15c], 0", "ret",
        dispatch = sym record_worker_retirement,
    );
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

fn matching_request(key: EntryKey, state: &MusicRequest, current_generation: u32) -> bool {
    state.matches(key) && state.generation == current_generation
}

fn entry_media_outcome(
    key: EntryKey,
    generation: u32,
    current_generation: u32,
    requests: &[MusicRequest; 2],
    last_terminal: MusicRequest,
) -> Option<MediaOutcome> {
    requests
        .iter()
        .find(|request| {
            request.generation == generation && matching_request(key, request, current_generation)
        })
        .map(|request| request.outcome)
        .or_else(|| {
            (last_terminal.generation == generation && last_terminal.matches(key))
                .then_some(last_terminal.outcome)
        })
}

// A matching admitted entry must take the starter's volume/update path even
// after a retired worker made the native media query inactive. The forced
// station caller is converted to argument 0 by station_start; restoration is
// a new epoch and retains its original forced behavior.
unsafe extern "C" fn station_music_active(
    priority: u32,
    include_playing: u32,
    _native_frame: *const u8,
) -> u8 {
    let native_query: unsafe extern "C" fn(u32, u32) -> u8 =
        unsafe { core::mem::transmute(NATIVE_ACTIVE_QUERY_ADDR) };
    let active = unsafe { native_query(priority, include_playing) };
    if active != 0 || priority != 7 || include_playing != 1 {
        return active;
    }
    let Some(key) = (unsafe { current_entry_key() }) else {
        return active;
    };
    let entry = ENTRY.lock();
    if entry.key == Some(key) && entry.admitted {
        1
    } else {
        active
    }
}

// The native callsite already pushed both cdecl arguments. The bridge adds
// only the live 0x008331C0 frame and leaves the caller's stack cleanup intact.
#[unsafe(naked)]
unsafe extern "C" fn station_active_bridge() {
    core::arch::naked_asm!(
        "push ebp",
        "mov ebp, esp",
        "push dword ptr [ebp]",
        "push dword ptr [ebp + 12]",
        "push dword ptr [ebp + 8]",
        "call {dispatch}",
        "add esp, 12",
        "pop ebp",
        "ret",
        dispatch = sym station_music_active,
    );
}

// All four hooked calls originate in native music-start or station-refresh.
// The native caller queries twice before storing. A worker can clear its slot
// between those calls, so both must read the generation-bound validated value
// even if the graph has not posted a completion event.
unsafe extern "C" fn station_duration_query(priority: u32) -> u32 {
    let native_query: unsafe extern "C" fn(u32) -> u32 =
        unsafe { core::mem::transmute(NATIVE_DURATION_QUERY_ADDR) };
    let native = unsafe { native_query(priority) };
    if priority != 7 {
        return native;
    }
    let Some(key) = (unsafe { current_entry_key() }) else {
        return native;
    };
    let requests = MUSIC_REQUESTS.lock();
    requests
        .iter()
        .enumerate()
        .find(|(_, state)| {
            matching_request(key, state, CURRENT_MUSIC_GENERATION.load(Ordering::Acquire))
        })
        .map_or(native, |(slot, state)| {
            remembered_duration(slot, state.generation)
        })
}

// SAFETY: the station is the live argument of 0x00834260. Its current entry
// and start tick are compared with the captured request before consuming an
// outcome. Native cursor code still chooses the next entry. A seek/Run
// HRESULT alone does not establish a terminal result.
unsafe extern "C" fn station_expiry_admission(station: usize, _native_frame: *const u8) -> i32 {
    let duration = unsafe {
        (station as *const u8)
            .add(0x10)
            .cast::<i32>()
            .read_unaligned()
    };
    let current_station = unsafe { (CURRENT_STATION_ADDR as *const usize).read_volatile() };
    if station != current_station {
        return duration;
    }
    let Some(key) = (unsafe { current_entry_key() }) else {
        return duration;
    };
    let (entry_key, accepted_generation, rejected, sound_attempted) = {
        let entry = ENTRY.lock();
        (
            entry.key,
            entry.accepted_generation,
            entry.rejected,
            entry.sound_attempted,
        )
    };
    if entry_key != Some(key) {
        return duration;
    }
    let outcome = if accepted_generation == 0 {
        None
    } else {
        let requests = *MUSIC_REQUESTS.lock();
        let terminal = *LAST_TERMINAL_REQUEST.lock();
        entry_media_outcome(
            key,
            accepted_generation,
            CURRENT_MUSIC_GENERATION.load(Ordering::Acquire),
            &requests,
            terminal,
        )
    };
    let needs_sound_check = rejected
        || matches!(outcome, Some(MediaOutcome::Complete | MediaOutcome::Failed))
        || (sound_attempted
            && ((accepted_generation == 0 && duration <= 0)
                || matches!(outcome, Some(MediaOutcome::Interrupted))
                || (accepted_generation != 0 && outcome.is_none())));
    let sound_active = if needs_sound_check {
        let native_active: unsafe extern "thiscall" fn(*mut c_void) -> u8 =
            unsafe { core::mem::transmute(NATIVE_SOUND_ACTIVE_ADDR) };
        (unsafe { native_active(GLOBAL_MUSIC_SOUND_ADDR as *mut c_void) != 0 })
            || (unsafe { station_object_sound_active(station) })
    } else {
        false
    };
    let action = {
        let mut entry = ENTRY.lock();
        if entry.key != Some(key) {
            return duration;
        }
        entry.expiry(outcome, sound_active, duration)
    };
    match action {
        ExpiryAction::Native => duration,
        ExpiryAction::Hold => 0,
        ExpiryAction::Advance => {
            // A terminal record can outlive slot reuse. Preserve native
            // timing while another priority-7 graph is still active.
            let native_media_active: unsafe extern "C" fn(u32, u32) -> u8 =
                unsafe { core::mem::transmute(NATIVE_ACTIVE_QUERY_ADDR) };
            if unsafe { native_media_active(7, 1) } != 0 {
                return duration;
            }
            // Native next compares start + timer < now. A positive one-tick
            // timer keeps the original cursor-advance and callback semantics.
            unsafe {
                (station as *mut u8)
                    .add(0x10)
                    .cast::<i32>()
                    .write_unaligned(1)
            };
            1
        }
    }
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
const STATION_ACTIVE_SITE: usize = 0x008334E3;
const STATION_ACTIVE_ORIGINAL: &[u8] = &[0xE8, 0x68, 0xD2, 0xFF, 0xFF];
const TERMINAL_SITE: usize = 0x00831A6D;
const TERMINAL_ORIGINAL: &[u8] = &[0xC6, 0x85, 0x83, 0xFE, 0xFF, 0xFF, 0x00];
const EXPIRY_SITE: usize = 0x00834680;
const EXPIRY_ORIGINAL: &[u8] = &[0x8B, 0x45, 0x08, 0x83, 0x78, 0x10, 0x00];
const WORKER_RETIRE_SITE: usize = 0x00831B06;
const WORKER_RETIRE_ORIGINAL: &[u8] = &[0x83, 0xBD, 0xA4, 0xFE, 0xFF, 0xFF, 0x00];
const STATION_START_CALLS: [(usize, &[u8]); 2] = [
    (0x0083556C, &[0xE8, 0x4F, 0xDC, 0xFF, 0xFF]),
    (0x0083561D, &[0xE8, 0x9E, 0xDB, 0xFF, 0xFF]),
];
const RADIO_QUEUE_CALL: (usize, &[u8]) = (0x0083398D, &[0xE8, 0x2E, 0xC7, 0xFF, 0xFF]);
const RESTORE_START_CALL: (usize, &[u8]) = (0x00836EDD, &[0xE8, 0xDE, 0xC2, 0xFF, 0xFF]);
const SOUND_START_CALL: (usize, &[u8]) = (0x00833861, &[0xE8, 0xCA, 0x4F, 0x2A, 0x00]);
const LIST_REBUILD_CALLS: [(usize, &[u8]); 2] = [
    (0x00834909, &[0xE8, 0x52, 0x27, 0x00, 0x00]),
    (0x00835DCA, &[0xE8, 0x91, 0x12, 0x00, 0x00]),
];
const OUTER_ADVANCE_CALL: (usize, &[u8]) = (0x008346CC, &[0xE8, 0x1F, 0x73, 0x00, 0x00]);
const INNER_ADVANCE_CALLS: [(usize, &[u8]); 2] = [
    (0x00834A82, &[0xE8, 0x59, 0x7D, 0x00, 0x00]),
    (0x0083559F, &[0xE8, 0x3C, 0x72, 0x00, 0x00]),
];
const INNER_RESET_CALLS: [(usize, &[u8]); 3] = [
    (0x0083354D, &[0xE8, 0x5E, 0x92, 0x00, 0x00]),
    (0x00834744, &[0xE8, 0x67, 0x80, 0x00, 0x00]),
    (0x008355AE, &[0xE8, 0xFD, 0x71, 0x00, 0x00]),
];

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
        "native media priority argument",
        0x008300F0,
        &[0x83, 0x7D, 0x08, 0x09],
    )
    .verify()?;
    CodeSignature::new(
        "native active query ABI",
        NATIVE_ACTIVE_QUERY_ADDR,
        &[0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x14],
    )
    .verify()?;
    CodeSignature::new(
        "native station starter ABI",
        NATIVE_STATION_START_ADDR,
        &[0x55, 0x8B, 0xEC],
    )
    .verify()?;
    CodeSignature::new(
        "native radio queue ABI",
        NATIVE_RADIO_QUEUE_ADDR,
        &[0x55, 0x8B, 0xEC],
    )
    .verify()?;
    CodeSignature::new(
        "native worker retirement lock",
        0x00831B01,
        &[0xE8, 0x6A, 0xE9, 0xFF, 0xFF],
    )
    .verify()?;
    CodeSignature::new(
        "native global sound start",
        0x0083385A,
        &[0x6A, 0x00, 0xB9, 0xBC, 0xD5, 0x1D, 0x01],
    )
    .verify()?;
    CodeSignature::new(
        "station sound list end ABI",
        NATIVE_LIST_END_ADDR,
        &[0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08],
    )
    .verify()?;
    CodeSignature::new(
        "station sound list item ABI",
        NATIVE_LIST_ITEM_ADDR,
        &[0x55, 0x8B, 0xEC, 0x51, 0x89, 0x4D],
    )
    .verify()?;
    CodeSignature::new(
        "station sound list next ABI",
        NATIVE_LIST_NEXT_ADDR,
        &[0x55, 0x8B, 0xEC, 0x51, 0x89, 0x4D],
    )
    .verify()?;
    CodeSignature::new(
        "station sound list owner",
        0x00834AE2,
        &[0x8B, 0x55, 0x08, 0x83, 0xC2, 0x1C, 0x89, 0x55, 0xC0],
    )
    .verify()?;
    CodeSignature::new(
        "station first sound query",
        0x00834B30,
        &[
            0x8B, 0x4D, 0xC0, 0xE8, 0x88, 0xCA, 0xE4, 0xFF, 0x8B, 0x08, 0x83, 0xC1, 0x04,
        ],
    )
    .verify()?;
    CodeSignature::new(
        "station second sound query",
        0x00834D28,
        &[
            0x8B, 0x4D, 0xC0, 0xE8, 0x90, 0xC8, 0xE4, 0xFF, 0x8B, 0x08, 0x83, 0xC1, 0x10,
        ],
    )
    .verify()?;
    CodeSignature::new(
        "native active query return",
        0x008308AF,
        &[0x8A, 0x45, 0xFF, 0x8B, 0xE5, 0x5D, 0xC3],
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
        "station selected list node",
        0x0083C82A,
        &[
            0x83, 0x78, 0x08, 0x00, 0x74, 0x11, 0x8B, 0x4D, 0xFC, 0x8B, 0x49, 0x08,
        ],
    )
    .verify()?;
    CodeSignature::new(
        "station list node advance",
        0x0083BA02,
        &[
            0x8B, 0x4D, 0xFC, 0x8B, 0x49, 0x08, 0xE8, 0x63, 0xA6, 0xEE, 0xFF, 0x8B, 0x55, 0xFC,
            0x89, 0x42, 0x08,
        ],
    )
    .verify()?;
    CodeSignature::new(
        "station nested music selection",
        0x0083350F,
        &[
            0x8B, 0x0D, 0x2C, 0xD4, 0x1D, 0x01, 0x8B, 0x49, 0x04, 0xE8, 0x03, 0x93, 0x00, 0x00,
            0x89, 0x45, 0xC0,
        ],
    )
    .verify()?;
    CodeSignature::new(
        "station nested music cursor",
        0x0083391E,
        &[0x8B, 0x4D, 0xC0, 0xE8, 0xFA, 0x8E, 0x00, 0x00],
    )
    .verify()?;
    CodeSignature::new(
        "station active result ABI",
        0x008334DF,
        &[
            0x6A, 0x01, 0x6A, 0x07, 0xE8, 0x68, 0xD2, 0xFF, 0xFF, 0x83, 0xC4, 0x08, 0x0F, 0xB6,
            0xC8,
        ],
    )
    .verify()?;
    CodeSignature::new(
        "native station expiry continuation",
        0x00834687,
        &[0x0F, 0x8E, 0xC0, 0x03, 0x00, 0x00],
    )
    .verify()?;
    CodeSignature::new(
        "native station expiry timer",
        0x0083468D,
        &[
            0x8B, 0x4D, 0x08, 0x8B, 0x51, 0x0C, 0x8B, 0x45, 0x08, 0x03, 0x50, 0x10, 0x3B, 0x55,
            0xEC,
        ],
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
    CodeSignature::new(
        "native event status frame",
        0x00831978,
        &[
            0x8D, 0x85, 0x20, 0xFE, 0xFF, 0xFF, 0x50, 0x8D, 0x8D, 0x14, 0xFE, 0xFF, 0xFF, 0x51,
        ],
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
    for (address, original) in STATION_START_CALLS {
        transaction.apply_patch(call_patch(
            "radio_music_start_admission",
            address,
            original,
            station_start as *const () as usize,
            &[],
        )?)?;
    }
    for (address, original) in LIST_REBUILD_CALLS {
        transaction.apply_patch(call_patch(
            "radio_music_rebuild_epoch",
            address,
            original,
            rebuild_station_list as *const () as usize,
            &[],
        )?)?;
    }
    for (address, original) in INNER_ADVANCE_CALLS {
        transaction.apply_patch(call_patch(
            "radio_music_inner_advance_epoch",
            address,
            original,
            advance_inner_list as *const () as usize,
            &[],
        )?)?;
    }
    for (address, original) in INNER_RESET_CALLS {
        transaction.apply_patch(call_patch(
            "radio_music_inner_reset_epoch",
            address,
            original,
            reset_inner_list as *const () as usize,
            &[],
        )?)?;
    }
    transaction.apply_patch(call_patch(
        "radio_music_outer_advance_epoch",
        OUTER_ADVANCE_CALL.0,
        OUTER_ADVANCE_CALL.1,
        advance_outer_list as *const () as usize,
        &[],
    )?)?;
    transaction.apply_patch(call_patch(
        "radio_music_queue_attempt",
        RADIO_QUEUE_CALL.0,
        RADIO_QUEUE_CALL.1,
        radio_queue as *const () as usize,
        &[],
    )?)?;
    transaction.apply_patch(call_patch(
        "radio_music_sound_attempt",
        SOUND_START_CALL.0,
        SOUND_START_CALL.1,
        music_sound_start as *const () as usize,
        &[],
    )?)?;
    transaction.apply_patch(call_patch(
        "radio_music_load_epoch",
        RESTORE_START_CALL.0,
        RESTORE_START_CALL.1,
        restored_station_start as *const () as usize,
        &[],
    )?)?;
    transaction.apply_patch(call_patch(
        "radio_music_station_active",
        STATION_ACTIVE_SITE,
        STATION_ACTIVE_ORIGINAL,
        station_active_bridge as *const () as usize,
        &[],
    )?)?;
    transaction.apply_patch(call_patch(
        "radio_music_terminal_event",
        TERMINAL_SITE,
        TERMINAL_ORIGINAL,
        terminal_bridge as *const () as usize,
        &[0x90, 0x90],
    )?)?;
    transaction.apply_patch(call_patch(
        "radio_music_worker_retirement",
        WORKER_RETIRE_SITE,
        WORKER_RETIRE_ORIGINAL,
        worker_retirement_bridge as *const () as usize,
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
        "[RADIO] Music entry admission, media outcomes, and native playlist progression installed"
    );
    Ok(())
}

#[cfg(test)]
#[path = "music_tests.rs"]
mod tests;
