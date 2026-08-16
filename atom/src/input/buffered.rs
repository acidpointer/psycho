//! Compatibility-preserving DirectInput keyboard event mirroring.
//!
//! FNV configures a 32-event keyboard buffer but normal gameplay observes only
//! immediate current/previous snapshots. Atom drains the already-installed
//! xNVSE device wrapper once after the normal sample, publishes those ordered
//! events to the action resolver, and mirrors the newest 32 events for later
//! native menu/focus consumers.
//!
//! Only the live keyboard object's `GetDeviceData` slot is chained. Every
//! other COM method and every non-keyboard object remains untouched. The slot
//! hook captures the current capability rather than identifying xNVSE or any
//! other owner. Calls use a short `try_lock`; contention falls through to the
//! predecessor instead of blocking an input thread.

use core::ffi::c_void;
use core::mem::size_of;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, TryLockError};

use libpsycho::os::windows::{
    hook::pointer::{PointerSlotHookContainer, PointerSlotHookError},
    memory::{MemoryError, validate_memory_range},
};
use thiserror::Error;

const EVENT_CAPACITY: usize = 32;
const GET_DEVICE_DATA_VTABLE_INDEX: usize = 10;
const DIGDD_PEEK: u32 = 1;
const DI_OK: i32 = 0;
const DI_BUFFEROVERFLOW: i32 = 1;
const BATCH_WORDS: usize = 3 + EVENT_CAPACITY * 5;

type GetDeviceDataFn =
    unsafe extern "system" fn(*mut c_void, u32, *mut DirectInputEvent, *mut u32, u32) -> i32;

static GET_DEVICE_DATA_HOOK: PointerSlotHookContainer<GetDeviceDataFn> =
    PointerSlotHookContainer::new();
static KEYBOARD_DEVICE: AtomicUsize = AtomicUsize::new(0);
static MIRROR: Mutex<MirrorState> = Mutex::new(MirrorState::new());
static LATEST_BATCH: KeyboardBatchStore = KeyboardBatchStore::new();
static BUFFER_OVERFLOWS: AtomicU32 = AtomicU32::new(0);
static LOCK_CONTENTIONS: AtomicU32 = AtomicU32::new(0);
static NATIVE_FAILURES: AtomicU32 = AtomicU32::new(0);

/// DirectInput's i686 `DIDEVICEOBJECTDATA` event payload.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct DirectInputEvent {
    offset: u32,
    data: u32,
    timestamp_ms: u32,
    sequence: u32,
    application_data: u32,
}

impl DirectInputEvent {
    /// Construct an event for deterministic replay and input adapters.
    pub const fn new(
        offset: u32,
        data: u32,
        timestamp_ms: u32,
        sequence: u32,
        application_data: u32,
    ) -> Self {
        Self {
            offset,
            data,
            timestamp_ms,
            sequence,
            application_data,
        }
    }

    /// Return the DirectInput object offset (keyboard scancode for this device).
    pub const fn offset(self) -> u32 {
        self.offset
    }

    /// Return the native event data; its high bit denotes a key press.
    pub const fn data(self) -> u32 {
        self.data
    }

    /// Return DirectInput's millisecond event timestamp.
    pub const fn timestamp_ms(self) -> u32 {
        self.timestamp_ms
    }

    /// Return DirectInput's event sequence number.
    pub const fn sequence(self) -> u32 {
        self.sequence
    }

    /// Return caller-defined application data.
    pub const fn application_data(self) -> u32 {
        self.application_data
    }

    /// Return whether the event reports a pressed key.
    pub const fn pressed(self) -> bool {
        self.data & 0x80 != 0
    }
}

const _: [(); 20] = [(); size_of::<DirectInputEvent>()];

/// Ordered keyboard events captured after one native gameplay sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyboardEventBatch {
    frame_id: u32,
    overflowed: bool,
    len: u8,
    events: [DirectInputEvent; EVENT_CAPACITY],
}

impl KeyboardEventBatch {
    /// An empty batch used when buffered capture is unavailable.
    pub const EMPTY: Self = Self {
        frame_id: 0,
        overflowed: false,
        len: 0,
        events: [DirectInputEvent::new(0, 0, 0, 0, 0); EVENT_CAPACITY],
    };

    /// Construct a bounded ordered batch for deterministic replay.
    ///
    /// Events beyond the native 32-event capacity are discarded and mark the
    /// batch overflowed, matching FNV's configured DirectInput buffer bound.
    pub fn from_events(frame_id: u32, events: &[DirectInputEvent]) -> Self {
        let mut batch = Self {
            frame_id,
            overflowed: events.len() > EVENT_CAPACITY,
            ..Self::EMPTY
        };
        let retained = events.len().min(EVENT_CAPACITY);
        let start = events.len().saturating_sub(retained);
        batch.events[..retained].copy_from_slice(&events[start..]);
        batch.len = retained as u8;
        batch
    }

    /// Return the matching native input-frame sequence number.
    pub const fn frame_id(self) -> u32 {
        self.frame_id
    }

    /// Return the ordered events retained in this batch.
    pub fn events(&self) -> &[DirectInputEvent] {
        &self.events[..usize::from(self.len)]
    }

    /// Return whether DirectInput or Atom reported bounded-buffer overflow.
    pub const fn overflowed(self) -> bool {
        self.overflowed
    }

    pub(crate) const fn with_frame_id(mut self, frame_id: u32) -> Self {
        self.frame_id = frame_id;
        self
    }
}

/// Bounded health counters for the buffered keyboard bridge.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BufferedKeyboardDiagnostics {
    overflows: u32,
    lock_contentions: u32,
    native_failures: u32,
}

impl BufferedKeyboardDiagnostics {
    /// Return observed native or mirror-buffer overflow reports.
    pub const fn overflows(self) -> u32 {
        self.overflows
    }

    /// Return calls that safely bypassed mirroring due to lock contention.
    pub const fn lock_contentions(self) -> u32 {
        self.lock_contentions
    }

    /// Return failed native `GetDeviceData` capture calls.
    pub const fn native_failures(self) -> u32 {
        self.native_failures
    }
}

/// Failure to prepare the live keyboard device capability.
#[derive(Debug, Error)]
pub(crate) enum BufferedInstallError {
    /// The native owner or keyboard device is not available at DeferredInit.
    #[error("native keyboard device is unavailable at DeferredInit")]
    DeviceUnavailable,
    /// The object's vtable storage cannot be read safely.
    #[error(transparent)]
    Memory(#[from] MemoryError),
    /// The current `GetDeviceData` capability cannot be chained safely.
    #[error(transparent)]
    Hook(#[from] PointerSlotHookError),
}

/// Return the most recent ordered keyboard-event capture.
pub fn latest_keyboard_events() -> KeyboardEventBatch {
    LATEST_BATCH.load()
}

/// Return bounded keyboard-bridge health counters.
pub fn buffered_keyboard_diagnostics() -> BufferedKeyboardDiagnostics {
    BufferedKeyboardDiagnostics {
        overflows: BUFFER_OVERFLOWS.load(Ordering::Relaxed),
        lock_contentions: LOCK_CONTENTIONS.load(Ordering::Relaxed),
        native_failures: NATIVE_FAILURES.load(Ordering::Relaxed),
    }
}

/// Prepare the live keyboard object's current `GetDeviceData` slot.
///
/// # Safety
///
/// `input_owner` must be the process-lifetime FNV input owner. Its keyboard
/// pointer and vtable must remain alive after successful installation.
pub(crate) unsafe fn prepare(input_owner: *mut c_void) -> Result<(), BufferedInstallError> {
    if input_owner.is_null() {
        return Err(BufferedInstallError::DeviceUnavailable);
    }
    let keyboard_slot = unsafe { input_owner.cast::<u8>().add(0x2C).cast::<*mut c_void>() };
    validate_memory_range(keyboard_slot.cast(), size_of::<*mut c_void>())?;
    let keyboard = unsafe { core::ptr::read_volatile(keyboard_slot) };
    if keyboard.is_null() {
        return Err(BufferedInstallError::DeviceUnavailable);
    }
    validate_memory_range(keyboard.cast_const(), size_of::<*mut c_void>())?;
    let vtable = unsafe { core::ptr::read_volatile(keyboard.cast::<*mut c_void>()) };
    if vtable.is_null() {
        return Err(BufferedInstallError::DeviceUnavailable);
    }
    let method_slot = unsafe {
        vtable
            .cast::<*mut c_void>()
            .add(GET_DEVICE_DATA_VTABLE_INDEX)
    };
    unsafe {
        GET_DEVICE_DATA_HOOK.init(
            "Atom keyboard GetDeviceData mirror",
            method_slot,
            get_device_data_detour,
        )?;
    }
    KEYBOARD_DEVICE.store(keyboard as usize, Ordering::Release);
    Ok(())
}

pub(crate) fn hook() -> &'static PointerSlotHookContainer<GetDeviceDataFn> {
    &GET_DEVICE_DATA_HOOK
}

pub(crate) fn predecessor_address() -> Result<usize, PointerSlotHookError> {
    GET_DEVICE_DATA_HOOK.predecessor_address()
}

/// Drain one ordered batch after FNV/xNVSE have completed immediate sampling.
pub(crate) fn capture(frame_id: u32) -> KeyboardEventBatch {
    let Some(mut mirror) = try_mirror() else {
        LOCK_CONTENTIONS.fetch_add(1, Ordering::Relaxed);
        return KeyboardEventBatch::EMPTY;
    };
    let Some(predecessor) = GET_DEVICE_DATA_HOOK.original().ok() else {
        return KeyboardEventBatch::EMPTY;
    };
    let keyboard = KEYBOARD_DEVICE.load(Ordering::Acquire) as *mut c_void;
    if keyboard.is_null() {
        return KeyboardEventBatch::EMPTY;
    }

    let mut batch = KeyboardEventBatch {
        frame_id,
        ..KeyboardEventBatch::EMPTY
    };
    let mut count = EVENT_CAPACITY as u32;
    let result = unsafe {
        predecessor(
            keyboard,
            size_of::<DirectInputEvent>() as u32,
            batch.events.as_mut_ptr(),
            &mut count,
            0,
        )
    };
    if result < 0 {
        NATIVE_FAILURES.fetch_add(1, Ordering::Relaxed);
        return batch;
    }

    batch.len = count.min(EVENT_CAPACITY as u32) as u8;
    batch.overflowed = result == DI_BUFFEROVERFLOW || count > EVENT_CAPACITY as u32;
    if batch.overflowed {
        BUFFER_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
    }
    let previously_overflowed = mirror.overflowed;
    mirror.append(batch.events());
    mirror.overflowed |= batch.overflowed;
    if mirror.overflowed && !previously_overflowed && !batch.overflowed {
        BUFFER_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
    }
    batch
}

pub(crate) fn publish(batch: KeyboardEventBatch) {
    LATEST_BATCH.publish(batch);
}

unsafe extern "system" fn get_device_data_detour(
    device: *mut c_void,
    data_size: u32,
    output: *mut DirectInputEvent,
    count: *mut u32,
    flags: u32,
) -> i32 {
    let predecessor = match GET_DEVICE_DATA_HOOK.original() {
        Ok(predecessor) => predecessor,
        Err(_) => return DI_OK,
    };
    if device as usize != KEYBOARD_DEVICE.load(Ordering::Acquire)
        || data_size as usize != size_of::<DirectInputEvent>()
        || count.is_null()
    {
        return unsafe { predecessor(device, data_size, output, count, flags) };
    }

    let Some(mut mirror) = try_mirror() else {
        LOCK_CONTENTIONS.fetch_add(1, Ordering::Relaxed);
        return unsafe { predecessor(device, data_size, output, count, flags) };
    };
    let requested = unsafe { core::ptr::read(count) };
    if flags & DIGDD_PEEK != 0 {
        unsafe { peek_events(predecessor, device, output, count, requested, &mut mirror) }
    } else {
        unsafe {
            consume_events(
                predecessor,
                device,
                output,
                count,
                requested,
                flags,
                &mut mirror,
            )
        }
    }
}

unsafe fn peek_events(
    predecessor: GetDeviceDataFn,
    device: *mut c_void,
    output: *mut DirectInputEvent,
    count: *mut u32,
    requested: u32,
    mirror: &mut MirrorState,
) -> i32 {
    if output.is_null() {
        let mut native_count = requested.saturating_sub(mirror.len as u32);
        let result = unsafe {
            predecessor(
                device,
                size_of::<DirectInputEvent>() as u32,
                core::ptr::null_mut(),
                &mut native_count,
                DIGDD_PEEK,
            )
        };
        unsafe {
            core::ptr::write(
                count,
                (mirror.len as u32)
                    .saturating_add(native_count)
                    .min(requested),
            );
        }
        return merged_result(result, mirror.overflowed);
    }

    // xNVSE cannot safely service non-NULL DIGDD_PEEK while its injected queue
    // is nonempty. Drain into Atom's mirror first, then return a non-consuming
    // copy. This preserves both the caller's peek contract and xNVSE events.
    fill_from_predecessor(predecessor, device, mirror);
    let copied = requested.min(mirror.len as u32) as usize;
    unsafe { core::ptr::copy_nonoverlapping(mirror.events.as_ptr(), output, copied) };
    unsafe { core::ptr::write(count, copied as u32) };
    merged_result(DI_OK, mirror.overflowed)
}

unsafe fn consume_events(
    predecessor: GetDeviceDataFn,
    device: *mut c_void,
    output: *mut DirectInputEvent,
    count: *mut u32,
    requested: u32,
    flags: u32,
    mirror: &mut MirrorState,
) -> i32 {
    let mirrored = requested.min(mirror.len as u32) as usize;
    if !output.is_null() && mirrored != 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(mirror.events.as_ptr(), output, mirrored);
        }
    }
    mirror.consume(mirrored);

    let mut native_count = requested.saturating_sub(mirrored as u32);
    let native_output = if output.is_null() {
        core::ptr::null_mut()
    } else {
        unsafe { output.add(mirrored) }
    };
    let result = unsafe {
        predecessor(
            device,
            size_of::<DirectInputEvent>() as u32,
            native_output,
            &mut native_count,
            flags,
        )
    };
    unsafe {
        core::ptr::write(count, (mirrored as u32).saturating_add(native_count));
    }
    let overflowed = mirror.overflowed;
    if mirror.len == 0 && flags & DIGDD_PEEK == 0 {
        mirror.overflowed = false;
    }
    merged_result(result, overflowed)
}

fn fill_from_predecessor(
    predecessor: GetDeviceDataFn,
    device: *mut c_void,
    mirror: &mut MirrorState,
) {
    let remaining = EVENT_CAPACITY.saturating_sub(mirror.len);
    if remaining == 0 {
        return;
    }
    let mut events = [DirectInputEvent::new(0, 0, 0, 0, 0); EVENT_CAPACITY];
    let mut count = remaining as u32;
    let result = unsafe {
        predecessor(
            device,
            size_of::<DirectInputEvent>() as u32,
            events.as_mut_ptr(),
            &mut count,
            0,
        )
    };
    if result < 0 {
        NATIVE_FAILURES.fetch_add(1, Ordering::Relaxed);
        return;
    }
    mirror.append(&events[..count.min(remaining as u32) as usize]);
    if result == DI_BUFFEROVERFLOW {
        mirror.overflowed = true;
        BUFFER_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
    }
}

fn merged_result(native: i32, mirrored_overflow: bool) -> i32 {
    if native < 0 {
        native
    } else if native == DI_BUFFEROVERFLOW || mirrored_overflow {
        DI_BUFFEROVERFLOW
    } else {
        DI_OK
    }
}

fn try_mirror() -> Option<MutexGuard<'static, MirrorState>> {
    match MIRROR.try_lock() {
        Ok(guard) => Some(guard),
        Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
        Err(TryLockError::WouldBlock) => None,
    }
}

struct MirrorState {
    events: [DirectInputEvent; EVENT_CAPACITY],
    len: usize,
    overflowed: bool,
}

impl MirrorState {
    const fn new() -> Self {
        Self {
            events: [DirectInputEvent::new(0, 0, 0, 0, 0); EVENT_CAPACITY],
            len: 0,
            overflowed: false,
        }
    }

    fn append(&mut self, events: &[DirectInputEvent]) {
        for event in events {
            if self.len == EVENT_CAPACITY {
                self.events.copy_within(1..EVENT_CAPACITY, 0);
                self.len -= 1;
                self.overflowed = true;
            }
            self.events[self.len] = *event;
            self.len += 1;
        }
    }

    fn consume(&mut self, count: usize) {
        let count = count.min(self.len);
        self.events.copy_within(count..self.len, 0);
        self.len -= count;
    }
}

struct KeyboardBatchStore {
    sequence: AtomicU32,
    words: [AtomicU32; BATCH_WORDS],
}

impl KeyboardBatchStore {
    const fn new() -> Self {
        Self {
            sequence: AtomicU32::new(0),
            words: [const { AtomicU32::new(0) }; BATCH_WORDS],
        }
    }

    fn publish(&self, batch: KeyboardEventBatch) {
        let mut words = [0; BATCH_WORDS];
        words[0] = batch.frame_id;
        words[1] = u32::from(batch.overflowed);
        words[2] = u32::from(batch.len);
        for (index, event) in batch.events.into_iter().enumerate() {
            let base = 3 + index * 5;
            words[base] = event.offset;
            words[base + 1] = event.data;
            words[base + 2] = event.timestamp_ms;
            words[base + 3] = event.sequence;
            words[base + 4] = event.application_data;
        }
        self.sequence.fetch_add(1, Ordering::AcqRel);
        for (target, value) in self.words.iter().zip(words) {
            target.store(value, Ordering::Relaxed);
        }
        self.sequence.fetch_add(1, Ordering::Release);
    }

    fn load(&self) -> KeyboardEventBatch {
        loop {
            let before = self.sequence.load(Ordering::Acquire);
            if before & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }
            let mut words = [0; BATCH_WORDS];
            for (target, source) in words.iter_mut().zip(&self.words) {
                *target = source.load(Ordering::Relaxed);
            }
            if before != self.sequence.load(Ordering::Acquire) {
                continue;
            }
            let mut batch = KeyboardEventBatch {
                frame_id: words[0],
                overflowed: words[1] != 0,
                len: words[2].min(EVENT_CAPACITY as u32) as u8,
                ..KeyboardEventBatch::EMPTY
            };
            for (index, event) in batch.events.iter_mut().enumerate() {
                let base = 3 + index * 5;
                *event = DirectInputEvent::new(
                    words[base],
                    words[base + 1],
                    words[base + 2],
                    words[base + 3],
                    words[base + 4],
                );
            }
            return batch;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static NATIVE_EVENTS: Mutex<Vec<DirectInputEvent>> = Mutex::new(Vec::new());
    static LAST_FLAGS: AtomicU32 = AtomicU32::new(u32::MAX);

    unsafe extern "system" fn queued_predecessor(
        _device: *mut c_void,
        data_size: u32,
        output: *mut DirectInputEvent,
        count: *mut u32,
        flags: u32,
    ) -> i32 {
        assert_eq!(data_size as usize, size_of::<DirectInputEvent>());
        assert!(!count.is_null());
        LAST_FLAGS.store(flags, Ordering::Relaxed);

        let requested = unsafe { core::ptr::read(count) } as usize;
        let mut events = NATIVE_EVENTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let copied = requested.min(events.len());
        if !output.is_null() {
            unsafe { core::ptr::copy_nonoverlapping(events.as_ptr(), output, copied) };
        }
        if flags & DIGDD_PEEK == 0 {
            events.drain(..copied);
        }
        unsafe { core::ptr::write(count, copied as u32) };
        DI_OK
    }

    #[test]
    fn non_null_peek_drains_the_predecessor_once_without_consuming_the_mirror() {
        let event = |sequence| DirectInputEvent::new(sequence, 0x80, sequence, sequence, 0);
        let mut mirror = MirrorState::new();
        mirror.append(&[event(1)]);
        *NATIVE_EVENTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = vec![event(2), event(3)];

        let mut peeked = [DirectInputEvent::default(); 3];
        let mut count = peeked.len() as u32;
        let result = unsafe {
            peek_events(
                queued_predecessor,
                core::ptr::dangling_mut(),
                peeked.as_mut_ptr(),
                &mut count,
                count,
                &mut mirror,
            )
        };
        assert_eq!(result, DI_OK);
        assert_eq!(LAST_FLAGS.load(Ordering::Relaxed), 0);
        assert_eq!(count, 3);
        assert_eq!(peeked.map(DirectInputEvent::sequence), [1, 2, 3]);
        assert_eq!(mirror.len, 3);
        assert!(
            NATIVE_EVENTS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty()
        );

        let mut consumed = [DirectInputEvent::default(); 3];
        let mut count = consumed.len() as u32;
        let result = unsafe {
            consume_events(
                queued_predecessor,
                core::ptr::dangling_mut(),
                consumed.as_mut_ptr(),
                &mut count,
                count,
                0,
                &mut mirror,
            )
        };
        assert_eq!(result, DI_OK);
        assert_eq!(count, 3);
        assert_eq!(consumed.map(DirectInputEvent::sequence), [1, 2, 3]);
        assert_eq!(mirror.len, 0);
    }
}
