//! Allocator-independent queued-task dispatch and release lifetime guards.

use std::{
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicUsize, Ordering},
};

use anyhow::Context;
use windows::Win32::System::Memory::{
    MEM_COMMIT, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_GUARD, PAGE_NOACCESS,
};

use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::winapi::{get_current_thread_id, virtual_query},
};

use crate::mods::{
    diagnostics,
    heap_replacer::{self, TaskPoolPinResult, TaskPoolState},
};

use super::{
    patching, statics,
    types::{TaskCallbackFn, TaskReleaseFn},
};

const REFCOUNT_OFFSET: usize = 0x08;
const TASK_CALLBACK_OFFSET: usize = 0x1C;
const BASE_NIREF_VTABLE: usize = 0x0101_DCE4;
const QUEUED_TEXTURE_VTABLE: usize = 0x0101_6788;
const DEAD_TASK_REFCOUNT: i32 = -0x7000_0000;
const TRACE_CAPACITY: usize = 256;

const TRACE_PIN: usize = 1;
const TRACE_DISPATCH: usize = 2;
const TRACE_RELEASE: usize = 3;
const TRACE_REJECT: usize = 4;

static RELEASE_ENABLED: AtomicBool = AtomicBool::new(false);
static DISPATCH_ENABLED: AtomicBool = AtomicBool::new(false);
static TRACE_ENABLED: AtomicBool = AtomicBool::new(false);
static PREVIOUS_TASK_RELEASE: AtomicUsize = AtomicUsize::new(0x0044_DD60);

static DISPATCH_ATTEMPTS: AtomicU32 = AtomicU32::new(0);
static DISPATCH_CALLS: AtomicU32 = AtomicU32::new(0);
static PIN_FAILURES: AtomicU32 = AtomicU32::new(0);
static INVALID_DISPATCHES: AtomicU32 = AtomicU32::new(0);
static BASE_VTABLE_REJECTIONS: AtomicU32 = AtomicU32::new(0);
static QUEUED_TEXTURE_FINALS: AtomicU32 = AtomicU32::new(0);
static RELEASE_GUARDS: AtomicU32 = AtomicU32::new(0);
static TOMBSTONES: AtomicU32 = AtomicU32::new(0);
static TRACE_DUMPS: AtomicU32 = AtomicU32::new(0);

pub(super) struct DiagnosticSnapshot {
    pub release_enabled: bool,
    pub dispatch_enabled: bool,
    pub release_predecessor: usize,
    pub dispatch_attempts: u64,
    pub dispatch_calls: u64,
    pub pin_failures: u64,
    pub invalid_dispatches: u64,
    pub base_vtable_rejections: u64,
    pub queued_texture_finals: u64,
    pub release_guards: u64,
    pub tombstones: u64,
    pub trace_dumps: u64,
}

pub(super) fn diagnostic_snapshot() -> DiagnosticSnapshot {
    DiagnosticSnapshot {
        release_enabled: RELEASE_ENABLED.load(Ordering::Acquire),
        dispatch_enabled: DISPATCH_ENABLED.load(Ordering::Acquire),
        release_predecessor: PREVIOUS_TASK_RELEASE.load(Ordering::Acquire),
        dispatch_attempts: u64::from(DISPATCH_ATTEMPTS.load(Ordering::Relaxed)),
        dispatch_calls: u64::from(DISPATCH_CALLS.load(Ordering::Relaxed)),
        pin_failures: u64::from(PIN_FAILURES.load(Ordering::Relaxed)),
        invalid_dispatches: u64::from(INVALID_DISPATCHES.load(Ordering::Relaxed)),
        base_vtable_rejections: u64::from(BASE_VTABLE_REJECTIONS.load(Ordering::Relaxed)),
        queued_texture_finals: u64::from(QUEUED_TEXTURE_FINALS.load(Ordering::Relaxed)),
        release_guards: u64::from(RELEASE_GUARDS.load(Ordering::Relaxed)),
        tombstones: u64::from(TOMBSTONES.load(Ordering::Relaxed)),
        trace_dumps: u64::from(TRACE_DUMPS.load(Ordering::Relaxed)),
    }
}

pub(super) fn install(trace_enabled: bool) -> anyhow::Result<()> {
    install_release_chain()?;
    RELEASE_ENABLED.store(true, Ordering::Release);
    TRACE_ENABLED.store(trace_enabled, Ordering::Release);

    let replacement = dispatch_replacement(checked_dispatch as *mut c_void);
    if let Err(err) = unsafe {
        patching::replace_block(
            statics::TASK_DISPATCH_ADDR,
            &statics::TASK_DISPATCH_BYTES,
            &replacement,
        )
    } {
        log::warn!("[QUEUED_TASK] Dispatch guard conflict: {:#}", err);
    } else {
        DISPATCH_ENABLED.store(true, Ordering::Release);
    }

    log::info!(
        "[QUEUED_TASK] Lifetime guard active release={} dispatch={} predecessor=0x{:08X} trace={}",
        RELEASE_ENABLED.load(Ordering::Acquire),
        DISPATCH_ENABLED.load(Ordering::Acquire),
        PREVIOUS_TASK_RELEASE.load(Ordering::Acquire),
        trace_enabled,
    );
    Ok(())
}

fn install_release_chain() -> anyhow::Result<()> {
    let current = unsafe { patching::relative_call_target(statics::TASK_HOLDER_RELEASE_CALL_ADDR) }
        .context("read queued-task holder release target")?;
    if current == holder_release_entry as *const () as usize {
        return Ok(());
    }
    anyhow::ensure!(
        is_executable(current),
        "holder release predecessor 0x{current:08X} is not executable"
    );
    PREVIOUS_TASK_RELEASE.store(current, Ordering::Release);
    let redirected = unsafe {
        patching::redirect_relative_call(
            statics::TASK_HOLDER_RELEASE_CALL_ADDR,
            holder_release_entry as *mut c_void,
        )
    }
    .context("redirect queued-task holder release call")?;
    anyhow::ensure!(
        redirected == current,
        "holder release target changed during install"
    );
    Ok(())
}

fn dispatch_replacement(target: *mut c_void) -> [u8; 13] {
    let displacement = (target as usize).wrapping_sub(statics::TASK_DISPATCH_ADDR + 8) as i32;
    let mut bytes = [0x90u8; 13];
    bytes[0..3].copy_from_slice(&[0x8B, 0x4D, 0xC8]);
    bytes[3] = 0xE8;
    bytes[4..8].copy_from_slice(&displacement.to_le_bytes());
    bytes
}

unsafe extern "thiscall" fn checked_dispatch(task: *mut c_void, argument: usize) {
    increment_main_thread(&DISPATCH_ATTEMPTS);
    let task_addr = task as usize;
    if task_addr == 0 || !task_addr.is_multiple_of(std::mem::align_of::<AtomicI32>()) {
        reject_dispatch("bad-task-pointer", task, 0, 0, 0);
        return;
    }

    let before = match heap_replacer::pin_task_refcount(task) {
        TaskPoolPinResult::Pinned(value) => value,
        TaskPoolPinResult::Rejected(observed) => {
            increment_main_thread(&PIN_FAILURES);
            reject_dispatch("free-or-dead-pool-task", task, 0, 0, observed);
            return;
        }
        TaskPoolPinResult::NotOwned => {
            if !is_readable(task_addr, REFCOUNT_OFFSET + 4) {
                reject_dispatch("unreadable-task", task, 0, 0, 0);
                return;
            }
            let refcount =
                unsafe { &*((task as *mut u8).add(REFCOUNT_OFFSET) as *const AtomicI32) };
            match pin_positive(refcount) {
                Some(value) => value,
                None => {
                    increment_main_thread(&PIN_FAILURES);
                    let observed = refcount.load(Ordering::Acquire);
                    reject_dispatch("non-positive-refcount", task, 0, 0, observed);
                    return;
                }
            }
        }
    };
    trace_record(
        TRACE_PIN,
        task_addr,
        read_vtable(task),
        before,
        before + 1,
        0,
        statics::TASK_DISPATCH_ADDR,
    );

    let vtable = read_vtable(task);
    if vtable == BASE_NIREF_VTABLE {
        increment_main_thread(&BASE_VTABLE_REJECTIONS);
        reject_dispatch("base-niref-vtable", task, vtable, 0, before + 1);
        release_dispatch_pin(task);
        return;
    }
    let Some(callback) = read_callback(vtable, TASK_CALLBACK_OFFSET) else {
        reject_dispatch("invalid-callback", task, vtable, 0, before + 1);
        release_dispatch_pin(task);
        return;
    };

    trace_record(
        TRACE_DISPATCH,
        task_addr,
        vtable,
        before + 1,
        before + 1,
        callback,
        statics::TASK_DISPATCH_ADDR,
    );
    increment_main_thread(&DISPATCH_CALLS);
    let Ok(callback_fn) = (unsafe { FnPtr::<TaskCallbackFn>::from_raw(callback as *mut c_void) })
    else {
        release_dispatch_pin(task);
        return;
    };
    unsafe { callback_fn.as_fn()(task, argument) };
    release_dispatch_pin(task);
}

fn pin_positive(refcount: &AtomicI32) -> Option<i32> {
    let mut current = refcount.load(Ordering::Acquire);
    loop {
        if current <= 0 || current == i32::MAX {
            return None;
        }
        match refcount.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Some(current),
            Err(observed) => current = observed,
        }
    }
}

#[unsafe(naked)]
unsafe extern "fastcall" fn holder_release_entry(_task: *mut c_void) {
    core::arch::naked_asm!(
        "mov edx, [ebp + 4]",
        "jmp {}",
        sym checked_release_body,
    );
}

fn release_dispatch_pin(task: *mut c_void) {
    // The pool-locked pin made this reference positive before dispatch, and
    // the dequeued local holder owns a separate reference until after this
    // callback returns. Release only the pin here; the holder's later release
    // still passes through the full corruption guard.
    call_previous_release(task);
}

unsafe extern "fastcall" fn checked_release_body(task: *mut c_void, caller: usize) {
    if !RELEASE_ENABLED.load(Ordering::Acquire) {
        call_previous_release(task);
        return;
    }

    let task_addr = task as usize;
    if task_addr == 0 || !is_readable(task_addr, REFCOUNT_OFFSET + 4) {
        guard_release("bad-pointer", task, 0, 0, 0);
        return;
    }

    let vtable = read_vtable(task);
    let refcount =
        unsafe { ptr::read_unaligned((task as *const u8).add(REFCOUNT_OFFSET) as *const i32) };
    trace_record(
        TRACE_RELEASE,
        task_addr,
        vtable,
        refcount,
        refcount.saturating_sub(1),
        0,
        caller,
    );

    if heap_replacer::task_pool_state(task) == TaskPoolState::Free {
        tombstone(task);
        guard_release("gheap-free-cell", task, vtable, 0, refcount);
        return;
    }
    if refcount <= 0 {
        tombstone(task);
        guard_release("non-positive-refcount", task, vtable, 0, refcount);
        return;
    }

    if vtable == QUEUED_TEXTURE_VTABLE && refcount == 1 {
        QUEUED_TEXTURE_FINALS.fetch_add(1, Ordering::Relaxed);
    }
    if refcount == 1 {
        let Some(destructor) = read_callback(vtable, 0) else {
            guard_release("invalid-destructor", task, vtable, 0, refcount);
            return;
        };
        if destructor == 0 {
            guard_release("null-destructor", task, vtable, destructor, refcount);
            return;
        }
    }

    call_previous_release(task);
}

fn call_previous_release(task: *mut c_void) {
    let target = PREVIOUS_TASK_RELEASE.load(Ordering::Acquire);
    if target == 0 || target == holder_release_entry as *const () as usize {
        guard_release(
            "invalid-release-predecessor",
            task,
            read_vtable(task),
            target,
            0,
        );
        return;
    }
    let Ok(previous) = (unsafe { FnPtr::<TaskReleaseFn>::from_raw(target as *mut c_void) }) else {
        return;
    };
    unsafe { previous.as_fn()(task) };
}

fn tombstone(task: *mut c_void) {
    let dead_vtable = (&DEAD_TASK_VTABLE as *const DeadTaskVTable) as usize;
    let Some(info) = heap_replacer::tombstone_free_task(task, dead_vtable, DEAD_TASK_REFCOUNT)
    else {
        return;
    };
    let n = TOMBSTONES.fetch_add(1, Ordering::Relaxed) + 1;
    if diagnostics::should_log_power_of_two(u64::from(n)) {
        log::warn!(
            "[QUEUED_TASK] tombstoned free task total={} task=0x{:08X} pool={} item={} cell={}",
            n,
            task as usize,
            info.pool_index,
            info.item_size,
            info.cell_index,
        );
    }
}

fn reject_dispatch(
    reason: &'static str,
    task: *mut c_void,
    vtable: usize,
    callback: usize,
    refcount: i32,
) {
    let n = increment_main_thread(&INVALID_DISPATCHES);
    trace_record(
        TRACE_REJECT,
        task as usize,
        vtable,
        refcount,
        refcount,
        callback,
        statics::TASK_DISPATCH_ADDR,
    );
    if diagnostics::should_log_power_of_two(u64::from(n)) {
        log::warn!(
            "[QUEUED_TASK] dispatch rejected reason={} total={} task=0x{:08X} vt=0x{:08X} callback=0x{:08X} rc={}",
            reason,
            n,
            task as usize,
            vtable,
            callback,
            refcount,
        );
        trace_dump(task as usize);
    }
}

fn guard_release(
    reason: &'static str,
    task: *mut c_void,
    vtable: usize,
    destructor: usize,
    refcount: i32,
) {
    let n = RELEASE_GUARDS.fetch_add(1, Ordering::Relaxed) + 1;
    if diagnostics::should_log_power_of_two(u64::from(n)) {
        log::warn!(
            "[QUEUED_TASK] release guarded reason={} total={} task=0x{:08X} vt=0x{:08X} dtor=0x{:08X} rc={}",
            reason,
            n,
            task as usize,
            vtable,
            destructor,
            refcount,
        );
    }
}

fn read_vtable(task: *mut c_void) -> usize {
    if task.is_null() {
        return 0;
    }
    unsafe { ptr::read_unaligned(task as *const usize) }
}

fn read_callback(vtable: usize, offset: usize) -> Option<usize> {
    if !is_readable(vtable, offset + 4) {
        return None;
    }
    let callback = unsafe { ptr::read_unaligned((vtable + offset) as *const usize) };
    if !is_executable(callback) {
        return None;
    }
    Some(callback)
}

fn is_readable(address: usize, len: usize) -> bool {
    if address < 0x10000 {
        return false;
    }
    let Ok(info) = virtual_query(address as *mut c_void) else {
        return false;
    };
    if info.state != MEM_COMMIT.0 || info.protect == PAGE_NOACCESS {
        return false;
    }
    if (info.protect.0 & PAGE_GUARD.0) != 0 {
        return false;
    }
    address.saturating_add(len) <= (info.base_address as usize).saturating_add(info.region_size)
}

fn is_executable(address: usize) -> bool {
    if address < 0x10000 {
        return false;
    }
    let Ok(info) = virtual_query(address as *mut c_void) else {
        return false;
    };
    if info.state != MEM_COMMIT.0 || (info.protect.0 & PAGE_GUARD.0) != 0 {
        return false;
    }
    matches!(
        info.protect,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}

#[repr(C)]
struct DeadTaskVTable {
    dtor: unsafe extern "thiscall" fn(*mut c_void, u32) -> *mut c_void,
    slots: [unsafe extern "thiscall" fn(*mut c_void) -> usize; 6],
    callback: unsafe extern "thiscall" fn(*mut c_void, usize) -> usize,
    tail: unsafe extern "thiscall" fn(*mut c_void) -> usize,
}

unsafe extern "thiscall" fn dead_dtor(this: *mut c_void, _flags: u32) -> *mut c_void {
    this
}

unsafe extern "thiscall" fn dead_no_arg(_this: *mut c_void) -> usize {
    0
}

unsafe extern "thiscall" fn dead_callback(_this: *mut c_void, _arg: usize) -> usize {
    0
}

static DEAD_TASK_VTABLE: DeadTaskVTable = DeadTaskVTable {
    dtor: dead_dtor,
    slots: [dead_no_arg; 6],
    callback: dead_callback,
    tail: dead_no_arg,
};

struct TraceRecord {
    sequence: AtomicUsize,
    task: AtomicUsize,
    vtable: AtomicUsize,
    before: AtomicI32,
    after: AtomicI32,
    thread: AtomicUsize,
    operation: AtomicUsize,
    target: AtomicUsize,
    caller: AtomicUsize,
}

impl TraceRecord {
    const fn new() -> Self {
        Self {
            sequence: AtomicUsize::new(0),
            task: AtomicUsize::new(0),
            vtable: AtomicUsize::new(0),
            before: AtomicI32::new(0),
            after: AtomicI32::new(0),
            thread: AtomicUsize::new(0),
            operation: AtomicUsize::new(0),
            target: AtomicUsize::new(0),
            caller: AtomicUsize::new(0),
        }
    }
}

static TRACE_SEQUENCE: AtomicUsize = AtomicUsize::new(1);
static TRACE: [TraceRecord; TRACE_CAPACITY] = [const { TraceRecord::new() }; TRACE_CAPACITY];

fn trace_record(
    operation: usize,
    task: usize,
    vtable: usize,
    before: i32,
    after: i32,
    target: usize,
    caller: usize,
) {
    if !TRACE_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let sequence = TRACE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let record = &TRACE[sequence & (TRACE_CAPACITY - 1)];
    record.sequence.store(0, Ordering::Relaxed);
    record.task.store(task, Ordering::Relaxed);
    record.vtable.store(vtable, Ordering::Relaxed);
    record.before.store(before, Ordering::Relaxed);
    record.after.store(after, Ordering::Relaxed);
    record
        .thread
        .store(get_current_thread_id() as usize, Ordering::Relaxed);
    record.operation.store(operation, Ordering::Relaxed);
    record.target.store(target, Ordering::Relaxed);
    record.caller.store(caller, Ordering::Relaxed);
    record.sequence.store(sequence, Ordering::Release);
}

fn trace_dump(task: usize) {
    if !TRACE_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    increment_main_thread(&TRACE_DUMPS);
    let newest = TRACE_SEQUENCE.load(Ordering::Acquire);
    let oldest = newest.saturating_sub(TRACE_CAPACITY);
    for sequence in (oldest..newest).rev() {
        let record = &TRACE[sequence & (TRACE_CAPACITY - 1)];
        if record.sequence.load(Ordering::Acquire) != sequence {
            continue;
        }
        let record_task = record.task.load(Ordering::Relaxed);
        let operation = record.operation.load(Ordering::Relaxed);
        let vtable = record.vtable.load(Ordering::Relaxed);
        let before = record.before.load(Ordering::Relaxed);
        let after = record.after.load(Ordering::Relaxed);
        let thread = record.thread.load(Ordering::Relaxed);
        let target = record.target.load(Ordering::Relaxed);
        let caller = record.caller.load(Ordering::Relaxed);
        if record.sequence.load(Ordering::Acquire) != sequence || record_task != task {
            continue;
        }
        log::warn!(
            "[QUEUED_TASK_TRACE] seq={} op={} task=0x{:08X} vt=0x{:08X} rc={}->{} tid={} target=0x{:08X} caller=0x{:08X}",
            sequence,
            operation,
            task,
            vtable,
            before,
            after,
            thread,
            target,
            caller,
        );
    }
}

#[inline]
fn increment_main_thread(counter: &AtomicU32) -> u32 {
    let next = counter.load(Ordering::Relaxed).wrapping_add(1);
    counter.store(next, Ordering::Relaxed);
    next
}
