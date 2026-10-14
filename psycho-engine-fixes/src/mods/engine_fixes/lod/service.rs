//! Yield the ordinary native attachment drain between complete callbacks.
//!
//! Native queues and strong holders retain ownership. A fixed live-frame chain
//! identifies the ordinary service and supplies its existing QPC allowance.
//! Blocking, modified or unreadable contexts drain fully. The first acquisition
//! always runs; expiration alone never discards a queued task. The three patches
//! install atomically, retaining native SEH cleanup and the incomplete AL result.

use super::native::{Site, word};
use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::{
        hook::transaction::ModificationTransaction,
        patch::OwnedCodePatch,
        winapi::{query_performance_counter, virtual_query},
    },
};
use std::{
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

static BUDGET: AtomicBool = AtomicBool::new(false);
static INSTALLED: AtomicBool = AtomicBool::new(false);
static YIELDS: AtomicU64 = AtomicU64::new(0);
static UNSUPPORTED: AtomicU64 = AtomicU64::new(0);
static PENDING_SAMPLE: AtomicU64 = AtomicU64::new(0);
static PENDING_SAMPLED: AtomicBool = AtomicBool::new(false);
static FIRST: Site = Site::new("lod_attach_first", 0x448C53, &[0xE8, 0x28, 6, 0, 0], true);
static NEXT: Site = Site::new("lod_attach_next", 0x448C86, &[0xE8, 0xF5, 5, 0, 0], true);
static RESULT: OwnedCodePatch = OwnedCodePatch::new(
    "lod_attach_result",
    0x448C8D,
    &[0xC6, 0x45, 0xEF, 1],
    &[0x90; 4],
);
type PopFn = unsafe extern "thiscall" fn(*mut c_void, *mut *mut c_void) -> u8;

/// Copied ordinary native deadline; it retains no live frame or object pointer.
#[derive(Clone, Copy)]
pub(super) struct Deadline {
    start: i64,
    allowance: i64,
}
impl Deadline {
    /// Native expiration is strict greater-than. Bad clock/arithmetic falls back.
    pub(super) fn expired(self, now: Option<i64>) -> Option<bool> {
        let now = now?;
        if self.start < 0 || self.allowance < 0 || now < self.start {
            return None;
        }
        Some(now.checked_sub(self.start)? > self.allowance)
    }
    /// Admit bounded optional work only while the native deadline is valid.
    pub(super) fn has_time(self) -> bool {
        self.expired(query_performance_counter().ok()) == Some(false)
    }
}

/// Install the shared service transaction; budgeting can be disabled independently.
pub(super) fn install(budget: bool) -> anyhow::Result<()> {
    unsafe {
        super::super::patching::verify_bytes(0x448C50, &[0x8B, 0x49, 0x1C])?;
        super::super::patching::verify_bytes(0x448C83, &[0x8B, 0x49, 0x1C])?;
        super::super::patching::verify_bytes(
            0x448C91,
            &[0xC7, 0x45, 0xFC, 0xFF, 0xFF, 0xFF, 0xFF],
        )?;
    }
    let mut tx = ModificationTransaction::new();
    FIRST.install(&mut tx, first as *const () as usize)?;
    NEXT.install(&mut tx, next as *const () as usize)?;
    tx.apply_patch(&RESULT)?;
    tx.commit();
    BUDGET.store(budget, Ordering::Release);
    INSTALLED.store(true, Ordering::Release);
    Ok(())
}

#[unsafe(naked)]
unsafe extern "thiscall" fn first(_: *mut c_void, _: *mut *mut c_void) -> u8 {
    core::arch::naked_asm!("mov edx, ebp", "jmp {}", sym first_body);
}
#[unsafe(naked)]
unsafe extern "thiscall" fn next(_: *mut c_void, _: *mut *mut c_void) -> u8 {
    core::arch::naked_asm!("mov edx, ebp", "jmp {}", sym next_body);
}
unsafe extern "fastcall" fn first_body(
    queue: *mut c_void,
    frame: usize,
    output: *mut *mut c_void,
) -> u8 {
    // The first bridge replaces the epilogue's initialization in every context.
    unsafe { ((frame - 0x11) as *mut u8).write(1) };
    let start = super::metrics::stamp();
    super::metrics::burst_begin(frame, start);
    if super::task_observation::is_admitted()
        && let Some((deadline, manager)) = unsafe { scope(queue as usize, frame) }
    {
        unsafe { super::task_observation::service(manager, deadline) };
    }
    super::metrics::duration(
        super::metrics::Stage::ServiceCost,
        start,
        super::metrics::stamp(),
    );
    let result = unsafe { pop(&FIRST, queue, output) };
    // The verified caller initializes and owns this local intrusive holder;
    // its actual pointer, rather than pop's AL, controls the native loop.
    if unsafe { output.read() }.is_null() {
        super::metrics::burst_finish(frame, super::metrics::stamp());
    }
    result
}
unsafe extern "fastcall" fn next_body(
    queue: *mut c_void,
    frame: usize,
    output: *mut *mut c_void,
) -> u8 {
    let start = super::metrics::stamp();
    super::metrics::burst_callback(frame);
    if BUDGET.load(Ordering::Acquire) {
        if let Some((deadline, _manager)) = unsafe { scope(queue as usize, frame) } {
            if deadline.expired(query_performance_counter().ok()) == Some(true)
                && unsafe { pending_and_clear(queue, output) }
            {
                unsafe { ((frame - 0x11) as *mut u8).write(0) };
                YIELDS.fetch_add(1, Ordering::Relaxed);
                super::metrics::duration(
                    super::metrics::Stage::ServiceCost,
                    start,
                    super::metrics::stamp(),
                );
                super::metrics::burst_finish(frame, super::metrics::stamp());
                return 0;
            }
        } else {
            UNSUPPORTED.fetch_add(1, Ordering::Relaxed);
        }
    }
    super::metrics::duration(
        super::metrics::Stage::ServiceCost,
        start,
        super::metrics::stamp(),
    );
    let result = unsafe { pop(&NEXT, queue, output) };
    if unsafe { output.read() }.is_null() {
        super::metrics::burst_finish(frame, super::metrics::stamp());
    }
    result
}
unsafe fn pop(site: &Site, queue: *mut c_void, output: *mut *mut c_void) -> u8 {
    let provider = unsafe { FnPtr::<PopFn>::from_address_unchecked(site.provider()) }.as_fn();
    unsafe { provider(queue, output) }
}

fn readable_stack(start: usize, size: usize, allocation: usize) -> bool {
    let Some(end) = start.checked_add(size) else {
        return false;
    };
    virtual_query(start as *mut c_void).is_ok_and(|info| {
        info.is_committed()
            && info.is_writable()
            && info.is_accessible()
            && info.allocation_base as usize == allocation
            && info.base_address as usize <= start
            && (info.base_address as usize)
                .checked_add(info.region_size)
                .is_some_and(|limit| end <= limit)
    })
}

/// Validate exactly the three live ancestor boundaries; no scan or pointer cache.
unsafe fn scope(queue: usize, frame: usize) -> Option<(Deadline, usize)> {
    let local = 0usize;
    let allocation = virtual_query((&local as *const usize).cast_mut().cast())
        .ok()?
        .allocation_base as usize;
    if frame & 3 != 0
        || !readable_stack(frame.checked_sub(0x18)?, 0x20, allocation)
        || unsafe { word(frame, 4) } != 0x446E59
    {
        return None;
    }
    let wrapper = unsafe { word(frame, 0) };
    if wrapper <= frame
        || wrapper & 3 != 0
        || !readable_stack(wrapper, 8, allocation)
        || unsafe { word(wrapper, 4) } != 0xC3DD2C
    {
        return None;
    }
    let service = unsafe { word(wrapper, 0) };
    if service <= wrapper
        || service & 3 != 0
        || !readable_stack(service.checked_sub(0x90)?, 0x98, allocation)
        || unsafe { word(service, 4) } != 0x86E89C
    {
        return None;
    }
    let loader = unsafe { word(frame, -0x18) };
    if loader == 0 || unsafe { word(loader, 0x1C) } != queue {
        return None;
    }
    let manager = unsafe { word(service, -0x90) };
    if manager == 0 || unsafe { word(manager, 0x68) } != 6 {
        return None;
    }
    let start = unsafe { ((service - 0x2C) as *const i64).read_unaligned() };
    let allowance = unsafe { ((service - 0x24) as *const i64).read_unaligned() };
    Some((Deadline { start, allowance }, manager))
}

unsafe fn pending_and_clear(queue: *mut c_void, output: *mut *mut c_void) -> bool {
    // The known queue/count provider proves +0x18 under this native lock.
    // Unknown providers preserve the complete installed pop path.
    if FIRST.provider() != 0x449280 || NEXT.provider() != 0x449280 {
        return false;
    }
    let vtable = unsafe { word(queue as usize, 0) };
    if vtable != 0x1017464
        || unsafe { word(vtable, 8) } != 0x44BBC0
        || unsafe { word(vtable, 0xC) } != 0x44B730
        || unsafe { word(vtable, 0x10) } != 0x9611E0
    {
        return false;
    }
    // The complete native count and counter-mutator bodies prove that +0x18
    // counts pending queue entries. An entry redirect/custom pop can change
    // this contract even with an unchanged vtable address: drain it fully.
    for (address, bytes) in [
        (
            0x9611E0,
            &[
                0x55, 0x8B, 0xEC, 0x51, 0x89, 0x4D, 0xFC, 0x8B, 0x45, 0xFC, 0x8B, 0x40, 0x18, 0x8B,
                0xE5, 0x5D, 0xC3,
            ][..],
        ),
        (
            0x44BBC0,
            &[
                0x55, 0x8B, 0xEC, 0x51, 0x89, 0x4D, 0xFC, 0x8B, 0x45, 0xFC, 0x83, 0xC0, 0x18, 0x50,
                0xE8, 0x8D, 0xF8, 0xFB, 0xFF, 0x83, 0xC4, 4, 0x8B, 0xE5, 0x5D, 0xC3,
            ][..],
        ),
        (
            0x44B730,
            &[
                0x55, 0x8B, 0xEC, 0x51, 0x89, 0x4D, 0xFC, 0x8B, 0x45, 0xFC, 0x83, 0xC0, 0x18, 0x50,
                0xE8, 0x5D, 0x62, 0xFB, 0xFF, 0x83, 0xC4, 4, 0x8B, 0xE5, 0x5D, 0xC3,
            ][..],
        ),
        (
            0x449280,
            &[
                0x55, 0x8B, 0xEC, 0x83, 0xEC, 8, 0x89, 0x4D, 0xF8, 0x6A, 0, 0x8B, 0x4D, 0xF8, 0x83,
                0xC1, 0x20, 0xE8, 0x5A, 0x69, 0xFC, 0xFF, 0x8B, 0x45, 8, 0x50, 0x8B, 0x4D, 0xF8,
                0xE8, 0xDE, 0xC, 0, 0, 0x8B, 0xC8, 0xE8, 0x17, 0x3C, 0, 0, 0x88, 0x45, 0xFF, 0x8B,
                0x4D, 0xF8, 0x83, 0xC1, 0x20, 0xE8, 0xE9, 0x68, 0xFC, 0xFF, 0x8A, 0x45, 0xFF, 0x8B,
                0xE5, 0x5D, 0xC2, 4, 0,
            ][..],
        ),
    ] {
        if unsafe { std::slice::from_raw_parts(address as *const u8, bytes.len()) } != bytes {
            return false;
        }
    }
    type LockFn = unsafe extern "thiscall" fn(*mut c_void, u32);
    type UnlockFn = unsafe extern "thiscall" fn(*mut c_void);
    type ClearFn = unsafe extern "thiscall" fn(*mut *mut c_void, *mut c_void);
    let lock = unsafe { FnPtr::<LockFn>::from_address_unchecked(0x40FBF0) }.as_fn();
    let unlock = unsafe { FnPtr::<UnlockFn>::from_address_unchecked(0x40FBA0) }.as_fn();
    let clear = unsafe { FnPtr::<ClearFn>::from_address_unchecked(0x6F74F0) }.as_fn();
    let guard = unsafe { queue.cast::<u8>().add(0x20).cast() };
    unsafe { lock(guard, 0) };
    type CountFn = unsafe extern "thiscall" fn(*mut c_void) -> u32;
    let count = unsafe { FnPtr::<CountFn>::from_address_unchecked(0x9611E0) }.as_fn();
    let count = unsafe { count(queue) };
    let pending = count != 0;
    if pending {
        unsafe { clear(output, std::ptr::null_mut()) };
    }
    unsafe { unlock(guard) };
    if super::metrics::enabled() {
        let tick = libpsycho::os::windows::winapi::get_tick_count();
        PENDING_SAMPLE.store(
            (u64::from(tick) << 32) | u64::from(count),
            Ordering::Relaxed,
        );
        PENDING_SAMPLED.store(true, Ordering::Release);
    }
    pending
}

/// Whether the ordinary attachment-service bridges committed successfully.
pub(super) fn installed() -> bool {
    INSTALLED.load(Ordering::Acquire)
}

/// Append service status without entering engine queues or changing dashboard ABI.
pub(super) fn append_report(out: &mut String) {
    use std::fmt::Write;
    let _ = writeln!(
        out,
        "LOD attachment budget installed={} enabled={} yields={} unsupported-scopes={}",
        INSTALLED.load(Ordering::Acquire),
        BUDGET.load(Ordering::Acquire),
        YIELDS.load(Ordering::Relaxed),
        UNSUPPORTED.load(Ordering::Relaxed)
    );
    if PENDING_SAMPLED.load(Ordering::Acquire) {
        let sample = PENDING_SAMPLE.load(Ordering::Relaxed);
        let age =
            libpsycho::os::windows::winapi::get_tick_count().wrapping_sub((sample >> 32) as u32);
        let _ = writeln!(
            out,
            "  last locked pending snapshot={} age-ms={} (expiration query)",
            sample as u32, age
        );
    } else {
        let _ = writeln!(out, "  locked pending snapshot unavailable");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deadline_matches_native_strict_comparison_and_rejects_invalid_clocks() {
        let deadline = Deadline {
            start: 100,
            allowance: 20,
        };
        assert_eq!(deadline.expired(Some(120)), Some(false));
        assert_eq!(deadline.expired(Some(121)), Some(true));
        assert_eq!(deadline.expired(Some(99)), None);
        assert_eq!(deadline.expired(None), None);
        assert_eq!(
            Deadline {
                start: 0,
                allowance: -1
            }
            .expired(Some(1)),
            None
        );
        assert_eq!(
            Deadline {
                start: -1,
                allowance: 1
            }
            .expired(Some(i64::MAX)),
            None
        );
    }
}
