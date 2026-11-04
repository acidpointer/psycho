//! Serialize injector list operations with the two native plane publishers.
//!
//! BSPortalGraph list readers run synchronously in the native main-frame
//! visibility pass. Injection is confined to normal main-thread presentation,
//! after that pass. Native reference attachment and the console command are
//! the two append callers; these bridges serialize their complete provider
//! calls with injector scans/unlinks. No culling or per-bound hook is added.
//! A retained graph excludes its destructor while injected nodes exist.
//!
//! Hooks are prepared transactionally at the pre-CRT barrier and always chain
//! the captured provider, including rollback survivors. The recursive lock
//! permits provider reentry and is never held over collection or cache I/O.
//! See the owning occlusion plan for the verified native call chains.

use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

use anyhow::{Context, Result, ensure};
use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::{
        hook::{callsite::Rel32CallHookContainer, transaction::ModificationTransaction},
        memory::read_bytes,
        patch::CodeSignature,
        winapi::{get_last_error_code, set_last_error},
    },
};
use parking_lot::{ReentrantMutex, ReentrantMutexGuard};

use super::contract::AppendFn;

static MUTATION: ReentrantMutex<()> = ReentrantMutex::new(());
static HOOKS: [Rel32CallHookContainer<AppendFn>; 2] = [const { Rel32CallHookContainer::new() }; 2];
static PROVIDERS: [AtomicPtr<c_void>; 2] = [const { AtomicPtr::new(core::ptr::null_mut()) }; 2];
static READY: AtomicBool = AtomicBool::new(false);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static UNGUARDED: AtomicUsize = AtomicUsize::new(0);
static DRAINED: AtomicBool = AtomicBool::new(false);

const CALLS: [usize; 2] = [0x0054_AA11, 0x005B_BBD1];
const BEFORE: [&[u8]; 2] = [&[0x50, 0x8B, 0x8D, 0x68, 0xFF, 0xFF, 0xFF], &[0x8B, 0xC8]];
const AFTER: [&[u8]; 2] = [
    &[0x8B, 0x4D, 0xF4, 0x64, 0x89, 0x0D, 0, 0, 0, 0],
    &[0xC6, 0x85, 0x67, 0xFF, 0xFF, 0xFF, 0x01],
];

/// Prepare both native publishers before any gameplay can execute them.
pub(super) fn install() -> Result<()> {
    ensure!(
        crate::entry::has_pre_crt_startup_boundary() && !crate::entry::is_initialized(),
        "occlusion list publication requires the pre-CRT barrier"
    );
    for index in 0..CALLS.len() {
        CodeSignature::new(
            "occlusion append caller arguments",
            CALLS[index] - BEFORE[index].len(),
            BEFORE[index],
        )
        .verify()?;
        CodeSignature::new(
            "occlusion append caller continuation",
            CALLS[index] + 5,
            AFTER[index],
        )
        .verify()?;
    }
    let bridges: [AppendFn; 2] = [append::<0>, append::<1>];
    for index in 0..CALLS.len() {
        // SAFETY: the exact caller frames pass thiscall(graph, plane), RET 4.
        // Capture all predecessors before making either bridge reachable.
        unsafe {
            HOOKS[index].init(
                "occlusion_plane_publication",
                CALLS[index] as *mut c_void,
                bridges[index],
            )
        }
        .with_context(|| format!("occlusion publisher 0x{:08X}", CALLS[index]))?;
        PROVIDERS[index].store(HOOKS[index].original()? as *mut c_void, Ordering::Release);
    }
    let mut transaction = ModificationTransaction::new();
    for hook in &HOOKS {
        transaction.enable_callsite(hook)?;
    }
    transaction.commit();
    READY.store(true, Ordering::Release);
    Ok(())
}

/// Whether both publication bridges were installed as one transaction.
pub(super) fn ready() -> bool {
    READY.load(Ordering::Acquire)
}

/// Publish synchronization after plugin loading, with no executable writes.
/// A non-chaining replacement of either prepared caller cannot be admitted.
pub(super) fn publish() -> Result<()> {
    ensure!(ready(), "native occlusion publishers were not prepared");
    let bridges: [AppendFn; 2] = [append::<0>, append::<1>];
    for index in 0..CALLS.len() {
        let displacement = (bridges[index] as usize).wrapping_sub(CALLS[index] + 5) as u32;
        let mut expected = [0xE8, 0, 0, 0, 0];
        expected[1..].copy_from_slice(&displacement.to_le_bytes());
        let observed = read_bytes(CALLS[index] as *const c_void, 5)?;
        ensure!(
            observed == expected,
            "occlusion publication caller ownership changed at 0x{:08X}",
            CALLS[index]
        );
    }
    ACTIVE.store(true, Ordering::SeqCst);
    Ok(())
}

/// Drain any append that entered before DeferredInit without acquiring a new
/// lazy owner or lock during startup. After ACTIVE's publication, every new
/// append is serialized. SeqCst enroll-before-check makes a zero observation
/// sufficient even when an entry races with publication. A busy first frame
/// simply retries; no engine lock is held while waiting for an old publisher.
pub(super) fn publishers_quiescent() -> bool {
    if DRAINED.load(Ordering::Acquire) {
        return true;
    }
    if !ACTIVE.load(Ordering::SeqCst) || UNGUARDED.load(Ordering::SeqCst) != 0 {
        return false;
    }
    DRAINED.store(true, Ordering::Release);
    true
}

/// Exclude native publishers during a main-thread injector list operation.
pub(super) fn lock() -> ReentrantMutexGuard<'static, ()> {
    MUTATION.lock()
}

unsafe extern "thiscall" fn append<const INDEX: usize>(graph: *mut c_void, plane: *mut c_void) {
    let pointer = PROVIDERS[INDEX].load(Ordering::Acquire);
    // SAFETY: install publishes this exact ABI before enabling a callsite.
    // Providers remain published for the lifetime of any rollback survivor.
    let provider = unsafe { FnPtr::<AppendFn>::from_address_unchecked(pointer as usize).as_fn() };
    UNGUARDED.fetch_add(1, Ordering::SeqCst);
    if !ACTIVE.load(Ordering::SeqCst) {
        // Before DeferredInit, forward without first-touching the recursive
        // mutex/TLS or introducing allocation into native startup.
        unsafe { provider(graph, plane) };
        UNGUARDED.fetch_sub(1, Ordering::SeqCst);
        return;
    }
    UNGUARDED.fetch_sub(1, Ordering::SeqCst);
    let entry_error = get_last_error_code();
    let guard = lock();
    set_last_error(entry_error);
    unsafe { provider(graph, plane) };
    let provider_error = get_last_error_code();
    drop(guard);
    set_last_error(provider_error);
}
