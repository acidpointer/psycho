//! Serializes model scene post-processing that uses process-global traversal state.
//!
//! # Native failure contract
//!
//! The recursive postprocessor at `0x004B5D10` finds `EditorMarker` nodes and
//! rewrites model scene data. It publishes the active scene root through
//! `0x011C6328` and the current traversal target through `0x011C6324`. These
//! slots belong to the process, not to a loader task or thread.
//!
//! At `0x004B5DDC` the function checks the target for NULL. It subsequently
//! reloads the same global at `0x004B5DED` and `0x004B5E0B`; the latter value is
//! dereferenced at `0x004B5E11` without another NULL check. A concurrent
//! traversal can finish and clear `0x011C6324` between those operations. The
//! July 25 crash captured exactly that state: `ECX == NULL` at `0x004B5E11` on
//! a model worker while loading `DLC03RadiationTrapLight.NIF`.
//!
//! The complete worker chain is:
//!
//! ```text
//! BSTaskManagerThread -> QueuedModel/BSStream -> 0x0043CCF0
//!   -> 0x0043AAF0 -> 0x0043ACE0 -> CALL 0x0043AFAC -> 0x004B5D10
//! ```
//!
//! `0x0043AFAC` is the sole external direct call. Calls at `0x004B5EFB` are
//! recursion inside the same transaction.
//!
//! # Intervention
//!
//! Psycho redirects only the external call and holds one process-wide
//! reentrant mutex while invoking the captured call owner. Locking the outer
//! boundary covers every global publication, recursive visit, and clear while
//! avoiding a lock operation per scene node. Reentrancy prevents self-deadlock
//! if a pre-existing owner synchronously re-enters model loading.
//!
//! Installation is capability based. The call may already target the vanilla
//! function or any executable mod wrapper; Psycho captures that exact target
//! and chains it without checking a module name, version, or address. A later
//! owner is observed but not wrapped again because it may already chain Psycho;
//! forcing a second wrap could create `Psycho -> later owner -> Psycho`
//! recursion. Normal direct-call hook chaining therefore remains compatible,
//! while a destructive later overwrite is reported as an ownership warning.
//!
//! # I/O, allocation, and failure policy
//!
//! This guard installs independently of `[io].parallel_enabled`: vanilla has
//! one model worker plus synchronous main-thread model loading, so disabling
//! Psycho's second worker does not remove the native race. Successful guard
//! installation is also a prerequisite for Psycho parallel I/O and LOD
//! prefetch, preventing those features from widening the unsafe window when
//! callsite ownership is unavailable.
//!
//! The mutex and counters have static storage. Protected calls perform no
//! engine allocation, free, file I/O, or routine logging, and never inspect or
//! select an allocator. The behavior is consequently identical with vanilla
//! heap, scrap-heap-only, and gheap-plus-scrap-heap modes. If the caller
//! fingerprint, direct-call ABI, or predecessor executability cannot be
//! established, installation leaves the callsite unchanged and the dependent
//! concurrency features retain their native-safe fallback.

use std::{
    ffi::c_void,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
};

use anyhow::{Context, ensure};
use libpsycho::{ffi::fnptr::FnPtr, os::windows::winapi::virtual_query};
use parking_lot::ReentrantMutex;

use crate::events;

use super::{patching, statics, types::ModelPostprocessFn};

const CALL_PREFIX_ADDR: usize = 0x0043_AFA0;
const CALL_PREFIX: [u8; 6] = [0x8B, 0x4D, 0xA0, 0x83, 0xC1, 0x0C];
const ARG_PUSH_ADDR: usize = 0x0043_AFAB;
const ARG_PUSH: [u8; 1] = [0x50];
const STACK_RESTORE_ADDR: usize = 0x0043_AFB1;
const STACK_RESTORE: [u8; 3] = [0x83, 0xC4, 0x04];
const VANILLA_TARGET: usize = 0x004B_5D10;

const OWNER_DISABLED: u8 = 0;
const OWNER_DIRECT: u8 = 1;
const OWNER_LATER: u8 = 2;
const OWNER_INVALID: u8 = 3;

static INSTALLED: AtomicBool = AtomicBool::new(false);
static PREDECESSOR: AtomicUsize = AtomicUsize::new(0);
static CALLSITE_OWNER: AtomicU8 = AtomicU8::new(OWNER_DISABLED);
static TRANSACTION_LOCK: LazyLock<ReentrantMutex<()>> = LazyLock::new(|| ReentrantMutex::new(()));
static TRANSACTIONS: AtomicU64 = AtomicU64::new(0);
static COMPLETIONS: AtomicU64 = AtomicU64::new(0);
static CONTENTIONS: AtomicU64 = AtomicU64::new(0);
static WAITERS: AtomicU32 = AtomicU32::new(0);

/// Read-only model postprocess guard state for diagnostics and feature gating.
#[derive(Clone, Copy)]
pub(super) struct Snapshot {
    /// Whether Psycho successfully installed the serialization boundary.
    pub installed: bool,
    /// Current direct-call ownership classification.
    pub owner: &'static str,
    /// Executable call owner captured below Psycho's wrapper.
    pub predecessor: usize,
    /// Number of protected transactions that started.
    pub transactions: u64,
    /// Number of protected transactions that returned.
    pub completions: u64,
    /// Number of transactions that had to wait for another thread.
    pub contentions: u64,
    /// Number of threads currently waiting for the serialization lock.
    pub waiters: u32,
}

/// Install the model postprocess serialization boundary.
///
/// The caller must run this during the pre-CRT startup barrier, before the
/// native task manager can execute model work. This quiescent point makes
/// predecessor publication and direct-call redirection one logical operation.
pub(super) fn install() -> anyhow::Result<()> {
    if INSTALLED.load(Ordering::Acquire) {
        return Ok(());
    }

    // Verify only instructions that establish this call's argument and cdecl
    // stack cleanup. The preceding helper CALL displacement is deliberately
    // excluded so a compatible mod may own that independent helper.
    unsafe {
        patching::verify_bytes(CALL_PREFIX_ADDR, &CALL_PREFIX)?;
        patching::verify_bytes(ARG_PUSH_ADDR, &ARG_PUSH)?;
        patching::verify_bytes(STACK_RESTORE_ADDR, &STACK_RESTORE)?;
    }

    let wrapper = serialized_model_postprocess as *const () as usize;
    let predecessor =
        unsafe { patching::relative_call_target(statics::MODEL_POSTPROCESS_CALL_ADDR) }
            .context("inspect model postprocess call owner")?;
    ensure!(
        predecessor != wrapper,
        "model postprocess call already targets Psycho without published ownership"
    );
    ensure!(
        is_executable(predecessor),
        "model postprocess call owner 0x{predecessor:08X} is not executable"
    );

    // Force construction before publishing the wrapper. This keeps the first
    // model load on the same allocation-free steady-state path as every later
    // load, regardless of which allocator mode the user selected.
    LazyLock::force(&TRANSACTION_LOCK);

    // Publish first so even an unexpected call immediately after the code
    // patch has a valid predecessor. Syringe's pre-CRT barrier guarantees the
    // task manager is not running while these two stores are performed.
    PREDECESSOR.store(predecessor, Ordering::Release);
    let redirected = unsafe {
        patching::redirect_relative_call(
            statics::MODEL_POSTPROCESS_CALL_ADDR,
            serialized_model_postprocess as *mut c_void,
        )
    }
    .context("install model postprocess serialization boundary")?;
    if redirected != predecessor {
        rollback_callsite(redirected);
        anyhow::bail!(
            "model postprocess call owner changed during install: expected 0x{predecessor:08X}, displaced 0x{redirected:08X}"
        );
    }

    CALLSITE_OWNER.store(OWNER_DIRECT, Ordering::Release);
    INSTALLED.store(true, Ordering::Release);
    log::info!(
        "[MODEL_POSTPROCESS] EditorMarker transaction serialized at 0x{:08X}; predecessor=0x{predecessor:08X} ({})",
        statics::MODEL_POSTPROCESS_CALL_ADDR,
        if predecessor == VANILLA_TARGET {
            "vanilla"
        } else {
            "chained"
        },
    );
    Ok(())
}

/// Observe late direct-call ownership without risking a hook-chain cycle.
pub(super) fn observe_event(kind: u32) {
    if kind != events::DEFERRED_INIT || !INSTALLED.load(Ordering::Acquire) {
        return;
    }

    let wrapper = serialized_model_postprocess as *const () as usize;
    let (state, current) = match unsafe {
        patching::relative_call_target(statics::MODEL_POSTPROCESS_CALL_ADDR)
    } {
        Ok(current) if current == wrapper => (OWNER_DIRECT, current),
        Ok(current) if is_executable(current) => (OWNER_LATER, current),
        Ok(current) => (OWNER_INVALID, current),
        Err(error) => {
            CALLSITE_OWNER.store(OWNER_INVALID, Ordering::Release);
            log::warn!("[MODEL_POSTPROCESS] Cannot observe deferred callsite ownership: {error:#}");
            return;
        }
    };

    CALLSITE_OWNER.store(state, Ordering::Release);
    if state == OWNER_LATER {
        // A normal later direct-call hook captured and chains our wrapper. Do
        // not seize the site again: doing so can turn that valid chain into a
        // recursion cycle. The diagnostic makes destructive replacements
        // visible without binding policy to any particular mod.
        log::info!(
            "[MODEL_POSTPROCESS] Deferred callsite owner moved to executable 0x{current:08X}; preserving later hook chain"
        );
    } else if state == OWNER_INVALID {
        log::warn!("[MODEL_POSTPROCESS] Deferred callsite owner 0x{current:08X} is not executable");
    }
}

/// Return whether the serialization boundary was installed successfully.
pub(super) fn is_ready() -> bool {
    INSTALLED.load(Ordering::Acquire)
}

/// Capture model postprocess counters without changing producer state.
pub(super) fn snapshot() -> Snapshot {
    Snapshot {
        installed: INSTALLED.load(Ordering::Acquire),
        owner: owner_name(CALLSITE_OWNER.load(Ordering::Acquire)),
        predecessor: PREDECESSOR.load(Ordering::Acquire),
        transactions: TRANSACTIONS.load(Ordering::Relaxed),
        completions: COMPLETIONS.load(Ordering::Acquire),
        contentions: CONTENTIONS.load(Ordering::Relaxed),
        waiters: WAITERS.load(Ordering::Acquire),
    }
}

unsafe extern "C" fn serialized_model_postprocess(root: *mut c_void) -> u8 {
    let predecessor = PREDECESSOR.load(Ordering::Acquire);
    if predecessor == 0 || predecessor == serialized_model_postprocess as *const () as usize {
        // This can occur only after an incomplete external patch operation.
        // Returning failure is safer than recursing or calling an unknown ABI.
        return 0;
    }
    let Ok(original) =
        (unsafe { FnPtr::<ModelPostprocessFn>::from_raw(predecessor as *mut c_void) })
    else {
        return 0;
    };

    with_serialized_transaction(|| unsafe { original.as_fn()(root) })
}

fn with_serialized_transaction<T>(operation: impl FnOnce() -> T) -> T {
    TRANSACTIONS.fetch_add(1, Ordering::Relaxed);
    let guard = if let Some(guard) = TRANSACTION_LOCK.try_lock() {
        guard
    } else {
        CONTENTIONS.fetch_add(1, Ordering::Relaxed);
        WAITERS.fetch_add(1, Ordering::AcqRel);
        let guard = TRANSACTION_LOCK.lock();
        WAITERS.fetch_sub(1, Ordering::AcqRel);
        guard
    };

    let result = operation();
    COMPLETIONS.fetch_add(1, Ordering::Release);
    drop(guard);
    result
}

fn rollback_callsite(predecessor: usize) {
    let wrapper = serialized_model_postprocess as *const () as usize;
    let current = unsafe { patching::relative_call_target(statics::MODEL_POSTPROCESS_CALL_ADDR) };
    match current {
        Ok(current) if current == wrapper => {
            let restored = unsafe {
                patching::redirect_relative_call(
                    statics::MODEL_POSTPROCESS_CALL_ADDR,
                    predecessor as *mut c_void,
                )
            };
            if matches!(restored, Ok(displaced) if displaced == wrapper) {
                PREDECESSOR.store(0, Ordering::Release);
                return;
            }
            log::error!(
                "[MODEL_POSTPROCESS] Failed to restore callsite after install ownership changed: {restored:?}"
            );
        }
        Ok(current) => log::error!(
            "[MODEL_POSTPROCESS] Cannot restore failed install because callsite ownership moved to 0x{current:08X}"
        ),
        Err(error) => log::error!(
            "[MODEL_POSTPROCESS] Cannot inspect callsite during failed-install rollback: {error:#}"
        ),
    }
}

fn owner_name(state: u8) -> &'static str {
    match state {
        OWNER_DIRECT => "direct",
        OWNER_LATER => "later-owner",
        OWNER_INVALID => "invalid",
        _ => "disabled",
    }
}

fn is_executable(address: usize) -> bool {
    if address < 0x10000 {
        return false;
    }
    virtual_query(address as *mut c_void).is_ok_and(|info| info.is_executable())
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Barrier, Mutex,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    };

    use super::{CONTENTIONS, with_serialized_transaction};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn model_postprocess_transactions_cannot_overlap() {
        let _test = TEST_LOCK
            .lock()
            .expect("serialize model-postprocess lock tests");
        let release_first = Arc::new(Barrier::new(2));
        let second_entered = Arc::new(AtomicBool::new(false));
        let (first_entered_tx, first_entered_rx) = mpsc::channel();

        let first_release = Arc::clone(&release_first);
        let first = thread::spawn(move || {
            with_serialized_transaction(|| {
                first_entered_tx
                    .send(())
                    .expect("signal first model postprocess");
                first_release.wait();
            });
        });
        first_entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first model postprocess entered");

        let contentions_before = CONTENTIONS.load(Ordering::Relaxed);
        let second_state = Arc::clone(&second_entered);
        let second = thread::spawn(move || {
            with_serialized_transaction(|| second_state.store(true, Ordering::Release));
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        while CONTENTIONS.load(Ordering::Relaxed) == contentions_before {
            assert!(
                Instant::now() < deadline,
                "second model postprocess did not contend"
            );
            thread::yield_now();
        }
        assert!(!second_entered.load(Ordering::Acquire));

        release_first.wait();
        first.join().expect("join first model postprocess");
        second.join().expect("join second model postprocess");
        assert!(second_entered.load(Ordering::Acquire));
    }

    #[test]
    fn nested_model_postprocess_transaction_is_reentrant() {
        let _test = TEST_LOCK
            .lock()
            .expect("serialize model-postprocess lock tests");
        let result = with_serialized_transaction(|| with_serialized_transaction(|| 0x5Au8));

        assert_eq!(result, 0x5A);
    }
}
