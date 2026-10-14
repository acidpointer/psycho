//! Join terrain-task publication before the native block teardown begins.
//!
//! A terrain block owns an intrusive task holder at +0x24. Native publication
//! clears that holder on an IO worker, while native teardown otherwise borrows
//! it across a cancellation wait. The worker can release the last task owner
//! during that wait, before cancellation's own self-retain. An entry retain on
//! a raw borrowed task cannot close this window.
//!
//! Publication and retirement acquisition share a fixed, allocation-free lock
//! stripe selected by the live block address. Retirement clones the native
//! holder under that lock, then releases the lock before native cancellation
//! can wait for a worker. After cancellation joins publication, it clears the
//! block's holder through its installed native provider and releases the pin
//! while the block remains live. Native teardown then owns all scene removal
//! and destruction. No lock spans cancellation, task destruction or block
//! teardown; workers for different stripes remain independent.
//!
//! The publication/retirement pair is admitted only after its startup transaction
//! commits. Best-effort rollback may leave a detour installed; without admission
//! it chains its original provider without touching holder state or locks.
//! Providers retain their native ABIs;
//! there is no allocator classification, task-state write, custom completion,
//! lifetime registry, per-event allocation, clock, or routine logging in these
//! hooks. Publication uses the existing supplemental-worker priority guard to
//! avoid a normal-priority retiree waiting behind a background lock owner.

use std::{
    ffi::c_void,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use anyhow::{Context, ensure};
use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::hook::{
        inline::inlinehook::InlineHookContainer, transaction::ModificationTransaction,
    },
};
use parking_lot::Mutex;

use super::native::{original, word};

const PUBLICATION: usize = 0x006F_A990;
const RETIREMENT: usize = 0x006F_A420;
const TASK_HOLDER: isize = 0x24;
const MANAGER: usize = 0x0120_2D98;
const CANCEL_CALL: usize = 0x006F_A51C;
const CLEAR_CALL: usize = 0x006F_A56F;
const STRIPES: usize = 64;

type BlockFn = unsafe extern "thiscall" fn(*mut c_void);
type CancelFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void, *mut c_void);
type HolderFn = unsafe extern "thiscall" fn(*mut *mut c_void, *mut c_void) -> *mut *mut c_void;

static PUBLISH: LazyLock<InlineHookContainer<BlockFn>> = LazyLock::new(InlineHookContainer::new);
static RETIRE: LazyLock<InlineHookContainer<BlockFn>> = LazyLock::new(InlineHookContainer::new);
static CANCEL_PROVIDER: AtomicUsize = AtomicUsize::new(0);
static CLEAR_PROVIDER: AtomicUsize = AtomicUsize::new(0);
static ADMITTED: AtomicBool = AtomicBool::new(false);
static BLOCK_LOCKS: [Mutex<()>; STRIPES] = [const { Mutex::new(()) }; STRIPES];

/// Install the complete terrain holder-acquisition/publication transaction.
///
/// The caller must be at the core's quiescent startup boundary. Native task
/// cancellation and block-holder clearing chain the providers already present
/// at the block destructor's calls. Failed activation never admits ownership
/// intervention, even if restoration of an entry hook also fails.
pub(super) fn install() -> anyhow::Result<()> {
    if ADMITTED.load(Ordering::Acquire) {
        return Ok(());
    }
    // These callsites prove the native thiscall argument contract used before
    // teardown. Capture installed providers without inspecting their modules.
    let cancel = unsafe { super::super::patching::relative_call_target(CANCEL_CALL) }
        .context("terrain cancellation provider")?;
    let clear = unsafe { super::super::patching::relative_call_target(CLEAR_CALL) }
        .context("terrain task-holder provider")?;
    ensure!(
        super::is_executable(cancel) && super::is_executable(clear),
        "terrain retirement provider is not executable"
    );
    ensure!(
        super::is_executable(0x528CB0) && super::is_executable(0x6F74F0),
        "native intrusive task-holder helpers are unavailable"
    );
    CANCEL_PROVIDER.store(cancel, Ordering::Release);
    CLEAR_PROVIDER.store(clear, Ordering::Release);
    unsafe {
        PUBLISH.init(
            "lod_terrain_publication_owner",
            PUBLICATION as *mut c_void,
            publish,
        )?;
        RETIRE.init(
            "lod_terrain_retirement_owner",
            RETIREMENT as *mut c_void,
            retire,
        )?;
    }
    let mut tx = ModificationTransaction::new();
    tx.enable_inline(&PUBLISH)?;
    tx.enable_inline(&RETIRE)?;
    tx.commit();
    // Targets are quiescent here. Both immutable trampolines and captured
    // providers are ready before either detour may intervene in ownership.
    ADMITTED.store(true, Ordering::Release);
    log::info!("[LOD] Terrain retirement joins publication with an owning task reference");
    Ok(())
}

fn block_lock(block: usize) -> &'static Mutex<()> {
    // A collision only serializes two independent publications. Unlike a
    // sidecar map, fixed stripes cannot lose a required ownership event.
    &BLOCK_LOCKS[(block >> 4).wrapping_mul(0x9E37_79B1) & (STRIPES - 1)]
}

/// One native intrusive reference cloned from a synchronized live holder.
/// It never outlives the native block destructor invocation.
struct TaskPin {
    pointer: *mut c_void,
}

impl TaskPin {
    /// Safety: the block remains live, and its publication stripe excludes
    /// every worker mutation of +0x24 until the native AddRef completes.
    unsafe fn acquire(block: *mut c_void) -> Self {
        let task = unsafe { word(block as usize, TASK_HOLDER) } as *mut c_void;
        let mut pin = Self {
            pointer: std::ptr::null_mut(),
        };
        // 528CB0 initializes one pointer-sized holder and retains task +8.
        // The native helpers accept null and do not allocate a new task.
        let retain = unsafe { FnPtr::<HolderFn>::from_address_unchecked(0x528CB0) }.as_fn();
        unsafe { retain(&mut pin.pointer, task) };
        pin
    }
}

impl Drop for TaskPin {
    fn drop(&mut self) {
        // Only this stack-local holder is cleared. The native helper pairs
        // its AddRef once and invokes any final destructor outside the stripe.
        let clear = unsafe { FnPtr::<HolderFn>::from_address_unchecked(0x6F74F0) }.as_fn();
        unsafe { clear(&mut self.pointer, std::ptr::null_mut()) };
    }
}

unsafe extern "thiscall" fn publish(block: *mut c_void) {
    if !ADMITTED.load(Ordering::Acquire) {
        unsafe { original(&PUBLISH)(block) };
        return;
    }
    // The native worker owns the task while calling 6FC020 -> 6FA990. A
    // retirement that observes a nonempty holder cannot free the block before
    // that worker returns: it owns a pin and waits outside this stripe.
    let _priority = super::super::io::supplemental_priority_guard();
    let _publication = block_lock(block as usize).lock();
    unsafe { original(&PUBLISH)(block) };
}

unsafe extern "thiscall" fn retire(block: *mut c_void) {
    if !ADMITTED.load(Ordering::Acquire) || block.is_null() {
        // A partially restored entry must remain inert. Its immutable original
        // trampoline was published before activation, even if rollback failed.
        // Null input likewise belongs to that provider without inspection.
        unsafe { original(&RETIRE)(block) };
        return;
    }
    let pin = {
        let _publication = block_lock(block as usize).lock();
        // Safety: the scalar-delete caller owns the live block until this
        // destructor returns. Publication's entire clear-and-publish tail is
        // excluded, so reading +0x24 and retaining it is one acquisition.
        unsafe { TaskPin::acquire(block) }
    };
    if !pin.pointer.is_null() {
        let manager = unsafe { word(MANAGER, 0) } as *mut c_void;
        if manager.is_null() {
            // Native teardown already owns the unavailable-manager behavior.
            // Retain its input through that call; the scalar-delete wrapper
            // frees block storage only after this hook and the pin return.
            unsafe { original(&RETIRE)(block) };
            return;
        }
        let cancel = unsafe {
            FnPtr::<CancelFn>::from_address_unchecked(CANCEL_PROVIDER.load(Ordering::Acquire))
        }
        .as_fn();
        // No stripe or sidecar lock is held. 44AC40 waits through states 3/4
        // and reserves queued work with the existing native CAS. Consequently
        // slot-2 publication finishes before scene/geometry teardown begins.
        unsafe { cancel(manager, pin.pointer, std::ptr::null_mut()) };
        {
            let _publication = block_lock(block as usize).lock();
            let clear = unsafe {
                FnPtr::<HolderFn>::from_address_unchecked(CLEAR_PROVIDER.load(Ordering::Acquire))
            }
            .as_fn();
            // Safety: main-thread retirement owns this block; no new task can
            // be assigned here. Publication has completed or was cancelled.
            // The pin protects a still-present task while the block reference
            // is cleared. Native teardown then sees an empty holder and does
            // not repeat the cancellation call on a borrowed pointer.
            unsafe {
                clear(
                    (block.cast::<u8>().add(TASK_HOLDER as usize)).cast(),
                    std::ptr::null_mut(),
                )
            };
        }
    }
    // A final task destructor runs while the block and node are still live;
    // release the temporary owner before native scene/block teardown.
    drop(pin);
    unsafe { original(&RETIRE)(block) };
}
