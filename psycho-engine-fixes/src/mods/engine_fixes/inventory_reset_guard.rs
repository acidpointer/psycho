//! Reject broken base-item lists before native inventory reset and refresh.
//!
//! The pre-CRT owner installs three entry and two native callsite hooks together.
//! Reset and actor refresh reject invalid input before their first mutation;
//! the standalone quest-item query conservatively protects uncertain inventory.
//! Stack-owned call scopes carry rejection through the two exact native
//! continuations. No later provider at either shared entry is bypassed.
//! Valid input chains each captured provider unchanged. No item, inventory list, owner,
//! reference count or allocator state is changed by admission.
//!
//! Native callers retain reference, base, inventory Data and list lifetimes
//! throughout admission and the original call. Guarded copies reject missing
//! memory, not readable stale objects or races after a snapshot. The existing
//! nonallocating extra-data getter retains its native cache/lock contract.
//! This is base-list containment, not general extra-data or heap validation.
//!
//! Calls use constant stack storage, linear list walks and no arbitrary length
//! cap. Repeated owners intentionally revalidate; no object pointer is cached
//! across calls. Memory copies and executable-page queries have unmeasured OS
//! cost. Only the first rejection logs. The helper edits next-launch config;
//! see docs/crash_20261020_levelup_inventory_plan.md for native proof and limits.

use std::{
    cell::Cell,
    ffi::c_void,
    sync::{
        LazyLock, OnceLock,
        atomic::{AtomicBool, AtomicPtr, Ordering},
    },
};

use anyhow::{Result, ensure};
use libpsycho::os::windows::{
    guarded_memory::{
        ThreadLocalSlot, prepare_current_process_memory_reader, read_current_process_memory,
    },
    hook::{
        callsite::Rel32CallHookContainer, inline::inlinehook::InlineHookContainer,
        transaction::ModificationTransaction,
    },
    winapi::{get_last_error_code, set_last_error, virtual_query},
};

type Query = unsafe extern "thiscall" fn(*mut c_void) -> u8;
type Reset = unsafe extern "thiscall" fn(*mut c_void, u8);
type ExistingInventory = unsafe extern "thiscall" fn(*mut c_void) -> *mut c_void;

const QUERY_ADDRESS: usize = 0x00577DE0;
const RESET_ADDRESS: usize = 0x00574920;
const ACTOR_ADDRESS: usize = 0x0089FB80;
const QUERY_FROM_RESET_ADDRESS: usize = 0x0057493E;
const RESET_FROM_ACTOR_ADDRESS: usize = 0x0089FC1F;
const EXISTING_INVENTORY_ADDRESS: usize = 0x00418520;
const BASE_OFFSET: usize = 0x20;
const EXTRA_LIST_OFFSET: usize = 0x44;
const FORM_TYPE_OFFSET: usize = 4;
const QUEST_QUERY_OFFSET: usize = 0x94;

// Complete native owners, including their call targets and return ABI. Changed
// bodies leave the whole fix inactive; no external provider is overwritten.
const QUERY_BODY: &[u8] = &[
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x89, 0x4D, 0xF0, 0xC6, 0x45, 0xFB, 0x00, 0x8B, 0x4D, 0xF0,
    0xE8, 0x1B, 0x55, 0xFE, 0xFF, 0x89, 0x45, 0xFC, 0x83, 0x7D, 0xFC, 0x00, 0x74, 0x1A, 0x8B, 0x45,
    0xF0, 0x50, 0xE8, 0x19, 0x74, 0xF4, 0xFF, 0x83, 0xC4, 0x04, 0x89, 0x45, 0xF4, 0x8B, 0x4D, 0xF4,
    0xE8, 0x4B, 0x85, 0xF5, 0xFF, 0x88, 0x45, 0xFB, 0x8A, 0x45, 0xFB, 0x8B, 0xE5, 0x5D, 0xC3,
];

const RESET_BODY: &[u8] = &[
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x18, 0x89, 0x4D, 0xE8, 0x8B, 0x0D, 0x38, 0xDF, 0x1D, 0x01, 0xE8,
    0xDC, 0x84, 0xEB, 0xFF, 0x0F, 0xB6, 0xC0, 0x85, 0xC0, 0x75, 0x13, 0x8B, 0x4D, 0xE8, 0xE8, 0x9D,
    0x34, 0x00, 0x00, 0x0F, 0xB6, 0xC8, 0x85, 0xC9, 0x74, 0x04, 0xC6, 0x45, 0x08, 0x01, 0x8B, 0x4D,
    0xE8, 0xE8, 0xBA, 0x89, 0xFE, 0xFF, 0x89, 0x45, 0xFC, 0x83, 0x7D, 0xFC, 0x00, 0x0F, 0x84, 0x17,
    0x01, 0x00, 0x00, 0xC7, 0x45, 0xF4, 0x00, 0x00, 0x00, 0x00, 0x0F, 0xB6, 0x55, 0x08, 0x85, 0xD2,
    0x74, 0x19, 0x8B, 0x45, 0xE8, 0x50, 0xE8, 0xA5, 0xA8, 0xF4, 0xFF, 0x83, 0xC4, 0x04, 0x89, 0x45,
    0xF4, 0x8B, 0x4D, 0xF4, 0xE8, 0x17, 0xCE, 0xF5, 0xFF, 0xEB, 0x1E, 0x8B, 0x4D, 0xE8, 0xE8, 0x2D,
    0xFA, 0x05, 0x00, 0x8B, 0xC8, 0xE8, 0x16, 0x65, 0xEA, 0xFF, 0x8B, 0x4D, 0xE8, 0x51, 0xE8, 0x7D,
    0xA8, 0xF4, 0xFF, 0x83, 0xC4, 0x04, 0x89, 0x45, 0xF4, 0x8B, 0x55, 0xE8, 0x8B, 0x02, 0x8B, 0x4D,
    0xE8, 0x8B, 0x90, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xD2, 0x0F, 0xB6, 0xC0, 0x85, 0xC0, 0x74, 0x0E,
    0x8B, 0x4D, 0xE8, 0x89, 0x4D, 0xF0, 0x8B, 0x4D, 0xF0, 0xE8, 0x82, 0x92, 0x33, 0x00, 0x8B, 0x4D,
    0xF4, 0xE8, 0x6A, 0xCA, 0xF5, 0xFF, 0x0F, 0xB6, 0x55, 0x08, 0x85, 0xD2, 0x75, 0x08, 0x8B, 0x4D,
    0xF4, 0xE8, 0x2A, 0xCC, 0xF5, 0xFF, 0x8B, 0x4D, 0xF4, 0xE8, 0x72, 0xCF, 0xF5, 0xFF, 0x8B, 0x4D,
    0xF4, 0xE8, 0xEA, 0x83, 0xEB, 0xFF, 0x0F, 0xB6, 0xC0, 0x85, 0xC0, 0x74, 0x0F, 0x8B, 0x4D, 0xE8,
    0xE8, 0xBB, 0xF9, 0x05, 0x00, 0x8B, 0xC8, 0xE8, 0xA4, 0x64, 0xEA, 0xFF, 0x8B, 0x4D, 0xE8, 0xE8,
    0xAC, 0xF9, 0x05, 0x00, 0x8B, 0xC8, 0xE8, 0x75, 0x95, 0xEA, 0xFF, 0x89, 0x45, 0xF8, 0x83, 0x7D,
    0xF8, 0x00, 0x74, 0x56, 0x8B, 0x4D, 0xF8, 0xE8, 0xA4, 0x0C, 0x2B, 0x00, 0x0F, 0xB6, 0xC8, 0x85,
    0xC9, 0x75, 0x47, 0x8B, 0x4D, 0xF8, 0xE8, 0x85, 0xCB, 0x10, 0x00, 0x8B, 0x10, 0x89, 0x55, 0xEC,
    0x6A, 0x00, 0x8B, 0x4D, 0xEC, 0xE8, 0x76, 0xF9, 0x05, 0x00, 0x8B, 0xC8, 0xE8, 0xEF, 0x93, 0xEA,
    0xFF, 0x8B, 0x45, 0xEC, 0x8B, 0x10, 0x8B, 0x4D, 0xEC, 0x8B, 0x82, 0x60, 0x01, 0x00, 0x00, 0xFF,
    0xD0, 0x0F, 0xB6, 0xC8, 0x85, 0xC9, 0x75, 0x08, 0x8B, 0x4D, 0xEC, 0xE8, 0x00, 0xD8, 0xFF, 0xFF,
    0x8B, 0x4D, 0xF8, 0xE8, 0x38, 0xAD, 0x0C, 0x00, 0xEB, 0xA4, 0x8B, 0xE5, 0x5D, 0xC2, 0x04, 0x00,
];

const ACTOR_BODY: &[u8] = &[
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x24, 0x89, 0x4D, 0xE0, 0x8B, 0x0D, 0x5C, 0xE4, 0x1D, 0x01, 0xE8,
    0xBC, 0xCC, 0xBD, 0xFF, 0x0F, 0xB6, 0xC0, 0x85, 0xC0, 0x75, 0x60, 0xC7, 0x45, 0xFC, 0x00, 0x00,
    0x00, 0x00, 0x8B, 0x4D, 0xE0, 0xE8, 0x76, 0x89, 0x03, 0x00, 0x85, 0xC0, 0x74, 0x1F, 0x8B, 0x4D,
    0xE0, 0xE8, 0x6A, 0x89, 0x03, 0x00, 0x8B, 0xC8, 0xE8, 0xA3, 0xD1, 0xBB, 0xFF, 0x83, 0xF8, 0x01,
    0x7F, 0x0B, 0x8B, 0x4D, 0xE0, 0xE8, 0x56, 0x89, 0x03, 0x00, 0x89, 0x45, 0xFC, 0x83, 0x7D, 0xFC,
    0x00, 0x74, 0x14, 0x6A, 0x01, 0x8B, 0x4D, 0xFC, 0x8B, 0x11, 0x8B, 0x4D, 0xFC, 0x8B, 0x82, 0x68,
    0x04, 0x00, 0x00, 0xFF, 0xD0, 0xEB, 0x14, 0x6A, 0x01, 0x6A, 0x00, 0x8B, 0x4D, 0xE0, 0x8B, 0x11,
    0x8B, 0x4D, 0xE0, 0x8B, 0x82, 0xCC, 0x01, 0x00, 0x00, 0xFF, 0xD0, 0x8B, 0x4D, 0xE0, 0xE8, 0xBD,
    0x47, 0xD3, 0xFF, 0x8B, 0xC8, 0xE8, 0x16, 0x89, 0xB7, 0xFF, 0x50, 0xE8, 0xA0, 0xD4, 0xBD, 0xFF,
    0x8B, 0xC8, 0xE8, 0xF9, 0xC0, 0xE4, 0xFF, 0x0F, 0xB6, 0x4D, 0x08, 0x51, 0x8B, 0x4D, 0xE0, 0xE8,
    0xFC, 0x4C, 0xCD, 0xFF, 0x8B, 0x55, 0xE0, 0x8B, 0x02, 0x8B, 0x4D, 0xE0, 0x8B, 0x90, 0xD0, 0x01,
    0x00, 0x00, 0xFF, 0xD2, 0x85, 0xC0, 0x0F, 0x84, 0xAC, 0x00, 0x00, 0x00, 0x8B, 0x4D, 0xE0, 0xE8,
    0xEC, 0xF7, 0xF0, 0xFF, 0x89, 0x45, 0xE4, 0xC7, 0x45, 0xEC, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x45,
    0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x4D, 0xE4, 0xE8, 0x13, 0x15, 0xB6, 0xFF, 0x89, 0x45, 0xDC,
    0x83, 0x7D, 0xDC, 0x2A, 0x74, 0x08, 0x83, 0x7D, 0xDC, 0x2B, 0x74, 0x0A, 0xEB, 0x0E, 0x8B, 0x45,
    0xE4, 0x89, 0x45, 0xEC, 0xEB, 0x06, 0x8B, 0x4D, 0xE4, 0x89, 0x4D, 0xE8, 0xC6, 0x45, 0xFB, 0x01,
    0xC6, 0x45, 0xF3, 0x01, 0x8B, 0x4D, 0xE0, 0xE8, 0x14, 0x48, 0x09, 0x00, 0x89, 0x45, 0xF4, 0x83,
    0x7D, 0xF4, 0x00, 0x74, 0x13, 0x8B, 0x4D, 0xF4, 0xE8, 0x63, 0x1E, 0xBA, 0xFF, 0x0F, 0xB6, 0xD0,
    0x85, 0xD2, 0x74, 0x04, 0xC6, 0x45, 0xF3, 0x00, 0x83, 0x7D, 0xEC, 0x00, 0x74, 0x1C, 0x6A, 0x01,
    0x6A, 0x00, 0x0F, 0xB6, 0x45, 0xF3, 0x50, 0x0F, 0xB6, 0x4D, 0xFB, 0x51, 0x8B, 0x55, 0xE0, 0x52,
    0x8B, 0x4D, 0xEC, 0xE8, 0xF8, 0x4A, 0xD6, 0xFF, 0xEB, 0x1E, 0x83, 0x7D, 0xE8, 0x00, 0x74, 0x18,
    0x6A, 0x01, 0x0F, 0xB6, 0x45, 0xF3, 0x50, 0x0F, 0xB6, 0x4D, 0xFB, 0x51, 0x8B, 0x55, 0xE0, 0x52,
    0x8B, 0x4D, 0xE8, 0xE8, 0x18, 0xA1, 0xD5, 0xFF, 0x8B, 0xE5, 0x5D, 0xC2, 0x04, 0x00,
];

static QUERY_HOOK: LazyLock<InlineHookContainer<Query>> = LazyLock::new(InlineHookContainer::new);
static RESET_HOOK: LazyLock<InlineHookContainer<Reset>> = LazyLock::new(InlineHookContainer::new);
static ACTOR_HOOK: LazyLock<InlineHookContainer<Reset>> = LazyLock::new(InlineHookContainer::new);
static QUERY_FROM_RESET_HOOK: LazyLock<Rel32CallHookContainer<Query>> =
    LazyLock::new(Rel32CallHookContainer::new);
static RESET_FROM_ACTOR_HOOK: LazyLock<Rel32CallHookContainer<Reset>> =
    LazyLock::new(Rel32CallHookContainer::new);
static QUERY_PROVIDER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static RESET_PROVIDER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ACTOR_PROVIDER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static QUERY_CALL_PROVIDER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static RESET_CALL_PROVIDER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static CALL_SCOPE_SLOT: OnceLock<ThreadLocalSlot> = OnceLock::new();
static CALL_SCOPE_HEALTHY: AtomicBool = AtomicBool::new(true);
static ADMITTED: AtomicBool = AtomicBool::new(false);
static REPORTED: AtomicBool = AtomicBool::new(false);

/// Install entry admission and its inseparable native continuation policy.
///
/// Entry ABIs and full bodies must match the supported binary. Every captured
/// provider is published before activation, so rollback survivors can forward.
pub(super) fn install() -> Result<()> {
    if ADMITTED.load(Ordering::Acquire) {
        return Ok(());
    }
    ensure!(
        crate::entry::has_pre_crt_startup_boundary() && !crate::entry::is_initialized(),
        "inventory-reset installation requires the quiescent pre-CRT boundary"
    );
    prepare_current_process_memory_reader()?;
    for (address, expected) in [
        (QUERY_ADDRESS, QUERY_BODY),
        (RESET_ADDRESS, RESET_BODY),
        (ACTOR_ADDRESS, ACTOR_BODY),
    ] {
        // These cold installer buffers have a fixed upper bound, not one
        // allocation per native operation.
        let mut observed = [0; ACTOR_BODY.len()];
        read_current_process_memory(address, &mut observed[..expected.len()])?;
        ensure!(
            &observed[..expected.len()] == expected,
            "native inventory body mismatch at 0x{address:08X}"
        );
    }
    // SAFETY: Verified native bodies prove ECX=this, a byte result/plain RET
    // for Query, and one stack byte argument/void result/RET 4 for both resets.
    unsafe {
        QUERY_HOOK.init(
            "inventory_quest_query_guard",
            QUERY_ADDRESS as *mut c_void,
            query,
        )?;
        RESET_HOOK.init("inventory_reset_guard", RESET_ADDRESS as *mut c_void, reset)?;
        ACTOR_HOOK.init(
            "actor_inventory_refresh_guard",
            ACTOR_ADDRESS as *mut c_void,
            refresh,
        )?;
        QUERY_FROM_RESET_HOOK.init(
            "inventory_reset_query_continuation",
            QUERY_FROM_RESET_ADDRESS as *mut c_void,
            query_from_reset,
        )?;
        RESET_FROM_ACTOR_HOOK.init(
            "actor_inventory_reset_continuation",
            RESET_FROM_ACTOR_ADDRESS as *mut c_void,
            reset_from_refresh,
        )?;
    }
    QUERY_PROVIDER.store(QUERY_HOOK.original()? as *mut c_void, Ordering::Release);
    RESET_PROVIDER.store(RESET_HOOK.original()? as *mut c_void, Ordering::Release);
    ACTOR_PROVIDER.store(ACTOR_HOOK.original()? as *mut c_void, Ordering::Release);
    QUERY_CALL_PROVIDER.store(
        QUERY_FROM_RESET_HOOK.original()? as *mut c_void,
        Ordering::Release,
    );
    RESET_CALL_PROVIDER.store(
        RESET_FROM_ACTOR_HOOK.original()? as *mut c_void,
        Ordering::Release,
    );
    prepare_call_scope()?;
    let mut transaction = ModificationTransaction::new();
    transaction.enable_inline(&*QUERY_HOOK)?;
    transaction.enable_inline(&*RESET_HOOK)?;
    transaction.enable_inline(&*ACTOR_HOOK)?;
    transaction.enable_callsite(&*QUERY_FROM_RESET_HOOK)?;
    transaction.enable_callsite(&*RESET_FROM_ACTOR_HOOK)?;
    transaction.commit();
    ADMITTED.store(true, Ordering::Release);
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Rejection {
    Reference,
    Base,
    Node,
    EmptyLink,
    FormCount,
    Form,
    QuestQuery,
    Cycle,
    InventoryOwner,
    CallScope,
}

/// Prepare one process-lifetime Win32 slot, without a PE TLS variable/callback.
fn prepare_call_scope() -> Result<()> {
    ensure!(
        CALL_SCOPE_HEALTHY.load(Ordering::Acquire),
        "inventory call scope is unhealthy"
    );
    if CALL_SCOPE_SLOT.get().is_none() {
        CALL_SCOPE_SLOT
            .set(ThreadLocalSlot::allocate()?)
            .map_err(|_| anyhow::anyhow!("inventory call scope is already initialized"))?;
    }
    Ok(())
}

/// Psycho-owned metadata, borrowed only while the associated provider runs.
/// Cell permits same-thread nested hooks to mark otherwise shared stack frames.
struct CallFrame {
    reference: *mut c_void,
    parent: Cell<*mut c_void>,
    rejected: Cell<bool>,
}

impl CallFrame {
    fn new(reference: *mut c_void) -> Self {
        Self {
            reference,
            parent: Cell::new(std::ptr::null_mut()),
            rejected: Cell::new(false),
        }
    }
}

/// Keep the frame immovable/borrowed until the preceding TLS value is restored.
struct CallScope<'a> {
    frame: &'a CallFrame,
    slot: ThreadLocalSlot,
    previous: *mut c_void,
}

impl<'a> CallScope<'a> {
    fn enter(frame: &'a CallFrame) -> Option<Self> {
        if !CALL_SCOPE_HEALTHY.load(Ordering::Acquire) {
            return None;
        }
        let slot = *CALL_SCOPE_SLOT.get()?;
        let error = get_last_error_code();
        let previous = slot.get();
        frame.parent.set(previous);
        let installed = slot
            .set((frame as *const CallFrame).cast_mut().cast())
            .is_ok();
        set_last_error(error);
        if !installed {
            CALL_SCOPE_HEALTHY.store(false, Ordering::Release);
            return None;
        }
        Some(Self {
            frame,
            slot,
            previous,
        })
    }

    fn rejected(&self) -> bool {
        self.frame.rejected.get()
    }
}

impl Drop for CallScope<'_> {
    fn drop(&mut self) {
        let error = get_last_error_code();
        if self.slot.set(self.previous).is_err() {
            // Never dereference a possibly stale stack frame after TLS failure.
            // Active bridges and later entries fail closed without reading it.
            CALL_SCOPE_HEALTHY.store(false, Ordering::Release);
        }
        set_last_error(error);
    }
}

fn reject_scoped_calls(reference: *mut c_void) {
    if !CALL_SCOPE_HEALTHY.load(Ordering::Acquire) {
        return;
    }
    let Some(slot) = CALL_SCOPE_SLOT.get() else {
        return;
    };
    let error = get_last_error_code();
    let mut current = slot.get();
    while !current.is_null() {
        // SAFETY: Only this module writes this private slot. Each published
        // frame remains borrowed on this thread's synchronous provider stack;
        // parent links contain the previous value, restored before unborrowing.
        // A failed restoration poisons the scope before another dereference.
        let frame = unsafe { &*current.cast::<CallFrame>() };
        if frame.reference == reference {
            frame.rejected.set(true);
        }
        current = frame.parent.get();
    }
    set_last_error(error);
}

fn read<const N: usize>(address: usize) -> Option<[u8; N]> {
    address.checked_add(N.checked_sub(1)?)?;
    let mut bytes = [0; N];
    read_current_process_memory(address, &mut bytes).ok()?;
    Some(bytes)
}

fn word(address: usize, offset: usize) -> Option<usize> {
    let bytes = read::<4>(address.checked_add(offset)?)?;
    Some(u32::from_le_bytes(bytes) as usize)
}

/// Validate the base container actually consumed by the reference getter.
///
/// None preserves native no-container handling. The actor and container
/// offsets are established by 0x0055D310 and the head accessor 0x00717E50.
fn admit_base(reference: usize) -> Result<bool, Rejection> {
    let base = word(reference, BASE_OFFSET).ok_or(Rejection::Reference)?;
    if base == 0 {
        return Ok(false);
    }
    let kind_address = base.checked_add(FORM_TYPE_OFFSET).ok_or(Rejection::Base)?;
    let [kind] = read::<1>(kind_address).ok_or(Rejection::Base)?;
    let offset = match kind {
        0x1B => 0x34,
        0x2A | 0x2B => 0x68,
        _ => return Ok(false),
    };
    admit_list(base.checked_add(offset).ok_or(Rejection::Base)?)?;
    Ok(true)
}

/// Validate every base entry before any owner may begin resetting inventory.
///
/// Native empty terminal nodes are accepted. A NULL data word with a live
/// successor is not empty to 0x008256D0 and would be dereferenced by reset.
fn admit_list(mut node: usize) -> Result<(), Rejection> {
    let mut checkpoint = node;
    let mut power = 1usize;
    let mut span = 0usize;
    while node != 0 {
        let fields = read::<8>(node).ok_or(Rejection::Node)?;
        let data =
            u32::from_le_bytes(fields[..4].try_into().map_err(|_| Rejection::Node)?) as usize;
        let next =
            u32::from_le_bytes(fields[4..].try_into().map_err(|_| Rejection::Node)?) as usize;
        if data == 0 {
            return if next == 0 {
                Ok(())
            } else {
                Err(Rejection::EmptyLink)
            };
        }
        // Reset also consumes count and the extra-data pointer. Require the
        // complete native FormCount prefix, not only its form-pointer word.
        let record = read::<12>(data).ok_or(Rejection::FormCount)?;
        let form = u32::from_le_bytes([record[4], record[5], record[6], record[7]]) as usize;
        let vtable = word(form, 0).ok_or(Rejection::Form)?;
        let callback = word(vtable, QUEST_QUERY_OFFSET).ok_or(Rejection::QuestQuery)?;
        if !virtual_query(callback as *mut c_void).is_ok_and(|page| page.is_executable()) {
            return Err(Rejection::QuestQuery);
        }
        node = next;
        if node != 0 && node == checkpoint {
            return Err(Rejection::Cycle);
        }
        span = span.checked_add(1).ok_or(Rejection::Cycle)?;
        if span == power {
            checkpoint = node;
            power = power.saturating_mul(2);
            span = 0;
        }
    }
    Ok(())
}

/// Admit both the reference's base and the existing inventory owner's base.
///
/// Safety: reference and its embedded ExtraDataList retain the native caller's
/// initialized-object lifetime. The nonallocating existing-inventory getter
/// uses that same list and native synchronization; it may update lookup cache
/// state, but creates no inventory and changes no item/owner/reference count.
unsafe fn admit_reference(reference: *mut c_void) -> Result<(), Rejection> {
    if !admit_base(reference as usize)? {
        return Ok(());
    }
    let extra = (reference as usize)
        .checked_add(EXTRA_LIST_OFFSET)
        .ok_or(Rejection::Reference)?;
    // SAFETY: 0x00418520 is the thiscall existing-Data getter used by vanilla
    // reset. It takes the caller-owned embedded ExtraDataList, returns Data
    // or NULL, has plain RET, and does not create missing inventory.
    let get: ExistingInventory = unsafe { std::mem::transmute(EXISTING_INVENTORY_ADDRESS) };
    let inventory = unsafe { get(extra as *mut c_void) } as usize;
    if inventory != 0 {
        let owner = word(inventory, 4).ok_or(Rejection::InventoryOwner)?;
        // The normal Data owner is this reference, whose base was just checked
        // under this call's native lifetime. Avoid walking that list twice.
        if owner != reference as usize && !admit_base(owner)? {
            // The Data predicate unconditionally adds four to the resulting
            // container, so native no-container handling is unavailable here.
            return Err(Rejection::InventoryOwner);
        }
    }
    Ok(())
}

fn report(reference: *mut c_void, reason: Rejection) {
    reject_scoped_calls(reference);
    // A shared operation does not own the current changed-record pointer.
    // The save owner only latches whole-load failure on its own thread.
    super::save_integrity::reject_inventory_reset_during_load();
    if !REPORTED.swap(true, Ordering::Relaxed) {
        log::warn!(
            "[INVENTORY_RESET] Rejected unsafe inventory processing; reset skipped: reference=0x{:08X}, reason={reason:?}",
            reference as usize,
        );
    }
}

/// Execute admission and restore the caller's Win32 last error on either path.
///
/// Safety: inherits the native reference/extra-list lifetime, as admit_reference.
unsafe fn admit_operation(reference: *mut c_void) -> bool {
    let previous_error = get_last_error_code();
    // SAFETY: The caller supplies the native operation's object lifetime.
    let admission = if CALL_SCOPE_HEALTHY.load(Ordering::Acquire) {
        unsafe { admit_reference(reference) }
    } else {
        Err(Rejection::CallScope)
    };
    let admitted = match admission {
        Ok(()) => true,
        Err(reason) => {
            report(reference, reason);
            false
        }
    };
    set_last_error(previous_error);
    admitted
}

/// Preserve uncertain quest inventory rather than expose it to native deletion.
unsafe extern "thiscall" fn query(reference: *mut c_void) -> u8 {
    // SAFETY: The hook inherits the native reference and extra-list lifetime.
    if ADMITTED.load(Ordering::Acquire) && !unsafe { admit_operation(reference) } {
        return 1;
    }
    let provider = QUERY_PROVIDER.load(Ordering::Acquire);
    if provider.is_null() {
        return 1;
    }
    // SAFETY: A process-lifetime trampoline is published before activation.
    let original: Query = unsafe { std::mem::transmute(provider) };
    unsafe { original(reference) }
}

/// Reject the entire inventory reset before its first query or mutation.
unsafe extern "thiscall" fn reset(reference: *mut c_void, mode: u8) {
    // SAFETY: Native reset supplies the documented thiscall input lifetime.
    unsafe { guarded_reset(&RESET_PROVIDER, reference, mode) };
}

/// Reject actor refresh before callbacks, reset and subsequent equipment work.
unsafe extern "thiscall" fn refresh(reference: *mut c_void, mode: u8) {
    // SAFETY: Native actor refresh supplies the same reference lifetime.
    unsafe { guarded_reset(&ACTOR_PROVIDER, reference, mode) };
}

/// Chain the native reset entry, retaining later providers and scoped rejection.
unsafe extern "thiscall" fn reset_with_result(reference: *mut c_void, mode: u8) -> bool {
    let provider = RESET_CALL_PROVIDER.load(Ordering::Acquire);
    if provider.is_null() {
        return !ADMITTED.load(Ordering::Acquire);
    }
    // SAFETY: Captured CALL target retains the native Reset ABI. Calling its
    // entry, rather than the inline trampoline, preserves later provider chains.
    let original: Reset = unsafe { std::mem::transmute(provider) };
    if !ADMITTED.load(Ordering::Acquire) {
        unsafe { original(reference, mode) };
        return true;
    }
    let frame = CallFrame::new(reference);
    let Some(scope) = CallScope::enter(&frame) else {
        let error = get_last_error_code();
        report(reference, Rejection::CallScope);
        set_last_error(error);
        return false;
    };
    unsafe { original(reference, mode) };
    let rejected = scope.rejected();
    drop(scope);
    !rejected && CALL_SCOPE_HEALTHY.load(Ordering::Acquire)
}

/// AL retains the native query result; bit 8 is private continuation rejection.
unsafe extern "thiscall" fn query_with_result(reference: *mut c_void) -> u32 {
    let provider = QUERY_CALL_PROVIDER.load(Ordering::Acquire);
    if provider.is_null() {
        return if ADMITTED.load(Ordering::Acquire) {
            0x101
        } else {
            1
        };
    }
    // SAFETY: Captured CALL target has Query ABI, including later entry hooks.
    let original: Query = unsafe { std::mem::transmute(provider) };
    if !ADMITTED.load(Ordering::Acquire) {
        return u32::from(unsafe { original(reference) });
    }
    let frame = CallFrame::new(reference);
    let Some(scope) = CallScope::enter(&frame) else {
        let error = get_last_error_code();
        report(reference, Rejection::CallScope);
        set_last_error(error);
        return 0x101;
    };
    let result = unsafe { original(reference) };
    let rejected = scope.rejected();
    drop(scope);
    u32::from(result) | (u32::from(rejected || !CALL_SCOPE_HEALTHY.load(Ordering::Acquire)) << 8)
}

/// Bridge only 0x0057493E; rejected query skips all native reset mutations.
/// EBP belongs to the verified 0x00574920 frame, with no saved registers/SEH
/// or local resources to release at this first query boundary.
#[unsafe(naked)]
unsafe extern "thiscall" fn query_from_reset(_reference: *mut c_void) -> u8 {
    core::arch::naked_asm!(
        "call {query}",
        "test eax, 0x100",
        "jz 2f",
        // Exact reset epilogue from 0x00574A7A, including outer mode cleanup.
        "mov esp, ebp",
        "pop ebp",
        "ret 4",
        "2:",
        "ret",
        query = sym query_with_result,
    );
}

/// Bridge only 0x0089FC1F; rejection executes the actor's native epilogue.
///
/// This is not callable as a standalone reset. Its EBP belongs to 0x0089FB80,
/// whose verified frame has no saved registers, SEH or pending local cleanup.
/// A rejected reset must skip the equipment consumers at 0x0089FCC3/0x0089FCE3.
#[unsafe(naked)]
unsafe extern "thiscall" fn reset_from_refresh(_reference: *mut c_void, _mode: u8) {
    core::arch::naked_asm!(
        // Re-push mode: the helper has its own return address and RET 4.
        "push dword ptr [esp + 4]",
        "call {reset}",
        "test al, al",
        "jz 2f",
        // Continue at 0x0089FC24 and consume this bridge's original mode.
        "ret 4",
        "2:",
        // Exact 0x0089FCE8 epilogue. Discard the inner return/mode and all
        // actor locals; RET 4 consumes the outer actor call's argument.
        "mov esp, ebp",
        "pop ebp",
        "ret 4",
        reset = sym reset_with_result,
    );
}

/// Keep admission and forwarding identical for both void reset owners.
unsafe fn guarded_reset(provider: &AtomicPtr<c_void>, reference: *mut c_void, mode: u8) {
    // SAFETY: The native reset/refresh owner supplies its object lifetime.
    if ADMITTED.load(Ordering::Acquire) && !unsafe { admit_operation(reference) } {
        return;
    }
    let provider = provider.load(Ordering::Acquire);
    if provider.is_null() {
        return;
    }
    // SAFETY: Both providers have the verified Reset ABI and process lifetime.
    let original: Reset = unsafe { std::mem::transmute(provider) };
    unsafe { original(reference, mode) };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Support for the retained game failure: execute production admission and
    // the real guarded-copy boundary. These do not recreate an engine object,
    // substitute a native provider, or establish gameplay acceptance.
    #[test]
    fn unreadable_reference_is_rejected_without_native_lookup() {
        for address in [0usize, 1, usize::MAX - BASE_OFFSET + 1, usize::MAX] {
            // SAFETY: Admission must reject the first guarded read, before it
            // can enter the native getter with an invalid reference.
            assert_eq!(
                unsafe { admit_reference(address as *mut c_void) },
                Err(Rejection::Reference),
            );
        }
    }

    #[test]
    fn rejected_operation_preserves_native_last_error() {
        let previous_error = get_last_error_code();
        for address in [0usize, 1, usize::MAX] {
            set_last_error(0x1234);
            // SAFETY: These addresses reject at the real guarded read before
            // the production operation can invoke any native game accessor.
            assert!(!unsafe { admit_operation(address as *mut c_void) });
            assert_eq!(get_last_error_code(), 0x1234);
        }
        set_last_error(previous_error);
    }

    #[test]
    fn call_scope_propagates_matching_rejection_and_restores_thread_state() {
        prepare_call_scope().expect("prepare real Win32 call scope");
        let error = get_last_error_code();
        let reference_a = &0u8 as *const u8 as *mut c_void;
        let reference_b = &1u8 as *const u8 as *mut c_void;
        // These are opaque identities for Psycho-owned frames, never stand-in
        // engine objects. Execute the production scope and real Win32 TLS.
        let outer = CallFrame::new(reference_a);
        let outer_scope = CallScope::enter(&outer).expect("enter outer provider scope");
        let unrelated = CallFrame::new(reference_b);
        let unrelated_scope = CallScope::enter(&unrelated).expect("enter unrelated scope");
        let inner = CallFrame::new(reference_a);
        let inner_scope = CallScope::enter(&inner).expect("enter nested query scope");
        set_last_error(0x4321);
        reject_scoped_calls(reference_a);
        assert_eq!(get_last_error_code(), 0x4321);
        assert!(inner_scope.rejected());
        assert!(!unrelated_scope.rejected());
        assert!(outer_scope.rejected());
        std::thread::spawn(|| {
            let slot = *CALL_SCOPE_SLOT.get().expect("published call scope");
            assert!(slot.get().is_null());
        })
        .join()
        .expect("join independent native thread");
        set_last_error(0x4321);
        drop(inner_scope);
        assert_eq!(get_last_error_code(), 0x4321);
        drop(unrelated_scope);
        assert_eq!(get_last_error_code(), 0x4321);
        drop(outer_scope);
        assert_eq!(get_last_error_code(), 0x4321);
        assert!(
            CALL_SCOPE_SLOT
                .get()
                .expect("published call scope")
                .get()
                .is_null()
        );
        set_last_error(error);
    }
}
