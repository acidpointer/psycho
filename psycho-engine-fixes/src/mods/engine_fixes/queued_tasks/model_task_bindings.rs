//! Reject invalid task values before native reference-map acquisition.
//!
//! Private acquisition stage of the parent's `queued_task_lifetime_guard`;
//! the parent owns installation and the shared configuration switch.
//!
//! Four typed assignment callers retain value+8 before the priority guard.
//! They run under the map's recursive exclusive lock with a published node
//! hazard. Rejection clears only that node's invalid value, without releasing
//! the replacement object, and returns through the native hazard-cleanup tail.
//! Iteration skips the rejected entry; lookup takes the native miss result.
//! The shared templates also serve other maps. Owner-side changes apply only
//! to the published ModelLoader+8 reference map, whose borrowed integer keys
//! need no dereference or retention during deferred cleanup.
//!
//! Erasure reuses the per-thread native cursor, so it must wait for every
//! active acquisition on that map to return. Thread-local stack scopes stage
//! keys in the oldest same-map call. At its boundary, locked non-owning search
//! removes only a still-empty binding through the current native erase slot.
//! A concurrently published valid value is preserved. No node links, native
//! ownership counts, allocator state, or third-party code are edited.
//!
//! RTTI rejects the proven NiObject view, whose count is at +4, rather than
//! allowlisting task vtables or callback code. Missing/unsupported RTTI chains
//! the installed provider. Snapshots neither pin an allocation nor establish
//! its generation; the original invalidating owner remains unresolved.
//!
//! Installation is transactional at quiescent core startup. One dynamically
//! resolved Win32 TLS slot owns a process-lifetime four-byte state per calling
//! thread, allocated only on that thread's first use. Subsequent valid calls
//! allocate, lock, and log nothing extra. Rejection uses bounded stack storage
//! and the native lock for cold cleanup. If scope allocation or staging fails,
//! invalid acquisition is still rejected, but erasure waits for a later call.

use std::{
    alloc::{Layout, alloc, dealloc},
    cell::UnsafeCell,
    ffi::c_void,
    ptr,
    sync::{
        LazyLock, OnceLock,
        atomic::{AtomicBool, AtomicPtr, Ordering},
    },
};

use anyhow::{Context, Result};
use libpsycho::os::windows::{
    guarded_memory::{
        ThreadLocalSlot, prepare_current_process_memory_reader, read_current_process_memory,
    },
    hook::{
        callsite::Rel32CallHookContainer, inline::inlinehook::InlineHookContainer,
        transaction::ModificationTransaction,
    },
    winapi::get_current_thread_id,
};

type AssignFn = unsafe extern "thiscall" fn(*mut usize, *const usize) -> *mut usize;
type IterateFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, *mut usize, *mut usize, u8) -> u8;
type LookupFn = unsafe extern "thiscall" fn(*mut c_void, usize, *mut usize) -> u8;
type SetValueFn = unsafe extern "thiscall" fn(*mut usize, usize) -> *mut usize;
type LockFn = unsafe extern "thiscall" fn(*mut c_void, u32);
type UnlockFn = unsafe extern "thiscall" fn(*mut c_void);
type ContextFn = unsafe extern "thiscall" fn(*mut c_void) -> *mut c_void;
type FindFn = unsafe extern "thiscall" fn(*mut c_void, u32, usize) -> u8;
type ClearHazardsFn = unsafe extern "thiscall" fn(*mut c_void);
type HashFn = unsafe extern "thiscall" fn(*mut c_void, usize) -> u32;
type EraseFn = unsafe extern "thiscall" fn(*mut c_void, usize) -> u8;

const PENDING_CAPACITY: usize = 64;
const MAX_BASES: usize = 64;
const MODEL_LOADER: usize = 0x011C_3B3C;
// Semantic base-type identities in the supported executable, not vtable or
// code admission lists. Name matching also admits duplicated plugin RTTI.
const TASK_TYPE: usize = 0x0118_5594;
const NI_OBJECT_TYPE: usize = 0x0118_54C8;
const TASK_NAME: &[u8] = b".?AV?$BSTask@_J@@\0";
const NI_OBJECT_NAME: &[u8] = b".?AVNiObject@@\0";

static ADMITTED: AtomicBool = AtomicBool::new(false);
static REJECTION_REPORTED: AtomicBool = AtomicBool::new(false);
static CLEANUP_FAILURE_REPORTED: AtomicBool = AtomicBool::new(false);
static SCOPE_SLOT: OnceLock<ThreadLocalSlot> = OnceLock::new();
static ITERATE_HOOK: LazyLock<InlineHookContainer<IterateFn>> =
    LazyLock::new(InlineHookContainer::new);
static LOOKUP_HOOK: LazyLock<InlineHookContainer<LookupFn>> =
    LazyLock::new(InlineHookContainer::new);
static ITERATE_PROVIDER: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static LOOKUP_PROVIDER: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static ASSIGN_HOOKS: LazyLock<[Rel32CallHookContainer<AssignFn>; 4]> =
    LazyLock::new(|| std::array::from_fn(|_| Rel32CallHookContainer::new()));
static ASSIGN_PROVIDERS: [AtomicPtr<c_void>; 4] = [const { AtomicPtr::new(ptr::null_mut()) }; 4];

struct AssignmentSite {
    call: usize,
    frame_depth: usize,
    context_depth: usize,
    node_offset: usize,
    cleanup: usize,
    result: u8,
    shim: AssignFn,
}

const SITES: [AssignmentSite; 4] = [
    AssignmentSite {
        call: 0x906BC8,
        frame_depth: 0x1C,
        context_depth: 0x10,
        node_offset: 0x14,
        cleanup: 0x906BFB,
        result: 1,
        shim: assign_first,
    },
    AssignmentSite {
        call: 0x906CAE,
        frame_depth: 0x10,
        context_depth: 8,
        node_offset: 0x18,
        cleanup: 0x906DA4,
        result: 1,
        shim: assign_next,
    },
    AssignmentSite {
        call: 0x906D5F,
        frame_depth: 0x10,
        context_depth: 8,
        node_offset: 0x14,
        cleanup: 0x906DA4,
        result: 1,
        shim: assign_next_bucket,
    },
    AssignmentSite {
        call: 0x44D546,
        frame_depth: 0x10,
        context_depth: 8,
        node_offset: 0x14,
        cleanup: 0x44D56D,
        result: 0,
        shim: assign_lookup,
    },
];

/// Install pre-retain containment under the existing queued-task guard setting.
///
/// Requires the supported native caller frames and quiescent core startup.
/// Captured providers remain live even if activation rolls back. Unsupported
/// fingerprints or setup failures leave admission false and native state
/// untouched. No game behavior or allocation-generation proof is implied.
pub(super) fn install() -> Result<()> {
    if ADMITTED.load(Ordering::Acquire) {
        return Ok(());
    }
    prepare_current_process_memory_reader().context("prepare task snapshots")?;
    if SCOPE_SLOT.get().is_none() {
        let slot = ThreadLocalSlot::allocate().context("allocate task-map scope slot")?;
        anyhow::ensure!(
            SCOPE_SLOT.set(slot).is_ok(),
            "task-map scope slot already set"
        );
    }
    // SAFETY: These readable main-image seams prove EBP-local ownership,
    // return-slot depth, output argument, and native hazard-cleanup epilogues.
    // Provider CALL displacements and outer entries may already be hooked.
    unsafe {
        super::patching::verify_bytes(
            0x906AF0,
            &[0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x56, 0x89, 0x4D, 0xF0],
        )?;
        for address in [0x906C10, 0x44D510] {
            super::patching::verify_bytes(
                address,
                &[0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0x89, 0x4D, 0xF8],
            )?;
        }
        for site in &SITES {
            super::patching::verify_bytes(
                site.call - 7,
                &[0x83, 0xC0, 0x04, 0x50, 0x8B, 0x4D, 0x10],
            )?;
            super::patching::verify_bytes(
                site.cleanup,
                &[0x8B, 0x4D, 0u8.wrapping_sub(site.context_depth as u8)],
            )?;
            anyhow::ensure!(
                super::patching::relative_call_target(site.cleanup + 3)? == 0x529000,
                "task-map hazard cleanup changed at 0x{:08X}",
                site.cleanup
            );
        }
        super::patching::verify_bytes(
            0x906C03,
            &[0x8A, 0x45, 0xFF, 0x5E, 0x8B, 0xE5, 0x5D, 0xC2, 0x0C, 0x00],
        )?;
        for address in [0x906DAC, 0x44D575] {
            super::patching::verify_bytes(
                address,
                &[0x8A, 0x45, 0xFF, 0x8B, 0xE5, 0x5D, 0xC2, 0x0C, 0x00],
            )?;
        }
        ITERATE_HOOK.init("task_map_iteration", 0x906570 as *mut c_void, iterate)?;
        LOOKUP_HOOK.init("task_map_lookup", 0x44BD60 as *mut c_void, lookup)?;
        for (index, site) in SITES.iter().enumerate() {
            ASSIGN_HOOKS[index].init(
                "task_map_acquisition",
                site.call as *mut c_void,
                site.shim,
            )?;
            ASSIGN_PROVIDERS[index].store(
                ASSIGN_HOOKS[index].original()? as *mut c_void,
                Ordering::Release,
            );
        }
    }
    ITERATE_PROVIDER.store(ITERATE_HOOK.original()? as *mut c_void, Ordering::Release);
    LOOKUP_PROVIDER.store(LOOKUP_HOOK.original()? as *mut c_void, Ordering::Release);
    let mut tx = ModificationTransaction::new();
    tx.enable_inline(&ITERATE_HOOK)?;
    tx.enable_inline(&LOOKUP_HOOK)?;
    for hook in ASSIGN_HOOKS.iter() {
        tx.enable_callsite(hook)?;
    }
    tx.commit();
    ADMITTED.store(true, Ordering::Release);
    log::info!("[QUEUED_TASK] Reference-map pre-retain containment active");
    Ok(())
}

/// Reject unreadable/non-positive task headers and a proven NiObject view.
///
/// Uses guarded snapshots only. Unsupported or absent type metadata admits
/// the existing provider; this is not an allocation pin or generation check.
/// Returns false before the complete hook group has been admitted.
pub(super) fn rejects_task_address(address: usize) -> bool {
    if !ADMITTED.load(Ordering::Acquire) {
        return false;
    }
    if address == 0 || !address.is_multiple_of(4) {
        return true;
    }
    let Some(header) = snapshot::<12>(address) else {
        return true;
    };
    let count = word(&header, 8) as i32;
    count <= 0 || count == i32::MAX || ni_object_view(word(&header, 0) as usize)
}

fn snapshot<const N: usize>(address: usize) -> Option<[u8; N]> {
    let mut bytes = [0; N];
    address.checked_add(N)?;
    read_current_process_memory(address, &mut bytes).ok()?;
    Some(bytes)
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_word(address: usize) -> Option<usize> {
    snapshot::<4>(address).map(|bytes| word(&bytes, 0) as usize)
}

enum BaseType {
    Task,
    NiObject,
    Other,
}

fn base_type(descriptor: usize) -> Option<BaseType> {
    if descriptor == TASK_TYPE {
        return Some(BaseType::Task);
    }
    if descriptor == NI_OBJECT_TYPE {
        return Some(BaseType::NiObject);
    }
    let address = descriptor.checked_add(8)?;
    let bytes = snapshot::<{ TASK_NAME.len() }>(address)?;
    if bytes == TASK_NAME {
        Some(BaseType::Task)
    } else if &bytes[..NI_OBJECT_NAME.len()] == NI_OBJECT_NAME {
        Some(BaseType::NiObject)
    } else {
        Some(BaseType::Other)
    }
}

fn ni_object_view(vtable: usize) -> bool {
    let Some(locator_slot) = vtable.checked_sub(4) else {
        return false;
    };
    let Some(locator) = read_word(locator_slot) else {
        return false;
    };
    let Some(col) = snapshot::<20>(locator) else {
        return false;
    };
    if word(&col, 0) != 0 || word(&col, 8) != 0 {
        return false;
    }
    let view_offset = word(&col, 4);
    let Some(hierarchy) = snapshot::<16>(word(&col, 16) as usize) else {
        return false;
    };
    let count = word(&hierarchy, 8) as usize;
    if word(&hierarchy, 0) != 0 || count == 0 || count > MAX_BASES {
        return false;
    }
    let mut bases = [0u8; MAX_BASES * 4];
    if read_current_process_memory(word(&hierarchy, 12) as usize, &mut bases[..count * 4]).is_err()
    {
        return false;
    }
    let mut ni_view = false;
    // The common task base is last in native ancestry. Visit it first so a
    // proven task view needs only one base descriptor snapshot and no strings.
    for index in (0..count).rev() {
        let Some(base) = snapshot::<28>(word(&bases, index * 4) as usize) else {
            return false;
        };
        if word(&base, 12) != u32::MAX {
            return false;
        } // Virtual-base layout: unknown.
        if word(&base, 8) != view_offset {
            continue;
        }
        match base_type(word(&base, 0) as usize) {
            Some(BaseType::Task) | None => return false,
            Some(BaseType::NiObject) => ni_view = true,
            Some(BaseType::Other) => {}
        }
    }
    ni_view
}

// The TLS payload outlives every stack scope. Scope entry/restoration only
// writes this owned word: no failed TlsSetValue can leave a dangling stack
// pointer. Successful slot publication deliberately retains the tiny payload
// for process lifetime, as the hook and TLS index are never unloaded.
struct ThreadState {
    top: *mut CallScope,
}
struct CallScope {
    previous: *mut CallScope,
    map: usize,
    keys: [usize; PENDING_CAPACITY],
    count: usize,
}

fn thread_state() -> Option<*mut ThreadState> {
    let slot = *SCOPE_SLOT.get()?;
    let existing = slot.get().cast::<ThreadState>();
    if !existing.is_null() {
        return Some(existing);
    }
    let layout = Layout::new::<ThreadState>();
    // SAFETY: A checked allocation, initialized before publication, owned
    // exclusively by this OS thread. There is no native engine callback here.
    let state = unsafe { alloc(layout).cast::<ThreadState>() };
    if state.is_null() {
        cleanup_failure();
        return None;
    }
    unsafe {
        state.write(ThreadState {
            top: ptr::null_mut(),
        });
    }
    if slot.set(state.cast()).is_err() {
        // SAFETY: Publication failed, so no scope or thread can use this block.
        unsafe {
            dealloc(state.cast(), layout);
        }
        cleanup_failure();
        return None;
    }
    Some(state)
}

struct ScopeLease {
    state: *mut ThreadState,
    previous: *mut CallScope,
}
impl Drop for ScopeLease {
    fn drop(&mut self) {
        // SAFETY: Per-thread, process-lifetime state; previous is still owned
        // by an enclosing invocation, or NULL. No callbacks run on restoration.
        unsafe {
            (*self.state).top = self.previous;
        }
    }
}

fn with_scope<T>(map: *mut c_void, invoke: impl FnOnce() -> T) -> T {
    let Some(state) = thread_state() else {
        return invoke();
    };
    // SAFETY: Only this thread accesses its own state. UnsafeCell permits
    // nested native callbacks to stage keys without overlapping Rust borrows.
    let previous = unsafe { (*state).top };
    let scope = UnsafeCell::new(CallScope {
        previous,
        map: map as usize,
        keys: [0; PENDING_CAPACITY],
        count: 0,
    });
    unsafe {
        (*state).top = scope.get();
    }
    let _lease = ScopeLease { state, previous };
    let result = invoke();
    loop {
        // No native frame for this call is active now. Reentrant cleanup
        // stages into the same owning scope and is drained after it returns.
        let key = unsafe {
            let current = &mut *scope.get();
            if current.count == 0 {
                break;
            }
            current.count -= 1;
            current.keys[current.count]
        };
        unsafe {
            cleanup_empty_binding(map, key);
        }
    }
    result
}

fn stage_key(map: usize, key: usize) -> bool {
    let Some(slot) = SCOPE_SLOT.get() else {
        return false;
    };
    let state = slot.get().cast::<ThreadState>();
    if state.is_null() {
        cleanup_failure();
        return false;
    }
    // SAFETY: Every link belongs to this thread's live with_scope stack. Walk
    // to the oldest same-map call so native cursor reuse cannot invalidate an
    // earlier acquisition. No Rust reference survives a provider callback.
    unsafe {
        let mut cursor = (*state).top;
        let mut owner = ptr::null_mut();
        while !cursor.is_null() {
            if (*cursor).map == map {
                owner = cursor;
            }
            cursor = (*cursor).previous;
        }
        if owner.is_null() {
            cleanup_failure();
            return false;
        }
        let scope = &mut *owner;
        if scope.keys[..scope.count].contains(&key) {
            return true;
        }
        if scope.count == PENDING_CAPACITY {
            cleanup_failure();
            return false;
        }
        scope.keys[scope.count] = key;
        scope.count += 1;
    }
    true
}

fn cleanup_failure() {
    if !CLEANUP_FAILURE_REPORTED.swap(true, Ordering::Relaxed) {
        log::warn!(
            "[QUEUED_TASK] Invalid task rejected; map cleanup deferred until a later acquisition"
        );
    }
}

fn is_reference_map(map: usize) -> bool {
    read_word(MODEL_LOADER)
        .filter(|loader| *loader != 0)
        .and_then(|loader| loader.checked_add(8))
        .and_then(read_word)
        == Some(map)
}

fn has_map_scope(map: usize) -> bool {
    let Some(slot) = SCOPE_SLOT.get() else {
        return false;
    };
    let state = slot.get().cast::<ThreadState>();
    if state.is_null() {
        return false;
    }
    // SAFETY: Same exclusively owned, live per-thread scope chain as stage_key.
    unsafe {
        let mut cursor = (*state).top;
        while !cursor.is_null() {
            if (*cursor).map == map {
                return true;
            }
            cursor = (*cursor).previous;
        }
    }
    false
}

unsafe extern "thiscall" fn iterate(
    map: *mut c_void,
    iterator: *mut c_void,
    key: *mut usize,
    output: *mut usize,
    advance: u8,
) -> u8 {
    // SAFETY: Published before activation; preserves the installed ABI and
    // receiver/output lifetimes. Native noncanonical AL results are preserved.
    let original: IterateFn =
        unsafe { std::mem::transmute(ITERATE_PROVIDER.load(Ordering::Acquire)) };
    if !ADMITTED.load(Ordering::Acquire) || !is_reference_map(map as usize) {
        return unsafe { original(map, iterator, key, output, advance) };
    }
    loop {
        let result = with_scope(map, || unsafe {
            original(map, iterator, key, output, advance)
        });
        // A rejected native result advances the iterator's saved key but has
        // no task. Continue from that key, including the rest of its bucket.
        if result == 0 || unsafe { output.read() != 0 } {
            return result;
        }
    }
}

unsafe extern "thiscall" fn lookup(map: *mut c_void, key: usize, output: *mut usize) -> u8 {
    let original: LookupFn =
        unsafe { std::mem::transmute(LOOKUP_PROVIDER.load(Ordering::Acquire)) };
    if !ADMITTED.load(Ordering::Acquire) || !is_reference_map(map as usize) {
        return unsafe { original(map, key, output) };
    }
    with_scope(map, || unsafe { original(map, key, output) })
}

// Each shim captures the native caller's EBP before Rust creates a frame.
// thiscall(dst, src) and fastcall(dst, EBP, src) both consume four stack bytes.
macro_rules! assignment_shim {
    ($shim:ident, $body:ident, $index:expr) => {
        #[unsafe(naked)]
        unsafe extern "thiscall" fn $shim(_destination: *mut usize, _source: *const usize) -> *mut usize {
            core::arch::naked_asm!("mov edx, ebp", "jmp {}", sym $body);
        }
        unsafe extern "fastcall" fn $body(destination: *mut usize, frame: usize,
            source: *const usize) -> *mut usize {
            unsafe { assign($index, destination, frame, source) }
        }
    };
}
assignment_shim!(assign_first, assign_first_body, 0);
assignment_shim!(assign_next, assign_next_body, 1);
assignment_shim!(assign_next_bucket, assign_next_bucket_body, 2);
assignment_shim!(assign_lookup, assign_lookup_body, 3);

unsafe fn assign(
    index: usize,
    destination: *mut usize,
    frame: usize,
    source: *const usize,
) -> *mut usize {
    let original: AssignFn =
        unsafe { std::mem::transmute(ASSIGN_PROVIDERS[index].load(Ordering::Acquire)) };
    if !ADMITTED.load(Ordering::Acquire) {
        return unsafe { original(destination, source) };
    }
    let site = &SITES[index];
    // SAFETY: The fingerprinted native frame has already used this live map
    // context to select and publish the source node. Its first word is the
    // receiver owned by the enclosing map operation, not external task data.
    let map = unsafe {
        let context = (frame.wrapping_sub(site.context_depth) as *const usize).read();
        (context as *const usize).read()
    };
    // Existing scopes retain the exact receiver even if the singleton changes
    // during a nested call. On TLS allocation failure, the published owner
    // still authorizes rejection, while repair is deferred without node edits.
    if !has_map_scope(map) && !is_reference_map(map) {
        return unsafe { original(destination, source) };
    }
    // SAFETY: The source holder and output belong to the native locked node
    // and caller respectively. The external object itself is only snapshotted.
    let value = unsafe { source.read() };
    if !rejects_task_address(value) {
        return unsafe { original(destination, source) };
    }
    unsafe {
        invalidate_binding(site, frame, source, value);
    }
    if site.result != 0 {
        // Native iteration must expose NULL so the outer wrapper skips this
        // entry. Preserve the ownership release of a valid prior output; never
        // release an invalid prior value as if it were a task.
        let previous = unsafe { destination.read() };
        if previous != 0 && !rejects_task_address(previous) {
            let set_value: SetValueFn = unsafe { std::mem::transmute(0x6F74F0usize) };
            unsafe {
                set_value(destination, 0);
            }
        } else {
            unsafe {
                destination.write(0);
            }
        }
    }
    // SAFETY: Verified prologue/local layout and CALL stack depth. Returning
    // through the native tail clears its hazards and restores nonvolatiles.
    // Lookup miss deliberately preserves its caller's previous output holder.
    unsafe {
        (frame.wrapping_sub(1) as *mut u8).write(site.result);
        (frame.wrapping_sub(site.frame_depth) as *mut usize).write(site.cleanup);
    }
    if !REJECTION_REPORTED.swap(true, Ordering::Relaxed) {
        log::warn!(
            "[QUEUED_TASK] Invalid map task rejected before retention; native acquisition skips the binding"
        );
    }
    destination
}

unsafe fn invalidate_binding(
    site: &AssignmentSite,
    frame: usize,
    source: *const usize,
    value: usize,
) {
    let Some(node) = (source as usize).checked_sub(4) else {
        cleanup_failure();
        return;
    };
    let Some(node_bytes) = snapshot::<12>(node) else {
        cleanup_failure();
        return;
    };
    // SAFETY: The verified native frame owns this context local.
    let context = unsafe { (frame.wrapping_sub(site.context_depth) as *const usize).read() };
    let Some(ctx) = snapshot::<28>(context) else {
        cleanup_failure();
        return;
    };
    let map = word(&ctx, 0) as usize;
    let selected = (word(&ctx, site.node_offset) & !1) as usize;
    let Some(lock_address) = map.checked_add(0x20) else {
        cleanup_failure();
        return;
    };
    let Some(lock) = snapshot::<8>(lock_address) else {
        cleanup_failure();
        return;
    };
    if selected != node
        || word(&node_bytes, 4) as usize != value
        || word(&lock, 0) != get_current_thread_id()
        || word(&lock, 4) == 0
        || !stage_key(map, word(&node_bytes, 0) as usize)
    {
        cleanup_failure();
        return;
    }
    // SAFETY: Native context identifies exactly this hazard-protected node,
    // its owning exclusive lock is held by this thread, and the value matches
    // our snapshot. Clear only the invalid payload, never decrement its object
    // or edit node links. Native erasure subsequently encounters an empty holder.
    unsafe {
        (source as *mut usize).write(0);
    }
}

struct NativeLock(*mut c_void);
impl Drop for NativeLock {
    fn drop(&mut self) {
        // SAFETY: Paired native recursive acquisition on this same thread.
        let unlock: UnlockFn = unsafe { std::mem::transmute(0x40FBA0usize) };
        unsafe {
            unlock(self.0);
        }
    }
}

unsafe fn cleanup_empty_binding(map: *mut c_void, key: usize) {
    // SAFETY: The owning scope's map receiver is still live. This runs only
    // after all native acquisition frames on this map have returned. Current
    // native entry providers and map slots are invoked with their proven ABI.
    let lock_pointer = unsafe { map.cast::<u8>().add(0x20).cast::<c_void>() };
    let lock: LockFn = unsafe { std::mem::transmute(0x40FBF0usize) };
    unsafe {
        lock(lock_pointer, 0);
    }
    let _lock = NativeLock(lock_pointer);
    let context_fn: ContextFn = unsafe { std::mem::transmute(0x449F80usize) };
    let context = unsafe { context_fn(map) };
    let clear: ClearHazardsFn = unsafe { std::mem::transmute(0x529000usize) };
    let Some(ctx) = snapshot::<28>(context as usize) else {
        cleanup_failure();
        return;
    };
    if word(&ctx, 0) as usize != map as usize {
        cleanup_failure();
        return;
    }
    let Some(vtable) = read_word(map as usize) else {
        cleanup_failure();
        return;
    };
    let Some(hash_address) = vtable.checked_add(0x24).and_then(read_word) else {
        cleanup_failure();
        return;
    };
    let Some(erase_address) = vtable.checked_add(0x14).and_then(read_word) else {
        cleanup_failure();
        return;
    };
    if hash_address == 0 || erase_address == 0 {
        cleanup_failure();
        return;
    }
    let hash: HashFn = unsafe { std::mem::transmute(hash_address) };
    let find: FindFn = unsafe { std::mem::transmute(0x529030usize) };
    let erase: EraseFn = unsafe { std::mem::transmute(erase_address) };
    let bucket = unsafe { hash(map, key) };
    let found = unsafe { find(context, bucket, key) };
    let empty = if found != 0 {
        read_word(context as usize + 0x14)
            .and_then(|node| snapshot::<12>(node & !1))
            .is_some_and(|node| word(&node, 0) as usize == key && word(&node, 4) == 0)
    } else {
        false
    };
    // Do not let the erase provider reuse a live search hazard/cursor.
    unsafe {
        clear(context);
    }
    if empty {
        unsafe {
            erase(map, key);
        }
    }
}
