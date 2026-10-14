//! Bounded generations and root/texture associations for owning queue candidates.
//!
//! The registry owns copied identities, never native tasks, blocks or nodes.
//! Constructors invalidate reused addresses; cancellation removes only the
//! supplied parent's interest for shared children; destruction invalidates the
//! instance. Publishers complete under this mutex without engine calls. Demand
//! visibility uses the scheduler's atomics. Capacity exhaustion disarms queued
//! promotion until world reset; it never drops a required lifetime invalidation.
//! Cancellation observation runs only after the native self-reference is acquired
//! and before it is released. Entry observers must not delay that acquisition.
//! Parent/child and node/root indexes are updated together under the same mutex.
//! Invalidation follows affected adjacency only and never allocates or scans the
//! whole registry. Link/root publication reserves every new index entry before
//! mutation; capacity/allocation failure clears all indexes and disarms promotion.

use super::{
    native::{Site, word},
    scheduler,
    service::Deadline,
};
use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::{
        hook::{inline::inlinehook::InlineHookContainer, transaction::ModificationTransaction},
        winapi::tls_get_value,
    },
};
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    ffi::c_void,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

const TASK_LIMIT: usize = 16384;
const EDGE_LIMIT: usize = 8192;
const SCAN_LIMIT: usize = 32;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Token {
    address: usize,
    generation: u64,
}
#[derive(Clone, Copy)]
struct Root {
    kind: usize,
    node: usize,
}
struct Record {
    generation: u64,
    root: Option<Root>,
    promoted: bool,
    created: Option<i64>,
    queued: Option<i64>,
    children: Vec<Token>,
}
struct Registry {
    generation: u64,
    records: HashMap<usize, Record>,
    parents: HashMap<usize, Vec<Token>>,
    nodes: HashMap<usize, Vec<Token>>,
    edges: usize,
    disarmed: bool,
    allocation_failures: u64,
    #[cfg(test)]
    invalidation_visits: usize,
}
impl Registry {
    fn new() -> Self {
        Self {
            generation: 0,
            records: HashMap::new(),
            parents: HashMap::new(),
            nodes: HashMap::new(),
            edges: 0,
            disarmed: false,
            allocation_failures: 0,
            #[cfg(test)]
            invalidation_visits: 0,
        }
    }
    fn invalidate(&mut self, address: usize) {
        let record = self.records.remove(&address);
        let parents = self.parents.remove(&address).unwrap_or_default();
        self.edges = self.edges.saturating_sub(parents.len());
        let Some(record) = record else {
            // Every edge publication creates its child record first. Losing
            // that invariant cannot leave usable generation associations.
            if !parents.is_empty() {
                self.disarm();
            }
            return;
        };
        let token = Token {
            address,
            generation: record.generation,
        };
        if let Some(root) = record.root {
            self.remove_node(root.node, token);
        }
        for parent in parents {
            #[cfg(test)]
            {
                self.invalidation_visits += 1;
            }
            self.remove_child(parent, token);
        }
        for child in record.children {
            #[cfg(test)]
            {
                self.invalidation_visits += 1;
            }
            // A self-edge, if present, was removed with incoming associations.
            if child.address != address {
                self.remove_parent(child, token);
            }
        }
    }

    fn remove_node(&mut self, node: usize, token: Token) {
        if let Some(roots) = self.nodes.get_mut(&node) {
            roots.retain(|root| *root != token);
            if roots.is_empty() {
                self.nodes.remove(&node);
            }
        }
    }

    fn remove_child(&mut self, parent: Token, child: Token) {
        if let Some(record) = self
            .records
            .get_mut(&parent.address)
            .filter(|record| record.generation == parent.generation)
        {
            #[cfg(test)]
            {
                self.invalidation_visits += record.children.len();
            }
            record.children.retain(|token| *token != child);
        }
    }

    fn remove_parent(&mut self, child: Token, parent: Token) {
        // Address reuse invalidates both directions before a new record exists.
        // A stale adjacency token cannot remove another generation's interest.
        if !self
            .records
            .get(&child.address)
            .is_some_and(|record| record.generation == child.generation)
        {
            return;
        }
        if let Some(parents) = self.parents.get_mut(&child.address) {
            let before = parents.len();
            #[cfg(test)]
            {
                self.invalidation_visits += before;
            }
            parents.retain(|token| *token != parent);
            self.edges = self.edges.saturating_sub(before - parents.len());
            if parents.is_empty() {
                self.parents.remove(&child.address);
            }
        }
    }

    fn allocation_failed(&mut self) {
        self.allocation_failures = self.allocation_failures.saturating_add(1);
        self.disarm();
    }
    fn record(&mut self, address: usize) -> Option<Token> {
        if self.disarmed || address == 0 {
            return None;
        }
        if !self.records.contains_key(&address) {
            if self.records.len() == TASK_LIMIT {
                self.disarm();
                return None;
            }
            if self.records.try_reserve(1).is_err() {
                self.allocation_failed();
                return None;
            }
            self.generation = self.generation.wrapping_add(1).max(1);
            self.records.insert(
                address,
                Record {
                    generation: self.generation,
                    root: None,
                    promoted: false,
                    created: None,
                    queued: None,
                    children: Vec::new(),
                },
            );
        }
        self.records.get(&address).map(|r| Token {
            address,
            generation: r.generation,
        })
    }
    fn root(&mut self, address: usize, kind: usize, node: usize) {
        if node == 0 {
            return;
        }
        let Some(token) = self.record(address) else {
            return;
        };
        let previous = self.records.get(&address).and_then(|record| record.root);
        let indexed = self
            .nodes
            .get(&node)
            .is_some_and(|roots| roots.contains(&token));
        if !indexed {
            if !self.nodes.contains_key(&node) && self.nodes.try_reserve(1).is_err() {
                self.allocation_failed();
                return;
            }
            if self.nodes.entry(node).or_default().try_reserve(1).is_err() {
                self.allocation_failed();
                return;
            }
        }
        if let Some(previous) = previous
            && previous.node != node
        {
            self.remove_node(previous.node, token);
        }
        // record() succeeded and no operation above removes a record unless
        // it returns on disarm. Both entries remain owned by this mutex.
        let Some(record) = self.records.get_mut(&address) else {
            self.disarm();
            return;
        };
        record.root = Some(Root { kind, node });
        record.created = super::metrics::stamp();
        if !indexed {
            let Some(roots) = self.nodes.get_mut(&node) else {
                self.disarm();
                return;
            };
            roots.push(token);
        }
    }
    fn link(&mut self, parent: usize, child: usize) {
        let Some(parent_token) = self
            .records
            .get(&parent)
            .filter(|r| r.root.is_some())
            .map(|r| Token {
                address: parent,
                generation: r.generation,
            })
        else {
            return;
        };
        let Some(child_token) = self.record(child) else {
            return;
        };
        if self
            .parents
            .get(&child)
            .is_some_and(|parents| parents.contains(&parent_token))
        {
            return;
        }
        if self.edges == EDGE_LIMIT {
            self.disarm();
            return;
        }
        if !self.parents.contains_key(&child) && self.parents.try_reserve(1).is_err() {
            self.allocation_failed();
            return;
        }
        if self
            .parents
            .entry(child)
            .or_default()
            .try_reserve(1)
            .is_err()
        {
            self.allocation_failed();
            return;
        }
        let Some(record) = self.records.get_mut(&parent) else {
            self.disarm();
            return;
        };
        if record.children.try_reserve(1).is_err() {
            self.allocation_failed();
            return;
        }
        // Both vectors have capacity before either direction is published.
        // The parent was verified before record(child), which cannot remove it
        // on success; the child was created above. No engine call runs here.
        let Some(parents) = self.parents.get_mut(&child) else {
            self.disarm();
            return;
        };
        parents.push(parent_token);
        let Some(record) = self.records.get_mut(&parent) else {
            self.disarm();
            return;
        };
        record.children.push(child_token);
        self.edges += 1;
    }
    fn cancel(&mut self, address: usize, parent: usize) {
        if parent == 0 {
            self.invalidate(address);
        } else {
            let parent_token = self
                .parents
                .get(&address)
                .and_then(|parents| parents.iter().find(|token| token.address == parent))
                .copied();
            let child_token = self.records.get(&address).map(|record| Token {
                address,
                generation: record.generation,
            });
            if let (Some(parent), Some(child)) = (parent_token, child_token) {
                self.remove_parent(child, parent);
                self.remove_child(parent, child);
            }
        }
    }
    fn visible(&self, address: usize, visible: impl Fn(Root) -> bool) -> Option<Token> {
        if self.disarmed {
            return None;
        }
        let record = self.records.get(&address)?;
        if record.promoted {
            return None;
        }
        let wanted = record.root.is_some_and(&visible)
            || self.parents.get(&address).is_some_and(|parents| {
                parents.iter().any(|parent| {
                    self.records.get(&parent.address).is_some_and(|r| {
                        r.generation == parent.generation && r.root.is_some_and(&visible)
                    })
                })
            });
        wanted.then_some(Token {
            address,
            generation: record.generation,
        })
    }
    fn promoted(&mut self, token: Token) {
        if let Some(record) = self
            .records
            .get_mut(&token.address)
            .filter(|r| r.generation == token.generation)
        {
            record.promoted = true;
        }
    }
    fn node_reused(&mut self, node: usize) {
        let Some(roots) = self.nodes.remove(&node) else {
            return;
        };
        for token in roots {
            if self.records.get(&token.address).is_some_and(|record| {
                record.generation == token.generation
                    && record.root.is_some_and(|root| root.node == node)
            }) {
                self.invalidate(token.address);
            }
        }
    }
    fn disarm(&mut self) {
        self.disarmed = true;
        self.records.clear();
        self.parents.clear();
        self.nodes.clear();
        self.edges = 0;
    }
    fn reset(&mut self) {
        self.records.clear();
        self.parents.clear();
        self.nodes.clear();
        self.edges = 0;
        self.disarmed = false;
        self.generation = self.generation.wrapping_add(1).max(1);
    }
}
static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| Mutex::new(Registry::new()));
static ADMITTED: AtomicBool = AtomicBool::new(false);
static INSTALLED: AtomicBool = AtomicBool::new(false);
static PROMOTED: AtomicU64 = AtomicU64::new(0);
static FAILED: AtomicU64 = AtomicU64::new(0);
static UNKNOWN_PROVIDER: AtomicU64 = AtomicU64::new(0);
static MISSING_TLS: AtomicU64 = AtomicU64::new(0);
static BUSY: AtomicU64 = AtomicU64::new(0);
type Constructor = unsafe extern "thiscall" fn(*mut c_void, u32) -> *mut c_void;
type Destructor = unsafe extern "thiscall" fn(*mut c_void);
type Link = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);
static BIRTH: LazyLock<InlineHookContainer<Constructor>> = LazyLock::new(InlineHookContainer::new);
static DEATH: LazyLock<InlineHookContainer<Destructor>> = LazyLock::new(InlineHookContainer::new);
static CANCEL_PIN: Site = Site::new(
    "lod_task_cancel_retained",
    0xC3CB89,
    &[0xFF, 0x15, 0xC0, 0xF1, 0xFD, 0x00],
    false,
);
static CANCEL_END: Site = Site::new(
    "lod_task_cancel_release",
    0xC3CE44,
    &[0x8B, 0x8D, 0x58, 0xFF, 0xFF, 0xFF],
    false,
);
static LINK: LazyLock<InlineHookContainer<Link>> = LazyLock::new(InlineHookContainer::new);
static NODE: Site = Site::new(
    "lod_node_reuse",
    0x6FD239,
    &[0x89, 0x4D, 0x80, 0x8B, 0x4D, 0x80],
    false,
);

/// Install all required lifetime observers in the constructor-priority transaction.
pub(super) fn install(tx: &mut ModificationTransaction) -> anyhow::Result<()> {
    unsafe {
        // These splices borrow C3CB70's live frame, not an entry provider's
        // invented frame. Require its exact owner/argument setup. Other entry
        // providers remain untouched; an unknown frame disables this group.
        super::super::patching::verify_bytes(
            0xC3CB70,
            &[
                0x55, 0x8B, 0xEC, 0x81, 0xEC, 0xB0, 0x00, 0x00, 0x00, 0x89, 0x8D, 0x58, 0xFF, 0xFF,
                0xFF, 0x8B, 0x85, 0x58, 0xFF, 0xFF, 0xFF, 0x83, 0xC0, 0x08, 0x50,
            ],
        )?;
        BIRTH.init("lod_task_birth", 0xC3C590 as *mut c_void, birth)?;
        DEATH.init("lod_task_death", 0xC3C620 as *mut c_void, death)?;
        LINK.init("lod_texture_link", 0xC3C700 as *mut c_void, link)?;
    }
    tx.enable_inline(&BIRTH)?;
    tx.enable_inline(&DEATH)?;
    tx.enable_inline(&LINK)?;
    CANCEL_PIN.install(tx, cancel_retained as *const () as usize)?;
    CANCEL_END.install(tx, cancel_release as *const () as usize)?;
    NODE.install(tx, node as *const () as usize)?;
    Ok(())
}

/// Admit queue service only after demand observation and world reset are installed.
pub(super) fn admit(enabled: bool) {
    ADMITTED.store(
        enabled && INSTALLED.load(Ordering::Acquire),
        Ordering::Release,
    );
}

/// Publish lifecycle installation only after its transaction commits.
pub(super) fn installed() {
    INSTALLED.store(true, Ordering::Release);
}

/// Whether every prerequisite for bounded queued promotion has committed.
pub(super) fn is_admitted() -> bool {
    if !ADMITTED.load(Ordering::Acquire) {
        return false;
    }
    let Some(registry) = REGISTRY.try_lock() else {
        BUSY.fetch_add(1, Ordering::Relaxed);
        return false;
    };
    !registry.disarmed
}

/// Whether task/node invalidation is complete, independent of priority policy.
pub(super) fn lifetimes_available() -> bool {
    INSTALLED.load(Ordering::Acquire)
}

/// Record a root while its native constructor still owns the block/node arguments.
pub(super) fn root(task: usize, kind: usize, node: usize) {
    if INSTALLED.load(Ordering::Acquire) {
        REGISTRY.lock().root(task, kind, node);
    }
    super::metrics::root(kind, node);
}

/// Invalidate every association at the established worldspace lifetime boundary.
pub(super) fn reset() {
    REGISTRY.lock().reset();
}

unsafe extern "thiscall" fn birth(task: *mut c_void, priority: u32) -> *mut c_void {
    REGISTRY.lock().invalidate(task as usize);
    unsafe { super::native::original(&BIRTH)(task, priority) }
}
unsafe extern "thiscall" fn death(task: *mut c_void) {
    REGISTRY.lock().invalidate(task as usize);
    unsafe { super::native::original(&DEATH)(task) };
}
#[unsafe(naked)]
unsafe extern "C" fn cancel_retained() {
    // Replay the actual stdcall retain before any Psycho lock or diagnostic.
    // Its argument is already on the native stack. Preserve the returned
    // registers/flags, observe while that reference is held, then resume the
    // native parent test. The current IAT provider remains authoritative.
    core::arch::naked_asm!(
        "call dword ptr [0xFDF1C0]", "pushfd", "pushad", "mov ecx, ebp", "call {}",
        "popad", "popfd", "push 0xC3CB8F", "ret", sym cancel_retained_body
    );
}
unsafe extern "fastcall" fn cancel_retained_body(frame: usize) {
    // Safety: C3CB79 saves the live task at -0xA8; the native retain above
    // protects it through C3CE4A. +0x0C is the original opaque parent argument.
    // Only copied identities enter the registry; no ownership is changed.
    let task = unsafe { word(frame, -0xA8) };
    let parent = unsafe { word(frame, 0xC) };
    let observed = {
        let mut registry = REGISTRY.lock();
        let observed = registry.records.contains_key(&task);
        registry.cancel(task, parent);
        observed
    };
    super::metrics::cancellation_begin(frame, observed);
}
#[unsafe(naked)]
unsafe extern "C" fn cancel_release() {
    // Every cancellation branch reaches C3CE44 before the native final
    // release. Finish optional timing while its frame/self-reference are live.
    core::arch::naked_asm!(
        "pushfd", "pushad", "mov ecx, ebp", "call {}", "popad", "popfd",
        "mov ecx, [ebp - 0xA8]", "push 0xC3CE4A", "ret", sym cancel_release_body
    );
}
unsafe extern "fastcall" fn cancel_release_body(frame: usize) {
    super::metrics::cancellation_finish(frame);
}
unsafe extern "thiscall" fn link(parent: *mut c_void, child: *mut c_void) {
    unsafe { super::native::original(&LINK)(parent, child) };
    // Native own-child array is serialized by its initialization owner. Confirm
    // actual publication rather than interpreting the void provider as success.
    let array = unsafe { word(parent as usize, 0x20) };
    if array == 0 {
        return;
    }
    let count = unsafe { word(array, 8) };
    let data = unsafe { word(array, 4) };
    if data == 0 || count > TASK_LIMIT {
        return;
    }
    if (0..count).any(|index| unsafe { word(data, (index * 4) as isize) } == child as usize) {
        REGISTRY.lock().link(parent as usize, child as usize);
    }
}
#[unsafe(naked)]
unsafe extern "C" fn node() {
    core::arch::naked_asm!("pushfd", "pushad", "call {}", "popad", "popfd",
        "mov [ebp - 0x80], ecx", "mov ecx, [ebp - 0x80]", "push 0x6FD23F", "ret", sym node_body);
}
unsafe extern "fastcall" fn node_body(node: usize) {
    scheduler::invalidate_visible(node);
    REGISTRY.lock().node_reused(node);
    super::metrics::node_reused(node);
}

/// Observe submit-entry while the native owner still owns the task, before a
/// worker can acquire it. Includes the enqueue call's work in queue delay.
pub(super) fn submitted(task: usize, time: Option<i64>) {
    let Some(mut registry) = REGISTRY.try_lock() else {
        super::metrics::dropped();
        return;
    };
    if let Some(record) = registry.records.get_mut(&task) {
        record.queued = time;
        if record.root.is_some() && record.created.is_some() {
            super::metrics::duration(
                super::metrics::Stage::Dependencies,
                record.created.take(),
                time,
            );
        }
    }
}

/// Copy a trace identity from a worker-owned task; no engine access under lock.
pub(super) fn worker_timing(task: usize) -> Option<(bool, Option<i64>)> {
    let registry = REGISTRY.try_lock()?;
    registry
        .records
        .get(&task)
        .map(|record| (record.root.is_some(), record.queued))
}

/// A native intrusive task pin, acquired only by the owning ordered iterator.
struct Pin {
    pointer: *mut c_void,
}
impl Drop for Pin {
    fn drop(&mut self) {
        let clear = unsafe { FnPtr::<unsafe extern "thiscall" fn(*mut *mut c_void, *mut c_void)>::from_address_unchecked(0x6F74F0) }.as_fn();
        unsafe { clear(&mut self.pointer, std::ptr::null_mut()) };
    }
}
#[repr(C)]
struct IteratorState {
    words: [u32; 7],
}
impl IteratorState {
    unsafe fn reset(&mut self) {
        let reset = unsafe {
            FnPtr::<unsafe extern "thiscall" fn(*mut Self, u32)>::from_address_unchecked(0xC42060)
        }
        .as_fn();
        unsafe { reset(self, 0) };
    }
}
impl Drop for IteratorState {
    fn drop(&mut self) {
        let destroy = unsafe {
            FnPtr::<unsafe extern "thiscall" fn(*mut Self, u32)>::from_address_unchecked(0xC40B40)
        }
        .as_fn();
        unsafe { destroy(self, 0) };
    }
}

/// Promote at most one owning candidate within the copied native deadline.
/// Safety: manager is live in the verified ordinary completion-service frame.
pub(super) unsafe fn service(manager: usize, deadline: Deadline) {
    if !is_admitted() || !deadline.has_time() {
        return;
    }
    // C3E029 passes this manager unchanged to C3E1B0, whose C3E286
    // iterator call uses that same ECX. Worker +0x30 points to this owner;
    // it is not an ordered-queue member inside the manager.
    let queue = manager;
    let start = super::metrics::stamp();
    let _cost = PromotionCost(start);
    let owner = unsafe { word(queue, 0x14) };
    if owner == 0 || tls_get_value(unsafe { word(owner, 4) } as u32).is_null() {
        MISSING_TLS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    type Acquire = unsafe extern "thiscall" fn(
        usize,
        *mut IteratorState,
        *mut u64,
        *mut *mut c_void,
        u8,
    ) -> u8;
    let acquire = unsafe { FnPtr::<Acquire>::from_address_unchecked(0xC40E70) }.as_fn();
    let mut iterator = IteratorState { words: [0; 7] };
    iterator.words[0] = 0x10C1664;
    unsafe { iterator.reset() };
    let mut selected = None;
    for _ in 0..SCAN_LIMIT {
        if !deadline.has_time() {
            break;
        }
        let mut pin = Pin {
            pointer: std::ptr::null_mut(),
        };
        let mut key = 0u64;
        if unsafe { acquire(queue, &mut iterator, &mut key, &mut pin.pointer, 1) } == 0 {
            break;
        }
        if pin.pointer.is_null() {
            continue;
        }
        let Some(registry) = REGISTRY.try_lock() else {
            BUSY.fetch_add(1, Ordering::Relaxed);
            break;
        };
        let token = registry.visible(pin.pointer as usize, |root| {
            scheduler::is_visible(root.kind, root.node)
        });
        drop(registry);
        if let Some(token) = token {
            // +0x0C is a naturally aligned native state word claimed with
            // InterlockedCompareExchange by workers and priority changes. An
            // atomic load is advisory; the native updater rechecks its CAS.
            let state = unsafe {
                std::sync::atomic::AtomicU32::from_ptr(pin.pointer.cast::<u8>().add(0xC).cast())
            }
            .load(Ordering::Relaxed);
            if state == 1 && ((key >> 16) & 0xFF) != 0 {
                selected = Some((pin, token));
                break;
            }
        }
    }
    // End traversal and discard all raw iterator state before any native rekey.
    unsafe { iterator.reset() };
    drop(iterator);
    let Some((pin, token)) = selected else {
        return;
    };
    if !deadline.has_time() {
        return;
    }
    let Some(registry) = REGISTRY.try_lock() else {
        BUSY.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let current = registry.visible(pin.pointer as usize, |root| {
        scheduler::is_visible(root.kind, root.node)
    });
    drop(registry);
    if current != Some(token) {
        return;
    }
    let vtable = unsafe { word(pin.pointer as usize, 0) };
    let provider = unsafe { word(vtable, 0x1C) };
    if provider != 0xC3CAE0 {
        UNKNOWN_PROVIDER.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let update =
        unsafe { FnPtr::<super::super::types::IoTaskPriorityFn>::from_address_unchecked(provider) }
            .as_fn();
    // C3E690 returns its actual acceptance in AL. C3DF40 and C3CAE0
    // preserve AL unchanged through ret-8 and ret-4 respectively. Never
    // inspect the live key after this call: queue workers can change it.
    if unsafe { update(pin.pointer, 0) } != 0 {
        REGISTRY.lock().promoted(token);
        PROMOTED.fetch_add(1, Ordering::Relaxed);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
    }
}

struct PromotionCost(Option<i64>);
impl Drop for PromotionCost {
    fn drop(&mut self) {
        super::metrics::duration(
            super::metrics::Stage::PromotionCost,
            self.0,
            super::metrics::stamp(),
        );
    }
}

/// Append current capability and native observed priority results to PsychoInfo.
pub(super) fn append_report(out: &mut String) {
    use std::fmt::Write;
    let registry = REGISTRY.lock();
    let _ = writeln!(
        out,
        "LOD queued priority admitted={} disarmed={} lifetimes={} identities={} links={} accepted={} rejected={} unknown-provider={} missing-TLS={} busy={} allocation-failures={}",
        ADMITTED.load(Ordering::Acquire),
        registry.disarmed,
        INSTALLED.load(Ordering::Acquire),
        registry.records.len(),
        registry.edges,
        PROMOTED.load(Ordering::Relaxed),
        FAILED.load(Ordering::Relaxed),
        UNKNOWN_PROVIDER.load(Ordering::Relaxed),
        MISSING_TLS.load(Ordering::Relaxed),
        BUSY.load(Ordering::Relaxed),
        registry.allocation_failures
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_texture_keeps_other_parent_and_rejects_address_reuse() {
        let mut registry = Registry::new();
        registry.root(10, 1, 100);
        registry.root(20, 1, 200);
        registry.link(10, 30);
        registry.link(20, 30);
        assert!(registry.visible(30, |_| true).is_some());
        registry.cancel(30, 10);
        assert!(registry.visible(30, |root| root.node == 200).is_some());
        registry.invalidate(20);
        registry.root(20, 1, 200);
        assert!(registry.visible(30, |_| true).is_none());
    }
    #[test]
    fn lifetime_reset_and_node_reuse_revoke_priority() {
        let mut registry = Registry::new();
        registry.root(10, 0, 100);
        registry.link(10, 30);
        registry.node_reused(100);
        assert!(registry.visible(30, |_| true).is_none());
        registry.root(10, 0, 100);
        registry.link(10, 30);
        let token = registry.visible(30, |_| true).unwrap();
        registry.promoted(token);
        assert!(registry.visible(30, |_| true).is_none());
        registry.reset();
        assert!(registry.visible(10, |_| true).is_none());
    }
    #[test]
    fn duplicate_links_and_overflow_preserve_native_fallback() {
        let mut registry = Registry::new();
        registry.root(10, 0, 100);
        registry.link(10, 30);
        registry.link(10, 30);
        assert_eq!(registry.edges, 1);
        registry.reset();
        // Fill the actual bound through production publication, with two
        // texture children per root, rather than assigning a fake edge count.
        for i in 1..=EDGE_LIMIT / 2 {
            registry.root(i * 10, 0, i * 100);
            registry.link(i * 10, i * 10 + 1);
            registry.link(i * 10, i * 10 + 2);
        }
        assert_eq!(registry.edges, EDGE_LIMIT);
        let extra = (EDGE_LIMIT / 2 + 1) * 10;
        registry.root(extra, 0, extra * 10);
        registry.link(extra, extra + 1);
        assert!(registry.disarmed);
        assert_eq!(registry.edges, 0);
        assert!(
            registry.records.is_empty() && registry.parents.is_empty() && registry.nodes.is_empty()
        );
        assert!(registry.visible(30, |_| true).is_none());
        registry.reset();
        assert!(!registry.disarmed);
    }

    #[test]
    fn leaf_invalidation_does_not_visit_unrelated_dependencies() {
        let mut registry = Registry::new();
        // Each root has the binary-proven two-texture dependency shape.
        for i in 1..=32 {
            let parent = i * 10;
            registry.root(parent, 0, i * 100);
            registry.link(parent, parent + 1);
            registry.link(parent, parent + 2);
        }
        registry.invalidation_visits = 0;
        registry.invalidate(11);
        assert_eq!(
            registry.invalidation_visits, 3,
            "leaf invalidation examined {} associations",
            registry.invalidation_visits
        );
        assert_eq!(registry.edges, 63);
        assert!(registry.visible(12, |_| true).is_some());
        assert!(registry.visible(21, |_| true).is_some());
    }

    #[test]
    fn node_reuse_removes_only_its_roots_and_shared_parent_interest() {
        let mut registry = Registry::new();
        for i in 1..=32 {
            registry.root(i * 10, 0, i * 100);
            registry.link(i * 10, if i == 2 { 11 } else { i * 10 + 1 });
            registry.link(i * 10, i * 10 + 2);
        }
        registry.invalidation_visits = 0;
        registry.node_reused(100);
        assert!(registry.invalidation_visits <= 5);
        assert_eq!(registry.edges, 62);
        assert!(registry.visible(10, |_| true).is_none());
        assert!(registry.visible(11, |root| root.node == 200).is_some());
        assert!(registry.visible(22, |_| true).is_some());
        registry.cancel(11, 20);
        assert!(registry.visible(11, |_| true).is_none());
        registry.root(10, 0, 100);
        assert!(registry.visible(11, |root| root.node == 100).is_none());
        registry.link(10, 11);
        assert!(registry.visible(11, |root| root.node == 100).is_some());
    }
}
