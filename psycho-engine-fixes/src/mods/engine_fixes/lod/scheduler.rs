//! Native LOD task-priority scheduling.

use std::{
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
};

use libpsycho::{ffi::fnptr::FnPtr, os::windows::hook::transaction::ModificationTransaction};

use super::super::{statics, types::IoTaskPriorityFn};

const LOD_PRIORITY: u32 = 0;
const TERRAIN: usize = 0;
const OBJECT: usize = 1;
const TREE: usize = 2;
const OBJECT_NODE_OFFSET: usize = 0;
const TREE_NODE_OFFSET: usize = 0x44;
const TERRAIN_NODE_OFFSET: usize = 0;
const SPECULATIVE_CAPACITY: usize = 4096;
const SPECULATIVE_PROBES: usize = 32;
const EMPTY: usize = 0;
const TOMBSTONE: usize = usize::MAX;

static PRIORITY_REQUESTED: AtomicBool = AtomicBool::new(false);
static PRIORITY_INSTALLED: AtomicBool = AtomicBool::new(false);
static PRIORITY_INSTALL_FAILURES: AtomicU32 = AtomicU32::new(0);
static SPECULATIVE_NODES: [AtomicUsize; SPECULATIVE_CAPACITY] =
    [const { AtomicUsize::new(EMPTY) }; SPECULATIVE_CAPACITY];

pub(in crate::mods::engine_fixes) struct Snapshot {
    pub priority_requested: bool,
    pub priority_installed: bool,
    pub priority_install_failures: u64,
}

pub(super) fn configure(priority_requested: bool) {
    PRIORITY_REQUESTED.store(priority_requested, Ordering::Release);
}

pub(super) fn install() -> anyhow::Result<()> {
    let result = install_inner();
    if result.is_err() {
        PRIORITY_INSTALL_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
    result
}

fn install_inner() -> anyhow::Result<()> {
    unsafe {
        statics::LOD_OBJECT_TASK_PRODUCER_HOOK.init(
            "lod_object_priority",
            statics::LOD_OBJECT_TASK_PRODUCER_ADDR as *mut c_void,
            hook_object_task_producer,
        )?;
        statics::LOD_TREE_TASK_PRODUCER_HOOK.init(
            "lod_tree_priority",
            statics::LOD_TREE_TASK_PRODUCER_ADDR as *mut c_void,
            hook_tree_task_producer,
        )?;
        statics::LOD_TERRAIN_TASK_PRODUCER_HOOK.init(
            "lod_terrain_priority",
            statics::LOD_TERRAIN_TASK_PRODUCER_ADDR as *mut c_void,
            hook_terrain_task_producer,
        )?;
    }

    let mut transaction = ModificationTransaction::new();
    transaction.enable_inline(&statics::LOD_OBJECT_TASK_PRODUCER_HOOK)?;
    transaction.enable_inline(&statics::LOD_TREE_TASK_PRODUCER_HOOK)?;
    transaction.enable_inline(&statics::LOD_TERRAIN_TASK_PRODUCER_HOOK)?;
    transaction.commit();
    PRIORITY_INSTALLED.store(true, Ordering::Release);
    log::info!(
        "[LOD] Demand-aware task priority installed: visible={LOD_PRIORITY}, Psycho-only speculative=native"
    );
    Ok(())
}

unsafe extern "thiscall" fn hook_object_task_producer(
    task: *mut c_void,
    argument_1: u32,
    argument_2: u32,
    argument_3: u32,
    argument_4: u32,
    argument_5: u32,
    argument_6: u8,
    argument_7: u8,
    argument_8: u8,
) -> *mut c_void {
    let original = match statics::LOD_OBJECT_TASK_PRODUCER_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            log::error!("[LOD] Object task producer trampoline missing: {error:?}");
            return task;
        }
    };
    let constructed_task = unsafe {
        original(
            task, argument_1, argument_2, argument_3, argument_4, argument_5, argument_6,
            argument_7, argument_8,
        )
    };
    unsafe {
        prioritize_visible_task(
            constructed_task,
            OBJECT,
            block_node(argument_1 as usize, OBJECT_NODE_OFFSET),
        )
    };
    constructed_task
}

unsafe extern "thiscall" fn hook_tree_task_producer(
    task: *mut c_void,
    argument_1: u32,
    argument_2: u32,
    argument_3: u32,
    argument_4: u32,
    argument_5: u32,
) -> *mut c_void {
    let original = match statics::LOD_TREE_TASK_PRODUCER_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            log::error!("[LOD] Tree task producer trampoline missing: {error:?}");
            return task;
        }
    };
    let constructed_task = unsafe {
        original(
            task, argument_1, argument_2, argument_3, argument_4, argument_5,
        )
    };
    unsafe {
        prioritize_visible_task(
            constructed_task,
            TREE,
            block_node(argument_1 as usize, TREE_NODE_OFFSET),
        )
    };
    constructed_task
}

unsafe extern "thiscall" fn hook_terrain_task_producer(
    task: *mut c_void,
    argument_1: u32,
    argument_2: u32,
    argument_3: u32,
    argument_4: u32,
    argument_5: u32,
) -> *mut c_void {
    let original = match statics::LOD_TERRAIN_TASK_PRODUCER_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            log::error!("[LOD] Terrain task producer trampoline missing: {error:?}");
            return task;
        }
    };
    let constructed_task = unsafe {
        original(
            task, argument_1, argument_2, argument_3, argument_4, argument_5,
        )
    };
    unsafe {
        prioritize_visible_task(
            constructed_task,
            TERRAIN,
            block_node(argument_1 as usize, TERRAIN_NODE_OFFSET),
        )
    };
    constructed_task
}

unsafe fn prioritize_visible_task(task: *mut c_void, kind: usize, node: usize) {
    // A consumed mark proves this constructor came from Psycho-only early
    // demand, so preserving the constructor's native priority keeps it in the
    // background. Missing/ambiguous provenance deliberately receives visible
    // priority zero.
    if task.is_null() || consume_speculative(kind, node) {
        return;
    }
    let update = unsafe {
        FnPtr::<IoTaskPriorityFn>::from_address_unchecked(statics::IO_TASK_PRIORITY_ADDR)
    }
    .as_fn();
    unsafe { update(task, LOD_PRIORITY) };
}

unsafe fn block_node(block: usize, offset: usize) -> usize {
    if block == 0 {
        return 0;
    }
    // Constructor argument one is the native LOD block. Static analysis proves
    // its demand-node owner at object/terrain +0x00 and tree +0x44.
    unsafe { ptr::read_unaligned((block + offset) as *const usize) }
}

/// Mark an unloaded LOD node whose demand exists only because Psycho extended
/// the native load radius.
///
/// The registry is fixed-size and allocation-free. Failure deliberately leaves
/// the node unmarked, which makes its eventual task visible-priority rather
/// than risking delayed or missing geometry.
pub(super) fn mark_speculative(kind: usize, node: *mut c_void) {
    let Some(key) = speculative_key(kind, node as usize) else {
        return;
    };
    let start = speculative_hash(key);
    let mut tombstone = None;
    for probe in 0..SPECULATIVE_PROBES {
        let slot = &SPECULATIVE_NODES[(start + probe) & (SPECULATIVE_CAPACITY - 1)];
        let observed = slot.load(Ordering::Acquire);
        if observed == key {
            return;
        }
        if observed == TOMBSTONE {
            tombstone.get_or_insert(slot);
            continue;
        }
        if observed != EMPTY {
            continue;
        }
        let target = tombstone.unwrap_or(slot);
        let expected = if tombstone.is_some() {
            TOMBSTONE
        } else {
            EMPTY
        };
        if target
            .compare_exchange(expected, key, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return;
        }
        // A racing demand changed this slot. Losing the mark is the safe
        // outcome because an unmarked task receives visible-demand priority.
        return;
    }
    if let Some(slot) = tombstone {
        let _ = slot.compare_exchange(TOMBSTONE, key, Ordering::AcqRel, Ordering::Acquire);
    }
}

/// Remove speculative provenance when native visible demand supersedes it or
/// the node leaves the extended prefetch range before task construction.
pub(super) fn clear_speculative(kind: usize, node: *mut c_void) {
    let _ = consume_speculative(kind, node as usize);
}

/// Clear every speculative mark at the worldspace lifetime boundary.
pub(super) fn reset_speculative() {
    for slot in &SPECULATIVE_NODES {
        slot.store(EMPTY, Ordering::Release);
    }
}

fn consume_speculative(kind: usize, node: usize) -> bool {
    let Some(key) = speculative_key(kind, node) else {
        return false;
    };
    let start = speculative_hash(key);
    for probe in 0..SPECULATIVE_PROBES {
        let slot = &SPECULATIVE_NODES[(start + probe) & (SPECULATIVE_CAPACITY - 1)];
        match slot.load(Ordering::Acquire) {
            EMPTY => return false,
            observed if observed == key => {
                return slot
                    .compare_exchange(key, TOMBSTONE, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok();
            }
            _ => {}
        }
    }
    false
}

fn speculative_key(kind: usize, node: usize) -> Option<usize> {
    if node == 0 || kind > TREE {
        return None;
    }
    Some((node & !0x3) | (kind + 1))
}

fn speculative_hash(key: usize) -> usize {
    (key >> 4).wrapping_mul(0x9E37_79B1) & (SPECULATIVE_CAPACITY - 1)
}

pub(super) fn snapshot() -> Snapshot {
    Snapshot {
        priority_requested: PRIORITY_REQUESTED.load(Ordering::Acquire),
        priority_installed: PRIORITY_INSTALLED.load(Ordering::Acquire),
        priority_install_failures: u64::from(PRIORITY_INSTALL_FAILURES.load(Ordering::Relaxed)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn speculative_mark_is_consumed_once() {
        let _test = TEST_LOCK.lock().expect("serialize provenance tests");
        reset_speculative();
        let node = 0x0012_3400usize as *mut c_void;
        mark_speculative(OBJECT, node);
        assert!(consume_speculative(OBJECT, node as usize));
        assert!(!consume_speculative(OBJECT, node as usize));
    }

    #[test]
    fn visible_demand_clears_stale_speculative_mark() {
        let _test = TEST_LOCK.lock().expect("serialize provenance tests");
        reset_speculative();
        let node = 0x0045_6700usize as *mut c_void;
        mark_speculative(TREE, node);
        clear_speculative(TREE, node);
        assert!(!consume_speculative(TREE, node as usize));
    }

    #[test]
    fn provenance_is_separate_for_each_lod_kind() {
        let _test = TEST_LOCK.lock().expect("serialize provenance tests");
        reset_speculative();
        let node = 0x0078_9A00usize as *mut c_void;
        mark_speculative(TERRAIN, node);
        assert!(!consume_speculative(OBJECT, node as usize));
        assert!(consume_speculative(TERRAIN, node as usize));
    }

    #[test]
    fn worldspace_reset_discards_all_marks() {
        let _test = TEST_LOCK.lock().expect("serialize provenance tests");
        reset_speculative();
        let node = 0x00AB_CD00usize as *mut c_void;
        mark_speculative(OBJECT, node);
        reset_speculative();
        assert!(!consume_speculative(OBJECT, node as usize));
    }
}
