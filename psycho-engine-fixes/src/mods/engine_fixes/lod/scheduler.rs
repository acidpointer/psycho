//! Native LOD task-priority scheduling.

use std::{
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};

use libpsycho::{ffi::fnptr::FnPtr, os::windows::hook::transaction::ModificationTransaction};

use super::super::{statics, types::IoTaskPriorityFn};

const LOD_PRIORITY: u32 = 0;
const TERRAIN: usize = 0;
const OBJECT: usize = 1;
const TREE: usize = 2;

static PRIORITY_REQUESTED: AtomicBool = AtomicBool::new(false);
static PRIORITY_INSTALLED: AtomicBool = AtomicBool::new(false);
static PRIORITY_INSTALL_FAILURES: AtomicU32 = AtomicU32::new(0);
static PRIORITY_BOOSTS: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];

pub(in crate::mods::engine_fixes) struct Snapshot {
    pub priority_requested: bool,
    pub priority_installed: bool,
    pub priority_install_failures: u64,
    pub priority_boosts: [u64; 3],
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
    log::info!("[LOD] Native task priority boost installed at {LOD_PRIORITY}");
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
    unsafe { boost_priority(constructed_task, OBJECT) };
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
    unsafe { boost_priority(constructed_task, TREE) };
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
    unsafe { boost_priority(constructed_task, TERRAIN) };
    constructed_task
}

unsafe fn boost_priority(task: *mut c_void, kind: usize) {
    if task.is_null() {
        return;
    }
    let update = unsafe {
        FnPtr::<IoTaskPriorityFn>::from_address_unchecked(statics::IO_TASK_PRIORITY_ADDR)
    }
    .as_fn();
    unsafe { update(task, LOD_PRIORITY) };
    PRIORITY_BOOSTS[kind].fetch_add(1, Ordering::Relaxed);
}

pub(super) fn snapshot() -> Snapshot {
    Snapshot {
        priority_requested: PRIORITY_REQUESTED.load(Ordering::Acquire),
        priority_installed: PRIORITY_INSTALLED.load(Ordering::Acquire),
        priority_install_failures: u64::from(PRIORITY_INSTALL_FAILURES.load(Ordering::Relaxed)),
        priority_boosts: std::array::from_fn(|index| {
            u64::from(PRIORITY_BOOSTS[index].load(Ordering::Relaxed))
        }),
    }
}
