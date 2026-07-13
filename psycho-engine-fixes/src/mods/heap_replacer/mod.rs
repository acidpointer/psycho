//! Heap replacer module for Fallout New Vegas.
//!
//! Replaces the game's heap and scrap heap allocators. The user-facing
//! `memory.allocator` config controls whether this module is disabled,
//! runs scrap_heap only, or runs gheap plus scrap_heap.

mod crt_inline;
pub mod gheap;
pub mod heap_validate;
mod install;
mod manifest;
pub mod mem_stats;
mod mimalloc;
mod mode;
pub mod scrap_heap;

pub use install::{
    initialize_gheap_runtime, initialize_sheap_runtime, install_gheap_and_sheap_hooks,
    install_sheap_hooks, prepare_gheap_hooks, prepare_sheap_hooks,
};
pub use manifest::{AllocatorPatchPlan, preflight};
pub use mimalloc::initialize_mimalloc;
pub(crate) use mode::set_active_mode;
pub use mode::{AllocatorMode, current_mode, decide_mode};

use libc::c_void;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TaskPoolState {
    Unknown,
    Live,
    Free,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TaskCellInfo {
    pub pool_index: u8,
    pub item_size: u32,
    pub cell_index: usize,
}

pub(crate) fn task_pool_state(task: *const c_void) -> TaskPoolState {
    if current_mode() != Some(AllocatorMode::GheapAndScrapHeap) {
        return TaskPoolState::Unknown;
    }
    let Some(info) = gheap::pool::ptr_info(task) else {
        return TaskPoolState::Unknown;
    };
    if !info.committed || info.offset != 0 {
        return TaskPoolState::Unknown;
    }
    if info.is_free {
        TaskPoolState::Free
    } else {
        TaskPoolState::Live
    }
}

pub(crate) fn tombstone_free_task(
    task: *mut c_void,
    vtable: usize,
    refcount: i32,
) -> Option<TaskCellInfo> {
    if current_mode() != Some(AllocatorMode::GheapAndScrapHeap) {
        return None;
    }
    let info = gheap::pool::tombstone_free_cell(task, vtable, refcount)?;
    Some(TaskCellInfo {
        pool_index: info.pool_index,
        item_size: info.item_size,
        cell_index: info.cell_index,
    })
}
