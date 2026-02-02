//! Heap replacer module for Fallout New Vegas.
//!
//! Replaces the game's heap and scrap heap allocators with MiMalloc and bump allocators.
//! Based on https://github.com/iranrmrf/Heap-Replacer

use std::sync::LazyLock;

use libpsycho::os::windows::hook::inline::inlinehook::InlineHookContainer;

pub(super) mod game_heap;
pub(super) mod scrap_heap;
pub(super) mod sheap;

mod types;
mod replacer;

pub use replacer::install_game_heap_hooks;
pub use types::*;

/// Game heap function addresses (Fallout New Vegas)
pub(super) const GAME_HEAP_ALLOCATE_ADDR: usize = 0x00AA3E40;
pub(super) const GAME_HEAP_REALLOCATE_ADDR_1: usize = 0x00AA4150;
pub(super) const GAME_HEAP_REALLOCATE_ADDR_2: usize = 0x00AA4200;
pub(super) const GAME_HEAP_MSIZE_ADDR: usize = 0x00AA44C0;
pub(super) const GAME_HEAP_FREE_ADDR: usize = 0x00AA4060;

/// Scrap heap function addresses (Fallout New Vegas)
pub(super) const SHEAP_INIT_FIX_ADDR: usize = 0x00AA53F0;
pub(super) const SHEAP_INIT_VAR_ADDR: usize = 0x00AA5410;
pub(super) const SHEAP_ALLOC_ADDR: usize = 0x00AA54A0;
pub(super) const SHEAP_FREE_ADDR: usize = 0x00AA5610;
pub(super) const SHEAP_PURGE_ADDR: usize = 0x00AA5460;
pub(super) const SHEAP_GET_THREAD_LOCAL_ADDR: usize = 0x00AA42E0;

/// Game heap hooks
pub static GAME_HEAP_ALLOCATE_HOOK: LazyLock<InlineHookContainer<GameHeapAllocateFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static GAME_HEAP_REALLOCATE_HOOK_1: LazyLock<InlineHookContainer<GameHeapReallocateFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static GAME_HEAP_REALLOCATE_HOOK_2: LazyLock<InlineHookContainer<GameHeapReallocateFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static GAME_HEAP_MSIZE_HOOK: LazyLock<InlineHookContainer<GameHeapMsizeFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static GAME_HEAP_FREE_HOOK: LazyLock<InlineHookContainer<GameHeapFreeFn>> =
    LazyLock::new(InlineHookContainer::new);

/// Scrap heap hooks
pub static SHEAP_INIT_FIX_HOOK: LazyLock<InlineHookContainer<SheapInitFixFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static SHEAP_INIT_VAR_HOOK: LazyLock<InlineHookContainer<SheapInitVarFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static SHEAP_ALLOC_HOOK: LazyLock<InlineHookContainer<SheapAllocFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static SHEAP_FREE_HOOK: LazyLock<InlineHookContainer<SheapFreeFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static SHEAP_PURGE_HOOK: LazyLock<InlineHookContainer<SheapPurgeFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static SHEAP_GET_THREAD_LOCAL_HOOK: LazyLock<InlineHookContainer<SheapGetThreadLocalFn>> =
    LazyLock::new(InlineHookContainer::new);
