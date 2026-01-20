
use std::sync::LazyLock;

use libpsycho::os::windows::hook::inline::inlinehook::InlineHookContainer;

mod types;
mod game_heap;
mod scrap_heap;
mod sheap;
mod replacer;

pub(super) use game_heap::*;
pub(super) use scrap_heap::*;
pub(super) use sheap::*;

pub use replacer::install_game_heap_hooks;

pub use types::*;


// ======================================================================================================================
// Addresses
// ======================================================================================================================

// Game Heap API addresses (Fallout New Vegas engine heap)
// Source: https://github.com/iranrmrf/Heap-Replacer/blob/master/heap_replacer/main/heap_replacer.h
pub(super) const GAME_HEAP_ALLOCATE_ADDR: usize = 0x00AA3E40;
pub(super) const GAME_HEAP_REALLOCATE_ADDR_1: usize = 0x00AA4150;
pub(super) const GAME_HEAP_REALLOCATE_ADDR_2: usize = 0x00AA4200;
pub(super) const GAME_HEAP_MSIZE_ADDR: usize = 0x00AA44C0;
pub(super) const GAME_HEAP_FREE_ADDR: usize = 0x00AA4060;

// Scrap Heap (sheap) API addresses (FNV engine stack-like heap)
pub(super) const SHEAP_INIT_FIX_ADDR: usize = 0x00AA53F0;
pub(super) const SHEAP_INIT_VAR_ADDR: usize = 0x00AA5410;
pub(super) const SHEAP_ALLOC_ADDR: usize = 0x00AA54A0;
pub(super) const SHEAP_FREE_ADDR: usize = 0x00AA5610;
pub(super) const SHEAP_PURGE_ADDR: usize = 0x00AA5460;
pub(super) const SHEAP_GET_THREAD_LOCAL_ADDR: usize = 0x00AA42E0;

// ======================================================================================================================
// Hooks
// ======================================================================================================================

// InlineHook containers for game heap functions
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

// InlineHook containers for sheap functions
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