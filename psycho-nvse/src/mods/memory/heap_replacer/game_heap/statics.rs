//! Hook containers and game addresses for the game heap domain.
//!
//! Each static is a LazyLock<InlineHookContainer<T>> that holds the
//! trampoline to the original function. The install module initializes
//! these during startup.

use std::sync::LazyLock;

use libpsycho::os::windows::hook::inline::inlinehook::InlineHookContainer;

use super::types::*;

// ---- Game heap alloc/free/msize/realloc ----

pub const GHEAP_ALLOC_ADDR: usize = 0x00AA3E40;
pub const GHEAP_FREE_ADDR: usize = 0x00AA4060;
pub const GHEAP_MSIZE_ADDR: usize = 0x00AA44C0;
pub const GHEAP_REALLOC_ADDR_1: usize = 0x00AA4150;
pub const GHEAP_REALLOC_ADDR_2: usize = 0x00AA4200;

pub static GHEAP_ALLOC_HOOK: LazyLock<InlineHookContainer<GameHeapAllocFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static GHEAP_FREE_HOOK: LazyLock<InlineHookContainer<GameHeapFreeFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static GHEAP_MSIZE_HOOK: LazyLock<InlineHookContainer<GameHeapMsizeFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static GHEAP_REALLOC_HOOK_1: LazyLock<InlineHookContainer<GameHeapReallocFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static GHEAP_REALLOC_HOOK_2: LazyLock<InlineHookContainer<GameHeapReallocFn>> =
    LazyLock::new(InlineHookContainer::new);

// ---- Main loop / frame hooks ----

/// Post-render hook position. After render pipeline finishes with all
/// scene graph data, safe to unload cells.
pub const MAIN_LOOP_MAINTENANCE_ADDR: usize = 0x008705D0;

/// Per-frame queue drain. Runs every frame pre-AI, pre-render.
/// Drains 10-20 NiNodes per call; under pressure we call it extra times.
pub const PER_FRAME_QUEUE_DRAIN_ADDR: usize = 0x00868850;

/// AI thread join. Called at 0x0086ee4e AFTER render and our main hook.
/// Only on multi-threaded systems (processor count > 1).
pub const AI_THREAD_JOIN_ADDR: usize = 0x008C7990;

pub static MAIN_LOOP_MAINTENANCE_HOOK: LazyLock<InlineHookContainer<MainLoopMaintenanceFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static PER_FRAME_QUEUE_DRAIN_HOOK: LazyLock<InlineHookContainer<PerFrameQueueDrainFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static AI_THREAD_JOIN_HOOK: LazyLock<InlineHookContainer<AIThreadJoinFn>> =
    LazyLock::new(InlineHookContainer::new);

// ---- PDD (ProcessDeferredDestruction) ----

/// FUN_00868d70: the core destruction function (1037 bytes, cdecl).
/// Called by ALL destruction paths: 5 normal PDD callers,
/// CellTransitionHandler, HeapCompact, per-frame drain.
/// We hook this to set the destruction guard.
pub const PDD_ADDR: usize = 0x00868D70;

pub static PDD_HOOK: LazyLock<InlineHookContainer<PDDFn>> =
    LazyLock::new(InlineHookContainer::new);

// ---- Texture cache ----

pub const TEXTURE_CACHE_FIND_ADDR: usize = 0x00A61A60;
pub const NISOURCETEXTURE_DTOR_ADDR: usize = 0x00A5FCA0;

pub static TEXTURE_CACHE_FIND_HOOK: LazyLock<InlineHookContainer<TextureCacheFindFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static NISOURCETEXTURE_DTOR_HOOK: LazyLock<InlineHookContainer<NiSourceTextureDtorFn>> =
    LazyLock::new(InlineHookContainer::new);

// ---- IO task ----

pub const TASK_RELEASE_ADDR: usize = 0x0044DD60;

pub static TASK_RELEASE_HOOK: LazyLock<InlineHookContainer<TaskReleaseFn>> =
    LazyLock::new(InlineHookContainer::new);

// ---- Skeleton update (ragdoll bone validation) ----

pub const SKELETON_UPDATE_ADDR: usize = 0x00C79680;

pub static SKELETON_UPDATE_HOOK: LazyLock<InlineHookContainer<SkeletonUpdateFn>> =
    LazyLock::new(InlineHookContainer::new);

// ---- Queued reference processing ----

/// FUN_0056f700: processes a queued reference after model loading completes.
/// Called from FUN_00451ef0 (queue dispatch) for every QueuedCharacter/
/// QueuedReference. Leads to ragdoll skeleton update which reads Havok
/// bone data. We hook this to skip processing for dead characters whose
/// ragdoll data has been freed by the Havok allocator.
pub const QUEUED_REF_PROCESS_ADDR: usize = 0x0056F700;

pub static QUEUED_REF_PROCESS_HOOK: LazyLock<InlineHookContainer<QueuedRefProcessFn>> =
    LazyLock::new(InlineHookContainer::new);
