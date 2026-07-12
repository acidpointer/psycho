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

/// FUN_0086f640: first helper called by post-render maintenance.
pub const PHASE10_PRE_ADDR: usize = 0x0086F640;

/// FUN_00832ad0: audio/radio update helper called from FUN_0086f640.
pub const PHASE10_AUDIO_UPDATE_ADDR: usize = 0x00832AD0;

/// FUN_00833d00: focus/audio update worker called from FUN_00832ad0.
pub const PHASE10_AUDIO_WORKER_ADDR: usize = 0x00833D00;

/// FUN_004ff1a0: scans radio station refs and builds the candidate list.
pub const RADIO_SIGNAL_SCAN_ADDR: usize = 0x004FF1A0;

/// FUN_00834260: updates one radio station/list entry.
pub const RADIO_STATION_UPDATE_ADDR: usize = 0x00834260;

/// FUN_0082fb70: helper called from FUN_0086f640 before world update.
pub const PHASE10_PRE_TAIL_ADDR: usize = 0x0082FB70;

/// FUN_0082d7c0: large world update helper called from FUN_0086f640.
pub const PHASE10_WORLD_UPDATE_ADDR: usize = 0x0082D7C0;

/// FUN_0086f890: render update helper called by post-render maintenance.
pub const PHASE10_MID_ADDR: usize = 0x0086F890;

/// FUN_00552570: queued object/model processing drain.
pub const PHASE10_QUEUE_DRAIN_ADDR: usize = 0x00552570;

/// FUN_0086f670: final helper called by post-render maintenance.
pub const PHASE10_POST_ADDR: usize = 0x0086F670;

/// Per-frame queue drain. Runs every frame pre-AI, pre-render.
/// Drains 10-20 NiNodes per call; under pressure we call it extra times.
pub const PER_FRAME_QUEUE_DRAIN_ADDR: usize = 0x00868850;

// IOManager main-thread processing. Phase 3 -- reads completed IO task data.
// pub const IO_MANAGER_PROCESS_ADDR: usize = 0x00C3DBF0;

// pub static IO_MANAGER_PROCESS_HOOK: LazyLock<InlineHookContainer<IOManagerProcessFn>> =
//     LazyLock::new(InlineHookContainer::new);

/// AI thread start. Called at Phase 6 to dispatch AI worker threads.
/// Only on multi-threaded systems (processor count > 1).
pub const AI_THREAD_START_ADDR: usize = 0x008C78C0;

/// AI thread join. Called at Phase 9 to wait for AI worker threads.
/// Only on multi-threaded systems (processor count > 1).
pub const AI_THREAD_JOIN_ADDR: usize = 0x008C7990;

/// StopHavok_DRAINAI (FUN_008324e0). Drains PPL task groups that
/// IOManager uses to dispatch AI Linear Task Thread work.
/// mode=0: stops + drains (safe before cell destruction).
/// mode=1: restarts simulation.
pub const HAVOK_STOP_START_ADDR: usize = 0x008324E0;

pub static MAIN_LOOP_MAINTENANCE_HOOK: LazyLock<InlineHookContainer<MainLoopMaintenanceFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static PHASE10_PRE_HOOK: LazyLock<InlineHookContainer<Phase10PreFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static PHASE10_AUDIO_UPDATE_HOOK: LazyLock<InlineHookContainer<Phase10AudioUpdateFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static PHASE10_AUDIO_WORKER_HOOK: LazyLock<InlineHookContainer<Phase10AudioWorkerFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static RADIO_SIGNAL_SCAN_HOOK: LazyLock<InlineHookContainer<RadioSignalScanFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static RADIO_STATION_UPDATE_HOOK: LazyLock<InlineHookContainer<RadioStationUpdateFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static PHASE10_PRE_TAIL_HOOK: LazyLock<InlineHookContainer<Phase10PreTailFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static PHASE10_WORLD_UPDATE_HOOK: LazyLock<InlineHookContainer<Phase10WorldUpdateFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static PHASE10_MID_HOOK: LazyLock<InlineHookContainer<Phase10MidFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static PHASE10_QUEUE_DRAIN_HOOK: LazyLock<InlineHookContainer<Phase10QueueDrainFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static PHASE10_POST_HOOK: LazyLock<InlineHookContainer<Phase10PostFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static PER_FRAME_QUEUE_DRAIN_HOOK: LazyLock<InlineHookContainer<PerFrameQueueDrainFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static AI_THREAD_START_HOOK: LazyLock<InlineHookContainer<AIThreadStartFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static AI_THREAD_JOIN_HOOK: LazyLock<InlineHookContainer<AIThreadJoinFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static HAVOK_STOP_START_HOOK: LazyLock<InlineHookContainer<HavokStopStartFn>> =
    LazyLock::new(InlineHookContainer::new);

// ---- PDD (ProcessDeferredDestruction) ----

/// FUN_00868d70: the core destruction function (1037 bytes, cdecl).
/// Called by ALL destruction paths: 5 normal PDD callers,
/// CellTransitionHandler, HeapCompact, per-frame drain.
pub const PDD_ADDR: usize = 0x00868D70;

// ---- Texture cache ----

pub const TEXTURE_CACHE_FIND_ADDR: usize = 0x00A61A60;
pub const NISOURCETEXTURE_DTOR_ADDR: usize = 0x00A5FCA0;

pub static TEXTURE_CACHE_FIND_HOOK: LazyLock<InlineHookContainer<TextureCacheFindFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static NISOURCETEXTURE_DTOR_HOOK: LazyLock<InlineHookContainer<NiSourceTextureDtorFn>> =
    LazyLock::new(InlineHookContainer::new);

/// FUN_00449A50: model-loader task scalar destructor. Under gheap stress,
/// FUN_00446B50 can dispatch this on an already-freed 80-byte pool cell.
pub const MODEL_TASK_DTOR_ADDR: usize = 0x00449A50;

pub static MODEL_TASK_DTOR_HOOK: LazyLock<InlineHookContainer<ModelTaskDtorFn>> =
    LazyLock::new(InlineHookContainer::new);

// ---- OOM Stage 8 (HeapCompact) ----

/// FUN_00866a90: OOM stage executor. Called by GameHeap retry loop,
/// periodic cleanup, and SBM heap resize. Case 8 hardcodes BSTaskManagerThread
/// indices 0/1 without bounds check -- crashes when thread_count==1.
/// We hook at entry to intercept case 8 and use release_bstask_sems_if_owned()
/// which validates the thread array before accessing slots.
pub const OOM_STAGE_EXEC_HOOK_ADDR: usize = 0x00866A90;

pub static OOM_STAGE_EXEC_HOOK: LazyLock<InlineHookContainer<OomStageExecFn>> =
    LazyLock::new(InlineHookContainer::new);

// ---- Queued reference processing ----

// FUN_0056f700: processes a queued reference after model loading completes.
// Called from FUN_00451ef0 (queue dispatch) for every QueuedCharacter/
// ---- Havok broadphase synchronization ----

// pub const HAVOK_ADD_ENTITY_ADDR: usize = 0x00C94BD0;
// pub const HAVOK_COLL_OBJ_DTOR_ADDR: usize = 0x00C40B70;
// pub const HAVOK_RAYCAST_ADDR: usize = 0x00CBF860;

// ---- Havok world synchronization ----

/// hkWorld_Lock: called before physics step and cell transitions.
pub const HKWORLD_LOCK_ADDR: usize = 0x00C3E310;

/// hkWorld_Unlock: called after physics step completes.
pub const HKWORLD_UNLOCK_ADDR: usize = 0x00C3E340;

pub static HKWORLD_LOCK_HOOK: LazyLock<InlineHookContainer<HkWorldLockFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static HKWORLD_UNLOCK_HOOK: LazyLock<InlineHookContainer<HkWorldUnlockFn>> =
    LazyLock::new(InlineHookContainer::new);

// // ---- Actor process synchronization ----

// pub const ACTOR_DOWNGRADE_ADDR: usize = 0x0096E870;
// pub const AI_PROCESS1_ADDR: usize = 0x0096C330;
// pub const AI_PROCESS2_ADDR: usize = 0x0096CB50;
// pub const CELL_MGMT_UPDATE_ADDR: usize = 0x00453550;
// pub const PROCESS_MGR_UPDATE_ADDR: usize = 0x009784C0;
