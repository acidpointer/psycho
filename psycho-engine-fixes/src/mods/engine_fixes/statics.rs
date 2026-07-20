//! Hook containers and game addresses for standalone engine fixes.

use std::sync::LazyLock;

use libpsycho::os::windows::hook::inline::inlinehook::InlineHookContainer;

use super::types::*;

// ---- Display / focus ----
//
// Display keeps its hook container local because it also owns several
// window-state atomics. It still installs through engine_fixes::install.

// ---- Navmesh/pathfinding low pointer guard ----

pub const NAVMESH_NAME_HELPER_ADDR: usize = 0x00690830;

pub static NAVMESH_NAME_HELPER_HOOK: LazyLock<InlineHookContainer<NavmeshNameHelperFn>> =
    LazyLock::new(InlineHookContainer::new);

// ---- ExtraContainerChanges::EntryData invalid form guard ----

pub const ENTRYDATA_LIST_SAVE_ADDR: usize = 0x004D4090;
pub const ENTRYDATA_LOAD_ADDR: usize = 0x004BEE00;

pub static ENTRYDATA_LIST_SAVE_HOOK: LazyLock<InlineHookContainer<EntryDataListSaveFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static ENTRYDATA_LOAD_HOOK: LazyLock<InlineHookContainer<EntryDataLoadFn>> =
    LazyLock::new(InlineHookContainer::new);

// ---- ExtraOwnership invalid owner guard ----

pub const EXTRAOWNERSHIP_LOAD_RESOLVE_CALL_ADDR: usize = 0x0042868F;
pub const BASE_EXTRA_LIST_GET_BY_TYPE_ADDR: usize = 0x00410220;
pub const LINKED_REF_CHILDREN_REMOVE_GET_BY_TYPE_CALL_ADDR: usize = 0x0041E614;
pub const LINKED_REF_TARGET_TYPE_GATE_ADDR: usize = 0x00568680;

pub static BASE_EXTRA_LIST_GET_BY_TYPE_HOOK: LazyLock<
    InlineHookContainer<BaseExtraListGetByTypeFn>,
> = LazyLock::new(InlineHookContainer::new);
pub static LINKED_REF_TARGET_TYPE_GATE_HOOK: LazyLock<
    InlineHookContainer<LinkedRefTargetTypeGateFn>,
> = LazyLock::new(InlineHookContainer::new);

// ---- bhkRagdollController not-ready bone table guard ----

pub const RAGDOLL_ALTERNATE_UPDATE_ADDR: usize = 0x00C7D630;
pub const RAGDOLL_SAVE_LOAD_WRITEBACK_ADDR: usize = 0x00C75B40;
pub const RAGDOLL_BONE_TRANSFORM_UPDATE_ADDR: usize = 0x00C7D810;
pub const RAGDOLL_PENETRATION_RAYCAST_ADDR: usize = 0x00CA1C50;

pub static RAGDOLL_ALTERNATE_UPDATE_HOOK: LazyLock<InlineHookContainer<RagdollAlternateUpdateFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static RAGDOLL_SAVE_LOAD_WRITEBACK_HOOK: LazyLock<
    InlineHookContainer<RagdollSaveLoadWritebackFn>,
> = LazyLock::new(InlineHookContainer::new);
pub static RAGDOLL_BONE_TRANSFORM_UPDATE_HOOK: LazyLock<
    InlineHookContainer<RagdollBoneTransformUpdateFn>,
> = LazyLock::new(InlineHookContainer::new);
pub static RAGDOLL_PENETRATION_RAYCAST_HOOK: LazyLock<
    InlineHookContainer<RagdollPenetrationRaycastFn>,
> = LazyLock::new(InlineHookContainer::new);

// ---- Havok sparse/invalid input guards ----

pub const HAVOK_ADD_ENTITY_BATCH_ADDR: usize = 0x00C94BD0;
pub const HAVOK_ENTITY_POST_ADD_ADDR: usize = 0x00CFFA00;
pub const HAVOK_NARROWPHASE_ADD_AGENTS_ADDR: usize = 0x00CF7080;
pub const HAVOK_PENDING_ADD_FLUSH_ADDR: usize = 0x00C674D0;

pub static HAVOK_ADD_ENTITY_BATCH_HOOK: LazyLock<InlineHookContainer<HavokAddEntityBatchFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static HAVOK_ENTITY_POST_ADD_HOOK: LazyLock<InlineHookContainer<HavokEntityPostAddFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static HAVOK_NARROWPHASE_ADD_AGENTS_HOOK: LazyLock<
    InlineHookContainer<HavokNarrowphaseAddAgentsFn>,
> = LazyLock::new(InlineHookContainer::new);
pub static HAVOK_PENDING_ADD_FLUSH_HOOK: LazyLock<InlineHookContainer<HavokPendingAddFlushFn>> =
    LazyLock::new(InlineHookContainer::new);

// ---- LowProcess generic-location ownership ----

pub const APPEND_REF_ID_ADDR: usize = 0x00865DF0;
pub const LOWPROCESS_SAVE_OWNER_ADDR: usize = 0x00910450;
pub const LOWPROCESS_SAVE_DATA_CALL_ADDR: usize = 0x009105A6;
pub const LOWPROCESS_SAVE_CALL_ADDR: usize = 0x009105BF;
pub const LOWPROCESS_SAVE_NEXT_CALL_ADDR: usize = 0x009105D0;
pub const MAIN_TASK_DRAIN_ADDR: usize = 0x00446B50;
pub const MAIN_TASK_DRAIN_CALL_ADDR: usize = 0x0094CFD6;
pub const VANILLA_LOWPROCESS_FUNC011F: usize = 0x0090CC10;
pub const LOWPROCESS_VTABLE_BASES: [usize; 4] = [0x01087864, 0x010886E4, 0x0108904C, 0x01089BCC];
pub const LOWPROCESS_FUNC011F_SLOTS: [usize; 4] = [0x01087CE0, 0x01088B60, 0x010894C8, 0x0108A048];

pub static LOWPROCESS_SAVE_OWNER_HOOK: LazyLock<InlineHookContainer<LowProcessSaveFn>> =
    LazyLock::new(InlineHookContainer::new);

// ---- Queued-task lifetime ----

pub const TASK_HOLDER_RELEASE_CALL_ADDR: usize = 0x0044CC04;
pub const TASK_DISPATCH_ADDR: usize = 0x00446C48;
pub const TASK_DISPATCH_BYTES: [u8; 13] = [
    0x8B, 0x55, 0xC8, 0x8B, 0x02, 0x8B, 0x4D, 0xC8, 0x8B, 0x50, 0x1C, 0xFF, 0xD2,
];

// ---- LOD streaming and distant-to-real handoff ----

pub const LOD_TERRAIN_DEMAND_ADDR: usize = 0x006F_E550;
pub const LOD_OBJECT_DEMAND_ADDR: usize = 0x006F_E620;
pub const LOD_TREE_DEMAND_ADDR: usize = 0x006F_E780;
pub const LOD_WORLDSPACE_RESET_ADDR: usize = 0x006F_CE00;

pub const LOD_CELL_INSERT_ADDR: usize = 0x0054_8230;
pub const LOD_CELL_REMOVE_ADDR: usize = 0x0054_CA90;
pub const LOD_CELL_ALTERNATE_DECREMENT_ADDR: usize = 0x0055_E1D0;
pub const LOD_CELL_READY_GATE_ADDR: usize = 0x0054_95A0;
pub const LOD_CELL_RELOAD_RESET_ADDR: usize = 0x0055_08B0;
pub const LOD_CELL_TEARDOWN_ADDR: usize = 0x0054_CD20;

pub const LOD_READY_INCREMENT_ADDR: usize = 0x0045_2390;
pub const LOD_READY_INCREMENT_CALL_ADDR: usize = 0x0045_20C4;
pub const LOD_READY_CALL_PREFIX_ADDR: usize = 0x0045_20C1;
pub const LOD_READY_CALL_PREFIX_BYTES: [u8; 3] = [0x8B, 0x4D, 0x0C];
pub const LOD_READY_CALL_SUFFIX_ADDR: usize = 0x0045_20C9;
pub const LOD_READY_CALL_SUFFIX_BYTES: [u8; 4] = [0xC6, 0x45, 0xEB, 0x01];

pub const FLOAT_SETTING_ACCESSOR_ADDR: usize = 0x0040_3E20;
pub const BLOCK_LOAD_DISTANCE_SETTING: usize = 0x011D_877C;
pub const TREE_LOAD_DISTANCE_SETTING: usize = 0x011D_8788;

// ---- IOManager parallelism ----

pub const LOCK_FREE_MAP_CONSTRUCTOR_A_ADDR: usize = 0x0044_C040;
pub const LOCK_FREE_MAP_CONSTRUCTOR_B_ADDR: usize = 0x0044_C270;
pub const BSTREE_LOCK_FREE_MAP_CONSTRUCTOR_ADDR: usize = 0x0066_5CB0;
pub const BSFILE_OPEN_STATE_ADDR: usize = 0x00AF_F490;
pub const EXTERIOR_CELL_LOADER_TASK_EXECUTE_ADDR: usize = 0x0052_7CB0;
pub const IO_MANAGER_WORKER_PATCH_ADDR: usize = 0x00C3_DA7A;
pub const IO_MANAGER_SINGLETON_ADDR: usize = 0x0120_2D98;
pub const BSTREE_MANAGER_SINGLETON_ADDR: usize = 0x011D_5C48;

// ---- LOD task priority ----

pub const LOD_OBJECT_TASK_PRODUCER_ADDR: usize = 0x006F_6D10;
pub const LOD_TREE_TASK_PRODUCER_ADDR: usize = 0x006F_9360;
pub const LOD_TERRAIN_TASK_PRODUCER_ADDR: usize = 0x006F_B980;
pub const IO_TASK_PRIORITY_ADDR: usize = 0x00C3_CAE0;

pub static LOD_TERRAIN_DEMAND_HOOK: LazyLock<InlineHookContainer<LodDemandFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static LOD_OBJECT_DEMAND_HOOK: LazyLock<InlineHookContainer<LodDemandFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static LOD_TREE_DEMAND_HOOK: LazyLock<InlineHookContainer<LodDemandFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static LOD_WORLDSPACE_RESET_HOOK: LazyLock<InlineHookContainer<LodWorldspaceResetFn>> =
    LazyLock::new(InlineHookContainer::new);

pub static LOD_CELL_INSERT_HOOK: LazyLock<InlineHookContainer<LodCellInsertFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static LOD_CELL_REMOVE_HOOK: LazyLock<InlineHookContainer<LodCellRemoveFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static LOD_CELL_ALTERNATE_DECREMENT_HOOK: LazyLock<InlineHookContainer<LodCellOwnerFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static LOD_CELL_READY_GATE_HOOK: LazyLock<InlineHookContainer<LodCellReadyGateFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static LOD_CELL_RELOAD_RESET_HOOK: LazyLock<InlineHookContainer<LodCellOwnerFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static LOD_CELL_TEARDOWN_HOOK: LazyLock<InlineHookContainer<LodCellOwnerFn>> =
    LazyLock::new(InlineHookContainer::new);

// ---- IOManager parallelism ----

pub static LOCK_FREE_MAP_CONSTRUCTOR_A_HOOK: LazyLock<
    InlineHookContainer<LockFreeMapConstructorFn>,
> = LazyLock::new(InlineHookContainer::new);
pub static LOCK_FREE_MAP_CONSTRUCTOR_B_HOOK: LazyLock<
    InlineHookContainer<LockFreeMapConstructorFn>,
> = LazyLock::new(InlineHookContainer::new);
pub static BSTREE_LOCK_FREE_MAP_CONSTRUCTOR_HOOK: LazyLock<
    InlineHookContainer<LockFreeMapConstructorFn>,
> = LazyLock::new(InlineHookContainer::new);
pub static BSFILE_OPEN_STATE_HOOK: LazyLock<InlineHookContainer<BsFileOpenStateFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static EXTERIOR_CELL_LOADER_TASK_EXECUTE_HOOK: LazyLock<
    InlineHookContainer<ExteriorCellLoaderTaskExecuteFn>,
> = LazyLock::new(InlineHookContainer::new);

// ---- LOD task priority ----

pub static LOD_OBJECT_TASK_PRODUCER_HOOK: LazyLock<InlineHookContainer<LodObjectTaskProducerFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static LOD_TREE_TASK_PRODUCER_HOOK: LazyLock<InlineHookContainer<LodBlockTaskProducerFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static LOD_TERRAIN_TASK_PRODUCER_HOOK: LazyLock<InlineHookContainer<LodBlockTaskProducerFn>> =
    LazyLock::new(InlineHookContainer::new);

// ---- IO static vertex-buffer lifetime ----

pub const GEOMETRY_STREAM_ALLOCATE_ADDR: usize = 0x00E8_BFA0;
pub const STATIC_GEOMETRY_ALLOCATE_ADDR: usize = 0x00E9_4C20;
pub const STATIC_GEOMETRY_RETIRE_ADDR: usize = 0x00E9_4770;
pub const STATIC_GEOMETRY_NULL_CHIP_GUARD_ADDR: usize = 0x00E9_4CDB;
pub const STATIC_GEOMETRY_NULL_CHIP_RESUME_ADDR: usize = 0x00E9_4CE0;
pub const GEOMETRY_CHIP_VALID_CALL_ADDRS: [usize; 6] = [
    0x00E6_D7A3,
    0x00E7_2003,
    0x00E7_298E,
    0x00E7_2AD6,
    0x00E7_4CD6,
    0x00E7_CADC,
];

pub static GEOMETRY_STREAM_ALLOCATE_HOOK: LazyLock<InlineHookContainer<GeometryStreamAllocateFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static STATIC_GEOMETRY_ALLOCATE_HOOK: LazyLock<InlineHookContainer<StaticGeometryAllocateFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static STATIC_GEOMETRY_RETIRE_HOOK: LazyLock<InlineHookContainer<StaticGeometryRetireFn>> =
    LazyLock::new(InlineHookContainer::new);

// ---- IO SpeedTree shared-state safety ----

pub const SPEEDTREE_CLONE_CONSTRUCTOR_ADDR: usize = 0x00B0_36D0;
pub const SPEEDTREE_COMPUTE_ADDR: usize = 0x00B0_44A0;
pub const SPEEDTREE_SCALAR_DESTRUCTOR_ADDR: usize = 0x0066_6910;
pub const SPEEDTREE_REGISTRY_CRITICAL_SECTION_ADDR: usize = 0x011F_8BC4;

pub static SPEEDTREE_CLONE_CONSTRUCTOR_HOOK: LazyLock<
    InlineHookContainer<SpeedTreeCloneConstructorFn>,
> = LazyLock::new(InlineHookContainer::new);
pub static SPEEDTREE_COMPUTE_HOOK: LazyLock<InlineHookContainer<SpeedTreeComputeFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static SPEEDTREE_SCALAR_DESTRUCTOR_HOOK: LazyLock<
    InlineHookContainer<SpeedTreeScalarDestructorFn>,
> = LazyLock::new(InlineHookContainer::new);
