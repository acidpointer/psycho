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
