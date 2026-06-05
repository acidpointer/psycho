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

pub static RAGDOLL_ALTERNATE_UPDATE_HOOK: LazyLock<InlineHookContainer<RagdollAlternateUpdateFn>> =
    LazyLock::new(InlineHookContainer::new);
pub static RAGDOLL_SAVE_LOAD_WRITEBACK_HOOK: LazyLock<
    InlineHookContainer<RagdollSaveLoadWritebackFn>,
> = LazyLock::new(InlineHookContainer::new);
pub static RAGDOLL_BONE_TRANSFORM_UPDATE_HOOK: LazyLock<
    InlineHookContainer<RagdollBoneTransformUpdateFn>,
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

// ---- Game-inlined _memset NULL-dst guard ----

pub const MEMSET_ADDR: usize = 0x00EC61C0;

pub static MEMSET_HOOK: LazyLock<InlineHookContainer<libpsycho::os::windows::types::MemsetFn>> =
    LazyLock::new(InlineHookContainer::new);
