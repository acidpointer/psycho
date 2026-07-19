//! Function signatures for standalone engine-fix hooks.
//!
//! These are game contracts, not allocator entrypoints. Addresses live in
//! `statics.rs` beside the hook containers that use them.

use libc::c_void;

/// FUN_00690830: returns a NavMeshInfo parent/cell identity pointer.
pub type NavmeshNameHelperFn = unsafe extern "fastcall" fn(*mut c_void) -> *mut c_void;

/// FUN_004D4090: saves the EntryData list owned by ExtraContainerChanges.
pub type EntryDataListSaveFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);

/// FUN_004BEE00: loads one EntryData body from the save buffer.
pub type EntryDataLoadFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);

/// FUN_00410220: BaseExtraList::GetByType.
pub type BaseExtraListGetByTypeFn = unsafe extern "thiscall" fn(*mut c_void, u8) -> *mut c_void;

/// FUN_00568680: checks whether a linked reference target has the terminal-like base type.
pub type LinkedRefTargetTypeGateFn = unsafe extern "thiscall" fn(*mut c_void) -> u8;

/// FUN_00C7D630: alternate bhkRagdollController update wrapper. It has one
/// stack argument and returns with `ret 4`.
pub type RagdollAlternateUpdateFn = unsafe extern "thiscall" fn(*mut c_void, u32);

/// FUN_00C7D810: bhkRagdollController bone transform update wrapper.
pub type RagdollBoneTransformUpdateFn = unsafe extern "thiscall" fn(*mut c_void);

/// FUN_00C75B40: writes the controller transform buffer back into bone entries.
pub type RagdollSaveLoadWritebackFn = unsafe extern "fastcall" fn(*mut c_void);

/// FUN_00CA1C50: performs the two best-effort penetration raycasts used by
/// hkaDetectRagdollPenetration and writes whether either ray hit.
pub type RagdollPenetrationRaycastFn = unsafe extern "thiscall" fn(
    *mut c_void,
    *mut u8,
    u32,
    *const c_void,
    *const c_void,
    *mut c_void,
    *mut c_void,
);

/// FUN_00CFFA00: per-entity AddedToWorld callback dispatcher.
pub type HavokEntityPostAddFn = unsafe extern "C" fn(entity: *mut c_void);

/// FUN_00C94BD0: hkpWorld::addEntityBatch.
pub type HavokAddEntityBatchFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut *mut c_void, i32, i32);

/// FUN_00CF7080: Havok narrowphase add-agent dispatcher.
pub type HavokNarrowphaseAddAgentsFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, i32, *mut c_void);

/// FUN_00C674D0: flushes the hkpWorld pending-add queue.
pub type HavokPendingAddFlushFn = unsafe extern "thiscall" fn(*mut c_void, *mut *mut c_void, u32);

/// FUN_00865DF0: serializes one optional TESForm reference.
pub type AppendRefIdFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void, u32);

/// FUN_00910450: serializes one LowProcess instance.
pub type LowProcessSaveFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);

/// FUN_00446B50: drains the main-thread queued-task stack.
pub type MainTaskDrainFn = unsafe extern "thiscall" fn(*mut c_void, u32);

/// ABI of the current intrusive queued-task release target.
pub type TaskReleaseFn = unsafe extern "fastcall" fn(*mut c_void);

/// Queued-task vtable slot +0x1C.
pub type TaskCallbackFn = unsafe extern "thiscall" fn(*mut c_void, usize);

/// Terrain/object/tree LOD demand predicates. ECX owns the terrain node and
/// the stack argument points to the camera XY(Z) vector.
pub type LodDemandFn = unsafe extern "thiscall" fn(*mut c_void, *const f32) -> i32;

/// BGSTerrainManager::ResetDistantLOD.
pub type LodWorldspaceResetFn = unsafe extern "fastcall" fn(*mut c_void);

/// TESObjectCELL reference insertion and VWD-total update.
pub type LodCellInsertFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void, u8);

/// TESObjectCELL reference removal and VWD-total update.
pub type LodCellRemoveFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);

/// Cell-only counter/reset/teardown helpers with their owner in ECX.
pub type LodCellOwnerFn = unsafe extern "fastcall" fn(*mut c_void);

/// TESObjectCELL distant-to-real readiness gate. Callers consume AL.
pub type LodCellReadyGateFn = unsafe extern "fastcall" fn(*mut c_void) -> u8;

/// TESObjectCELL +0xAA successful real-3D counter increment.
pub type LodReadyIncrementFn = unsafe extern "fastcall" fn(*mut c_void);

/// Game setting float accessor at 0x00403E20.
pub type GameSettingFloatFn = unsafe extern "thiscall" fn(*mut c_void) -> *const f32;

/// SpeedTree core clone constructor. The new clone is in ECX and the source
/// core object is the only stack argument.
pub type SpeedTreeCloneConstructorFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void) -> *mut c_void;

/// SpeedTree core scalar deleting destructor. Bit zero in `flags` requests
/// physical deletion after the destructor body.
pub type SpeedTreeScalarDestructorFn = unsafe extern "thiscall" fn(*mut c_void, u32) -> *mut c_void;
