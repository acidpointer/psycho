//! Function signatures for standalone engine-fix hooks.
//!
//! These are game contracts, not allocator entrypoints. Addresses live in
//! `statics.rs` beside the hook containers that use them.

use libc::c_void;

/// TESActorBase::~TESActorBase, shared by TESNPC and TESCreature.
pub type ActorBaseDtorFn = unsafe extern "thiscall" fn(*mut c_void);

/// NiControllerSequence::~NiControllerSequence at `0x00A35640`.
pub type NiControllerSequenceDtorFn = unsafe extern "thiscall" fn(*mut c_void);

/// FUN_00690830: returns a NavMeshInfo parent/cell identity pointer.
pub type NavmeshNameHelperFn = unsafe extern "fastcall" fn(*mut c_void) -> *mut c_void;

/// FUN_004D4090: saves the EntryData list owned by ExtraContainerChanges.
pub type EntryDataListSaveFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);

/// FUN_004BEE00: loads one EntryData body from the save buffer.
pub type EntryDataLoadFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);

/// FUN_00410220: BaseExtraList::GetByType.
pub type BaseExtraListGetByTypeFn = unsafe extern "thiscall" fn(*mut c_void, u8) -> *mut c_void;

/// FUN_00421C60: stores an encounter zone in a BaseExtraList, or removes the
/// typed ExtraEncounterZone when `zone` is NULL.
pub type BaseExtraListSetEncounterZoneFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);

/// FUN_00567D20: resolves a reference's encounter zone through its reference,
/// parent cell, and worldspace fallbacks.
pub type EncounterZoneResolverFn = unsafe extern "thiscall" fn(*mut c_void) -> *mut c_void;

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

/// Native LowProcess serializer at `0x00910450`.
///
/// `process` is the live process object in `ECX`; `writer` is the active save
/// writer passed on the stack. The callee returns with `ret 4`.
pub type LowProcessSaveFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);

/// FUN_00446B50: drains the main-thread queued-task stack.
pub type MainTaskDrainFn = unsafe extern "thiscall" fn(*mut c_void, u32);

/// Model EditorMarker postprocessor entered through `0x0043AFAC`.
///
/// The cdecl function takes the scene root on the stack and returns a byte in
/// `AL`. The audited native caller discards that return value.
pub type ModelPostprocessFn = unsafe extern "C" fn(*mut c_void) -> u8;

/// ABI of the current intrusive queued-task release target.
pub type TaskReleaseFn = unsafe extern "fastcall" fn(*mut c_void);

/// Queued-task vtable slot +0x1C.
pub type TaskCallbackFn = unsafe extern "thiscall" fn(*mut c_void, usize);

/// Shared source-texture cache publisher at `0x00A61C50`.
///
/// All eight native callers clean two words after the call. Seven pass null as
/// the second word; `0x0043C596` can pass the opaque value returned from
/// `QueuedTexture+0x2C`. The native body consumes only the source word, but a
/// chained provider must receive the opaque context unchanged.
pub type SourceTextureCachePublishFn = unsafe extern "C" fn(*mut c_void, *mut c_void);

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

/// LockFreeMap constructors. The first stack argument is the number of
/// per-thread scratch slots used by both native backing allocations.
pub type LockFreeMapConstructorFn =
    unsafe extern "thiscall" fn(*mut c_void, i32, u32, u32) -> *mut c_void;

/// BSFile open-state initializer. It opens the stream's optional cache and
/// publishes the final open flag at `this + 0x2C`.
pub type BsFileOpenStateFn = unsafe extern "fastcall" fn(*mut c_void);

/// IOManager task submission at `0x00C3FB50`.
///
/// The manager is in `ECX`, the queued task is the sole stack argument, and
/// `AL` reports whether insertion into the native priority queue succeeded.
pub type IoManagerSubmitFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void) -> u8;

/// BSTaskManagerThread constructor at `0x00C3EE70`.
///
/// `thread_number` is the engine's one-based task-thread number plus one:
/// IOManager worker indices zero and one are constructed as numbers two and
/// three. The base constructor has created a suspended Win32 thread before
/// this function returns.
pub type IoWorkerConstructorFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, u32) -> *mut c_void;

/// IOManager worker task phase callbacks at `0x00C3FC80` and `0x00C3FCA0`.
///
/// Both callbacks receive the manager in `ECX` and the current queued task as
/// their only stack argument.
pub type IoTaskPhaseFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);

/// Per-form cell insertion transaction at `0x00550500`.
///
/// The destination cell is in `ECX`, the form is the sole stack argument, and
/// `AL` reports whether the insertion and its nested form construction
/// succeeded.
pub type CellFormInsertFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void) -> u8;

/// BGSAutoWater cell-build transaction at `0x0049C860`.
///
/// The cell is the sole stack argument and the function returns with plain
/// `ret`, so this is a C-style caller-cleanup ABI. The complete call owns both
/// process-global AutoWater scratch objects from teardown through final
/// publication.
pub type AutoWaterBuildFn = unsafe extern "C" fn(*mut c_void);

/// Native IOTask dependency-priority propagation and queue reordering.
pub type IoTaskPriorityFn = unsafe extern "thiscall" fn(*mut c_void, u32);

/// Object LOD producer constructor at 0x006F6D10.
pub type LodObjectTaskProducerFn =
    unsafe extern "thiscall" fn(*mut c_void, u32, u32, u32, u32, u32, u8, u8, u8) -> *mut c_void;

/// Tree and terrain LOD producer constructors.
pub type LodBlockTaskProducerFn =
    unsafe extern "thiscall" fn(*mut c_void, u32, u32, u32, u32, u32) -> *mut c_void;

/// NiDX9VertexBufferManager release-then-allocate wrapper. Both arguments are
/// stack-owned and the native function returns with `ret 8`.
pub type GeometryStreamAllocateFn = unsafe extern "stdcall" fn(*mut c_void, u32) -> u8;

/// NiStaticGeometryGroup slot +0x18.
pub type StaticGeometryAllocateFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, u32) -> *mut c_void;

/// NiStaticGeometryGroup slot +0x1C.
pub type StaticGeometryRetireFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void, u32);

/// SpeedTree core clone constructor. The new clone is in ECX and the source
/// core object is the only stack argument.
pub type SpeedTreeCloneConstructorFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void) -> *mut c_void;

/// BSTreeModel clone materializer. The destination model is in ECX and the
/// parsed source model is the only stack argument.
pub type BsTreeCloneModelFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void) -> u8;

/// BSTreeModel file/reload materializer. The destination model is in ECX; the
/// stack arguments identify the requesting reference and native load mode.
pub type BsTreeReloadModelFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void, u32) -> u8;

/// SpeedTreeRT Compute entry. This call owns the process-global generation
/// scratch state from initialization through final model publication.
pub type SpeedTreeComputeFn =
    unsafe extern "thiscall" fn(*mut c_void, *const c_void, u32, u8) -> u8;

/// SpeedTree core scalar deleting destructor. Bit zero in `flags` requests
/// physical deletion after the destructor body.
pub type SpeedTreeScalarDestructorFn = unsafe extern "thiscall" fn(*mut c_void, u32) -> *mut c_void;
