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
