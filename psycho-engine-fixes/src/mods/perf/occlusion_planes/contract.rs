//! Native addresses, byte signatures and ABI for occlusion-plane injection.
//!
//! Every address is a fixed virtual address in the supported
//! FalloutNV 1.4.0.525 executable. The signatures are the exact first bytes of
//! each function, captured during the runtime visibility research. They are
//! verified once, lazily, before the feature becomes active; a mismatch keeps
//! the native path untouched.
//!
//! No native code is patched. The module calls only these verified functions at
//! cell/scene-graph changes on the game's main thread.

use core::ffi::c_void;

use libpsycho::os::windows::patch::CodeSignature;

/// Game allocator (`operator new`, cdecl, one size argument).
pub(super) const ALLOC: usize = 0x00AA_13E0;
/// Default `BSOcclusionPlane` constructor (thiscall, `this` = 0xFC buffer).
pub(super) const CONSTRUCT: usize = 0x00C3_35D0;
/// Size setter: copies two floats to plane +0x14/+0x18.
pub(super) const SET_SIZE: usize = 0x0041_6A30;
/// Position setter: copies three floats to plane +0x08.
pub(super) const SET_POSITION: usize = 0x0041_69F0;
/// Axis-angle rotation matrix builder (ecx = 9-float matrix).
pub(super) const BUILD_ROTATION: usize = 0x0041_68A0;
/// Rotation setter: copies nine floats to plane +0x1C.
pub(super) const SET_ROTATION: usize = 0x0041_6A70;
/// Append a plane to the scene-graph occluder list at scene_graph + 8.
pub(super) const APPEND: usize = 0x00C5_AE70;
/// Return one list node to the native pool (this = list, arg = node, ret 4).
pub(super) const FREE_NODE: usize = 0x004A_49E0;
/// Engine singleton table getter (`[index]`, index 0 is the scene-graph owner).
pub(super) const SINGLETON: usize = 0x0045_0B80;
/// `NiRefObject` reference count offset inside the object.
pub(super) const REFCOUNT_OFFSET: usize = 0x04;
/// `NiRefObject::DeleteThis` vtable slot (scalar deleting destructor).
pub(super) const VTABLE_DELETE_THIS: usize = 0x04;
/// `BSOcclusionPlane::+0xEA` camera-side test flag.
///
/// `0x00C335D0` sets it to 1 (two-sided: `0x00C358A0` returns immediately).
/// Writing zero makes `0x00C358A0` build the rectangle plane and activate the
/// plane only when the camera is on the rectangle's negative side, which is the
/// outward side for the matrix convention emitted here. This is the engine's
/// own camera-side rejection and costs no per-frame Rust work.
pub(super) const PLANE_SIDE_FLAG: usize = 0xEA;

/// Compressed plane allocation size.
pub(super) const PLANE_SIZE: usize = 0xFC;

// Scene-graph occluder list at `scene_graph + 8`.
pub(super) const LIST_OFFSET: usize = 0x08;
pub(super) const LIST_HEAD: usize = 0x00;
pub(super) const LIST_TAIL: usize = 0x04;
pub(super) const LIST_COUNT: usize = 0x08;
pub(super) const NODE_NEXT: usize = 0x00;
pub(super) const NODE_PREV: usize = 0x04;
pub(super) const NODE_PLANE: usize = 0x08;

/// Scene-graph pointer inside the singleton returned by `SINGLETON(0)`.
pub(super) const OWNER_SCENE_GRAPH: usize = 0x1E0;
/// Observer/player world position inside the same singleton.
pub(super) const OWNER_POSITION: usize = 0x1F0;

// ---------------------------------------------------------------------------
// Live cell/ref/scene offsets for the runtime occluder collector.
//
// All offsets are verified against the supported executable: the tList walk
// against the engine's own child traversal at 0x00A5DBE0, `NiAVObject`/
// `NiGeometry` against `NiGeometry::UpdateWorldBound` at 0x00A80710, and the
// `IsNode`/`IsGeometry` virtual slots against the NiNode (0x0109B5AC) and
// NiTriShape (0x0109D454) vtables.
// ---------------------------------------------------------------------------

/// `TESForm::typeID` (u8).
pub(super) const TESFORM_TYPE_ID: usize = 0x04;
/// `TESObjectREFR::baseForm`.
pub(super) const REFR_BASE_FORM: usize = 0x20;
/// `TESObjectREFR::renderState`.
pub(super) const REFR_RENDER_STATE: usize = 0x64;
/// `TESObjectREFR::parentCell`.
pub(super) const REFR_PARENT_CELL: usize = 0x40;
/// `TESObjectCELL::objectList` (`tList<TESObjectREFR>`). The head node holds
/// the first reference in its `data` field; `tList` is a singly linked list.
pub(super) const CELL_OBJECT_LIST: usize = 0xAC;
/// `tList` node data offset.
pub(super) const TLIST_DATA: usize = 0x00;
/// `tList` node next offset.
pub(super) const TLIST_NEXT: usize = 0x04;
/// `RenderState::niNode`.
pub(super) const RENDER_STATE_NODE: usize = 0x14;
/// `NiNode` child array base and count.
pub(super) const NODE_CHILD_BASE: usize = 0xA0;
pub(super) const NODE_CHILD_COUNT: usize = 0xA6;
/// `NiAVObject::m_kWorld` rotation, translation and scale.
pub(super) const WORLD_ROTATION: usize = 0x68;
pub(super) const WORLD_TRANSLATION: usize = 0x8C;
pub(super) const WORLD_SCALE: usize = 0x98;
/// `NiAVObject::m_pWorldBound` (pointer to a `NiBound` center + radius).
pub(super) const AVOBJECT_WORLD_BOUND: usize = 0x20;
pub(super) const NIBOUND_RADIUS: usize = 0x0C;
/// `NiGeometry::m_kProperties` alpha pointer, model data and skin instance.
pub(super) const GEOMETRY_ALPHA: usize = 0x9C;
pub(super) const GEOMETRY_MODEL_DATA: usize = 0xB8;
pub(super) const GEOMETRY_SKIN: usize = 0xBC;
/// `NiGeometryData`: vertex count, vertex pointer, compression flags.
/// Verified against `NiGeometryData` bound/vertex users at `0x00A87900` and
/// `0x00A66F90` and the compression getter at `0x00EE8AA0`.
pub(super) const GEOMETRY_DATA_VERTEX_COUNT: usize = 0x08;
pub(super) const GEOMETRY_DATA_VERTICES: usize = 0x20;
pub(super) const GEOMETRY_DATA_COMPRESS: usize = 0x39;
pub(super) const COMPRESS_POSITION: u8 = 0x10;
/// `NiAlphaProperty::m_usFlags`.
pub(super) const ALPHA_FLAGS: usize = 0x18;
/// `NiAlphaProperty` vtable (`0x00A5D3BB` stores it in the constructor). The
/// pointer at `NiGeometry +0x9C` is treated as an alpha property only when its
/// vtable matches; otherwise the geometry is admitted. This keeps a wrong or
/// shifted property offset from rejecting every geometry in the cell.
pub(super) const ALPHA_PROPERTY_VTABLE: usize = 0x0109_B4F4;
/// `NiObject` virtual slots: `IsNode` and `IsGeometry`.
pub(super) const VTABLE_IS_NODE: usize = 0x0C;
pub(super) const VTABLE_IS_GEOMETRY: usize = 0x18;
/// `NiAlphaProperty` flag bits that mark see-through or cutout surfaces.
pub(super) const ALPHA_BLEND: u16 = 0x0001;
pub(super) const ALPHA_TEST: u16 = 0x0200;
/// `TESForm::typeID` values accepted as static occluder candidates.
///
/// The collector reads the loaded 3D geometry, not the base form's authored
/// bounds, so the base type only decides which references are worth walking.
/// `TESObjectSTAT` and `BGSStaticCollection` are static content.
/// `BGSMovableStatic` is deliberately excluded: its 3D can move after the
/// planes are generated, which would leave a stale occluder behind.
pub(super) const FORM_TYPE_STAT: u8 = 0x20;
pub(super) const FORM_TYPE_STATIC_COLLECTION: u8 = 0x21;

/// `NiObject::IsNode`/`IsGeometry`: returns `this` or null.
pub(super) type IsKindFn = unsafe extern "thiscall" fn(*mut c_void) -> *mut c_void;

/// `DataHandler` singleton pointer global (`DataHandler::Get()` returns
/// `*(DataHandler**)0x011C3F2C`).
pub(super) const DATA_HANDLER_PTR: usize = 0x011C_3F2C;
/// `DataHandler::modList` (`ModList`; `tList<ModInfo>` head at `+0`).
pub(super) const DATA_HANDLER_MOD_LIST: usize = 0x210;
/// `ModInfo::name` (char[0x104]) and the embedded `WIN32_FIND_DATA` file size
/// (`fileData` at `+0x29C`; size low at `+0x20`, high at `+0x1C` inside it).
pub(super) const MOD_INFO_NAME: usize = 0x20;
pub(super) const MOD_INFO_NAME_CAPACITY: usize = 0x104;
pub(super) const MOD_INFO_FILE_SIZE_LOW: usize = 0x2BC;
pub(super) const MOD_INFO_FILE_SIZE_HIGH: usize = 0x2B8;
/// Upper bound on loaded mods (mod index space is 0x00..0xFF).
pub(super) const MOD_INFO_MAX: usize = 0xFF;

// Player, cell and worldspace anchors.
pub(super) const PLAYER_PTR: usize = 0x011D_EA3C;
pub(super) const CELL_FORM_ID: usize = 0x0C;
/// `TESObjectCELL::coords` (`CellCoordinates*`). The grid X/Y are the two
/// dwords at the pointed structure, not the cell field itself.
pub(super) const CELL_EXTERIOR_COORDS: usize = 0x48;
pub(super) const COORDS_X: usize = 0x00;
pub(super) const COORDS_Y: usize = 0x04;
pub(super) const CELL_WORLDSPACE: usize = 0xC0;
pub(super) const TESFORM_REF_ID: usize = 0x0C;

/// Game allocator.
pub(super) type AllocFn = unsafe extern "cdecl" fn(usize) -> *mut c_void;
/// Default plane constructor.
pub(super) type ConstructFn = unsafe extern "thiscall" fn(*mut c_void) -> *mut c_void;
/// Two-float setter (size).
pub(super) type SetPairFn = unsafe extern "thiscall" fn(*mut c_void, *const f32);
/// Three-float setter (position).
pub(super) type SetTripleFn = unsafe extern "thiscall" fn(*mut c_void, *const f32);
/// Axis-angle matrix builder.
pub(super) type BuildRotationFn = unsafe extern "thiscall" fn(*mut f32, f32, f32, f32, f32);
/// Nine-float setter (rotation).
pub(super) type SetRotationFn = unsafe extern "thiscall" fn(*mut c_void, *const f32);
/// List append.
pub(super) type AppendFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);
/// List node free.
pub(super) type FreeNodeFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);
/// Singleton getter.
pub(super) type SingletonFn = unsafe extern "cdecl" fn(usize) -> *mut c_void;

/// Exact first-byte expectations for every called function.
///
/// A supported executable matches all of them. Any mismatch disables the
/// feature before it touches the occluder list.
pub(super) static SIGNATURES: &[CodeSignature] = &[
    CodeSignature::new(
        "occlusion plane allocator",
        ALLOC,
        &[
            0x51, 0x8B, 0x44, 0x24, 0x08, 0x85, 0xC0, 0x75, 0x05, 0xB8, 0x01, 0x00, 0x00, 0x00,
            0x6A, 0x00, 0x6A, 0xFF, 0x89, 0x44, 0x24, 0x08, 0xA1, 0x80,
        ],
    ),
    CodeSignature::new(
        "occlusion plane constructor",
        CONSTRUCT,
        &[
            0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x78, 0xD8, 0xF2, 0x00, 0x64, 0xA1, 0x00, 0x00,
            0x00, 0x00, 0x50, 0x83, 0xEC, 0x24, 0x56, 0x57, 0xA1, 0xBC, 0x16, 0x1C, 0x01, 0x33,
            0xC5, 0x50, 0x8D, 0x45, 0xF4, 0x64, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x89,
        ],
    ),
    CodeSignature::new(
        "occlusion plane size setter",
        SET_SIZE,
        &[
            0x55, 0x8B, 0xEC, 0x51, 0x89, 0x4D, 0xFC, 0x8B, 0x45, 0x08, 0x8B, 0x08, 0x8B, 0x50,
            0x04, 0x8B, 0x45, 0xFC, 0x89, 0x48, 0x14, 0x89, 0x50, 0x18,
        ],
    ),
    CodeSignature::new(
        "occlusion plane position setter",
        SET_POSITION,
        &[
            0x55, 0x8B, 0xEC, 0x51, 0x89, 0x4D, 0xFC, 0x8B, 0x45, 0x08, 0x8B, 0x4D, 0xFC, 0x83,
            0xC1, 0x08, 0x8B, 0x10, 0x89, 0x11, 0x8B, 0x50, 0x04, 0x89,
        ],
    ),
    CodeSignature::new(
        "occlusion plane rotation setter",
        SET_ROTATION,
        &[
            0x55, 0x8B, 0xEC, 0x51, 0x56, 0x57, 0x89, 0x4D, 0xFC, 0x8B, 0x75, 0x08, 0x8B, 0x7D,
            0xFC, 0x83, 0xC7, 0x1C, 0xB9, 0x09, 0x00, 0x00, 0x00, 0xF3,
        ],
    ),
    CodeSignature::new(
        "occlusion plane rotation builder",
        BUILD_ROTATION,
        &[
            0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x34, 0x89, 0x4D, 0xCC, 0x8D, 0x45, 0xF0, 0x50, 0x8D,
            0x4D, 0xF4, 0x51, 0x51, 0xD9, 0x45, 0x08, 0xD9, 0x1C, 0x24, 0xE8, 0xE3, 0x00, 0x00,
            0x00, 0x83, 0xC4, 0x0C,
        ],
    ),
    CodeSignature::new(
        "occlusion plane list append",
        APPEND,
        &[
            0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x28, 0x89, 0x4D, 0xD8, 0x83, 0x7D, 0x08, 0x00, 0x74,
            0x2C, 0x8B, 0x45, 0xD8, 0x83, 0xC0, 0x08, 0x89, 0x45, 0xDC, 0x8B, 0x4D, 0xDC, 0x83,
            0xC1, 0x08, 0xE8, 0x7D,
        ],
    ),
    CodeSignature::new(
        "occlusion plane list node free",
        FREE_NODE,
        &[
            0x55, 0x8B, 0xEC, 0x51, 0x89, 0x4D, 0xFC, 0x8B, 0x45, 0x08, 0xC7, 0x40, 0x08, 0x00,
            0x00, 0x00, 0x00, 0x8B, 0x4D, 0x08, 0x51, 0x8B, 0x4D, 0xFC,
        ],
    ),
    CodeSignature::new(
        "scene graph singleton getter",
        SINGLETON,
        &[
            0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x8B, 0x04, 0x85, 0xC8, 0x91, 0x1F, 0x01, 0x5D,
            0xC3, 0xCC,
        ],
    ),
];
