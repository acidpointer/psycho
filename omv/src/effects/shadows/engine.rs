//! Typed access to the executable-specific Fallout: New Vegas shadow ABI.
//!
//! All addresses and offsets in this module belong only to the supported
//! `FalloutNV.exe` identity below. They are derived from the repository's
//! authoritative shadow analysis and the matching xNVSE/NVR class layouts.
//! Keeping them together makes ABI drift visible in tests and prevents magic
//! numbers from spreading into renderer code.
//!
//! The test build consumes the complete recovered contract. Production uses
//! only the subset needed by native traversal, so unused-layout warnings are
//! suppressed here rather than deleting durable reverse-engineering evidence.

#![cfg_attr(not(test), allow(dead_code))]

use core::ops::Range;

/// SHA-256 identity of the only executable covered by the native contract.
pub(super) const FNV_EXE_SHA256: &str =
    "42fee7d6cd74e801372aa89c8f71c974cebd3c20ec9ad43d1465b8fa9646b49c";

/// Calling conventions at engine boundaries used by the replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EngineCallAbi {
    /// Object receiver arrives in ECX and the callee removes no stack args.
    ThiscallReceiverEcx,
}

/// Common-prefix ownership and caller coverage for the supported executable.
pub(super) struct HookSiteContract;

impl HookSiteContract {
    /// Common native shadow prefix owned by all three dispatcher branches.
    pub(super) const COMMON_PREFIX: usize = 0x0087_1290;
    /// Native post-shadow tail that a replacement must call exactly once.
    pub(super) const NATIVE_TAIL: usize = 0x0087_1A50;
    /// Direct return addresses for the three dispatcher branch variants.
    pub(super) const BRANCH_RETURNS: [usize; 3] = [0x0087_0856, 0x0087_0A79, 0x0087_0C41];
    /// Complete entry fingerprint overwritten by the inline hook.
    pub(super) const ENTRY_PROLOGUE: [u8; 9] =
        [0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x9C, 0x00, 0x00, 0x00];
    /// ABI of the hooked common prefix.
    pub(super) const ENTRY_ABI: EngineCallAbi = EngineCallAbi::ThiscallReceiverEcx;
    /// ABI preserved when explicitly invoking the native tail.
    pub(super) const TAIL_ABI: EngineCallAbi = EngineCallAbi::ThiscallReceiverEcx;
}

/// Supported engine geometry categories and their native submission entries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GeometryKind {
    /// `NiTriStrips`, submitted through `RenderTriStripsAlt`.
    TriStrips,
    /// `NiTriShape`, submitted through `RenderTriShapeAlt`.
    TriShape,
    /// One prepared `NiSkinPartition::Partition`.
    Skinned,
}

impl GeometryKind {
    /// Return the proven native render entry for this geometry category.
    pub(super) const fn render_address(self) -> usize {
        match self {
            Self::TriStrips => 0x00E7_4840,
            Self::TriShape => 0x00E7_45A0,
            Self::Skinned => 0x00E6_D310,
        }
    }
}

/// Raw 32-bit class sizes and offsets consumed by bounded render-thread reads.
pub(super) struct NativeLayout;

impl NativeLayout {
    /// Process global containing the supported executable's `TES*` manager.
    pub(super) const TES_SINGLETON_PTR: usize = 0x011D_EA10;
    /// Process global containing the `PlayerCharacter*`.
    pub(super) const PLAYER_SINGLETON_PTR: usize = 0x011D_EA3C;
    /// Process global containing the active `NiDX9Renderer*`.
    pub(super) const NIDX9_RENDERER_SINGLETON_PTR: usize = 0x011C_73B4;
    /// Process global containing the active `WorldSceneGraph*`.
    pub(super) const WORLD_SCENE_GRAPH_PTR: usize = 0x011D_EB7C;
    /// Runtime `fDefaultWorldFOV` setting used by NVR cascade compensation.
    pub(super) const DEFAULT_WORLD_FOV: usize = 0x0120_3160;
    /// `SceneGraph::cameraFOV` in degrees.
    pub(super) const SCENE_GRAPH_CAMERA_FOV: usize = 0xBC;
    /// `NiDX9Renderer::renderState`.
    pub(super) const NIDX9_RENDERER_RENDER_STATE: usize = 0x8B8;
    /// `NiDX9RenderState::m_auiCullModeMapping[4][2]`.
    pub(super) const NIDX9_RENDER_STATE_CULL_MODE_MAPPING: usize = 0xD4;
    /// `NiDX9RenderState::LeftHanded`, which selects the mapping column.
    pub(super) const NIDX9_RENDER_STATE_LEFT_HANDED: usize = 0xF4;
    /// `TES::gridCellArray`.
    pub(super) const TES_GRID_CELL_ARRAY: usize = 0x08;
    /// `TES::objectLODRoot`.
    pub(super) const TES_OBJECT_LOD_ROOT: usize = 0x0C;
    /// `TES::landLOD`.
    pub(super) const TES_LAND_LOD_ROOT: usize = 0x10;
    /// `TES::directionalLight`.
    pub(super) const TES_DIRECTIONAL_LIGHT: usize = 0x1C;
    /// `TES::currentCell`.
    pub(super) const TES_CURRENT_CELL: usize = 0x34;
    /// `TESObjectCELL::flags0`.
    pub(super) const CELL_FLAGS: usize = 0x24;
    /// Inline head of `TESObjectCELL::objectList`.
    pub(super) const CELL_OBJECT_LIST: usize = 0xAC;
    /// `TESObjectREFR::baseForm`.
    pub(super) const REFERENCE_BASE_FORM: usize = 0x20;
    /// `TESObjectREFR::parentCell`.
    pub(super) const REFERENCE_PARENT_CELL: usize = 0x40;
    /// `TESObjectREFR::renderData`.
    pub(super) const REFERENCE_RENDER_DATA: usize = 0x64;
    /// `TESObjectREFRData::niNode`.
    pub(super) const REFERENCE_DATA_NODE: usize = 0x14;
    /// `TESForm::flags`, including the no-shadow-cast bit.
    pub(super) const TES_FORM_FLAGS: usize = 0x08;
    /// `TESForm::formType`, used by NVR's per-cascade form profiles.
    pub(super) const TES_FORM_TYPE: usize = 0x04;
    /// Size of `NiAVObject`.
    pub(super) const NI_AV_OBJECT_SIZE: usize = 0x9C;
    /// `NiAVObject::m_parent`.
    pub(super) const NI_AV_OBJECT_PARENT: usize = 0x18;
    /// Pointer to `NiAVObject::m_kWorldBound`.
    pub(super) const NI_AV_OBJECT_WORLD_BOUND: usize = 0x20;
    /// `NiAVObject::m_flags`.
    pub(super) const NI_AV_OBJECT_FLAGS: usize = 0x30;
    /// `NiAVObject::m_worldTransform`.
    pub(super) const NI_AV_OBJECT_WORLD_TRANSFORM: usize = 0x68;
    /// Size of `NiNode`.
    pub(super) const NI_NODE_SIZE: usize = 0xAC;
    /// `NiNode::m_children` (`NiTArray<NiAVObject*>`).
    pub(super) const NI_NODE_CHILDREN: usize = 0x9C;
    /// Size of `NiGeometry`.
    pub(super) const NI_GEOMETRY_SIZE: usize = 0xC4;
    /// `NiGeometry::propertyState`.
    pub(super) const NI_GEOMETRY_PROPERTIES: usize = 0x9C;
    /// `NiGeometry::geomData`.
    pub(super) const NI_GEOMETRY_DATA: usize = 0xB8;
    /// `NiGeometry::skinInstance`.
    pub(super) const NI_GEOMETRY_SKIN: usize = 0xBC;
    /// `NiGeometry::shader`.
    pub(super) const NI_GEOMETRY_SHADER: usize = 0xC0;
    /// `NiMaterialProperty::fAlpha` (`+0x40` is emission multiplier).
    pub(super) const NI_MATERIAL_ALPHA: usize = 0x3C;
    /// `BSDismemberSkinInstance::partitionNumber`.
    pub(super) const DISMEMBER_PARTITION_COUNT: usize = 0x34;
    /// `BSDismemberSkinInstance::partitions`.
    pub(super) const DISMEMBER_PARTITIONS: usize = 0x38;
    /// `BSDismemberSkinInstance::IsRenderable`.
    pub(super) const DISMEMBER_RENDERABLE: usize = 0x3C;
    /// `NiGeometry::propertyState.m_spAlphaProperty`.
    pub(super) const NI_PROPERTY_ALPHA: usize = 0x9C;
    /// `NiGeometry::propertyState.m_spMaterialProperty`.
    pub(super) const NI_PROPERTY_MATERIAL: usize = 0xA4;
    /// `NiGeometry::propertyState.m_spShadeProperty`.
    pub(super) const NI_PROPERTY_SHADE: usize = 0xA8;
    /// `NiGeometry::propertyState.m_spStencilProperty`.
    pub(super) const NI_PROPERTY_STENCIL: usize = 0xAC;
    /// Size of `NiGeometryData`.
    pub(super) const NI_GEOMETRY_DATA_SIZE: usize = 0x40;
    /// `NiGeometryData::m_usDirtyFlags`.
    pub(super) const NI_GEOMETRY_DATA_DIRTY_FLAGS: usize = 0x0E;
    /// `NiGeometryData::m_pkBuffData`.
    pub(super) const NI_GEOMETRY_DATA_BUFFER: usize = 0x34;
    /// Complete `NiGeometryBufferData` size.
    pub(super) const NI_GEOMETRY_BUFFER_SIZE: usize = 0x54;
    /// Complete `NiSkinInstance` size.
    pub(super) const NI_SKIN_INSTANCE_SIZE: usize = 0x34;
    /// Complete `NiSkinPartition` size.
    pub(super) const NI_SKIN_PARTITION_SIZE: usize = 0x10;
    /// Complete `NiSkinPartition::Partition` stride.
    pub(super) const NI_SKIN_PARTITION_ENTRY_SIZE: usize = 0x2C;
    /// Size of `NiPointLight`.
    pub(super) const NI_POINT_LIGHT_SIZE: usize = 0xFC;
    /// `NiDynamicEffect::CastShadows` within `NiPointLight`.
    pub(super) const NI_POINT_LIGHT_CASTS_SHADOWS: usize = 0x9E;
    /// `NiLight::Spec`, whose red component is NVR's effective radius.
    pub(super) const NI_POINT_LIGHT_SPECULAR: usize = 0xE0;
    /// `ShadowSceneLight::kGeometryList`.
    pub(super) const SHADOW_SCENE_LIGHT_GEOMETRY_LIST: usize = 0xE0;
    /// `ShadowSceneLight::bPointLight`.
    pub(super) const SHADOW_SCENE_LIGHT_POINT: usize = 0xF4;
    /// `ShadowSceneLight::bAmbientLight`.
    pub(super) const SHADOW_SCENE_LIGHT_AMBIENT: usize = 0xF5;
    /// `ShadowSceneLight::sourceLight`.
    pub(super) const SHADOW_SCENE_LIGHT_SOURCE: usize = 0xF8;
    /// `ShadowSceneLight::spShadowRenderTarget`.
    pub(super) const SHADOW_SCENE_LIGHT_RENDER_TARGET: usize = 0x10C;
    /// `ShadowSceneLight::bIsEnabled`.
    pub(super) const SHADOW_SCENE_LIGHT_ENABLED: usize = 0x110;
    /// Complete `ShadowSceneLight` size in the supported xNVSE layout.
    pub(super) const SHADOW_SCENE_LIGHT_SIZE: usize = 0x250;
    /// The native list is borrowed only during the common-prefix transaction.
    pub(super) const SHADOW_GEOMETRY_LIST_VALID_ONLY_DURING_COMMON_PREFIX_EPOCH: bool = true;
}

/// Version-one vertex/pixel register ABI of the generation shader family.
pub(super) struct ShadowGenerationAbi;

impl ShadowGenerationAbi {
    /// Object world-transform rows in vertex constants.
    pub(super) const WORLD_ROWS: Range<usize> = 0..4;
    /// Light view-projection rows in vertex constants.
    pub(super) const VIEW_PROJECTION_ROWS: Range<usize> = 4..8;
    /// Geometry-kind, alpha-control, and point-radius data.
    pub(super) const GEOMETRY_DATA: usize = 8;
    /// Fifty-four rows reserved for up to 18 three-row bone matrices.
    pub(super) const BONE_ROWS: Range<usize> = 9..63;
    /// SpeedTree billboard, wind, and leaf registers.
    pub(super) const SPEEDTREE_ROWS: Range<usize> = 63..140;
    /// Terrain-LOD world/range/morph registers.
    pub(super) const TERRAIN_LOD_ROWS: Range<usize> = 140..146;
    /// Alpha-tested diffuse texture sampler.
    pub(super) const DIFFUSE_SAMPLER: u32 = 0;
}
