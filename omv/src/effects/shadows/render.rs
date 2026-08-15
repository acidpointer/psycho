//! Native geometry traversal and submission for shadow-map generation.
//!
//! The engine remains the owner of vertex/index buffers and skin matrices.
//! OMV binds those already-prepared buffers to dedicated shadow shaders, calls
//! the original renderer submissions, and restores the geometry dirty flags
//! that the native helpers clear. All object pointers are borrowed only for
//! the common shadow transaction.

use core::{ffi::c_void, mem::transmute, ptr::read_unaligned};

use libpsycho::os::windows::directx9::{
    D3DCMP_ALWAYS, D3DCMP_LESSEQUAL, D3DCULL_CCW, D3DCULL_CW, D3DCULL_NONE, D3DRS_ADAPTIVETESS_Y,
    D3DRS_ALPHABLENDENABLE, D3DRS_ALPHAFUNC, D3DRS_ALPHAREF, D3DRS_ALPHATESTENABLE,
    D3DRS_COLORWRITEENABLE, D3DRS_CULLMODE, D3DRS_DEPTHBIAS, D3DRS_MULTISAMPLEANTIALIAS,
    D3DRS_MULTISAMPLEMASK, D3DRS_POINTSIZE, D3DRS_SLOPESCALEDEPTHBIAS, D3DRS_STENCILENABLE,
    D3DRS_ZENABLE, D3DRS_ZFUNC, D3DRS_ZWRITEENABLE, D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV,
    D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER, D3DSAMP_MIPFILTER, D3DSAMP_SRGBTEXTURE, D3DTADDRESS_WRAP,
    D3DTEXF_NONE, D3DTEXF_POINT, Device9Ref, Direct3DResult, PixelShader9, VertexShader9,
    direct3d_failure,
};

use super::{
    contract::{
        CasterAdmission, CasterPolicy, SkinIndexEncoding, dismember_partition_is_renderable,
        first_person_caster_is_excluded, skinned_submission_is_available,
        sphere_intersects_cube_face, sphere_intersects_point_light,
    },
    engine::{GeometryKind, NativeLayout, ShadowGenerationAbi},
    math::{CascadeProjection, Sphere, camera_relative_world_matrix},
};

const MAX_NODE_VISITS: usize = 32_768;
const MAX_NODE_CHILDREN: usize = 16_384;
const MAX_SKIN_PARTITIONS: usize = 64;
const MAX_BONES_PER_PARTITION: usize = 18;
const MAX_PARENT_VISITS: usize = 128;
const MAX_SKIN_STATE_SNAPSHOTS: usize = 2_048;
const SKIN_LOOKUP_CAPACITY: usize = MAX_SKIN_STATE_SNAPSHOTS * 2;
const NI_AV_OBJECT_APP_CULLED: u32 = 1 << 0;
const SHADOW_BONE_REGISTERS: u32 = 3;
const INVALID_BONE_REGISTERS: u32 = u32::MAX;
const AMD_ALPHA_TO_COVERAGE_OFF: u32 = u32::from_le_bytes(*b"A2M0");

const NI_OBJECT_IS_NODE_SLOT: usize = 0x03;
const NI_OBJECT_IS_FADE_NODE_SLOT: usize = 0x04;
const NI_OBJECT_IS_MULTIBOUND_NODE_SLOT: usize = 0x05;
const NI_OBJECT_IS_GEOMETRY_SLOT: usize = 0x06;
const NI_OBJECT_IS_TRI_STRIPS_SLOT: usize = 0x08;
const NI_OBJECT_GET_RTTI_SLOT: usize = 0x02;
const MULTIBOUND_SHAPE_GET_BOUND_SLOT: usize = 0x29;

const NI_TARRAY_DATA: usize = 0x04;
const NI_TARRAY_END: usize = 0x0A;
const NI_SWITCH_NODE_RTTI: usize = 0x011F_5EB4;
const NI_SWITCH_ACTIVE_INDEX: usize = 0xB0;
const BS_DISMEMBER_SKIN_RTTI: usize = 0x011F_49D8;
const BS_MULTIBOUND: usize = 0xAC;
const BS_MULTIBOUND_SHAPE: usize = 0x0C;
const BS_FADE_ALPHA: usize = 0xB8;

const SHADE_FIRST_PERSON: u16 = 1 << 1;
const SHADER_REFRACTION: u32 = 0x0000_8000;
const SHADER_FIRE_REFRACTION: u32 = 0x0001_0000;
const SHADER_DECAL: u32 = 0x0400_0000;
const SHADER_DYNAMIC_DECAL: u32 = 0x0800_0000;
const SHADER_LOD_LANDSCAPE: u32 = 1 << 1;
const ALPHA_BLEND: u16 = 0x0001;
const ALPHA_TEST: u16 = 0x0200;

const SHADE_FLAGS: usize = 0x18;
const SHADE_TYPE: usize = 0x1C;
const SHADER_FLAGS_1: usize = 0x20;
const SHADER_FLAGS_2: usize = 0x24;
const SHADER_DEFINITION_INDEX: usize = 0x58;
const SHADOW_LIGHT_SHADER: u32 = 0x01;
const PARALLAX_SHADER: u32 = 0x0F;
const LIGHTING_30_SHADER: u32 = 0x1D;
const ALPHA_FLAGS: usize = 0x18;
const STENCIL_FLAGS: usize = 0x18;
const PPLIGHTING_TEXTURE_ZERO: usize = 0xAC;
const SPEEDTREE_LEAF_DATA: usize = 0x88;
const SPEEDTREE_LEAF_ROWS: usize = 0x08;
const TREE_MODEL: usize = 0xE4;
const TREE_LEAF_TEXTURE: usize = 0x30;
const NI_TEXTURE_RENDERER_DATA: usize = 0x24;
const DX9_TEXTURE: usize = 0x64;

const GEOMETRY_BUFFER_FVF: usize = 0x0C;
const GEOMETRY_BUFFER_DECLARATION: usize = 0x10;
const GEOMETRY_BUFFER_VERTEX_COUNT: usize = 0x18;
const GEOMETRY_BUFFER_STREAM_COUNT: usize = 0x20;
const GEOMETRY_BUFFER_STRIDES: usize = 0x24;
const GEOMETRY_BUFFER_CHIPS: usize = 0x28;
const GEOMETRY_BUFFER_INDEX_BUFFER: usize = 0x34;
const VERTEX_CHIP_BUFFER: usize = 0x08;

const SKIN_PARTITION_COUNT: usize = 0x08;
const SKIN_PARTITION_ARRAY: usize = 0x0C;
const PARTITION_BONES: usize = 0x20;
const PARTITION_BONE_INDICES: usize = 0x04;
const PARTITION_BUFFER: usize = 0x28;
// `NiDX9Renderer::CalculateBoneMatrices` subtracts this engine camera origin
// from the translation column of every output 3x4 matrix. NVR synchronizes the
// global in `SetupSceneCamera`; OMV instead keeps engine state untouched and
// rebases the copied rows into its coherent captured-camera domain.
const CAMERA_WORLD_TRANSLATION: usize = 0x011F_474C;

const SPEEDTREE_ROCK_PARAMS: usize = 0x0120_0658;
const SPEEDTREE_RUSTLE_PARAMS: usize = 0x0120_0668;
const SPEEDTREE_WIND_ROWS: usize = 0x0120_0688;
const TERRAIN_LOADED_RANGE: usize = 0x011F_95F4;
const TERRAIN_LOD_DROP: usize = 0x011A_D808;
const PPLIGHTING_MORPH_DISTANCE: usize = 0x80;

type VirtualCast = unsafe extern "thiscall" fn(*mut u8) -> *mut u8;
type GetRtti = unsafe extern "thiscall" fn(*mut u8) -> *const NativeRtti;
type GetMultiBound = unsafe extern "thiscall" fn(*mut u8, *mut NativeBound);
type CalculateBoneMatrices =
    unsafe extern "thiscall" fn(*mut c_void, *mut u8, *mut u8, u8, i32, u8);
type DrawSkinnedGeometry = unsafe extern "thiscall" fn(*mut c_void, *mut u8, *mut u8, *mut c_void);

#[repr(C)]
struct NativeRtti {
    _name: *const u8,
    parent: *const NativeRtti,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeBound {
    center: [f32; 3],
    radius: f32,
}

/// Device shader objects shared by every shadow-map generation pass.
pub(super) struct GenerationPrograms {
    /// Directional vertex programs for D3DCOLOR, UBYTE4N, and UBYTE4 skins.
    pub(super) directional_vertex: [VertexShader9; 3],
    /// EVSM4 caster pixel program.
    pub(super) directional_pixel: PixelShader9,
    /// Point-cube vertex programs for D3DCOLOR, UBYTE4N, and UBYTE4 skins.
    pub(super) cube_vertex: [VertexShader9; 3],
    /// Radial-depth cube pixel program.
    pub(super) cube_pixel: PixelShader9,
}

/// Geometry ownership selected for one shadow-map submission.
///
/// Point cubes keep immutable world geometry in a backing cube and refresh
/// only animated skins in the visible cube faces. Directional traversal still
/// uses `All` because its static/actor split happens at root admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CasterSubset {
    All,
    Static,
    Dynamic,
}

impl CasterSubset {
    const fn admits(self, skinned: bool) -> bool {
        match self {
            Self::All => true,
            Self::Static => !skinned,
            Self::Dynamic => skinned,
        }
    }

    const fn owns_presentation_visibility(self) -> bool {
        matches!(self, Self::Dynamic)
    }
}

/// Return whether this traversal may submit the object's presented branch.
///
/// Retained static maps intentionally ignore camera-epoch application culling,
/// but same-frame actors and actor overlays must honor it at every hierarchy
/// level. Otherwise hidden head, equipment, or LOD alternatives can be drawn
/// together as one deformed shadow.
const fn presentation_object_is_visible(owns_presentation_visibility: bool, flags: u32) -> bool {
    !owns_presentation_visibility || flags & NI_AV_OBJECT_APP_CULLED == 0
}

/// Select the one presented child owned by an engine switch node.
///
/// A negative or stale index presents no child. Falling back to ordinary child
/// traversal in either case would project mutually exclusive fixture, armor,
/// or LOD meshes together.
const fn switch_active_child_index(active: i32, child_count: usize) -> Option<usize> {
    if active >= 0 && (active as usize) < child_count {
        Some(active as usize)
    } else {
        None
    }
}

/// Push one borrowed node identity without growing the render-thread stack.
///
/// The visit limit bounds popped nodes, not siblings waiting on the depth-first
/// stack. A broad hierarchy can therefore exhaust reserved storage before the
/// visit limit is reached. Returning `false` lets the transactional producer
/// use native fallback without allocating or publishing a partial map.
fn push_traversal_node(nodes: &mut Vec<usize>, identity: usize) -> bool {
    if nodes.len() == nodes.capacity() {
        return false;
    }
    nodes.push(identity);
    true
}

/// Mutable allocation-free traversal state retained with device resources.
pub(super) struct TraversalScratch {
    nodes: Vec<usize>,
    skin_states: Vec<SkinStateSnapshot>,
    skin_lookup: Vec<SkinLookupSlot>,
    skin_lookup_generation: u32,
    declarations: Vec<VertexDeclarationEncoding>,
    render_state: Option<RenderStateSnapshot>,
}

#[derive(Clone, Copy)]
struct SkinStateSnapshot {
    skin: usize,
    frame_id: u32,
    bone_registers: u32,
    world_transform: [u32; 13],
    calculation_initialized: bool,
}

#[derive(Clone, Copy, Default)]
struct SkinLookupSlot {
    generation: u32,
    skin: usize,
    state_index: u16,
}

#[derive(Clone, Copy)]
struct VertexDeclarationEncoding {
    declaration: usize,
    encoding: SkinIndexEncoding,
}

#[derive(Clone, Copy)]
struct RenderStateSnapshot {
    state: usize,
    internal_normalize_normals: u8,
}

impl TraversalScratch {
    /// Preallocate the only traversal container used by routine render calls.
    pub(super) fn with_capacity() -> Self {
        Self {
            nodes: Vec::with_capacity(MAX_NODE_VISITS),
            skin_states: Vec::with_capacity(MAX_SKIN_STATE_SNAPSHOTS),
            // A load factor of at most one half bounds probe chains while the
            // generation stamp resets logical ownership without clearing the
            // table in every producer transaction.
            skin_lookup: vec![SkinLookupSlot::default(); SKIN_LOOKUP_CAPACITY],
            skin_lookup_generation: 0,
            declarations: Vec::with_capacity(64),
            render_state: None,
        }
    }

    /// Begin one engine-state journal around all native skinned submissions.
    ///
    /// D3D state blocks do not own `NiSkinInstance` calculation stamps or the
    /// CPU-side `NiDX9RenderState::InternalNormalizeNormals` byte. The native
    /// bone helper writes both. Capturing them once per producer lets repeated
    /// cascade/cube submissions reuse the calculated matrices, then restores
    /// the renderer value and a cache-coherent skin stamp before the later
    /// native body pass.
    ///
    /// # Safety
    ///
    /// `renderer` and its render-state object must remain engine-owned for the
    /// complete serialized common-shadow transaction.
    pub(super) unsafe fn begin_native_state_journal(
        &mut self,
        renderer: *mut c_void,
    ) -> Direct3DResult<()> {
        if renderer.is_null() || self.render_state.is_some() || !self.skin_states.is_empty() {
            return Err(direct3d_failure());
        }
        let state =
            unsafe { read::<*mut u8>(renderer.cast(), NativeLayout::NIDX9_RENDERER_RENDER_STATE) };
        if state.is_null() {
            return Err(direct3d_failure());
        }
        self.render_state = Some(RenderStateSnapshot {
            state: state as usize,
            internal_normalize_normals: unsafe {
                read::<u8>(
                    state,
                    NativeLayout::NIDX9_RENDER_STATE_INTERNAL_NORMALIZE_NORMALS,
                )
            },
        });
        // Declaration COM identities are borrowed from engine buffers. Keep
        // the cache inside this serialized transaction so a later engine
        // destruction/reuse cannot alias an old encoding entry.
        self.declarations.clear();
        self.begin_skin_lookup_generation();
        Ok(())
    }

    /// Restore or coherently invalidate engine-owned skin calculation state.
    ///
    /// The bone allocation and matrix storage deliberately remain live: the
    /// helper may have grown that engine-owned cache after freeing its former
    /// allocation. Restoring those pointers would create a use-after-free.
    /// A skin previously calculated with OMV's same three-register mode keeps
    /// its exact stamp. A different original mode cannot be restored beside
    /// the newly written mode-three matrices; its mode is instead invalidated
    /// so the next native calculation cannot take a false cache hit.
    ///
    /// # Safety
    ///
    /// All journaled objects must still belong to the active common-shadow
    /// transaction. This method must run before control reaches the native
    /// tail, including every producer failure path.
    pub(super) unsafe fn restore_native_state_journal(&mut self) -> Direct3DResult<()> {
        let Some(render_state) = self.render_state.take() else {
            return Err(direct3d_failure());
        };
        for snapshot in self.skin_states.drain(..) {
            let skin = snapshot.skin as *mut u8;
            unsafe {
                write(skin, NativeLayout::NI_SKIN_FRAME_ID, snapshot.frame_id);
                let restored_mode = if snapshot.bone_registers == SHADOW_BONE_REGISTERS {
                    snapshot.bone_registers
                } else {
                    INVALID_BONE_REGISTERS
                };
                write(skin, NativeLayout::NI_SKIN_BONE_REGISTERS, restored_mode);
            }
        }
        self.declarations.clear();
        unsafe {
            write(
                render_state.state as *mut u8,
                NativeLayout::NIDX9_RENDER_STATE_INTERNAL_NORMALIZE_NORMALS,
                render_state.internal_normalize_normals,
            );
        }
        Ok(())
    }

    /// Advance the allocation-free skin lookup to a logically empty epoch.
    fn begin_skin_lookup_generation(&mut self) {
        self.skin_lookup_generation = self.skin_lookup_generation.wrapping_add(1);
        if self.skin_lookup_generation == 0 {
            // Wrapping once requires billions of successful producer
            // transactions. Pay one bounded reset instead of allowing stale
            // slots to alias the new generation.
            self.skin_lookup.fill(SkinLookupSlot::default());
            self.skin_lookup_generation = 1;
        }
    }

    fn skin_lookup_start(skin: usize) -> usize {
        debug_assert!(SKIN_LOOKUP_CAPACITY.is_power_of_two());
        let mut hash = skin >> 2;
        hash ^= hash >> 16;
        hash = hash.wrapping_mul(0x7FEB_352D);
        hash ^= hash >> 15;
        hash & (SKIN_LOOKUP_CAPACITY - 1)
    }

    /// Find one journaled skin through the current fixed-capacity hash epoch.
    fn skin_state_index(&self, skin: usize) -> Option<usize> {
        let start = Self::skin_lookup_start(skin);
        for probe in 0..SKIN_LOOKUP_CAPACITY {
            let slot = self.skin_lookup[(start + probe) & (SKIN_LOOKUP_CAPACITY - 1)];
            if slot.generation != self.skin_lookup_generation {
                return None;
            }
            if slot.skin == skin {
                return Some(usize::from(slot.state_index));
            }
        }
        None
    }

    /// Insert a unique skin/index pair without allocation or replacement.
    fn insert_skin_state(&mut self, skin: usize, state_index: usize) -> bool {
        let Ok(state_index) = u16::try_from(state_index) else {
            return false;
        };
        let start = Self::skin_lookup_start(skin);
        for probe in 0..SKIN_LOOKUP_CAPACITY {
            let slot = &mut self.skin_lookup[(start + probe) & (SKIN_LOOKUP_CAPACITY - 1)];
            if slot.generation != self.skin_lookup_generation {
                *slot = SkinLookupSlot {
                    generation: self.skin_lookup_generation,
                    skin,
                    state_index,
                };
                return true;
            }
            if slot.skin == skin {
                return usize::from(slot.state_index) == usize::from(state_index);
            }
        }
        false
    }

    /// Journal one skin and return its stable transaction-local state index.
    unsafe fn capture_skin_state(&mut self, skin: *mut u8) -> Direct3DResult<usize> {
        if skin.is_null() || self.render_state.is_none() {
            return Err(direct3d_failure());
        }
        if let Some(index) = self.skin_state_index(skin as usize) {
            return Ok(index);
        }
        // Never reallocate in the render hook. Overflow fails the replacement
        // transaction and takes the already-supported native fallback.
        if self.skin_states.len() >= MAX_SKIN_STATE_SNAPSHOTS {
            return Err(direct3d_failure());
        }
        let index = self.skin_states.len();
        self.skin_states.push(SkinStateSnapshot {
            skin: skin as usize,
            frame_id: unsafe { read::<u32>(skin, NativeLayout::NI_SKIN_FRAME_ID) },
            bone_registers: unsafe { read::<u32>(skin, NativeLayout::NI_SKIN_BONE_REGISTERS) },
            world_transform: [0; 13],
            calculation_initialized: false,
        });
        if !self.insert_skin_state(skin as usize, index) {
            self.skin_states.pop();
            return Err(direct3d_failure());
        }
        Ok(index)
    }

    /// Prepare the native matrix cache for one skin/transform pair.
    ///
    /// Attachments may share one `NiSkinInstance` while using distinct world
    /// transforms. FNV's native helper keys its fast path by frame and register
    /// mode only; without this additional key a later child can reuse matrices
    /// calculated for a different geometry, producing detached heads or gear.
    unsafe fn prepare_skin_calculation(
        &mut self,
        skin: *mut u8,
        world_transform: [u32; 13],
    ) -> Direct3DResult<()> {
        let index = unsafe { self.capture_skin_state(skin)? };
        let snapshot = self
            .skin_states
            .get_mut(index)
            .ok_or_else(direct3d_failure)?;
        if snapshot.calculation_initialized {
            if snapshot.world_transform != world_transform {
                unsafe {
                    write(skin, NativeLayout::NI_SKIN_FRAME_ID, u32::MAX);
                    write(
                        skin,
                        NativeLayout::NI_SKIN_BONE_REGISTERS,
                        INVALID_BONE_REGISTERS,
                    );
                }
                snapshot.world_transform = world_transform;
            }
            return Ok(());
        }
        // The native cache may have been populated earlier in this frame by a
        // different geometry sharing the skin. Its frame/mode stamp does not
        // record that transform, so the first OMV use must establish a known
        // matrix owner before same-transform shadow draws may reuse it.
        unsafe {
            write(skin, NativeLayout::NI_SKIN_FRAME_ID, u32::MAX);
            write(
                skin,
                NativeLayout::NI_SKIN_BONE_REGISTERS,
                INVALID_BONE_REGISTERS,
            );
        }
        snapshot.world_transform = world_transform;
        snapshot.calculation_initialized = true;
        Ok(())
    }

    /// Resolve and cache the blend-index interpretation of a bound buffer.
    ///
    /// The native buffer fields are the same ownership source used by
    /// [`bind_geometry_buffer`]. Looking up their declaration pointer before
    /// querying D3D makes the common cached path CPU-only; a declaration
    /// snapshot is needed only once per distinct engine declaration in the
    /// serialized transaction.
    ///
    /// # Safety
    ///
    /// `buffer` must remain an engine-owned geometry buffer for the complete
    /// call and must already be bound through [`bind_geometry_buffer`].
    unsafe fn skin_index_encoding(
        &mut self,
        device: &Device9Ref<'_>,
        buffer: *mut u8,
    ) -> Direct3DResult<SkinIndexEncoding> {
        // Skinned FNV geometry uses declarations. Treating an unexpected FVF
        // as a known byte layout could index outside the uploaded bone rows.
        if buffer.is_null() || unsafe { read::<u32>(buffer, GEOMETRY_BUFFER_FVF) } != 0 {
            return Err(direct3d_failure());
        }
        let declaration = unsafe { read::<*mut c_void>(buffer, GEOMETRY_BUFFER_DECLARATION) };
        if declaration.is_null() {
            return Err(direct3d_failure());
        }
        if let Some(cached) = self
            .declarations
            .iter()
            .find(|cached| cached.declaration == declaration as usize)
        {
            return Ok(cached.encoding);
        }
        let snapshot = device.vertex_declaration_snapshot()?;
        // `bind_geometry_buffer` and this query are adjacent. A mismatch means
        // native state changed unexpectedly; fail the replacement transaction
        // instead of caching a declaration under the wrong engine identity.
        if snapshot.handle != declaration {
            return Err(direct3d_failure());
        }
        let encoding = snapshot.elements[..snapshot.element_count as usize]
            .iter()
            .find_map(|element| {
                SkinIndexEncoding::from_declaration_element(
                    element.Type,
                    element.Usage,
                    element.UsageIndex,
                )
            })
            .ok_or_else(direct3d_failure)?;
        if self.declarations.len() >= self.declarations.capacity() {
            return Err(direct3d_failure());
        }
        self.declarations.push(VertexDeclarationEncoding {
            declaration: declaration as usize,
            encoding,
        });
        Ok(encoding)
    }
}

/// Configure generation render state common to cascades and cube faces.
pub(super) fn configure_generation_state(device: &Device9Ref<'_>) -> Direct3DResult<()> {
    device.set_render_state(D3DRS_ZENABLE, 1)?;
    device.set_render_state(D3DRS_ZWRITEENABLE, 1)?;
    device.set_render_state(D3DRS_ZFUNC, D3DCMP_LESSEQUAL.0 as u32)?;
    device.set_render_state(D3DRS_CULLMODE, D3DCULL_NONE.0 as u32)?;
    device.set_render_state(D3DRS_ALPHABLENDENABLE, 0)?;
    device.set_render_state(D3DRS_ALPHATESTENABLE, 0)?;
    device.set_render_state(D3DRS_ALPHAREF, 0)?;
    device.set_render_state(D3DRS_ALPHAFUNC, D3DCMP_ALWAYS.0 as u32)?;
    device.set_render_state(D3DRS_STENCILENABLE, 0)?;
    device.set_render_state(D3DRS_COLORWRITEENABLE, 0xF)?;
    device.set_render_state(D3DRS_MULTISAMPLEANTIALIAS, 1)?;
    device.set_render_state(D3DRS_MULTISAMPLEMASK, u32::MAX)?;
    // Native foliage paths use vendor-specific alpha-to-coverage toggles.
    // Shadow-map shaders perform their own explicit alpha clip, so inheriting
    // those toggles would discard or partially cover opaque EVSM/cube writes.
    match crate::backend::fnv_alpha_coverage_mode() {
        crate::backend::AlphaCoverageMode::None => {}
        crate::backend::AlphaCoverageMode::Nvidia => {
            device.set_render_state(D3DRS_ADAPTIVETESS_Y, 0)?;
        }
        crate::backend::AlphaCoverageMode::Amd => {
            device.set_render_state(D3DRS_POINTSIZE, AMD_ALPHA_TO_COVERAGE_OFF)?;
        }
    }
    device.set_render_state(D3DRS_DEPTHBIAS, 0)?;
    device.set_render_state(D3DRS_SLOPESCALEDEPTHBIAS, 0)
}

/// Bind one directional map transform before traversing all admitted roots.
pub(super) fn begin_directional_map(
    device: &Device9Ref<'_>,
    programs: &GenerationPrograms,
    world_to_shadow: [[f32; 4]; 4],
) -> Direct3DResult<()> {
    device.set_vertex_shader(&programs.directional_vertex[0])?;
    device.set_pixel_shader(&programs.directional_pixel)?;
    device.set_vertex_shader_constant_f(4, &world_to_shadow)
}

/// Bind one point-light face transform and radial-depth constants.
pub(super) fn begin_point_face(
    device: &Device9Ref<'_>,
    programs: &GenerationPrograms,
    world_to_shadow: [[f32; 4]; 4],
    light_position_radius: [f32; 4],
) -> Direct3DResult<()> {
    device.set_vertex_shader(&programs.cube_vertex[0])?;
    device.set_pixel_shader(&programs.cube_pixel)?;
    device.set_vertex_shader_constant_f(4, &world_to_shadow)?;
    device.set_vertex_shader_constant_f(63, &[light_position_radius])
}

/// Traverse one scene root and submit every admitted caster.
///
/// # Safety
///
/// All engine pointers must belong to the current common-shadow transaction.
pub(super) unsafe fn draw_directional_root(
    device: &Device9Ref<'_>,
    programs: &GenerationPrograms,
    renderer: *mut c_void,
    projection: CascadeProjection,
    camera_translation: [f32; 3],
    first_person_root: *mut u8,
    root: *mut u8,
    is_land: bool,
    is_lod: bool,
    minimum_radius: f32,
    actor_overlay: bool,
    scratch: &mut TraversalScratch,
) -> Direct3DResult<()> {
    let context = DrawContext {
        device,
        programs,
        renderer,
        projection: Some(projection),
        camera_translation,
        first_person_root,
        cube_center: None,
        cube_radius: None,
        cube_face: None,
        is_land,
        is_lod,
        minimum_radius,
        subset: CasterSubset::All,
        actor_overlay,
    };
    unsafe { traverse_root(context, root, scratch) }
}

/// Traverse one canonical scene root for a point-light cube face.
///
/// # Safety
///
/// `root` and `first_person_root` must remain live for the current common-shadow
/// invocation.
#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn draw_point_root(
    device: &Device9Ref<'_>,
    programs: &GenerationPrograms,
    renderer: *mut c_void,
    camera_translation: [f32; 3],
    first_person_root: *mut u8,
    light_position: [f32; 3],
    radius: f32,
    face: usize,
    root: *mut u8,
    is_land: bool,
    is_lod: bool,
    subset: CasterSubset,
    scratch: &mut TraversalScratch,
) -> Direct3DResult<()> {
    let context = DrawContext {
        device,
        programs,
        renderer,
        projection: None,
        camera_translation,
        first_person_root,
        cube_center: Some(light_position),
        cube_radius: Some(radius),
        cube_face: Some(face),
        is_land,
        is_lod,
        minimum_radius: CasterPolicy::quality_default().minimum_radius,
        subset,
        actor_overlay: false,
    };
    unsafe { traverse_root(context, root, scratch) }
}

#[derive(Clone, Copy)]
struct DrawContext<'a> {
    device: &'a Device9Ref<'a>,
    programs: &'a GenerationPrograms,
    renderer: *mut c_void,
    projection: Option<CascadeProjection>,
    camera_translation: [f32; 3],
    first_person_root: *mut u8,
    cube_center: Option<[f32; 3]>,
    cube_radius: Option<f32>,
    cube_face: Option<usize>,
    is_land: bool,
    is_lod: bool,
    minimum_radius: f32,
    subset: CasterSubset,
    actor_overlay: bool,
}

unsafe fn traverse_root(
    context: DrawContext<'_>,
    root: *mut u8,
    scratch: &mut TraversalScratch,
) -> Direct3DResult<()> {
    scratch.nodes.clear();
    if !root.is_null() && !push_traversal_node(&mut scratch.nodes, root as usize) {
        return Err(direct3d_failure());
    }
    let mut visited = 0usize;
    while let Some(identity) = scratch.nodes.pop() {
        if visited >= MAX_NODE_VISITS {
            break;
        }
        visited += 1;
        let object = identity as *mut u8;
        if !presentation_object_is_visible(
            context.subset.owns_presentation_visibility() || context.actor_overlay,
            unsafe { read::<u32>(object, NativeLayout::NI_AV_OBJECT_FLAGS) },
        ) {
            // Dynamic roots are rebuilt from the current presentation pose.
            // Honoring culling at every hierarchy level prevents hidden head,
            // equipment, or LOD alternatives from being projected together.
            continue;
        }
        // These moments outlive the native camera-cull epoch. NVR could honor
        // APP_CULLED because it rebuilt its maps every frame; doing so in a
        // retained map permanently removes a caster which happened to be
        // behind the camera at generation time. Shadow-frustum, light-volume,
        // form, fade, and multibound tests below remain the authoritative
        // bounded admission policy.
        let geometry = unsafe { virtual_cast(object, NI_OBJECT_IS_GEOMETRY_SLOT) };
        if !geometry.is_null() {
            unsafe { draw_geometry(context, geometry, scratch)? };
            continue;
        }
        let node = unsafe { virtual_cast(object, NI_OBJECT_IS_NODE_SLOT) };
        if node.is_null() || !unsafe { object_bound_within(context, node) } {
            continue;
        }
        let fade = unsafe { virtual_cast(node, NI_OBJECT_IS_FADE_NODE_SLOT) };
        if !fade.is_null()
            && unsafe { read::<f32>(fade, BS_FADE_ALPHA) }.is_finite()
            && unsafe { read::<f32>(fade, BS_FADE_ALPHA) } < 0.75
        {
            continue;
        }
        let multibound = unsafe { virtual_cast(node, NI_OBJECT_IS_MULTIBOUND_NODE_SLOT) };
        if !multibound.is_null() && !unsafe { multibound_within(context, multibound) } {
            continue;
        }

        let children = unsafe { node.add(NativeLayout::NI_NODE_CHILDREN) };
        let end = (unsafe { read::<u16>(children, NI_TARRAY_END) } as usize).min(MAX_NODE_CHILDREN);
        let data = unsafe { read::<*mut *mut u8>(children, NI_TARRAY_DATA) };
        if data.is_null() {
            continue;
        }
        if unsafe { rtti_is_kind_of(node, NI_SWITCH_NODE_RTTI) } {
            let active = unsafe { read::<i32>(node, NI_SWITCH_ACTIVE_INDEX) };
            if let Some(active) = switch_active_child_index(active, end) {
                let child = unsafe { read_unaligned(data.add(active)) };
                if !child.is_null() && !push_traversal_node(&mut scratch.nodes, child as usize) {
                    return Err(direct3d_failure());
                }
            }
            continue;
        }
        for index in (0..end).rev() {
            let child = unsafe { read_unaligned(data.add(index)) };
            if !child.is_null() && !push_traversal_node(&mut scratch.nodes, child as usize) {
                return Err(direct3d_failure());
            }
        }
    }
    Ok(())
}

unsafe fn draw_geometry(
    context: DrawContext<'_>,
    geometry: *mut u8,
    scratch: &mut TraversalScratch,
) -> Direct3DResult<()> {
    if geometry.is_null() {
        return Ok(());
    }
    // Point animation revisits only a few cube faces but the native light list
    // may contain thousands of immutable geometries. Reject the opposite
    // ownership family from the one pointer read needed to identify a skin,
    // before material, ancestry, bound, texture, and buffer classification.
    let skinned = !unsafe { read::<*mut u8>(geometry, NativeLayout::NI_GEOMETRY_SKIN) }.is_null();
    if !context.subset.admits(skinned) {
        return Ok(());
    }
    let Some(classification) = (unsafe { classify_geometry(context, geometry) }) else {
        return Ok(());
    };
    debug_assert_eq!(classification.skinned, skinned);
    let world = unsafe { geometry_world_matrix(geometry, context.camera_translation) }
        .ok_or_else(direct3d_failure)?;
    let mut geometry_data = [classification.geometry_kind, 0.0, 0.0, 0.0];
    if context.actor_overlay {
        geometry_data[3] = 2.0;
    }
    if let Some(radius) = context.cube_radius {
        geometry_data[2] = radius;
        // Dynamic point-cube draws sample the immutable static cube in s1 and
        // publish the nearer static-or-animated radial depth. The D3D depth
        // surface covers only the animated pass, so this shader merge is what
        // prevents an actor behind a wall from replacing the wall.
        geometry_data[3] = if context.subset == CasterSubset::Dynamic {
            1.0
        } else {
            0.0
        };
    }

    if classification.alpha {
        // A missing cutout texture cannot be approximated by a solid caster:
        // that turns fences and foliage into large opaque blocks. Skip the
        // geometry when its engine texture chain is incomplete.
        let Some(texture) = (unsafe { diffuse_texture(geometry, classification.speedtree) }) else {
            return Ok(());
        };
        geometry_data[1] = 1.0;
        unsafe { context.device.set_raw_base_texture(0, texture.cast())? };
        configure_alpha_sampler(context.device)?;
    }

    context.device.set_vertex_shader_constant_f(0, &world)?;
    context
        .device
        .set_vertex_shader_constant_f(8, &[geometry_data])?;
    context
        .device
        .set_pixel_shader_constant_f(0, &[geometry_data])?;
    if context.cube_radius.is_some() {
        // Cube views use right-handed face transforms while native material
        // culling is camera-handedness dependent. Keeping both sides here is
        // required for thin interior walls to occlude every cube direction.
        context
            .device
            .set_render_state(D3DRS_CULLMODE, D3DCULL_NONE.0 as u32)?;
    } else {
        unsafe { set_geometry_cull_mode(context.device, context.renderer.cast(), geometry)? };
    }

    if classification.skinned {
        return unsafe { draw_skinned(context, geometry, world, scratch) };
    }
    if classification.speedtree {
        unsafe { upload_speedtree_constants(context, geometry)? };
    } else if classification.terrain_lod {
        unsafe { upload_terrain_constants(context, geometry, world)? };
    }

    let model = unsafe { read::<*mut u8>(geometry, NativeLayout::NI_GEOMETRY_DATA) };
    let buffer = unsafe { read::<*mut u8>(model, NativeLayout::NI_GEOMETRY_DATA_BUFFER) };
    unsafe { bind_geometry_buffer(context.device, buffer)? };
    let dirty = unsafe { read::<u16>(model, NativeLayout::NI_GEOMETRY_DATA_DIRTY_FLAGS) };
    let strips = !unsafe { virtual_cast(geometry, NI_OBJECT_IS_TRI_STRIPS_SLOT) }.is_null();
    let submitted =
        unsafe { crate::hooks::submit_shadow_geometry(context.renderer, geometry.cast(), strips) };
    unsafe { write::<u16>(model, NativeLayout::NI_GEOMETRY_DATA_DIRTY_FLAGS, dirty) };
    submitted.then_some(()).ok_or_else(direct3d_failure)
}

#[derive(Clone, Copy)]
struct GeometryClassification {
    geometry_kind: f32,
    alpha: bool,
    skinned: bool,
    speedtree: bool,
    terrain_lod: bool,
}

unsafe fn classify_geometry(
    context: DrawContext<'_>,
    geometry: *mut u8,
) -> Option<GeometryClassification> {
    if geometry.is_null()
        || unsafe { read::<*mut u8>(geometry, NativeLayout::NI_GEOMETRY_SHADER) }.is_null()
        || !unsafe { object_bound_within(context, geometry) }
        || unsafe { faded_by_parent(geometry) }
    {
        return None;
    }
    let model = unsafe { read::<*mut u8>(geometry, NativeLayout::NI_GEOMETRY_DATA) };
    if model.is_null() {
        return None;
    }
    let shade = unsafe { read::<*mut u8>(geometry, NativeLayout::NI_PROPERTY_SHADE) };
    if shade.is_null() {
        return None;
    }
    let shader_type = unsafe { read::<u32>(shade, SHADE_TYPE) };
    let shader_flags = unsafe { read::<u32>(shade, SHADER_FLAGS_1) };
    let incompatible = shader_flags
        & (SHADER_REFRACTION | SHADER_FIRE_REFRACTION | SHADER_DECAL | SHADER_DYNAMIC_DECAL)
        != 0;
    let first_person = unsafe { read::<u16>(shade, SHADE_FLAGS) } & SHADE_FIRST_PERSON != 0;
    let material = unsafe { read::<*mut u8>(geometry, NativeLayout::NI_PROPERTY_MATERIAL) };
    let material_alpha = if material.is_null() {
        1.0
    } else {
        unsafe { read::<f32>(material, NativeLayout::NI_MATERIAL_ALPHA) }
    };
    if !material_alpha.is_finite() || material_alpha < 0.05 {
        return None;
    }
    let bound = unsafe { object_bound(geometry, context.camera_translation) }?;
    let admission = CasterAdmission {
        form_casts_shadows: true,
        app_culled: false,
        refraction: incompatible,
        fire_refraction: false,
        decal: false,
        dynamic_decal: false,
        // Parent fade nodes own the 0.75 admission threshold. Material alpha
        // instead follows NVR's much smaller 0.05 rejection threshold so a
        // translucent alpha-tested leaf still contributes its cutout shape.
        fade_alpha: 1.0,
        bound_radius: bound.radius,
        within_frustum: true,
        within_multibound: true,
    };
    let policy = CasterPolicy::quality_default().with_minimum_radius(context.minimum_radius)?;
    let under_first_person_root =
        unsafe { object_is_beneath_root(geometry, context.first_person_root) };
    if first_person_caster_is_excluded(first_person, under_first_person_root)
        || policy.admit(admission).is_err()
    {
        return None;
    }

    let skin = unsafe { read::<*mut u8>(geometry, NativeLayout::NI_GEOMETRY_SKIN) };
    let skinned = !skin.is_null();
    if !skinned {
        let buffer = unsafe { read::<*mut u8>(model, NativeLayout::NI_GEOMETRY_DATA_BUFFER) };
        if buffer.is_null() || unsafe { read::<u32>(buffer, GEOMETRY_BUFFER_VERTEX_COUNT) } == 0 {
            return None;
        }
    }
    // NVR's cube vertex shader stores the point-light position in c63, then
    // its SpeedTree path overwrites c63-c139. That silently generates invalid
    // radial depth. Point maps therefore reject that unsupported route while
    // directional cascades retain the complete SpeedTree caster path.
    if context.cube_radius.is_some() && shader_type == 6 {
        return None;
    }
    let speedtree = !skinned && shader_type == 6;
    let lighting =
        is_lighting_shader_definition(unsafe { read::<u32>(shade, SHADER_DEFINITION_INDEX) });
    let terrain_lod = !skinned
        && !speedtree
        && lighting
        && context.is_land
        && context.is_lod
        && unsafe { read::<u32>(shade, SHADER_FLAGS_2) } & SHADER_LOD_LANDSCAPE != 0;
    // NVR's pass order is semantic. Skinned actors and SpeedTree leaves claim
    // geometry before the ordinary lighting-property test. Applying that test
    // first drops HairShader actor partitions and produces incomplete bodies.
    if !skinned && !speedtree && !lighting {
        return None;
    }
    let alpha_property = unsafe { read::<*mut u8>(geometry, NativeLayout::NI_PROPERTY_ALPHA) };
    let alpha_cutout = !alpha_property.is_null()
        && unsafe { read::<u16>(alpha_property, ALPHA_FLAGS) } & (ALPHA_BLEND | ALPHA_TEST) != 0;
    // Skinned and terrain passes precede NVR's alpha pass. SpeedTree leaves
    // always use their tree-model diffuse alpha, independent of NiAlphaProperty.
    let alpha = speedtree || (!skinned && !terrain_lod && alpha_cutout);
    Some(GeometryClassification {
        geometry_kind: if skinned {
            1.0
        } else if speedtree {
            2.0
        } else if terrain_lod {
            3.0
        } else {
            0.0
        },
        alpha,
        skinned,
        speedtree,
        terrain_lod,
    })
}

/// Check explicit scene-graph ownership without retaining or mutating engine
/// flags. The bound prevents a corrupt parent cycle from stalling the render
/// thread; a valid FNV view-model hierarchy is far shallower than this limit.
unsafe fn object_is_beneath_root(mut object: *mut u8, root: *mut u8) -> bool {
    if root.is_null() {
        return false;
    }
    for _ in 0..MAX_PARENT_VISITS {
        if object.is_null() {
            return false;
        }
        if object == root {
            return true;
        }
        object = unsafe { read::<*mut u8>(object, NativeLayout::NI_AV_OBJECT_PARENT) };
    }
    false
}

fn is_lighting_shader_definition(shader_definition: u32) -> bool {
    matches!(
        shader_definition,
        SHADOW_LIGHT_SHADER | PARALLAX_SHADER | LIGHTING_30_SHADER
    )
}

unsafe fn draw_skinned(
    context: DrawContext<'_>,
    geometry: *mut u8,
    fallback_world: [[f32; 4]; 4],
    scratch: &mut TraversalScratch,
) -> Direct3DResult<()> {
    let skin = unsafe { read::<*mut u8>(geometry, NativeLayout::NI_GEOMETRY_SKIN) };
    let partition = unsafe { read::<*mut u8>(skin, NativeLayout::NI_SKIN_PARTITION) };
    if partition.is_null() {
        return Ok(());
    }
    let dismember = unsafe { rtti_is_kind_of(skin, BS_DISMEMBER_SKIN_RTTI) };
    let dismember_renderable =
        !dismember || unsafe { read::<u8>(skin, NativeLayout::DISMEMBER_RENDERABLE) } != 0;
    if !dismember_partition_is_renderable(dismember_renderable, None) {
        return Ok(());
    }
    let world_transform = unsafe {
        read_unaligned(
            geometry
                .add(NativeLayout::NI_AV_OBJECT_WORLD_TRANSFORM)
                .cast::<[u32; 13]>(),
        )
    };
    unsafe { scratch.prepare_skin_calculation(skin, world_transform)? };
    let calculate: CalculateBoneMatrices =
        unsafe { transmute(ShadowGenerationAbi::CALCULATE_BONE_MATRICES) };
    unsafe {
        calculate(
            context.renderer,
            skin,
            geometry.add(NativeLayout::NI_AV_OBJECT_WORLD_TRANSFORM),
            0,
            SHADOW_BONE_REGISTERS as i32,
            1,
        )
    };
    let native_camera_translation =
        unsafe { read_unaligned(CAMERA_WORLD_TRANSLATION as *const [f32; 3]) };
    if !native_camera_translation.into_iter().all(f32::is_finite) {
        return Err(direct3d_failure());
    }
    let skin_world = unsafe { read::<*mut [[f32; 4]; 4]>(skin, NativeLayout::NI_SKIN_TO_WORLD) };
    let world = if skin_world.is_null() {
        fallback_world
    } else {
        unsafe { read_unaligned(skin_world) }
    };
    context.device.set_vertex_shader_constant_f(0, &world)?;

    let count =
        (unsafe { read::<u32>(partition, SKIN_PARTITION_COUNT) } as usize).min(MAX_SKIN_PARTITIONS);
    let partitions = unsafe { read::<*mut u8>(partition, SKIN_PARTITION_ARRAY) };
    let bone_rows = unsafe { read::<*const [f32; 4]>(skin, NativeLayout::NI_SKIN_BONE_MATRICES) };
    if partitions.is_null() || bone_rows.is_null() {
        return Ok(());
    }
    let dismember_entries = if dismember {
        unsafe { read::<*mut u8>(skin, NativeLayout::DISMEMBER_PARTITIONS) }
    } else {
        core::ptr::null_mut()
    };
    let dismember_count = if dismember {
        (unsafe { read::<u32>(skin, NativeLayout::DISMEMBER_PARTITION_COUNT) }) as usize
    } else {
        0
    };
    let draw: DrawSkinnedGeometry = unsafe { transmute(GeometryKind::Skinned.render_address()) };
    for index in 0..count {
        let partition_enabled = (!dismember_entries.is_null() && index < dismember_count)
            .then(|| unsafe { read::<u8>(dismember_entries, index * 4) } != 0);
        if !dismember_partition_is_renderable(dismember_renderable, partition_enabled) {
            continue;
        }
        let entry = unsafe { partitions.add(index * NativeLayout::NI_SKIN_PARTITION_ENTRY_SIZE) };
        let bones = unsafe { read::<u16>(entry, PARTITION_BONES) } as usize;
        if bones == 0 || bones > MAX_BONES_PER_PARTITION {
            continue;
        }
        let indices = unsafe { read::<*const u16>(entry, PARTITION_BONE_INDICES) };
        let buffer = unsafe { read::<*mut u8>(entry, PARTITION_BUFFER) };
        if !skinned_submission_is_available(false, !buffer.is_null()) {
            continue;
        }
        for bone in 0..bones {
            let source = if indices.is_null() {
                bone
            } else {
                (unsafe { read_unaligned(indices.add(bone)) }) as usize
            };
            let mut rows: [[f32; 4]; 3] =
                unsafe { read_unaligned(bone_rows.add(source * 3).cast::<[[f32; 4]; 3]>()) };
            // Static casters are explicitly camera-relative before upload.
            // Apply the exact equivalent correction to native skin matrices;
            // otherwise only actors are displaced whenever the engine global
            // camera belongs to an earlier or alternate render view.
            rows = rebase_bone_rows(rows, native_camera_translation, context.camera_translation)
                .ok_or_else(direct3d_failure)?;
            context
                .device
                .set_vertex_shader_constant_f((9 + bone * 3) as u32, &rows)?;
        }
        unsafe { bind_geometry_buffer(context.device, buffer)? };
        let encoding =
            unsafe { scratch.skin_index_encoding(context.device, buffer)? }.shader_index();
        let vertex = if context.cube_radius.is_some() {
            &context.programs.cube_vertex[encoding]
        } else {
            &context.programs.directional_vertex[encoding]
        };
        context.device.set_vertex_shader(vertex)?;
        unsafe { draw(context.renderer, buffer, entry, core::ptr::null_mut()) };
    }
    Ok(())
}

/// Rebase one native 3x4 skin matrix into OMV's captured-camera domain.
///
/// Fallout stores each translation component in the fourth value of the
/// corresponding axis row. The native bone builder has already subtracted
/// `native_camera_translation`; adding the origin delta makes its output
/// equivalent to subtracting `shadow_camera_translation` in the first place.
pub(super) fn rebase_bone_rows(
    mut rows: [[f32; 4]; 3],
    native_camera_translation: [f32; 3],
    shadow_camera_translation: [f32; 3],
) -> Option<[[f32; 4]; 3]> {
    if !rows.iter().flatten().all(|value| value.is_finite())
        || !native_camera_translation.into_iter().all(f32::is_finite)
        || !shadow_camera_translation.into_iter().all(f32::is_finite)
    {
        return None;
    }
    let camera_delta: [f32; 3] = std::array::from_fn(|axis| {
        native_camera_translation[axis] - shadow_camera_translation[axis]
    });
    for axis in 0..3 {
        rows[axis][3] += camera_delta[axis];
    }
    rows.iter()
        .flatten()
        .all(|value| value.is_finite())
        .then_some(rows)
}

unsafe fn bind_geometry_buffer(device: &Device9Ref<'_>, buffer: *mut u8) -> Direct3DResult<()> {
    if buffer.is_null() {
        return Err(direct3d_failure());
    }
    let stream_count = unsafe { read::<u32>(buffer, GEOMETRY_BUFFER_STREAM_COUNT) } as usize;
    if stream_count == 0 || stream_count > 16 {
        return Err(direct3d_failure());
    }
    let strides = unsafe { read::<*const u32>(buffer, GEOMETRY_BUFFER_STRIDES) };
    let chips = unsafe { read::<*const *mut u8>(buffer, GEOMETRY_BUFFER_CHIPS) };
    if strides.is_null() || chips.is_null() {
        return Err(direct3d_failure());
    }
    for stream in 0..stream_count {
        let chip = unsafe { read_unaligned(chips.add(stream)) };
        if chip.is_null() {
            return Err(direct3d_failure());
        }
        let vertex_buffer = unsafe { read::<*mut c_void>(chip, VERTEX_CHIP_BUFFER) };
        let stride = unsafe { read_unaligned(strides.add(stream)) };
        unsafe { device.set_raw_stream_source(stream as u32, vertex_buffer, 0, stride)? };
    }
    let index_buffer = unsafe { read::<*mut c_void>(buffer, GEOMETRY_BUFFER_INDEX_BUFFER) };
    unsafe { device.set_raw_indices(index_buffer)? };
    let fvf = unsafe { read::<u32>(buffer, GEOMETRY_BUFFER_FVF) };
    if fvf != 0 {
        device.set_fvf(fvf)
    } else {
        let declaration = unsafe { read::<*mut c_void>(buffer, GEOMETRY_BUFFER_DECLARATION) };
        unsafe { device.set_raw_vertex_declaration(declaration) }
    }
}

unsafe fn upload_speedtree_constants(
    context: DrawContext<'_>,
    geometry: *mut u8,
) -> Direct3DResult<()> {
    let sun = crate::backend::native_sky_frame()
        .map(|frame| frame.sun_direction)
        .unwrap_or([0.4, 0.3, 0.866]);
    let right = normalize(cross([0.0, 0.0, 1.0], sun)).unwrap_or([1.0, 0.0, 0.0]);
    let up = normalize(cross(sun, right)).unwrap_or([0.0, 1.0, 0.0]);
    context.device.set_vertex_shader_constant_f(
        63,
        &[
            [right[0], right[1], right[2], 0.0],
            [up[0], up[1], up[2], 0.0],
        ],
    )?;
    // The three native blocks are not contiguous: c65 is rock, c66 is
    // rustle, and c67-c82 are sixteen wind rows. Reading one fabricated span
    // would consume unrelated globals between those blocks.
    let rock = unsafe { read_unaligned(SPEEDTREE_ROCK_PARAMS as *const [f32; 4]) };
    let rustle = unsafe { read_unaligned(SPEEDTREE_RUSTLE_PARAMS as *const [f32; 4]) };
    let wind = unsafe { core::slice::from_raw_parts(SPEEDTREE_WIND_ROWS as *const [f32; 4], 16) };
    context.device.set_vertex_shader_constant_f(65, &[rock])?;
    context.device.set_vertex_shader_constant_f(66, &[rustle])?;
    context.device.set_vertex_shader_constant_f(67, wind)?;
    let shade = unsafe { read::<*mut u8>(geometry, NativeLayout::NI_PROPERTY_SHADE) };
    let leaf_data = unsafe { read::<*mut u8>(shade, SPEEDTREE_LEAF_DATA) };
    if !leaf_data.is_null() {
        let rows = unsafe { read::<*const [f32; 4]>(leaf_data, SPEEDTREE_LEAF_ROWS) };
        if !rows.is_null() {
            let rows = unsafe { core::slice::from_raw_parts(rows, 48) };
            context.device.set_vertex_shader_constant_f(83, rows)?;
        }
    }
    Ok(())
}

unsafe fn upload_terrain_constants(
    context: DrawContext<'_>,
    geometry: *mut u8,
    world: [[f32; 4]; 4],
) -> Direct3DResult<()> {
    let transpose: [[f32; 4]; 4] =
        std::array::from_fn(|row| std::array::from_fn(|column| world[column][row]));
    context
        .device
        .set_vertex_shader_constant_f(140, &transpose)?;
    let loaded = unsafe { read_unaligned(TERRAIN_LOADED_RANGE as *const [f32; 4]) };
    let loaded = [
        loaded[0] - context.camera_translation[0],
        loaded[1] - context.camera_translation[1],
        loaded[2] - 15.0,
        loaded[3] - 15.0,
    ];
    let shade = unsafe { read::<*mut u8>(geometry, NativeLayout::NI_PROPERTY_SHADE) };
    let morph = unsafe { read::<f32>(shade, PPLIGHTING_MORPH_DISTANCE) };
    let drop = unsafe { read_unaligned(TERRAIN_LOD_DROP as *const f32) };
    context
        .device
        .set_vertex_shader_constant_f(144, &[loaded, [morph, drop, 0.0, 0.0]])
}

unsafe fn geometry_world_matrix(
    geometry: *mut u8,
    camera_translation: [f32; 3],
) -> Option<[[f32; 4]; 4]> {
    let transform = unsafe { geometry.add(NativeLayout::NI_AV_OBJECT_WORLD_TRANSFORM) };
    let rotation = unsafe { read_unaligned(transform.cast::<[[f32; 3]; 3]>()) };
    let translation = unsafe { read::<[f32; 3]>(transform, 0x24) };
    let scale = unsafe { read::<f32>(transform, 0x30) };
    camera_relative_world_matrix(rotation, translation, scale, camera_translation)
}

unsafe fn object_bound_within(context: DrawContext<'_>, object: *mut u8) -> bool {
    let Some(bound) = (unsafe { object_bound(object, context.camera_translation) }) else {
        return context.projection.is_none();
    };
    // NVR expresses each form profile's minimum bound in shadow-map pixels
    // and converts it to world units from the stabilized cascade radius.
    // Land roots are exempt in the source because their aggregate bound says
    // nothing about the terrain patches beneath them.
    if !context.is_land && bound.radius < context.minimum_radius {
        return false;
    }
    if let Some(projection) = context.projection {
        projection.contains(bound)
    } else if let (Some(center), Some(radius)) = (context.cube_center, context.cube_radius) {
        sphere_intersects_point_light(bound.center, bound.radius, center, radius)
            && context.cube_face.is_none_or(|face| {
                let center_from_light =
                    std::array::from_fn(|axis| bound.center[axis] - center[axis]);
                sphere_intersects_cube_face(center_from_light, bound.radius, face)
            })
    } else {
        true
    }
}

unsafe fn object_bound(object: *mut u8, camera_translation: [f32; 3]) -> Option<Sphere> {
    let bound = unsafe { read::<*mut NativeBound>(object, NativeLayout::NI_AV_OBJECT_WORLD_BOUND) };
    if bound.is_null() {
        return None;
    }
    let bound = unsafe { read_unaligned(bound) };
    let center = std::array::from_fn(|index| bound.center[index] - camera_translation[index]);
    (center.into_iter().all(f32::is_finite) && bound.radius.is_finite() && bound.radius >= 0.0)
        .then_some(Sphere {
            center,
            radius: bound.radius,
        })
}

unsafe fn multibound_within(context: DrawContext<'_>, node: *mut u8) -> bool {
    let Some(projection) = context.projection else {
        return true;
    };
    let multibound = unsafe { read::<*mut u8>(node, BS_MULTIBOUND) };
    if multibound.is_null() {
        return true;
    }
    let shape = unsafe { read::<*mut u8>(multibound, BS_MULTIBOUND_SHAPE) };
    if shape.is_null() {
        return true;
    }
    let Some(function) = (unsafe { virtual_function(shape, MULTIBOUND_SHAPE_GET_BOUND_SLOT) })
    else {
        return true;
    };
    let get_bound: GetMultiBound = unsafe { transmute(function) };
    let mut bound = NativeBound {
        center: [0.0; 3],
        radius: 0.0,
    };
    unsafe { get_bound(shape, &mut bound) };
    let sphere = Sphere {
        center: std::array::from_fn(|index| {
            bound.center[index] - context.camera_translation[index]
        }),
        radius: bound.radius,
    };
    projection.contains(sphere)
}

unsafe fn faded_by_parent(mut object: *mut u8) -> bool {
    for _ in 0..8 {
        object = unsafe { read::<*mut u8>(object, NativeLayout::NI_AV_OBJECT_PARENT) };
        if object.is_null() {
            return false;
        }
        let fade = unsafe { virtual_cast(object, NI_OBJECT_IS_FADE_NODE_SLOT) };
        if !fade.is_null() {
            let alpha = unsafe { read::<f32>(fade, BS_FADE_ALPHA) };
            return !alpha.is_finite() || alpha < 0.75;
        }
    }
    false
}

unsafe fn diffuse_texture(geometry: *mut u8, speedtree: bool) -> Option<*mut u8> {
    if speedtree {
        let parent = unsafe { read::<*mut u8>(geometry, NativeLayout::NI_AV_OBJECT_PARENT) };
        let tree = if parent.is_null() {
            core::ptr::null_mut()
        } else {
            unsafe { read::<*mut u8>(parent, NativeLayout::NI_AV_OBJECT_PARENT) }
        };
        if tree.is_null() {
            return None;
        }
        let model = unsafe { read::<*mut u8>(tree, TREE_MODEL) };
        if model.is_null() {
            return None;
        }
        let texture = unsafe { read::<*mut u8>(model, TREE_LEAF_TEXTURE) };
        return unsafe { texture_base(texture) };
    }
    let shade = unsafe { read::<*mut u8>(geometry, NativeLayout::NI_PROPERTY_SHADE) };
    let texture_slot = unsafe { read::<*mut *mut u8>(shade, PPLIGHTING_TEXTURE_ZERO) };
    if texture_slot.is_null() {
        return None;
    }
    let texture = unsafe { read_unaligned(texture_slot) };
    unsafe { texture_base(texture) }
}

unsafe fn texture_base(texture: *mut u8) -> Option<*mut u8> {
    if texture.is_null() {
        return None;
    }
    let renderer_data = unsafe { read::<*mut u8>(texture, NI_TEXTURE_RENDERER_DATA) };
    if renderer_data.is_null() {
        return None;
    }
    let base = unsafe { read::<*mut u8>(renderer_data, DX9_TEXTURE) };
    (!base.is_null()).then_some(base)
}

fn configure_alpha_sampler(device: &Device9Ref<'_>) -> Direct3DResult<()> {
    device.set_sampler_state(0, D3DSAMP_ADDRESSU, D3DTADDRESS_WRAP.0 as u32)?;
    device.set_sampler_state(0, D3DSAMP_ADDRESSV, D3DTADDRESS_WRAP.0 as u32)?;
    device.set_sampler_state(0, D3DSAMP_MAGFILTER, D3DTEXF_POINT.0 as u32)?;
    device.set_sampler_state(0, D3DSAMP_MINFILTER, D3DTEXF_POINT.0 as u32)?;
    device.set_sampler_state(0, D3DSAMP_MIPFILTER, D3DTEXF_NONE.0 as u32)?;
    device.set_sampler_state(0, D3DSAMP_SRGBTEXTURE, 0)
}

/// Resolve one native stencil draw mode through the renderer's handedness map.
///
/// Values outside D3D9's three legal cull modes reject the mapping instead of
/// leaking an engine-layout error into device state.
pub(super) fn mapped_cull_mode(
    draw_mode: usize,
    left_handed: bool,
    mapping: [[u32; 2]; 4],
) -> Option<u32> {
    let value = *mapping.get(draw_mode)?.get(left_handed as usize)?;
    matches!(
        value,
        value if value == D3DCULL_NONE.0 as u32
            || value == D3DCULL_CW.0 as u32
            || value == D3DCULL_CCW.0 as u32
    )
    .then_some(value)
}

unsafe fn set_geometry_cull_mode(
    device: &Device9Ref<'_>,
    renderer: *mut u8,
    geometry: *mut u8,
) -> Direct3DResult<()> {
    let stencil = unsafe { read::<*mut u8>(geometry, NativeLayout::NI_PROPERTY_STENCIL) };
    if stencil.is_null() {
        return device.set_render_state(D3DRS_CULLMODE, D3DCULL_CCW.0 as u32);
    }
    let draw_mode = ((unsafe { read::<u16>(stencil, STENCIL_FLAGS) } >> 10) & 0x3) as usize;
    let render_state = if renderer.is_null() {
        core::ptr::null_mut()
    } else {
        unsafe { read::<*mut u8>(renderer, NativeLayout::NIDX9_RENDERER_RENDER_STATE) }
    };
    if !render_state.is_null() {
        let mapping = unsafe {
            read::<[[u32; 2]; 4]>(
                render_state,
                NativeLayout::NIDX9_RENDER_STATE_CULL_MODE_MAPPING,
            )
        };
        let left_handed =
            unsafe { read::<u32>(render_state, NativeLayout::NIDX9_RENDER_STATE_LEFT_HANDED) } != 0;
        if let Some(mode) = mapped_cull_mode(draw_mode, left_handed, mapping) {
            return device.set_render_state(D3DRS_CULLMODE, mode);
        }
    }
    // The engine map is preferred because it handles mirrored/left-handed
    // actor geometry. This conservative fallback retains the previous legal
    // mapping if the native renderer object is unexpectedly unavailable.
    let fallback = match draw_mode {
        2 => D3DCULL_CW,
        3 => D3DCULL_NONE,
        _ => D3DCULL_CCW,
    };
    device.set_render_state(D3DRS_CULLMODE, fallback.0 as u32)
}

unsafe fn virtual_cast(object: *mut u8, slot: usize) -> *mut u8 {
    let Some(function) = (unsafe { virtual_function(object, slot) }) else {
        return core::ptr::null_mut();
    };
    let function: VirtualCast = unsafe { transmute(function) };
    unsafe { function(object) }
}

unsafe fn virtual_function(object: *mut u8, slot: usize) -> Option<*const c_void> {
    if object.is_null() {
        return None;
    }
    let vtable = unsafe { read_unaligned(object.cast::<*const *const c_void>()) };
    if vtable.is_null() {
        return None;
    }
    let function = unsafe { read_unaligned(vtable.add(slot)) };
    (!function.is_null()).then_some(function)
}

unsafe fn rtti_is_kind_of(object: *mut u8, expected: usize) -> bool {
    let Some(function) = (unsafe { virtual_function(object, NI_OBJECT_GET_RTTI_SLOT) }) else {
        return false;
    };
    let get_rtti: GetRtti = unsafe { transmute(function) };
    let mut rtti = unsafe { get_rtti(object) };
    for _ in 0..32 {
        if rtti.is_null() {
            return false;
        }
        if rtti as usize == expected {
            return true;
        }
        rtti = unsafe { (*rtti).parent };
    }
    false
}

unsafe fn read<T: Copy>(base: *const u8, offset: usize) -> T {
    unsafe { read_unaligned(base.add(offset).cast::<T>()) }
}

unsafe fn write<T>(base: *mut u8, offset: usize, value: T) {
    unsafe { core::ptr::write_unaligned(base.add(offset).cast::<T>(), value) };
}

fn cross(left: [f32; 3], right: [f32; 3]) -> [f32; 3] {
    [
        left[1] * right[2] - left[2] * right[1],
        left[2] * right[0] - left[0] * right[2],
        left[0] * right[1] - left[1] * right[0],
    ]
}

fn normalize(value: [f32; 3]) -> Option<[f32; 3]> {
    let length = value
        .into_iter()
        .map(|component| component * component)
        .sum::<f32>()
        .sqrt();
    (length.is_finite() && length > 0.0001).then(|| value.map(|component| component / length))
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::{
        CasterSubset, NI_AV_OBJECT_APP_CULLED, TraversalScratch, presentation_object_is_visible,
        push_traversal_node, read, switch_active_child_index, write,
    };
    use crate::effects::shadows::engine::NativeLayout;

    #[test]
    fn point_static_and_dynamic_caster_subsets_are_disjoint_and_complete() {
        assert!(CasterSubset::Static.admits(false));
        assert!(!CasterSubset::Static.admits(true));
        assert!(!CasterSubset::Dynamic.admits(false));
        assert!(CasterSubset::Dynamic.admits(true));
        assert!(CasterSubset::All.admits(false));
        assert!(CasterSubset::All.admits(true));
    }

    #[test]
    fn presentation_culling_rejects_hidden_actor_children_but_not_retained_world_roots() {
        assert!(presentation_object_is_visible(true, 0));
        assert!(!presentation_object_is_visible(
            true,
            NI_AV_OBJECT_APP_CULLED
        ));
        assert!(
            presentation_object_is_visible(false, NI_AV_OBJECT_APP_CULLED),
            "camera culling removed a wall from a retained point cube"
        );
    }

    #[test]
    fn switch_nodes_submit_only_the_presented_child() {
        assert_eq!(switch_active_child_index(2, 4), Some(2));
        assert_eq!(switch_active_child_index(-1, 4), None);
        assert_eq!(switch_active_child_index(4, 4), None);
        assert_eq!(switch_active_child_index(0, 0), None);
    }

    #[test]
    fn traversal_stack_rejects_overflow_without_growing_in_the_render_path() {
        let mut nodes = Vec::with_capacity(2);
        assert!(push_traversal_node(&mut nodes, 1));
        assert!(push_traversal_node(&mut nodes, 2));
        let capacity = nodes.capacity();

        assert!(!push_traversal_node(&mut nodes, 3));
        assert_eq!(nodes, [1, 2]);
        assert_eq!(nodes.capacity(), capacity);
    }

    #[test]
    fn skin_journal_lookup_is_fixed_capacity_and_generation_scoped() {
        let mut scratch = TraversalScratch::with_capacity();
        let capacity = scratch.skin_lookup.capacity();
        scratch.begin_skin_lookup_generation();

        for index in 0..super::MAX_SKIN_STATE_SNAPSHOTS {
            let skin = 0x1000 + index * 4;
            assert!(scratch.insert_skin_state(skin, index));
            assert_eq!(scratch.skin_state_index(skin), Some(index));
        }
        assert_eq!(scratch.skin_lookup.capacity(), capacity);
        assert_eq!(scratch.skin_state_index(0xDEAD_BEE0), None);

        scratch.begin_skin_lookup_generation();
        assert_eq!(
            scratch.skin_state_index(0x1000),
            None,
            "a later producer transaction reused a stale skin/index owner"
        );
        assert_eq!(scratch.skin_lookup.capacity(), capacity);
    }

    #[test]
    fn skinned_journal_restores_native_body_state_after_repeated_shadow_submission() {
        let mut renderer =
            vec![0_u8; NativeLayout::NIDX9_RENDERER_RENDER_STATE + size_of::<usize>()];
        let mut render_state =
            vec![0_u8; NativeLayout::NIDX9_RENDER_STATE_INTERNAL_NORMALIZE_NORMALS + 1];
        let mut skin = vec![0_u8; NativeLayout::NI_SKIN_BONE_REGISTERS + size_of::<u32>()];
        let renderer_ptr = renderer.as_mut_ptr();
        let render_state_ptr = render_state.as_mut_ptr();
        let skin_ptr = skin.as_mut_ptr();
        unsafe {
            write(
                renderer_ptr,
                NativeLayout::NIDX9_RENDERER_RENDER_STATE,
                render_state_ptr,
            );
            write(
                render_state_ptr,
                NativeLayout::NIDX9_RENDER_STATE_INTERNAL_NORMALIZE_NORMALS,
                1_u8,
            );
            write(skin_ptr, NativeLayout::NI_SKIN_FRAME_ID, 7_u32);
            write(skin_ptr, NativeLayout::NI_SKIN_BONE_REGISTERS, 4_u32);
        }

        let mut scratch = TraversalScratch::with_capacity();
        unsafe {
            scratch
                .begin_native_state_journal(renderer_ptr.cast())
                .expect("valid fake renderer");
            scratch
                .prepare_skin_calculation(skin_ptr, [1; 13])
                .expect("first caster");

            // Model `CalculateBoneMatrices`: the first shadow route claims the
            // current frame/mode and updates the renderer-global normalize flag.
            write(skin_ptr, NativeLayout::NI_SKIN_FRAME_ID, 99_u32);
            write(skin_ptr, NativeLayout::NI_SKIN_BONE_REGISTERS, 3_u32);
            write(
                render_state_ptr,
                NativeLayout::NIDX9_RENDER_STATE_INTERNAL_NORMALIZE_NORMALS,
                0_u8,
            );

            // A point face or another cascade can submit the same transform
            // without defeating the native helper's useful same-frame cache.
            scratch
                .prepare_skin_calculation(skin_ptr, [1; 13])
                .expect("repeated transform");
            assert_eq!(read::<u32>(skin_ptr, NativeLayout::NI_SKIN_FRAME_ID), 99);

            // A shared skin under a different child transform must force the
            // helper to rebuild instead of reusing another body part's rows.
            scratch
                .prepare_skin_calculation(skin_ptr, [2; 13])
                .expect("distinct attachment transform");
            assert_eq!(
                read::<u32>(skin_ptr, NativeLayout::NI_SKIN_FRAME_ID),
                u32::MAX
            );
            assert_eq!(
                read::<u32>(skin_ptr, NativeLayout::NI_SKIN_BONE_REGISTERS),
                u32::MAX
            );
            write(skin_ptr, NativeLayout::NI_SKIN_FRAME_ID, 99_u32);
            write(skin_ptr, NativeLayout::NI_SKIN_BONE_REGISTERS, 3_u32);
            scratch
                .restore_native_state_journal()
                .expect("engine state restore");

            assert_eq!(read::<u32>(skin_ptr, NativeLayout::NI_SKIN_FRAME_ID), 7);
            assert_eq!(
                read::<u32>(skin_ptr, NativeLayout::NI_SKIN_BONE_REGISTERS),
                u32::MAX,
                "restoring a current-frame mode-4 stamp after writing mode-3 matrices makes the native cache lie"
            );
            assert_eq!(
                read::<u8>(
                    render_state_ptr,
                    NativeLayout::NIDX9_RENDER_STATE_INTERNAL_NORMALIZE_NORMALS,
                ),
                1
            );
        }
    }
}
