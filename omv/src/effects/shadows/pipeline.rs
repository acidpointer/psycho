//! Transactional D3D9 producer and pre-alpha shadow consumer.
//!
//! All default-pool resources are owned here and are released as one device
//! generation. The common engine hook only publishes a frame after every map,
//! scene boundary, and state restoration succeeds. The pre-alpha consumer is
//! nonblocking and accepts the current or immediately preceding presentation:
//! the native producer and outer image-space callback are separate engine
//! transactions, while older or failed work still expires deterministically.

use core::ffi::c_void;
use std::time::Instant;

use libpsycho::os::windows::directx9::{
    CubeTexture9, D3DBLEND_ONE, D3DBLENDOP_ADD, D3DCLEAR_STENCIL, D3DCLEAR_TARGET,
    D3DCLEAR_ZBUFFER, D3DCMP_ALWAYS, D3DCUBEMAP_FACE_NEGATIVE_X, D3DCUBEMAP_FACE_NEGATIVE_Y,
    D3DCUBEMAP_FACE_NEGATIVE_Z, D3DCUBEMAP_FACE_POSITIVE_X, D3DCUBEMAP_FACE_POSITIVE_Y,
    D3DCUBEMAP_FACE_POSITIVE_Z, D3DCUBEMAP_FACES, D3DCULL_NONE, D3DFMT_A16B16G16R16F, D3DFMT_D24S8,
    D3DFMT_G16R16F, D3DFMT_R32F, D3DMULTISAMPLE_4_SAMPLES, D3DMULTISAMPLE_NONE,
    D3DPT_TRIANGLESTRIP, D3DRS_ADAPTIVETESS_Y, D3DRS_ALPHABLENDENABLE, D3DRS_ALPHAFUNC,
    D3DRS_ALPHAREF, D3DRS_ALPHATESTENABLE, D3DRS_BLENDOP, D3DRS_COLORWRITEENABLE,
    D3DRS_COLORWRITEENABLE1, D3DRS_CULLMODE, D3DRS_DESTBLEND, D3DRS_MULTISAMPLEANTIALIAS,
    D3DRS_MULTISAMPLEMASK, D3DRS_POINTSIZE, D3DRS_SCISSORTESTENABLE, D3DRS_SRCBLEND,
    D3DRS_SRGBWRITEENABLE, D3DRS_STENCILENABLE, D3DRS_ZENABLE, D3DRS_ZWRITEENABLE,
    D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV, D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER, D3DSAMP_MIPFILTER,
    D3DSAMP_SRGBTEXTURE, D3DSBT_ALL, D3DSURFACE_DESC, D3DTADDRESS_CLAMP, D3DTEXF_LINEAR,
    D3DTEXF_NONE, D3DTEXF_POINT, D3DVIEWPORT9, Device9Ref, Direct3DResult, PixelShader9, RECT,
    ScreenVertex, StateBlock9, Surface9, Texture9, direct3d_failure,
};

use crate::{
    backend::{
        self, CameraFrame, DepthFrame, DepthResolveOutcome, DepthResolveSlot, DepthResolveStage,
    },
    render_state::{
        RenderAttachments, RenderTargetSlots, capture_state_block, finish_render_transaction,
    },
};

use super::{
    NativeShadowsSettings,
    contract::{
        CASCADE_COUNT, CascadeDirty, CascadeScheduler, CascadeSplit, DirectionalRootSetSignature,
        NVR_CASCADE_RESOLUTION, NVR_POINT_LIGHT_COUNT, POINT_CONSUMER_BATCH_SIZE, PointMapCache,
        PointMapPlan, PointMapSignature, SceneKind, cascade_minimum_caster_radius,
        consumer_has_shadow_work, directional_caster_work, directional_root_set_dirty,
        effective_contact_distance, evsm4_moments, nvr_contact_sample_offsets, point_consumer_plan,
        point_light_scissor, practical_cascade_splits, publication_epoch_is_usable,
        retained_cascade_refresh,
    },
    math::{
        CascadeProjection, ShadowCamera, cascade_projection, point_cube_views,
        stabilize_sun_direction,
    },
    native::{self, DIRECTIONAL_ROOT_CACHE_CAPACITY, DirectionalRoot, NativeScene, PointLightSet},
    render::{self, CasterSubset, GenerationPrograms, TraversalScratch},
    shaders::ShadowBytecode,
};

const ATLAS_RESOLUTION: u32 = NVR_CASCADE_RESOLUTION * 2;
const ACTOR_MAP_RESOLUTION: u32 = NVR_CASCADE_RESOLUTION / 2;
const POINT_CUBE_RESOLUTION: u32 = 512;
const BLEED_REDUCTION: f32 = 0.2;
const MAX_ERROR_LOGS: u32 = 8;
const AMD_ALPHA_TO_COVERAGE_OFF: u32 = u32::from_le_bytes(*b"A2M0");

const CUBE_FACES: [D3DCUBEMAP_FACES; 6] = [
    D3DCUBEMAP_FACE_POSITIVE_X,
    D3DCUBEMAP_FACE_NEGATIVE_X,
    D3DCUBEMAP_FACE_POSITIVE_Y,
    D3DCUBEMAP_FACE_NEGATIVE_Y,
    D3DCUBEMAP_FACE_POSITIVE_Z,
    D3DCUBEMAP_FACE_NEGATIVE_Z,
];

/// Result returned to the common-hook owner after one replacement attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReplacementResult {
    /// OMV produced every requested map and restored the native D3D state.
    Produced,
    /// The replacement could not run; the complete native prefix remains safe.
    FallbackNative,
}

/// Scalar publication for one sampled point shadow.
#[derive(Clone, Copy, Debug, Default)]
struct PublishedPointLight {
    position: [f32; 3],
    color: [f32; 3],
    radius: f32,
    shadow_fade: f32,
}

/// Immutable metadata paired with persistent texture resources.
#[derive(Clone, Copy, Debug)]
struct PublishedFrame {
    render_epoch: u32,
    scene: SceneKind,
    directional: bool,
    sun_direction: [f32; 3],
    matrices: [[[f32; 4]; 4]; CASCADE_COUNT],
    matrix_origins: [[f32; 3]; CASCADE_COUNT],
    /// Actor-map XY scale/offset in each parent cascade's clip domain.
    actor_crops: [[f32; 4]; 3],
    /// Actor-only moments available for near, middle, and far cascades.
    actor_overlay_mask: u8,
    splits: [CascadeSplit; CASCADE_COUNT],
    points: [PublishedPointLight; NVR_POINT_LIGHT_COUNT],
    point_count: usize,
}

/// Complete device-generation state retained across producer and consumer calls.
pub(super) struct ShadowPipeline {
    resources: Option<ShadowResources>,
    scheduler: CascadeScheduler,
    published: Option<PublishedFrame>,
    last_scene: Option<SceneKind>,
    last_sun: Option<[f32; 3]>,
    last_frustum: Option<[f32; 6]>,
    last_directional_profile: Option<[f32; 2]>,
    /// Actor cascade footprint stored in the last completed map transaction.
    last_dynamic_cascade_mask: u8,
    /// Complete scene-root identity paired with the retained directional maps.
    last_directional_roots: Option<[DirectionalRootSetSignature; CASCADE_COUNT]>,
    point_cache: PointMapCache,
    point_cell_identity: usize,
    resource_failure_generation: Option<u32>,
    error_logs: u32,
    production_logged: [bool; 2],
    composition_logged: [bool; 2],
    clock_origin: Instant,
}

impl Default for ShadowPipeline {
    fn default() -> Self {
        Self {
            resources: None,
            scheduler: CascadeScheduler::default(),
            published: None,
            last_scene: None,
            last_sun: None,
            last_frustum: None,
            last_directional_profile: None,
            last_dynamic_cascade_mask: 0,
            last_directional_roots: None,
            point_cache: PointMapCache::default(),
            point_cell_identity: 0,
            resource_failure_generation: None,
            error_logs: 0,
            production_logged: [false; 2],
            composition_logged: [false; 2],
            clock_origin: Instant::now(),
        }
    }
}

impl ShadowPipeline {
    /// Drop all default-pool resources before the engine resets its device.
    pub(super) fn release(&mut self) {
        self.resources = None;
        self.published = None;
        self.scheduler = CascadeScheduler::default();
        self.last_scene = None;
        self.last_sun = None;
        self.last_frustum = None;
        self.last_directional_profile = None;
        self.last_dynamic_cascade_mask = 0;
        self.last_directional_roots = None;
        self.point_cache = PointMapCache::default();
        self.point_cell_identity = 0;
        self.resource_failure_generation = None;
        self.production_logged = [false; 2];
        self.composition_logged = [false; 2];
    }

    /// Invalidate consumer publication without discarding expensive resources.
    pub(super) fn invalidate_publication(&mut self) {
        self.published = None;
    }

    /// Return whether this render epoch already owns a complete publication.
    pub(super) fn has_current_publication(&self, scene: SceneKind) -> bool {
        self.published.is_some_and(|publication| {
            publication.render_epoch == crate::hooks::render_epoch() && publication.scene == scene
        })
    }

    /// Return the stabilized directional vector paired with the live atlas.
    pub(super) fn directional_sun_direction(&self) -> Option<[f32; 3]> {
        let publication = self.published?;
        (publication.directional
            && publication_epoch_is_usable(publication.render_epoch, crate::hooks::render_epoch()))
        .then_some(publication.sun_direction)
    }

    /// Produce directional or point maps for one proven common-hook context.
    ///
    /// # Safety
    ///
    /// `scene` and every object reachable from it must remain owned by the
    /// serialized engine common-shadow call until this method returns.
    pub(super) unsafe fn produce(
        &mut self,
        scene: NativeScene,
        bytecode: &ShadowBytecode,
        settings: NativeShadowsSettings,
    ) -> ReplacementResult {
        let Some(device_ptr) = backend::d3d_device_ptr() else {
            return ReplacementResult::FallbackNative;
        };
        let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
            return ReplacementResult::FallbackNative;
        };

        // Copy the coherent camera POD before a default-pool allocation can
        // reenter or stall in the driver. The engine does not guarantee a
        // second equivalent common-shadow invocation, so first-use resource
        // creation and map generation must complete in this transaction.
        let Some(camera) = crate::fnv_world_pipeline::shadow_generation_camera()
            .or_else(|| unsafe { backend::fnv_world_camera_frame_fast(1, 1) })
            .filter(|camera| camera.available && camera.world_transform.available)
        else {
            return ReplacementResult::FallbackNative;
        };
        let Some(shadow_camera) = shadow_camera(camera) else {
            return ReplacementResult::FallbackNative;
        };

        let generation = backend::d3d_device_generation();
        if self.resource_failure_generation == Some(generation) {
            return ReplacementResult::FallbackNative;
        }
        let shared_ready = self
            .resources
            .as_ref()
            .is_some_and(|resources| resources.device_identity == device_ptr as usize);
        if !shared_ready {
            self.release();
            match ShadowResources::create(&device, bytecode) {
                Ok(resources) => {
                    self.resources = Some(resources);
                }
                Err(error) => {
                    self.resource_failure_generation = Some(generation);
                    self.log_error("could not create shared shadow shader resources", &error);
                    return ReplacementResult::FallbackNative;
                }
            }
        }

        let resources = self.resources.as_mut().ok_or_else(direct3d_failure);
        let branch_result = match resources {
            Ok(resources) => resources.ensure_branch(&device, scene.kind, generation, settings),
            Err(error) => Err(error),
        };
        if let Err(error) = branch_result {
            self.log_error(
                "could not create shadow resources for the current location",
                &error,
            );
            return ReplacementResult::FallbackNative;
        }
        // Texture writes become visible immediately. Remove the publication
        // before touching them so a later failure cannot expose a partly
        // updated atlas or cube family to pre-alpha composition.
        self.published = None;
        let result = self.produce_transaction(&device, scene, camera, shadow_camera, settings);
        match result {
            Ok(publication) => {
                if let Some(publication) = publication {
                    let branch = scene_branch_index(publication.scene);
                    if !self.production_logged[branch] {
                        log::info!(
                            "[SHADOWS] {} maps produced for the common epoch ({} shadowed point lights)",
                            scene_branch_label(publication.scene),
                            publication.point_count
                        );
                        self.production_logged[branch] = true;
                    }
                    self.published = Some(publication);
                }
                ReplacementResult::Produced
            }
            Err(error) => {
                self.log_error(
                    "shadow production failed and fell back to native shadows",
                    &error,
                );
                ReplacementResult::FallbackNative
            }
        }
    }

    fn produce_transaction(
        &mut self,
        device: &Device9Ref<'_>,
        scene: NativeScene,
        camera: CameraFrame,
        shadow_camera: ShadowCamera,
        settings: NativeShadowsSettings,
    ) -> Direct3DResult<Option<PublishedFrame>> {
        let slots = RenderTargetSlots::query(device)?;
        let attachments = RenderAttachments::capture(device, slots)?;
        // Stage every CPU-side cache mutation beside the D3D transaction.
        // `draw_maps` may finish its texture writes and still lose `EndScene`
        // or state restoration. In that case the next invocation must repeat
        // the same cadence rather than treating an unpublished map family as
        // current.
        let mut scheduler = self.scheduler;
        let mut last_scene = self.last_scene;
        let mut last_sun = self.last_sun;
        let mut last_frustum = self.last_frustum;
        let mut last_directional_profile = self.last_directional_profile;
        let mut last_dynamic_cascade_mask = self.last_dynamic_cascade_mask;
        let mut last_directional_roots = self.last_directional_roots;
        let mut point_cache = self.point_cache;
        let mut point_cell_identity = self.point_cell_identity;
        let now_millis = self
            .clock_origin
            .elapsed()
            .as_millis()
            .min(u64::MAX as u128) as u64;
        let resources = self.resources.as_mut().ok_or_else(direct3d_failure)?;
        capture_state_block(&resources.state_block)?;

        let begin_result = device.begin_scene();
        if let Err(error) = begin_result {
            return finish_render_transaction(
                device,
                &attachments,
                Some(&resources.state_block),
                Err(error),
            )
            .map(|()| None);
        }

        if let Err(error) = unsafe { resources.scratch.begin_native_state_journal(scene.renderer) }
        {
            let mut result = Err(error);
            if let Err(end_error) = device.end_scene()
                && result.is_ok()
            {
                result = Err(end_error);
            }
            return finish_render_transaction(
                device,
                &attachments,
                Some(&resources.state_block),
                result,
            )
            .map(|()| None);
        }

        let draw_result = unsafe {
            resources.draw_maps(
                device,
                scene,
                camera,
                shadow_camera,
                &mut scheduler,
                &mut last_scene,
                &mut last_sun,
                &mut last_frustum,
                &mut last_directional_profile,
                &mut last_dynamic_cascade_mask,
                &mut last_directional_roots,
                &mut point_cache,
                &mut point_cell_identity,
                now_millis,
                settings,
            )
        };
        let mut result = draw_result;
        if let Err(error) = unsafe { resources.scratch.restore_native_state_journal() }
            && result.is_ok()
        {
            result = Err(error);
        }
        if let Err(error) = device.end_scene()
            && result.is_ok()
        {
            result = Err(error);
        }
        let publication = result.as_ref().ok().copied().flatten();
        finish_render_transaction(
            device,
            &attachments,
            Some(&resources.state_block),
            result.map(|_| ()),
        )?;
        self.scheduler = scheduler;
        self.last_scene = last_scene;
        self.last_sun = last_sun;
        self.last_frustum = last_frustum;
        self.last_directional_profile = last_directional_profile;
        self.last_dynamic_cascade_mask = last_dynamic_cascade_mask;
        self.last_directional_roots = last_directional_roots;
        self.point_cache = point_cache;
        self.point_cell_identity = point_cell_identity;
        Ok(publication)
    }

    /// Composite the current main-view publication into opaque scene color.
    ///
    /// # Safety
    ///
    /// RT0 must be the live main-world surface at the pre-alpha boundary.
    pub(super) unsafe fn consume_before_alpha(
        &mut self,
        device_ptr: *mut c_void,
        settings: NativeShadowsSettings,
    ) -> Direct3DResult<bool> {
        let Some(publication) = self.published else {
            return Ok(false);
        };
        if !publication_epoch_is_usable(publication.render_epoch, crate::hooks::render_epoch()) {
            self.published = None;
            return Ok(false);
        }
        let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
            return Err(direct3d_failure());
        };
        let Some(resources) = self.resources.as_mut() else {
            return Ok(false);
        };
        if resources.device_identity != device_ptr as usize {
            self.release();
            return Ok(false);
        }
        let composed = unsafe { resources.consume(device, publication, settings)? };
        if composed {
            let branch = scene_branch_index(publication.scene);
            if !self.composition_logged[branch] {
                log::info!(
                    "[SHADOWS] {} publication composed into scene color",
                    scene_branch_label(publication.scene)
                );
                self.composition_logged[branch] = true;
            }
        }
        Ok(composed)
    }

    fn log_error(&mut self, message: &'static str, error: &impl core::fmt::Display) {
        if self.error_logs < MAX_ERROR_LOGS {
            log::warn!("[SHADOWS] {message}: {error}");
            self.error_logs += 1;
        }
    }
}

fn scene_branch_index(scene: SceneKind) -> usize {
    (scene == SceneKind::Interior) as usize
}

fn scene_branch_label(scene: SceneKind) -> &'static str {
    if scene == SceneKind::Interior {
        "interior"
    } else {
        "exterior"
    }
}

struct ShadowResources {
    device_identity: usize,
    programs: GenerationPrograms,
    far_clear_pixel: PixelShader9,
    point_pixel_one: PixelShader9,
    point_pixel_six: PixelShader9,
    point_pixel_twelve: PixelShader9,
    contact_pixel: PixelShader9,
    contact_blur_pixel: PixelShader9,
    composite_pixel: PixelShader9,
    directional_composite_pixel: PixelShader9,
    directional: Option<DirectionalResources>,
    points: Option<PointResources>,
    directional_failure_generation: Option<u32>,
    point_failure_generation: Option<u32>,
    consumer: Option<ConsumerTargets>,
    state_block: StateBlock9,
    scratch: TraversalScratch,
    directional_roots: Vec<DirectionalRoot>,
    cascade_matrices: [[[f32; 4]; 4]; CASCADE_COUNT],
    cascade_projections: [Option<CascadeProjection>; CASCADE_COUNT],
    cascade_origins: [[f32; 3]; CASCADE_COUNT],
    actor_crops: [[f32; 4]; 3],
    cascade_spheres: [[f32; 4]; CASCADE_COUNT],
    cascade_splits: [CascadeSplit; CASCADE_COUNT],
    /// Stabilized light direction paired with each retained atlas quadrant.
    cascade_suns: [[f32; 3]; CASCADE_COUNT],
    // Directional atlas metadata is published as one immutable camera/sun
    // epoch. Atmosphere must never consume a newer sun than the retained maps.
    cascade_sun: [f32; 3],
}

/// Exterior-only map family. It is created on first exterior production so
/// an interior session never pays for the 4096 atlas or FP16 work surfaces.
struct DirectionalResources {
    atlas: Texture9,
    atlas_surface: Surface9,
    /// Four-sample generation target matching NVR custom-quality coverage.
    directional_generation_surface: Surface9,
    /// Reusable single-sample resolve for static and actor map publication.
    _directional_moments: Texture9,
    /// Single-sample resolve copied into one persistent atlas quadrant.
    directional_moments_surface: Surface9,
    /// Coverage-aware two-channel actor work target. Static EVSM4 and actor
    /// coverage cannot share a resolve format: averaging a hardware-zero
    /// EVSM clear with a valid sample does not produce a valid distribution.
    directional_actor_generation_surface: Surface9,
    /// Actor near/middle maps packed side-by-side. Packing them behind one
    /// sampler lowers the already-heavy compositor's static instruction and
    /// texture-read footprint. Their fitted projection preserves or increases
    /// caster texel density at half the static-map dimension.
    actor_near_middle_moments: Texture9,
    actor_near_middle_surface: Surface9,
    /// Actor-only far map; cascade three never admits animated actors.
    actor_far_moments: Texture9,
    actor_far_surface: Surface9,
    directional_depth: Surface9,
    directional_actor_depth: Surface9,
    samples: u32,
}

impl DirectionalResources {
    fn create(device: &Device9Ref<'_>) -> Direct3DResult<Self> {
        let atlas = device.create_render_target_texture(
            ATLAS_RESOLUTION,
            ATLAS_RESOLUTION,
            D3DFMT_A16B16G16R16F,
        )?;
        let atlas_surface = atlas.surface_level(0)?;
        // Receiver filtering can soften a recorded edge, but it cannot recover
        // a thin triangle missed by a center-only raster sample. NVR custom
        // quality uses four coverage samples. OMV retains that silhouette
        // quality on one reusable 2048 work surface instead of NVR's complete
        // 4096 multisampled atlas, then resolves only a quadrant that changed.
        let directional_generation_surface = device.create_render_target_surface(
            NVR_CASCADE_RESOLUTION,
            NVR_CASCADE_RESOLUTION,
            D3DFMT_A16B16G16R16F,
            D3DMULTISAMPLE_4_SAMPLES,
            0,
            false,
        )?;
        let directional_moments = device.create_render_target_texture(
            NVR_CASCADE_RESOLUTION,
            NVR_CASCADE_RESOLUTION,
            D3DFMT_A16B16G16R16F,
        )?;
        let directional_moments_surface = directional_moments.surface_level(0)?;
        let create_actor_family = |format| -> Direct3DResult<_> {
            let generation = device.create_render_target_surface(
                ACTOR_MAP_RESOLUTION,
                ACTOR_MAP_RESOLUTION,
                format,
                D3DMULTISAMPLE_4_SAMPLES,
                0,
                false,
            )?;
            let near_middle = device.create_render_target_texture(
                ACTOR_MAP_RESOLUTION * 2,
                ACTOR_MAP_RESOLUTION,
                format,
            )?;
            let far = device.create_render_target_texture(
                ACTOR_MAP_RESOLUTION,
                ACTOR_MAP_RESOLUTION,
                format,
            )?;
            let near_middle_surface = near_middle.surface_level(0)?;
            let far_surface = far.surface_level(0)?;
            Ok((
                generation,
                near_middle,
                near_middle_surface,
                far,
                far_surface,
            ))
        };
        // G16R16F halves the presentation-rate actor bandwidth. Some early
        // shader-model-three devices expose the format for textures but not
        // four-sample render targets; retain a quality-equivalent A16B16G16R16F
        // family there instead of making the complete shadow branch fail.
        let (
            directional_actor_generation_surface,
            actor_near_middle,
            actor_near_middle_surface,
            actor_far,
            actor_far_surface,
        ) = create_actor_family(D3DFMT_G16R16F)
            .or_else(|_| create_actor_family(D3DFMT_A16B16G16R16F))?;
        let directional_depth = device.create_depth_stencil_surface(
            NVR_CASCADE_RESOLUTION,
            NVR_CASCADE_RESOLUTION,
            D3DFMT_D24S8,
            D3DMULTISAMPLE_4_SAMPLES,
            0,
            true,
        )?;
        let directional_actor_depth = device.create_depth_stencil_surface(
            ACTOR_MAP_RESOLUTION,
            ACTOR_MAP_RESOLUTION,
            D3DFMT_D24S8,
            D3DMULTISAMPLE_4_SAMPLES,
            0,
            true,
        )?;
        Ok(Self {
            atlas,
            atlas_surface,
            directional_generation_surface,
            _directional_moments: directional_moments,
            directional_moments_surface,
            directional_actor_generation_surface,
            actor_near_middle_moments: actor_near_middle,
            actor_near_middle_surface,
            actor_far_moments: actor_far,
            actor_far_surface,
            directional_depth,
            directional_actor_depth,
            samples: 4,
        })
    }
}

/// Bounded local-light map family shared by interior and exterior locations.
struct PointResources {
    /// Published static-plus-actor cubes sampled by the receiver.
    point_cubes: Vec<CubeTexture9>,
    /// Immutable world geometry used to erase old actor silhouettes without
    /// resubmitting every wall and object on each presentation.
    static_cubes: Vec<CubeTexture9>,
    point_depth: Surface9,
}

impl PointResources {
    fn create(device: &Device9Ref<'_>, count: usize) -> Direct3DResult<Self> {
        let mut point_cubes = Vec::with_capacity(count);
        let mut static_cubes = Vec::with_capacity(count);
        for _ in 0..count {
            point_cubes.push(
                device.create_cube_render_target_texture(POINT_CUBE_RESOLUTION, D3DFMT_R32F)?,
            );
            static_cubes.push(
                device.create_cube_render_target_texture(POINT_CUBE_RESOLUTION, D3DFMT_R32F)?,
            );
        }
        let point_depth = device.create_depth_stencil_surface(
            POINT_CUBE_RESOLUTION,
            POINT_CUBE_RESOLUTION,
            D3DFMT_D24S8,
            D3DMULTISAMPLE_NONE,
            0,
            true,
        )?;
        Ok(Self {
            point_cubes,
            static_cubes,
            point_depth,
        })
    }
}

impl ShadowResources {
    fn create(device: &Device9Ref<'_>, bytecode: &ShadowBytecode) -> Direct3DResult<Self> {
        Ok(Self {
            device_identity: device.as_raw() as usize,
            programs: GenerationPrograms {
                directional_vertex: device.create_vertex_shader(&bytecode.directional_vertex)?,
                directional_pixel: device.create_pixel_shader(&bytecode.directional_pixel)?,
                cube_vertex: device.create_vertex_shader(&bytecode.cube_vertex)?,
                cube_pixel: device.create_pixel_shader(&bytecode.cube_pixel)?,
            },
            far_clear_pixel: device.create_pixel_shader(&bytecode.far_clear_pixel)?,
            point_pixel_one: device.create_pixel_shader(&bytecode.point_accumulation_one)?,
            point_pixel_six: device.create_pixel_shader(&bytecode.point_accumulation_six)?,
            point_pixel_twelve: device.create_pixel_shader(&bytecode.point_accumulation_twelve)?,
            contact_pixel: device.create_pixel_shader(&bytecode.contact)?,
            contact_blur_pixel: device.create_pixel_shader(&bytecode.contact_blur)?,
            composite_pixel: device.create_pixel_shader(&bytecode.composite)?,
            directional_composite_pixel: device
                .create_pixel_shader(&bytecode.directional_composite)?,
            directional: None,
            points: None,
            directional_failure_generation: None,
            point_failure_generation: None,
            consumer: None,
            state_block: device.create_state_block(D3DSBT_ALL)?,
            scratch: TraversalScratch::with_capacity(),
            directional_roots: Vec::with_capacity(DIRECTIONAL_ROOT_CACHE_CAPACITY),
            cascade_matrices: [[[0.0; 4]; 4]; CASCADE_COUNT],
            cascade_projections: [None; CASCADE_COUNT],
            cascade_origins: [[0.0; 3]; CASCADE_COUNT],
            actor_crops: [[1.0, 1.0, 0.0, 0.0]; 3],
            cascade_spheres: [[0.0; 4]; CASCADE_COUNT],
            cascade_splits: [CascadeSplit {
                near: 0.0,
                far: 0.0,
            }; CASCADE_COUNT],
            cascade_suns: [[0.0; 3]; CASCADE_COUNT],
            cascade_sun: [0.0; 3],
        })
    }

    fn ensure_branch(
        &mut self,
        device: &Device9Ref<'_>,
        scene: SceneKind,
        generation: u32,
        settings: NativeShadowsSettings,
    ) -> Direct3DResult<()> {
        if self.point_failure_generation == Some(generation) {
            return Err(direct3d_failure());
        }
        let requested = settings
            .interior_shadowed_lights
            .clamp(1, NVR_POINT_LIGHT_COUNT);
        if self
            .points
            .as_ref()
            .is_none_or(|points| points.point_cubes.len() < requested)
        {
            match PointResources::create(device, requested) {
                Ok(points) => {
                    log::info!(
                        "[SHADOWS] Local-light resources ready ({} x {} cube maps)",
                        requested,
                        POINT_CUBE_RESOLUTION
                    );
                    self.points = Some(points);
                }
                Err(error) => {
                    self.point_failure_generation = Some(generation);
                    return Err(error);
                }
            }
        }
        if scene != SceneKind::Interior {
            if self.directional_failure_generation == Some(generation) {
                return Err(direct3d_failure());
            }
            if self.directional.is_none() {
                match DirectionalResources::create(device) {
                    Ok(directional) => {
                        log::info!(
                            "[SHADOWS] Exterior resources ready ({} x {} EVSM4 cascades, {}x sampling)",
                            CASCADE_COUNT,
                            NVR_CASCADE_RESOLUTION,
                            directional.samples
                        );
                        self.directional = Some(directional);
                    }
                    Err(error) => {
                        self.directional_failure_generation = Some(generation);
                        return Err(error);
                    }
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn draw_maps(
        &mut self,
        device: &Device9Ref<'_>,
        scene: NativeScene,
        camera: CameraFrame,
        shadow_camera: ShadowCamera,
        scheduler: &mut CascadeScheduler,
        last_scene: &mut Option<SceneKind>,
        last_sun: &mut Option<[f32; 3]>,
        last_frustum: &mut Option<[f32; 6]>,
        last_directional_profile: &mut Option<[f32; 2]>,
        last_dynamic_cascade_mask: &mut u8,
        last_directional_roots: &mut Option<[DirectionalRootSetSignature; CASCADE_COUNT]>,
        point_cache: &mut PointMapCache,
        point_cell_identity: &mut usize,
        now_millis: u64,
        settings: NativeShadowsSettings,
    ) -> Direct3DResult<Option<PublishedFrame>> {
        clear_auxiliary_targets(device)?;
        let directional = scene.kind != SceneKind::Interior;
        let mut actor_overlay_mask = 0_u8;
        if directional {
            let sky = backend::native_sky_frame().ok_or_else(direct3d_failure)?;
            let sun = stabilize_sun_direction(*last_sun, sky.sun_direction)
                .ok_or_else(direct3d_failure)?;
            let frustum = camera_signature(camera);
            let directional_profile = [settings.exterior_distance, settings.cascade_split_lambda];
            let splits = practical_cascade_splits(
                camera.near_z,
                camera.far_z,
                settings.exterior_distance,
                settings.cascade_split_lambda,
            )
            .ok_or_else(direct3d_failure)?;
            let first_projection =
                cascade_projection(shadow_camera, splits[0], sun, NVR_CASCADE_RESOLUTION)
                    .ok_or_else(direct3d_failure)?;
            let mut projections = [first_projection; CASCADE_COUNT];
            for index in 1..CASCADE_COUNT {
                projections[index] =
                    cascade_projection(shadow_camera, splits[index], sun, NVR_CASCADE_RESOLUTION)
                        .ok_or_else(direct3d_failure)?;
            }
            // Collect once so actor bounds can route near animation to the
            // independent overlay and invalidate only intersecting outer maps.
            // The same cache is then reused by every submitted map; it never
            // survives the engine-owned common-shadow transaction.
            let mut directional_roots = core::mem::take(&mut self.directional_roots);
            let roots_complete =
                unsafe { native::collect_directional_roots(scene, &mut directional_roots) };
            let current_root_signature = roots_complete
                .then(|| native::directional_root_set_signatures(directional_roots.as_slice()));
            let dynamic_cascade_mask = if roots_complete {
                unsafe {
                    native::directional_dynamic_cascade_mask(
                        directional_roots.as_slice(),
                        splits,
                        shadow_camera.forward,
                        camera.world_transform.translation,
                    )
                }
            } else {
                // The complete overflow visitor cannot cheaply precompute
                // actor bounds. Conservatively refresh all actor-capable maps.
                0b0111
            };
            let caster_work = directional_caster_work(
                *last_dynamic_cascade_mask,
                dynamic_cascade_mask,
                roots_complete,
            );
            let frustum_changed = last_frustum
                .is_none_or(|previous| projection_materially_changed(previous, frustum));
            let root_dirty =
                directional_root_set_dirty(*last_directional_roots, current_root_signature);
            let invalidating_change = *last_scene != Some(scene.kind) || frustum_changed;
            let (mandatory_dirty, quality_dirty) = if invalidating_change {
                (CascadeDirty::all(), CascadeDirty::none())
            } else if root_dirty != CascadeDirty::none() {
                (root_dirty, CascadeDirty::none())
            } else if *last_directional_profile != Some(directional_profile) {
                (
                    CascadeDirty::from_mask(cascade_split_change_mask(self.cascade_splits, splits)),
                    CascadeDirty::none(),
                )
            } else {
                // Near actors follow presentation cadence in their private
                // overlay. Static maps remain immutable while their guarded
                // spheres contain the current receiver slices; outer actor
                // maps and each expired projection rebuild independently.
                let mut mandatory_mask = caster_work.static_map_mask;
                let mut quality_mask = 0_u8;
                for index in 0..CASCADE_COUNT {
                    let stored = self.cascade_spheres[index];
                    let stored_absolute: [f32; 3] = std::array::from_fn(|axis| {
                        self.cascade_origins[index][axis] + stored[axis]
                    });
                    let current_absolute: [f32; 3] = std::array::from_fn(|axis| {
                        camera.world_transform.translation[axis] + projections[index].center[axis]
                    });
                    let refresh = retained_cascade_refresh(
                        stored_absolute,
                        stored[3],
                        current_absolute,
                        projections[index].receiver_radius,
                        self.cascade_suns[index],
                        sun,
                        NVR_CASCADE_RESOLUTION,
                    );
                    if refresh.mandatory {
                        mandatory_mask |= 1 << index;
                    } else if refresh.quality {
                        quality_mask |= 1 << index;
                    }
                }
                (
                    CascadeDirty::from_mask(mandatory_mask),
                    CascadeDirty::from_mask(quality_mask),
                )
            };
            let plan =
                scheduler.plan_refreshes_at_millis(mandatory_dirty, quality_dirty, now_millis);
            // Cell and reference lists are identical for every due cascade.
            // Apply each map's form profile from the scalar metadata gathered
            // above. A capacity overflow uses the complete visitor below; it
            // never drops casters or allocates in this render transaction.
            let render_result = (|| -> Direct3DResult<()> {
                for index in 0..CASCADE_COUNT {
                    if plan.render[index] {
                        let projection = projections[index];
                        let minimum_radius = cascade_minimum_caster_radius(
                            index,
                            projection.radius,
                            NVR_CASCADE_RESOLUTION,
                        )
                        .ok_or_else(direct3d_failure)?;
                        unsafe {
                            self.draw_directional_map(
                                device,
                                scene,
                                index,
                                projection,
                                camera.world_transform.translation,
                                minimum_radius,
                                roots_complete.then_some(directional_roots.as_slice()),
                                roots_complete && index < 3,
                            )?
                        };
                        // A cached atlas quadrant and its projection are one
                        // immutable result. Replacing only the matrix on skipped
                        // cadence frames samples old moments through a new
                        // transform, producing neutral or displaced shadows while
                        // wasting CPU on a projection that cannot be rendered.
                        // The consumer rebases this retained transform from the
                        // generation origin to the current camera instead.
                        self.cascade_matrices[index] = projection.world_to_shadow;
                        self.cascade_projections[index] = Some(projection);
                        self.cascade_origins[index] = camera.world_transform.translation;
                        self.cascade_spheres[index] = [
                            projection.center[0],
                            projection.center[1],
                            projection.center[2],
                            projection.radius,
                        ];
                        self.cascade_splits[index] = splits[index];
                        self.cascade_suns[index] = sun;
                    }
                }
                // Outer overlays are copied first only to keep the historical
                // near-last ordering deterministic. Every result now leaves
                // the reusable resolve immediately for its packed persistent
                // slot, so no later overlay can overwrite a published map.
                // The far actor texture doubles as the mandatory same-size
                // MSAA resolve. Publish near/middle first and far last so a
                // live far result is never overwritten by the scratch role.
                for index in [1_usize, 0, 2] {
                    if caster_work.actor_overlay_mask & (1 << index) == 0 {
                        continue;
                    }
                    let static_projection =
                        self.cascade_projections[index].ok_or_else(direct3d_failure)?;
                    let actor_bounds = unsafe {
                        native::directional_actor_bounds(
                            directional_roots.as_slice(),
                            index,
                            static_projection,
                            self.cascade_origins[index],
                        )
                    }
                    .ok_or_else(direct3d_failure)?;
                    let actor_projection = static_projection
                        .cropped_to_actor_bounds(actor_bounds, ACTOR_MAP_RESOLUTION)
                        .ok_or_else(direct3d_failure)?;
                    unsafe {
                        self.draw_directional_actor_overlay(
                            device,
                            scene,
                            index,
                            actor_projection.projection,
                            self.cascade_origins[index],
                            directional_roots.as_slice(),
                        )?
                    };
                    self.actor_crops[index] = actor_projection.uv_scale_offset;
                    actor_overlay_mask |= 1 << index;
                }
                Ok(())
            })();
            // Do not retain engine pointers beyond the common-prefix epoch,
            // even though the vector allocation itself remains reusable.
            directional_roots.clear();
            self.directional_roots = directional_roots;
            render_result?;
            scheduler.commit(plan);
            if plan.render[0] {
                self.cascade_sun = sun;
            }
            *last_sun = Some(sun);
            *last_directional_profile = Some(directional_profile);
            *last_dynamic_cascade_mask = dynamic_cascade_mask;
            *last_directional_roots = current_root_signature;
            if frustum_changed {
                // Keep the last materially distinct projection as the
                // comparison anchor. Updating this on every sub-pixel jitter
                // would let a slowly changing FOV remain forever inside the
                // per-frame dead band instead of accumulating to a rebuild.
                *last_frustum = Some(frustum);
            }
        }

        // Local sources remain part of native scene lighting outdoors too.
        // Omitting their cubes made the Pip-Boy and practical lights cast no
        // shadow whenever a directional atlas was active. Selection is still
        // capped by the same user-owned budget and unchanged cubes are cached.
        let points = unsafe {
            let retained_identities = if *point_cell_identity == scene.cell as usize {
                point_cache.identities()
            } else {
                [0; NVR_POINT_LIGHT_COUNT]
            };
            native::select_point_lights(
                camera.world_transform.translation,
                shadow_camera.forward,
                retained_identities,
                settings.interior_shadowed_lights,
                settings.interior_light_radius_multiplier,
                settings.interior_light_draw_distance,
            )
        };
        let mut current = [PointMapSignature::EMPTY; NVR_POINT_LIGHT_COUNT];
        let mut dynamic_faces = [0_u8; NVR_POINT_LIGHT_COUNT];
        for (index, point) in points.shadowed().iter().enumerate() {
            let caster_snapshot = unsafe { native::point_light_caster_snapshot(point) };
            current[index] = PointMapSignature {
                identity: point.identity,
                position: point.position,
                radius: point.radius,
                caster_signature: caster_snapshot.static_signature,
            };
            dynamic_faces[index] = caster_snapshot.dynamic_faces;
        }
        let active_cache = if *point_cell_identity == scene.cell as usize {
            *point_cache
        } else {
            PointMapCache::default()
        };
        let plan = active_cache.plan(current, dynamic_faces, points.shadowed().len());
        unsafe { self.draw_point_maps(device, scene, camera, points.shadowed(), plan)? };
        *point_cache = plan.next;
        *point_cell_identity = scene.cell as usize;
        let point_map_metadata = plan.published;

        // Location identity participates in directional dirty detection. It
        // advances for interiors too, so the retained atlas is neutralized and
        // rebuilt when the next exterior becomes active.
        *last_scene = Some(scene.kind);
        let mut published_points = [PublishedPointLight::default(); NVR_POINT_LIGHT_COUNT];
        for slot in 0..points.shadowed().len() {
            let source = plan.source_index(slot).ok_or_else(direct3d_failure)?;
            let point = points.shadowed().get(source).ok_or_else(direct3d_failure)?;
            let map = point_map_metadata[slot];
            published_points[slot] = PublishedPointLight {
                position: map.position,
                color: point.color,
                radius: map.radius,
                shadow_fade: point.shadow_fade,
            };
        }
        Ok(Some(PublishedFrame {
            render_epoch: crate::hooks::render_epoch(),
            scene: scene.kind,
            directional,
            sun_direction: self.cascade_sun,
            matrices: self.cascade_matrices,
            matrix_origins: self.cascade_origins,
            actor_crops: self.actor_crops,
            actor_overlay_mask,
            splits: self.cascade_splits,
            points: published_points,
            point_count: points.shadowed().len(),
        }))
    }

    unsafe fn draw_directional_map(
        &mut self,
        device: &Device9Ref<'_>,
        scene: NativeScene,
        cascade: usize,
        projection: CascadeProjection,
        camera_translation: [f32; 3],
        minimum_radius: f32,
        cached_roots: Option<&[DirectionalRoot]>,
        exclude_dynamic_actors: bool,
    ) -> Direct3DResult<()> {
        let directional = self.directional.as_ref().ok_or_else(direct3d_failure)?;
        device.set_render_target(0, &directional.directional_generation_surface)?;
        device.set_depth_stencil_surface(Some(&directional.directional_depth))?;
        set_viewport(device, 0, 0, NVR_CASCADE_RESOLUTION, NVR_CASCADE_RESOLUTION)?;
        device.clear_attachments(D3DCLEAR_ZBUFFER as u32 | D3DCLEAR_STENCIL as u32, 0, 1.0, 0)?;
        draw_evsm_far_clear(
            device,
            &self.far_clear_pixel,
            NVR_CASCADE_RESOLUTION,
            NVR_CASCADE_RESOLUTION,
        )?;
        // The clear helper temporarily detaches depth for its transformed
        // full-screen vertices. Reattach the already-cleared matching depth
        // surface before any geometry writes moments.
        device.set_depth_stencil_surface(Some(&directional.directional_depth))?;
        render::configure_generation_state(device)?;
        render::begin_directional_map(device, &self.programs, projection.world_to_shadow)?;
        let mut draw_result = Ok(());
        let mut draw_root = |root: *mut u8, is_land: bool, is_lod: bool| {
            if draw_result.is_ok() {
                draw_result = unsafe {
                    render::draw_directional_root(
                        device,
                        scene.renderer,
                        projection,
                        camera_translation,
                        scene.first_person_root,
                        root,
                        is_land,
                        is_lod,
                        minimum_radius,
                        false,
                        &mut self.scratch,
                    )
                };
            }
        };
        if let Some(roots) = cached_roots {
            for root in roots.iter().copied().filter(|root| {
                root.enabled_for(cascade) && !(exclude_dynamic_actors && root.is_dynamic_actor())
            }) {
                draw_root(root.node(), root.is_land, root.is_lod);
            }
        } else {
            unsafe {
                // Capacity overflow is rare and intentionally preserves the
                // old complete bounded visitor instead of reallocating or
                // accepting a partial shadow map.
                native::visit_directional_roots(scene, cascade, |root, is_land, is_lod| {
                    draw_root(root, is_land, is_lod);
                });
            }
        }
        draw_result?;
        self.copy_cascade_to_atlas(device, cascade)
    }

    /// Render animated actors for one cascade into the reusable resolve.
    ///
    /// The static atlas excludes these roots, so a changing player/NPC pose
    /// cannot leave a ghost. A caster-fitted 1024 four-sample target
    /// concentrates samples on occupied light space rather than shading the
    /// empty extent of a full static cascade.
    unsafe fn draw_directional_actor_overlay(
        &mut self,
        device: &Device9Ref<'_>,
        scene: NativeScene,
        cascade: usize,
        projection: CascadeProjection,
        camera_translation: [f32; 3],
        roots: &[DirectionalRoot],
    ) -> Direct3DResult<()> {
        let directional = self.directional.as_ref().ok_or_else(direct3d_failure)?;
        device.set_render_target(0, &directional.directional_actor_generation_surface)?;
        device.set_depth_stencil_surface(Some(&directional.directional_actor_depth))?;
        set_viewport(device, 0, 0, ACTOR_MAP_RESOLUTION, ACTOR_MAP_RESOLUTION)?;
        // RG stores `(depth * coverage, coverage)`. A black multisample clear
        // is therefore an exact neutral distribution, while resolve and
        // bilinear filtering preserve partial silhouette coverage linearly.
        // Hardware-zero EVSM4 was not closed under either operation and made
        // tiny actor edge coverage expand into the rectangular artifacts in
        // the 2026-08-13 actor captures.
        device.clear_attachments(
            D3DCLEAR_TARGET as u32 | D3DCLEAR_ZBUFFER as u32 | D3DCLEAR_STENCIL as u32,
            0,
            1.0,
            0,
        )?;
        render::configure_generation_state(device)?;
        render::begin_directional_map(device, &self.programs, projection.world_to_shadow)?;
        for root in roots
            .iter()
            .copied()
            .filter(|root| unsafe { root.is_active_dynamic_actor() } && root.enabled_for(cascade))
        {
            unsafe {
                render::draw_directional_root(
                    device,
                    scene.renderer,
                    projection,
                    camera_translation,
                    scene.first_person_root,
                    root.node(),
                    false,
                    false,
                    0.0,
                    true,
                    &mut self.scratch,
                )?
            };
        }
        // Resolve once and copy the complete actor distribution into its
        // persistent packed slot. A full 2048x2048 static/actor merge every
        // frame was substantially more work than selecting the nearer moments
        // only at visible receivers.
        device.clear_texture(0)?;
        device.stretch_rect(
            &directional.directional_actor_generation_surface,
            None,
            &directional.actor_far_surface,
            None,
            D3DTEXF_NONE,
        )?;
        let (destination, destination_rect) = match cascade {
            0 | 1 => {
                let left = cascade as i32 * ACTOR_MAP_RESOLUTION as i32;
                (
                    &directional.actor_near_middle_surface,
                    Some(RECT {
                        left,
                        top: 0,
                        right: left + ACTOR_MAP_RESOLUTION as i32,
                        bottom: ACTOR_MAP_RESOLUTION as i32,
                    }),
                )
            }
            // The full-surface resolve above is already the persistent far
            // publication. Avoid a redundant self-copy, which D3D9 does not
            // define and which would add another 1024-square transfer.
            2 => return Ok(()),
            _ => return Err(direct3d_failure()),
        };
        device.stretch_rect(
            &directional.actor_far_surface,
            None,
            destination,
            destination_rect.as_ref(),
            D3DTEXF_NONE,
        )?;
        Ok(())
    }

    /// Publish one completed generation map into its persistent atlas slot.
    ///
    /// Filtering at generation time touched every 2048x2048 texel twice even
    /// when only a small on-screen region sampled the map. The consumer now
    /// performs a bounded stable kernel at visible receivers, so this exact
    /// GPU copy is the only full-map publication work.
    fn copy_cascade_to_atlas(
        &mut self,
        device: &Device9Ref<'_>,
        cascade: usize,
    ) -> Direct3DResult<()> {
        let directional = self.directional.as_ref().ok_or_else(direct3d_failure)?;
        let (x, y) = cascade_origin(cascade);
        device.clear_texture(0)?;
        // D3D9 resolves a multisampled render target only through a full-size
        // StretchRect into a single-sample surface of the same format. Keep
        // this explicit intermediate separate from the quadrant copy; a
        // partial resolve is not a portable D3D9 operation.
        device.stretch_rect(
            &directional.directional_generation_surface,
            None,
            &directional.directional_moments_surface,
            None,
            D3DTEXF_NONE,
        )?;
        let destination = RECT {
            left: x as i32,
            top: y as i32,
            right: (x + NVR_CASCADE_RESOLUTION) as i32,
            bottom: (y + NVR_CASCADE_RESOLUTION) as i32,
        };
        device.stretch_rect(
            &directional.directional_moments_surface,
            None,
            &directional.atlas_surface,
            Some(&destination),
            D3DTEXF_NONE,
        )?;
        Ok(())
    }

    unsafe fn draw_point_maps(
        &mut self,
        device: &Device9Ref<'_>,
        scene: NativeScene,
        camera: CameraFrame,
        points: &PointLightSet,
        plan: PointMapPlan,
    ) -> Direct3DResult<()> {
        // A captured engine state may have any prior texture bound. D3D9
        // rejects a cube face as a render target while that cube aliases a
        // sampler, so unbind every pixel sampler inside the state-blocked
        // transaction before touching either persistent cube family.
        for sampler in 0..16 {
            device.clear_texture(sampler)?;
        }
        for index in 0..points.len() {
            if plan.render_faces[index] == 0 {
                continue;
            }
            let source = plan.source_index(index).ok_or_else(direct3d_failure)?;
            let point = points.get(source).ok_or_else(direct3d_failure)?;
            let views = point_cube_views(point.relative_position, point.radius)
                .ok_or_else(direct3d_failure)?;
            for face in 0..6 {
                if plan.render_faces[index] & (1 << face) == 0 {
                    continue;
                }
                if plan.static_faces[index] & (1 << face) != 0 {
                    // The backup owns only immutable geometry. It changes
                    // solely with light identity/position/radius, never with
                    // actor animation, so walls and clutter are not walked at
                    // presentation cadence.
                    device.clear_texture(1)?;
                    let point_resources = self.points.as_ref().ok_or_else(direct3d_failure)?;
                    let static_surface =
                        point_resources.static_cubes[index].surface(CUBE_FACES[face], 0)?;
                    device.set_render_target(0, &static_surface)?;
                    device.set_depth_stencil_surface(Some(&point_resources.point_depth))?;
                    set_viewport(device, 0, 0, POINT_CUBE_RESOLUTION, POINT_CUBE_RESOLUTION)?;
                    device.clear_attachments(
                        D3DCLEAR_TARGET as u32 | D3DCLEAR_ZBUFFER as u32 | D3DCLEAR_STENCIL as u32,
                        0xFFFF_FFFF,
                        1.0,
                        0,
                    )?;
                    unsafe {
                        self.draw_point_face_casters(
                            device,
                            scene,
                            camera,
                            point,
                            views[face].world_to_shadow,
                            face,
                            CasterSubset::Static,
                        )?
                    };
                }

                let point_resources = self.points.as_ref().ok_or_else(direct3d_failure)?;
                let static_surface =
                    point_resources.static_cubes[index].surface(CUBE_FACES[face], 0)?;
                let published_surface =
                    point_resources.point_cubes[index].surface(CUBE_FACES[face], 0)?;
                device.clear_texture(1)?;
                device.stretch_rect(
                    &static_surface,
                    None,
                    &published_surface,
                    None,
                    D3DTEXF_NONE,
                )?;

                if plan.dynamic_draw_faces[index] & (1 << face) != 0 {
                    device.set_render_target(0, &published_surface)?;
                    device.set_depth_stencil_surface(Some(&point_resources.point_depth))?;
                    set_viewport(device, 0, 0, POINT_CUBE_RESOLUTION, POINT_CUBE_RESOLUTION)?;
                    // The static radial depth is already in the color target.
                    // Clear only actor-pass depth; the cube pixel shader takes
                    // min(actor, static) at actor fragments so occlusion by an
                    // immutable wall remains exact.
                    device.clear_attachments(
                        D3DCLEAR_ZBUFFER as u32 | D3DCLEAR_STENCIL as u32,
                        0,
                        1.0,
                        0,
                    )?;
                    device.set_cube_texture(1, &point_resources.static_cubes[index])?;
                    set_point_clamp_sampler(device, 1)?;
                    unsafe {
                        self.draw_point_face_casters(
                            device,
                            scene,
                            camera,
                            point,
                            views[face].world_to_shadow,
                            face,
                            CasterSubset::Dynamic,
                        )?
                    };
                }
            }
        }
        Ok(())
    }

    /// Submit one point face from the requested disjoint caster family.
    ///
    /// # Safety
    ///
    /// `scene`, `point`, and every native geometry pointer visited from them
    /// must remain live for the common-shadow transaction.
    #[allow(clippy::too_many_arguments)]
    unsafe fn draw_point_face_casters(
        &mut self,
        device: &Device9Ref<'_>,
        scene: NativeScene,
        camera: CameraFrame,
        point: &native::PointLight,
        world_to_shadow: [[f32; 4]; 4],
        face: usize,
        subset: CasterSubset,
    ) -> Direct3DResult<()> {
        render::configure_generation_state(device)?;
        render::begin_point_face(
            device,
            &self.programs,
            world_to_shadow,
            [
                point.relative_position[0],
                point.relative_position[1],
                point.relative_position[2],
                point.radius,
            ],
        )?;
        let mut draw_result = Ok(());
        let visited = unsafe {
            native::visit_point_geometry(point, |geometry| {
                if draw_result.is_ok() {
                    draw_result = render::draw_point_geometry(
                        device,
                        scene.renderer,
                        camera.world_transform.translation,
                        scene.first_person_root,
                        point.relative_position,
                        point.radius,
                        face,
                        geometry,
                        subset,
                        &mut self.scratch,
                    );
                }
            })
        };
        if visited == 0 {
            unsafe {
                native::visit_point_fallback_roots(scene, |root, is_land, is_lod| {
                    if draw_result.is_ok() {
                        draw_result = render::draw_point_root(
                            device,
                            scene.renderer,
                            camera.world_transform.translation,
                            scene.first_person_root,
                            point.relative_position,
                            point.radius,
                            face,
                            root,
                            is_land,
                            is_lod,
                            subset,
                            &mut self.scratch,
                        );
                    }
                });
            }
        }
        draw_result
    }

    unsafe fn consume(
        &mut self,
        device: Device9Ref<'_>,
        publication: PublishedFrame,
        settings: NativeShadowsSettings,
    ) -> Direct3DResult<bool> {
        if !consumer_has_shadow_work(publication.directional, publication.point_count) {
            return Ok(false);
        }
        let provider = backend::active_depth_provider();
        let source = device.render_target(0)?;
        let desc = source.desc()?;
        if desc.Width == 0 || desc.Height == 0 {
            return Ok(false);
        }
        let depth = match unsafe {
            backend::resolve_scene_depth(
                provider,
                device.as_raw().cast(),
                None,
                DepthResolveSlot::World,
                DepthResolveStage::PreAlphaWorld,
                None,
                "FNV shadows before alpha and atmosphere",
                crate::hooks::render_epoch(),
            )
        } {
            DepthResolveOutcome::Resolved { depth, .. } => depth,
            DepthResolveOutcome::Busy | DepthResolveOutcome::Rejected => return Ok(false),
        };
        let Some(depth_texture) = depth.texture else {
            return Ok(false);
        };
        if depth.world_projection.reversed_depth.is_none() {
            return Ok(false);
        }
        let camera = if depth.world_projection.camera.available {
            depth.world_projection.camera
        } else {
            backend::fnv_world_camera_frame(desc.Width, desc.Height)
                .filter(|camera| camera.available)
                .ok_or_else(direct3d_failure)?
        };
        if !camera.world_transform.available {
            return Ok(false);
        }
        let recreate = self
            .consumer
            .as_ref()
            .is_none_or(|targets| !targets.matches(&desc));
        if recreate {
            self.consumer = Some(ConsumerTargets::create(&device, &desc)?);
        }
        self.consumer
            .as_mut()
            .ok_or_else(direct3d_failure)?
            .ensure_branch(
                &device,
                publication.point_count > 0,
                publication.directional && settings.contact_shadows,
                &desc,
            )?;
        let targets = self.consumer.as_ref().ok_or_else(direct3d_failure)?;
        let slots = RenderTargetSlots::query(&device)?;
        let attachments = RenderAttachments::capture(&device, slots)?;
        capture_state_block(&self.state_block)?;
        let draw_result = self.draw_consumer(
            &device,
            &source,
            &desc,
            depth,
            depth_texture.as_ptr(),
            camera,
            publication,
            targets,
            settings,
        );
        finish_render_transaction(&device, &attachments, Some(&self.state_block), draw_result)?;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    fn draw_consumer(
        &self,
        device: &Device9Ref<'_>,
        source: &Surface9,
        desc: &D3DSURFACE_DESC,
        depth: DepthFrame,
        depth_texture: *mut c_void,
        camera: CameraFrame,
        publication: PublishedFrame,
        targets: &ConsumerTargets,
        settings: NativeShadowsSettings,
    ) -> Direct3DResult<()> {
        clear_auxiliary_targets(device)?;
        bind_fullscreen_state(device)?;
        let common = consumer_camera_constants(desc, depth, camera);
        set_viewport(device, 0, 0, desc.Width, desc.Height)?;

        if publication.point_count > 0 {
            let local_lights = targets.local_lights.as_ref().ok_or_else(direct3d_failure)?;
            let view = shadow_camera(camera).ok_or_else(direct3d_failure)?;
            let mut constants = common;
            constants[6] = [
                depth.world_projection.reversed_depth_f32(),
                0.0,
                settings.interior_receiver_bias,
                0.0,
            ];
            device.set_pixel_shader_constant_f(0, &constants)?;
            let mut scissors = [None; NVR_POINT_LIGHT_COUNT];
            for index in 0..publication.point_count {
                let light = publication.points[index];
                let relative: [f32; 3] = std::array::from_fn(|axis| {
                    light.position[axis] - camera.world_transform.translation[axis]
                });
                let view_position = [
                    dot3(relative, view.right),
                    dot3(relative, view.up),
                    dot3(relative, view.forward),
                ];
                scissors[index] = point_light_scissor(
                    view_position,
                    light.radius,
                    [
                        camera.frustum_left,
                        camera.frustum_right,
                        camera.frustum_top,
                        camera.frustum_bottom,
                    ],
                    desc.Width,
                    desc.Height,
                );
            }
            device.set_render_target(0, &local_lights.deficit_surface)?;
            device.set_render_target(1, &local_lights.total_surface)?;
            device.clear_attachments(D3DCLEAR_TARGET as u32, 0, 1.0, 0)?;
            // Reconstruct depth and the edge-aware normal inside the same
            // scissored draw that consumes the cubes. The equations are
            // identical to the former geometry pass, but its full-resolution
            // FP16 write/read pair and render-target transition disappear.
            unsafe { device.set_raw_base_texture(0, depth_texture)? };
            set_point_clamp_sampler(device, 0)?;
            device.set_pixel_shader_constant_f(0, &constants)?;
            let plan = point_consumer_plan(scissors, publication.point_count);
            let mut drew_batch = false;
            for draw in plan.draws() {
                let point_pixel = match draw.count {
                    0 | 1 => &self.point_pixel_one,
                    2..=6 => &self.point_pixel_six,
                    _ => &self.point_pixel_twelve,
                };
                device.set_pixel_shader(point_pixel)?;
                let mut positions = [[0.0; 4]; POINT_CONSUMER_BATCH_SIZE];
                let mut colors = [[0.0; 4]; POINT_CONSUMER_BATCH_SIZE];
                for (slot, index) in draw
                    .indices
                    .into_iter()
                    .take(draw.count as usize)
                    .enumerate()
                {
                    let light = publication.points[index as usize];
                    let relative: [f32; 3] = std::array::from_fn(|axis| {
                        light.position[axis] - camera.world_transform.translation[axis]
                    });
                    positions[slot] = [relative[0], relative[1], relative[2], light.radius];
                    colors[slot] = [
                        light.color[0],
                        light.color[1],
                        light.color[2],
                        light.shadow_fade,
                    ];
                    device.set_cube_texture(
                        (slot + 1) as u32,
                        &self
                            .points
                            .as_ref()
                            .ok_or_else(direct3d_failure)?
                            .point_cubes[index as usize],
                    )?;
                    set_point_clamp_sampler(device, (slot + 1) as u32)?;
                }
                device.set_scissor_rect(
                    draw.scissor.left as i32,
                    draw.scissor.top as i32,
                    draw.scissor.right as i32,
                    draw.scissor.bottom as i32,
                )?;
                device.set_render_state(D3DRS_SCISSORTESTENABLE, 1)?;
                device.set_pixel_shader_constant_f(
                    6,
                    &[{
                        let mut control = constants[6];
                        control[1] = draw.count as f32;
                        control
                    }],
                )?;
                device.set_pixel_shader_constant_f(7, &positions)?;
                device.set_pixel_shader_constant_f(19, &colors)?;
                device.set_render_state(D3DRS_ALPHABLENDENABLE, drew_batch as u32)?;
                if drew_batch {
                    device.set_render_state(D3DRS_SRCBLEND, D3DBLEND_ONE.0 as u32)?;
                    device.set_render_state(D3DRS_DESTBLEND, D3DBLEND_ONE.0 as u32)?;
                    device.set_render_state(D3DRS_BLENDOP, D3DBLENDOP_ADD.0 as u32)?;
                }
                draw_quad(device, 0, 0, desc.Width, desc.Height)?;
                drew_batch = true;
            }
            device.set_render_state(D3DRS_SCISSORTESTENABLE, 0)?;
            device.set_render_state(D3DRS_ALPHABLENDENABLE, 0)?;
            // Subsequent contact and composition targets are single-output.
            // D3D9 requires every attached MRT to match the active viewport,
            // so detach the full-resolution auxiliary target immediately.
            device.clear_render_target(1)?;
        }

        let contact_distance =
            effective_contact_distance(settings.contact_distance, camera.far_z).unwrap_or(0.0);
        let contact_enabled = publication.directional
            && settings.contact_shadows
            && contact_distance > 0.0
            && targets.contact.is_some();
        if contact_enabled {
            let contact = targets.contact.as_ref().ok_or_else(direct3d_failure)?;
            let view = shadow_camera(camera).ok_or_else(direct3d_failure)?;
            let view_sun = [
                dot3(publication.sun_direction, view.right),
                dot3(publication.sun_direction, view.up),
                dot3(publication.sun_direction, view.forward),
                0.0,
            ];
            device.set_render_target(0, &contact.raw_surface)?;
            set_viewport(device, 0, 0, contact.width, contact.height)?;
            device.set_pixel_shader(&self.contact_pixel)?;
            unsafe { device.set_raw_base_texture(0, depth_texture)? };
            set_point_clamp_sampler(device, 0)?;
            device.set_pixel_shader_constant_f(0, &common[..3])?;
            device.set_pixel_shader_constant_f(
                6,
                &[[
                    depth.world_projection.reversed_depth_f32(),
                    contact_distance,
                    settings.contact_ray_distance,
                    20.0,
                ]],
            )?;
            device.set_pixel_shader_constant_f(7, &[view_sun])?;
            device.set_pixel_shader_constant_f(8, &[nvr_contact_sample_offsets()])?;
            device.set_pixel_shader_constant_f(
                9,
                &[[
                    1.0 / depth.world_projection.sampled_depth_levels(),
                    0.0,
                    0.0,
                    0.0,
                ]],
            )?;
            draw_quad(device, 0, 0, contact.width, contact.height)?;

            // Receiver depth can validate a wall but cannot validate the ray
            // occluder that produced last frame's contact evidence. Temporal
            // accumulation therefore creates unavoidable motion trails. Use a
            // same-frame bilateral cross instead: it removes binary speckle
            // without retaining any camera- or occluder-dependent state.
            device.clear_texture(0)?;
            device.set_render_target(0, &contact.filtered_surface)?;
            device.set_pixel_shader(&self.contact_blur_pixel)?;
            device.set_texture(0, &contact.raw)?;
            set_point_clamp_sampler(device, 0)?;
            device.set_pixel_shader_constant_f(
                0,
                &[[
                    contact.width as f32,
                    contact.height as f32,
                    1.0 / contact.width as f32,
                    1.0 / contact.height as f32,
                ]],
            )?;
            draw_quad(device, 0, 0, contact.width, contact.height)?;
        }

        // Source-owned composition is necessary for two distinct identities:
        // directional neutral is one, while local-deficit neutral is zero.
        // A scene copy lets one pass preserve sky/HDR emitters and combine both
        // terms without an illegal read/write alias or two incompatible blends.
        for sampler in 0..=7 {
            device.clear_texture(sampler)?;
        }
        crate::render_state::copy_exact_color_surface(device, source, &targets.source_surface)?;
        device.set_render_target(0, source)?;
        set_viewport(device, 0, 0, desc.Width, desc.Height)?;
        device.set_pixel_shader(if publication.point_count == 0 {
            &self.directional_composite_pixel
        } else {
            &self.composite_pixel
        })?;
        device.set_texture(0, &targets.source)?;
        unsafe { device.set_raw_base_texture(1, depth_texture)? };
        set_linear_clamp_sampler(device, 0)?;
        set_point_clamp_sampler(device, 1)?;
        set_linear_clamp_sampler(device, 2)?;
        set_linear_clamp_sampler(device, 3)?;
        set_point_clamp_sampler(device, 4)?;

        let mut matrices = publication.matrices;
        // Cascade ownership is view-depth based. Retained transforms remain
        // map-owned and are rebased from their generation origins below; the
        // guarded clipmap spheres already prove current receiver coverage.
        for index in 0..CASCADE_COUNT {
            matrices[index] = translate_shadow_matrix(
                matrices[index],
                camera.world_transform.translation,
                publication.matrix_origins[index],
            );
        }
        device.set_pixel_shader_constant_f(0, &common[..6])?;
        for (index, matrix) in matrices.iter().enumerate() {
            device.set_pixel_shader_constant_f((6 + index * 4) as u32, matrix)?;
        }
        let splits = publication.cascade_splits();
        device.set_pixel_shader_constant_f(26, &[[1.0 / 65_536.0, 0.0, 0.0, 0.0]])?;
        if publication.directional {
            let directional = self.directional.as_ref().ok_or_else(direct3d_failure)?;
            device.set_texture(2, &directional.atlas)?;
            if publication.actor_overlay_mask & 0b011 != 0 {
                device.set_texture(5, &directional.actor_near_middle_moments)?;
                set_linear_clamp_sampler(device, 5)?;
            }
            if publication.actor_overlay_mask & 0b100 != 0 {
                device.set_texture(7, &directional.actor_far_moments)?;
                set_linear_clamp_sampler(device, 7)?;
            }
        }
        if publication.point_count > 0 {
            let local_lights = targets.local_lights.as_ref().ok_or_else(direct3d_failure)?;
            device.set_texture(3, &local_lights.deficit)?;
            device.set_texture(6, &local_lights.total)?;
            set_linear_clamp_sampler(device, 6)?;
        }
        if contact_enabled {
            let contact = targets.contact.as_ref().ok_or_else(direct3d_failure)?;
            device.set_texture(4, &contact.filtered)?;
        }
        let point_darkness = if publication.scene == SceneKind::Interior {
            settings.interior_darkness
        } else {
            settings.exterior_darkness
        };
        device.set_pixel_shader_constant_f(
            22,
            &[
                splits,
                [
                    depth.world_projection.reversed_depth_f32(),
                    publication.directional as u8 as f32,
                    settings.exterior_darkness,
                    BLEED_REDUCTION,
                ],
                [
                    splits[0] * 0.05,
                    splits[1] * 0.05,
                    splits[2] * 0.05,
                    splits[3] * 0.05,
                ],
                [
                    0.5 / NVR_CASCADE_RESOLUTION as f32,
                    1.0 - 0.5 / NVR_CASCADE_RESOLUTION as f32,
                    0.75 / NVR_CASCADE_RESOLUTION as f32,
                    0.0,
                ],
            ],
        )?;
        device.set_pixel_shader_constant_f(31, &[[contact_enabled as u8 as f32, 0.0, 0.0, 0.0]])?;
        device.set_pixel_shader_constant_f(
            32,
            &[[
                (publication.point_count > 0) as u8 as f32,
                point_darkness,
                0.0,
                0.0,
            ]],
        )?;
        device.set_pixel_shader_constant_f(
            33,
            &[[
                publication.sun_direction[0],
                publication.sun_direction[1],
                publication.sun_direction[2],
                0.0,
            ]],
        )?;
        let contact_texel = targets.contact.as_ref().map_or([0.0; 2], |contact| {
            [1.0 / contact.width as f32, 1.0 / contact.height as f32]
        });
        device.set_pixel_shader_constant_f(
            34,
            &[std::array::from_fn(|index| {
                u8::from(publication.actor_overlay_mask & (1 << index) != 0) as f32
            })],
        )?;
        device
            .set_pixel_shader_constant_f(35, &[[contact_texel[0], contact_texel[1], 0.0, 0.0]])?;
        device.set_pixel_shader_constant_f(36, &publication.actor_crops)?;
        device.set_pixel_shader_constant_f(
            39,
            &[[
                0.5 / ACTOR_MAP_RESOLUTION as f32,
                1.0 - 0.5 / ACTOR_MAP_RESOLUTION as f32,
                0.0,
                0.0,
            ]],
        )?;
        device.set_render_state(D3DRS_ALPHABLENDENABLE, 0)?;
        device.set_render_state(D3DRS_COLORWRITEENABLE, 0xF)?;
        draw_quad(device, 0, 0, desc.Width, desc.Height)?;
        Ok(())
    }
}

impl PublishedFrame {
    fn cascade_splits(self) -> [f32; 4] {
        self.splits.map(|split| split.far)
    }
}

struct ConsumerTargets {
    width: u32,
    height: u32,
    format: libpsycho::os::windows::directx9::D3DFORMAT,
    source: Texture9,
    source_surface: Surface9,
    local_lights: Option<LocalLightConsumerTargets>,
    contact: Option<ContactConsumerTargets>,
}

/// Full-resolution exact RGB local-light ownership and occlusion estimates.
struct LocalLightConsumerTargets {
    deficit: Texture9,
    deficit_surface: Surface9,
    total: Texture9,
    total_surface: Surface9,
}

/// Half-resolution current-frame contact evidence and bilateral resolve.
struct ContactConsumerTargets {
    raw: Texture9,
    raw_surface: Surface9,
    filtered: Texture9,
    filtered_surface: Surface9,
    width: u32,
    height: u32,
}

impl ConsumerTargets {
    fn create(device: &Device9Ref<'_>, desc: &D3DSURFACE_DESC) -> Direct3DResult<Self> {
        // Direct scene multiplication is legal only for formats which expose
        // post-pixel-shader blending. Fail transactionally so the established
        // native fallback remains available on an unusual D3D9 device.
        device.check_render_target_blending_support(desc.Format)?;
        let source = device.create_render_target_texture(desc.Width, desc.Height, desc.Format)?;
        let source_surface = source.surface_level(0)?;
        Ok(Self {
            width: desc.Width,
            height: desc.Height,
            format: desc.Format,
            source,
            source_surface,
            local_lights: None,
            contact: None,
        })
    }

    fn ensure_branch(
        &mut self,
        device: &Device9Ref<'_>,
        point_lights: bool,
        contact_shadows: bool,
        desc: &D3DSURFACE_DESC,
    ) -> Direct3DResult<()> {
        if point_lights && self.local_lights.is_none() {
            self.local_lights = Some(LocalLightConsumerTargets::create(device, desc)?);
        }
        if contact_shadows && self.contact.is_none() {
            self.contact = Some(ContactConsumerTargets::create(device, desc)?);
        }
        Ok(())
    }

    fn matches(&self, desc: &D3DSURFACE_DESC) -> bool {
        self.width == desc.Width && self.height == desc.Height && self.format == desc.Format
    }
}

impl LocalLightConsumerTargets {
    fn create(device: &Device9Ref<'_>, desc: &D3DSURFACE_DESC) -> Direct3DResult<Self> {
        if device.simultaneous_render_target_count()? < 2 {
            return Err(direct3d_failure());
        }
        device.check_render_target_blending_support(D3DFMT_A16B16G16R16F)?;
        // The same scissored draw emits exact RGB totals and exact RGB
        // deficits. Keeping these in equal-format MRTs avoids both a second
        // fullscreen pass and cross-channel artifacts between colored lights.
        let deficit =
            device.create_render_target_texture(desc.Width, desc.Height, D3DFMT_A16B16G16R16F)?;
        let total =
            device.create_render_target_texture(desc.Width, desc.Height, D3DFMT_A16B16G16R16F)?;
        Ok(Self {
            deficit_surface: deficit.surface_level(0)?,
            deficit,
            total_surface: total.surface_level(0)?,
            total,
        })
    }
}

impl ContactConsumerTargets {
    fn create(device: &Device9Ref<'_>, desc: &D3DSURFACE_DESC) -> Direct3DResult<Self> {
        let width = desc.Width.div_ceil(2).max(1);
        let height = desc.Height.div_ceil(2).max(1);
        let raw = device.create_render_target_texture(width, height, D3DFMT_G16R16F)?;
        let filtered = device.create_render_target_texture(width, height, D3DFMT_G16R16F)?;
        Ok(Self {
            raw_surface: raw.surface_level(0)?,
            filtered_surface: filtered.surface_level(0)?,
            raw,
            filtered,
            width,
            height,
        })
    }
}

fn shadow_camera(camera: CameraFrame) -> Option<ShadowCamera> {
    let transform = camera.world_transform;
    let right = [
        transform.rotation[0][2],
        transform.rotation[1][2],
        transform.rotation[2][2],
    ];
    let up = [
        transform.rotation[0][1],
        transform.rotation[1][1],
        transform.rotation[2][1],
    ];
    let forward = [
        transform.rotation[0][0],
        transform.rotation[1][0],
        transform.rotation[2][0],
    ];
    let candidate = ShadowCamera {
        near: camera.near_z,
        far: camera.far_z,
        frustum_left: camera.frustum_left,
        frustum_right: camera.frustum_right,
        frustum_bottom: camera.frustum_bottom,
        frustum_top: camera.frustum_top,
        forward,
        up,
        right,
        translation: transform.translation,
        // This helper is called only from the serialized world-shadow
        // producer/consumer epochs where WorldSceneGraph is live.
        fov_compensation: unsafe { native::directional_fov_compensation() },
    };
    (camera.available && transform.available).then_some(candidate)
}

fn camera_signature(camera: CameraFrame) -> [f32; 6] {
    [
        camera.near_z,
        camera.far_z,
        camera.frustum_left,
        camera.frustum_right,
        camera.frustum_bottom,
        camera.frustum_top,
    ]
}

/// Build receiver selection spheres in the camera domain used by composition.
///
/// Cached matrices deliberately remain tied to their generation origins, but
/// cascade choice is a property of the current view. Reusing a cached map's
/// larger coverage sphere here makes the blend shell move across world walls
/// and then jump whenever that map refreshes.
#[cfg(test)]
pub(super) fn consumer_selection_spheres(
    mut camera: ShadowCamera,
    splits: [CascadeSplit; CASCADE_COUNT],
    sun_direction: [f32; 3],
) -> Option<[[f32; 4]; CASCADE_COUNT]> {
    // The depth buffer was rasterized with TAA's off-centre lens, so depth
    // reconstruction must retain that lens. Cascade ownership is different:
    // the atlas producer uses the restored output camera. Remove only the lens
    // centre here while preserving its exact width, height, pose, and FOV.
    // Otherwise every Halton sample moves the blend shell across static walls.
    let half_width = (camera.frustum_right - camera.frustum_left) * 0.5;
    let half_height = (camera.frustum_top - camera.frustum_bottom) * 0.5;
    camera.frustum_left = -half_width;
    camera.frustum_right = half_width;
    camera.frustum_bottom = -half_height;
    camera.frustum_top = half_height;
    let first = cascade_projection(camera, splits[0], sun_direction, NVR_CASCADE_RESOLUTION)?;
    let mut spheres = [first.receiver_sphere(); CASCADE_COUNT];
    for index in 1..CASCADE_COUNT {
        spheres[index] =
            cascade_projection(camera, splits[index], sun_direction, NVR_CASCADE_RESOLUTION)?
                .receiver_sphere();
    }
    Some(spheres)
}

/// Return the atlas quadrants whose complete frustum interval changed.
///
/// NVR derives every interval from the configured distance. Distance and
/// lambda edits therefore invalidate every quadrant whose near or far plane
/// changed; retaining a hybrid near profile creates atlas crop seams.
fn cascade_split_change_mask(
    previous: [CascadeSplit; CASCADE_COUNT],
    current: [CascadeSplit; CASCADE_COUNT],
) -> u8 {
    const SPLIT_EPSILON: f32 = 0.001;
    previous
        .into_iter()
        .zip(current)
        .enumerate()
        .fold(0, |mask, (index, (previous, current))| {
            if (previous.near - current.near).abs() > SPLIT_EPSILON
                || (previous.far - current.far).abs() > SPLIT_EPSILON
            {
                mask | (1 << index)
            } else {
                mask
            }
        })
}

/// Distinguish a real projection change from OMV's sub-pixel TAA lens shift.
///
/// The frustum edge pairs can translate together by less than one pixel while
/// their shape remains unchanged. Rebuilding four 2048 maps for that shift is
/// both wasteful and visually less stable. Width, height, near, and far still
/// use a tight relative tolerance, while an off-center lens shift is admitted
/// only below one 2048-map texel in normalized frustum space.
fn projection_materially_changed(previous: [f32; 6], current: [f32; 6]) -> bool {
    if !previous
        .iter()
        .chain(current.iter())
        .all(|value| value.is_finite())
    {
        return true;
    }

    const SHAPE_RELATIVE_EPSILON: f32 = 0.0001;
    const CENTER_NORMALIZED_EPSILON: f32 = 1.0 / NVR_CASCADE_RESOLUTION as f32;
    let relative_changed = |left: f32, right: f32| {
        let scale = left.abs().max(right.abs()).max(1.0);
        (left - right).abs() > scale * SHAPE_RELATIVE_EPSILON
    };
    if relative_changed(previous[0], current[0]) || relative_changed(previous[1], current[1]) {
        return true;
    }

    let previous_width = previous[3] - previous[2];
    let current_width = current[3] - current[2];
    let previous_height = previous[5] - previous[4];
    let current_height = current[5] - current[4];
    if previous_width <= 0.0
        || current_width <= 0.0
        || previous_height <= 0.0
        || current_height <= 0.0
        || relative_changed(previous_width, current_width)
        || relative_changed(previous_height, current_height)
    {
        return true;
    }

    let center_x_shift =
        ((current[2] + current[3]) - (previous[2] + previous[3])).abs() * 0.5 / previous_width;
    let center_y_shift =
        ((current[4] + current[5]) - (previous[4] + previous[5])).abs() * 0.5 / previous_height;
    center_x_shift > CENTER_NORMALIZED_EPSILON || center_y_shift > CENTER_NORMALIZED_EPSILON
}

fn consumer_camera_constants(
    desc: &D3DSURFACE_DESC,
    depth: DepthFrame,
    camera: CameraFrame,
) -> [[f32; 4]; 7] {
    let near = camera.near_z.max(0.01);
    let far = camera.far_z.max(near + 1.0);
    let transform = camera.world_transform;
    [
        [
            desc.Width as f32,
            desc.Height as f32,
            1.0 / desc.Width.max(1) as f32,
            1.0 / desc.Height.max(1) as f32,
        ],
        [near * far, far - near, near, far],
        [
            camera.frustum_left,
            camera.frustum_right,
            camera.frustum_bottom,
            camera.frustum_top,
        ],
        [
            transform.rotation[0][2] * transform.scale,
            transform.rotation[0][1] * transform.scale,
            transform.rotation[0][0] * transform.scale,
            0.0,
        ],
        [
            transform.rotation[1][2] * transform.scale,
            transform.rotation[1][1] * transform.scale,
            transform.rotation[1][0] * transform.scale,
            0.0,
        ],
        [
            transform.rotation[2][2] * transform.scale,
            transform.rotation[2][1] * transform.scale,
            transform.rotation[2][0] * transform.scale,
            0.0,
        ],
        [depth.world_projection.reversed_depth_f32(), 0.0, 0.0, 0.0],
    ]
}

fn translate_shadow_matrix(
    matrix: [[f32; 4]; 4],
    current_origin: [f32; 3],
    map_origin: [f32; 3],
) -> [[f32; 4]; 4] {
    let delta: [f32; 3] = std::array::from_fn(|index| current_origin[index] - map_origin[index]);
    let mut adjusted = matrix;
    for column in 0..4 {
        adjusted[3][column] = matrix[3][column]
            + delta[0] * matrix[0][column]
            + delta[1] * matrix[1][column]
            + delta[2] * matrix[2][column];
    }
    adjusted
}

fn draw_evsm_far_clear(
    device: &Device9Ref<'_>,
    shader: &PixelShader9,
    width: u32,
    height: u32,
) -> Direct3DResult<()> {
    bind_fullscreen_state(device)?;
    device.set_pixel_shader(shader)?;
    let moments = evsm4_moments(1.0, true).ok_or_else(direct3d_failure)?;
    device.set_pixel_shader_constant_f(0, &[moments])?;
    draw_quad(device, 0, 0, width, height)
}

fn bind_fullscreen_state(device: &Device9Ref<'_>) -> Direct3DResult<()> {
    device.set_depth_stencil_surface(None)?;
    device.clear_vertex_shader()?;
    unsafe { device.set_raw_vertex_declaration(core::ptr::null_mut())? };
    device.set_fvf(ScreenVertex::FVF)?;
    device.set_render_state(D3DRS_ZENABLE, 0)?;
    device.set_render_state(D3DRS_ZWRITEENABLE, 0)?;
    device.set_render_state(D3DRS_CULLMODE, D3DCULL_NONE.0 as u32)?;
    device.set_render_state(D3DRS_ALPHABLENDENABLE, 0)?;
    // The producer is entered from several native shadow branches and the
    // consumer runs before OMV's regular screen pipeline establishes state.
    // In both cases Fallout may leave pixel-rejection state enabled. D3D9
    // still reports a successful draw when alpha/stencil reject every pixel,
    // which previously paid the complete map/contact cost with no visible
    // composition.
    device.set_render_state(D3DRS_ALPHATESTENABLE, 0)?;
    device.set_render_state(D3DRS_ALPHAREF, 0)?;
    device.set_render_state(D3DRS_ALPHAFUNC, D3DCMP_ALWAYS.0 as u32)?;
    device.set_render_state(D3DRS_STENCILENABLE, 0)?;
    device.set_render_state(D3DRS_SCISSORTESTENABLE, 0)?;
    device.set_render_state(D3DRS_MULTISAMPLEANTIALIAS, 1)?;
    device.set_render_state(D3DRS_MULTISAMPLEMASK, u32::MAX)?;
    match crate::backend::fnv_alpha_coverage_mode() {
        crate::backend::AlphaCoverageMode::None => {}
        crate::backend::AlphaCoverageMode::Nvidia => {
            device.set_render_state(D3DRS_ADAPTIVETESS_Y, 0)?;
        }
        crate::backend::AlphaCoverageMode::Amd => {
            device.set_render_state(D3DRS_POINTSIZE, AMD_ALPHA_TO_COVERAGE_OFF)?;
        }
    }
    device.set_render_state(D3DRS_SRGBWRITEENABLE, 0)?;
    device.set_render_state(D3DRS_COLORWRITEENABLE, 0xF)?;
    // Point-light accumulation uses same-format MRTs. The native caller may
    // leave RT1's independent mask disabled even when RT0 is writable.
    device.set_render_state(D3DRS_COLORWRITEENABLE1, 0xF)?;
    Ok(())
}

fn clear_auxiliary_targets(device: &Device9Ref<'_>) -> Direct3DResult<()> {
    for target in 1..device.simultaneous_render_target_count()?.min(4) {
        device.clear_render_target(target)?;
    }
    Ok(())
}

fn set_viewport(
    device: &Device9Ref<'_>,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
) -> Direct3DResult<()> {
    device.set_viewport(&D3DVIEWPORT9 {
        X: x,
        Y: y,
        Width: width,
        Height: height,
        MinZ: 0.0,
        MaxZ: 1.0,
    })
}

fn draw_quad(
    device: &Device9Ref<'_>,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
) -> Direct3DResult<()> {
    let left = x as f32 - 0.5;
    let top = y as f32 - 0.5;
    let right = (x + width) as f32 - 0.5;
    let bottom = (y + height) as f32 - 0.5;
    let quad = [
        ScreenVertex::new(left, top, 0.0, 0.0),
        ScreenVertex::new(right, top, 1.0, 0.0),
        ScreenVertex::new(left, bottom, 0.0, 1.0),
        ScreenVertex::new(right, bottom, 1.0, 1.0),
    ];
    unsafe { device.draw_primitive_up(D3DPT_TRIANGLESTRIP, 2, &quad) }
}

fn set_linear_clamp_sampler(device: &Device9Ref<'_>, sampler: u32) -> Direct3DResult<()> {
    device.set_sampler_state(sampler, D3DSAMP_ADDRESSU, D3DTADDRESS_CLAMP.0 as u32)?;
    device.set_sampler_state(sampler, D3DSAMP_ADDRESSV, D3DTADDRESS_CLAMP.0 as u32)?;
    device.set_sampler_state(sampler, D3DSAMP_MINFILTER, D3DTEXF_LINEAR.0 as u32)?;
    device.set_sampler_state(sampler, D3DSAMP_MAGFILTER, D3DTEXF_LINEAR.0 as u32)?;
    device.set_sampler_state(sampler, D3DSAMP_MIPFILTER, D3DTEXF_NONE.0 as u32)?;
    device.set_sampler_state(sampler, D3DSAMP_SRGBTEXTURE, 0)
}

fn set_point_clamp_sampler(device: &Device9Ref<'_>, sampler: u32) -> Direct3DResult<()> {
    device.set_sampler_state(sampler, D3DSAMP_ADDRESSU, D3DTADDRESS_CLAMP.0 as u32)?;
    device.set_sampler_state(sampler, D3DSAMP_ADDRESSV, D3DTADDRESS_CLAMP.0 as u32)?;
    device.set_sampler_state(sampler, D3DSAMP_MINFILTER, D3DTEXF_POINT.0 as u32)?;
    device.set_sampler_state(sampler, D3DSAMP_MAGFILTER, D3DTEXF_POINT.0 as u32)?;
    device.set_sampler_state(sampler, D3DSAMP_MIPFILTER, D3DTEXF_NONE.0 as u32)?;
    device.set_sampler_state(sampler, D3DSAMP_SRGBTEXTURE, 0)
}

fn cascade_origin(cascade: usize) -> (u32, u32) {
    (
        (cascade as u32 % 2) * NVR_CASCADE_RESOLUTION,
        (cascade as u32 / 2) * NVR_CASCADE_RESOLUTION,
    )
}

fn dot3(left: [f32; 3], right: [f32; 3]) -> f32 {
    left[0] * right[0] + left[1] * right[1] + left[2] * right[2]
}

#[cfg(test)]
mod tests {
    use super::{
        cascade_split_change_mask, consumer_selection_spheres, projection_materially_changed,
        translate_shadow_matrix,
    };
    use crate::effects::shadows::{
        contract::{cascade_sphere_selection, practical_cascade_splits},
        math::{ShadowCamera, cascade_projection},
    };

    #[test]
    fn extending_shadow_distance_refreshes_every_changed_nvr_interval() {
        let base = practical_cascade_splits(5.0, 28_000.0, 6_000.0, 0.9).expect("base splits");
        let extended =
            practical_cascade_splits(5.0, 28_000.0, 20_000.0, 0.9).expect("extended splits");
        assert_eq!(cascade_split_change_mask(base, extended), 0b1111);
    }

    #[test]
    fn projection_cache_ignores_subpixel_jitter_but_accumulates_real_changes() {
        let base = [5.0, 28_000.0, -1.0, 1.0, -0.5625, 0.5625];
        let mut jittered = base;
        let horizontal_half_pixel = (base[3] - base[2]) * 0.5 / 1920.0;
        let vertical_half_pixel = (base[5] - base[4]) * -0.5 / 1080.0;
        jittered[2] += horizontal_half_pixel;
        jittered[3] += horizontal_half_pixel;
        jittered[4] += vertical_half_pixel;
        jittered[5] += vertical_half_pixel;
        assert!(!projection_materially_changed(base, jittered));

        let mut changed_fov = base;
        changed_fov[2] -= 0.01;
        changed_fov[3] += 0.01;
        assert!(projection_materially_changed(base, changed_fov));

        let mut changed_lens = base;
        changed_lens[2] += 0.01;
        changed_lens[3] += 0.01;
        assert!(projection_materially_changed(base, changed_lens));
        assert!(projection_materially_changed(base, [f32::NAN; 6]));
    }

    #[test]
    fn cached_cascade_matrix_rebases_from_map_origin_to_current_camera() {
        let matrix = [
            [2.0, 3.0, 5.0, 7.0],
            [11.0, 13.0, 17.0, 19.0],
            [23.0, 29.0, 31.0, 37.0],
            [41.0, 43.0, 47.0, 53.0],
        ];
        assert_eq!(
            translate_shadow_matrix(matrix, [4.0, 5.0, 6.0], [4.0, 5.0, 6.0]),
            matrix
        );

        let adjusted = translate_shadow_matrix(matrix, [11.0, 18.0, 35.0], [10.0, 20.0, 32.0]);
        for column in 0..4 {
            let expected = matrix[3][column] + matrix[0][column] - 2.0 * matrix[1][column]
                + 3.0 * matrix[2][column];
            assert_eq!(adjusted[3][column], expected);
        }
        assert_eq!(adjusted[..3], matrix[..3]);
    }

    #[test]
    fn taa_lens_jitter_cannot_move_a_directional_cascade_boundary() {
        let base = ShadowCamera {
            near: 5.0,
            far: 353_840.0,
            frustum_left: -1.791_67,
            frustum_right: 1.791_67,
            frustum_bottom: -0.75,
            frustum_top: 0.75,
            forward: [1.0, 0.0, 0.0],
            up: [0.0, 0.0, 1.0],
            right: [0.0, 1.0, 0.0],
            translation: [-72_987.38, -80_610.17, 13_890.36],
            fov_compensation: 1.0,
        };
        // This is the scale and direction of the changing frustum centers in
        // the supplied 3440x1440 runtime trace. It changes only projection
        // jitter; camera pose and FOV remain identical.
        let jittered = ShadowCamera {
            frustum_left: base.frustum_left + 0.000_45,
            frustum_right: base.frustum_right + 0.000_45,
            frustum_bottom: base.frustum_bottom - 0.000_35,
            frustum_top: base.frustum_top - 0.000_35,
            ..base
        };
        let splits = practical_cascade_splits(base.near, base.far, 6_000.0, 0.9)
            .expect("runtime cascade profile");
        let sun = [0.4, 0.3, 0.866_025_4];

        // Negative control: feeding the rendered (jittered) lens directly to
        // cascade construction moves a world-space boundary even though the
        // producer atlas was built with the restored lens.
        let raw_base = splits.map(|split| {
            cascade_projection(base, split, sun, 2_048)
                .expect("base cascade")
                .receiver_sphere()
        });
        let raw_jittered = splits.map(|split| {
            cascade_projection(jittered, split, sun, 2_048)
                .expect("jittered cascade")
                .receiver_sphere()
        });
        let first_boundary = raw_base[0][1] + raw_base[0][3];
        let jittered_boundary = raw_jittered[0][1] + raw_jittered[0][3];
        let receiver = [
            (raw_base[0][0] + raw_jittered[0][0]) * 0.5,
            (first_boundary + jittered_boundary) * 0.5,
            (raw_base[0][2] + raw_jittered[0][2]) * 0.5,
        ];
        assert_ne!(
            cascade_sphere_selection(receiver, raw_base).map(|selection| selection.cascade),
            cascade_sphere_selection(receiver, raw_jittered).map(|selection| selection.cascade),
            "negative control did not place the receiver across the moving boundary"
        );

        let selected_base =
            consumer_selection_spheres(base, splits, sun).expect("base consumer cascade family");
        let selected_jittered = consumer_selection_spheres(jittered, splits, sun)
            .expect("jittered consumer cascade family");
        assert_eq!(
            cascade_sphere_selection(receiver, selected_base).map(|selection| selection.cascade),
            cascade_sphere_selection(receiver, selected_jittered)
                .map(|selection| selection.cascade),
            "TAA lens jitter moved the live cascade/blend boundary across a static receiver"
        );
    }
}
