//! Transactional D3D9 producer and scene-pre shadow consumer.
//!
//! All default-pool resources are owned here and are released as one device
//! generation. The common engine hook only publishes a frame after every map,
//! scene boundary, and state restoration succeeds. The scene-pre consumer is
//! nonblocking and accepts only a publication from the current presentation
//! epoch, so failed or transient shadow work can never leak stale maps.

use core::ffi::c_void;

use libpsycho::os::windows::directx9::{
    CubeTexture9, D3DBLEND_ONE, D3DBLENDOP_ADD, D3DCLEAR_STENCIL, D3DCLEAR_TARGET,
    D3DCLEAR_ZBUFFER, D3DCUBEMAP_FACE_NEGATIVE_X, D3DCUBEMAP_FACE_NEGATIVE_Y,
    D3DCUBEMAP_FACE_NEGATIVE_Z, D3DCUBEMAP_FACE_POSITIVE_X, D3DCUBEMAP_FACE_POSITIVE_Y,
    D3DCUBEMAP_FACE_POSITIVE_Z, D3DCUBEMAP_FACES, D3DCULL_NONE, D3DFMT_A16B16G16R16F, D3DFMT_D24S8,
    D3DFMT_G16R16F, D3DFMT_R32F, D3DMULTISAMPLE_4_SAMPLES, D3DMULTISAMPLE_NONE,
    D3DPT_TRIANGLESTRIP, D3DRS_ALPHABLENDENABLE, D3DRS_BLENDOP, D3DRS_CULLMODE, D3DRS_DESTBLEND,
    D3DRS_SCISSORTESTENABLE, D3DRS_SRCBLEND, D3DRS_SRGBWRITEENABLE, D3DRS_ZENABLE,
    D3DRS_ZWRITEENABLE, D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV, D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER,
    D3DSAMP_MIPFILTER, D3DSBT_ALL, D3DSURFACE_DESC, D3DTADDRESS_CLAMP, D3DTEXF_LINEAR,
    D3DTEXF_NONE, D3DTEXF_POINT, D3DVIEWPORT9, Device9Ref, Direct3DResult, PixelShader9, RECT,
    ScreenVertex, StateBlock9, Surface9, Texture9, direct3d_failure,
};

use crate::{
    backend::{self, CameraFrame, DepthAccess, DepthFrame},
    render_state::{
        RenderAttachments, RenderTargetSlots, capture_state_block, finish_render_transaction,
    },
};

use super::{
    contract::{
        CASCADE_COUNT, CascadeDirty, CascadeScheduler, CascadeSplit, InvocationContext,
        NVR_CASCADE_RESOLUTION, NVR_POINT_LIGHT_COUNT, SceneKind, evsm4_moments,
        practical_cascade_splits,
    },
    math::{
        CascadeProjection, ShadowCamera, cascade_projection, point_cube_views,
        stabilize_sun_direction,
    },
    native::{self, NativeScene, PointLightSelection, PointLightSet},
    render::{self, GenerationPrograms, TraversalScratch},
    shaders::ShadowBytecode,
};

const ATLAS_RESOLUTION: u32 = NVR_CASCADE_RESOLUTION * 2;
const POINT_CUBE_RESOLUTION: u32 = 512;
const SHADOW_DISTANCE: f32 = 6_000.0;
const CASCADE_LAMBDA: f32 = 0.9;
const EXTERIOR_SHADOW_DARKNESS: f32 = 0.75;
const INTERIOR_SHADOW_DARKNESS: f32 = 0.65;
const BLEED_REDUCTION: f32 = 0.2;
const POINT_RECEIVER_BIAS: f32 = 0.018;
const CONTACT_MAX_DEPTH: f32 = 180_000.0;
const CONTACT_RAY_DISTANCE: f32 = 2_000.0;
const CONTACT_THICKNESS: f32 = 20.0;
const MAX_ERROR_LOGS: u32 = 8;

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
    splits: [CascadeSplit; CASCADE_COUNT],
    points: [PublishedPointLight; NVR_POINT_LIGHT_COUNT],
    point_count: usize,
    unshadowed_points: [PublishedPointLight; NVR_POINT_LIGHT_COUNT],
    unshadowed_point_count: usize,
}

/// Complete device-generation state retained across producer and consumer calls.
pub(super) struct ShadowPipeline {
    resources: Option<ShadowResources>,
    scheduler: CascadeScheduler,
    published: Option<PublishedFrame>,
    last_scene: Option<SceneKind>,
    last_sun: Option<[f32; 3]>,
    last_frustum: Option<[f32; 6]>,
    resource_failure_generation: Option<u32>,
    error_logs: u32,
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
            resource_failure_generation: None,
            error_logs: 0,
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
        self.resource_failure_generation = None;
    }

    /// Invalidate consumer publication without discarding expensive resources.
    pub(super) fn invalidate_publication(&mut self) {
        self.published = None;
    }

    /// Return whether this gameplay epoch already owns a complete publication.
    pub(super) fn has_current_main_publication(&self, scene: SceneKind) -> bool {
        self.published.is_some_and(|publication| {
            publication.render_epoch == crate::hooks::render_epoch() && publication.scene == scene
        })
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
        context: InvocationContext,
        bytecode: &ShadowBytecode,
    ) -> ReplacementResult {
        let Some(device_ptr) = backend::d3d_device_ptr() else {
            return ReplacementResult::FallbackNative;
        };
        let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
            return ReplacementResult::FallbackNative;
        };
        let generation = backend::d3d_device_generation();
        if self.resource_failure_generation == Some(generation) {
            return ReplacementResult::FallbackNative;
        }
        if self
            .resources
            .as_ref()
            .is_none_or(|resources| resources.device_identity != device_ptr as usize)
        {
            self.release();
            match ShadowResources::create(&device, bytecode) {
                Ok(resources) => self.resources = Some(resources),
                Err(error) => {
                    self.resource_failure_generation = Some(generation);
                    self.log_error("could not create the fixed shadow resource family", &error);
                    return ReplacementResult::FallbackNative;
                }
            }
        }

        let Some(camera) = (unsafe { backend::fnv_world_camera_frame_fast(1, 1) })
            .filter(|camera| camera.available && camera.world_transform.available)
        else {
            return ReplacementResult::FallbackNative;
        };
        let Some(shadow_camera) = shadow_camera(camera) else {
            return ReplacementResult::FallbackNative;
        };

        // Texture writes become visible immediately. Remove the publication
        // before touching them so a later failure cannot expose a partly
        // updated atlas or cube family to scene-pre composition.
        self.published = None;
        let result = self.produce_transaction(&device, scene, context, camera, shadow_camera);
        match result {
            Ok(publication) => {
                if let Some(publication) = publication {
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
        context: InvocationContext,
        camera: CameraFrame,
        shadow_camera: ShadowCamera,
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

        let draw_result = unsafe {
            resources.draw_maps(
                device,
                scene,
                context,
                camera,
                shadow_camera,
                &mut scheduler,
                &mut last_scene,
                &mut last_sun,
                &mut last_frustum,
            )
        };
        let mut result = draw_result;
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
        Ok(publication)
    }

    /// Composite the current main-view publication into scene color.
    ///
    /// # Safety
    ///
    /// `source_rendered_texture` must be the live FNV image-space source for
    /// the current outer scene-pre callback.
    pub(super) unsafe fn consume_scene_pre(
        &mut self,
        device_ptr: *mut c_void,
        source_rendered_texture: *mut c_void,
    ) -> Direct3DResult<bool> {
        let Some(publication) = self.published else {
            return Ok(false);
        };
        if publication.render_epoch != crate::hooks::render_epoch() {
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
        unsafe { resources.consume(device, source_rendered_texture, publication) }
    }

    fn log_error(&mut self, message: &'static str, error: &impl core::fmt::Display) {
        if self.error_logs < MAX_ERROR_LOGS {
            log::warn!("[SHADOWS] {message}: {error}");
            self.error_logs += 1;
        }
    }
}

struct ShadowResources {
    device_identity: usize,
    programs: GenerationPrograms,
    far_clear_pixel: PixelShader9,
    blur_pixel: PixelShader9,
    normal_pixel: PixelShader9,
    contact_pixel: PixelShader9,
    contact_blur_pixel: PixelShader9,
    point_pixel: PixelShader9,
    composite_pixel: PixelShader9,
    atlas: Texture9,
    atlas_surface: Surface9,
    directional_workspace: Surface9,
    directional_depth: Surface9,
    blur: Texture9,
    blur_surface: Surface9,
    point_cubes: Vec<CubeTexture9>,
    point_depth: Surface9,
    consumer: Option<ConsumerTargets>,
    state_block: StateBlock9,
    scratch: TraversalScratch,
    cascade_matrices: [[[f32; 4]; 4]; CASCADE_COUNT],
    cascade_origins: [[f32; 3]; CASCADE_COUNT],
    cascade_splits: [CascadeSplit; CASCADE_COUNT],
}

impl ShadowResources {
    fn create(device: &Device9Ref<'_>, bytecode: &ShadowBytecode) -> Direct3DResult<Self> {
        let atlas = device.create_render_target_texture(
            ATLAS_RESOLUTION,
            ATLAS_RESOLUTION,
            D3DFMT_A16B16G16R16F,
        )?;
        let atlas_surface = atlas.surface_level(0)?;
        let directional_workspace = device.create_render_target_surface(
            NVR_CASCADE_RESOLUTION,
            NVR_CASCADE_RESOLUTION,
            D3DFMT_A16B16G16R16F,
            D3DMULTISAMPLE_4_SAMPLES,
            0,
            false,
        )?;
        let directional_depth = device.create_depth_stencil_surface(
            NVR_CASCADE_RESOLUTION,
            NVR_CASCADE_RESOLUTION,
            D3DFMT_D24S8,
            D3DMULTISAMPLE_4_SAMPLES,
            0,
            true,
        )?;
        let blur = device.create_render_target_texture(
            NVR_CASCADE_RESOLUTION,
            NVR_CASCADE_RESOLUTION,
            D3DFMT_A16B16G16R16F,
        )?;
        let blur_surface = blur.surface_level(0)?;
        let mut point_cubes = Vec::with_capacity(NVR_POINT_LIGHT_COUNT);
        for _ in 0..NVR_POINT_LIGHT_COUNT {
            point_cubes.push(
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
            device_identity: device.as_raw() as usize,
            programs: GenerationPrograms {
                directional_vertex: device.create_vertex_shader(&bytecode.directional_vertex)?,
                directional_pixel: device.create_pixel_shader(&bytecode.directional_pixel)?,
                cube_vertex: device.create_vertex_shader(&bytecode.cube_vertex)?,
                cube_pixel: device.create_pixel_shader(&bytecode.cube_pixel)?,
            },
            far_clear_pixel: device.create_pixel_shader(&bytecode.far_clear_pixel)?,
            blur_pixel: device.create_pixel_shader(&bytecode.blur_pixel)?,
            normal_pixel: device.create_pixel_shader(&bytecode.normal_reconstruction)?,
            contact_pixel: device.create_pixel_shader(&bytecode.contact)?,
            contact_blur_pixel: device.create_pixel_shader(&bytecode.contact_blur)?,
            point_pixel: device.create_pixel_shader(&bytecode.point_accumulation)?,
            composite_pixel: device.create_pixel_shader(&bytecode.composite)?,
            atlas,
            atlas_surface,
            directional_workspace,
            directional_depth,
            blur,
            blur_surface,
            point_cubes,
            point_depth,
            consumer: None,
            state_block: device.create_state_block(D3DSBT_ALL)?,
            scratch: TraversalScratch::with_capacity(),
            cascade_matrices: [[[0.0; 4]; 4]; CASCADE_COUNT],
            cascade_origins: [[0.0; 3]; CASCADE_COUNT],
            cascade_splits: [CascadeSplit {
                near: 0.0,
                far: 0.0,
            }; CASCADE_COUNT],
        })
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn draw_maps(
        &mut self,
        device: &Device9Ref<'_>,
        scene: NativeScene,
        context: InvocationContext,
        camera: CameraFrame,
        shadow_camera: ShadowCamera,
        scheduler: &mut CascadeScheduler,
        last_scene: &mut Option<SceneKind>,
        last_sun: &mut Option<[f32; 3]>,
        last_frustum: &mut Option<[f32; 6]>,
    ) -> Direct3DResult<Option<PublishedFrame>> {
        clear_auxiliary_targets(device)?;
        let mut points = PointLightSelection::default();
        let directional = scene.kind != SceneKind::Interior;
        let mut sun_direction = [0.0, 0.0, 1.0];
        if directional {
            let sky = backend::native_sky_frame().ok_or_else(direct3d_failure)?;
            let sun = stabilize_sun_direction(*last_sun, sky.sun_direction)
                .ok_or_else(direct3d_failure)?;
            sun_direction = sun;
            let frustum = camera_signature(camera);
            let frustum_changed = last_frustum
                .is_none_or(|previous| projection_materially_changed(previous, frustum));
            let dirty = if *last_scene != Some(scene.kind)
                || last_sun.is_none_or(|previous| dot3(previous, sun) < 0.9998)
                || frustum_changed
            {
                CascadeDirty::all()
            } else {
                CascadeDirty::none()
            };
            let plan = scheduler.plan(context, dirty);
            let splits = practical_cascade_splits(
                camera.near_z,
                camera.far_z,
                SHADOW_DISTANCE,
                CASCADE_LAMBDA,
            )
            .ok_or_else(direct3d_failure)?;
            for index in 0..CASCADE_COUNT {
                if !plan.render[index] {
                    continue;
                }
                let projection =
                    cascade_projection(shadow_camera, splits[index], sun, NVR_CASCADE_RESOLUTION)
                        .ok_or_else(direct3d_failure)?;
                unsafe {
                    self.draw_directional_map(
                        device,
                        scene,
                        index,
                        projection,
                        camera.world_transform.translation,
                    )?
                };
                self.cascade_matrices[index] = projection.world_to_shadow;
                self.cascade_origins[index] = camera.world_transform.translation;
                self.cascade_splits[index] = splits[index];
            }
            scheduler.commit(plan);
            if context == InvocationContext::Main {
                *last_scene = Some(scene.kind);
                *last_sun = Some(sun);
            }
            if context == InvocationContext::Main && frustum_changed {
                // Keep the last materially distinct projection as the
                // comparison anchor. Updating this on every sub-pixel jitter
                // would let a slowly changing FOV remain forever inside the
                // per-frame dead band instead of accumulating to a rebuild.
                *last_frustum = Some(frustum);
            }
        }

        // Supplied NVR defaults render exterior point shadows neither by day
        // nor night. OMV preserves that behavior and spends the expensive
        // twelve-cube budget only on the interior branch it replaces.
        if scene.kind == SceneKind::Interior {
            points = unsafe {
                native::select_point_lights(
                    camera.world_transform.translation,
                    shadow_camera.forward,
                )
            };
            unsafe { self.draw_point_maps(device, scene, camera, points.shadowed())? };
        }

        if context != InvocationContext::Main {
            return Ok(None);
        }
        let mut published_points = [PublishedPointLight::default(); NVR_POINT_LIGHT_COUNT];
        for (index, point) in points.shadowed().iter().enumerate() {
            published_points[index] = PublishedPointLight {
                position: point.position,
                color: point.color,
                radius: point.radius,
            };
        }
        let mut unshadowed_points = [PublishedPointLight::default(); NVR_POINT_LIGHT_COUNT];
        for (index, point) in points.unshadowed().iter().enumerate() {
            unshadowed_points[index] = PublishedPointLight {
                position: point.position,
                color: point.color,
                radius: point.radius,
            };
        }
        Ok(Some(PublishedFrame {
            render_epoch: crate::hooks::render_epoch(),
            scene: scene.kind,
            directional,
            sun_direction,
            matrices: self.cascade_matrices,
            matrix_origins: self.cascade_origins,
            splits: self.cascade_splits,
            points: published_points,
            point_count: points.shadowed().len(),
            unshadowed_points,
            unshadowed_point_count: points.unshadowed().len(),
        }))
    }

    unsafe fn draw_directional_map(
        &mut self,
        device: &Device9Ref<'_>,
        scene: NativeScene,
        cascade: usize,
        projection: CascadeProjection,
        camera_translation: [f32; 3],
    ) -> Direct3DResult<()> {
        device.set_render_target(0, &self.directional_workspace)?;
        device.set_depth_stencil_surface(Some(&self.directional_depth))?;
        set_viewport(device, 0, 0, NVR_CASCADE_RESOLUTION, NVR_CASCADE_RESOLUTION)?;
        device.clear_attachments(D3DCLEAR_ZBUFFER as u32 | D3DCLEAR_STENCIL as u32, 0, 1.0, 0)?;
        draw_evsm_far_clear(device, &self.far_clear_pixel)?;
        // The clear helper temporarily detaches depth for its transformed
        // full-screen vertices. Reattach the already-cleared matching MSAA
        // surface before any geometry writes depth.
        device.set_depth_stencil_surface(Some(&self.directional_depth))?;
        render::configure_generation_state(device)?;
        render::begin_directional_map(device, &self.programs, projection.world_to_shadow)?;
        let mut draw_result = Ok(());
        unsafe {
            native::visit_directional_roots(scene, |root, is_land, is_lod| {
                if draw_result.is_ok() {
                    draw_result = render::draw_directional_root(
                        device,
                        scene.renderer,
                        projection,
                        camera_translation,
                        root,
                        is_land,
                        is_lod,
                        &mut self.scratch,
                    );
                }
            });
        }
        draw_result?;
        self.resolve_and_filter_cascade(device, cascade)
    }

    fn resolve_and_filter_cascade(
        &self,
        device: &Device9Ref<'_>,
        cascade: usize,
    ) -> Direct3DResult<()> {
        let (x, y) = cascade_origin(cascade);
        let quadrant = RECT {
            left: x as i32,
            top: y as i32,
            right: (x + NVR_CASCADE_RESOLUTION) as i32,
            bottom: (y + NVR_CASCADE_RESOLUTION) as i32,
        };

        // StretchRect cannot read a surface still bound as RT0. The blur
        // surface is a safe temporary attachment and is overwritten next.
        device.set_depth_stencil_surface(None)?;
        device.set_render_target(0, &self.blur_surface)?;
        device.stretch_rect(
            &self.directional_workspace,
            None,
            &self.atlas_surface,
            Some(&quadrant),
            D3DTEXF_NONE,
        )?;

        bind_fullscreen_state(device)?;
        device.set_pixel_shader(&self.blur_pixel)?;
        device.set_texture(0, &self.atlas)?;
        set_linear_clamp_sampler(device, 0)?;
        device.set_pixel_shader_constant_f(
            0,
            &[
                [1.0, 0.0, 0.0, 0.0],
                [
                    1.0 / ATLAS_RESOLUTION as f32,
                    1.0 / ATLAS_RESOLUTION as f32,
                    0.0,
                    0.0,
                ],
                [
                    0.5,
                    0.5,
                    x as f32 / ATLAS_RESOLUTION as f32,
                    y as f32 / ATLAS_RESOLUTION as f32,
                ],
            ],
        )?;
        set_viewport(device, 0, 0, NVR_CASCADE_RESOLUTION, NVR_CASCADE_RESOLUTION)?;
        draw_quad(device, 0, 0, NVR_CASCADE_RESOLUTION, NVR_CASCADE_RESOLUTION)?;

        // The vertical pass writes back into the atlas quadrant, so the atlas
        // sampler must be removed before that surface becomes writable.
        device.clear_texture(0)?;
        device.set_render_target(0, &self.atlas_surface)?;
        device.set_texture(0, &self.blur)?;
        device.set_pixel_shader_constant_f(
            0,
            &[
                [0.0, 1.0, 0.0, 0.0],
                [
                    1.0 / NVR_CASCADE_RESOLUTION as f32,
                    1.0 / NVR_CASCADE_RESOLUTION as f32,
                    0.0,
                    0.0,
                ],
                [1.0, 1.0, 0.0, 0.0],
            ],
        )?;
        set_viewport(device, x, y, NVR_CASCADE_RESOLUTION, NVR_CASCADE_RESOLUTION)?;
        draw_quad(device, x, y, NVR_CASCADE_RESOLUTION, NVR_CASCADE_RESOLUTION)
    }

    unsafe fn draw_point_maps(
        &mut self,
        device: &Device9Ref<'_>,
        scene: NativeScene,
        camera: CameraFrame,
        points: &PointLightSet,
    ) -> Direct3DResult<()> {
        for (index, point) in points.iter().enumerate() {
            let views = point_cube_views(point.relative_position, point.radius)
                .ok_or_else(direct3d_failure)?;
            for face in 0..6 {
                let surface = self.point_cubes[index].surface(CUBE_FACES[face], 0)?;
                device.set_render_target(0, &surface)?;
                device.set_depth_stencil_surface(Some(&self.point_depth))?;
                set_viewport(device, 0, 0, POINT_CUBE_RESOLUTION, POINT_CUBE_RESOLUTION)?;
                device.clear_attachments(
                    D3DCLEAR_TARGET as u32 | D3DCLEAR_ZBUFFER as u32 | D3DCLEAR_STENCIL as u32,
                    0xFFFF_FFFF,
                    1.0,
                    0,
                )?;
                render::configure_generation_state(device)?;
                render::begin_point_face(
                    device,
                    &self.programs,
                    views[face].world_to_shadow,
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
                                point.relative_position,
                                point.radius,
                                geometry,
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
                                    point.relative_position,
                                    point.radius,
                                    root,
                                    is_land,
                                    is_lod,
                                    &mut self.scratch,
                                );
                            }
                        });
                    }
                }
                draw_result?;
            }
        }
        Ok(())
    }

    unsafe fn consume(
        &mut self,
        device: Device9Ref<'_>,
        source_rendered_texture: *mut c_void,
        publication: PublishedFrame,
    ) -> Direct3DResult<bool> {
        let provider = backend::active_depth_provider();
        let Some(source_ptr) =
            backend::rendered_texture_color_surface(provider, source_rendered_texture)
        else {
            return Ok(false);
        };
        let source = unsafe { Surface9::retain_raw(source_ptr)? };
        let desc = source.desc()?;
        if desc.Width == 0 || desc.Height == 0 {
            return Ok(false);
        }
        let depth = match backend::try_depth_frame(provider, crate::hooks::render_epoch()) {
            DepthAccess::Ready(depth) => depth,
            DepthAccess::Busy => return Ok(false),
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
    ) -> Direct3DResult<()> {
        clear_auxiliary_targets(device)?;
        bind_fullscreen_state(device)?;
        let common = consumer_camera_constants(desc, depth, camera);
        set_viewport(device, 0, 0, desc.Width, desc.Height)?;

        if publication.directional {
            // Modern NVR's custom-quality exterior path includes a short
            // screen-space contact ray. Keep it as a visibility term in the
            // point buffer, then depth-filter through the otherwise unused
            // normals target. No extra full-resolution allocation is needed.
            device.set_render_target(0, &targets.point_surface)?;
            device.set_pixel_shader(&self.contact_pixel)?;
            unsafe { device.set_raw_base_texture(0, depth_texture)? };
            set_point_clamp_sampler(device, 0)?;
            device.set_pixel_shader_constant_f(0, &common[..3])?;
            let view_light_direction = world_to_view_direction(camera, publication.sun_direction);
            device.set_pixel_shader_constant_f(
                6,
                &[
                    [
                        depth.world_projection.reversed_depth_f32(),
                        CONTACT_MAX_DEPTH,
                        CONTACT_RAY_DISTANCE,
                        CONTACT_THICKNESS,
                    ],
                    [
                        view_light_direction[0],
                        view_light_direction[1],
                        view_light_direction[2],
                        0.0,
                    ],
                ],
            )?;
            draw_quad(device, 0, 0, desc.Width, desc.Height)?;

            device.clear_texture(0)?;
            device.set_render_target(0, &targets.normals_surface)?;
            device.set_pixel_shader(&self.contact_blur_pixel)?;
            device.set_texture(0, &targets.point)?;
            unsafe { device.set_raw_base_texture(1, depth_texture)? };
            set_linear_clamp_sampler(device, 0)?;
            set_point_clamp_sampler(device, 1)?;
            device.set_pixel_shader_constant_f(0, &common[..2])?;
            device.set_pixel_shader_constant_f(
                6,
                &[[depth.world_projection.reversed_depth_f32(), 1.0, 0.0, 0.0]],
            )?;
            draw_quad(device, 0, 0, desc.Width, desc.Height)?;

            device.clear_texture(0)?;
            device.set_render_target(0, &targets.point_surface)?;
            device.set_texture(0, &targets.normals)?;
            device.set_pixel_shader_constant_f(
                6,
                &[[depth.world_projection.reversed_depth_f32(), 0.0, 1.0, 0.0]],
            )?;
            draw_quad(device, 0, 0, desc.Width, desc.Height)?;
        } else {
            device.set_render_target(0, &targets.normals_surface)?;
            device.set_pixel_shader(&self.normal_pixel)?;
            unsafe { device.set_raw_base_texture(0, depth_texture)? };
            set_point_clamp_sampler(device, 0)?;
            device.set_pixel_shader_constant_f(0, &common)?;
            draw_quad(device, 0, 0, desc.Width, desc.Height)?;

            device.clear_texture(0)?;
            device.set_render_target(0, &targets.point_surface)?;
            device.clear_attachments(D3DCLEAR_TARGET as u32, 0, 1.0, 0)?;
            if publication.point_count + publication.unshadowed_point_count > 0 {
                device.set_pixel_shader(&self.point_pixel)?;
                unsafe { device.set_raw_base_texture(0, depth_texture)? };
                device.set_texture(7, &targets.normals)?;
                set_point_clamp_sampler(device, 7)?;
                let mut pass_index = 0u32;
                for shadowed in [true, false] {
                    let (lights, light_count) = if shadowed {
                        (&publication.points, publication.point_count)
                    } else {
                        (
                            &publication.unshadowed_points,
                            publication.unshadowed_point_count,
                        )
                    };
                    for batch in 0..2 {
                        let first = batch * 6;
                        if first >= light_count {
                            break;
                        }
                        let count = (light_count - first).min(6);
                        let mut positions = [[0.0; 4]; 6];
                        let mut colors = [[0.0; 4]; 6];
                        for index in 0..count {
                            let light = lights[first + index];
                            let relative: [f32; 3] = std::array::from_fn(|axis| {
                                light.position[axis] - camera.world_transform.translation[axis]
                            });
                            positions[index] =
                                [relative[0], relative[1], relative[2], light.radius];
                            colors[index] = [light.color[0], light.color[1], light.color[2], 1.0];
                            if shadowed {
                                device.set_cube_texture(
                                    (index + 1) as u32,
                                    &self.point_cubes[first + index],
                                )?;
                                set_point_clamp_sampler(device, (index + 1) as u32)?;
                            }
                        }
                        let mut constants = common;
                        constants[6] = [
                            depth.world_projection.reversed_depth_f32(),
                            count as f32,
                            POINT_RECEIVER_BIAS,
                            (!shadowed) as u8 as f32,
                        ];
                        device.set_pixel_shader_constant_f(0, &constants)?;
                        device.set_pixel_shader_constant_f(7, &positions)?;
                        device.set_pixel_shader_constant_f(13, &colors)?;
                        device.set_render_state(D3DRS_ALPHABLENDENABLE, (pass_index > 0) as u32)?;
                        if pass_index > 0 {
                            device.set_render_state(D3DRS_SRCBLEND, D3DBLEND_ONE.0 as u32)?;
                            device.set_render_state(D3DRS_DESTBLEND, D3DBLEND_ONE.0 as u32)?;
                            device.set_render_state(D3DRS_BLENDOP, D3DBLENDOP_ADD.0 as u32)?;
                        }
                        draw_quad(device, 0, 0, desc.Width, desc.Height)?;
                        pass_index += 1;
                    }
                }
                device.set_render_state(D3DRS_ALPHABLENDENABLE, 0)?;
            }
        }

        // Preserve the source before the compositor writes back into it.
        for sampler in 0..=7 {
            device.clear_texture(sampler)?;
        }
        device.stretch_rect(
            source,
            None,
            &targets.scene_copy_surface,
            None,
            D3DTEXF_NONE,
        )?;
        device.set_render_target(0, source)?;
        device.set_pixel_shader(&self.composite_pixel)?;
        device.set_texture(0, &targets.scene_copy)?;
        unsafe { device.set_raw_base_texture(1, depth_texture)? };
        device.set_texture(2, &self.atlas)?;
        device.set_texture(3, &targets.point)?;
        for sampler in 0..=3 {
            set_linear_clamp_sampler(device, sampler)?;
        }

        let mut matrices = publication.matrices;
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
        device.set_pixel_shader_constant_f(
            22,
            &[
                splits,
                [
                    depth.world_projection.reversed_depth_f32(),
                    publication.directional as u8 as f32,
                    if publication.directional {
                        EXTERIOR_SHADOW_DARKNESS
                    } else {
                        INTERIOR_SHADOW_DARKNESS
                    },
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
                    0.0,
                    0.0,
                ],
            ],
        )?;
        draw_quad(device, 0, 0, desc.Width, desc.Height)
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
    normals: Texture9,
    normals_surface: Surface9,
    point: Texture9,
    point_surface: Surface9,
    scene_copy: Texture9,
    scene_copy_surface: Surface9,
}

impl ConsumerTargets {
    fn create(device: &Device9Ref<'_>, desc: &D3DSURFACE_DESC) -> Direct3DResult<Self> {
        let normals =
            device.create_render_target_texture(desc.Width, desc.Height, D3DFMT_A16B16G16R16F)?;
        let point = device.create_render_target_texture(desc.Width, desc.Height, D3DFMT_G16R16F)?;
        let scene_copy =
            device.create_render_target_texture(desc.Width, desc.Height, desc.Format)?;
        Ok(Self {
            width: desc.Width,
            height: desc.Height,
            format: desc.Format,
            normals_surface: normals.surface_level(0)?,
            point_surface: point.surface_level(0)?,
            scene_copy_surface: scene_copy.surface_level(0)?,
            normals,
            point,
            scene_copy,
        })
    }

    fn matches(&self, desc: &D3DSURFACE_DESC) -> bool {
        self.width == desc.Width && self.height == desc.Height && self.format == desc.Format
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

fn world_to_view_direction(camera: CameraFrame, direction: [f32; 3]) -> [f32; 3] {
    let rotation = camera.world_transform.rotation;
    let right = [rotation[0][2], rotation[1][2], rotation[2][2]];
    let up = [rotation[0][1], rotation[1][1], rotation[2][1]];
    let forward = [rotation[0][0], rotation[1][0], rotation[2][0]];
    [
        dot3(direction, right),
        dot3(direction, up),
        dot3(direction, forward),
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

fn draw_evsm_far_clear(device: &Device9Ref<'_>, shader: &PixelShader9) -> Direct3DResult<()> {
    bind_fullscreen_state(device)?;
    device.set_pixel_shader(shader)?;
    let moments = evsm4_moments(1.0, true).ok_or_else(direct3d_failure)?;
    device.set_pixel_shader_constant_f(0, &[moments])?;
    draw_quad(device, 0, 0, NVR_CASCADE_RESOLUTION, NVR_CASCADE_RESOLUTION)
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
    device.set_render_state(D3DRS_SCISSORTESTENABLE, 0)?;
    device.set_render_state(D3DRS_SRGBWRITEENABLE, 0)
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
    device.set_sampler_state(sampler, D3DSAMP_MIPFILTER, D3DTEXF_NONE.0 as u32)
}

fn set_point_clamp_sampler(device: &Device9Ref<'_>, sampler: u32) -> Direct3DResult<()> {
    device.set_sampler_state(sampler, D3DSAMP_ADDRESSU, D3DTADDRESS_CLAMP.0 as u32)?;
    device.set_sampler_state(sampler, D3DSAMP_ADDRESSV, D3DTADDRESS_CLAMP.0 as u32)?;
    device.set_sampler_state(sampler, D3DSAMP_MINFILTER, D3DTEXF_POINT.0 as u32)?;
    device.set_sampler_state(sampler, D3DSAMP_MAGFILTER, D3DTEXF_POINT.0 as u32)?;
    device.set_sampler_state(sampler, D3DSAMP_MIPFILTER, D3DTEXF_NONE.0 as u32)
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
    use super::{projection_materially_changed, translate_shadow_matrix, world_to_view_direction};
    use crate::backend::{CameraFrame, CameraTransformFrame};

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
    fn contact_ray_converts_world_sun_into_fnv_view_axes() {
        let camera = CameraFrame {
            world_transform: CameraTransformFrame {
                rotation: [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
                scale: 1.0,
                available: true,
                ..CameraTransformFrame::default()
            },
            available: true,
            ..CameraFrame::default()
        };
        // FNV's identity camera faces world +X, with view +X mapped to world
        // +Z (right), view +Y to world +Y, and view +Z to world +X.
        assert_eq!(
            world_to_view_direction(camera, [1.0, 0.0, 0.0]),
            [0.0, 0.0, 1.0]
        );
        assert_eq!(
            world_to_view_direction(camera, [0.0, 1.0, 0.0]),
            [0.0, 1.0, 0.0]
        );
        assert_eq!(
            world_to_view_direction(camera, [0.0, 0.0, 1.0]),
            [1.0, 0.0, 0.0]
        );
    }
}
