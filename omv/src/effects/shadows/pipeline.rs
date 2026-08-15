//! Transactional D3D9 producer and pre-alpha shadow consumer.
//!
//! All default-pool resources are owned here and are released as one device
//! generation. The common engine hook only publishes a frame after every map,
//! scene boundary, and state restoration succeeds. The pre-alpha consumer is
//! nonblocking and accepts the current or immediately preceding presentation.
//! An exact world context binds the later color/depth receiver, but map
//! production precedes that context in the native engine transaction.

use core::{cell::Cell, ffi::c_void};
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
    D3DSAMP_SRGBTEXTURE, D3DSURFACE_DESC, D3DTADDRESS_CLAMP, D3DTEXF_LINEAR, D3DTEXF_NONE,
    D3DTEXF_POINT, D3DVIEWPORT9, Device9Ref, Direct3DResult, PixelShader9, RECT, ScreenVertex,
    ShadowConsumerState9, ShadowProducerState9, Surface9, Texture9, direct3d_failure,
};

use crate::{
    backend::{
        self, CameraFrame, DepthFrame, DepthResolveOutcome, DepthResolveSlot, DepthResolveStage,
    },
    render_state::{
        RenderAttachments, RenderTargetSlots, capture_exact_render_state,
        finish_exact_render_transaction,
    },
};

use super::{
    NativeShadowsSettings,
    contract::{
        CASCADE_COUNT, CascadeDirty, CascadeScheduler, CascadeSplit, ClipmapRect, ClipmapScroll,
        DirectionalRootSetSignature, MAX_CLIPMAP_STRIP_WIDTH, NVR_CASCADE_RESOLUTION,
        NVR_POINT_LIGHT_COUNT, POINT_CONSUMER_BATCH_SIZE, PointMapCache, PointMapPlan,
        PointMapSignature, SceneKind, ShadowMapUpdate, ShadowPublicationIdentity, SunCompetition,
        cascade_minimum_caster_radius, clipmap_texel_delta, consumer_has_shadow_work,
        directional_caster_work, directional_root_set_dirty, effective_contact_distance,
        evsm4_moments, local_light_clear_coverage, nvr_contact_sample_offsets, point_consumer_plan,
        point_light_scissor, practical_cascade_splits, publication_epoch_is_usable,
        publication_identity_is_usable, retained_cascade_refresh,
    },
    math::{
        CascadeProjection, ShadowCamera, cascade_projection, point_cube_views,
        stabilize_sun_direction,
    },
    native::{
        self, DIRECTIONAL_ROOT_CACHE_CAPACITY, DirectionalRoot, NativeScene,
        POINT_ACTOR_BOUND_CACHE_CAPACITY, PointLightSet,
    },
    render::{self, CasterSubset, GenerationPrograms, TraversalScratch},
    shaders::ShadowBytecode,
};

const ATLAS_RESOLUTION: u32 = NVR_CASCADE_RESOLUTION * 2;
const ACTOR_MAP_RESOLUTION: u32 = NVR_CASCADE_RESOLUTION / 2;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShadowProductionStage {
    Idle,
    CaptureState,
    BeginScene,
    BeginNativeJournal,
    DirectionalInputs,
    StaticCascade(u8),
    ActorBounds(u8),
    ActorOverlay(u8),
    PointMaps,
    RestoreNativeJournal,
    EndScene,
    RestoreD3dState,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ActiveWorldContext {
    transaction: u64,
    render_epoch: u32,
    color_surface: usize,
    depth_surface: usize,
    rendered_texture: usize,
    device_generation: u32,
    generation_camera: CameraFrame,
    depth_camera: CameraFrame,
}

impl ActiveWorldContext {
    fn identity(self, scene: SceneKind, invocation: u8) -> ShadowPublicationIdentity {
        ShadowPublicationIdentity {
            render_epoch: self.render_epoch,
            transaction: self.transaction,
            scene,
            invocation,
            color_surface: self.color_surface,
            depth_surface: self.depth_surface,
            device_generation: self.device_generation,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct WorldContextGuard {
    transaction: u64,
    previous: Option<ActiveWorldContext>,
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
    identity: ShadowPublicationIdentity,
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
    /// Same-epoch native sunlight used only by dynamic-only exterior composition.
    sun_competition: SunCompetition,
}

/// Capture weather/time sunlight only for the dynamic-only exterior branch.
///
/// The snapshot is copied into the immutable publication beside the point maps;
/// the later pre-alpha consumer must not dereference a newer Sky object or mix
/// different weather epochs. Missing native data is deliberately neutral rather
/// than a reason to discard valid point maps: zero competition is the accepted
/// nighttime/interior equation.
fn capture_sun_competition(
    scene: SceneKind,
    directional: bool,
    point_lights: bool,
) -> SunCompetition {
    if scene == SceneKind::Interior || directional || !point_lights {
        return SunCompetition::default();
    }
    let Some(sky) = backend::native_sky_frame().filter(|sky| sky.is_exterior) else {
        return SunCompetition::default();
    };
    SunCompetition::from_native(sky.sun_direction, sky.sun_light, sky.daylight).unwrap_or_default()
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
    next_world_transaction: u64,
    active_world_context: Option<ActiveWorldContext>,
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
            next_world_transaction: 0,
            active_world_context: None,
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

    #[allow(clippy::too_many_arguments)]
    pub(super) fn begin_world_context(
        &mut self,
        color_surface: usize,
        depth_surface: usize,
        rendered_texture: usize,
        generation_camera: CameraFrame,
        depth_camera: CameraFrame,
    ) -> WorldContextGuard {
        self.next_world_transaction = self.next_world_transaction.wrapping_add(1).max(1);
        let transaction = self.next_world_transaction;
        let previous = self.active_world_context;
        self.active_world_context = Some(ActiveWorldContext {
            transaction,
            render_epoch: crate::hooks::render_epoch(),
            color_surface,
            depth_surface,
            rendered_texture,
            device_generation: backend::d3d_device_generation(),
            generation_camera,
            depth_camera,
        });
        WorldContextGuard {
            transaction,
            previous,
        }
    }

    pub(super) fn end_world_context(&mut self, guard: WorldContextGuard) {
        if self
            .active_world_context
            .is_some_and(|context| context.transaction == guard.transaction)
        {
            self.active_world_context = guard.previous;
        }
    }

    /// Build producer metadata without requiring the later world destination.
    pub(super) fn current_publication_identity(
        &self,
        scene: SceneKind,
        invocation: u8,
    ) -> Option<ShadowPublicationIdentity> {
        Some(self.active_world_context.map_or(
            ShadowPublicationIdentity {
                render_epoch: crate::hooks::render_epoch(),
                transaction: 0,
                scene,
                invocation,
                color_surface: 0,
                depth_surface: 0,
                device_generation: backend::d3d_device_generation(),
            },
            |context| context.identity(scene, invocation),
        ))
    }

    /// Invalidate consumer publication without discarding expensive resources.
    pub(super) fn invalidate_publication(&mut self) {
        self.published = None;
    }

    /// Return whether this render epoch already owns a complete publication.
    pub(super) fn has_current_publication(&self, identity: ShadowPublicationIdentity) -> bool {
        self.published.is_some_and(|publication| {
            publication.identity.render_epoch == identity.render_epoch
                && publication.scene == identity.scene
                && publication.identity.device_generation == identity.device_generation
        })
    }

    /// Return the stabilized directional vector paired with the live atlas.
    pub(super) fn directional_sun_direction(&self) -> Option<[f32; 3]> {
        let publication = self.published?;
        (publication.directional
            && publication_epoch_is_usable(
                publication.identity.render_epoch,
                crate::hooks::render_epoch(),
            ))
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
        identity: ShadowPublicationIdentity,
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
        let live_camera = unsafe { backend::fnv_world_camera_frame_fast(1, 1) };
        let context_camera = self
            .active_world_context
            .map(|context| context.generation_camera);
        let temporal_camera =
            live_camera.and_then(crate::fnv_world_pipeline::shadow_generation_camera);
        let Some(camera) = temporal_camera
            .or(live_camera)
            .or(context_camera)
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

        let directional = settings.directional_enabled_for(scene.kind);
        let point_lights = settings.point_enabled_for(scene.kind);
        let Some(resources) = self.resources.as_mut() else {
            let error = direct3d_failure();
            self.log_error("shared shadow resources disappeared", &error);
            return ReplacementResult::FallbackNative;
        };
        let branch_result =
            resources.ensure_branch(&device, directional, point_lights, generation, settings);
        let transition = match branch_result {
            Ok(transition) => transition,
            Err(_) => return ReplacementResult::FallbackNative,
        };
        if transition.point_resources_replaced {
            // Map metadata is meaningful only for the cube family that
            // produced it. Force every admitted face to rebuild before a new
            // publication can sample the replacement resolution.
            self.published = None;
            self.point_cache = PointMapCache::default();
            self.point_cell_identity = 0;
        }
        // Build the no-work transcript before capturing a render target,
        // state block, scene pair, or native renderer journal. Re-publishing
        // immutable maps for a new epoch is a CPU metadata operation; making
        // it enter D3D was a measurable fixed cost even in an empty room.
        if self.last_dynamic_cascade_mask == 0
            && !self.point_cache.has_dynamic_casters()
            && let Some(publication) = unsafe {
                self.try_republish_without_d3d(identity, scene, camera, shadow_camera, settings)
            }
        {
            self.published = Some(publication);
            return ReplacementResult::Produced;
        }
        // Texture writes become visible immediately. Remove the publication
        // before touching them so a later failure cannot expose a partly
        // updated atlas or cube family to pre-alpha composition.
        self.published = None;
        let result =
            self.produce_transaction(&device, identity, scene, camera, shadow_camera, settings);
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
                let stage = self
                    .resources
                    .as_ref()
                    .map_or(ShadowProductionStage::Idle, |resources| {
                        resources.production_stage
                    });
                self.log_error_at_stage(
                    "shadow production failed and fell back to native shadows",
                    stage,
                    &error,
                );
                ReplacementResult::FallbackNative
            }
        }
    }

    /// Publish a proven unchanged map family without entering D3D.
    ///
    /// This intentionally repeats the bounded native input snapshot used by
    /// the rendering planner. Returning `None` is conservative and delegates
    /// to the ordinary transactional path. Returning `Some` requires exact
    /// equality of every static signature, no current or abandoned animated
    /// footprint, no cascade refresh, and a point plan containing zero faces.
    ///
    /// # Safety
    ///
    /// `scene` and all pointers discovered from it must remain live through
    /// this serialized common-shadow invocation.
    unsafe fn try_republish_without_d3d(
        &mut self,
        identity: ShadowPublicationIdentity,
        scene: NativeScene,
        camera: CameraFrame,
        shadow_camera: ShadowCamera,
        settings: NativeShadowsSettings,
    ) -> Option<PublishedFrame> {
        let directional = settings.directional_enabled_for(scene.kind);
        let point_lights = settings.point_enabled_for(scene.kind);
        if self.last_scene != Some(scene.kind) {
            return None;
        }
        let (
            cascade_projections,
            cascade_spheres,
            cascade_origins,
            cascade_suns,
            cascade_sun,
            cascade_matrices,
            actor_crops,
            cascade_splits,
        ) = {
            let resources = self.resources.as_ref()?;
            (
                resources.cascade_projections,
                resources.cascade_spheres,
                resources.cascade_origins,
                resources.cascade_suns,
                resources.cascade_sun,
                resources.cascade_matrices,
                resources.actor_crops,
                resources.cascade_splits,
            )
        };

        let directional_inputs = if directional {
            let sky = backend::native_sky_frame()?;
            let sun = stabilize_sun_direction(self.last_sun, sky.sun_direction)?;
            let frustum = camera_signature(camera);
            if self
                .last_frustum
                .is_none_or(|previous| projection_materially_changed(previous, frustum))
                || self.last_directional_profile
                    != Some([settings.exterior_distance, settings.cascade_split_lambda])
                || cascade_projections.iter().any(Option::is_none)
            {
                return None;
            }
            let splits = practical_cascade_splits(
                camera.near_z,
                camera.far_z,
                settings.exterior_distance,
                settings.cascade_split_lambda,
            )?;
            for (index, split) in splits.into_iter().enumerate() {
                let current =
                    cascade_projection(shadow_camera, split, sun, NVR_CASCADE_RESOLUTION)?;
                let stored = cascade_spheres[index];
                let stored_absolute =
                    std::array::from_fn(|axis| cascade_origins[index][axis] + stored[axis]);
                let current_absolute = std::array::from_fn(|axis| {
                    camera.world_transform.translation[axis] + current.center[axis]
                });
                let refresh = retained_cascade_refresh(
                    stored_absolute,
                    stored[3],
                    current_absolute,
                    current.receiver_radius,
                    cascade_suns[index],
                    sun,
                    NVR_CASCADE_RESOLUTION,
                );
                if refresh.mandatory || refresh.quality {
                    return None;
                }
            }
            Some((sun, splits))
        } else {
            None
        };

        let retained_identities = if self.point_cell_identity == scene.cell as usize {
            self.point_cache.identities()
        } else {
            [0; NVR_POINT_LIGHT_COUNT]
        };
        let points = if point_lights {
            unsafe {
                native::select_point_lights(
                    camera.world_transform.translation,
                    shadow_camera.forward,
                    retained_identities,
                    settings.interior_shadowed_lights,
                    settings.interior_light_radius_multiplier,
                    settings.interior_light_draw_distance,
                )
            }
        } else {
            native::PointLightSelection::default()
        };
        // The complete root vector is borrowed only inside this serialized
        // scope and is restored on every outcome. It replaces up to twelve
        // independent native light-geometry walks in the no-work path.
        let (mut roots, mut actor_bounds, mut actor_roots) = {
            let resources = self.resources.as_mut()?;
            (
                core::mem::take(&mut resources.directional_roots),
                core::mem::take(&mut resources.point_actor_bounds),
                core::mem::take(&mut resources.point_actor_roots),
            )
        };
        let has_points = points.shadowed().len() != 0;
        let needs_roots = directional || has_points;
        let roots_complete =
            !needs_roots || unsafe { native::collect_directional_roots(scene, &mut roots) };
        let actor_bounds_complete = !has_points
            || (roots_complete
                && unsafe {
                    native::collect_point_actor_bounds(
                        roots.as_slice(),
                        &mut actor_bounds,
                        &mut actor_roots,
                    )
                });
        let directional_signatures =
            directional_inputs.map(|_| native::directional_root_set_signatures(roots.as_slice()));
        let dynamic_mask = directional_inputs.map(|(_, splits)| unsafe {
            native::directional_dynamic_cascade_mask(
                roots.as_slice(),
                splits,
                shadow_camera.forward,
                camera.world_transform.translation,
            )
        });
        let mut signatures = [PointMapSignature::EMPTY; NVR_POINT_LIGHT_COUNT];
        let mut dynamic_faces = [0_u8; NVR_POINT_LIGHT_COUNT];
        for (index, point) in points.shadowed().iter().enumerate() {
            if !roots_complete {
                continue;
            }
            let static_signature = native::point_scene_static_signature(
                roots.as_slice(),
                point.position,
                point.radius,
            );
            signatures[index] = PointMapSignature {
                identity: point.identity,
                position: point.position,
                radius: point.radius,
                caster_signature: static_signature,
            };
            dynamic_faces[index] = if actor_bounds_complete {
                native::point_light_dynamic_faces_from_bounds(
                    actor_bounds.as_slice(),
                    point.position,
                )
            } else {
                super::contract::ALL_CUBE_FACES
            };
        }
        roots.clear();
        actor_bounds.clear();
        actor_roots.clear();
        // `resources` was present when all allocations were taken and this
        // method never replaces it. Use an invariant assertion instead of an
        // optional exit: every ordinary return after the native snapshot must
        // first return all reusable allocations and discard their pointers.
        let resources = self
            .resources
            .as_mut()
            .expect("shadow resources remain owned throughout no-work planning");
        resources.directional_roots = roots;
        resources.point_actor_bounds = actor_bounds;
        resources.point_actor_roots = actor_roots;
        let directional_changed = directional_no_work_state_changed(
            directional,
            directional_root_set_dirty(self.last_directional_roots, directional_signatures),
            self.last_dynamic_cascade_mask,
            dynamic_mask,
        );
        if !roots_complete || !actor_bounds_complete || directional_changed {
            return None;
        }
        let active_cache = if self.point_cell_identity == scene.cell as usize {
            self.point_cache
        } else {
            PointMapCache::default()
        };
        let point_plan = active_cache.plan(signatures, dynamic_faces, points.shadowed().len());
        if point_plan.render_faces.into_iter().any(|faces| faces != 0) {
            return None;
        }

        let mut published_points = [PublishedPointLight::default(); NVR_POINT_LIGHT_COUNT];
        for (slot, published) in published_points
            .iter_mut()
            .enumerate()
            .take(points.shadowed().len())
        {
            let source = point_plan.source_index(slot)?;
            let point = points.shadowed().get(source)?;
            let map = point_plan.published[slot];
            *published = PublishedPointLight {
                position: map.position,
                color: point.color,
                radius: map.radius,
                shadow_fade: point.shadow_fade,
            };
        }
        self.point_cache = point_plan.next;
        self.point_cell_identity = scene.cell as usize;
        self.last_scene = Some(scene.kind);
        if let Some((sun, _)) = directional_inputs {
            self.last_sun = Some(sun);
            self.last_dynamic_cascade_mask = 0;
            self.last_directional_roots = directional_signatures;
        }
        let sun_competition = capture_sun_competition(scene.kind, directional, point_lights);
        Some(PublishedFrame {
            identity,
            scene: scene.kind,
            directional,
            sun_direction: cascade_sun,
            matrices: cascade_matrices,
            matrix_origins: cascade_origins,
            actor_crops,
            actor_overlay_mask: 0,
            splits: cascade_splits,
            points: published_points,
            point_count: points.shadowed().len(),
            sun_competition,
        })
    }

    fn produce_transaction(
        &mut self,
        device: &Device9Ref<'_>,
        identity: ShadowPublicationIdentity,
        scene: NativeScene,
        camera: CameraFrame,
        shadow_camera: ShadowCamera,
        settings: NativeShadowsSettings,
    ) -> Direct3DResult<Option<PublishedFrame>> {
        let slots = RenderTargetSlots::from_reported_count(
            self.resources
                .as_ref()
                .ok_or_else(direct3d_failure)?
                .render_target_count,
        );
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
        resources.production_stage = ShadowProductionStage::CaptureState;
        let d3d_state = capture_exact_render_state(|| ShadowProducerState9::capture(device))?;

        resources.production_stage = ShadowProductionStage::BeginScene;
        let begin_result = device.begin_scene();
        if let Err(error) = begin_result {
            return finish_exact_render_transaction(device, &attachments, Err(error), || {
                d3d_state.restore(device)
            })
            .map(|()| None);
        }

        resources.production_stage = ShadowProductionStage::BeginNativeJournal;
        if let Err(error) = unsafe { resources.scratch.begin_native_state_journal(scene.renderer) }
        {
            let mut result = Err(error);
            if let Err(end_error) = device.end_scene()
                && result.is_ok()
            {
                result = Err(end_error);
            }
            return finish_exact_render_transaction(device, &attachments, result, || {
                d3d_state.restore(device)
            })
            .map(|()| None);
        }

        let draw_result = unsafe {
            resources.draw_maps(
                device,
                identity,
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
        resources.production_stage = ShadowProductionStage::RestoreNativeJournal;
        if let Err(error) = unsafe { resources.scratch.restore_native_state_journal() }
            && result.is_ok()
        {
            result = Err(error);
        }
        resources.production_stage = ShadowProductionStage::EndScene;
        if let Err(error) = device.end_scene()
            && result.is_ok()
        {
            result = Err(error);
        }
        let publication = result.as_ref().ok().copied().flatten();
        resources.production_stage = ShadowProductionStage::RestoreD3dState;
        finish_exact_render_transaction(device, &attachments, result.map(|_| ()), || {
            d3d_state.restore(device)
        })?;
        self.scheduler = scheduler;
        self.last_scene = last_scene;
        self.last_sun = last_sun;
        self.last_frustum = last_frustum;
        self.last_directional_profile = last_directional_profile;
        self.last_dynamic_cascade_mask = last_dynamic_cascade_mask;
        self.last_directional_roots = last_directional_roots;
        self.point_cache = point_cache;
        self.point_cell_identity = point_cell_identity;
        if let Some(resources) = self.resources.as_mut() {
            resources.production_stage = ShadowProductionStage::Idle;
        }
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
        let Some(context) = self.active_world_context else {
            return Ok(false);
        };
        let Some(publication) = self.published else {
            return Ok(false);
        };
        if !publication_epoch_is_usable(
            publication.identity.render_epoch,
            crate::hooks::render_epoch(),
        ) {
            self.published = None;
            return Ok(false);
        }
        if publication.identity.transaction != 0 {
            let expected = context.identity(publication.scene, publication.identity.invocation);
            if !publication_identity_is_usable(publication.identity, expected) {
                self.published = None;
                return Ok(false);
            }
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
        let composed = unsafe { resources.consume(device, context, publication, settings)? };
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

    fn log_error_at_stage(
        &mut self,
        message: &'static str,
        stage: ShadowProductionStage,
        error: &impl core::fmt::Display,
    ) {
        if self.error_logs < MAX_ERROR_LOGS {
            log::warn!("[SHADOWS] {message} at {stage:?}: {error}");
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

/// Reject retained directional publication only when the current branch owns
/// directional maps. Interior point-only frames deliberately keep exterior
/// signatures dormant; comparing `Some(exterior)` with `None(interior)` would
/// otherwise force a complete D3D transaction in every static interior.
fn directional_no_work_state_changed(
    directional: bool,
    root_dirty: CascadeDirty,
    previous_dynamic_mask: u8,
    current_dynamic_mask: Option<u8>,
) -> bool {
    directional
        && (root_dirty != CascadeDirty::none()
            || previous_dynamic_mask != 0
            || current_dynamic_mask.is_none_or(|mask| mask != 0))
}

struct ShadowResources {
    device_identity: usize,
    render_target_count: u32,
    programs: GenerationPrograms,
    far_clear_pixel: PixelShader9,
    point_pixel_one: PixelShader9,
    point_pixel_six: PixelShader9,
    point_pixel_twelve: PixelShader9,
    contact_pixel: PixelShader9,
    composite_pixel: PixelShader9,
    point_only_composite_pixel: PixelShader9,
    exterior_point_only_composite_pixel: PixelShader9,
    directional_composite_pixel: PixelShader9,
    directional: Option<DirectionalResources>,
    points: Option<PointResources>,
    directional_failure_generation: Option<u32>,
    point_failure: Option<PointResourceFailure>,
    consumer: Option<ConsumerTargets>,
    scratch: TraversalScratch,
    directional_roots: Vec<DirectionalRoot>,
    point_actor_bounds: Vec<[f32; 4]>,
    point_actor_roots: Vec<DirectionalRoot>,
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
    production_stage: ShadowProductionStage,
}

/// Exact failed point-resource request retained until its inputs change.
///
/// A resolution switch can fail because the driver cannot satisfy the peak
/// allocation while the last-good family remains live. Remembering the full
/// request prevents a render-hook allocation storm, while including capacity
/// permits a cheaper retry after the user lowers the light budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PointResourceFailure {
    device_generation: u32,
    resolution: u32,
    capacity: usize,
}

/// Successful lazy branch changes which invalidate retained producer maps.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct BranchTransition {
    point_resources_replaced: bool,
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
    /// Bounded multisample targets used to regenerate only exposed clipmap
    /// rows or columns. Their fixed 64-texel minor axis is the executable
    /// producer budget; larger motion falls back to a complete scratch map.
    horizontal_strip: DirectionalStripResources,
    vertical_strip: DirectionalStripResources,
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

/// One fixed-size multisampled directional strip and its exact resolve.
struct DirectionalStripResources {
    generation_surface: Surface9,
    _moments: Texture9,
    moments_surface: Surface9,
    depth: Surface9,
    width: u32,
    height: u32,
}

/// Borrowed actor-only point-caster index for one serialized transaction.
struct PointActorIndex<'a> {
    roots: &'a [DirectionalRoot],
    /// False selects the complete native light-list fallback.
    complete: bool,
}

impl DirectionalStripResources {
    fn create(device: &Device9Ref<'_>, width: u32, height: u32) -> Direct3DResult<Self> {
        let generation_surface = device.create_render_target_surface(
            width,
            height,
            D3DFMT_A16B16G16R16F,
            D3DMULTISAMPLE_4_SAMPLES,
            0,
            false,
        )?;
        let moments = device.create_render_target_texture(width, height, D3DFMT_A16B16G16R16F)?;
        let moments_surface = moments.surface_level(0)?;
        let depth = device.create_depth_stencil_surface(
            width,
            height,
            D3DFMT_D24S8,
            D3DMULTISAMPLE_4_SAMPLES,
            0,
            true,
        )?;
        Ok(Self {
            generation_surface,
            _moments: moments,
            moments_surface,
            depth,
            width,
            height,
        })
    }
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
        let horizontal_strip = DirectionalStripResources::create(
            device,
            NVR_CASCADE_RESOLUTION,
            MAX_CLIPMAP_STRIP_WIDTH,
        )?;
        let vertical_strip = DirectionalStripResources::create(
            device,
            MAX_CLIPMAP_STRIP_WIDTH,
            NVR_CASCADE_RESOLUTION,
        )?;
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
            horizontal_strip,
            vertical_strip,
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
    /// Square face dimension shared by both cube families and depth.
    resolution: u32,
}

impl PointResources {
    /// Create a complete point family without exposing partial allocations.
    ///
    /// The caller retains the old family until this returns `Ok`, so COM
    /// resources accumulated in either local vector are released naturally on
    /// every early error and the render path can continue with its last-good
    /// profile after the user selects that profile again.
    fn create(device: &Device9Ref<'_>, count: usize, resolution: u32) -> Direct3DResult<Self> {
        let mut point_cubes = Vec::with_capacity(count);
        let mut static_cubes = Vec::with_capacity(count);
        for _ in 0..count {
            point_cubes.push(device.create_cube_render_target_texture(resolution, D3DFMT_R32F)?);
            static_cubes.push(device.create_cube_render_target_texture(resolution, D3DFMT_R32F)?);
        }
        let point_depth = device.create_depth_stencil_surface(
            resolution,
            resolution,
            D3DFMT_D24S8,
            D3DMULTISAMPLE_NONE,
            0,
            true,
        )?;
        Ok(Self {
            point_cubes,
            static_cubes,
            point_depth,
            resolution,
        })
    }

    /// Return whether this family can satisfy a request without reallocating.
    fn supports(&self, capacity: usize, resolution: u32) -> bool {
        self.resolution == resolution && self.point_cubes.len() >= capacity
    }
}

impl ShadowResources {
    fn create(device: &Device9Ref<'_>, bytecode: &ShadowBytecode) -> Direct3DResult<Self> {
        let render_target_count = device.simultaneous_render_target_count()?.min(4);
        Ok(Self {
            device_identity: device.as_raw() as usize,
            render_target_count,
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
            composite_pixel: device.create_pixel_shader(&bytecode.composite)?,
            point_only_composite_pixel: device
                .create_pixel_shader(&bytecode.point_only_composite)?,
            exterior_point_only_composite_pixel: device
                .create_pixel_shader(&bytecode.exterior_point_only_composite)?,
            directional_composite_pixel: device
                .create_pixel_shader(&bytecode.directional_composite)?,
            directional: None,
            points: None,
            directional_failure_generation: None,
            point_failure: None,
            consumer: None,
            scratch: TraversalScratch::with_capacity(),
            directional_roots: Vec::with_capacity(DIRECTIONAL_ROOT_CACHE_CAPACITY),
            point_actor_bounds: Vec::with_capacity(POINT_ACTOR_BOUND_CACHE_CAPACITY),
            point_actor_roots: Vec::with_capacity(POINT_ACTOR_BOUND_CACHE_CAPACITY),
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
            production_stage: ShadowProductionStage::Idle,
        })
    }

    fn ensure_branch(
        &mut self,
        device: &Device9Ref<'_>,
        directional: bool,
        point_lights: bool,
        generation: u32,
        settings: NativeShadowsSettings,
    ) -> Direct3DResult<BranchTransition> {
        let mut transition = BranchTransition::default();
        if point_lights {
            let requested = settings
                .interior_shadowed_lights
                .clamp(1, NVR_POINT_LIGHT_COUNT);
            let resolution = settings.dynamic_shadow_quality.cube_resolution();
            let has_matching_resources = self
                .points
                .as_ref()
                .is_some_and(|points| points.supports(requested, resolution));
            let failure = PointResourceFailure {
                device_generation: generation,
                resolution,
                capacity: requested,
            };
            if has_matching_resources {
                // Moving to a working profile is also an explicit retry
                // boundary. If the user later selects a formerly failed tier,
                // make one fresh attempt instead of poisoning it forever.
                self.point_failure = None;
            } else {
                if self.point_failure == Some(failure) {
                    return Err(direct3d_failure());
                }
                match PointResources::create(device, requested, resolution) {
                    Ok(points) => {
                        log::info!(
                            "[SHADOWS] Local-light resources ready ({} x {} cube maps)",
                            requested,
                            resolution
                        );
                        // Assignment is the commit point: until every cube and
                        // the matching depth surface exists, `self.points`
                        // continues to own the last-good resource family.
                        self.points = Some(points);
                        self.point_failure = None;
                        transition.point_resources_replaced = true;
                    }
                    Err(error) => {
                        self.point_failure = Some(failure);
                        log::warn!(
                            "[SHADOWS] Could not create requested local-light resources (lights={}, cube_resolution={}, device_generation={}): {}",
                            requested,
                            resolution,
                            generation,
                            error
                        );
                        return Err(error);
                    }
                }
            }
        }
        if directional {
            if self.directional_failure_generation == Some(generation) {
                return Err(direct3d_failure());
            }
            if self.directional.is_none() {
                match DirectionalResources::create(device) {
                    Ok(directional) => {
                        log::info!(
                            "[SHADOWS] Experimental sun resources ready ({} x {} EVSM4 cascades, {}x sampling)",
                            CASCADE_COUNT,
                            NVR_CASCADE_RESOLUTION,
                            directional.samples
                        );
                        self.directional = Some(directional);
                    }
                    Err(error) => {
                        self.directional_failure_generation = Some(generation);
                        log::warn!(
                            "[SHADOWS] Could not create experimental sun resources for device generation {}: {}",
                            generation,
                            error
                        );
                        return Err(error);
                    }
                }
            }
        }
        Ok(transition)
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn draw_maps(
        &mut self,
        device: &Device9Ref<'_>,
        identity: ShadowPublicationIdentity,
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
        clear_auxiliary_targets(device, self.render_target_count)?;
        let directional = settings.directional_enabled_for(scene.kind);
        let point_lights = settings.point_enabled_for(scene.kind);
        let sun_competition = capture_sun_competition(scene.kind, directional, point_lights);
        let mut actor_overlay_mask = 0_u8;
        // One cell/root snapshot owns static invalidation, directional actor
        // overlays, and point-light actor coverage. Rewalking every selected
        // light's potentially 8,192-entry geometry list was the dominant CPU
        // cost in light-heavy exteriors and interiors.
        let mut directional_roots = core::mem::take(&mut self.directional_roots);
        let mut roots_complete = false;
        if directional {
            self.production_stage = ShadowProductionStage::DirectionalInputs;
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
            roots_complete =
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
            let mut plan =
                scheduler.plan_refreshes_at_millis(mandatory_dirty, quality_dirty, now_millis);
            // Cell and reference lists are identical for every due cascade.
            // Apply each map's form profile from the scalar metadata gathered
            // above. A capacity overflow uses the complete visitor below; it
            // never drops casters or allocates in this render transaction.
            let render_result = (|| -> Direct3DResult<()> {
                for index in 0..CASCADE_COUNT {
                    if plan.render[index] {
                        self.production_stage = ShadowProductionStage::StaticCascade(index as u8);
                        let requested_projection = projections[index];
                        let minimum_radius = cascade_minimum_caster_radius(
                            index,
                            requested_projection.radius,
                            NVR_CASCADE_RESOLUTION,
                        )
                        .ok_or_else(direct3d_failure)?;
                        let retained_projection = self.cascade_projections[index];
                        let update = if roots_complete
                            && !mandatory_dirty.contains(index)
                            && self.cascade_suns[index] == sun
                            && let Some(retained) = retained_projection
                        {
                            // Compare both transforms in the retained map's
                            // coordinate origin. Stable clipmaps differ by an
                            // exact integer XY translation; their light-space
                            // depth is deliberately kept in the old domain.
                            let desired = translate_shadow_matrix(
                                requested_projection.world_to_shadow,
                                self.cascade_origins[index],
                                camera.world_transform.translation,
                            );
                            clipmap_texel_delta(
                                retained.world_to_shadow,
                                desired,
                                NVR_CASCADE_RESOLUTION,
                            )
                            .and_then(|delta| {
                                ShadowMapUpdate::scroll(delta[0], delta[1], NVR_CASCADE_RESOLUTION)
                            })
                            .unwrap_or(ShadowMapUpdate::Rebuild)
                        } else {
                            ShadowMapUpdate::Rebuild
                        };

                        let projection = match (update, retained_projection) {
                            (ShadowMapUpdate::Scroll(scroll), Some(retained)) => {
                                let desired = translate_shadow_matrix(
                                    requested_projection.world_to_shadow,
                                    self.cascade_origins[index],
                                    camera.world_transform.translation,
                                );
                                let mut scrolled = retained
                                    .with_xy_origin_from(desired)
                                    .ok_or_else(direct3d_failure)?;
                                let stored = self.cascade_spheres[index];
                                let stored_absolute: [f32; 3] = std::array::from_fn(|axis| {
                                    self.cascade_origins[index][axis] + stored[axis]
                                });
                                let toward_camera: [f32; 3] = std::array::from_fn(|axis| {
                                    camera.world_transform.translation[axis] - stored_absolute[axis]
                                });
                                let parallel = dot3(toward_camera, sun);
                                let perpendicular: [f32; 3] = std::array::from_fn(|axis| {
                                    toward_camera[axis] - sun[axis] * parallel
                                });
                                scrolled.center =
                                    std::array::from_fn(|axis| stored[axis] + perpendicular[axis]);
                                scrolled.receiver_radius = requested_projection.receiver_radius;
                                unsafe {
                                    self.draw_directional_scroll(
                                        device,
                                        scene,
                                        index,
                                        scrolled,
                                        self.cascade_origins[index],
                                        minimum_radius,
                                        directional_roots.as_slice(),
                                        roots_complete && index < 3,
                                        scroll,
                                    )?
                                };
                                scrolled
                            }
                            (ShadowMapUpdate::Reuse, _) => {
                                // Pure light-axis translation does not expose
                                // an XY texel. Retain the valid depth volume;
                                // its guard will request a complete rebuild if
                                // that motion becomes material.
                                plan.render[index] = false;
                                continue;
                            }
                            _ => {
                                unsafe {
                                    self.draw_directional_map(
                                        device,
                                        scene,
                                        index,
                                        requested_projection,
                                        camera.world_transform.translation,
                                        minimum_radius,
                                        roots_complete.then_some(directional_roots.as_slice()),
                                        roots_complete && index < 3,
                                    )?
                                };
                                requested_projection
                            }
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
                        if !matches!(update, ShadowMapUpdate::Scroll(_)) {
                            self.cascade_origins[index] = camera.world_transform.translation;
                        }
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
                    self.production_stage = ShadowProductionStage::ActorBounds(index as u8);
                    let actor_bounds = unsafe {
                        native::directional_actor_bounds(
                            directional_roots.as_slice(),
                            index,
                            static_projection,
                            self.cascade_origins[index],
                        )
                    };
                    let (actor_projection, actor_crop) = match actor_bounds {
                        native::DirectionalActorBounds::NoWork => continue,
                        native::DirectionalActorBounds::Croppable(bounds) => {
                            if let Some(cropped) = static_projection
                                .cropped_to_actor_bounds(bounds, ACTOR_MAP_RESOLUTION)
                            {
                                (cropped.projection, cropped.uv_scale_offset)
                            } else {
                                (static_projection, [1.0, 1.0, 0.0, 0.0])
                            }
                        }
                        native::DirectionalActorBounds::FullProjection => {
                            (static_projection, [1.0, 1.0, 0.0, 0.0])
                        }
                    };
                    self.production_stage = ShadowProductionStage::ActorOverlay(index as u8);
                    unsafe {
                        self.draw_directional_actor_overlay(
                            device,
                            scene,
                            index,
                            actor_projection,
                            self.cascade_origins[index],
                            directional_roots.as_slice(),
                        )?
                    };
                    self.actor_crops[index] = actor_crop;
                    actor_overlay_mask |= 1 << index;
                }
                Ok(())
            })();
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

        if !directional && point_lights {
            roots_complete =
                unsafe { native::collect_directional_roots(scene, &mut directional_roots) };
        }

        // Local sources remain part of native scene lighting outdoors too.
        // Omitting their cubes made the Pip-Boy and practical lights cast no
        // shadow whenever a directional atlas was active. Selection is still
        // capped by the same user-owned budget and unchanged cubes are cached.
        self.production_stage = ShadowProductionStage::PointMaps;
        let points = if point_lights {
            unsafe {
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
            }
        } else {
            native::PointLightSelection::default()
        };
        let mut current = [PointMapSignature::EMPTY; NVR_POINT_LIGHT_COUNT];
        let mut dynamic_faces = [0_u8; NVR_POINT_LIGHT_COUNT];
        let mut point_actor_bounds = core::mem::take(&mut self.point_actor_bounds);
        let mut point_actor_roots = core::mem::take(&mut self.point_actor_roots);
        let has_points = points.shadowed().len() != 0;
        let actor_bounds_complete = !has_points
            || (roots_complete
                && unsafe {
                    native::collect_point_actor_bounds(
                        directional_roots.as_slice(),
                        &mut point_actor_bounds,
                        &mut point_actor_roots,
                    )
                });
        for (index, point) in points.shadowed().iter().enumerate() {
            let caster_snapshot = if roots_complete {
                native::PointCasterSnapshot {
                    dynamic_faces: if actor_bounds_complete {
                        native::point_light_dynamic_faces_from_bounds(
                            point_actor_bounds.as_slice(),
                            point.position,
                        )
                    } else {
                        super::contract::ALL_CUBE_FACES
                    },
                    static_signature: native::point_scene_static_signature(
                        directional_roots.as_slice(),
                        point.position,
                        point.radius,
                    ),
                }
            } else {
                unsafe { native::point_light_caster_snapshot(point) }
            };
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
        unsafe {
            self.draw_point_maps(
                device,
                scene,
                camera,
                points.shadowed(),
                PointActorIndex {
                    roots: point_actor_roots.as_slice(),
                    complete: actor_bounds_complete,
                },
                plan,
            )?
        };
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
        // Native nodes never cross the common-prefix lifetime boundary. Only
        // the allocation is retained for the next serialized invocation.
        directional_roots.clear();
        self.directional_roots = directional_roots;
        point_actor_bounds.clear();
        self.point_actor_bounds = point_actor_bounds;
        point_actor_roots.clear();
        self.point_actor_roots = point_actor_roots;
        Ok(Some(PublishedFrame {
            identity,
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
            sun_competition,
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

    /// Assemble one translated cascade in unpublished scratch storage.
    ///
    /// The old overlap and every exposed band cover the scratch map exactly.
    /// Publication is a single final copy, so any failed clear, draw, resolve,
    /// or state mutation leaves the currently sampled atlas quadrant intact.
    #[allow(clippy::too_many_arguments)]
    unsafe fn draw_directional_scroll(
        &mut self,
        device: &Device9Ref<'_>,
        scene: NativeScene,
        cascade: usize,
        projection: CascadeProjection,
        generation_origin: [f32; 3],
        minimum_radius: f32,
        roots: &[DirectionalRoot],
        exclude_dynamic_actors: bool,
        scroll: ClipmapScroll,
    ) -> Direct3DResult<()> {
        let directional = self.directional.as_ref().ok_or_else(direct3d_failure)?;
        let (atlas_x, atlas_y) = cascade_origin(cascade);
        let source_overlap = offset_rect(scroll.source_overlap(), atlas_x, atlas_y);
        let destination_overlap = d3d_rect(scroll.overlap());
        device.clear_texture(0)?;
        device.stretch_rect(
            &directional.atlas_surface,
            Some(&source_overlap),
            &directional.directional_moments_surface,
            Some(&destination_overlap),
            D3DTEXF_NONE,
        )?;

        for rect in scroll.exposed().iter().copied() {
            let horizontal = rect.width() > MAX_CLIPMAP_STRIP_WIDTH;
            let strip = if horizontal {
                &directional.horizontal_strip
            } else {
                &directional.vertical_strip
            };
            debug_assert!(rect.width() <= strip.width && rect.height() <= strip.height);
            let strip_projection = projection
                .cropped_to_texel_rect(rect, NVR_CASCADE_RESOLUTION)
                .ok_or_else(direct3d_failure)?;
            device.set_render_target(0, &strip.generation_surface)?;
            device.set_depth_stencil_surface(Some(&strip.depth))?;
            set_viewport(device, 0, 0, rect.width(), rect.height())?;
            device.clear_attachments(
                D3DCLEAR_ZBUFFER as u32 | D3DCLEAR_STENCIL as u32,
                0,
                1.0,
                0,
            )?;
            draw_evsm_far_clear(device, &self.far_clear_pixel, rect.width(), rect.height())?;
            device.set_depth_stencil_surface(Some(&strip.depth))?;
            render::configure_generation_state(device)?;
            render::begin_directional_map(
                device,
                &self.programs,
                strip_projection.world_to_shadow,
            )?;
            for root in roots.iter().copied().filter(|root| {
                root.enabled_for(cascade) && !(exclude_dynamic_actors && root.is_dynamic_actor())
            }) {
                unsafe {
                    render::draw_directional_root(
                        device,
                        scene.renderer,
                        strip_projection,
                        generation_origin,
                        scene.first_person_root,
                        root.node(),
                        root.is_land,
                        root.is_lod,
                        minimum_radius,
                        false,
                        &mut self.scratch,
                    )?
                };
            }
            device.clear_texture(0)?;
            device.stretch_rect(
                &strip.generation_surface,
                None,
                &strip.moments_surface,
                None,
                D3DTEXF_NONE,
            )?;
            let strip_source = RECT {
                left: 0,
                top: 0,
                right: rect.width() as i32,
                bottom: rect.height() as i32,
            };
            let scratch_destination = d3d_rect(rect);
            device.stretch_rect(
                &strip.moments_surface,
                Some(&strip_source),
                &directional.directional_moments_surface,
                Some(&scratch_destination),
                D3DTEXF_NONE,
            )?;
        }

        let atlas_destination = RECT {
            left: atlas_x as i32,
            top: atlas_y as i32,
            right: (atlas_x + NVR_CASCADE_RESOLUTION) as i32,
            bottom: (atlas_y + NVR_CASCADE_RESOLUTION) as i32,
        };
        device.stretch_rect(
            &directional.directional_moments_surface,
            None,
            &directional.atlas_surface,
            Some(&atlas_destination),
            D3DTEXF_NONE,
        )?;
        Ok(())
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
        actors: PointActorIndex<'_>,
        plan: PointMapPlan,
    ) -> Direct3DResult<()> {
        if !plan.render_faces.into_iter().any(|faces| faces != 0) {
            return Ok(());
        }
        let point_resolution = self
            .points
            .as_ref()
            .ok_or_else(direct3d_failure)?
            .resolution;
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
                    set_viewport(device, 0, 0, point_resolution, point_resolution)?;
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
                    set_viewport(device, 0, 0, point_resolution, point_resolution)?;
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
                    if actors.complete {
                        unsafe {
                            self.draw_point_dynamic_roots(
                                device,
                                scene,
                                camera,
                                point,
                                views[face].world_to_shadow,
                                face,
                                actors.roots,
                            )?
                        };
                    } else {
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
        }
        Ok(())
    }

    /// Submit animated point casters from the transaction's shared root set.
    ///
    /// Native light lists may contain thousands of immutable geometry leaves.
    /// Rewalking that list for each animated cube face only to reject every
    /// static leaf is avoidable: the complete root snapshot already identifies
    /// every actor, and ordinary point-frustum tests still occur during root
    /// traversal. An incomplete root snapshot never enters this route.
    ///
    /// # Safety
    ///
    /// `scene`, `point`, and all `roots` must belong to the active serialized
    /// common-shadow transaction.
    #[allow(clippy::too_many_arguments)]
    unsafe fn draw_point_dynamic_roots(
        &mut self,
        device: &Device9Ref<'_>,
        scene: NativeScene,
        camera: CameraFrame,
        point: &native::PointLight,
        world_to_shadow: [[f32; 4]; 4],
        face: usize,
        actor_roots: &[DirectionalRoot],
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
        for root in actor_roots.iter().copied() {
            unsafe {
                render::draw_point_root(
                    device,
                    scene.renderer,
                    camera.world_transform.translation,
                    scene.first_person_root,
                    point.relative_position,
                    point.radius,
                    face,
                    root.node(),
                    false,
                    false,
                    CasterSubset::Dynamic,
                    &mut self.scratch,
                )?
            };
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
        context: ActiveWorldContext,
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
        if source.as_raw() as usize != context.color_surface {
            return Ok(false);
        }
        let depth = match unsafe {
            backend::resolve_scene_depth(
                provider,
                device.as_raw().cast(),
                Some(context.rendered_texture as *mut c_void),
                DepthResolveSlot::World,
                DepthResolveStage::PreAlphaWorld,
                Some(context.depth_camera),
                "FNV shadows before alpha and atmosphere",
                context.render_epoch,
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
        if depth.world_projection.source_surface != context.depth_surface {
            return Ok(false);
        }
        let camera = context.depth_camera;
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
        let slots = RenderTargetSlots::from_reported_count(self.render_target_count);
        let attachments = RenderAttachments::capture(&device, slots)?;
        let d3d_state = capture_exact_render_state(|| ShadowConsumerState9::capture(&device))?;
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
        finish_exact_render_transaction(&device, &attachments, draw_result, || {
            d3d_state.restore(&device)
        })?;
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
        clear_auxiliary_targets(device, self.render_target_count)?;
        bind_fullscreen_state(device)?;
        let common = consumer_camera_constants(desc, depth, camera);
        let mut matrices = publication.matrices;
        for index in 0..CASCADE_COUNT {
            matrices[index] = translate_shadow_matrix(
                matrices[index],
                camera.world_transform.translation,
                publication.matrix_origins[index],
            );
        }
        let splits = publication.cascade_splits();

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
                    local_lights.width,
                    local_lights.height,
                );
            }
            device.set_render_target(0, &local_lights.deficit_surface)?;
            device.set_render_target(1, &local_lights.total_surface)?;
            set_viewport(device, 0, 0, local_lights.width, local_lights.height)?;
            let plan = point_consumer_plan(scissors, publication.point_count);
            let current_coverage = plan.coverage();
            if !local_lights.initialized.get() {
                // Newly allocated render targets have undefined contents.
                // This is the only full-surface clear in their lifetime.
                device.clear_attachments(D3DCLEAR_TARGET as u32, 0, 1.0, 0)?;
                local_lights.initialized.set(true);
            } else if let Some(clear) =
                local_light_clear_coverage(local_lights.previous_coverage.get(), current_coverage)
            {
                device.clear_attachment_rect(
                    &RECT {
                        left: clear.left as i32,
                        top: clear.top as i32,
                        right: clear.right as i32,
                        bottom: clear.bottom as i32,
                    },
                    D3DCLEAR_TARGET as u32,
                    0,
                    1.0,
                    0,
                )?;
            }
            // Reconstruct depth and the edge-aware normal inside the same
            // scissored draw that consumes the cubes. The equations are
            // identical to the former geometry pass, but its full-resolution
            // FP16 write/read pair and render-target transition disappear.
            unsafe { device.set_raw_base_texture(0, depth_texture)? };
            set_point_clamp_sampler(device, 0)?;
            device.set_pixel_shader_constant_f(0, &constants)?;
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
                draw_quad(device, 0, 0, local_lights.width, local_lights.height)?;
                drew_batch = true;
            }
            device.set_render_state(D3DRS_SCISSORTESTENABLE, 0)?;
            device.set_render_state(D3DRS_ALPHABLENDENABLE, 0)?;
            local_lights.previous_coverage.set(current_coverage);
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
        }

        // Source-owned composition is necessary for two distinct identities:
        // directional neutral is one, while local-deficit neutral is zero.
        // A scene copy lets one pass preserve sky/HDR emitters and combine both
        // terms without an illegal read/write alias or two incompatible blends.
        for sampler in 0..=8 {
            device.clear_texture(sampler)?;
        }
        crate::render_state::copy_exact_color_surface(device, source, &targets.source_surface)?;
        device.set_render_target(0, source)?;
        set_viewport(device, 0, 0, desc.Width, desc.Height)?;
        device.set_pixel_shader(
            match (
                publication.directional,
                publication.scene,
                publication.point_count,
            ) {
                (true, _, 0) => &self.directional_composite_pixel,
                (true, _, _) => &self.composite_pixel,
                (false, SceneKind::Interior, _) => &self.point_only_composite_pixel,
                (false, _, _) => &self.exterior_point_only_composite_pixel,
            },
        )?;
        device.set_texture(0, &targets.source)?;
        unsafe { device.set_raw_base_texture(1, depth_texture)? };
        set_linear_clamp_sampler(device, 0)?;
        set_point_clamp_sampler(device, 1)?;
        if publication.directional {
            let directional = self.directional.as_ref().ok_or_else(direct3d_failure)?;
            device.set_texture(2, &directional.atlas)?;
            set_linear_clamp_sampler(device, 2)?;
            if publication.actor_overlay_mask & 0b011 != 0 {
                device.set_texture(3, &directional.actor_near_middle_moments)?;
                set_linear_clamp_sampler(device, 3)?;
            }
            if publication.actor_overlay_mask & 0b100 != 0 {
                device.set_texture(4, &directional.actor_far_moments)?;
                set_linear_clamp_sampler(device, 4)?;
            }
        }
        if publication.point_count > 0 {
            let local_lights = targets.local_lights.as_ref().ok_or_else(direct3d_failure)?;
            let deficit_sampler = if publication.directional { 5 } else { 3 };
            device.set_texture(deficit_sampler, &local_lights.deficit)?;
            device.set_texture(6, &local_lights.total)?;
            set_point_clamp_sampler(device, deficit_sampler)?;
            set_point_clamp_sampler(device, 6)?;
        }
        if contact_enabled {
            let contact = targets.contact.as_ref().ok_or_else(direct3d_failure)?;
            device.set_texture(7, &contact.raw)?;
            set_point_clamp_sampler(device, 7)?;
        }
        let point_darkness = if publication.scene == SceneKind::Interior {
            settings.interior_darkness
        } else {
            settings.exterior_darkness
        };
        device.set_pixel_shader_constant_f(
            0,
            if publication.directional {
                &common[..6]
            } else if publication.scene != SceneKind::Interior {
                // Exterior point-only composition reconstructs the same
                // receiver normal as point accumulation. Interiors retain the
                // old two-row upload and execute no hidden sunlight work.
                &common[..6]
            } else {
                &common[..2]
            },
        )?;
        if publication.directional {
            for (index, matrix) in matrices.iter().enumerate() {
                device.set_pixel_shader_constant_f((6 + index * 4) as u32, matrix)?;
            }
            device.set_pixel_shader_constant_f(
                22,
                &[
                    splits,
                    [
                        depth.world_projection.reversed_depth_f32(),
                        1.0,
                        settings.exterior_darkness,
                        0.0,
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
            device.set_pixel_shader_constant_f(
                27,
                &[[
                    publication.sun_direction[0],
                    publication.sun_direction[1],
                    publication.sun_direction[2],
                    0.0,
                ]],
            )?;
            device.set_pixel_shader_constant_f(
                28,
                &[std::array::from_fn(|index| {
                    u8::from(publication.actor_overlay_mask & (1 << index) != 0) as f32
                })],
            )?;
            device.set_pixel_shader_constant_f(29, &publication.actor_crops)?;
            device.set_pixel_shader_constant_f(
                32,
                &[[
                    0.5 / ACTOR_MAP_RESOLUTION as f32,
                    1.0 - 0.5 / ACTOR_MAP_RESOLUTION as f32,
                    0.0,
                    0.0,
                ]],
            )?;
            device.set_pixel_shader_constant_f(
                33,
                &[[contact_enabled as u8 as f32, 0.0, 0.0, 0.0]],
            )?;
            device.set_pixel_shader_constant_f(
                34,
                &[[
                    (publication.point_count > 0) as u8 as f32,
                    point_darkness,
                    0.0,
                    0.0,
                ]],
            )?;
        }
        device.set_pixel_shader_constant_f(
            23,
            &[[
                depth.world_projection.reversed_depth_f32(),
                publication.directional as u8 as f32,
                settings.exterior_darkness,
                0.0,
            ]],
        )?;
        device.set_pixel_shader_constant_f(26, &[[1.0 / 65_536.0, 0.0, 0.0, 0.0]])?;
        if !publication.directional {
            if publication.scene != SceneKind::Interior {
                device.set_pixel_shader_constant_f(
                    6,
                    &publication.sun_competition.shader_constants(),
                )?;
            }
            device.set_pixel_shader_constant_f(31, &[[0.0; 4]])?;
            device.set_pixel_shader_constant_f(
                32,
                &[[
                    (publication.point_count > 0) as u8 as f32,
                    point_darkness,
                    0.0,
                    0.0,
                ]],
            )?;
        }
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
    width: u32,
    height: u32,
    initialized: Cell<bool>,
    previous_coverage: Cell<Option<super::contract::LightScissorRect>>,
}

/// Full-resolution current-frame contact evidence and bilateral resolve.
struct ContactConsumerTargets {
    raw: Texture9,
    raw_surface: Surface9,
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
        let width = desc.Width.max(1);
        let height = desc.Height.max(1);
        let deficit = device.create_render_target_texture(width, height, D3DFMT_A16B16G16R16F)?;
        let total = device.create_render_target_texture(width, height, D3DFMT_A16B16G16R16F)?;
        Ok(Self {
            deficit_surface: deficit.surface_level(0)?,
            deficit,
            total_surface: total.surface_level(0)?,
            total,
            width,
            height,
            initialized: Cell::new(false),
            previous_coverage: Cell::new(None),
        })
    }
}

impl ContactConsumerTargets {
    fn create(device: &Device9Ref<'_>, desc: &D3DSURFACE_DESC) -> Direct3DResult<Self> {
        let width = desc.Width.max(1);
        let height = desc.Height.max(1);
        let raw = device.create_render_target_texture(width, height, D3DFMT_G16R16F)?;
        Ok(Self {
            raw_surface: raw.surface_level(0)?,
            raw,
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

fn clear_auxiliary_targets(
    device: &Device9Ref<'_>,
    render_target_count: u32,
) -> Direct3DResult<()> {
    for target in 1..render_target_count {
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

fn d3d_rect(rect: ClipmapRect) -> RECT {
    RECT {
        left: rect.left as i32,
        top: rect.top as i32,
        right: rect.right as i32,
        bottom: rect.bottom as i32,
    }
}

fn offset_rect(rect: ClipmapRect, x: u32, y: u32) -> RECT {
    RECT {
        left: (rect.left + x) as i32,
        top: (rect.top + y) as i32,
        right: (rect.right + x) as i32,
        bottom: (rect.bottom + y) as i32,
    }
}

fn dot3(left: [f32; 3], right: [f32; 3]) -> f32 {
    left[0] * right[0] + left[1] * right[1] + left[2] * right[2]
}

#[cfg(test)]
mod tests {
    use super::{
        cascade_split_change_mask, consumer_selection_spheres, directional_no_work_state_changed,
        projection_materially_changed, translate_shadow_matrix,
    };
    use crate::effects::shadows::{
        contract::{
            CascadeDirty, NVR_CASCADE_RESOLUTION, cascade_sphere_selection, clipmap_texel_delta,
            practical_cascade_splits,
        },
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
    fn interior_no_work_path_ignores_dormant_exterior_state() {
        assert!(!directional_no_work_state_changed(
            false,
            CascadeDirty::all(),
            0,
            None,
        ));
        assert!(directional_no_work_state_changed(
            true,
            CascadeDirty::all(),
            0,
            Some(0),
        ));
        assert!(directional_no_work_state_changed(
            true,
            CascadeDirty::none(),
            0,
            None,
        ));
    }

    #[test]
    fn translated_clipmap_delta_matches_receiver_texel_motion() {
        let retained_camera = ShadowCamera {
            near: 5.0,
            far: 28_000.0,
            frustum_left: -1.2,
            frustum_right: 1.2,
            frustum_bottom: -0.7,
            frustum_top: 0.7,
            forward: [1.0, 0.0, 0.0],
            up: [0.0, 0.0, 1.0],
            right: [0.0, 1.0, 0.0],
            translation: [12_345.0, -4_321.0, 800.0],
            fov_compensation: 1.0,
        };
        let desired_camera = ShadowCamera {
            translation: [12_537.0, -4_257.0, 832.0],
            ..retained_camera
        };
        let split =
            practical_cascade_splits(5.0, 28_000.0, 6_000.0, 0.9).expect("cascade profile")[0];
        let sun = [0.4, 0.3, 0.866_025_4];
        let retained = cascade_projection(retained_camera, split, sun, NVR_CASCADE_RESOLUTION)
            .expect("retained projection");
        let requested = cascade_projection(desired_camera, split, sun, NVR_CASCADE_RESOLUTION)
            .expect("desired projection");
        let desired_in_retained_origin = translate_shadow_matrix(
            requested.world_to_shadow,
            retained_camera.translation,
            desired_camera.translation,
        );
        let delta = clipmap_texel_delta(
            retained.world_to_shadow,
            desired_in_retained_origin,
            NVR_CASCADE_RESOLUTION,
        )
        .expect("stable projection must move by whole texels");
        assert_ne!(delta, [0, 0]);

        // A fixed camera-relative point expressed in the retained origin
        // moves by exactly the copy offset. This proves the D3D top-left Y
        // convention as well as the source-to-destination sign.
        let point = [0.0_f32, 0.0, 0.0, 1.0];
        let project = |matrix: [[f32; 4]; 4]| {
            std::array::from_fn::<_, 4, _>(|column| {
                (0..4)
                    .map(|row| point[row] * matrix[row][column])
                    .sum::<f32>()
            })
        };
        let old = project(retained.world_to_shadow);
        let new = project(desired_in_retained_origin);
        let half = NVR_CASCADE_RESOLUTION as f32 * 0.5;
        let observed = [
            ((new[0] - old[0]) * half).round() as i32,
            (-(new[1] - old[1]) * half).round() as i32,
        ];
        assert_eq!(observed, delta);
        assert!(
            retained
                .with_xy_origin_from(desired_in_retained_origin)
                .is_some()
        );
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
