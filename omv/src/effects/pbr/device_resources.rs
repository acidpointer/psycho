//! D3D resource ownership for native PBR.
//!
//! This creates shader handles from prepared bytecode and owns the dynamic
//! close-terrain light-data texture. Paired close-terrain pixel resources are
//! specialized: the even handle is native-only and the odd handle admits a
//! nonempty supplemental payload. Creation is bounded per frame and kept
//! outside `SetShaders`. Ownership is keyed by the lifecycle device generation
//! as well as pointer identity, because D3D9 reset may preserve the COM address
//! while invalidating every default-pool resource. Presentation, draw, and
//! Recreate callbacks use `try_lock` only. A compiler publication or resource
//! owner that is momentarily busy defers creation, rejects a draw, or rejects
//! reset; it never stalls the serialized renderer thread.

use std::sync::{
    LazyLock,
    atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
};
use std::{ffi::c_void, sync::Arc};

use libpsycho::os::windows::directx9::{
    Device9Ref, DynamicRgba32fTexture9, PixelShader9, VertexShader9,
};
use parking_lot::Mutex;

use super::{compiler, shader_registry};

const CREATE_BUDGET_PER_FRAME: usize = 4;
const TEMPLATE_ID_NONE: u32 = u32::MAX;
pub(super) const SUPPLEMENTAL_LIGHT_SAMPLER: u32 = 14;

static LAST_CREATE_FAILED_TEMPLATE_ID: AtomicU32 = AtomicU32::new(TEMPLATE_ID_NONE);
static HANDLES: LazyLock<Vec<AtomicUsize>> = LazyLock::new(|| {
    (0..shader_registry::template_count())
        .map(|_| AtomicUsize::new(0))
        .collect()
});
static LAND_LOD_CREATE_FAILED: AtomicBool = AtomicBool::new(false);
static TERRAIN_FADE_CREATE_FAILED: AtomicBool = AtomicBool::new(false);
static CLOSE_TERRAIN_CREATE_FAILED: AtomicBool = AtomicBool::new(false);
static LAND_LOD_RESOURCES_READY: AtomicBool = AtomicBool::new(false);
static TERRAIN_FADE_RESOURCES_READY: AtomicBool = AtomicBool::new(false);
static CLOSE_TERRAIN_RESOURCES_READY: AtomicBool = AtomicBool::new(false);
static ALL_RESOURCES_READY: AtomicBool = AtomicBool::new(false);
static RESOURCES: LazyLock<Mutex<ResourceState>> = LazyLock::new(|| {
    Mutex::new(ResourceState {
        device: 0,
        device_generation: 0,
        supplemental_light_texture: None,
        supplemental_light_texture_create_failed: false,
        supplemental_light_payload_valid: false,
        supplemental_light_payload: [[0; 4];
            super::terrain_lights::SUPPLEMENTAL_LIGHT_TEXTURE_TEXELS],
        slots: (0..shader_registry::template_count())
            .map(|_| ResourceSlot::new())
            .collect(),
    })
});

struct ResourceState {
    device: usize,
    device_generation: u32,
    supplemental_light_texture: Option<DynamicRgba32fTexture9>,
    supplemental_light_texture_create_failed: bool,
    supplemental_light_payload_valid: bool,
    supplemental_light_payload:
        [[u32; 4]; super::terrain_lights::SUPPLEMENTAL_LIGHT_TEXTURE_TEXELS],
    slots: Vec<ResourceSlot>,
}

struct ResourceSlot {
    bytecode: Option<Arc<[u32]>>,
    pixel_shader: Option<PixelShader9>,
    vertex_shader: Option<VertexShader9>,
    create_failed: bool,
}

impl ResourceSlot {
    fn new() -> Self {
        Self {
            bytecode: None,
            pixel_shader: None,
            vertex_shader: None,
            create_failed: false,
        }
    }

    fn clear_shader(&mut self) {
        self.pixel_shader = None;
        self.vertex_shader = None;
        self.create_failed = false;
    }

    fn has_shader(&self) -> bool {
        self.pixel_shader.is_some() || self.vertex_shader.is_some()
    }
}

pub(super) fn service_frame() {
    let Some(device_ptr) = crate::backend::d3d_device_ptr() else {
        return;
    };
    let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
        return;
    };

    let Some(mut state) = RESOURCES.try_lock() else {
        return;
    };
    let device_key = device_ptr as usize;
    let device_generation = crate::backend::d3d_device_generation();
    if state.device != device_key || state.device_generation != device_generation {
        // A generation transition invalidates all prior device state, including
        // an s14 override whose restore failed while the old device was lost.
        // Clearing the marker earlier would be unsafe on a still-live device.
        super::hooks::forget_supplemental_light_texture_binding_after_device_change();
        clear_published_handles();
        CLOSE_TERRAIN_RESOURCES_READY.store(false, Ordering::Release);
        ALL_RESOURCES_READY.store(false, Ordering::Release);
        state.device = device_key;
        state.device_generation = device_generation;
        state.supplemental_light_texture = None;
        state.supplemental_light_texture_create_failed = false;
        state.supplemental_light_payload_valid = false;
        for slot in &mut state.slots {
            slot.clear_shader();
        }
    }

    let mut created_this_frame = 0usize;
    if state.supplemental_light_texture.is_none() && !state.supplemental_light_texture_create_failed
    {
        match device.create_dynamic_rgba32f_texture(
            super::terrain_lights::SUPPLEMENTAL_LIGHT_TEXTURE_WIDTH as u32,
            super::terrain_lights::SUPPLEMENTAL_LIGHT_TEXTURE_HEIGHT as u32,
        ) {
            Ok(texture) => {
                state.supplemental_light_texture = Some(texture);
                created_this_frame += 1;
            }
            Err(_) => state.supplemental_light_texture_create_failed = true,
        }
    }

    for template_id in 0..state.slots.len() {
        if created_this_frame >= CREATE_BUDGET_PER_FRAME {
            break;
        }

        let slot = &mut state.slots[template_id];
        if slot.has_shader() || slot.create_failed {
            continue;
        }

        if slot.bytecode.is_none()
            && let Some(bytecode) = compiler::prepared_bytecode(template_id as u16)
        {
            slot.bytecode = Some(bytecode);
        }

        let Some(bytecode) = slot.bytecode.as_deref() else {
            continue;
        };
        let Some(template) = shader_registry::template_at(template_id as u16) else {
            slot.create_failed = true;
            LAST_CREATE_FAILED_TEMPLATE_ID.store(template_id as u32, Ordering::Release);
            continue;
        };

        let created = match template.stage {
            shader_registry::ShaderStage::Pixel => match device.create_pixel_shader(bytecode) {
                Ok(shader) => {
                    let handle = shader.as_raw();
                    slot.pixel_shader = Some(shader);
                    publish_handle(template_id, handle);
                    true
                }
                Err(_) => {
                    LAST_CREATE_FAILED_TEMPLATE_ID.store(template_id as u32, Ordering::Release);
                    false
                }
            },
            shader_registry::ShaderStage::Vertex => match device.create_vertex_shader(bytecode) {
                Ok(shader) => {
                    let handle = shader.as_raw();
                    slot.vertex_shader = Some(shader);
                    publish_handle(template_id, handle);
                    true
                }
                Err(_) => {
                    LAST_CREATE_FAILED_TEMPLATE_ID.store(template_id as u32, Ordering::Release);
                    false
                }
            },
        };

        if created {
            created_this_frame += 1;
        } else {
            slot.create_failed = true;
        }
    }

    update_failure_state(&state);
}

pub(super) fn object_shader_handle(template_id: u16) -> Option<*mut c_void> {
    published_handle(template_id)
}

pub(super) fn object_created_count() -> usize {
    RESOURCES
        .try_lock()
        .as_deref()
        .map(|state| {
            state
                .slots
                .iter()
                .take(shader_registry::object_template_count())
                .filter(|slot| slot.has_shader())
                .count()
        })
        .unwrap_or(0)
}

pub(super) fn object_create_failed() -> bool {
    RESOURCES.try_lock().as_deref().is_some_and(|state| {
        state
            .slots
            .iter()
            .take(shader_registry::object_template_count())
            .any(|slot| slot.create_failed)
    })
}

pub(super) fn object_create_failed_count() -> usize {
    RESOURCES
        .try_lock()
        .as_deref()
        .map(|state| {
            state
                .slots
                .iter()
                .take(shader_registry::object_template_count())
                .filter(|slot| slot.create_failed)
                .count()
        })
        .unwrap_or(0)
}

pub(super) fn object_last_create_failed_template_label() -> &'static str {
    template_label(LAST_CREATE_FAILED_TEMPLATE_ID.load(Ordering::Acquire))
}

pub(super) fn object_resources_ready() -> bool {
    RESOURCES.try_lock().as_deref().is_some_and(|state| {
        state
            .slots
            .iter()
            .take(shader_registry::object_template_count())
            .all(ResourceSlot::has_shader)
    })
}

pub(super) fn all_resources_ready() -> bool {
    ALL_RESOURCES_READY.load(Ordering::Acquire)
}

pub(super) fn land_lod_shader_handle(stage: shader_registry::ShaderStage) -> Option<*mut c_void> {
    let template_id = shader_registry::land_lod_template_id(stage);
    published_handle(template_id)
}

pub(super) fn land_lod_resources_ready() -> bool {
    LAND_LOD_RESOURCES_READY.load(Ordering::Acquire)
}

pub(super) fn land_lod_created_count() -> usize {
    family_created_count(land_lod_range())
}

pub(super) fn land_lod_create_failed_count() -> usize {
    family_create_failed_count(land_lod_range())
}

pub(super) fn land_lod_create_failed() -> bool {
    LAND_LOD_CREATE_FAILED.load(Ordering::Acquire)
}

pub(super) fn terrain_fade_shader_handle(
    stage: shader_registry::ShaderStage,
) -> Option<*mut c_void> {
    resource_handle(shader_registry::terrain_fade_template_id(stage))
}

pub(super) fn terrain_fade_resources_ready() -> bool {
    TERRAIN_FADE_RESOURCES_READY.load(Ordering::Acquire)
}

pub(super) fn terrain_fade_created_count() -> usize {
    family_created_count(terrain_fade_range())
}

pub(super) fn terrain_fade_create_failed_count() -> usize {
    family_create_failed_count(terrain_fade_range())
}

pub(super) fn terrain_fade_create_failed() -> bool {
    TERRAIN_FADE_CREATE_FAILED.load(Ordering::Acquire)
}

pub(super) fn close_terrain_shader_handle(
    stage: shader_registry::ShaderStage,
    sls_number: u16,
) -> Option<*mut c_void> {
    resource_handle(shader_registry::close_terrain_template_id(
        stage, sls_number,
    )?)
}

/// Return the native-only pixel handle paired with an engine terrain row.
pub(super) fn close_terrain_fast_pixel_handle(sls_number: u16) -> Option<*mut c_void> {
    close_terrain_shader_handle(
        shader_registry::ShaderStage::Pixel,
        shader_registry::close_terrain_fast_sls(sls_number),
    )
}

/// Return the supplemental-light pixel handle paired with a terrain row.
pub(super) fn close_terrain_supplemental_pixel_handle(sls_number: u16) -> Option<*mut c_void> {
    close_terrain_shader_handle(
        shader_registry::ShaderStage::Pixel,
        shader_registry::close_terrain_supplemental_sls(sls_number),
    )
}

/// Return whether both pixel specializations and the shared vertex shader exist.
pub(super) fn close_terrain_variant_resources_ready(pixel_sls: u16) -> bool {
    close_terrain_shader_handle(shader_registry::ShaderStage::Vertex, 2100).is_some()
        && close_terrain_fast_pixel_handle(pixel_sls).is_some()
        && close_terrain_supplemental_pixel_handle(pixel_sls).is_some()
}

pub(super) fn close_terrain_create_failed() -> bool {
    CLOSE_TERRAIN_CREATE_FAILED.load(Ordering::Acquire)
}

pub(super) fn close_terrain_resources_ready() -> bool {
    CLOSE_TERRAIN_RESOURCES_READY.load(Ordering::Acquire)
}

pub(super) fn close_terrain_created_count() -> usize {
    family_created_count(close_terrain_range())
}

pub(super) fn close_terrain_create_failed_count() -> usize {
    family_create_failed_count(close_terrain_range())
        + RESOURCES
            .try_lock()
            .as_deref()
            .is_some_and(|state| state.supplemental_light_texture_create_failed) as usize
}

/// Upload if changed, then bind the supplemental close-terrain light texture.
///
/// The resource owner is acquired with `try_lock`; contention or a stale
/// device generation rejects the draw instead of blocking. An exact cached
/// image avoids serialization, locking, and copying for repeated payloads. A
/// changed texture uses a discard write so earlier draws may keep consuming
/// their renamed storage.
pub(super) fn upload_and_bind_supplemental_light_texture(
    device: &Device9Ref<'_>,
    lights: &super::terrain_lights::SupplementalTerrainLights,
) -> bool {
    let Some(mut state) = RESOURCES.try_lock() else {
        return false;
    };
    if state.device != device.as_raw() as usize
        || state.device_generation != crate::backend::d3d_device_generation()
    {
        return false;
    }
    if state.supplemental_light_texture.is_none() {
        return false;
    }
    let payload_matches = state.supplemental_light_payload_valid
        && lights.matches_shader_texture_bits(&state.supplemental_light_payload);
    if !payload_matches {
        // Materialize the fixed 1 KiB image only after exact comparison proves
        // that the existing device contents cannot be reused. The common
        // repeated-payload path therefore performs neither a stack clear nor a
        // driver lock; the uncommon changed path remains allocation-free.
        let mut texels = [[0.0; 4]; super::terrain_lights::SUPPLEMENTAL_LIGHT_TEXTURE_TEXELS];
        lights.write_shader_texture(&mut texels);
        if state
            .supplemental_light_texture
            .as_ref()
            .is_none_or(|texture| texture.write_discard(&texels).is_err())
        {
            return false;
        }
        // Store exact bits rather than a hash. A collision must never reuse a
        // different light payload, and this fixed copy occurs only after the
        // matching upload has succeeded.
        for (cached, incoming) in state.supplemental_light_payload.iter_mut().zip(&texels) {
            *cached = incoming.map(f32::to_bits);
        }
        state.supplemental_light_payload_valid = true;
    }
    let Some(texture) = state.supplemental_light_texture.as_ref() else {
        return false;
    };
    device
        .set_texture(SUPPLEMENTAL_LIGHT_SAMPLER, texture.texture())
        .is_ok()
}

fn resource_handle(template_id: u16) -> Option<*mut c_void> {
    published_handle(template_id)
}

/// Reset current-device resources after `before_drop` restores engine state.
///
/// The callback runs only after the resource owner is acquired. A busy owner
/// returns `false` without changing handles or D3D state, allowing Recreate to
/// abort and retry without waiting.
pub(super) fn try_reset_after(before_drop: impl FnOnce()) -> bool {
    let Some(mut state) = RESOURCES.try_lock() else {
        return false;
    };
    before_drop();
    clear_published_handles();
    state.device = 0;
    state.device_generation = 0;
    state.supplemental_light_texture = None;
    state.supplemental_light_texture_create_failed = false;
    state.supplemental_light_payload_valid = false;
    LAST_CREATE_FAILED_TEMPLATE_ID.store(TEMPLATE_ID_NONE, Ordering::Release);
    for slot in &mut state.slots {
        *slot = ResourceSlot::new();
    }
    LAND_LOD_CREATE_FAILED.store(false, Ordering::Release);
    TERRAIN_FADE_CREATE_FAILED.store(false, Ordering::Release);
    CLOSE_TERRAIN_CREATE_FAILED.store(false, Ordering::Release);
    LAND_LOD_RESOURCES_READY.store(false, Ordering::Release);
    TERRAIN_FADE_RESOURCES_READY.store(false, Ordering::Release);
    CLOSE_TERRAIN_RESOURCES_READY.store(false, Ordering::Release);
    ALL_RESOURCES_READY.store(false, Ordering::Release);
    true
}

fn publish_handle(template_id: usize, handle: *mut c_void) {
    if let Some(slot) = HANDLES.get(template_id) {
        slot.store(handle as usize, Ordering::Release);
    }
}

fn published_handle(template_id: u16) -> Option<*mut c_void> {
    let handle = HANDLES.get(template_id as usize)?.load(Ordering::Acquire) as *mut c_void;
    (!handle.is_null()).then_some(handle)
}

fn clear_published_handles() {
    for handle in HANDLES.iter() {
        handle.store(0, Ordering::Release);
    }
}

fn update_failure_state(state: &ResourceState) {
    ALL_RESOURCES_READY.store(
        // The light-data texture belongs only to close terrain. Keeping it out
        // of the global shader gate lets object, LandLOD, and TerrainFade PBR
        // remain available if this new format is unsupported; the dedicated
        // close-terrain gate below still fails that entire family atomically.
        state.slots.iter().all(ResourceSlot::has_shader),
        Ordering::Release,
    );
    let land_lod_first = shader_registry::object_template_count();
    LAND_LOD_RESOURCES_READY.store(
        state.slots[land_lod_first..land_lod_first + 2]
            .iter()
            .all(ResourceSlot::has_shader),
        Ordering::Release,
    );
    LAND_LOD_CREATE_FAILED.store(
        state.slots[land_lod_first..land_lod_first + 2]
            .iter()
            .any(|slot| slot.create_failed),
        Ordering::Release,
    );

    let terrain_fade_first =
        shader_registry::terrain_fade_template_id(shader_registry::ShaderStage::Vertex) as usize;
    TERRAIN_FADE_RESOURCES_READY.store(
        state.slots[terrain_fade_first..terrain_fade_first + 2]
            .iter()
            .all(ResourceSlot::has_shader),
        Ordering::Release,
    );
    TERRAIN_FADE_CREATE_FAILED.store(
        state.slots[terrain_fade_first..terrain_fade_first + 2]
            .iter()
            .any(|slot| slot.create_failed),
        Ordering::Release,
    );

    let close_terrain_first =
        shader_registry::terrain_fade_template_id(shader_registry::ShaderStage::Pixel) as usize + 1;
    CLOSE_TERRAIN_RESOURCES_READY.store(
        state.slots[close_terrain_first..]
            .iter()
            .all(ResourceSlot::has_shader)
            && state.supplemental_light_texture.is_some(),
        Ordering::Release,
    );
    CLOSE_TERRAIN_CREATE_FAILED.store(
        state.slots[close_terrain_first..]
            .iter()
            .any(|slot| slot.create_failed)
            || state.supplemental_light_texture_create_failed,
        Ordering::Release,
    );
}

fn template_label(template_id: u32) -> &'static str {
    if template_id == TEMPLATE_ID_NONE {
        return "none";
    }

    u16::try_from(template_id)
        .ok()
        .and_then(shader_registry::template_at)
        .map_or("unknown", |template| template.label)
}

fn family_created_count(range: std::ops::Range<usize>) -> usize {
    RESOURCES
        .try_lock()
        .as_deref()
        .map(|state| {
            state.slots[range]
                .iter()
                .filter(|slot| slot.has_shader())
                .count()
        })
        .unwrap_or(0)
}

fn family_create_failed_count(range: std::ops::Range<usize>) -> usize {
    RESOURCES
        .try_lock()
        .as_deref()
        .map(|state| {
            state.slots[range]
                .iter()
                .filter(|slot| slot.create_failed)
                .count()
        })
        .unwrap_or(0)
}

fn land_lod_range() -> std::ops::Range<usize> {
    let start = shader_registry::object_template_count();
    start..start + 2
}

fn terrain_fade_range() -> std::ops::Range<usize> {
    let start = land_lod_range().end;
    start..start + 2
}

fn close_terrain_range() -> std::ops::Range<usize> {
    terrain_fade_range().end..shader_registry::template_count()
}
