//! D3D shader resource ownership.
//!
//! This creates D3D shader handles from prepared bytecode. Creation is
//! bounded per frame and kept outside `SetShaders`.

use std::ffi::c_void;
use std::sync::{
    LazyLock,
    atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
};

use libpsycho::os::windows::directx9::{Device9Ref, PixelShader9, VertexShader9};
use parking_lot::Mutex;

use super::{compiler, shader_registry};

const CREATE_BUDGET_PER_FRAME: usize = 4;
const TEMPLATE_ID_NONE: u32 = u32::MAX;

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
static RESOURCES: LazyLock<Mutex<ResourceState>> = LazyLock::new(|| {
    Mutex::new(ResourceState {
        device: 0,
        slots: (0..shader_registry::template_count())
            .map(|_| ResourceSlot::new())
            .collect(),
    })
});

struct ResourceState {
    device: usize,
    slots: Vec<ResourceSlot>,
}

struct ResourceSlot {
    bytecode: Option<Vec<u32>>,
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

    let mut state = RESOURCES.lock();
    let device_key = device_ptr as usize;
    if state.device != device_key {
        clear_published_handles();
        state.device = device_key;
        for slot in &mut state.slots {
            slot.clear_shader();
        }
    }

    let mut created_this_frame = 0usize;
    for template_id in 0..state.slots.len() {
        if created_this_frame >= CREATE_BUDGET_PER_FRAME {
            break;
        }

        let slot = &mut state.slots[template_id];
        if slot.has_shader() || slot.create_failed {
            continue;
        }

        if slot.bytecode.is_none()
            && let Some(bytecode) = compiler::take_ready_bytecode(template_id as u16)
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
                    log::info!(
                        "[PBR] Pixel shader created {} handle={handle:p}",
                        template.label
                    );
                    true
                }
                Err(err) => {
                    LAST_CREATE_FAILED_TEMPLATE_ID.store(template_id as u32, Ordering::Release);
                    log::warn!(
                        "[PBR] Pixel shader creation failed {}: {err}",
                        template.label
                    );
                    false
                }
            },
            shader_registry::ShaderStage::Vertex => match device.create_vertex_shader(bytecode) {
                Ok(shader) => {
                    let handle = shader.as_raw();
                    slot.vertex_shader = Some(shader);
                    publish_handle(template_id, handle);
                    log::info!(
                        "[PBR] Vertex shader created {} handle={handle:p}",
                        template.label
                    );
                    true
                }
                Err(err) => {
                    LAST_CREATE_FAILED_TEMPLATE_ID.store(template_id as u32, Ordering::Release);
                    log::warn!(
                        "[PBR] Vertex shader creation failed {}: {err}",
                        template.label
                    );
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
        .lock()
        .slots
        .iter()
        .take(shader_registry::object_template_count())
        .filter(|slot| slot.has_shader())
        .count()
}

pub(super) fn object_create_failed() -> bool {
    RESOURCES
        .lock()
        .slots
        .iter()
        .take(shader_registry::object_template_count())
        .any(|slot| slot.create_failed)
}

pub(super) fn object_create_failed_count() -> usize {
    RESOURCES
        .lock()
        .slots
        .iter()
        .take(shader_registry::object_template_count())
        .filter(|slot| slot.create_failed)
        .count()
}

pub(super) fn object_last_create_failed_template_label() -> &'static str {
    template_label(LAST_CREATE_FAILED_TEMPLATE_ID.load(Ordering::Acquire))
}

pub(super) fn object_resources_ready() -> bool {
    let state = RESOURCES.lock();
    state
        .slots
        .iter()
        .take(shader_registry::object_template_count())
        .all(ResourceSlot::has_shader)
}

pub(super) fn land_lod_shader_handle(stage: shader_registry::ShaderStage) -> Option<*mut c_void> {
    let template_id = shader_registry::land_lod_template_id(stage);
    published_handle(template_id)
}

pub(super) fn land_lod_resources_ready() -> bool {
    LAND_LOD_RESOURCES_READY.load(Ordering::Acquire)
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

pub(super) fn close_terrain_variant_resources_ready(pixel_sls: u16) -> bool {
    close_terrain_shader_handle(shader_registry::ShaderStage::Vertex, 2100).is_some()
        && close_terrain_shader_handle(shader_registry::ShaderStage::Pixel, pixel_sls).is_some()
}

pub(super) fn close_terrain_create_failed() -> bool {
    CLOSE_TERRAIN_CREATE_FAILED.load(Ordering::Acquire)
}

fn resource_handle(template_id: u16) -> Option<*mut c_void> {
    published_handle(template_id)
}

pub(super) fn reset() {
    let mut state = RESOURCES.lock();
    clear_published_handles();
    state.device = 0;
    LAST_CREATE_FAILED_TEMPLATE_ID.store(TEMPLATE_ID_NONE, Ordering::Release);
    for slot in &mut state.slots {
        *slot = ResourceSlot::new();
    }
    LAND_LOD_CREATE_FAILED.store(false, Ordering::Release);
    TERRAIN_FADE_CREATE_FAILED.store(false, Ordering::Release);
    CLOSE_TERRAIN_CREATE_FAILED.store(false, Ordering::Release);
    LAND_LOD_RESOURCES_READY.store(false, Ordering::Release);
    TERRAIN_FADE_RESOURCES_READY.store(false, Ordering::Release);
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
    CLOSE_TERRAIN_CREATE_FAILED.store(
        state.slots[close_terrain_first..]
            .iter()
            .any(|slot| slot.create_failed),
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
