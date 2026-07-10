//! D3D shader resource ownership.
//!
//! This creates D3D shader handles from prepared object bytecode. Creation is
//! bounded per frame and kept outside `SetShaders`.

use std::ffi::c_void;
use std::sync::{
    LazyLock,
    atomic::{AtomicU32, Ordering},
};

use libpsycho::os::windows::directx9::{Device9Ref, PixelShader9, VertexShader9};
use parking_lot::Mutex;

use super::{compiler, shader_registry};

const CREATE_BUDGET_PER_FRAME: usize = 4;
const TEMPLATE_ID_NONE: u32 = u32::MAX;

static LAST_CREATE_FAILED_TEMPLATE_ID: AtomicU32 = AtomicU32::new(TEMPLATE_ID_NONE);
static RESOURCES: LazyLock<Mutex<ResourceState>> = LazyLock::new(|| {
    Mutex::new(ResourceState {
        device: 0,
        slots: (0..shader_registry::object_template_count())
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

    fn handle(&self) -> Option<*mut c_void> {
        self.pixel_shader
            .as_ref()
            .map(PixelShader9::as_raw)
            .or_else(|| self.vertex_shader.as_ref().map(VertexShader9::as_raw))
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
        let Some(template) = shader_registry::object_template_at(template_id as u16) else {
            slot.create_failed = true;
            LAST_CREATE_FAILED_TEMPLATE_ID.store(template_id as u32, Ordering::Release);
            continue;
        };

        let created = match template.stage {
            shader_registry::ShaderStage::Pixel => match device.create_pixel_shader(bytecode) {
                Ok(shader) => {
                    let handle = shader.as_raw();
                    slot.pixel_shader = Some(shader);
                    log::info!(
                        "[PBR] Object PBR pixel shader created {} handle={handle:p}",
                        template.label
                    );
                    true
                }
                Err(err) => {
                    LAST_CREATE_FAILED_TEMPLATE_ID.store(template_id as u32, Ordering::Release);
                    log::warn!(
                        "[PBR] Object PBR pixel shader creation failed {}: {err}",
                        template.label
                    );
                    false
                }
            },
            shader_registry::ShaderStage::Vertex => match device.create_vertex_shader(bytecode) {
                Ok(shader) => {
                    let handle = shader.as_raw();
                    slot.vertex_shader = Some(shader);
                    log::info!(
                        "[PBR] Object PBR vertex shader created {} handle={handle:p}",
                        template.label
                    );
                    true
                }
                Err(err) => {
                    LAST_CREATE_FAILED_TEMPLATE_ID.store(template_id as u32, Ordering::Release);
                    log::warn!(
                        "[PBR] Object PBR vertex shader creation failed {}: {err}",
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
}

pub(super) fn object_shader_handle(template_id: u16) -> Option<*mut c_void> {
    RESOURCES
        .lock()
        .slots
        .get(template_id as usize)
        .and_then(ResourceSlot::handle)
}

pub(super) fn object_created_count() -> usize {
    RESOURCES
        .lock()
        .slots
        .iter()
        .filter(|slot| slot.has_shader())
        .count()
}

pub(super) fn object_create_failed() -> bool {
    RESOURCES.lock().slots.iter().any(|slot| slot.create_failed)
}

pub(super) fn object_create_failed_count() -> usize {
    RESOURCES
        .lock()
        .slots
        .iter()
        .filter(|slot| slot.create_failed)
        .count()
}

pub(super) fn object_last_create_failed_template_label() -> &'static str {
    template_label(LAST_CREATE_FAILED_TEMPLATE_ID.load(Ordering::Acquire))
}

pub(super) fn object_resources_ready() -> bool {
    let state = RESOURCES.lock();
    !state.slots.is_empty() && state.slots.iter().all(ResourceSlot::has_shader)
}

pub(super) fn reset() {
    let mut state = RESOURCES.lock();
    state.device = 0;
    LAST_CREATE_FAILED_TEMPLATE_ID.store(TEMPLATE_ID_NONE, Ordering::Release);
    for slot in &mut state.slots {
        *slot = ResourceSlot::new();
    }
}

fn template_label(template_id: u32) -> &'static str {
    if template_id == TEMPLATE_ID_NONE {
        return "none";
    }

    u16::try_from(template_id)
        .ok()
        .and_then(shader_registry::object_template_at)
        .map_or("unknown", |template| template.label)
}
