//! Fallout New Vegas backend.

use core::{ffi::c_void, fmt, mem::size_of};
use std::sync::{
    LazyLock,
    atomic::{AtomicU32, AtomicUsize, Ordering},
};

use libpsycho::os::windows::{
    directx9::{
        D3DCULL_NONE, D3DFMT_INTZ, D3DPT_POINTLIST, D3DRESZ_POINT_SIZE, D3DRS_ALPHABLENDENABLE,
        D3DRS_COLORWRITEENABLE, D3DRS_CULLMODE, D3DRS_POINTSIZE, D3DRS_ZENABLE, D3DRS_ZWRITEENABLE,
        D3DSBT_ALL, Device9Ref, Direct3DResult, NIDX9_RENDERER_DEVICE_OFFSET, PositionVertex,
        StateBlock9, Texture9,
    },
    memory::validate_memory_range,
};
use parking_lot::Mutex;
use windows::Win32::Graphics::Direct3D9::D3DSURFACE_DESC;
use windows::core::Error as WindowsError;

use super::{CameraFrame, DepthResolveSlot};

const NIDX9_RENDERER_SINGLETON_PTR: usize = 0x011C73B4;
const BSSHADERMANAGER_CAMERA_PTR: usize = 0x011F917C;

const NICAMERA_FRUSTUM_NEAR_OFFSET: usize = 0xEC;
const NICAMERA_FRUSTUM_FAR_OFFSET: usize = 0xF0;
const MAX_DEPTH_RESOLVE_LOGS: u32 = 16;

static DEPTH_RESOLVE_LOGS: AtomicU32 = AtomicU32::new(0);
static RESOLVED_WORLD_DEPTH_TEXTURE: AtomicUsize = AtomicUsize::new(0);
static RESOLVED_FIRST_PERSON_DEPTH_TEXTURE: AtomicUsize = AtomicUsize::new(0);
static DEPTH_RESOLVE: LazyLock<Mutex<FnvDepthResolve>> =
    LazyLock::new(|| Mutex::new(FnvDepthResolve::default()));

pub(super) fn d3d_device_ptr() -> Option<*mut c_void> {
    unsafe {
        let renderer = read_ptr(NIDX9_RENDERER_SINGLETON_PTR)?;
        if renderer.is_null() {
            return None;
        }

        read_ptr(renderer as usize + NIDX9_RENDERER_DEVICE_OFFSET).and_then(|device| {
            if device.is_null() {
                None
            } else {
                Some(device.cast::<c_void>())
            }
        })
    }
}

pub(super) fn camera_frame(desc: &D3DSURFACE_DESC) -> CameraFrame {
    let fallback = CameraFrame::fallback(desc);

    unsafe {
        let Some(camera) = read_ptr(BSSHADERMANAGER_CAMERA_PTR) else {
            return fallback;
        };
        if camera.is_null() {
            return fallback;
        }

        let near_z = match read_f32(camera as usize + NICAMERA_FRUSTUM_NEAR_OFFSET) {
            Some(value) => value,
            None => 0.0,
        };
        let far_z = match read_f32(camera as usize + NICAMERA_FRUSTUM_FAR_OFFSET) {
            Some(value) => value,
            None => 0.0,
        };
        if !near_z.is_finite() || !far_z.is_finite() || near_z <= 0.0 || far_z <= near_z {
            return fallback;
        }

        CameraFrame {
            near_z,
            far_z,
            aspect_ratio: fallback.aspect_ratio,
        }
    }
}

pub(super) fn depth_texture_ptr() -> Option<*mut c_void> {
    let ptr = RESOLVED_WORLD_DEPTH_TEXTURE.load(Ordering::Acquire);
    (ptr != 0).then_some(ptr as *mut c_void)
}

pub(super) fn first_person_depth_texture_ptr() -> Option<*mut c_void> {
    let ptr = RESOLVED_FIRST_PERSON_DEPTH_TEXTURE.load(Ordering::Acquire);
    (ptr != 0).then_some(ptr as *mut c_void)
}

pub(super) unsafe fn resolve_scene_depth(
    device_ptr: *mut c_void,
    slot: DepthResolveSlot,
    reason: &'static str,
) -> bool {
    match unsafe { DEPTH_RESOLVE.lock().resolve(device_ptr, slot, reason) } {
        Ok(()) => true,
        Err(err) => {
            log_depth_resolve_skip(slot, reason, &err);
            false
        }
    }
}

pub(super) fn finish_frame() {
    RESOLVED_WORLD_DEPTH_TEXTURE.store(0, Ordering::Release);
    RESOLVED_FIRST_PERSON_DEPTH_TEXTURE.store(0, Ordering::Release);
}

pub(super) fn reset_depth_resources() {
    RESOLVED_WORLD_DEPTH_TEXTURE.store(0, Ordering::Release);
    RESOLVED_FIRST_PERSON_DEPTH_TEXTURE.store(0, Ordering::Release);
    DEPTH_RESOLVE.lock().release();
}

unsafe fn read_ptr(address: usize) -> Option<*mut u8> {
    unsafe { read_ptr_checked(address, "unreadable pointer").ok() }
}

unsafe fn read_ptr_checked(address: usize, cause: &'static str) -> Result<*mut u8, &'static str> {
    let slot = address as *const c_void;
    validate_memory_range(slot, size_of::<*mut u8>()).map_err(|_| cause)?;
    Ok(unsafe { (address as *const *mut u8).read() })
}

unsafe fn read_f32(address: usize) -> Option<f32> {
    let slot = address as *const c_void;
    validate_memory_range(slot, size_of::<f32>()).ok()?;
    Some(unsafe { (address as *const f32).read() })
}

fn log_depth_resolve_skip(
    slot: DepthResolveSlot,
    reason: &'static str,
    err: &FnvDepthResolveError,
) {
    if DEPTH_RESOLVE_LOGS.fetch_add(1, Ordering::AcqRel) < MAX_DEPTH_RESOLVE_LOGS {
        log::warn!(
            "[FNV] Active D3D depth resolve skipped: slot={}, reason={reason}, err={err}",
            slot.label()
        );
    }
}

#[derive(Default)]
struct FnvDepthResolve {
    device_ptr: usize,
    world_target: Option<FnvDepthTarget>,
    first_person_target: Option<FnvDepthTarget>,
    state_block: Option<StateBlock9>,
    success_logs: u32,
}

impl FnvDepthResolve {
    unsafe fn resolve(
        &mut self,
        device_ptr: *mut c_void,
        slot: DepthResolveSlot,
        reason: &'static str,
    ) -> Result<(), FnvDepthResolveError> {
        let Some(device) = (unsafe { Device9Ref::from_raw_void(device_ptr) }) else {
            return Err(FnvDepthResolveError::Static("null D3D device"));
        };

        if self.device_ptr != 0 && self.device_ptr != device_ptr as usize {
            self.release();
        }
        self.device_ptr = device_ptr as usize;

        let source_surface = device.depth_stencil_surface()?;
        let Some(source_surface) = source_surface.as_ref() else {
            return Err(FnvDepthResolveError::Static(
                "missing active D3D depth surface",
            ));
        };
        let desc = source_surface.desc()?;
        if desc.Width == 0 || desc.Height == 0 {
            return Err(FnvDepthResolveError::Static("empty depth surface"));
        }

        self.ensure_resources(&device, &desc, slot)?;

        let Some(target) = self.target(slot).as_ref() else {
            return Err(FnvDepthResolveError::Static("missing INTZ target"));
        };
        let Some(state_block) = self.state_block.as_ref() else {
            return Err(FnvDepthResolveError::Static("missing D3D state block"));
        };

        state_block.capture()?;
        let states = D3dResolveStates::capture(&device)?;
        let original_depth = device.depth_stencil_surface()?;

        let draw_result = (|| -> Direct3DResult<()> { target.resolve(&device) })();

        let restore_result = states.restore_before_resz(&device);
        let resz_result = device.set_render_state(D3DRS_POINTSIZE, D3DRESZ_POINT_SIZE);
        let point_size_restore_result = device.set_render_state(D3DRS_POINTSIZE, states.point_size);
        let state_restore_result = state_block.apply();

        draw_result?;
        restore_result?;
        resz_result?;
        point_size_restore_result?;
        state_restore_result?;
        device.set_depth_stencil_surface(original_depth.as_ref())?;

        let texture_ptr = target.texture.as_raw_base_texture() as usize;
        match slot {
            DepthResolveSlot::World => {
                RESOLVED_WORLD_DEPTH_TEXTURE.store(texture_ptr, Ordering::Release);
            }
            DepthResolveSlot::FirstPerson => {
                RESOLVED_FIRST_PERSON_DEPTH_TEXTURE.store(texture_ptr, Ordering::Release);
            }
        }
        self.log_success(slot, reason, &desc);
        Ok(())
    }

    fn ensure_resources(
        &mut self,
        device: &Device9Ref<'_>,
        desc: &D3DSURFACE_DESC,
        slot: DepthResolveSlot,
    ) -> Result<(), FnvDepthResolveError> {
        let needs_target = self
            .target(slot)
            .as_ref()
            .is_none_or(|target| !target.matches(desc));

        if needs_target {
            *self.target_mut(slot) = Some(FnvDepthTarget::create(device, desc)?);
            log::info!(
                "[FNV] INTZ depth target: slot={}, size={}x{}",
                slot.label(),
                desc.Width,
                desc.Height
            );
        }

        if self.state_block.is_none() {
            self.state_block = Some(device.create_state_block(D3DSBT_ALL)?);
        }

        Ok(())
    }

    fn target(&self, slot: DepthResolveSlot) -> &Option<FnvDepthTarget> {
        match slot {
            DepthResolveSlot::World => &self.world_target,
            DepthResolveSlot::FirstPerson => &self.first_person_target,
        }
    }

    fn target_mut(&mut self, slot: DepthResolveSlot) -> &mut Option<FnvDepthTarget> {
        match slot {
            DepthResolveSlot::World => &mut self.world_target,
            DepthResolveSlot::FirstPerson => &mut self.first_person_target,
        }
    }

    fn log_success(
        &mut self,
        slot: DepthResolveSlot,
        reason: &'static str,
        desc: &D3DSURFACE_DESC,
    ) {
        if self.success_logs < 8 {
            log::debug!(
                "[FNV] Active D3D depth resolved: slot={}, reason={reason}, size={}x{}",
                slot.label(),
                desc.Width,
                desc.Height
            );
            self.success_logs += 1;
        }
    }

    fn release(&mut self) {
        self.device_ptr = 0;
        self.world_target = None;
        self.first_person_target = None;
        self.state_block = None;
    }
}

struct FnvDepthTarget {
    width: u32,
    height: u32,
    texture: Texture9,
}

impl FnvDepthTarget {
    fn create(
        device: &Device9Ref<'_>,
        desc: &D3DSURFACE_DESC,
    ) -> Result<Self, FnvDepthResolveError> {
        device.direct3d()?.check_default_resz_support()?;
        let texture = device.create_depth_stencil_texture(desc.Width, desc.Height, D3DFMT_INTZ)?;

        Ok(Self {
            width: desc.Width,
            height: desc.Height,
            texture,
        })
    }

    fn matches(&self, desc: &D3DSURFACE_DESC) -> bool {
        self.width == desc.Width && self.height == desc.Height
    }

    fn resolve(&self, device: &Device9Ref<'_>) -> Direct3DResult<()> {
        device.set_texture(0, &self.texture)?;
        device.clear_vertex_shader()?;
        device.clear_pixel_shader()?;
        device.set_fvf(PositionVertex::FVF)?;
        device.set_render_state(D3DRS_CULLMODE, D3DCULL_NONE.0 as u32)?;
        device.set_render_state(D3DRS_ALPHABLENDENABLE, 0)?;
        device.set_render_state(D3DRS_ZENABLE, 0)?;
        device.set_render_state(D3DRS_ZWRITEENABLE, 0)?;
        device.set_render_state(D3DRS_COLORWRITEENABLE, 0)?;

        let point = [PositionVertex::origin()];
        unsafe {
            device.draw_primitive_up(D3DPT_POINTLIST, 1, &point)?;
        }

        Ok(())
    }
}

#[derive(Clone, Copy)]
struct D3dResolveStates {
    cull: u32,
    alpha_blend: u32,
    z_enable: u32,
    z_write: u32,
    color_write: u32,
    point_size: u32,
}

impl D3dResolveStates {
    fn capture(device: &Device9Ref<'_>) -> Direct3DResult<Self> {
        Ok(Self {
            cull: device.render_state(D3DRS_CULLMODE)?,
            alpha_blend: device.render_state(D3DRS_ALPHABLENDENABLE)?,
            z_enable: device.render_state(D3DRS_ZENABLE)?,
            z_write: device.render_state(D3DRS_ZWRITEENABLE)?,
            color_write: device.render_state(D3DRS_COLORWRITEENABLE)?,
            point_size: device.render_state(D3DRS_POINTSIZE)?,
        })
    }

    fn restore_before_resz(self, device: &Device9Ref<'_>) -> Direct3DResult<()> {
        device.set_render_state(D3DRS_COLORWRITEENABLE, self.color_write)?;
        device.set_render_state(D3DRS_ZWRITEENABLE, self.z_write)?;
        device.set_render_state(D3DRS_ZENABLE, self.z_enable)?;
        device.set_render_state(D3DRS_ALPHABLENDENABLE, self.alpha_blend)?;
        device.set_render_state(D3DRS_CULLMODE, self.cull)?;
        Ok(())
    }
}

#[derive(Debug)]
enum FnvDepthResolveError {
    Static(&'static str),
    D3d(WindowsError),
}

impl fmt::Display for FnvDepthResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static(message) => f.write_str(message),
            Self::D3d(err) => write!(f, "{err}"),
        }
    }
}

impl From<WindowsError> for FnvDepthResolveError {
    fn from(value: WindowsError) -> Self {
        Self::D3d(value)
    }
}

impl From<&'static str> for FnvDepthResolveError {
    fn from(value: &'static str) -> Self {
        Self::Static(value)
    }
}
