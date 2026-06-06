//! Active game backend for the portable D3D9 renderer.

use core::ffi::c_void;

use windows::Win32::Graphics::Direct3D9::D3DSURFACE_DESC;

use crate::config::DepthProviderConfig;

mod fnv;

pub(crate) fn d3d_device_ptr() -> Option<*mut c_void> {
    fnv::d3d_device_ptr()
}

pub(crate) fn startup_log(depth_provider: DepthProvider) {
    log::info!("[BACKEND] Active backend: Fallout New Vegas");
    log::info!("[BACKEND] Depth provider: {}", depth_provider.label());
}

pub(crate) fn camera_frame(depth_provider: DepthProvider, desc: &D3DSURFACE_DESC) -> CameraFrame {
    match depth_provider {
        DepthProvider::None => CameraFrame::fallback(desc),
        DepthProvider::FalloutNewVegas => fnv::camera_frame(desc),
    }
}

pub(crate) fn depth_texture_ptr(depth_provider: DepthProvider) -> Option<*mut c_void> {
    match depth_provider {
        DepthProvider::None => None,
        DepthProvider::FalloutNewVegas => fnv::depth_texture_ptr(),
    }
}

pub(crate) unsafe fn resolve_scene_depth(
    depth_provider: DepthProvider,
    device_ptr: *mut c_void,
    reason: &'static str,
) -> bool {
    match depth_provider {
        DepthProvider::None => false,
        DepthProvider::FalloutNewVegas => unsafe { fnv::resolve_scene_depth(device_ptr, reason) },
    }
}

pub(crate) fn finish_frame() {
    fnv::finish_frame();
}

pub(crate) fn reset_depth_resources() {
    fnv::reset_depth_resources();
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum DepthProvider {
    #[default]
    None,
    FalloutNewVegas,
}

impl DepthProvider {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::FalloutNewVegas => "fallout_new_vegas",
        }
    }
}

impl From<DepthProviderConfig> for DepthProvider {
    fn from(value: DepthProviderConfig) -> Self {
        match value {
            DepthProviderConfig::None => Self::None,
            DepthProviderConfig::FalloutNewVegas => Self::FalloutNewVegas,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct FrameInputs {
    pub(crate) camera: CameraFrame,
    pub(crate) depth: DepthFrame,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DepthFrame {
    pub(crate) provider: DepthProvider,
    pub(crate) texture: Option<DepthTexture>,
}

impl DepthFrame {
    pub(crate) fn none() -> Self {
        Self {
            provider: DepthProvider::None,
            texture: None,
        }
    }

    pub(crate) fn from_texture(provider: DepthProvider, texture: DepthTexture) -> Self {
        Self {
            provider,
            texture: Some(texture),
        }
    }

    pub(crate) fn is_available(self) -> bool {
        self.texture.is_some()
    }

    pub(crate) fn provider_id(self) -> f32 {
        match self.provider {
            DepthProvider::None => 0.0,
            DepthProvider::FalloutNewVegas => 2.0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DepthTexture {
    ptr: *mut c_void,
}

impl DepthTexture {
    pub(crate) fn new(ptr: *mut c_void) -> Option<Self> {
        (!ptr.is_null()).then_some(Self { ptr })
    }

    pub(crate) fn as_ptr(self) -> *mut c_void {
        self.ptr
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CameraFrame {
    pub(crate) near_z: f32,
    pub(crate) far_z: f32,
    pub(crate) aspect_ratio: f32,
}

impl CameraFrame {
    pub(crate) fn fallback(desc: &D3DSURFACE_DESC) -> Self {
        let aspect_ratio = if desc.Height > 0 {
            desc.Width as f32 / desc.Height as f32
        } else {
            1.0
        };

        Self {
            near_z: 0.0,
            far_z: 0.0,
            aspect_ratio,
        }
    }
}

impl Default for CameraFrame {
    fn default() -> Self {
        Self {
            near_z: 0.0,
            far_z: 0.0,
            aspect_ratio: 1.0,
        }
    }
}
