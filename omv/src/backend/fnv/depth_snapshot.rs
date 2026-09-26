//! Raw single-sample depth snapshots through the production SM3 shader.
//!
//! CPU bytecode is prepared at DeferredInit. The small zero-initialized slot
//! owns its heap state only afterward; it adds no pre-deferred worker or TLS.
//! Default-pool resources belong to one device and are retired before Reset.
//! Captures never compile, block, or publish a partially rendered texture.

use super::DepthResolveSlot;
use crate::render_state::{RenderAttachments, RenderTargetSlots, finish_exact_render_transaction};
use libpsycho::os::windows::directx9::*;
use parking_lot::Mutex;

pub(super) const SOURCE: &str = include_str!("../../../shaders/embedded/depth_snapshot.hlsl");
static SERVICE: Mutex<Option<Box<Service>>> = Mutex::new(None);

struct Service {
    bytecode: Vec<u32>,
    pipeline: Option<Pipeline>,
    current: bool,
    captures: u32,
}

struct Target {
    texture: Texture9,
    surface: Surface9,
    width: u32,
    height: u32,
}

struct Pipeline {
    device: usize,
    shader: PixelShader9,
    slots: RenderTargetSlots,
    vertex_textures: bool,
    targets: [Option<Target>; 2],
}

/// Prepare the one shipped shader at the deferred handoff, never from capture.
pub(super) fn prepare() -> anyhow::Result<()> {
    let mut service = SERVICE.lock();
    if service.is_none() {
        let bytecode = crate::shaders::compile_hlsl_source_target(
            "depth_snapshot.hlsl",
            SOURCE.as_bytes(),
            "ps_3_0",
        )?;
        *service = Some(Box::new(Service {
            bytecode,
            pipeline: None,
            current: false,
            captures: 0,
        }));
    }
    Ok(())
}

/// Release all GPU snapshot references before Reset or a provider transition.
/// Contention leaves ownership intact and prevents the caller entering Reset.
pub(super) fn release() -> bool {
    let Some(mut guard) = SERVICE.try_lock() else {
        return false;
    };
    let old = guard.as_mut().and_then(|service| {
        service.current = false;
        service.pipeline.take()
    });
    drop(guard);
    drop(old);
    true
}

/// Whether the last successful physical transport used this snapshot route.
pub(super) fn is_current() -> bool {
    SERVICE
        .try_lock()
        .is_some_and(|s| s.as_ref().is_some_and(|s| s.current))
}

/// Cumulative successful snapshot draws, separate from vendor copy counters.
pub(super) fn capture_count() -> u32 {
    SERVICE
        .try_lock()
        .and_then(|s| s.as_ref().map(|s| s.captures))
        .unwrap_or(0)
}

/// Mark a failed or legacy capture without retiring still-consumed snapshots.
pub(super) fn mark_unused() {
    if let Some(mut service) = SERVICE.try_lock() {
        if let Some(service) = service.as_mut() {
            service.current = false;
        }
    }
}

/// Check whether the persistent world destination can serve the next epoch.
pub(super) fn world_target_matches(device: usize, width: u32, height: u32) -> bool {
    SERVICE.try_lock().is_some_and(|service| {
        service
            .as_ref()
            .and_then(|s| s.pipeline.as_ref())
            .is_some_and(|p| {
                p.device == device
                    && p.targets[0]
                        .as_ref()
                        .is_some_and(|t| t.width == width && t.height == height)
            })
    })
}

/// Capture a live single-sample INTZ texture surface into stable raw R32F.
/// `image_extent` is the paired native color extent, starting at attachment
/// pixel (0, 0). Larger shared depth backing is cropped without resampling:
/// native D3D9 color and depth attachments address the same integer pixels.
/// The returned pointer is borrowed until reset/provider change or reuse of
/// this semantic slot. The caller must preserve its stage/camera/epoch rules.
pub(super) fn capture(
    device: &Device9Ref<'_>,
    source: &Surface9,
    slot: DepthResolveSlot,
    image_extent: [u32; 2],
) -> Direct3DResult<usize> {
    let desc = source.desc()?;
    if desc.Format != D3DFMT_INTZ
        || desc.MultiSampleType != D3DMULTISAMPLE_NONE
        || desc.Width == 0
        || desc.Height == 0
        || image_extent[0] == 0
        || image_extent[1] == 0
        || image_extent[0] > desc.Width
        || image_extent[1] > desc.Height
    {
        return Err(direct3d_failure());
    }
    let texture = source.texture_container()?.ok_or_else(direct3d_failure)?;
    // A texture container is authoritative ownership evidence; requiring the
    // exact level-zero surface also excludes accidental mip/cube aliasing.
    if texture.surface_level(0)?.as_raw() != source.as_raw() {
        return Err(direct3d_failure());
    }
    let Some(mut guard) = SERVICE.try_lock() else {
        return Err(direct3d_failure());
    };
    let service = guard.as_mut().ok_or_else(direct3d_failure)?;
    service.current = false;
    if service
        .pipeline
        .as_ref()
        .is_none_or(|p| p.device != device.as_raw() as usize)
    {
        service.pipeline = Some(Pipeline {
            device: device.as_raw() as usize,
            shader: device.create_pixel_shader(&service.bytecode)?,
            slots: RenderTargetSlots::query(device)?,
            vertex_textures: device.device_caps()?.VertexTextureFilterCaps != 0,
            targets: [None, None],
        });
    }
    let pipeline = service.pipeline.as_mut().ok_or_else(direct3d_failure)?;
    let index = match slot {
        DepthResolveSlot::World => 0,
        DepthResolveSlot::FirstPerson => 1,
    };
    if pipeline.targets[index]
        .as_ref()
        .is_none_or(|t| t.width != image_extent[0] || t.height != image_extent[1])
    {
        let texture =
            device.create_render_target_texture(image_extent[0], image_extent[1], D3DFMT_R32F)?;
        let surface = texture.surface_level(0)?;
        pipeline.targets[index] = Some(Target {
            texture,
            surface,
            width: image_extent[0],
            height: image_extent[1],
        });
    }
    let target = pipeline.targets[index]
        .as_ref()
        .ok_or_else(direct3d_failure)?;
    let mut attachments = RenderAttachments::capture(device, pipeline.slots)?;
    // The snapshot draw disables depth testing and writing, so a compatible
    // bound depth stays bound through the draw. Retention removes the
    // detach/rebind pair that would split the driver render pass around the
    // draw; the restored attachment set is unchanged either way.
    attachments.retain_compatible_depth(device, target.width, target.height, D3DFMT_R32F);
    // Only journal states this draw mutates. Broad state blocks also replay
    // unrelated native constants, transforms, lights and texture-stage state.
    let state = DepthSnapshotState9::capture(device, pipeline.vertex_textures)?;
    let draw = (|| {
        if attachments.depth_retained() {
            pipeline.slots.clear_auxiliary(device)?;
        } else {
            pipeline.slots.prepare_target_change(device)?;
        }
        // A previous consumer may still have either snapshot bound. Remove all
        // pixel sampler aliases before binding the snapshot as a target.
        for sampler in 0..16 {
            device.clear_texture(sampler)?;
        }
        if pipeline.vertex_textures {
            for sampler in 257..261 {
                device.clear_texture(sampler)?;
            }
        }
        device.set_render_target(0, &target.surface)?;
        device.set_viewport(&D3DVIEWPORT9 {
            X: 0,
            Y: 0,
            Width: target.width,
            Height: target.height,
            MinZ: 0.0,
            MaxZ: 1.0,
        })?;
        device.clear_vertex_shader()?;
        device.set_fvf(ScreenVertex::FVF)?;
        device.set_stream_source_frequency(0, 1)?;
        device.set_pixel_shader(&pipeline.shader)?;
        for (state, value) in [
            (D3DRS_ZENABLE, 0),
            (D3DRS_ZWRITEENABLE, 0),
            (D3DRS_STENCILENABLE, 0),
            (D3DRS_ALPHATESTENABLE, 0),
            (D3DRS_ALPHABLENDENABLE, 0),
            (D3DRS_CULLMODE, D3DCULL_NONE.0 as u32),
            (D3DRS_SCISSORTESTENABLE, 0),
            (D3DRS_FOGENABLE, 0),
            (D3DRS_CLIPPLANEENABLE, 0),
            (D3DRS_SRGBWRITEENABLE, 0),
            (D3DRS_COLORWRITEENABLE, 15),
            (D3DRS_MULTISAMPLEANTIALIAS, 0),
            (D3DRS_MULTISAMPLEMASK, u32::MAX),
        ] {
            device.set_render_state(state, value)?;
        }
        match super::alpha_coverage_mode() {
            super::AlphaCoverageMode::None => {}
            super::AlphaCoverageMode::Nvidia => device.set_render_state(D3DRS_ADAPTIVETESS_Y, 0)?,
            super::AlphaCoverageMode::Amd => {
                device.set_render_state(D3DRS_POINTSIZE, u32::from_le_bytes(*b"A2M0"))?
            }
        }
        for (state, value) in [
            (D3DSAMP_ADDRESSU, D3DTADDRESS_CLAMP.0 as u32),
            (D3DSAMP_ADDRESSV, D3DTADDRESS_CLAMP.0 as u32),
            (D3DSAMP_MINFILTER, D3DTEXF_POINT.0 as u32),
            (D3DSAMP_MAGFILTER, D3DTEXF_POINT.0 as u32),
            (D3DSAMP_MIPFILTER, D3DTEXF_NONE.0 as u32),
            (D3DSAMP_SRGBTEXTURE, 0),
        ] {
            device.set_sampler_state(0, state, value)?;
        }
        device.set_texture(0, &texture)?;
        let vertices = [
            ScreenVertex::new(-0.5, -0.5, 0.0, 0.0),
            ScreenVertex::new(
                target.width as f32 * 2.0 - 0.5,
                -0.5,
                2.0 * target.width as f32 / desc.Width as f32,
                0.0,
            ),
            ScreenVertex::new(
                -0.5,
                target.height as f32 * 2.0 - 0.5,
                0.0,
                2.0 * target.height as f32 / desc.Height as f32,
            ),
        ];
        // ScreenVertex's repr(C) and FVF exactly describe these three vertices.
        unsafe { device.draw_primitive_up(D3DPT_TRIANGLELIST, 1, &vertices) }
    })();
    finish_exact_render_transaction(device, &attachments, draw, || state.restore(device))?;
    service.current = true;
    service.captures = service.captures.saturating_add(1);
    Ok(target.texture.as_raw_base_texture() as usize)
}
