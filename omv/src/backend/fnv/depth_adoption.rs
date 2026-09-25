//! Prepare existing depth for replacement at a complete native clear.
//!
//! This is the executable D3D half of the native ClearBuffer contract. It
//! refuses partial depth/stencil coverage and incompatible color attachments.
//! A candidate is initialized before native ownership changes, with the old
//! binding and viewport restored on every result. Only the first adoption of
//! a native identity allocates; already-owned clears bypass this module.

use libpsycho::os::windows::directx9::*;

/// Inputs read at NiDX9Renderer::ClearBuffer, before its initializing clear.
/// The rectangle uses native left/right/top/bottom normalized coordinates.
pub(super) struct NativeClear {
    pub flags: u32,
    pub rectangle: Option<[f32; 4]>,
    pub origin: [u32; 2],
    pub depth: f32,
    pub stencil: u32,
}

/// Prepare an initialized INTZ candidate without changing the native owner.
/// Returns `None` when replacing the source would discard retained pixels or
/// stencil. Errors leave ownership unchanged and attempt both state restores;
/// a failed restore is returned even if preparation otherwise succeeded.
/// Caller owns the render thread and source lifetime throughout this call.
pub(super) fn prepare(
    device: &Device9Ref<'_>,
    source: &Surface9,
    clear: &NativeClear,
    mrt_count: u32,
) -> Direct3DResult<Option<(Texture9, Surface9)>> {
    let desc = source.desc()?;
    if desc.Format != D3DFMT_D24S8
        || desc.MultiSampleType != D3DMULTISAMPLE_NONE
        || clear.flags & 6 != 6
        || clear.origin != [0, 0]
        || clear.rectangle.is_some_and(|r| r != [0.0, 1.0, 1.0, 0.0])
        || !clear.depth.is_finite()
        || !(0.0..=1.0).contains(&clear.depth)
        || device
            .depth_stencil_surface()?
            .as_ref()
            .map(Surface9::as_raw)
            != Some(source.as_raw())
    {
        return Ok(None);
    }
    for index in 0..mrt_count.clamp(1, 4) {
        let Some(color) = device.optional_render_target(index)? else {
            if index == 0 {
                return Ok(None);
            }
            continue;
        };
        let color = color.desc()?;
        if color.MultiSampleType != D3DMULTISAMPLE_NONE
            || color.Width > desc.Width
            || color.Height > desc.Height
            || (index == 0 && (color.Width != desc.Width || color.Height != desc.Height))
        {
            return Ok(None);
        }
        device.check_depth_stencil_match(color.Format, D3DFMT_INTZ)?;
    }
    // D3D9 Clear is clipped by both viewport and enabled scissor. Native
    // ClearBuffer expands viewport dimensions, but retains its stored origin.
    if device.render_state(D3DRS_SCISSORTESTENABLE)? != 0 {
        let rect = device.scissor_rect()?;
        if rect.left > 0
            || rect.top > 0
            || i64::from(rect.right) < i64::from(desc.Width)
            || i64::from(rect.bottom) < i64::from(desc.Height)
        {
            return Ok(None);
        }
    }
    let texture = device.create_depth_stencil_texture(desc.Width, desc.Height, D3DFMT_INTZ)?;
    let surface = texture.surface_level(0)?;
    let viewport = device.viewport()?;
    let result = (|| {
        device.set_depth_stencil_surface(Some(&surface))?;
        device.set_viewport(&D3DVIEWPORT9 {
            X: 0,
            Y: 0,
            Width: desc.Width,
            Height: desc.Height,
            MinZ: viewport.MinZ,
            MaxZ: viewport.MaxZ,
        })?;
        device.clear_attachments(
            (D3DCLEAR_ZBUFFER | D3DCLEAR_STENCIL) as u32,
            0,
            clear.depth,
            clear.stencil,
        )
    })();
    // No native call occurs while the device binding temporarily differs
    // from its cache. Restore both states even after a failed D3D operation.
    let depth_restore = device.set_depth_stencil_surface(Some(source));
    let viewport_restore = device.set_viewport(&viewport);
    depth_restore?;
    viewport_restore?;
    result?;
    Ok(Some((texture, surface)))
}
