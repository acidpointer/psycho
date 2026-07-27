//! Direct3D 9 state transactions shared by OMV screen-space pipelines.
//!
//! D3D9 all-state blocks do not capture render targets or the depth-stencil
//! attachment. OMV therefore snapshots those attachments separately and
//! restores them before applying the state block. That ordering is mandatory:
//! `SetRenderTarget` resets viewport and scissor state, so applying the state
//! block last makes the engine's raster state authoritative again.
//!
//! The module also owns the phase-color copy contract. The current phase copy
//! may be bound at both `s0` and fallback world-color sampler `s3`; every write
//! unbinds both aliases before `StretchRect` to avoid driver-dependent feedback
//! corruption.

use libpsycho::os::windows::directx9::{
    D3DTEXF_NONE, Device9Ref, Direct3DResult, StateBlock9, Surface9, Texture9, direct3d_failure,
};

const MAX_D3D9_RENDER_TARGETS: u32 = 4;
const SCENE_COPY_SAMPLERS: [u32; 2] = [0, 3];

/// Capability-bounded render-target slots used by one D3D9 device.
///
/// D3D9 exposes at most four simultaneous targets. Keeping the normalized count
/// in the runtime avoids querying device capabilities in each render pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RenderTargetSlots {
    count: u32,
}

impl RenderTargetSlots {
    /// Query and normalize the render-target count for `device`.
    pub(crate) fn query(device: &Device9Ref<'_>) -> Direct3DResult<Self> {
        Ok(Self::from_reported(
            device.simultaneous_render_target_count()?,
        ))
    }

    fn from_reported(count: u32) -> Self {
        Self {
            count: count.clamp(1, MAX_D3D9_RENDER_TARGETS),
        }
    }

    /// Unbind every supported auxiliary render target without touching RT0.
    pub(crate) fn clear_auxiliary(self, device: &Device9Ref<'_>) -> Direct3DResult<()> {
        for index in self.auxiliary_indices() {
            device.clear_render_target(index)?;
        }
        Ok(())
    }

    /// Detach attachments that can make a subsequent RT0 binding incompatible.
    pub(crate) fn prepare_target_change(self, device: &Device9Ref<'_>) -> Direct3DResult<()> {
        device.set_depth_stencil_surface(None)?;
        self.clear_auxiliary(device)
    }

    fn auxiliary_indices(self) -> std::ops::Range<u32> {
        1..self.count
    }
}

/// Snapshot of attachments omitted from a D3D9 `D3DSBT_ALL` state block.
pub(crate) struct RenderAttachments {
    targets: [Option<Surface9>; MAX_D3D9_RENDER_TARGETS as usize],
    depth: Option<Surface9>,
    slots: RenderTargetSlots,
}

impl RenderAttachments {
    /// Capture all render-target slots supported by the device and optional depth.
    pub(crate) fn capture(
        device: &Device9Ref<'_>,
        slots: RenderTargetSlots,
    ) -> Direct3DResult<Self> {
        let mut targets = std::array::from_fn(|_| None);
        targets[0] = Some(device.render_target(0)?);
        for index in slots.auxiliary_indices() {
            targets[index as usize] = device.optional_render_target(index)?;
        }
        Ok(Self {
            targets,
            depth: device.depth_stencil_surface()?,
            slots,
        })
    }

    /// Restore every captured attachment while preserving the first D3D failure.
    pub(crate) fn restore(&self, device: &Device9Ref<'_>) -> Direct3DResult<()> {
        // Depth and auxiliary targets can be incompatible with RT0's dimensions
        // or multisample mode. Detach them before changing RT0, then rebuild the
        // exact engine attachment set in dependency order.
        let mut result = device.set_depth_stencil_surface(None);
        for index in self.slots.auxiliary_indices() {
            keep_first_error(&mut result, device.clear_render_target(index));
        }
        if let Some(target0) = self.targets[0].as_ref() {
            keep_first_error(&mut result, device.set_render_target(0, target0));
        }
        for index in self.slots.auxiliary_indices() {
            keep_first_error(
                &mut result,
                restore_target(device, index, self.targets[index as usize].as_ref()),
            );
        }
        keep_first_error(
            &mut result,
            device.set_depth_stencil_surface(self.depth.as_ref()),
        );
        result
    }
}

/// Finish a screen draw and restore all native D3D state on every result path.
pub(crate) fn finish_render_transaction(
    device: &Device9Ref<'_>,
    attachments: &RenderAttachments,
    state_block: Option<&StateBlock9>,
    mut draw_result: Direct3DResult<()>,
) -> Direct3DResult<()> {
    // SetRenderTarget resets viewport and scissor state. Attachments must
    // therefore be restored first and the all-state block applied last.
    keep_first_error(&mut draw_result, attachments.restore(device));
    keep_first_error(
        &mut draw_result,
        state_block.map_or_else(|| Err(direct3d_failure()), StateBlock9::apply),
    );
    draw_result
}

/// Copy a screen-color surface into a texture that will be sampled by OMV.
///
/// The phase copy participates in two shader ABIs: `s0` is the current effect
/// input and `s3` is the fallback world-color input. Both bindings must be
/// cleared before the texture's surface becomes a `StretchRect` destination.
/// `sampler3_texture` is rebound only after the write completes so downstream
/// loose shaders retain their world-color contract.
pub(crate) fn copy_scene_color_for_sampling(
    device: &Device9Ref<'_>,
    source: &Surface9,
    destination: &Surface9,
    sampler3_texture: &Texture9,
) -> Direct3DResult<()> {
    for sampler in SCENE_COPY_SAMPLERS {
        device.clear_texture(sampler)?;
    }
    // Source and destination have identical phase dimensions, so NONE performs
    // an exact copy without requiring optional StretchRect filtering support.
    device.stretch_rect(source, None, destination, None, D3DTEXF_NONE)?;
    // s3 remains part of the public loose-shader ABI. Rebind only after the
    // destination is no longer writable so downstream shaders retain either
    // the captured world color or the documented current-color fallback.
    device.set_texture(3, sampler3_texture)
}

fn restore_target(
    device: &Device9Ref<'_>,
    index: u32,
    target: Option<&Surface9>,
) -> Direct3DResult<()> {
    match target {
        Some(target) => device.set_render_target(index, target),
        None => device.clear_render_target(index),
    }
}

fn keep_first_error(result: &mut Direct3DResult<()>, next: Direct3DResult<()>) {
    if result.is_ok() && next.is_err() {
        *result = next;
    }
}

#[cfg(test)]
mod tests {
    use super::{RenderTargetSlots, SCENE_COPY_SAMPLERS};

    #[test]
    fn render_target_slots_are_bounded_to_the_d3d9_contract() {
        assert_eq!(RenderTargetSlots::from_reported(0).count, 1);
        assert_eq!(RenderTargetSlots::from_reported(1).count, 1);
        assert_eq!(RenderTargetSlots::from_reported(2).count, 2);
        assert_eq!(RenderTargetSlots::from_reported(4).count, 4);
        assert_eq!(RenderTargetSlots::from_reported(8).count, 4);
        assert_eq!(
            RenderTargetSlots::from_reported(1)
                .auxiliary_indices()
                .collect::<Vec<_>>(),
            []
        );
        assert_eq!(
            RenderTargetSlots::from_reported(4)
                .auxiliary_indices()
                .collect::<Vec<_>>(),
            [1, 2, 3]
        );
    }

    #[test]
    fn phase_copy_unbinds_primary_and_fallback_aliases() {
        fn alias_remains_after(unbound: &[u32]) -> bool {
            let mut aliases = [false; 4];
            aliases[0] = true;
            aliases[3] = true;
            for &sampler in unbound {
                aliases[sampler as usize] = false;
            }
            aliases.into_iter().any(|alias| alias)
        }

        // This negative control models the reported implementation: clearing
        // only s0 leaves the same destination texture live at fallback s3.
        assert!(alias_remains_after(&[0]));
        assert!(!alias_remains_after(&SCENE_COPY_SAMPLERS));
    }

    #[test]
    fn phase_copy_uses_an_exact_unfiltered_stretch() {
        let source = include_str!("render_state.rs");
        let signature = ["pub(crate) fn copy_scene_color_", "for_sampling("].concat();
        let body = source
            .split_once(&signature)
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\n}\n"))
            .map(|(body, _)| body)
            .expect("phase-copy helper body");
        assert!(body.contains("for sampler in SCENE_COPY_SAMPLERS"));
        assert!(body.contains("D3DTEXF_NONE"));
        assert!(!body.contains("D3DTEXF_POINT"));
        let unbind = body.find("device.clear_texture").expect("sampler unbind");
        let copy = body.find("device.stretch_rect").expect("surface copy");
        let rebind = body.find("device.set_texture").expect("sampler rebind");
        assert!(unbind < copy);
        assert!(copy < rebind);
    }

    #[test]
    fn missing_depth_surface_uses_the_documented_hresult() {
        let source = include_str!("../../libpsycho/src/os/windows/directx9.rs");
        let signature = ["pub fn depth_stencil_", "surface(&self)"].concat();
        let body = source
            .split_once(&signature)
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\n    }\n"))
            .map(|(body, _)| body)
            .expect("depth-stencil query body");
        assert!(body.contains("D3DERR_NOTFOUND"));
        assert!(!body.contains("E_POINTER"));
    }
}
