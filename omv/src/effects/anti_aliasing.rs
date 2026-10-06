//! Embedded spatial anti-aliasing pipelines.
//!
//! Every production variant is compiled by a process worker. The render path
//! creates D3D objects from immutable bytecode and never performs cache I/O.

use std::{
    sync::{
        LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use anyhow::Result;
use libpsycho::os::windows::directx9::{
    D3DCLEAR_TARGET, D3DFMT_A8R8G8B8, D3DRS_SRGBWRITEENABLE, D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV,
    D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER, D3DSAMP_MIPFILTER, D3DSAMP_SRGBTEXTURE, D3DSURFACE_DESC,
    D3DTADDRESS_CLAMP, D3DTEXF_LINEAR, D3DTEXF_NONE, D3DVIEWPORT9, Device9Ref, Direct3DResult,
    PixelShader9, ScreenVertex, Surface9, Texture9, direct3d_failure,
};

use crate::shaders::{self, EmbeddedEffectKind, ScreenShaderSource};
use parking_lot::Mutex;

#[cfg(test)]
mod image_tests;
mod smaa;

const FIRST_OPTION_REGISTER: u32 = 3;

const FAST_FXAA_SHADER: &[u8] = include_bytes!("../../shaders/embedded/aa_fast_fxaa.hlsl");
const NFAA_SHADER: &[u8] = include_bytes!("../../shaders/embedded/aa_nfaa.hlsl");
const AXAA_SHADER: &[u8] = include_bytes!("../../shaders/embedded/aa_axaa.hlsl");
const DLAA_PREFILTER_SHADER: &[u8] =
    include_bytes!("../../shaders/embedded/aa_dlaa_prefilter.hlsl");
const DLAA_RESOLVE_SHADER: &[u8] = include_bytes!("../../shaders/embedded/aa_dlaa_resolve.hlsl");
const SMAA_EDGES_SHADER: &[u8] = include_bytes!("../../shaders/embedded/aa_smaa_edges.hlsl");
const SMAA_WEIGHTS_SHADER: &[u8] = include_bytes!("../../shaders/embedded/aa_smaa_weights.hlsl");
const SMAA_BLEND_SHADER: &[u8] = include_bytes!("../../shaders/embedded/aa_smaa_blend.hlsl");

static COMPILE_STARTED: AtomicBool = AtomicBool::new(false);
static COMPILE_FAILED: AtomicBool = AtomicBool::new(false);
static COMPILE_READY: AtomicBool = AtomicBool::new(false);
static BYTECODE: LazyLock<Mutex<Option<AntiAliasingBytecode>>> = LazyLock::new(|| Mutex::new(None));

struct AntiAliasingBytecode {
    fast_fxaa: Vec<u32>,
    nfaa: Vec<u32>,
    axaa: Vec<u32>,
    dlaa_prefilter: Vec<u32>,
    dlaa_resolve: Vec<u32>,
    smaa_edges: Vec<u32>,
    smaa_weights: Vec<u32>,
    smaa_blend: Vec<u32>,
}

impl AntiAliasingBytecode {
    fn compile() -> Result<Self> {
        Ok(Self {
            fast_fxaa: shaders::compile_hlsl_source("aa_fast_fxaa.hlsl", FAST_FXAA_SHADER)?,
            nfaa: shaders::compile_hlsl_source("aa_nfaa.hlsl", NFAA_SHADER)?,
            axaa: shaders::compile_hlsl_source("aa_axaa.hlsl", AXAA_SHADER)?,
            dlaa_prefilter: shaders::compile_hlsl_source(
                "aa_dlaa_prefilter.hlsl",
                DLAA_PREFILTER_SHADER,
            )?,
            dlaa_resolve: shaders::compile_hlsl_source(
                "aa_dlaa_resolve.hlsl",
                DLAA_RESOLVE_SHADER,
            )?,
            smaa_edges: shaders::compile_hlsl_source(
                "aa_smaa_edges.hlsl",
                &smaa::source(SMAA_EDGES_SHADER),
            )?,
            smaa_weights: shaders::compile_hlsl_source(
                "aa_smaa_weights.hlsl",
                &smaa::source(SMAA_WEIGHTS_SHADER),
            )?,
            smaa_blend: shaders::compile_hlsl_source(
                "aa_smaa_blend.hlsl",
                &smaa::source(SMAA_BLEND_SHADER),
            )?,
        })
    }
}

/// Start process-owned spatial-AA shader preparation.
pub(crate) fn service_preparation() {
    if COMPILE_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    if let Err(err) = thread::Builder::new()
        .name("omv-spatial-aa-compile".to_owned())
        .spawn(
            || match super::shader_preparation::run_serialized(AntiAliasingBytecode::compile) {
                Ok(bytecode) => {
                    *BYTECODE.lock() = Some(bytecode);
                    COMPILE_READY.store(true, Ordering::Release);
                }
                Err(err) => {
                    COMPILE_FAILED.store(true, Ordering::Release);
                    log::warn!("[AA] Shader preparation failed: {err:#}");
                }
            },
        )
    {
        COMPILE_FAILED.store(true, Ordering::Release);
        log::warn!("[AA] Could not start shader preparation: {err}");
    }
}

/// Return whether every spatial-AA variant is ready for device creation.
pub(crate) fn preparation_ready() -> bool {
    COMPILE_READY.load(Ordering::Acquire) && !COMPILE_FAILED.load(Ordering::Acquire)
}

#[cfg(test)]
mod shader_compile_tests {
    use super::*;

    #[test]
    fn embedded_anti_aliasing_shaders_compile() {
        for (name, source) in [
            ("aa_fast_fxaa.hlsl", FAST_FXAA_SHADER),
            ("aa_nfaa.hlsl", NFAA_SHADER),
            ("aa_axaa.hlsl", AXAA_SHADER),
            ("aa_dlaa_prefilter.hlsl", DLAA_PREFILTER_SHADER),
            ("aa_dlaa_resolve.hlsl", DLAA_RESOLVE_SHADER),
            ("aa_smaa_edges.hlsl", SMAA_EDGES_SHADER),
            ("aa_smaa_weights.hlsl", SMAA_WEIGHTS_SHADER),
            ("aa_smaa_blend.hlsl", SMAA_BLEND_SHADER),
        ] {
            let assembled = if name.starts_with("aa_smaa_") {
                smaa::source(source)
            } else {
                source.to_vec()
            };
            crate::shaders::assert_hlsl_compiles(name, &assembled, "ps_3_0");
        }
    }

    /// Compiled-cost inventory for every spatial-AA variant family.
    ///
    /// Counts legacy ps_3_0 instruction tokens and static texture-op sites
    /// through OMV's real compilation path, mirroring the ambient-occlusion
    /// suite's budget pattern. Ceilings are pinned to the audited values so a
    /// quality-neutral optimization that lowers real cost must also lower its
    /// ceiling deliberately, and silent shader growth fails the suite.
    #[test]
    fn spatial_aa_variant_compiled_cost_inventory() {
        const COMMENT: u16 = 0xfffe;
        const END: u16 = 0xffff;
        const TEXLD: u16 = 66;
        const TEXLDD: u16 = 93;
        const TEXLDL: u16 = 95;

        let compiled_instruction_opcodes = |bytecode: &[u32]| -> Vec<u16> {
            let mut opcodes = Vec::new();
            let mut offset = 1usize;
            while offset < bytecode.len() {
                let token = bytecode[offset];
                let opcode = token as u16;
                if opcode == END {
                    break;
                }
                if opcode == COMMENT {
                    offset += 1 + ((token >> 16) & 0x7fff) as usize;
                    continue;
                }
                opcodes.push(opcode);
                offset += 1 + ((token >> 24) & 0x0f) as usize;
            }
            assert!(offset < bytecode.len(), "shader bytecode has no END token");
            opcodes
        };

        for (name, source, instruction_limit, texture_limit) in [
            ("aa_fast_fxaa.hlsl", FAST_FXAA_SHADER, 111, 9),
            ("aa_nfaa.hlsl", NFAA_SHADER, 138, 9),
            ("aa_axaa.hlsl", AXAA_SHADER, 372, 12),
            ("aa_dlaa_prefilter.hlsl", DLAA_PREFILTER_SHADER, 31, 5),
            ("aa_dlaa_resolve.hlsl", DLAA_RESOLVE_SHADER, 265, 17),
            ("aa_smaa_edges.hlsl", SMAA_EDGES_SHADER, 150, 14),
            // Full reference lookups, diagonal searches and actual corner
            // patterns replace the four-pixel analytic approximation.
            // The official diagonal/corner graph adds real bounded work. The
            // ceiling includes OMV's PS-side offsets and dynamic corner value;
            // this is a quality change, not a quality-neutral optimization.
            ("aa_smaa_weights.hlsl", SMAA_WEIGHTS_SHADER, 698, 40),
            ("aa_smaa_blend.hlsl", SMAA_BLEND_SHADER, 120, 9),
        ] {
            let assembled = if name.starts_with("aa_smaa_") {
                smaa::source(source)
            } else {
                source.to_vec()
            };
            let bytecode = crate::shaders::compile_hlsl_source_target(name, &assembled, "ps_3_0")
                .unwrap_or_else(|error| panic!("{name} failed to compile: {error:#}"));
            let opcodes = compiled_instruction_opcodes(&bytecode);
            let texture_count = opcodes
                .iter()
                .filter(|opcode| matches!(**opcode, TEXLD | TEXLDD | TEXLDL))
                .count();
            assert!(
                opcodes.len() <= instruction_limit,
                "{name} grew to {} instructions (limit {instruction_limit})",
                opcodes.len()
            );
            assert!(
                texture_count <= texture_limit,
                "{name} grew to {texture_count} texture sites (limit {texture_limit})"
            );
            // Inspect the actual compiled register operands, not source text.
            // SMAA owns s0..s2 and one interpolated UV; all shaders must stay
            // within SM3's 32 temporaries and 224 float constants.
            let mut offset = 1;
            while offset < bytecode.len() && bytecode[offset] as u16 != END {
                let token = bytecode[offset];
                if token as u16 == COMMENT {
                    offset += 1 + ((token >> 16) & 0x7fff) as usize;
                    continue;
                }
                let length = ((token >> 24) & 15) as usize;
                // DEF/DEFI/DEFB carry immediate words after their destination,
                // which must never be interpreted as register operands.
                let operands = if matches!(token as u16, 47 | 48 | 81) {
                    1
                } else {
                    length
                };
                for &parameter in &bytecode[offset + 1..offset + 1 + operands] {
                    if parameter & 0x8000_0000 == 0 {
                        continue;
                    }
                    let register_type = ((parameter >> 28) & 7) | ((parameter >> 8) & 24);
                    let register = parameter & 0x7ff;
                    match register_type {
                        0 => assert!(register < 32, "{name}: temporary r{register}"),
                        2 => assert!(register < 224, "{name}: float constant c{register}"),
                        10 if name.starts_with("aa_smaa_") => {
                            assert!(register < 3, "{name}: sampler s{register}")
                        }
                        1 if name.starts_with("aa_smaa_") => {
                            assert_eq!(register, 0, "{name}: extra interpolator")
                        }
                        _ => {}
                    }
                }
                offset += 1 + length;
            }
        }
    }

    #[test]
    fn dlaa_uses_rgb_luma() {
        for shader in [DLAA_PREFILTER_SHADER, DLAA_RESOLVE_SHADER] {
            let source = std::str::from_utf8(shader).expect("DLAA source is UTF-8");
            assert!(source.contains("dot(color, float3(0.2126, 0.7152, 0.0722))"));
            assert!(!source.contains("color.ggg"));
        }
    }
}

pub(crate) struct AntiAliasingEffect {
    fast_fxaa: PixelShader9,
    nfaa: PixelShader9,
    axaa: PixelShader9,
    dlaa_prefilter: PixelShader9,
    dlaa_resolve: PixelShader9,
    smaa_edges: PixelShader9,
    smaa_weights: PixelShader9,
    smaa_blend: PixelShader9,
    scratch_primary: Option<EffectTarget>,
    scratch_secondary: Option<SmaaTargetOwner>,
}

/// Preserve the existing inline AA/runtime owner size: lookup ownership lives
/// behind the former second-target slot, only allocated on the first SMAA draw.
struct SmaaTargetOwner {
    resources: Box<SmaaTargets>,
    _reserved: [usize; 4],
}

struct SmaaTargets {
    target: EffectTarget,
    lookup: smaa::LookupTextures,
}

const _: () = assert!(
    std::mem::size_of::<Option<SmaaTargetOwner>>() == std::mem::size_of::<Option<EffectTarget>>()
);

impl AntiAliasingEffect {
    /// Create device-owned AA shaders from prepared process bytecode.
    ///
    /// `Ok(None)` is a normal nonblocking result while preparation is active.
    pub(crate) fn create(device: &Device9Ref<'_>) -> Direct3DResult<Option<Self>> {
        service_preparation();
        if COMPILE_FAILED.load(Ordering::Acquire) {
            return Err(direct3d_failure());
        }
        if !COMPILE_READY.load(Ordering::Acquire) {
            return Ok(None);
        }
        let Some(bytecode) = BYTECODE.try_lock() else {
            return Ok(None);
        };
        let Some(bytecode) = bytecode.as_ref() else {
            return Ok(None);
        };
        Ok(Some(Self {
            fast_fxaa: device.create_pixel_shader(&bytecode.fast_fxaa)?,
            nfaa: device.create_pixel_shader(&bytecode.nfaa)?,
            axaa: device.create_pixel_shader(&bytecode.axaa)?,
            dlaa_prefilter: device.create_pixel_shader(&bytecode.dlaa_prefilter)?,
            dlaa_resolve: device.create_pixel_shader(&bytecode.dlaa_resolve)?,
            smaa_edges: device.create_pixel_shader(&bytecode.smaa_edges)?,
            smaa_weights: device.create_pixel_shader(&bytecode.smaa_weights)?,
            smaa_blend: device.create_pixel_shader(&bytecode.smaa_blend)?,
            scratch_primary: None,
            scratch_secondary: None,
        }))
    }

    pub(crate) fn draw(
        &mut self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        source: &ScreenShaderSource,
        scene_color: &Texture9,
    ) -> Direct3DResult<()> {
        match source.embedded_effect_kind() {
            Some(EmbeddedEffectKind::FastFxaa) => draw_single(
                device,
                backbuffer,
                desc,
                source,
                scene_color,
                &self.fast_fxaa,
            ),
            Some(EmbeddedEffectKind::Nfaa) => {
                draw_single(device, backbuffer, desc, source, scene_color, &self.nfaa)
            }
            Some(EmbeddedEffectKind::Axaa) => {
                draw_single(device, backbuffer, desc, source, scene_color, &self.axaa)
            }
            Some(EmbeddedEffectKind::Dlaa) => {
                self.draw_dlaa(device, backbuffer, desc, source, scene_color)
            }
            Some(EmbeddedEffectKind::Smaa) => {
                self.draw_smaa(device, backbuffer, desc, source, scene_color)
            }
            _ => Ok(()),
        }
    }

    fn draw_dlaa(
        &mut self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        source: &ScreenShaderSource,
        scene_color: &Texture9,
    ) -> Direct3DResult<()> {
        let prefilter_shader = self.dlaa_prefilter.clone();
        let resolve_shader = self.dlaa_resolve.clone();
        let needs_target = self
            .scratch_primary
            .as_ref()
            .is_none_or(|target| !target.matches(desc));
        if needs_target {
            self.scratch_primary = Some(EffectTarget::create(device, desc)?);
        }
        let Some(target) = self.scratch_primary.as_ref() else {
            return Ok(());
        };

        bind_constants(device, desc, source)?;
        bind_target(device, &target.surface, desc)?;
        device.set_texture(0, scene_color)?;
        device.set_pixel_shader(&prefilter_shader)?;
        draw_quad(device, desc)?;

        bind_target(device, backbuffer, desc)?;
        device.set_texture(0, &target.texture)?;
        device.set_pixel_shader(&resolve_shader)?;
        draw_quad(device, desc)
    }

    fn draw_smaa(
        &mut self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        source: &ScreenShaderSource,
        scene_color: &Texture9,
    ) -> Direct3DResult<()> {
        // Lookup data and edges/weights are never sRGB. Preserve the current
        // phase's color encoding; upstream supports gamma-space blending when
        // a separate sRGB color-input contract is unavailable.
        device.set_render_state(D3DRS_SRGBWRITEENABLE, 0)?;
        for sampler in 0..3 {
            for (state, value) in [
                (D3DSAMP_ADDRESSU, D3DTADDRESS_CLAMP.0 as u32),
                (D3DSAMP_ADDRESSV, D3DTADDRESS_CLAMP.0 as u32),
                (D3DSAMP_MINFILTER, D3DTEXF_LINEAR.0 as u32),
                (D3DSAMP_MAGFILTER, D3DTEXF_LINEAR.0 as u32),
                (D3DSAMP_MIPFILTER, D3DTEXF_NONE.0 as u32),
                (D3DSAMP_SRGBTEXTURE, 0),
            ] {
                device.set_sampler_state(sampler, state, value)?;
            }
        }
        let edges_shader = self.smaa_edges.clone();
        let blend_shader = self.smaa_blend.clone();
        let edge_debug = smaa_edge_debug(source);
        let weights_shader = if edge_debug {
            None
        } else {
            Some(self.smaa_weights.clone())
        };
        let needs_primary = self
            .scratch_primary
            .as_ref()
            .is_none_or(|target| !target.matches(desc));
        if needs_primary {
            self.scratch_primary = Some(EffectTarget::create(device, desc)?);
        }
        if !edge_debug {
            let needs_secondary = self
                .scratch_secondary
                .as_ref()
                .is_none_or(|owner| !owner.resources.target.matches(desc));
            if needs_secondary {
                let target = EffectTarget::create(device, desc)?;
                if let Some(owner) = self.scratch_secondary.as_mut() {
                    owner.resources.target = target;
                } else {
                    self.scratch_secondary = Some(SmaaTargetOwner {
                        resources: Box::new(SmaaTargets {
                            target,
                            lookup: smaa::LookupTextures::create(device)?,
                        }),
                        _reserved: [0; 4],
                    });
                }
            }
        }
        let Some(edges) = self.scratch_primary.as_ref() else {
            return Ok(());
        };

        bind_constants(device, desc, source)?;
        // Previous passes can leave these targets bound at s1/s2. Remove
        // every locally owned alias before either becomes writable again.
        device.clear_texture(1)?;
        device.clear_texture(2)?;
        bind_target(device, &edges.surface, desc)?;
        // The reference edge detector discards non-edges. Clear every frame
        // so those pixels never inherit stale edges from a previous image.
        device.clear_attachments(D3DCLEAR_TARGET as u32, 0, 1.0, 0)?;
        device.set_texture(0, scene_color)?;
        device.set_pixel_shader(&edges_shader)?;
        draw_quad(device, desc)?;

        if let (Some(weights), Some(weights_shader)) =
            (self.scratch_secondary.as_ref(), weights_shader.as_ref())
        {
            let weights_target = &weights.resources.target;
            bind_target(device, &weights_target.surface, desc)?;
            device.set_texture(0, &edges.texture)?;
            let lookup = &weights.resources.lookup;
            device.set_texture(1, &lookup.area)?;
            device.set_texture(2, &lookup.search)?;
            device.set_pixel_shader(weights_shader)?;
            draw_quad(device, desc)?;
        }

        bind_target(device, backbuffer, desc)?;
        device.set_texture(0, scene_color)?;
        if edge_debug {
            device.set_texture(1, &edges.texture)?;
        } else if let Some(weights) = self.scratch_secondary.as_ref() {
            device.set_texture(1, &weights.resources.target.texture)?;
        }
        device.set_texture(2, &edges.texture)?;
        device.set_pixel_shader(&blend_shader)?;
        draw_quad(device, desc)?;
        crate::render_state::clear_sampler(device, 1)?;
        device.clear_texture(2)
    }
}

fn smaa_edge_debug(source: &ScreenShaderSource) -> bool {
    source
        .option_constants
        .get(1)
        .is_some_and(|options| options[1] > 0.5 && options[1] < 1.5)
}

fn draw_single(
    device: &Device9Ref<'_>,
    backbuffer: &Surface9,
    desc: &D3DSURFACE_DESC,
    source: &ScreenShaderSource,
    scene_color: &Texture9,
    shader: &PixelShader9,
) -> Direct3DResult<()> {
    bind_target(device, backbuffer, desc)?;
    device.set_texture(0, scene_color)?;
    bind_constants(device, desc, source)?;
    device.set_pixel_shader(shader)?;
    draw_quad(device, desc)
}

fn bind_constants(
    device: &Device9Ref<'_>,
    desc: &D3DSURFACE_DESC,
    source: &ScreenShaderSource,
) -> Direct3DResult<()> {
    device.set_pixel_shader_constant_f(
        0,
        &[[
            desc.Width as f32,
            desc.Height as f32,
            1.0 / desc.Width.max(1) as f32,
            1.0 / desc.Height.max(1) as f32,
        ]],
    )?;
    if !source.option_constants.is_empty() {
        device.set_pixel_shader_constant_f(FIRST_OPTION_REGISTER, &source.option_constants)?;
    }
    Ok(())
}

fn bind_target(
    device: &Device9Ref<'_>,
    surface: &Surface9,
    desc: &D3DSURFACE_DESC,
) -> Direct3DResult<()> {
    crate::render_state::clear_sampler(device, 0)?;
    // Spatial AA is the only screen pipeline whose passes previously
    // inherited FVF, vertex-shader, and viewport state from whatever ran
    // before them. After a native draw left its own vertex format, or on a
    // letterboxed frame whose viewport carries the native Y offset, the
    // quad rendered with the wrong vertex interpretation: garbage geometry
    // over a rectangle of the target while the rest kept the previous
    // frame. Every pass now binds its full drawing state explicitly.
    device.clear_vertex_shader()?;
    device.set_fvf(ScreenVertex::FVF)?;
    // Viewport ownership hygiene: RHW quads ignore the viewport offset under
    // DXVK, but the pass must not depend on that driver behavior.
    device.set_viewport(&D3DVIEWPORT9 {
        X: 0,
        Y: 0,
        Width: desc.Width,
        Height: desc.Height,
        MinZ: 0.0,
        MaxZ: 1.0,
    })?;
    device.set_render_target(0, surface)
}

fn draw_quad(device: &Device9Ref<'_>, desc: &D3DSURFACE_DESC) -> Direct3DResult<()> {
    let width = desc.Width as f32;
    let height = desc.Height as f32;
    let quad = [
        ScreenVertex::new(-0.5, -0.5, 0.0, 0.0),
        ScreenVertex::new(width - 0.5, -0.5, 1.0, 0.0),
        ScreenVertex::new(-0.5, height - 0.5, 0.0, 1.0),
        ScreenVertex::new(width - 0.5, height - 0.5, 1.0, 1.0),
    ];
    unsafe { crate::render_state::draw_fullscreen_quad(device, &quad) }
}

struct EffectTarget {
    texture: Texture9,
    surface: Surface9,
    width: u32,
    height: u32,
}

impl EffectTarget {
    fn create(device: &Device9Ref<'_>, desc: &D3DSURFACE_DESC) -> Direct3DResult<Self> {
        let texture =
            device.create_render_target_texture(desc.Width, desc.Height, D3DFMT_A8R8G8B8)?;
        let surface = texture.surface_level(0)?;
        Ok(Self {
            texture,
            surface,
            width: desc.Width,
            height: desc.Height,
        })
    }

    fn matches(&self, desc: &D3DSURFACE_DESC) -> bool {
        self.width == desc.Width && self.height == desc.Height
    }
}
