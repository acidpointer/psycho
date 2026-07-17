//! Embedded spatial anti-aliasing pipelines.

use libpsycho::os::windows::directx9::{
    D3DFMT_A8R8G8B8, D3DPT_TRIANGLESTRIP, D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER, D3DSURFACE_DESC,
    D3DTEXF_LINEAR, Device9Ref, Direct3DResult, PixelShader9, ScreenVertex, Surface9, Texture9,
    direct3d_failure,
};

use crate::shaders::{self, EmbeddedEffectKind, ScreenShaderSource};

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
            crate::shaders::assert_hlsl_compiles(name, source, "ps_3_0");
        }
    }

    #[test]
    fn smaa_weight_search_uses_explicit_lod_samples_without_dynamic_loops() {
        let source = std::str::from_utf8(SMAA_WEIGHTS_SHADER).expect("SMAA source is UTF-8");
        assert!(!source.contains("tex2D("));
        assert!(!source.contains("for ("));
        assert!(!source.contains("while ("));
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
    fast_fxaa: ShaderSlot,
    nfaa: ShaderSlot,
    axaa: ShaderSlot,
    dlaa_prefilter: ShaderSlot,
    dlaa_resolve: ShaderSlot,
    smaa_edges: ShaderSlot,
    smaa_weights: ShaderSlot,
    smaa_blend: ShaderSlot,
    scratch_primary: Option<EffectTarget>,
    scratch_secondary: Option<EffectTarget>,
}

impl AntiAliasingEffect {
    pub(crate) fn create() -> Self {
        Self {
            fast_fxaa: ShaderSlot::new("aa_fast_fxaa.hlsl", FAST_FXAA_SHADER),
            nfaa: ShaderSlot::new("aa_nfaa.hlsl", NFAA_SHADER),
            axaa: ShaderSlot::new("aa_axaa.hlsl", AXAA_SHADER),
            dlaa_prefilter: ShaderSlot::new("aa_dlaa_prefilter.hlsl", DLAA_PREFILTER_SHADER),
            dlaa_resolve: ShaderSlot::new("aa_dlaa_resolve.hlsl", DLAA_RESOLVE_SHADER),
            smaa_edges: ShaderSlot::new("aa_smaa_edges.hlsl", SMAA_EDGES_SHADER),
            smaa_weights: ShaderSlot::new("aa_smaa_weights.hlsl", SMAA_WEIGHTS_SHADER),
            smaa_blend: ShaderSlot::new("aa_smaa_blend.hlsl", SMAA_BLEND_SHADER),
            scratch_primary: None,
            scratch_secondary: None,
        }
    }

    pub(crate) fn draw(
        &mut self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        source: &ScreenShaderSource,
        scene_color: &Texture9,
    ) -> Direct3DResult<()> {
        if source.embedded_effect_kind() == Some(EmbeddedEffectKind::Smaa) {
            for sampler in 1..=2 {
                device.set_sampler_state(sampler, D3DSAMP_MINFILTER, D3DTEXF_LINEAR.0 as u32)?;
                device.set_sampler_state(sampler, D3DSAMP_MAGFILTER, D3DTEXF_LINEAR.0 as u32)?;
            }
        }
        match source.embedded_effect_kind() {
            Some(EmbeddedEffectKind::FastFxaa) => match self.fast_fxaa.get(device)?.cloned() {
                Some(shader) => draw_single(device, backbuffer, desc, source, scene_color, &shader),
                None => Ok(()),
            },
            Some(EmbeddedEffectKind::Nfaa) => match self.nfaa.get(device)?.cloned() {
                Some(shader) => draw_single(device, backbuffer, desc, source, scene_color, &shader),
                None => Ok(()),
            },
            Some(EmbeddedEffectKind::Axaa) => match self.axaa.get(device)?.cloned() {
                Some(shader) => draw_single(device, backbuffer, desc, source, scene_color, &shader),
                None => Ok(()),
            },
            Some(EmbeddedEffectKind::Dlaa) => {
                self.draw_dlaa(device, backbuffer, desc, source, scene_color)
            }
            Some(EmbeddedEffectKind::Smaa) => {
                self.draw_smaa(device, backbuffer, desc, source, scene_color)
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn prepare(
        &mut self,
        device: &Device9Ref<'_>,
        source: &ScreenShaderSource,
    ) -> Direct3DResult<bool> {
        let available = match source.embedded_effect_kind() {
            Some(EmbeddedEffectKind::FastFxaa) => self.fast_fxaa.get(device)?.is_some(),
            Some(EmbeddedEffectKind::Nfaa) => self.nfaa.get(device)?.is_some(),
            Some(EmbeddedEffectKind::Axaa) => self.axaa.get(device)?.is_some(),
            Some(EmbeddedEffectKind::Dlaa) => {
                self.dlaa_prefilter.get(device)?.is_some()
                    && self.dlaa_resolve.get(device)?.is_some()
            }
            Some(EmbeddedEffectKind::Smaa) => {
                self.smaa_edges.get(device)?.is_some()
                    && (smaa_edge_debug(source) || self.smaa_weights.get(device)?.is_some())
                    && self.smaa_blend.get(device)?.is_some()
            }
            _ => false,
        };
        Ok(available)
    }

    fn draw_dlaa(
        &mut self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        source: &ScreenShaderSource,
        scene_color: &Texture9,
    ) -> Direct3DResult<()> {
        let Some(prefilter_shader) = self.dlaa_prefilter.get(device)?.cloned() else {
            return Ok(());
        };
        let Some(resolve_shader) = self.dlaa_resolve.get(device)?.cloned() else {
            return Ok(());
        };
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
        let Some(edges_shader) = self.smaa_edges.get(device)?.cloned() else {
            return Ok(());
        };
        let Some(blend_shader) = self.smaa_blend.get(device)?.cloned() else {
            return Ok(());
        };
        let edge_debug = smaa_edge_debug(source);
        let weights_shader = if edge_debug {
            None
        } else {
            let Some(shader) = self.smaa_weights.get(device)?.cloned() else {
                return Ok(());
            };
            Some(shader)
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
                .is_none_or(|target| !target.matches(desc));
            if needs_secondary {
                self.scratch_secondary = Some(EffectTarget::create(device, desc)?);
            }
        }
        let Some(edges) = self.scratch_primary.as_ref() else {
            return Ok(());
        };

        bind_constants(device, desc, source)?;
        bind_target(device, &edges.surface, desc)?;
        device.set_texture(0, scene_color)?;
        device.set_pixel_shader(&edges_shader)?;
        draw_quad(device, desc)?;

        if let (Some(weights), Some(weights_shader)) =
            (self.scratch_secondary.as_ref(), weights_shader.as_ref())
        {
            bind_target(device, &weights.surface, desc)?;
            device.set_texture(0, &edges.texture)?;
            device.set_pixel_shader(weights_shader)?;
            draw_quad(device, desc)?;
        }

        bind_target(device, backbuffer, desc)?;
        device.set_texture(0, scene_color)?;
        if edge_debug {
            device.set_texture(1, &edges.texture)?;
        } else if let Some(weights) = self.scratch_secondary.as_ref() {
            device.set_texture(1, &weights.texture)?;
        }
        device.set_texture(2, &edges.texture)?;
        device.set_pixel_shader(&blend_shader)?;
        draw_quad(device, desc)?;
        device.clear_texture(1)?;
        device.clear_texture(2)
    }
}

fn smaa_edge_debug(source: &ScreenShaderSource) -> bool {
    source
        .option_constants
        .get(1)
        .is_some_and(|options| options[1] > 0.5 && options[1] < 1.5)
}

struct ShaderSlot {
    source_name: &'static str,
    source: &'static [u8],
    shader: Option<PixelShader9>,
    failed: bool,
}

impl ShaderSlot {
    const fn new(source_name: &'static str, source: &'static [u8]) -> Self {
        Self {
            source_name,
            source,
            shader: None,
            failed: false,
        }
    }

    fn get(&mut self, device: &Device9Ref<'_>) -> Direct3DResult<Option<&PixelShader9>> {
        if self.failed {
            return Ok(None);
        }
        if self.shader.is_none() {
            match compile_shader(device, self.source_name, self.source) {
                Ok(shader) => self.shader = Some(shader),
                Err(err) => {
                    self.failed = true;
                    return Err(err);
                }
            }
        }
        Ok(self.shader.as_ref())
    }
}

fn compile_shader(
    device: &Device9Ref<'_>,
    source_name: &str,
    source: &[u8],
) -> Direct3DResult<PixelShader9> {
    let bytecode = match shaders::compile_hlsl_source(source_name, source) {
        Ok(bytecode) => bytecode,
        Err(err) => {
            log::warn!("[AA] Failed to compile {source_name}: {err:#}");
            return Err(direct3d_failure());
        }
    };
    device.create_pixel_shader(&bytecode)
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
    _desc: &D3DSURFACE_DESC,
) -> Direct3DResult<()> {
    device.clear_texture(0)?;
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
    unsafe { device.draw_primitive_up(D3DPT_TRIANGLESTRIP, 2, &quad) }
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
