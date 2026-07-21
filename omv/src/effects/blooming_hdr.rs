//! Engine-side atmospheric bloom and HDR pipeline.

use libpsycho::os::windows::directx9::{
    D3DCULL_NONE, D3DFMT_A8R8G8B8, D3DFORMAT, D3DPOOL_MANAGED, D3DPT_TRIANGLESTRIP,
    D3DRS_ADAPTIVETESS_Y, D3DRS_ALPHABLENDENABLE, D3DRS_ALPHATESTENABLE, D3DRS_COLORWRITEENABLE,
    D3DRS_CULLMODE, D3DRS_MULTISAMPLEANTIALIAS, D3DRS_MULTISAMPLEMASK, D3DRS_POINTSIZE,
    D3DRS_SCISSORTESTENABLE, D3DRS_SRGBWRITEENABLE, D3DRS_STENCILENABLE, D3DRS_ZENABLE,
    D3DRS_ZWRITEENABLE, D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV, D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER,
    D3DSAMP_MIPFILTER, D3DSAMP_SRGBTEXTURE, D3DSURFACE_DESC, D3DTA_TEXTURE, D3DTADDRESS_CLAMP,
    D3DTEXF_LINEAR, D3DTEXF_NONE, D3DTEXF_POINT, D3DTOP_SELECTARG1, D3DTSS_ALPHAARG1,
    D3DTSS_ALPHAOP, D3DTSS_COLORARG1, D3DTSS_COLOROP, D3DVIEWPORT9, Device9Ref, Direct3DResult,
    PixelShader9, ScreenVertex, Surface9, Texture9,
};

use crate::{
    backend::{DepthTexture, FrameInputs},
    luts::LutAsset,
    shaders::{self, ScreenShaderSource, ShaderOptionValue},
};

const COLOR_WRITE_ALL: u32 = 0x0F;
const EFFECT_CONSTANT_REGISTER: u32 = 9;
const BLOOM_SCALE: u32 = 4;
const COLOR_GRADE_CONSTANT_REGISTER: u32 = 10;
#[cfg(test)]
const LUT_SIZE: u32 = 32;
#[cfg(test)]
const LUT_COUNT: usize = 5;
const AMD_ALPHA_TO_COVERAGE_OFF: u32 = 0x4143_5446;

const EXTRACT_SHADER: &[u8] = include_bytes!("../../shaders/embedded/bloom_hdr_extract.hlsl");
const BLUR_SHADER: &[u8] = include_bytes!("../../shaders/embedded/bloom_hdr_blur.hlsl");
const COMPOSE_SHADER: &[u8] = include_bytes!("../../shaders/embedded/bloom_hdr_compose.hlsl");
const CHROMATIC_SHADER: &[u8] = include_bytes!("../../shaders/embedded/chromatic_aberration.hlsl");

fn chromatic_aberration_active(source: &ScreenShaderSource) -> bool {
    source.enabled
        && source_option_float(source, "strength", 0.0) > 1.0e-5
        && source_option_bool(source, "chromatic_aberration_enabled", false)
        && source_option_float(source, "chromatic_aberration", 0.0) > 1.0e-5
}

#[cfg(test)]
pub(crate) fn color_grade_source_active(source: &ScreenShaderSource) -> bool {
    color_grade_source_active_with_lut(source, true)
}

fn color_grade_source_active_with_lut(source: &ScreenShaderSource, lut_available: bool) -> bool {
    if !source.enabled || source_option_float(source, "strength", 0.0) <= 1.0e-5 {
        return false;
    }
    source_option_bool(source, "color_grading_enabled", false)
        || (lut_available
            && source_option_bool(source, "lut_enabled", false)
            && source_option_float(source, "lut_strength", 0.0) > 1.0e-5)
        || (source_option_bool(source, "deband_enabled", false)
            && source_option_float(source, "deband", 0.0) > 1.0e-5)
        || (source_option_bool(source, "film_grain_enabled", false)
            && source_option_float(source, "film_grain", 0.0) > 1.0e-5)
        || (source_option_bool(source, "vignette_enabled", false)
            && source_option_float(source, "vignette", 0.0) > 1.0e-5)
        || (source_option_bool(source, "halation_enabled", false)
            && source_option_float(source, "halation", 0.0) > 1.0e-5)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FinalColorWorkPlan {
    bloom: bool,
    bloom_intermediate: bool,
    color_grade: bool,
    chromatic_aberration: bool,
}

impl FinalColorWorkPlan {
    #[cfg(test)]
    pub(crate) fn from_sources(
        bloom_source: Option<&ScreenShaderSource>,
        color_grade_source: Option<&ScreenShaderSource>,
    ) -> Self {
        Self::from_sources_with_lut_available(bloom_source, color_grade_source, true)
    }

    pub(crate) fn from_sources_with_lut_available(
        bloom_source: Option<&ScreenShaderSource>,
        color_grade_source: Option<&ScreenShaderSource>,
        lut_available: bool,
    ) -> Self {
        let bloom = bloom_source.is_some_and(|source| source.enabled);
        let halation = color_grade_source.is_some_and(|source| {
            source.enabled
                && source_option_float(source, "strength", 0.0) > 1.0e-5
                && source_option_bool(source, "halation_enabled", false)
                && source_option_float(source, "halation", 0.0) > 1.0e-5
        });
        Self {
            bloom,
            bloom_intermediate: bloom || halation,
            color_grade: color_grade_source
                .is_some_and(|source| color_grade_source_active_with_lut(source, lut_available)),
            chromatic_aberration: color_grade_source.is_some_and(chromatic_aberration_active),
        }
    }

    pub(crate) const fn has_work(self) -> bool {
        self.bloom || self.color_grade || self.chromatic_aberration
    }

    #[cfg(test)]
    const fn effect_draw_count(self) -> u32 {
        let base = if self.bloom_intermediate {
            4
        } else if self.color_grade {
            1
        } else {
            0
        };
        base + self.chromatic_aberration as u32
    }

    #[cfg(test)]
    const fn quarter_resolution_draw_count(self) -> u32 {
        if self.bloom_intermediate { 3 } else { 0 }
    }
}

fn bloom_target_dimensions(width: u32, height: u32) -> (u32, u32) {
    ((width / BLOOM_SCALE).max(1), (height / BLOOM_SCALE).max(1))
}

pub(crate) struct FinalColorShaderBytecode {
    extract: Vec<u32>,
    blur: Vec<u32>,
    compose: Vec<u32>,
    chromatic: Vec<u32>,
}

impl FinalColorShaderBytecode {
    pub(crate) fn prepare() -> anyhow::Result<Self> {
        Ok(Self {
            extract: prepare_shader("bloom_hdr_extract.hlsl", EXTRACT_SHADER)?,
            blur: prepare_shader("bloom_hdr_blur.hlsl", BLUR_SHADER)?,
            compose: prepare_shader("bloom_hdr_compose.hlsl", COMPOSE_SHADER)?,
            chromatic: prepare_shader("chromatic_aberration.hlsl", CHROMATIC_SHADER)?,
        })
    }
}

fn prepare_shader(source_name: &str, source: &[u8]) -> anyhow::Result<Vec<u32>> {
    #[cfg(test)]
    {
        shaders::compile_hlsl_source_target(source_name, source, "ps_3_0")
    }
    #[cfg(not(test))]
    {
        shaders::compile_hlsl_source(source_name, source)
    }
}

#[cfg(test)]
mod shader_compile_tests {
    use super::{
        BLUR_SHADER, CHROMATIC_SHADER, COMPOSE_SHADER, ColorGradeSettings, EXTRACT_SHADER,
        FinalColorShaderBytecode, FinalColorWorkPlan, LUT_COUNT, LUT_SIZE, apply_lut_recipe,
        bloom_target_dimensions, color_grade_source_active, fullscreen_quad, generate_builtin_lut,
        identity_lut_pixels, native_environment_weight,
    };
    use crate::{
        backend::{FrameInputs, MaterialStateFrame, NativeSkyFrame},
        config::EmbeddedEffectsConfig,
        shaders::{self, EmbeddedEffectKind},
    };

    const FILM_GRAIN_NOISE_CODES: f32 = 24.0;
    const DEBAND_DITHER_NOISE_CODES: f32 = 4.0;

    fn compiled_instruction_opcodes(bytecode: &[u32]) -> Vec<u16> {
        const COMMENT: u16 = 0xfffe;
        const END: u16 = 0xffff;

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
    }

    fn shader_budget(name: &str, source: &[u8]) -> (usize, usize) {
        const TEXLD: u16 = 66;
        const TEXLDD: u16 = 93;
        const TEXLDL: u16 = 95;
        let bytecode = crate::shaders::compile_hlsl_source_target(name, source, "ps_3_0")
            .expect("compose shader");
        let opcodes = compiled_instruction_opcodes(&bytecode);
        let texture_count = opcodes
            .iter()
            .filter(|opcode| matches!(**opcode, TEXLD | TEXLDD | TEXLDL))
            .count();
        (opcodes.len(), texture_count)
    }

    fn unpack_argb(pixel: u32) -> [f32; 3] {
        [
            ((pixel >> 16) & 0xff) as f32 / 255.0,
            ((pixel >> 8) & 0xff) as f32 / 255.0,
            (pixel & 0xff) as f32 / 255.0,
        ]
    }

    fn sample_lut(pixels: &[u32], input: [f32; 3]) -> [f32; 3] {
        let size = LUT_SIZE as usize;
        let position = input.map(|value| value.clamp(0.0, 1.0) * (LUT_SIZE - 1) as f32);
        let low = position.map(|value| value.floor() as usize);
        let high = low.map(|value| (value + 1).min(size - 1));
        let fraction = [
            position[0] - low[0] as f32,
            position[1] - low[1] as f32,
            position[2] - low[2] as f32,
        ];
        let texel = |red: usize, green: usize, blue: usize| {
            unpack_argb(pixels[green * size * size + blue * size + red])
        };
        let lerp = |left: [f32; 3], right: [f32; 3], amount: f32| {
            std::array::from_fn(|channel| left[channel] + (right[channel] - left[channel]) * amount)
        };
        let low_blue = lerp(
            lerp(
                texel(low[0], low[1], low[2]),
                texel(high[0], low[1], low[2]),
                fraction[0],
            ),
            lerp(
                texel(low[0], high[1], low[2]),
                texel(high[0], high[1], low[2]),
                fraction[0],
            ),
            fraction[1],
        );
        let high_blue = lerp(
            lerp(
                texel(low[0], low[1], high[2]),
                texel(high[0], low[1], high[2]),
                fraction[0],
            ),
            lerp(
                texel(low[0], high[1], high[2]),
                texel(high[0], high[1], high[2]),
                fraction[0],
            ),
            fraction[1],
        );
        lerp(low_blue, high_blue, fraction[2])
    }

    fn deband_reference(
        image: &[[f32; 3]],
        width: usize,
        height: usize,
        x: usize,
        y: usize,
        strength: f32,
    ) -> [f32; 3] {
        let sample = |x: f32, y: f32| {
            let low_x = x.floor() as isize;
            let low_y = y.floor() as isize;
            let fraction_x = x - low_x as f32;
            let fraction_y = y - low_y as f32;
            let texel = |x: isize, y: isize| {
                image[y.clamp(0, height as isize - 1) as usize * width
                    + x.clamp(0, width as isize - 1) as usize]
            };
            let top: [f32; 3] = std::array::from_fn(|channel| {
                texel(low_x, low_y)[channel]
                    + (texel(low_x + 1, low_y)[channel] - texel(low_x, low_y)[channel]) * fraction_x
            });
            let bottom: [f32; 3] = std::array::from_fn(|channel| {
                texel(low_x, low_y + 1)[channel]
                    + (texel(low_x + 1, low_y + 1)[channel] - texel(low_x, low_y + 1)[channel])
                        * fraction_x
            });
            std::array::from_fn::<_, 3, _>(|channel| {
                top[channel] + (bottom[channel] - top[channel]) * fraction_y
            })
        };
        let strength = strength.clamp(0.0, 1.0);
        let radius = 6.0;
        let center = sample(x as f32, y as f32);
        let left = sample(x as f32 - radius, y as f32);
        let right = sample(x as f32 + radius, y as f32);
        let up = sample(x as f32, y as f32 - radius);
        let down = sample(x as f32, y as f32 + radius);
        let average: [f32; 3] = std::array::from_fn(|channel| {
            (center[channel] + left[channel] + right[channel] + up[channel] + down[channel]) * 0.2
        });
        let edge = (0..3)
            .map(|channel| {
                (left[channel] - right[channel])
                    .abs()
                    .max((up[channel] - down[channel]).abs())
                    .max((center[channel] - average[channel]).abs())
            })
            .fold(0.0f32, f32::max);
        let value = (edge * 42.5).clamp(0.0, 1.0);
        let flat_weight = 1.0 - value * value * (3.0 - 2.0 * value);
        std::array::from_fn(|channel| {
            center[channel] + (average[channel] - center[channel]) * strength * flat_weight * 0.85
        })
    }

    fn luma(color: [f32; 3]) -> f32 {
        color[0] * 0.2126 + color[1] * 0.7152 + color[2] * 0.0722
    }

    fn smooth01(value: f32) -> f32 {
        let value = value.clamp(0.0, 1.0);
        value * value * (3.0 - 2.0 * value)
    }

    fn lerp3(left: [f32; 3], right: [f32; 3], amount: f32) -> [f32; 3] {
        std::array::from_fn(|channel| left[channel] + (right[channel] - left[channel]) * amount)
    }

    fn neutral_grade() -> ColorGradeSettings {
        ColorGradeSettings {
            enabled: true,
            strength: 1.0,
            color_grading_enabled: true,
            exposure: 0.0,
            contrast: 0.0,
            saturation: 1.0,
            vibrance: 0.0,
            temperature: 0.0,
            tint: 0.0,
            black_fade: 0.0,
            highlight_rolloff: 0.0,
            lut_enabled: true,
            lut_strength: 0.0,
            deband_enabled: true,
            deband: 0.0,
            film_grain_enabled: true,
            film_grain: 0.0,
            vignette_enabled: true,
            vignette: 0.0,
            halation_enabled: true,
            halation: 0.0,
            chromatic_aberration_enabled: true,
            chromatic_aberration: 0.0,
            debug_split: false,
            environment_weight: 1.0,
            lut_size: 32.0,
            lut_domain_min: [0.0; 3],
            lut_domain_max: [1.0; 3],
        }
    }

    fn grade_reference(
        input: [f32; 3],
        bloom: [f32; 3],
        uv: [f32; 2],
        dimensions: [f32; 2],
        settings: ColorGradeSettings,
        lut: &[u32],
    ) -> [f32; 3] {
        let mut color = input.map(|channel| channel * settings.exposure.clamp(-1.5, 1.5).exp2());
        let temperature = settings.temperature.clamp(-1.0, 1.0);
        let tint = settings.tint.clamp(-1.0, 1.0);
        let white_balance = [
            1.0 + temperature * 0.10 + tint * 0.025,
            1.0 - tint * 0.055,
            1.0 - temperature * 0.10 + tint * 0.025,
        ];
        for channel in 0..3 {
            color[channel] *= white_balance[channel];
        }

        for channel in &mut color {
            *channel = 0.5 + (*channel - 0.5) * (1.0 + settings.contrast.clamp(-0.5, 0.5));
        }
        let color_luma = luma(color);
        let maximum = color.into_iter().fold(f32::NEG_INFINITY, f32::max);
        let minimum = color.into_iter().fold(f32::INFINITY, f32::min);
        let adaptive_vibrance =
            1.0 + settings.vibrance.clamp(-1.0, 1.0) * (1.0 - (maximum - minimum).clamp(0.0, 1.0));
        let saturation = settings.saturation.max(0.0) * adaptive_vibrance.max(0.0);
        for channel in &mut color {
            *channel = color_luma + (*channel - color_luma) * saturation;
        }

        let black_fade = settings.black_fade.clamp(0.0, 1.0) * 0.06;
        let shoulder = settings.highlight_rolloff.clamp(0.0, 1.0) * 0.65;
        for channel in &mut color {
            *channel = (black_fade + *channel * (1.0 - black_fade)).clamp(0.0, 1.0);
            *channel = *channel * (1.0 + shoulder) / (1.0 + shoulder * *channel);
        }

        let lut_color = sample_lut(lut, color);
        color = lerp3(color, lut_color, settings.lut_strength.clamp(0.0, 1.0));
        for channel in 0..3 {
            color[channel] += bloom[channel]
                * [1.0, 0.28, 0.10][channel]
                * settings.halation.clamp(0.0, 1.0)
                * 0.85;
        }
        let mut centered = [uv[0] * 2.0 - 1.0, uv[1] * 2.0 - 1.0];
        centered[0] *= dimensions[0] / dimensions[1].max(1.0);
        let vignette = smooth01(
            ((centered[0] * centered[0] + centered[1] * centered[1]) * 0.42).clamp(0.0, 1.0),
        );
        let vignette_scale = 1.0 - vignette * settings.vignette.clamp(0.0, 1.0) * 0.32;
        color = color.map(|channel| (channel * vignette_scale).clamp(0.0, 1.0));
        lerp3(input, color, settings.strength.clamp(0.0, 1.0))
    }

    fn chromatic_reference(
        image: &[[f32; 4]],
        width: usize,
        height: usize,
        x: usize,
        y: usize,
        amount_pixels: f32,
    ) -> [f32; 4] {
        let sample = |uv: [f32; 2]| {
            let position = [
                uv[0].clamp(0.0, 1.0) * width as f32 - 0.5,
                uv[1].clamp(0.0, 1.0) * height as f32 - 0.5,
            ];
            let low = [position[0].floor() as isize, position[1].floor() as isize];
            let fraction = [position[0] - low[0] as f32, position[1] - low[1] as f32];
            let texel = |x: isize, y: isize| {
                image[y.clamp(0, height as isize - 1) as usize * width
                    + x.clamp(0, width as isize - 1) as usize]
            };
            let top = std::array::from_fn::<_, 4, _>(|channel| {
                texel(low[0], low[1])[channel]
                    + (texel(low[0] + 1, low[1])[channel] - texel(low[0], low[1])[channel])
                        * fraction[0]
            });
            let bottom = std::array::from_fn::<_, 4, _>(|channel| {
                texel(low[0], low[1] + 1)[channel]
                    + (texel(low[0] + 1, low[1] + 1)[channel] - texel(low[0], low[1] + 1)[channel])
                        * fraction[0]
            });
            std::array::from_fn::<_, 4, _>(|channel| {
                top[channel] + (bottom[channel] - top[channel]) * fraction[1]
            })
        };
        let uv = [
            (x as f32 + 0.5) / width as f32,
            (y as f32 + 0.5) / height as f32,
        ];
        let center = sample(uv);
        let pixel_vector = [(uv[0] - 0.5) * width as f32, (uv[1] - 0.5) * height as f32];
        let radius_squared = pixel_vector[0] * pixel_vector[0] + pixel_vector[1] * pixel_vector[1];
        let inverse_radius = 1.0 / radius_squared.max(0.000001).sqrt();
        let normalized_radius =
            (((uv[0] - 0.5) * 2.0).powi(2) + ((uv[1] - 0.5) * 2.0).powi(2)).sqrt();
        let radial_weight = smooth01(normalized_radius);
        let radial = [
            pixel_vector[0] * inverse_radius,
            pixel_vector[1] * inverse_radius,
        ];
        let offset = [
            radial[0] * amount_pixels * radial_weight / width as f32,
            radial[1] * amount_pixels * radial_weight / height as f32,
        ];
        let positive = sample([uv[0] + offset[0], uv[1] + offset[1]]);
        let negative = sample([uv[0] - offset[0], uv[1] - offset[1]]);
        [positive[0], center[1], negative[2], center[3]]
    }

    fn color_distance(left: [f32; 3], right: [f32; 3]) -> f32 {
        (0..3)
            .map(|channel| (left[channel] - right[channel]).abs())
            .sum()
    }

    fn chroma(color: [f32; 3]) -> f32 {
        color.into_iter().fold(f32::NEG_INFINITY, f32::max)
            - color.into_iter().fold(f32::INFINITY, f32::min)
    }

    fn golden_noise(pixel: [f32; 2], frame: f32) -> f32 {
        let seed = pixel[0] * 0.06711056 + pixel[1] * 0.00583715 + frame * 0.000731;
        (52.9829189 * seed.fract()).fract()
    }

    fn unorm8_code(value: f32) -> u8 {
        (value.clamp(0.0, 1.0) * 255.0).round() as u8
    }

    fn film_grain_reference(
        input: [f32; 3],
        pixel: [f32; 2],
        dimensions: [f32; 2],
        frame: f32,
        amount: f32,
        master: f32,
    ) -> [f32; 3] {
        let uv = [pixel[0] / dimensions[0], pixel[1] / dimensions[1]];
        let grain_pixel = [
            (uv[0] + 0.173) * dimensions[0],
            (uv[1] + 0.173) * dimensions[1],
        ];
        let grain_mask = 1.0 - (luma(input) * 0.65).clamp(0.0, 1.0);
        let grain = (golden_noise(grain_pixel, frame + 19.0) - 0.5)
            * amount.clamp(0.0, 1.0)
            * master.clamp(0.0, 1.0)
            * grain_mask
            * FILM_GRAIN_NOISE_CODES
            / 255.0;
        input.map(|channel| (channel + grain).clamp(0.0, 1.0))
    }

    fn finishing_dither_reference(
        input: [f32; 3],
        pixel: [f32; 2],
        frame: f32,
        deband_strength: f32,
        flat_weight: f32,
    ) -> [f32; 3] {
        let noise = (golden_noise(pixel, frame) - 0.5)
            * deband_strength.clamp(0.0, 1.0)
            * flat_weight.clamp(0.0, 1.0)
            * DEBAND_DITHER_NOISE_CODES
            / 255.0;
        input.map(|channel| (channel + noise).clamp(0.0, 1.0))
    }

    fn compose_bloom_reference(
        base: [f32; 3],
        bloom: [f32; 3],
        intensity: f32,
        shadow_lift: f32,
        shoulder: f32,
    ) -> [f32; 3] {
        let lift = 1.0 + shadow_lift.clamp(0.0, 1.0) * 0.25;
        let contribution = bloom.map(|channel| channel * intensity.max(0.0) * lift);
        let shoulder = shoulder.clamp(0.0, 1.0);
        let additive = std::array::from_fn(|channel| {
            base[channel] + contribution[channel] * (1.0 - base[channel] * (0.25 + shoulder * 0.55))
        });
        let screen = std::array::from_fn(|channel| {
            1.0 - (1.0 - base[channel].clamp(0.0, 1.0))
                * (1.0 - contribution[channel].clamp(0.0, 1.0))
        });
        lerp3(additive, screen, shoulder * 0.70)
    }

    #[test]
    fn embedded_bloom_shaders_compile() {
        crate::shaders::assert_hlsl_compiles("bloom_hdr_extract.hlsl", EXTRACT_SHADER, "ps_3_0");
        crate::shaders::assert_hlsl_compiles("bloom_hdr_blur.hlsl", BLUR_SHADER, "ps_3_0");
        crate::shaders::assert_hlsl_compiles("bloom_hdr_compose.hlsl", COMPOSE_SHADER, "ps_3_0");
    }

    #[test]
    fn every_final_color_pass_stays_within_fixed_gpu_budgets() {
        for (name, source, max_instructions, max_samples) in [
            ("bloom_hdr_extract_budget.hlsl", EXTRACT_SHADER, 220, 10),
            ("bloom_hdr_blur_budget.hlsl", BLUR_SHADER, 80, 9),
            ("bloom_hdr_compose_budget.hlsl", COMPOSE_SHADER, 500, 13),
            ("chromatic_aberration_budget.hlsl", CHROMATIC_SHADER, 70, 3),
        ] {
            let (instructions, texture_samples) = shader_budget(name, source);
            assert!(
                instructions <= max_instructions,
                "{name} grew to {instructions} instructions"
            );
            assert!(
                texture_samples <= max_samples,
                "{name} grew to {texture_samples} texture samples"
            );
        }
    }

    #[test]
    fn fused_bloom_reference_preserves_the_previous_neutral_contract() {
        let base = [0.17, 0.46, 0.81];
        assert_eq!(compose_bloom_reference(base, [0.0; 3], 1.7, 0.8, 0.6), base);
        assert_eq!(compose_bloom_reference(base, [0.9; 3], 0.0, 0.8, 0.6), base);
        let output = compose_bloom_reference(base, [0.25, 0.18, 0.09], 0.7, 0.4, 0.3);
        assert!(
            output
                .iter()
                .zip(base)
                .all(|(value, original)| value > &original)
        );
        assert!(
            output
                .iter()
                .all(|value| value.is_finite() && *value <= 1.25)
        );

        let blur_weights = [
            0.188, 0.168, 0.168, 0.122, 0.122, 0.074, 0.074, 0.042, 0.042,
        ];
        assert!((blur_weights.into_iter().sum::<f32>() - 1.0).abs() < 1.0e-6);
        let extract = std::str::from_utf8(EXTRACT_SHADER).expect("extract UTF-8");
        let blur = std::str::from_utf8(BLUR_SHADER).expect("blur UTF-8");
        assert_eq!(extract.matches("SampleColor(").count(), 6);
        assert_eq!(extract.matches("IsFirstPersonPixel(").count(), 6);
        assert_eq!(blur.matches("SampleBloom(").count(), 10);
        assert!(extract.contains("return float4(0.0f, 0.0f, 0.0f, 1.0f)"));
    }

    #[test]
    fn final_color_work_and_memory_budgets_are_derived_from_runtime_plan() {
        let config = EmbeddedEffectsConfig::default();
        let sources = shaders::merge_embedded_sources(&config, Vec::new());
        let bloom = sources
            .iter()
            .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::BloomingHdr));
        let grade = sources
            .iter()
            .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade));

        let neither = FinalColorWorkPlan::from_sources(None, None);
        let bloom_only = FinalColorWorkPlan::from_sources(bloom, None);
        let mut no_halation_config = config;
        no_halation_config.color_grade.halation_enabled = false;
        let no_halation_sources = shaders::merge_embedded_sources(&no_halation_config, Vec::new());
        let grade_without_halation = no_halation_sources
            .iter()
            .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade));
        let grade_only = FinalColorWorkPlan::from_sources(None, grade_without_halation);
        let halation_grade = FinalColorWorkPlan::from_sources(None, grade);
        let fused = FinalColorWorkPlan::from_sources(bloom, grade);
        assert_eq!(neither.effect_draw_count(), 0);
        assert!(!neither.has_work());
        assert_eq!(bloom_only.effect_draw_count(), 4);
        assert_eq!(bloom_only.quarter_resolution_draw_count(), 3);
        assert_eq!(grade_only.effect_draw_count(), 1);
        assert_eq!(grade_only.quarter_resolution_draw_count(), 0);
        assert_eq!(halation_grade.effect_draw_count(), 4);
        assert_eq!(halation_grade.quarter_resolution_draw_count(), 3);
        assert_eq!(fused.effect_draw_count(), 4);
        assert_eq!(fused.quarter_resolution_draw_count(), 3);

        let shipped = crate::luts::shipped_luts_for_test();
        let catalog_bytes: usize = shipped
            .iter()
            .map(|lut| lut.pixels.len() * std::mem::size_of::<u32>())
            .sum();
        assert_eq!(catalog_bytes, 1_835_008);
        assert_eq!(
            shipped[0].pixels.len() * std::mem::size_of::<u32>(),
            131_072
        );
    }

    #[test]
    fn every_finishing_family_switch_independently_controls_work() {
        fn disabled_config() -> EmbeddedEffectsConfig {
            let mut config = EmbeddedEffectsConfig::default();
            config.blooming_hdr.enabled = false;
            config.color_grade.color_grading_enabled = false;
            config.color_grade.lut_enabled = false;
            config.color_grade.deband_enabled = false;
            config.color_grade.film_grain_enabled = false;
            config.color_grade.vignette_enabled = false;
            config.color_grade.halation_enabled = false;
            config.color_grade.chromatic_aberration_enabled = false;
            config
        }

        let source_for = |config: &EmbeddedEffectsConfig| {
            shaders::merge_embedded_sources(config, Vec::new())
                .into_iter()
                .find(|source| {
                    source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade)
                })
                .expect("color grade source")
        };
        let disabled = source_for(&disabled_config());
        assert!(!FinalColorWorkPlan::from_sources(None, Some(&disabled)).has_work());

        let families: [(&str, fn(&mut crate::config::ColorGradeConfig)); 6] = [
            ("analytic", |grade| grade.color_grading_enabled = true),
            ("lut", |grade| grade.lut_enabled = true),
            ("deband", |grade| grade.deband_enabled = true),
            ("grain", |grade| grade.film_grain_enabled = true),
            ("vignette", |grade| grade.vignette_enabled = true),
            ("halation", |grade| grade.halation_enabled = true),
        ];
        for (name, enable) in families {
            let mut config = disabled_config();
            enable(&mut config.color_grade);
            let source = source_for(&config);
            let plan =
                FinalColorWorkPlan::from_sources_with_lut_available(None, Some(&source), true);
            assert!(plan.color_grade, "{name} switch did not schedule compose");
            assert_eq!(
                plan.effect_draw_count(),
                if name == "halation" { 4 } else { 1 }
            );
            assert_eq!(
                plan.quarter_resolution_draw_count(),
                if name == "halation" { 3 } else { 0 }
            );
            if name == "lut" {
                assert!(
                    !FinalColorWorkPlan::from_sources_with_lut_available(
                        None,
                        Some(&source),
                        false,
                    )
                    .has_work(),
                    "missing LUT scheduled hidden work"
                );
            }
        }

        let mut config = disabled_config();
        config.color_grade.chromatic_aberration_enabled = true;
        config.color_grade.chromatic_aberration = 0.5;
        let source = source_for(&config);
        let plan = FinalColorWorkPlan::from_sources(None, Some(&source));
        assert!(!plan.color_grade);
        assert!(plan.chromatic_aberration);
        assert_eq!(plan.effect_draw_count(), 1);
    }

    #[test]
    fn bloom_target_dimensions_cover_tiny_odd_and_standard_backbuffers() {
        assert_eq!(bloom_target_dimensions(0, 0), (1, 1));
        assert_eq!(bloom_target_dimensions(1, 3), (1, 1));
        assert_eq!(bloom_target_dimensions(7, 9), (1, 2));
        assert_eq!(bloom_target_dimensions(1920, 1080), (480, 270));
        assert_eq!(bloom_target_dimensions(1919, 1079), (479, 269));
    }

    #[test]
    fn final_color_pipeline_neutralizes_inherited_d3d_state() {
        let source = include_str!("blooming_hdr.rs");
        for required in [
            "device.set_render_state(D3DRS_STENCILENABLE, 0)?",
            "device.set_render_state(D3DRS_SCISSORTESTENABLE, 0)?",
            "device.set_render_state(D3DRS_MULTISAMPLEMASK, u32::MAX)?",
            "device.set_render_state(D3DRS_SRGBWRITEENABLE, 0)?",
            "device.set_sampler_state(sampler, D3DSAMP_SRGBTEXTURE, 0)?",
            "device.set_depth_stencil_surface(None)?",
            "device.clear_render_target(index)?",
        ] {
            assert!(
                source.contains(required),
                "missing final-color state: {required}"
            );
        }
        assert!(source.contains("crate::backend::AlphaCoverageMode::Nvidia"));
        assert!(source.contains("crate::backend::AlphaCoverageMode::Amd"));
        assert!(source.contains("for sampler in 0..=5"));
        assert!(source.contains("D3DFMT_A8R8G8B8, D3DPOOL_MANAGED"));
        assert!(source.contains("device.create_render_target_texture(width, height, format)"));
        assert!(
            source
                .contains("self.width == width && self.height == height && self.format == format")
        );
    }

    #[test]
    fn fullscreen_geometry_obeys_the_d3d9_half_pixel_and_triangle_strip_contract() {
        let quad = fullscreen_quad(1919, 1079);
        assert_eq!(
            [quad[0].x, quad[0].y, quad[0].u, quad[0].v],
            [-0.5, -0.5, 0.0, 0.0]
        );
        assert_eq!(
            [quad[1].x, quad[1].y, quad[1].u, quad[1].v],
            [1918.5, -0.5, 1.0, 0.0]
        );
        assert_eq!(
            [quad[2].x, quad[2].y, quad[2].u, quad[2].v],
            [-0.5, 1078.5, 0.0, 1.0]
        );
        assert_eq!(
            [quad[3].x, quad[3].y, quad[3].u, quad[3].v],
            [1918.5, 1078.5, 1.0, 1.0]
        );
        assert!(
            quad.iter()
                .all(|vertex| vertex.z == 0.0 && vertex.rhw == 1.0)
        );
        assert!(
            include_str!("blooming_hdr.rs")
                .contains("device.draw_primitive_up(D3DPT_TRIANGLESTRIP, 2, &quad)")
        );
    }

    #[test]
    fn shaders_and_luts_are_staged_outside_the_render_path() {
        let prepared = FinalColorShaderBytecode::prepare().expect("prepared final-color shaders");
        for bytecode in [
            &prepared.extract,
            &prepared.blur,
            &prepared.compose,
            &prepared.chromatic,
        ] {
            assert_eq!(bytecode.first().copied(), Some(0xffff_0300));
            assert_eq!(bytecode.last().copied(), Some(0x0000_ffff));
        }

        let source = include_str!("blooming_hdr.rs");
        let draw_start = source
            .rfind("    pub(crate) fn draw(")
            .expect("draw method");
        let draw_end = source[draw_start..]
            .find("\n    fn ensure_targets(")
            .map(|offset| draw_start + offset)
            .expect("draw method end");
        let draw = &source[draw_start..draw_end];
        for forbidden in [
            "compile_",
            "prepare_shader",
            "generate_builtin_lut",
            "Vec::",
            "fs::",
            "lock(",
        ] {
            assert!(
                !draw.contains(forbidden),
                "render path contains {forbidden}"
            );
        }
    }

    #[test]
    fn packed_luts_are_bounded_distinct_and_neutral_is_identity() {
        let identity = generate_builtin_lut(0);
        assert_eq!(identity.len(), (LUT_SIZE * LUT_SIZE * LUT_SIZE) as usize);
        for input in [
            [0.0, 0.0, 0.0],
            [1.0, 1.0, 1.0],
            [0.13, 0.52, 0.91],
            [0.87, 0.21, 0.44],
        ] {
            let output = sample_lut(&identity, input);
            for channel in 0..3 {
                assert!((output[channel] - input[channel]).abs() <= 1.0 / 255.0);
            }
        }

        let probe = [0.63, 0.37, 0.18];
        let neutral = sample_lut(&identity, probe);
        for preset in 1..LUT_COUNT {
            let pixels = generate_builtin_lut(preset);
            assert_eq!(pixels.len(), identity.len());
            let output = sample_lut(&pixels, probe);
            assert!(
                output
                    .iter()
                    .all(|value| value.is_finite() && (0.0..=1.0).contains(value))
            );
            let difference: f32 = output
                .iter()
                .zip(neutral)
                .map(|(left, right)| (left - right).abs())
                .sum();
            assert!(difference > 0.025, "preset {preset} is visually redundant");
        }
    }

    #[test]
    fn lut_reference_image_has_no_slice_seams_or_non_finite_pixels() {
        for preset in 0..LUT_COUNT {
            let pixels = generate_builtin_lut(preset);
            let mut previous = sample_lut(&pixels, [0.0, 0.0, 0.0]);
            for step in 1..=256 {
                let value = step as f32 / 256.0;
                let current = sample_lut(&pixels, [value, value, value]);
                assert!(current.iter().all(|channel| channel.is_finite()));
                let previous_luma =
                    previous[0] * 0.2126 + previous[1] * 0.7152 + previous[2] * 0.0722;
                let current_luma = current[0] * 0.2126 + current[1] * 0.7152 + current[2] * 0.0722;
                assert!(
                    current_luma + 1.0e-5 >= previous_luma,
                    "preset {preset} reverses the neutral ramp at {step}"
                );
                let maximum_jump = (0..3)
                    .map(|channel| (current[channel] - previous[channel]).abs())
                    .fold(0.0f32, f32::max);
                assert!(maximum_jump < 0.025, "preset {preset} has a LUT slice seam");
                previous = current;
            }

            for y in 0..36 {
                for x in 0..64 {
                    let input = [x as f32 / 63.0, y as f32 / 35.0, (x + y) as f32 / 98.0];
                    let sampled = sample_lut(&pixels, input);
                    let analytic = apply_lut_recipe(preset, input);
                    for channel in 0..3 {
                        assert!(sampled[channel].is_finite());
                        assert!((0.0..=1.0).contains(&sampled[channel]));
                        assert!((sampled[channel] - analytic[channel]).abs() < 0.012);
                    }
                }
            }
        }
    }

    #[test]
    fn analytic_grade_controls_have_independent_reference_contracts() {
        let lut = generate_builtin_lut(0);
        let input = [0.18, 0.42, 0.73];
        let apply = |settings| {
            grade_reference(
                input,
                [0.0; 3],
                [0.5, 0.5],
                [1920.0, 1080.0],
                settings,
                &lut,
            )
        };
        let neutral = apply(neutral_grade());
        assert!(color_distance(neutral, input) <= 1.0 / 255.0 * 3.0);

        let mut settings = neutral_grade();
        settings.exposure = 1.0;
        let exposed = apply(settings);
        assert!(exposed.iter().zip(neutral).all(|(high, low)| high > &low));

        settings = neutral_grade();
        settings.contrast = 0.5;
        let dark = grade_reference([0.25; 3], [0.0; 3], [0.5; 2], [1.0; 2], settings, &lut);
        let bright = grade_reference([0.75; 3], [0.0; 3], [0.5; 2], [1.0; 2], settings, &lut);
        let pivot = grade_reference([0.5; 3], [0.0; 3], [0.5; 2], [1.0; 2], settings, &lut);
        assert!(dark[0] < 0.25 && bright[0] > 0.75);
        assert!((pivot[0] - 0.5).abs() <= 1.0 / 255.0);

        settings = neutral_grade();
        settings.saturation = 0.0;
        let desaturated = apply(settings);
        assert!(chroma(desaturated) <= 1.0e-6);

        settings = neutral_grade();
        settings.vibrance = 1.0;
        let low_chroma = grade_reference(
            [0.40, 0.44, 0.48],
            [0.0; 3],
            [0.5; 2],
            [1.0; 2],
            settings,
            &lut,
        );
        let high_chroma = grade_reference(
            [0.05, 0.45, 0.95],
            [0.0; 3],
            [0.5; 2],
            [1.0; 2],
            settings,
            &lut,
        );
        assert!(chroma(low_chroma) / 0.08 > chroma(high_chroma) / 0.90);

        settings = neutral_grade();
        settings.temperature = 1.0;
        let warm = apply(settings);
        assert!(warm[0] > neutral[0] && warm[2] < neutral[2]);
        settings = neutral_grade();
        settings.tint = 1.0;
        let magenta = apply(settings);
        assert!(magenta[0] > neutral[0] && magenta[1] < neutral[1] && magenta[2] > neutral[2]);

        settings = neutral_grade();
        settings.black_fade = 1.0;
        let faded_black = grade_reference([0.0; 3], [0.0; 3], [0.5; 2], [1.0; 2], settings, &lut);
        assert!(
            faded_black
                .iter()
                .all(|channel| (*channel - 0.06).abs() <= 1.0 / 255.0)
        );

        settings = neutral_grade();
        settings.highlight_rolloff = 1.0;
        let values: Vec<f32> = (0..=100)
            .map(|step| {
                let value = step as f32 / 100.0;
                grade_reference([value; 3], [0.0; 3], [0.5; 2], [1.0; 2], settings, &lut)[0]
            })
            .collect();
        assert!(values.windows(2).all(|pair| pair[1] >= pair[0]));
        assert!(values[90] - values[80] < 0.10);
        assert!(values[0].abs() <= 1.0e-6 && (values[100] - 1.0).abs() <= 1.0e-6);
    }

    #[test]
    fn lut_halation_vignette_and_master_strength_obey_reference_contracts() {
        let neutral_lut = generate_builtin_lut(0);
        let stylized_lut = generate_builtin_lut(2);
        let input = [0.32, 0.48, 0.67];

        let mut settings = neutral_grade();
        settings.lut_strength = 1.0;
        let lut_output = grade_reference(
            input,
            [0.0; 3],
            [0.5; 2],
            [16.0, 9.0],
            settings,
            &stylized_lut,
        );
        assert!(color_distance(lut_output, input) > 0.02);

        settings = neutral_grade();
        settings.halation = 1.0;
        let no_bloom = grade_reference(
            input,
            [0.0; 3],
            [0.5; 2],
            [16.0, 9.0],
            settings,
            &neutral_lut,
        );
        let with_bloom = grade_reference(
            input,
            [0.8; 3],
            [0.5; 2],
            [16.0, 9.0],
            settings,
            &neutral_lut,
        );
        let delta =
            std::array::from_fn::<_, 3, _>(|channel| with_bloom[channel] - no_bloom[channel]);
        assert!(delta[0] > delta[1] && delta[1] > delta[2] && delta[2] > 0.0);

        settings = neutral_grade();
        settings.vignette = 1.0;
        let center = grade_reference(
            input,
            [0.0; 3],
            [0.5; 2],
            [16.0, 9.0],
            settings,
            &neutral_lut,
        );
        let corner = grade_reference(
            input,
            [0.0; 3],
            [0.0; 2],
            [16.0, 9.0],
            settings,
            &neutral_lut,
        );
        assert!(color_distance(center, input) <= 1.0 / 255.0 * 3.0);
        assert!(
            corner
                .iter()
                .zip(center)
                .all(|(edge, middle)| edge < &middle)
        );

        settings.exposure = 1.5;
        settings.temperature = -1.0;
        settings.lut_strength = 1.0;
        settings.halation = 1.0;
        settings.strength = 0.0;
        let bypassed = grade_reference(
            input,
            [1.0; 3],
            [0.0; 2],
            [16.0, 9.0],
            settings,
            &stylized_lut,
        );
        assert_eq!(bypassed, input);
    }

    #[test]
    fn full_reference_frames_are_finite_bounded_and_default_grade_changes_the_scene() {
        let shipped_luts = crate::luts::shipped_luts_for_test();
        let neutral_lut = &shipped_luts[0].pixels;
        let default_lut = &shipped_luts[1].pixels;
        let config = crate::config::ColorGradeConfig::default();
        let mut defaults = neutral_grade();
        defaults.strength = config.strength;
        defaults.exposure = config.exposure;
        defaults.contrast = config.contrast;
        defaults.saturation = config.saturation;
        defaults.vibrance = config.vibrance;
        defaults.temperature = config.temperature;
        defaults.tint = config.tint;
        defaults.black_fade = config.black_fade;
        defaults.highlight_rolloff = config.highlight_rolloff;
        defaults.lut_strength = config.lut_strength;
        defaults.vignette = config.vignette;
        defaults.halation = config.halation;

        let mut changed = 0usize;
        for &(width, height) in &[(63usize, 35usize), (64, 36)] {
            for y in 0..height {
                for x in 0..width {
                    let input = [
                        x as f32 / (width - 1) as f32,
                        y as f32 / (height - 1) as f32,
                        ((x * 17 + y * 29) % 101) as f32 / 100.0,
                    ];
                    let uv = [
                        (x as f32 + 0.5) / width as f32,
                        (y as f32 + 0.5) / height as f32,
                    ];
                    let output = grade_reference(
                        input,
                        [0.08, 0.05, 0.02],
                        uv,
                        [width as f32, height as f32],
                        defaults,
                        default_lut,
                    );
                    assert!(
                        output
                            .iter()
                            .all(|value| value.is_finite() && (0.0..=1.0).contains(value))
                    );
                    changed += (color_distance(output, input) > 0.005) as usize;

                    let identity = grade_reference(
                        input,
                        [0.0; 3],
                        uv,
                        [width as f32, height as f32],
                        neutral_grade(),
                        neutral_lut,
                    );
                    assert!(color_distance(identity, input) <= 3.0 / 255.0);
                }
            }
        }
        assert!(
            changed > 3_500,
            "default grade did not materially affect enough pixels"
        );
    }

    #[test]
    fn chromatic_reference_is_radial_subpixel_bounded_and_rejects_center_sample_bug() {
        for &(width, height) in &[(63usize, 35usize), (64, 36)] {
            let constant = vec![[0.31, 0.47, 0.73, 0.29]; width * height];
            for &(x, y) in &[(0, 0), (width / 2, height / 2), (width - 1, height - 1)] {
                assert_eq!(
                    chromatic_reference(&constant, width, height, x, y, 1.0),
                    constant[y * width + x]
                );
            }

            let image: Vec<[f32; 4]> = (0..height)
                .flat_map(|y| {
                    (0..width).map(move |x| {
                        [
                            x as f32 / (width - 1) as f32,
                            y as f32 / (height - 1) as f32,
                            1.0 - x as f32 / (width - 1) as f32,
                            0.37,
                        ]
                    })
                })
                .collect();
            let mut changed = 0usize;
            for y in 0..height {
                for x in 0..width {
                    let output = chromatic_reference(&image, width, height, x, y, 0.75);
                    assert!(
                        output
                            .iter()
                            .all(|value| value.is_finite() && (0.0..=1.0).contains(value))
                    );
                    assert!((output[3] - 0.37).abs() < 1.0e-6);
                    let center = image[y * width + x];
                    changed += ((output[0] - center[0]).abs() > 1.0e-5
                        || (output[2] - center[2]).abs() > 1.0e-5)
                        as usize;
                    let central = (x as isize - width as isize / 2).abs() <= 1
                        && (y as isize - height as isize / 2).abs() <= 1;
                    if central {
                        assert!((output[0] - center[0]).abs() < 0.001);
                        assert!((output[2] - center[2]).abs() < 0.001);
                    }
                }
            }
            assert!(
                changed > width * height / 2,
                "center-only negative control was not rejected"
            );
        }
    }

    #[test]
    fn remaining_finishing_controls_have_visible_default_response() {
        let defaults = crate::config::ColorGradeConfig::default();

        let mut halation = neutral_grade();
        halation.strength = defaults.strength;
        halation.halation = defaults.halation;
        let input = [0.20, 0.20, 0.20];
        let output = grade_reference(
            input,
            [0.50, 0.50, 0.50],
            [0.5; 2],
            [16.0, 9.0],
            halation,
            &identity_lut_pixels(32),
        );
        assert!(
            output[0] - input[0] >= 2.0 / 255.0,
            "default halation changes red by only {:.3} code values",
            (output[0] - input[0]) * 255.0
        );

        let chromatic_edge_shift = defaults.chromatic_aberration * defaults.strength;
        assert!(
            chromatic_edge_shift >= 0.5,
            "default chromatic shift is only {chromatic_edge_shift:.3} px"
        );
    }

    #[test]
    fn every_other_default_finishing_family_survives_unorm8_output() {
        let defaults = crate::config::ColorGradeConfig::default();
        let identity_lut = identity_lut_pixels(32);
        let shipped_luts = crate::luts::shipped_luts_for_test();
        let probes = [
            [31.0 / 255.0, 74.0 / 255.0, 169.0 / 255.0],
            [92.0 / 255.0, 131.0 / 255.0, 48.0 / 255.0],
            [193.0 / 255.0, 142.0 / 255.0, 67.0 / 255.0],
            [224.0 / 255.0, 209.0 / 255.0, 187.0 / 255.0],
        ];
        let code_distance = |left: [f32; 3], right: [f32; 3]| -> u32 {
            (0..3)
                .map(|channel| {
                    (unorm8_code(left[channel]) as i16 - unorm8_code(right[channel]) as i16)
                        .unsigned_abs() as u32
                })
                .sum()
        };

        let neutral = neutral_grade();
        let mut analytic = neutral;
        analytic.strength = defaults.strength;
        analytic.exposure = defaults.exposure;
        analytic.contrast = defaults.contrast;
        analytic.saturation = defaults.saturation;
        analytic.vibrance = defaults.vibrance;
        analytic.temperature = defaults.temperature;
        analytic.tint = defaults.tint;
        analytic.black_fade = defaults.black_fade;
        analytic.highlight_rolloff = defaults.highlight_rolloff;
        let analytic_delta: u32 = probes
            .iter()
            .map(|input| {
                code_distance(
                    grade_reference(
                        *input,
                        [0.0; 3],
                        [0.5; 2],
                        [1920.0, 1080.0],
                        analytic,
                        &identity_lut,
                    ),
                    grade_reference(
                        *input,
                        [0.0; 3],
                        [0.5; 2],
                        [1920.0, 1080.0],
                        neutral,
                        &identity_lut,
                    ),
                )
            })
            .sum();
        assert!(
            analytic_delta >= 8,
            "default analytic grade changes the probe set by only {analytic_delta} code values"
        );

        let mut lut = neutral;
        lut.strength = defaults.strength;
        lut.lut_strength = defaults.lut_strength;
        let lut_delta: u32 = probes
            .iter()
            .map(|input| {
                code_distance(
                    grade_reference(
                        *input,
                        [0.0; 3],
                        [0.5; 2],
                        [1920.0, 1080.0],
                        lut,
                        &shipped_luts[1].pixels,
                    ),
                    grade_reference(
                        *input,
                        [0.0; 3],
                        [0.5; 2],
                        [1920.0, 1080.0],
                        neutral,
                        &identity_lut,
                    ),
                )
            })
            .sum();
        assert!(
            lut_delta >= 12,
            "default LUT changes the probe set by only {lut_delta} code values"
        );

        let input = [128.0 / 255.0; 3];
        let mut vignette = neutral;
        vignette.strength = defaults.strength;
        vignette.vignette = defaults.vignette;
        let vignette_output = grade_reference(
            input,
            [0.0; 3],
            [0.0, 0.5],
            [1920.0, 1080.0],
            vignette,
            &identity_lut,
        );
        assert!(
            code_distance(vignette_output, input) >= 3,
            "default vignette disappears at the quantized screen edge"
        );

        let mut halation = neutral;
        halation.strength = defaults.strength;
        halation.halation = defaults.halation;
        let halation_input = [51.0 / 255.0; 3];
        let halation_output = grade_reference(
            halation_input,
            [0.5; 3],
            [0.5; 2],
            [1920.0, 1080.0],
            halation,
            &identity_lut,
        );
        assert!(
            code_distance(halation_output, halation_input) >= 10,
            "default halation disappears at the quantized output"
        );

        let width = 64usize;
        let height = 36usize;
        let image: Vec<[f32; 4]> = (0..height)
            .flat_map(|_| {
                (0..width).map(|x| {
                    let value = x as f32 / (width - 1) as f32;
                    [value, 0.37, 1.0 - value, 0.61]
                })
            })
            .collect();
        let chromatic_amount = defaults.chromatic_aberration * defaults.strength;
        let chromatic_changed = (0..height)
            .flat_map(|y| (0..width).map(move |x| (x, y)))
            .filter(|&(x, y)| {
                let output = chromatic_reference(&image, width, height, x, y, chromatic_amount);
                let center = image[y * width + x];
                unorm8_code(output[0]) != unorm8_code(center[0])
                    || unorm8_code(output[2]) != unorm8_code(center[2])
            })
            .count();
        assert!(
            chromatic_changed >= width * height / 4,
            "enabled default chromatic response changes only {chromatic_changed} quantized pixels"
        );
    }

    #[test]
    fn default_film_grain_survives_the_unorm8_output_boundary() {
        let defaults = crate::config::ColorGradeConfig::default();
        let width = 4096usize;
        let input = [128.0 / 255.0; 3];
        let input_code = unorm8_code(input[0]) as i16;
        let deltas: Vec<i16> = (0..width)
            .map(|x| {
                let output = film_grain_reference(
                    input,
                    [x as f32 + 0.5, 37.5],
                    [width as f32, 64.0],
                    41.0,
                    defaults.film_grain,
                    defaults.strength,
                );
                unorm8_code(output[0]) as i16 - input_code
            })
            .collect();
        let changed = deltas.iter().filter(|delta| **delta != 0).count();
        let rms = (deltas
            .iter()
            .map(|delta| (*delta as f32).powi(2))
            .sum::<f32>()
            / width as f32)
            .sqrt();
        assert!(
            changed >= width * 3 / 10,
            "default grain changed only {changed}/{width} quantized midtone pixels"
        );
        assert!(
            rms >= 0.55,
            "default grain reaches only {rms:.3} code-value RMS after quantization"
        );
    }

    #[test]
    fn default_deband_dither_survives_unorm8_and_stays_edge_gated() {
        let defaults = crate::config::ColorGradeConfig::default();
        let width = 8192usize;
        let input = [128.0 / 255.0; 3];
        let input_code = unorm8_code(input[0]) as i16;
        let strength = defaults.deband * defaults.strength;
        let deltas: Vec<i16> = (0..width)
            .map(|x| {
                let output =
                    finishing_dither_reference(input, [x as f32 + 0.5, 23.5], 41.0, strength, 1.0);
                unorm8_code(output[0]) as i16 - input_code
            })
            .collect();
        let changed = deltas.iter().filter(|delta| **delta != 0).count();
        let mean = deltas.iter().map(|delta| *delta as f32).sum::<f32>() / width as f32;
        assert!(
            changed >= width / 4,
            "default deband changed only {changed}/{width} quantized flat pixels"
        );
        assert!(
            mean.abs() <= 0.05,
            "default deband dither has a {mean:.3}-code bias"
        );

        for x in 0..256 {
            let output = finishing_dither_reference(input, [x as f32 + 0.5, 23.5], 41.0, 1.0, 0.0);
            assert_eq!(output, input, "edge rejection leaked dither at pixel {x}");
        }
    }

    #[test]
    fn debanding_is_identity_on_constants_and_softens_quantized_steps() {
        for &(width, height) in &[(63usize, 35usize), (64, 36)] {
            let constant = vec![[0.42, 0.42, 0.42]; width * height];
            for &(x, y) in &[
                (0, 0),
                (width - 1, 0),
                (0, height - 1),
                (width / 2, height / 2),
            ] {
                assert_eq!(
                    deband_reference(&constant, width, height, x, y, 1.0),
                    [0.42; 3]
                );
            }
        }

        let width = 513usize;
        let image: Vec<[f32; 3]> = (0..width)
            .map(|x| {
                let band = ((x as f32 / (width - 1) as f32) * 255.0).floor() / 255.0;
                [band; 3]
            })
            .collect();
        let boundary = (1..width - 1)
            .find(|x| image[*x][0] != image[x - 1][0])
            .expect("band boundary");
        let original_jump = image[boundary][0] - image[boundary - 1][0];
        let filtered_left = deband_reference(&image, width, 1, boundary - 1, 0, 1.0)[0];
        let filtered_right = deband_reference(&image, width, 1, boundary, 0, 1.0)[0];
        assert!(filtered_right - filtered_left < original_jump);
        assert_eq!(
            deband_reference(&image, width, 1, boundary, 0, 0.0),
            image[boundary]
        );
    }

    #[test]
    fn debanding_preserves_edges_thin_features_gradients_and_frame_boundaries() {
        let width = 17usize;
        let height = 9usize;
        let mut hard_edge = vec![[0.05; 3]; width * height];
        for y in 0..height {
            for x in width / 2..width {
                hard_edge[y * width + x] = [0.95; 3];
            }
        }
        for x in [width / 2 - 1, width / 2] {
            assert_eq!(
                deband_reference(&hard_edge, width, height, x, height / 2, 1.0),
                hard_edge[height / 2 * width + x]
            );
        }

        let mut thin = vec![[0.1; 3]; width * height];
        thin[(height / 2) * width + width / 2] = [1.0, 0.8, 0.2];
        assert_eq!(
            deband_reference(&thin, width, height, width / 2, height / 2, 1.0),
            [1.0, 0.8, 0.2]
        );

        let gradient: Vec<[f32; 3]> = (0..height)
            .flat_map(|_| (0..width).map(|x| [x as f32 / (width - 1) as f32; 3]))
            .collect();
        for x in 1..width - 1 {
            let output = deband_reference(&gradient, width, height, x, height / 2, 1.0);
            assert!((output[0] - gradient[height / 2 * width + x][0]).abs() < 1.0e-6);
        }
        for &(x, y) in &[
            (0, 0),
            (width - 1, 0),
            (0, height - 1),
            (width - 1, height - 1),
        ] {
            let output = deband_reference(&gradient, width, height, x, y, 1.0);
            assert!(
                output
                    .iter()
                    .all(|value| value.is_finite() && (0.0..=1.0).contains(value))
            );
        }
    }

    #[test]
    fn grain_and_dither_noise_is_deterministic_decorrelated_and_strictly_bounded() {
        let pixels = [[0.5, 0.5], [12.5, 8.5], [1919.5, 1079.5]];
        for pixel in pixels {
            let first = golden_noise(pixel, 41.0);
            assert_eq!(first, golden_noise(pixel, 41.0));
            assert!((0.0..1.0).contains(&first));
            assert_ne!(first, golden_noise(pixel, 42.0));
            let maximum_grain = (first - 0.5).abs() * FILM_GRAIN_NOISE_CODES / 255.0;
            let maximum_dither = (first - 0.5).abs() * DEBAND_DITHER_NOISE_CODES / 255.0;
            assert!(maximum_grain <= 12.0 / 255.0 + 1.0e-7);
            assert!(maximum_dither <= 2.0 / 255.0 + 1.0e-7);
        }

        let defaults = crate::config::ColorGradeConfig::default();
        let midtone_mask = 1.0 - 0.5 * 0.65;
        let mean_square_codes = (0..1024)
            .map(|index| {
                let noise = golden_noise([index as f32 + 0.5, 37.5], 41.0) - 0.5;
                let codes = noise
                    * FILM_GRAIN_NOISE_CODES
                    * defaults.film_grain
                    * defaults.strength
                    * midtone_mask;
                codes * codes
            })
            .sum::<f32>()
            / 1024.0;
        assert!(
            mean_square_codes.sqrt() >= 0.20,
            "default grain RMS is still visually inert"
        );
    }

    #[test]
    fn native_environment_response_is_stable_and_fail_open() {
        let mut frame = FrameInputs::default();
        assert_eq!(native_environment_weight(&frame), 1.0);

        frame.material_state = MaterialStateFrame {
            exterior_known: true,
            is_exterior: true,
        };
        frame.sky = Some(NativeSkyFrame {
            sky_upper: [0.0; 3],
            sky_lower: [0.0; 3],
            horizon: [0.0; 3],
            sun_light: [0.0; 3],
            sun_disk: [0.0; 3],
            sun_direction: [0.0, 0.0, 1.0],
            daylight: 0.0,
            game_hour: 0.0,
            is_exterior: true,
            reversed_depth: true,
        });
        assert!((native_environment_weight(&frame) - 0.78).abs() < 1.0e-6);
        frame.sky.as_mut().expect("sky").daylight = 1.0;
        assert_eq!(native_environment_weight(&frame), 1.0);
        frame.material_state.is_exterior = false;
        assert!((native_environment_weight(&frame) - 0.70).abs() < 1.0e-6);
    }

    #[test]
    fn environment_response_modulates_only_stylized_lut_strength() {
        let lut = crate::luts::shipped_luts_for_test().swap_remove(1);
        let lut_names = vec![lut.display_name.clone()];
        let lut_ids = vec![lut.id];
        let mut config = EmbeddedEffectsConfig::default();
        config.color_grade.lut_file_id = lut.id;
        config.color_grade.lut_strength = 0.8;
        config.color_grade.environment_response = 1.0;
        let sources =
            shaders::merge_embedded_sources_with_luts(&config, &lut_names, &lut_ids, Vec::new());
        let source = sources
            .iter()
            .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade))
            .expect("color grade source");

        let unknown = ColorGradeSettings::from_source_with_lut(
            Some(source),
            &FrameInputs::default(),
            Some(&lut),
        );
        assert!((unknown.lut_strength - 0.8).abs() < 1.0e-6);

        let mut interior = FrameInputs::default();
        interior.material_state = MaterialStateFrame {
            exterior_known: true,
            is_exterior: false,
        };
        let interior =
            ColorGradeSettings::from_source_with_lut(Some(source), &interior, Some(&lut));
        assert!((interior.lut_strength - 0.56).abs() < 1.0e-6);

        let mut no_response = config;
        no_response.color_grade.environment_response = 0.0;
        let sources = shaders::merge_embedded_sources_with_luts(
            &no_response,
            &lut_names,
            &lut_ids,
            Vec::new(),
        );
        let source = sources
            .iter()
            .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade))
            .expect("color grade source");
        let interior = ColorGradeSettings::from_source_with_lut(
            Some(source),
            &FrameInputs {
                material_state: MaterialStateFrame {
                    exterior_known: true,
                    is_exterior: false,
                },
                ..FrameInputs::default()
            },
            Some(&lut),
        );
        assert!((interior.lut_strength - 0.8).abs() < 1.0e-6);

        no_response.color_grade.lut_enabled = false;
        no_response.color_grade.lut_strength = 1.0;
        let sources = shaders::merge_embedded_sources_with_luts(
            &no_response,
            &lut_names,
            &lut_ids,
            Vec::new(),
        );
        let source = sources
            .iter()
            .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade))
            .expect("color grade source");
        assert_eq!(
            ColorGradeSettings::from_source(Some(source), &FrameInputs::default()).lut_strength,
            0.0
        );
    }

    #[test]
    fn zero_strength_skips_grade_only_pipeline_creation_and_draw() {
        let mut config = EmbeddedEffectsConfig::default();
        config.blooming_hdr.enabled = false;
        config.color_grade.enabled = true;
        config.color_grade.strength = 0.0;
        let sources = shaders::merge_embedded_sources(&config, Vec::new());
        let source = sources
            .iter()
            .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade))
            .expect("color grade source");
        assert!(!color_grade_source_active(source));
        assert!(
            !ColorGradeSettings::from_source(Some(source), &FrameInputs::default()).is_active()
        );
        let bloom = sources
            .iter()
            .find(|candidate| {
                candidate.embedded_effect_kind() == Some(EmbeddedEffectKind::BloomingHdr)
            })
            .expect("bloom source");
        assert!(!FinalColorWorkPlan::from_sources(Some(bloom), Some(source)).has_work());
    }

    #[test]
    fn render_boundary_sanitizes_every_untrusted_grade_option() {
        let mut config = EmbeddedEffectsConfig::default();
        config.color_grade.strength = 99.0;
        config.color_grade.exposure = -99.0;
        config.color_grade.contrast = 99.0;
        config.color_grade.saturation = -99.0;
        config.color_grade.vibrance = 99.0;
        config.color_grade.temperature = -99.0;
        config.color_grade.tint = 99.0;
        config.color_grade.black_fade = 99.0;
        config.color_grade.highlight_rolloff = 99.0;
        config.color_grade.lut_strength = 99.0;
        config.color_grade.deband = 99.0;
        config.color_grade.film_grain = 99.0;
        config.color_grade.vignette = 99.0;
        config.color_grade.halation = 99.0;
        config.color_grade.chromatic_aberration = 99.0;
        let sources = shaders::merge_embedded_sources(&config, Vec::new());
        let source = sources
            .iter()
            .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade))
            .expect("color grade source");
        let settings = ColorGradeSettings::from_source(Some(source), &FrameInputs::default());
        assert_eq!(settings.strength, 1.0);
        assert_eq!(settings.exposure, -1.5);
        assert_eq!(settings.contrast, 0.5);
        assert_eq!(settings.saturation, 0.0);
        assert_eq!(settings.vibrance, 1.0);
        assert_eq!(settings.temperature, -1.0);
        assert_eq!(settings.tint, 1.0);
        assert_eq!(settings.black_fade, 1.0);
        assert_eq!(settings.highlight_rolloff, 1.0);
        assert_eq!(settings.lut_strength, 1.0);
        assert_eq!(settings.deband, 1.0);
        assert_eq!(settings.film_grain, 1.0);
        assert_eq!(settings.vignette, 1.0);
        assert_eq!(settings.halation, 1.0);
        assert_eq!(settings.chromatic_aberration, 4.0);
    }

    #[test]
    fn lut_switch_or_missing_catalog_is_an_exact_shader_bypass() {
        let mut config = EmbeddedEffectsConfig::default();
        config.color_grade.lut_enabled = false;
        config.color_grade.lut_strength = 1.0;
        let sources = shaders::merge_embedded_sources(&config, Vec::new());
        let source = sources
            .iter()
            .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade))
            .expect("color grade source");
        let settings = ColorGradeSettings::from_source(Some(source), &FrameInputs::default());
        assert_eq!(settings.lut_strength, 0.0);

        config.color_grade.lut_enabled = true;
        let sources = shaders::merge_embedded_sources(&config, Vec::new());
        let source = sources
            .iter()
            .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade))
            .expect("color grade source");
        let settings =
            ColorGradeSettings::from_source_with_lut(Some(source), &FrameInputs::default(), None);
        assert_eq!(settings.lut_strength, 0.0);
    }

    #[test]
    fn color_grade_constant_abi_matches_all_shader_register_lanes() {
        let settings = ColorGradeSettings {
            enabled: true,
            strength: 0.11,
            color_grading_enabled: true,
            exposure: 0.22,
            contrast: 0.33,
            saturation: 0.44,
            vibrance: 0.55,
            temperature: 0.66,
            tint: 0.77,
            black_fade: 0.88,
            highlight_rolloff: 0.99,
            lut_enabled: true,
            lut_strength: 0.12,
            deband_enabled: true,
            deband: 0.23,
            film_grain_enabled: true,
            film_grain: 0.34,
            vignette_enabled: true,
            vignette: 0.45,
            halation_enabled: true,
            halation: 0.56,
            chromatic_aberration_enabled: true,
            chromatic_aberration: 0.78,
            debug_split: true,
            environment_weight: 0.67,
            lut_size: 17.0,
            lut_domain_min: [0.0, 0.0, 0.0],
            lut_domain_max: [2.0, 4.0, 0.5],
        };
        assert_eq!(
            settings.constants(true),
            [
                [0.11, 0.22, 0.33, 0.44],
                [0.55, 0.66, 0.77, 0.88],
                [0.99, 0.12, 0.23, 0.34],
                [0.45, 0.56, 1.0, 0.78],
                [1.0, 1.0, 0.67, 0.0],
                [1.0, 1.0, 1.0, 1.0],
                [1.0, 1.0, 1.0, 0.0],
                [0.5, 0.25, 2.0, 17.0],
                [0.0, 0.0, 0.0, 0.0],
            ]
        );

        let source = std::str::from_utf8(COMPOSE_SHADER).expect("compose UTF-8");
        for declaration in [
            "float4 GradeData0 : register(c10);",
            "float4 GradeData1 : register(c11);",
            "float4 GradeData2 : register(c12);",
            "float4 GradeData3 : register(c13);",
            "float4 GradeData4 : register(c14);",
            "float4 GradeData5 : register(c15);",
            "float4 GradeData6 : register(c16);",
            "float4 LutDomainScale : register(c17);",
            "float4 LutDomainBias : register(c18);",
            "sampler2D ColorLut : register(s5);",
        ] {
            assert!(
                source.contains(declaration),
                "missing ABI declaration {declaration}"
            );
        }
        for equation in [
            "float3 color = inputColor * exp2(GradeData0.y);",
            "color = 0.5f.xxx + (color - 0.5f.xxx) * (1.0f + GradeData0.z);",
            "float adaptiveVibrance = 1.0f + GradeData1.x * (1.0f - saturate(chromaRange));",
            "float saturation = GradeData0.w * adaptiveVibrance;",
            "float blackFade = GradeData1.w * 0.06f;",
            "color = color * (1.0f + shoulder) / (1.0f + shoulder * color);",
            "color = lerp(color, lutColor, GradeData2.y * master);",
            "* GradeData3.y * master * 0.85f;",
            "color *= 1.0f - vignette * GradeData3.x * master * 0.32f;",
            "return lerp(inputColor, color, master);",
            "return lerp(center, average, strength * flatWeight * 0.85f);",
            "base = DebandScene(input.uv, base, debandFlatWeight);",
            "static const float FilmGrainNoiseScaleCodes = 24.0f;",
            "static const float DebandDitherNoiseScaleCodes = 4.0f;",
            "? GradeData2.z * GradeData0.x * debandFlatWeight * DebandDitherNoiseScaleCodes",
            "* grainMask * FilmGrainNoiseScaleCodes / 255.0f;",
        ] {
            assert!(
                source.contains(equation),
                "CPU reference lost shader equation: {equation}"
            );
        }
        assert!(source.contains("GradeData3.z > 0.5f"));
        assert!(source.contains("GradeData4.x > 0.5f"));
        assert!(source.contains("GradeData4.y > 0.5f"));
    }

    #[test]
    fn final_color_contract_preserves_alpha_and_avoids_screen_adaptation() {
        let source = std::str::from_utf8(COMPOSE_SHADER).expect("compose UTF-8");
        assert!(source.contains("baseSample.a"));
        assert!(source.contains("SampleColorLut"));
        assert_eq!(source.matches("tex2Dlod(ColorLut").count(), 2);
        assert!(!source.contains("averageLuma"));
        assert!(!source.contains("AutoExposure"));
        assert!(!source.contains("ddx("));
        assert!(!source.contains("ddy("));
        assert!(source.contains("color = input.uv.x < 0.5f ? ungraded : color"));

        let chromatic = std::str::from_utf8(CHROMATIC_SHADER).expect("chromatic UTF-8");
        assert_eq!(chromatic.matches("SampleScene(").count(), 4);
        assert!(chromatic.contains("radialDirection * ScreenData.zw * ChromaticData.x"));
        assert!(chromatic.contains("length((input.uv - 0.5f) * 2.0f)"));
        assert!(chromatic.contains("return float4(red, center.g, blue, center.a);"));
        assert!(!chromatic.contains("ddx("));
        assert!(!chromatic.contains("ddy("));

        let implementation = include_str!("blooming_hdr.rs");
        assert!(implementation.contains("if composed {"));
        assert!(implementation.contains("if work.bloom_intermediate {"));
        assert!(implementation.contains("bind_bloom_effect_constants"));
        assert!(implementation.contains("&grade.constants(bloom_enabled)"));
        assert!(implementation.contains(
            "device.stretch_rect(backbuffer, None, scene_copy_surface, None, D3DTEXF_POINT)?"
        ));
        assert!(implementation.contains("self.draw_chromatic_aberration("));
    }
}

pub(crate) struct BloomingHdrEffect {
    extract_shader: PixelShader9,
    blur_shader: PixelShader9,
    compose_shader: PixelShader9,
    chromatic_shader: PixelShader9,
    neutral_bloom: Texture9,
    lut_texture: Texture9,
    lut_revision: Option<(u32, u64)>,
    targets: Option<BloomTargets>,
}

impl BloomingHdrEffect {
    pub(crate) fn create(
        device: &Device9Ref<'_>,
        shaders: &FinalColorShaderBytecode,
    ) -> Direct3DResult<Self> {
        Ok(Self {
            extract_shader: device.create_pixel_shader(&shaders.extract)?,
            blur_shader: device.create_pixel_shader(&shaders.blur)?,
            compose_shader: device.create_pixel_shader(&shaders.compose)?,
            chromatic_shader: device.create_pixel_shader(&shaders.chromatic)?,
            neutral_bloom: create_argb_texture(device, 1, 1, &[0xFF00_0000])?,
            lut_texture: create_argb_texture(device, 4, 2, &identity_lut_pixels(2))?,
            lut_revision: None,
            targets: None,
        })
    }

    pub(crate) fn draw(
        &mut self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &FrameInputs,
        bloom_source: Option<&ScreenShaderSource>,
        color_grade_source: Option<&ScreenShaderSource>,
        selected_lut: Option<&LutAsset>,
        scene_copy_surface: &Surface9,
        scene_color: &Texture9,
        frame_index: u32,
    ) -> Direct3DResult<()> {
        let bloom_source = bloom_source.filter(|source| source.enabled);
        let work = FinalColorWorkPlan::from_sources_with_lut_available(
            bloom_source,
            color_grade_source,
            selected_lut.is_some(),
        );
        let grade = ColorGradeSettings::from_source_with_lut(
            color_grade_source,
            frame_inputs,
            selected_lut,
        );
        if !work.has_work() {
            return Ok(());
        }

        if grade.lut_enabled {
            self.ensure_lut(device, selected_lut)?;
        }
        bind_pipeline_state(device)?;
        bind_depth_inputs(device, &frame_inputs.depth.first_person_texture)?;

        if work.bloom_intermediate {
            self.ensure_targets(device, desc)?;
            let Some(targets) = self.targets.as_ref() else {
                return Ok(());
            };
            self.draw_extract(
                device,
                targets,
                desc,
                frame_inputs,
                bloom_source,
                scene_color,
                frame_index,
            )?;
            self.draw_blur(
                device,
                targets,
                frame_inputs,
                bloom_source,
                frame_index,
                [targets.inv_width, 0.0],
            )?;
            self.draw_blur(
                device,
                targets,
                frame_inputs,
                bloom_source,
                frame_index,
                [0.0, targets.inv_height],
            )?;
        }

        let composed = work.bloom || grade.is_active();
        if composed {
            self.draw_compose(
                device,
                backbuffer,
                desc,
                frame_inputs,
                bloom_source,
                &grade,
                work.bloom_intermediate,
                work.bloom,
                scene_color,
                frame_index,
            )?;
        }
        if work.chromatic_aberration {
            if composed {
                device.clear_texture(0)?;
                device.stretch_rect(backbuffer, None, scene_copy_surface, None, D3DTEXF_POINT)?;
            }
            self.draw_chromatic_aberration(
                device,
                backbuffer,
                desc,
                scene_color,
                grade.chromatic_aberration * grade.strength,
            )?;
        }
        Ok(())
    }

    fn ensure_lut(
        &mut self,
        device: &Device9Ref<'_>,
        selected_lut: Option<&LutAsset>,
    ) -> Direct3DResult<()> {
        let Some(asset) = selected_lut else {
            return Ok(());
        };
        let revision = (asset.id, asset.revision);
        if self.lut_revision == Some(revision) {
            return Ok(());
        }
        let texture =
            create_argb_texture(device, asset.size * asset.size, asset.size, &asset.pixels)?;
        self.lut_texture = texture;
        self.lut_revision = Some(revision);
        log::info!("[LUT] Uploaded {} ({}^3)", asset.file_name, asset.size);
        Ok(())
    }

    fn ensure_targets(
        &mut self,
        device: &Device9Ref<'_>,
        desc: &D3DSURFACE_DESC,
    ) -> Direct3DResult<()> {
        let (width, height) = bloom_target_dimensions(desc.Width, desc.Height);
        let format = desc.Format;

        let needs_targets = self
            .targets
            .as_ref()
            .is_none_or(|targets| !targets.matches(width, height, format));
        if needs_targets {
            self.targets = Some(BloomTargets::create(device, width, height, format)?);
            log::info!("[BLOOM_HDR] Intermediate targets: {}x{}", width, height);
        }

        Ok(())
    }

    fn draw_extract(
        &self,
        device: &Device9Ref<'_>,
        targets: &BloomTargets,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &FrameInputs,
        source: Option<&ScreenShaderSource>,
        scene_color: &Texture9,
        frame_index: u32,
    ) -> Direct3DResult<()> {
        bind_target(
            device,
            &targets.extract.surface,
            targets.width,
            targets.height,
        )?;
        device.set_texture(0, scene_color)?;
        bind_common_constants(device, desc, frame_inputs, source, frame_index, 0.0)?;
        device.set_pixel_shader(&self.extract_shader)?;
        draw_quad(device, targets.width, targets.height)
    }

    fn draw_blur(
        &self,
        device: &Device9Ref<'_>,
        targets: &BloomTargets,
        frame_inputs: &FrameInputs,
        source: Option<&ScreenShaderSource>,
        frame_index: u32,
        direction: [f32; 2],
    ) -> Direct3DResult<()> {
        let (input, output) = if direction[0] != 0.0 {
            (&targets.extract.texture, &targets.blur.surface)
        } else {
            (&targets.blur.texture, &targets.extract.surface)
        };

        bind_target(device, output, targets.width, targets.height)?;
        device.set_texture(0, input)?;
        bind_lowres_constants(device, targets, frame_inputs, source, frame_index, 1.0)?;
        device.set_pixel_shader_constant_f(
            EFFECT_CONSTANT_REGISTER,
            &[[direction[0], direction[1], 0.0, 0.0]],
        )?;
        device.set_pixel_shader(&self.blur_shader)?;
        draw_quad(device, targets.width, targets.height)
    }

    fn draw_compose(
        &self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &FrameInputs,
        bloom_source: Option<&ScreenShaderSource>,
        grade: &ColorGradeSettings,
        bloom_texture_ready: bool,
        bloom_enabled: bool,
        scene_color: &Texture9,
        frame_index: u32,
    ) -> Direct3DResult<()> {
        bind_target(device, backbuffer, desc.Width, desc.Height)?;
        device.set_texture(0, scene_color)?;
        bind_depth_inputs(device, &frame_inputs.depth.first_person_texture)?;
        let bloom_texture = if bloom_texture_ready {
            self.targets
                .as_ref()
                .map(|targets| &targets.extract.texture)
                .unwrap_or(&self.neutral_bloom)
        } else {
            &self.neutral_bloom
        };
        device.set_texture(4, bloom_texture)?;
        device.set_texture(5, &self.lut_texture)?;
        bind_compose_constants(
            device,
            desc,
            frame_inputs,
            bloom_source,
            grade,
            bloom_enabled,
            frame_index,
        )?;
        let target_data = self
            .targets
            .as_ref()
            .map_or([1.0, 1.0, 1.0, 1.0], |targets| {
                [
                    targets.inv_width,
                    targets.inv_height,
                    targets.width as f32,
                    targets.height as f32,
                ]
            });
        device.set_pixel_shader_constant_f(EFFECT_CONSTANT_REGISTER, &[target_data])?;
        device.set_pixel_shader(&self.compose_shader)?;
        draw_quad(device, desc.Width, desc.Height)
    }

    fn draw_chromatic_aberration(
        &self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        scene_color: &Texture9,
        amount_pixels: f32,
    ) -> Direct3DResult<()> {
        bind_target(device, backbuffer, desc.Width, desc.Height)?;
        device.set_texture(0, scene_color)?;
        device.set_pixel_shader_constant_f(
            0,
            &[[
                desc.Width as f32,
                desc.Height as f32,
                1.0 / desc.Width as f32,
                1.0 / desc.Height as f32,
            ]],
        )?;
        device.set_pixel_shader_constant_f(3, &[[amount_pixels, 0.0, 0.0, 0.0]])?;
        device.set_pixel_shader(&self.chromatic_shader)?;
        draw_quad(device, desc.Width, desc.Height)
    }
}

fn bind_pipeline_state(device: &Device9Ref<'_>) -> Direct3DResult<()> {
    device.clear_vertex_shader()?;
    device.set_fvf(ScreenVertex::FVF)?;
    device.set_render_state(D3DRS_CULLMODE, D3DCULL_NONE.0 as u32)?;
    device.set_render_state(D3DRS_ALPHABLENDENABLE, 0)?;
    device.set_render_state(D3DRS_ALPHATESTENABLE, 0)?;
    device.set_render_state(D3DRS_ZENABLE, 0)?;
    device.set_render_state(D3DRS_ZWRITEENABLE, 0)?;
    device.set_render_state(D3DRS_STENCILENABLE, 0)?;
    device.set_render_state(D3DRS_SCISSORTESTENABLE, 0)?;
    device.set_render_state(D3DRS_MULTISAMPLEANTIALIAS, 1)?;
    device.set_render_state(D3DRS_MULTISAMPLEMASK, u32::MAX)?;
    match crate::backend::fnv_alpha_coverage_mode() {
        crate::backend::AlphaCoverageMode::None => {}
        crate::backend::AlphaCoverageMode::Nvidia => {
            device.set_render_state(D3DRS_ADAPTIVETESS_Y, 0)?;
        }
        crate::backend::AlphaCoverageMode::Amd => {
            device.set_render_state(D3DRS_POINTSIZE, AMD_ALPHA_TO_COVERAGE_OFF)?;
        }
    }
    device.set_render_state(D3DRS_SRGBWRITEENABLE, 0)?;
    device.set_render_state(D3DRS_COLORWRITEENABLE, COLOR_WRITE_ALL)?;
    for sampler in 0..=5 {
        device.set_sampler_state(sampler, D3DSAMP_ADDRESSU, D3DTADDRESS_CLAMP.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_ADDRESSV, D3DTADDRESS_CLAMP.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_MINFILTER, D3DTEXF_LINEAR.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_MAGFILTER, D3DTEXF_LINEAR.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_MIPFILTER, D3DTEXF_NONE.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_SRGBTEXTURE, 0)?;
    }
    for sampler in [1, 2] {
        device.set_sampler_state(sampler, D3DSAMP_MINFILTER, D3DTEXF_POINT.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_MAGFILTER, D3DTEXF_POINT.0 as u32)?;
    }
    device.set_texture_stage_state(0, D3DTSS_COLOROP, D3DTOP_SELECTARG1.0 as u32)?;
    device.set_texture_stage_state(0, D3DTSS_COLORARG1, D3DTA_TEXTURE)?;
    device.set_texture_stage_state(0, D3DTSS_ALPHAOP, D3DTOP_SELECTARG1.0 as u32)?;
    device.set_texture_stage_state(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE)?;
    Ok(())
}

fn bind_target(
    device: &Device9Ref<'_>,
    surface: &Surface9,
    width: u32,
    height: u32,
) -> Direct3DResult<()> {
    let viewport = D3DVIEWPORT9 {
        X: 0,
        Y: 0,
        Width: width,
        Height: height,
        MinZ: 0.0,
        MaxZ: 1.0,
    };

    device.clear_texture(0)?;
    device.clear_texture(4)?;
    device.clear_texture(5)?;
    device.set_depth_stencil_surface(None)?;
    for index in 1..=3 {
        device.clear_render_target(index)?;
    }
    device.set_render_target(0, surface)?;
    device.set_viewport(&viewport)
}

fn bind_depth_inputs(
    device: &Device9Ref<'_>,
    first_person_depth: &Option<DepthTexture>,
) -> Direct3DResult<()> {
    if let Some(depth) = first_person_depth {
        unsafe {
            device.set_raw_base_texture(2, depth.as_ptr())?;
        }
    } else {
        device.clear_texture(2)?;
    }

    Ok(())
}

fn bind_common_constants(
    device: &Device9Ref<'_>,
    desc: &D3DSURFACE_DESC,
    frame_inputs: &FrameInputs,
    source: Option<&ScreenShaderSource>,
    frame_index: u32,
    pass_index: f32,
) -> Direct3DResult<()> {
    device.set_pixel_shader_constant_f(
        0,
        &[
            [
                desc.Width as f32,
                desc.Height as f32,
                1.0 / desc.Width as f32,
                1.0 / desc.Height as f32,
            ],
            [
                frame_index as f32,
                pass_index,
                4.0,
                frame_inputs.depth.first_person_texture.is_some() as u8 as f32,
            ],
            [
                frame_inputs.camera.near_z,
                frame_inputs.camera.far_z,
                frame_inputs.camera.aspect_ratio,
                frame_inputs.depth.provider_id(),
            ],
        ],
    )?;
    bind_bloom_effect_constants(device, frame_inputs, source)
}

fn bind_lowres_constants(
    device: &Device9Ref<'_>,
    targets: &BloomTargets,
    frame_inputs: &FrameInputs,
    source: Option<&ScreenShaderSource>,
    frame_index: u32,
    pass_index: f32,
) -> Direct3DResult<()> {
    device.set_pixel_shader_constant_f(
        0,
        &[
            [
                targets.width as f32,
                targets.height as f32,
                targets.inv_width,
                targets.inv_height,
            ],
            [
                frame_index as f32,
                pass_index,
                4.0,
                frame_inputs.depth.first_person_texture.is_some() as u8 as f32,
            ],
            [
                frame_inputs.camera.near_z,
                frame_inputs.camera.far_z,
                frame_inputs.camera.aspect_ratio,
                frame_inputs.depth.provider_id(),
            ],
        ],
    )?;
    bind_bloom_effect_constants(device, frame_inputs, source)
}

fn bind_compose_constants(
    device: &Device9Ref<'_>,
    desc: &D3DSURFACE_DESC,
    frame_inputs: &FrameInputs,
    bloom_source: Option<&ScreenShaderSource>,
    grade: &ColorGradeSettings,
    bloom_enabled: bool,
    frame_index: u32,
) -> Direct3DResult<()> {
    device.set_pixel_shader_constant_f(
        0,
        &[
            [
                desc.Width as f32,
                desc.Height as f32,
                1.0 / desc.Width as f32,
                1.0 / desc.Height as f32,
            ],
            [
                frame_index as f32,
                3.0,
                4.0,
                frame_inputs.depth.first_person_texture.is_some() as u8 as f32,
            ],
            [
                frame_inputs.camera.near_z,
                frame_inputs.camera.far_z,
                frame_inputs.camera.aspect_ratio,
                frame_inputs.depth.provider_id(),
            ],
        ],
    )?;
    bind_bloom_effect_constants(device, frame_inputs, bloom_source)?;
    device.set_pixel_shader_constant_f(
        COLOR_GRADE_CONSTANT_REGISTER,
        &grade.constants(bloom_enabled),
    )
}

fn bind_bloom_effect_constants(
    device: &Device9Ref<'_>,
    frame_inputs: &FrameInputs,
    source: Option<&ScreenShaderSource>,
) -> Direct3DResult<()> {
    if let Some(source) = source {
        return bind_effect_constants(device, frame_inputs, source);
    }

    // Halation owns a highlight blur even when user-facing Bloom is disabled.
    // These restrained fallback values isolate bright material without adding
    // the atmosphere lift or visible Bloom composition.
    device.set_pixel_shader_constant_f(
        3,
        &[
            [0.0, 0.58, 3.2, 0.25],
            [0.0, 0.0, 0.82, 0.12],
            [0.0, 0.0, 0.0, 0.0],
        ],
    )
}

fn bind_effect_constants(
    device: &Device9Ref<'_>,
    frame_inputs: &FrameInputs,
    source: &ScreenShaderSource,
) -> Direct3DResult<()> {
    if !source.option_constants.is_empty() {
        device.set_pixel_shader_constant_f(3, &source.option_constants)?;
    }
    device.set_pixel_shader_constant_f(
        6,
        &[[
            frame_inputs.environment.fog_start,
            frame_inputs.environment.fog_end,
            frame_inputs.environment.fog_power,
            frame_inputs.environment.fog_available_f32(),
        ]],
    )?;
    device.set_pixel_shader_constant_f(
        8,
        &[[
            frame_inputs.sun.screen_x,
            frame_inputs.sun.screen_y,
            frame_inputs.sun.available_f32(),
            frame_inputs.sun.daylight,
        ]],
    )
}

#[derive(Clone, Copy, Debug)]
struct ColorGradeSettings {
    enabled: bool,
    strength: f32,
    color_grading_enabled: bool,
    exposure: f32,
    contrast: f32,
    saturation: f32,
    vibrance: f32,
    temperature: f32,
    tint: f32,
    black_fade: f32,
    highlight_rolloff: f32,
    lut_enabled: bool,
    lut_strength: f32,
    deband_enabled: bool,
    deband: f32,
    film_grain_enabled: bool,
    film_grain: f32,
    vignette_enabled: bool,
    vignette: f32,
    halation_enabled: bool,
    halation: f32,
    chromatic_aberration_enabled: bool,
    chromatic_aberration: f32,
    debug_split: bool,
    environment_weight: f32,
    lut_size: f32,
    lut_domain_min: [f32; 3],
    lut_domain_max: [f32; 3],
}

impl ColorGradeSettings {
    #[cfg(test)]
    fn from_source(source: Option<&ScreenShaderSource>, frame_inputs: &FrameInputs) -> Self {
        Self::from_source_with_metadata(source, frame_inputs, Some((32.0, [0.0; 3], [1.0; 3])))
    }

    fn from_source_with_lut(
        source: Option<&ScreenShaderSource>,
        frame_inputs: &FrameInputs,
        selected_lut: Option<&LutAsset>,
    ) -> Self {
        Self::from_source_with_metadata(
            source,
            frame_inputs,
            selected_lut.map(|lut| (lut.size as f32, lut.domain_min, lut.domain_max)),
        )
    }

    fn from_source_with_metadata(
        source: Option<&ScreenShaderSource>,
        frame_inputs: &FrameInputs,
        lut_metadata: Option<(f32, [f32; 3], [f32; 3])>,
    ) -> Self {
        let Some(source) = source else {
            return Self::disabled();
        };

        let environment_response =
            source_option_float(source, "environment_response", 0.0).clamp(0.0, 1.0);
        let environment_weight = native_environment_weight(frame_inputs);
        let configured_lut_strength =
            source_option_float(source, "lut_strength", 0.0).clamp(0.0, 1.0);
        let lut_enabled = source_option_bool(source, "lut_enabled", false)
            && lut_metadata.is_some()
            && configured_lut_strength > 1.0e-5;
        let lut_strength = if lut_enabled {
            configured_lut_strength * (1.0 + (environment_weight - 1.0) * environment_response)
        } else {
            0.0
        };
        let (lut_size, lut_domain_min, lut_domain_max) =
            lut_metadata.unwrap_or((2.0, [0.0; 3], [1.0; 3]));

        Self {
            enabled: source.enabled,
            strength: source_option_float(source, "strength", 0.0).clamp(0.0, 1.0),
            color_grading_enabled: source_option_bool(source, "color_grading_enabled", false),
            exposure: source_option_float(source, "exposure", 0.0).clamp(-1.5, 1.5),
            contrast: source_option_float(source, "contrast", 0.0).clamp(-0.5, 0.5),
            saturation: source_option_float(source, "saturation", 1.0).clamp(0.0, 2.0),
            vibrance: source_option_float(source, "vibrance", 0.0).clamp(-1.0, 1.0),
            temperature: source_option_float(source, "temperature", 0.0).clamp(-1.0, 1.0),
            tint: source_option_float(source, "tint", 0.0).clamp(-1.0, 1.0),
            black_fade: source_option_float(source, "black_fade", 0.0).clamp(0.0, 1.0),
            highlight_rolloff: source_option_float(source, "highlight_rolloff", 0.0)
                .clamp(0.0, 1.0),
            lut_enabled,
            lut_strength,
            deband_enabled: source_option_bool(source, "deband_enabled", false),
            deband: source_option_float(source, "deband", 0.0).clamp(0.0, 1.0),
            film_grain_enabled: source_option_bool(source, "film_grain_enabled", false),
            film_grain: source_option_float(source, "film_grain", 0.0).clamp(0.0, 1.0),
            vignette_enabled: source_option_bool(source, "vignette_enabled", false),
            vignette: source_option_float(source, "vignette", 0.0).clamp(0.0, 1.0),
            halation_enabled: source_option_bool(source, "halation_enabled", false),
            halation: source_option_float(source, "halation", 0.0).clamp(0.0, 1.0),
            chromatic_aberration_enabled: source_option_bool(
                source,
                "chromatic_aberration_enabled",
                false,
            ),
            chromatic_aberration: source_option_float(source, "chromatic_aberration", 0.0)
                .clamp(0.0, 4.0),
            debug_split: source_option_bool(source, "debug_split", false),
            environment_weight,
            lut_size,
            lut_domain_min,
            lut_domain_max,
        }
    }

    const fn disabled() -> Self {
        Self {
            enabled: false,
            strength: 0.0,
            color_grading_enabled: false,
            exposure: 0.0,
            contrast: 0.0,
            saturation: 1.0,
            vibrance: 0.0,
            temperature: 0.0,
            tint: 0.0,
            black_fade: 0.0,
            highlight_rolloff: 0.0,
            lut_enabled: false,
            lut_strength: 0.0,
            deband_enabled: false,
            deband: 0.0,
            film_grain_enabled: false,
            film_grain: 0.0,
            vignette_enabled: false,
            vignette: 0.0,
            halation_enabled: false,
            halation: 0.0,
            chromatic_aberration_enabled: false,
            chromatic_aberration: 0.0,
            debug_split: false,
            environment_weight: 1.0,
            lut_size: 2.0,
            lut_domain_min: [0.0; 3],
            lut_domain_max: [1.0; 3],
        }
    }

    fn is_active(self) -> bool {
        self.enabled
            && self.strength > 1.0e-5
            && (self.color_grading_enabled
                || self.lut_enabled
                || (self.deband_enabled && self.deband > 1.0e-5)
                || (self.film_grain_enabled && self.film_grain > 1.0e-5)
                || (self.vignette_enabled && self.vignette > 1.0e-5)
                || (self.halation_enabled && self.halation > 1.0e-5))
    }

    fn constants(self, bloom_enabled: bool) -> [[f32; 4]; 9] {
        [
            [self.strength, self.exposure, self.contrast, self.saturation],
            [self.vibrance, self.temperature, self.tint, self.black_fade],
            [
                self.highlight_rolloff,
                self.lut_strength,
                self.deband,
                self.film_grain,
            ],
            [
                self.vignette,
                self.halation,
                self.debug_split as u8 as f32,
                self.chromatic_aberration,
            ],
            [
                self.is_active() as u8 as f32,
                bloom_enabled as u8 as f32,
                self.environment_weight,
                0.0,
            ],
            [
                self.color_grading_enabled as u8 as f32,
                self.lut_enabled as u8 as f32,
                self.deband_enabled as u8 as f32,
                self.film_grain_enabled as u8 as f32,
            ],
            [
                self.vignette_enabled as u8 as f32,
                self.halation_enabled as u8 as f32,
                self.chromatic_aberration_enabled as u8 as f32,
                0.0,
            ],
            [
                1.0 / (self.lut_domain_max[0] - self.lut_domain_min[0]),
                1.0 / (self.lut_domain_max[1] - self.lut_domain_min[1]),
                1.0 / (self.lut_domain_max[2] - self.lut_domain_min[2]),
                self.lut_size,
            ],
            [
                -self.lut_domain_min[0] / (self.lut_domain_max[0] - self.lut_domain_min[0]),
                -self.lut_domain_min[1] / (self.lut_domain_max[1] - self.lut_domain_min[1]),
                -self.lut_domain_min[2] / (self.lut_domain_max[2] - self.lut_domain_min[2]),
                0.0,
            ],
        ]
    }
}

fn source_option_float(source: &ScreenShaderSource, key: &str, fallback: f32) -> f32 {
    source
        .options
        .iter()
        .find(|option| option.key == key)
        .and_then(|option| match option.value {
            ShaderOptionValue::Float(value) if value.is_finite() => Some(value),
            _ => None,
        })
        .unwrap_or(fallback)
}

fn source_option_bool(source: &ScreenShaderSource, key: &str, fallback: bool) -> bool {
    source
        .options
        .iter()
        .find(|option| option.key == key)
        .and_then(|option| match option.value {
            ShaderOptionValue::Bool(value) => Some(value),
            _ => None,
        })
        .unwrap_or(fallback)
}

fn native_environment_weight(frame_inputs: &FrameInputs) -> f32 {
    if !frame_inputs.material_state.exterior_known {
        return 1.0;
    }
    if !frame_inputs.material_state.is_exterior {
        return 0.70;
    }

    let daylight = frame_inputs
        .sky
        .map(|sky| sky.daylight)
        .filter(|daylight| daylight.is_finite())
        .unwrap_or(frame_inputs.sun.daylight)
        .clamp(0.0, 1.0);
    0.78 + 0.22 * daylight
}

fn draw_quad(device: &Device9Ref<'_>, width: u32, height: u32) -> Direct3DResult<()> {
    let quad = fullscreen_quad(width, height);
    unsafe { device.draw_primitive_up(D3DPT_TRIANGLESTRIP, 2, &quad) }
}

fn fullscreen_quad(width: u32, height: u32) -> [ScreenVertex; 4] {
    let width = width as f32;
    let height = height as f32;
    [
        ScreenVertex::new(-0.5, -0.5, 0.0, 0.0),
        ScreenVertex::new(width - 0.5, -0.5, 1.0, 0.0),
        ScreenVertex::new(-0.5, height - 0.5, 0.0, 1.0),
        ScreenVertex::new(width - 0.5, height - 0.5, 1.0, 1.0),
    ]
}

fn identity_lut_pixels(size: u32) -> Vec<u32> {
    let mut pixels = Vec::with_capacity((size * size * size) as usize);
    let denominator = (size - 1) as f32;
    for green in 0..size {
        for blue in 0..size {
            for red in 0..size {
                pixels.push(pack_argb([
                    red as f32 / denominator,
                    green as f32 / denominator,
                    blue as f32 / denominator,
                ]));
            }
        }
    }
    pixels
}

fn create_argb_texture(
    device: &Device9Ref<'_>,
    width: u32,
    height: u32,
    pixels: &[u32],
) -> Direct3DResult<Texture9> {
    let texture = device.create_texture(width, height, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)?;
    texture.write_level0_argb(width, height, pixels)?;
    Ok(texture)
}

#[cfg(test)]
#[cfg(test)]
#[derive(Clone, Copy)]
struct LutRecipe {
    contrast: f32,
    saturation: f32,
    gamma: f32,
    black_fade: f32,
    balance: [f32; 3],
    shadow_tint: [f32; 3],
    highlight_tint: [f32; 3],
}

#[cfg(test)]
#[cfg(test)]
fn lut_recipe(preset: usize) -> Option<LutRecipe> {
    match preset {
        1 => Some(LutRecipe {
            contrast: 0.055,
            saturation: 1.025,
            gamma: 0.985,
            black_fade: 0.006,
            balance: [0.010, 0.003, -0.009],
            shadow_tint: [-0.006, 0.001, 0.010],
            highlight_tint: [0.012, 0.004, -0.010],
        }),
        2 => Some(LutRecipe {
            contrast: 0.11,
            saturation: 0.84,
            gamma: 0.965,
            black_fade: 0.014,
            balance: [0.030, 0.012, -0.026],
            shadow_tint: [0.008, 0.004, -0.008],
            highlight_tint: [0.024, 0.010, -0.020],
        }),
        3 => Some(LutRecipe {
            contrast: 0.15,
            saturation: 0.64,
            gamma: 1.025,
            black_fade: 0.035,
            balance: [0.008, 0.008, 0.003],
            shadow_tint: [-0.002, 0.006, 0.012],
            highlight_tint: [0.014, 0.012, 0.002],
        }),
        4 => Some(LutRecipe {
            contrast: 0.10,
            saturation: 1.20,
            gamma: 1.01,
            black_fade: 0.016,
            balance: [-0.006, -0.004, 0.016],
            shadow_tint: [-0.020, 0.004, 0.036],
            highlight_tint: [0.028, -0.004, 0.020],
        }),
        _ => None,
    }
}

#[cfg(test)]
#[cfg(test)]
fn generate_builtin_lut(preset: usize) -> Vec<u32> {
    let texel_count = (LUT_SIZE * LUT_SIZE * LUT_SIZE) as usize;
    let mut pixels = Vec::with_capacity(texel_count);
    let denominator = (LUT_SIZE - 1) as f32;
    for green in 0..LUT_SIZE {
        for blue in 0..LUT_SIZE {
            for red in 0..LUT_SIZE {
                let input = [
                    red as f32 / denominator,
                    green as f32 / denominator,
                    blue as f32 / denominator,
                ];
                pixels.push(pack_argb(apply_lut_recipe(preset, input)));
            }
        }
    }
    pixels
}

#[cfg(test)]
#[cfg(test)]
#[cfg(test)]
fn apply_lut_recipe(preset: usize, input: [f32; 3]) -> [f32; 3] {
    let Some(recipe) = lut_recipe(preset) else {
        return input.map(|value| value.clamp(0.0, 1.0));
    };

    let mut color = input.map(|value| {
        (0.5 + (value - 0.5) * (1.0 + recipe.contrast))
            .clamp(0.0, 1.0)
            .powf(recipe.gamma)
    });
    let luma = color[0] * 0.2126 + color[1] * 0.7152 + color[2] * 0.0722;
    for channel in &mut color {
        *channel = luma + (*channel - luma) * recipe.saturation;
    }

    let shadow = 1.0 - smooth_step(0.10, 0.62, luma);
    let highlight = smooth_step(0.42, 0.92, luma);
    for channel in 0..3 {
        color[channel] += recipe.balance[channel]
            + recipe.shadow_tint[channel] * shadow
            + recipe.highlight_tint[channel] * highlight;
        color[channel] = recipe.black_fade + color[channel] * (1.0 - recipe.black_fade);
        color[channel] = color[channel].clamp(0.0, 1.0);
    }
    color
}

#[cfg(test)]
#[cfg(test)]
fn smooth_step(edge0: f32, edge1: f32, value: f32) -> f32 {
    let value = ((value - edge0) / (edge1 - edge0)).clamp(0.0, 1.0);
    value * value * (3.0 - 2.0 * value)
}

fn pack_argb(color: [f32; 3]) -> u32 {
    let channel = |value: f32| (value.clamp(0.0, 1.0) * 255.0).round() as u32;
    0xFF00_0000 | (channel(color[0]) << 16) | (channel(color[1]) << 8) | channel(color[2])
}

struct BloomTargets {
    width: u32,
    height: u32,
    inv_width: f32,
    inv_height: f32,
    format: D3DFORMAT,
    extract: EffectTarget,
    blur: EffectTarget,
}

impl BloomTargets {
    fn create(
        device: &Device9Ref<'_>,
        width: u32,
        height: u32,
        format: D3DFORMAT,
    ) -> Direct3DResult<Self> {
        Ok(Self {
            width,
            height,
            inv_width: 1.0 / width as f32,
            inv_height: 1.0 / height as f32,
            format,
            extract: EffectTarget::create(device, width, height, format)?,
            blur: EffectTarget::create(device, width, height, format)?,
        })
    }

    fn matches(&self, width: u32, height: u32, format: D3DFORMAT) -> bool {
        self.width == width && self.height == height && self.format == format
    }
}

struct EffectTarget {
    texture: Texture9,
    surface: Surface9,
}

impl EffectTarget {
    fn create(
        device: &Device9Ref<'_>,
        width: u32,
        height: u32,
        format: D3DFORMAT,
    ) -> Direct3DResult<Self> {
        let texture = device.create_render_target_texture(width, height, format)?;
        let surface = texture.surface_level(0)?;
        Ok(Self { texture, surface })
    }
}
