//! Engine-side Bloom, display adaptation, and final-color pipeline.
//!
//! Final-color HLSL preparation is process-owned and asynchronous. Device
//! creation consumes an immutable shared bytecode catalog, so neither startup
//! configuration nor render callbacks invoke the compiler. Automatic exposure
//! is deliberately display-referred: Fallout's native image-space work owns
//! HDR mapping before this phase, and OMV shapes only the remaining display
//! range. At no more than 60 Hz, one fixed-grid draw writes a 128-entry
//! ping-pong FP16 response curve and replicated temporal state; the fused
//! compose reduces automatic adaptation to one filtered lookup and one
//! multiply. Fixed neutral mode uses a scalar luminance curve in the compose
//! pass and avoids temporal resources. There is no CPU readback or extra
//! full-resolution pass.

use std::{
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use libpsycho::os::windows::directx9::{
    D3DCULL_NONE, D3DFMT_A8R8G8B8, D3DFMT_A16B16G16R16F, D3DFORMAT, D3DPOOL_MANAGED,
    D3DPT_TRIANGLESTRIP, D3DRS_ADAPTIVETESS_Y, D3DRS_ALPHABLENDENABLE, D3DRS_ALPHATESTENABLE,
    D3DRS_COLORWRITEENABLE, D3DRS_CULLMODE, D3DRS_MULTISAMPLEANTIALIAS, D3DRS_MULTISAMPLEMASK,
    D3DRS_POINTSIZE, D3DRS_SCISSORTESTENABLE, D3DRS_SRGBWRITEENABLE, D3DRS_STENCILENABLE,
    D3DRS_ZENABLE, D3DRS_ZWRITEENABLE, D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV, D3DSAMP_MAGFILTER,
    D3DSAMP_MINFILTER, D3DSAMP_MIPFILTER, D3DSAMP_SRGBTEXTURE, D3DSURFACE_DESC, D3DTA_TEXTURE,
    D3DTADDRESS_CLAMP, D3DTADDRESS_WRAP, D3DTEXF_LINEAR, D3DTEXF_NONE, D3DTEXF_POINT,
    D3DTOP_SELECTARG1, D3DTSS_ALPHAARG1, D3DTSS_ALPHAOP, D3DTSS_COLORARG1, D3DTSS_COLOROP,
    D3DVIEWPORT9, Device9Ref, Direct3DResult, PixelShader9, ScreenVertex, Surface9, Texture9,
};

use crate::{
    backend::{DepthTexture, FrameInputs},
    config::{AdaptiveToneConfig, ToneMapperMode},
    luts::LutAsset,
    render_state::RenderTargetSlots,
    shaders::{self, ScreenShaderSource, ShaderOptionValue},
};
use parking_lot::Mutex;

const COLOR_WRITE_ALL: u32 = 0x0F;
const EFFECT_CONSTANT_REGISTER: u32 = 9;
const BLOOM_SCALE: u32 = 4;
const COLOR_GRADE_CONSTANT_REGISTER: u32 = 10;
const FILM_GRAIN_TEXTURE_SIZE: u32 = 512;
const FILM_GRAIN_TEXTURE_SEED: u32 = 0xC0FF_EE11;
const ADAPTIVE_RESPONSE_WIDTH: u32 = 128;
const ADAPTIVE_UPDATE_INTERVAL_SECONDS: f32 = 1.0 / 60.0;
#[cfg(test)]
const LUT_SIZE: u32 = 32;
#[cfg(test)]
const LUT_COUNT: usize = 5;
const AMD_ALPHA_TO_COVERAGE_OFF: u32 = 0x4143_5446;

static COMPILE_STARTED: AtomicBool = AtomicBool::new(false);
static COMPILE_FAILED: AtomicBool = AtomicBool::new(false);
static COMPILE_READY: AtomicBool = AtomicBool::new(false);
static BYTECODE: LazyLock<Mutex<Option<Arc<FinalColorShaderBytecode>>>> =
    LazyLock::new(|| Mutex::new(None));

/// Render-local state for distributing response work across high-refresh frames.
///
/// Scheduling phase and elapsed integration time are intentionally separate.
/// Keeping only one accumulator would either discard fractional cadence at
/// refresh rates such as 75 Hz or integrate the same fraction twice.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct AdaptiveUpdateClock {
    phase_seconds: f32,
    elapsed_seconds: f32,
}

fn schedule_adaptive_update(
    mut clock: AdaptiveUpdateClock,
    history_continuous: bool,
    frame_seconds: f32,
) -> (AdaptiveUpdateClock, Option<f32>) {
    let frame_seconds = if frame_seconds.is_finite() {
        frame_seconds.clamp(1.0 / 240.0, 1.0 / 20.0)
    } else {
        1.0 / 60.0
    };
    if !history_continuous {
        return (AdaptiveUpdateClock::default(), Some(frame_seconds));
    }

    clock.elapsed_seconds = (clock.elapsed_seconds + frame_seconds).min(1.0 / 20.0);
    if frame_seconds >= ADAPTIVE_UPDATE_INTERVAL_SECONDS {
        let elapsed_seconds = clock.elapsed_seconds;
        return (AdaptiveUpdateClock::default(), Some(elapsed_seconds));
    }

    // Subtracting, rather than clearing, the cadence phase distributes 60
    // updates evenly at non-multiple refresh rates. `elapsed_seconds` still
    // measures real time since the last draw, so the shader's half-life math
    // never integrates the retained scheduling fraction twice.
    clock.phase_seconds += frame_seconds;
    if clock.phase_seconds + 1.0e-6 < ADAPTIVE_UPDATE_INTERVAL_SECONDS {
        return (clock, None);
    }
    clock.phase_seconds = (clock.phase_seconds - ADAPTIVE_UPDATE_INTERVAL_SECONDS).max(0.0);
    let elapsed_seconds = clock.elapsed_seconds;
    clock.elapsed_seconds = 0.0;
    (clock, Some(elapsed_seconds))
}

const EXTRACT_SHADER: &[u8] = include_bytes!("../../shaders/embedded/bloom_hdr_extract.hlsl");
const BLUR_SHADER: &[u8] = include_bytes!("../../shaders/embedded/bloom_hdr_blur.hlsl");
const COMPOSE_SHADER: &[u8] = include_bytes!("../../shaders/embedded/bloom_hdr_compose.hlsl");
const CHROMATIC_SHADER: &[u8] = include_bytes!("../../shaders/embedded/chromatic_aberration.hlsl");
const ADAPTIVE_TONE_SHADER: &[u8] = include_bytes!("../../shaders/embedded/adaptive_tone.hlsl");

const COMPOSE_VARIANT_STATIC: u8 = 1;
const COMPOSE_VARIANT_ADAPTIVE: u8 = 2;

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
    if !source.enabled {
        return false;
    }
    let creative_master_active = source_option_float(source, "strength", 0.0) > 1.0e-5;
    let creative_work = creative_master_active
        && (source_option_bool(source, "color_grading_enabled", false)
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
                && source_option_float(source, "halation", 0.0) > 1.0e-5));

    // Adaptive display is top-level Current Look state, not a creative-grade
    // sub-control. Sharing the fused source saves a draw, but the unrelated
    // creative master must neither attenuate nor disable exposure and tone.
    creative_work || adaptive_tone_source_active(source)
}

fn adaptive_tone_source_active(source: &ScreenShaderSource) -> bool {
    if !source.enabled {
        return false;
    }
    let mode = crate::config::ToneMapperMode::from_index(source_option_integer(
        source,
        "tone_mapper_mode",
        0,
    ));
    (source_option_bool(source, "auto_exposure_enabled", false)
        && source_option_float(source, "exposure_range_ev", 0.0) > 1.0e-5)
        || (mode != crate::config::ToneMapperMode::Off
            && source_option_float(source, "tone_mapper_strength", 0.0) > 1.0e-5)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FinalColorWorkPlan {
    bloom: bool,
    bloom_intermediate: bool,
    color_grade: bool,
    chromatic_aberration: bool,
    adaptive_history: bool,
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
            adaptive_history: color_grade_source.is_some_and(|source| {
                AdaptiveToneSettings::from_source(Some(source)).requires_history()
            }),
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
        base + self.chromatic_aberration as u32 + self.adaptive_history as u32
    }

    #[cfg(test)]
    const fn quarter_resolution_draw_count(self) -> u32 {
        if self.bloom_intermediate { 3 } else { 0 }
    }

    #[cfg(test)]
    const fn internal_full_resolution_copy_count(self) -> u32 {
        // The phase owner performs the sole initial scene copy. Composition
        // and chromatic aberration communicate through a renderable texture.
        0
    }
}

fn bloom_target_dimensions(width: u32, height: u32) -> (u32, u32) {
    ((width / BLOOM_SCALE).max(1), (height / BLOOM_SCALE).max(1))
}

pub(crate) struct FinalColorShaderBytecode {
    extract: Vec<u32>,
    blur: Vec<u32>,
    compose_legacy: Vec<u32>,
    compose_static: Vec<u32>,
    compose_adaptive: Vec<u32>,
    adaptive_tone: Vec<u32>,
    chromatic: Vec<u32>,
}

impl FinalColorShaderBytecode {
    pub(crate) fn prepare() -> anyhow::Result<Self> {
        Ok(Self {
            extract: prepare_shader("bloom_hdr_extract.hlsl", EXTRACT_SHADER)?,
            blur: prepare_shader("bloom_hdr_blur.hlsl", BLUR_SHADER)?,
            compose_legacy: prepare_shader("bloom_hdr_compose.hlsl", COMPOSE_SHADER)?,
            compose_static: prepare_shader(
                "bloom_hdr_compose_static.hlsl",
                &compose_variant_source(COMPOSE_VARIANT_STATIC),
            )?,
            compose_adaptive: prepare_shader(
                "bloom_hdr_compose_adaptive.hlsl",
                &compose_variant_source(COMPOSE_VARIANT_ADAPTIVE),
            )?,
            adaptive_tone: prepare_shader("adaptive_tone.hlsl", ADAPTIVE_TONE_SHADER)?,
            chromatic: prepare_shader("chromatic_aberration.hlsl", CHROMATIC_SHADER)?,
        })
    }
}

fn compose_variant_source(variant: u8) -> Vec<u8> {
    let mut source = format!("#define OMV_TONE_VARIANT {variant}\n").into_bytes();
    source.extend_from_slice(COMPOSE_SHADER);
    source
}

/// Start process-owned final-color shader preparation.
pub(crate) fn service_preparation() {
    if COMPILE_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    if let Err(err) = thread::Builder::new()
        .name("omv-final-color-compile".to_owned())
        .spawn(|| {
            match super::shader_preparation::run_serialized(FinalColorShaderBytecode::prepare) {
                Ok(bytecode) => {
                    *BYTECODE.lock() = Some(Arc::new(bytecode));
                    COMPILE_READY.store(true, Ordering::Release);
                }
                Err(err) => {
                    COMPILE_FAILED.store(true, Ordering::Release);
                    log::warn!("[FINAL_COLOR] Shader preparation failed: {err:#}");
                }
            }
        })
    {
        COMPILE_FAILED.store(true, Ordering::Release);
        log::warn!("[FINAL_COLOR] Could not start shader preparation: {err}");
    }
}

/// Return whether final-color bytecode is ready for a nonblocking catalog poll.
pub(crate) fn preparation_ready() -> bool {
    COMPILE_READY.load(Ordering::Acquire) && !COMPILE_FAILED.load(Ordering::Acquire)
}

/// Clone the prepared process-owned final-color bytecode catalog without
/// blocking a render callback.
pub(crate) fn prepared_bytecode() -> Option<Arc<FinalColorShaderBytecode>> {
    if !COMPILE_READY.load(Ordering::Acquire) || COMPILE_FAILED.load(Ordering::Acquire) {
        return None;
    }
    BYTECODE.try_lock()?.as_ref().cloned()
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
        ADAPTIVE_RESPONSE_WIDTH, ADAPTIVE_TONE_SHADER, AdaptiveToneSettings, AdaptiveUpdateClock,
        BLUR_SHADER, CHROMATIC_SHADER, COMPOSE_SHADER, COMPOSE_VARIANT_ADAPTIVE,
        COMPOSE_VARIANT_STATIC, ColorGradeSettings, ComposeVariant, EXTRACT_SHADER,
        FILM_GRAIN_TEXTURE_SIZE, FinalColorShaderBytecode, FinalColorWorkPlan, LUT_COUNT, LUT_SIZE,
        apply_lut_recipe, bloom_target_dimensions, color_grade_source_active,
        compose_variant_source, film_grain_pixels, fullscreen_quad, generate_builtin_lut,
        identity_lut_pixels, native_environment_weight, schedule_adaptive_update,
    };
    use crate::{
        backend::{FrameInputs, MaterialStateFrame, NativeSkyFrame},
        config::{AdaptiveToneConfig, EmbeddedEffectsConfig, ToneMapperMode},
        shaders::{self, EmbeddedEffectKind},
    };

    const FILM_GRAIN_DEFAULT_SIZE: f32 = 1.743_985;
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
            film_grain_size: 1.0,
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

    fn sample_reference_grain(pixels: &[u32], uv: [f32; 2]) -> f32 {
        let size = FILM_GRAIN_TEXTURE_SIZE as isize;
        let position = [
            uv[0] * FILM_GRAIN_TEXTURE_SIZE as f32 - 0.5,
            uv[1] * FILM_GRAIN_TEXTURE_SIZE as f32 - 0.5,
        ];
        let low = [position[0].floor() as isize, position[1].floor() as isize];
        let fraction = [position[0] - low[0] as f32, position[1] - low[1] as f32];
        let texel = |x: isize, y: isize| {
            let index = y.rem_euclid(size) as usize * FILM_GRAIN_TEXTURE_SIZE as usize
                + x.rem_euclid(size) as usize;
            (((pixels[index] >> 16) & 0xFF) as f32 / 255.0) * 2.0 - 1.0
        };
        let top = texel(low[0], low[1])
            + (texel(low[0] + 1, low[1]) - texel(low[0], low[1])) * fraction[0];
        let bottom = texel(low[0], low[1] + 1)
            + (texel(low[0] + 1, low[1] + 1) - texel(low[0], low[1] + 1)) * fraction[0];
        top + (bottom - top) * fraction[1]
    }

    fn film_grain_noise(pixels: &[u32], pixel: [f32; 2], frame: f32, grain_size: f32) -> f32 {
        let grain_size = grain_size.clamp(0.3, 3.0);
        let offset = [(frame * 0.754_877_7).fract(), (frame * 0.569_840_3).fract()];
        sample_reference_grain(
            pixels,
            [
                pixel[0] / (grain_size * FILM_GRAIN_TEXTURE_SIZE as f32) + offset[0],
                pixel[1] / (grain_size * FILM_GRAIN_TEXTURE_SIZE as f32) + offset[1],
            ],
        )
    }

    fn unorm8_code(value: f32) -> u8 {
        (value.clamp(0.0, 1.0) * 255.0).round() as u8
    }

    fn film_grain_reference(
        input: [f32; 3],
        grain_pixels: &[u32],
        pixel: [f32; 2],
        frame: f32,
        amount: f32,
        master: f32,
        grain_size: f32,
    ) -> [f32; 3] {
        let response = 1.0 - luma(input).clamp(0.0, 1.0).sqrt();
        let grain = film_grain_noise(grain_pixels, pixel, frame, grain_size)
            * amount.clamp(0.0, 2.0)
            * master.clamp(0.0, 1.0)
            * response;
        input.map(|channel| (channel + channel * grain).clamp(0.0, 1.0))
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

    fn smooth01_reference(value: f32) -> f32 {
        let value = value.clamp(0.0, 1.0);
        value * value * (3.0 - 2.0 * value)
    }

    fn adapt_value_reference(
        current: f32,
        target: f32,
        frame_seconds: f32,
        speed_scale: f32,
        half_life_seconds: f32,
    ) -> f32 {
        let frame_seconds = frame_seconds.clamp(1.0 / 240.0, 1.0 / 20.0);
        let alpha =
            1.0 - (-frame_seconds * speed_scale.clamp(0.10, 4.0) / half_life_seconds).exp2();
        current + (target - current) * alpha.clamp(0.0, 1.0)
    }

    fn transient_exposure_step_reference(
        adapted_log: f32,
        exposure_ev: f32,
        measured_log: f32,
        frame_seconds: f32,
        speed_scale: f32,
        exposure_range_ev: f32,
    ) -> (f32, f32) {
        let adaptation_half_life = if measured_log > adapted_log {
            0.52
        } else {
            1.05
        };
        let adapted_log = adapt_value_reference(
            adapted_log,
            measured_log,
            frame_seconds,
            speed_scale,
            adaptation_half_life,
        );
        let delta = measured_log - adapted_log;
        let deadband = smooth01_reference((delta.abs() - 0.035) / 0.12);
        let target = (delta * deadband).clamp(-exposure_range_ev, exposure_range_ev);
        let exposure_ev =
            adapt_value_reference(exposure_ev, target, frame_seconds, speed_scale, 0.14);
        (adapted_log, exposure_ev)
    }

    fn adapt_tone_reference(
        current: f32,
        target: f32,
        frame_seconds: f32,
        speed_scale: f32,
    ) -> f32 {
        let half_life = if target > current { 0.22 } else { 0.72 };
        adapt_value_reference(current, target, frame_seconds, speed_scale, half_life)
    }

    fn automatic_response_scale_reference(
        display_luma: f32,
        exposure_ev: f32,
        tone_strength: f32,
        tone_activity: f32,
    ) -> f32 {
        let exposure_scale = exposure_ev.exp2();
        let exposed_luma = display_luma.max(0.0) * exposure_scale;
        let linear_luma = exposed_luma.powf(2.2);
        let reinhard_ratio = (1.0 + linear_luma / 6.25) / (1.0 + linear_luma);
        let activity_scale = 0.70 + 0.60 * tone_activity.clamp(0.0, 1.0);
        let effective_strength = tone_strength * activity_scale;
        exposure_scale * reinhard_ratio.max(0.000_01).powf(effective_strength / 2.2)
    }

    fn invisible_automatic_response_scale_negative_control(
        peak: f32,
        master: f32,
        tone_strength: f32,
        tone_activity: f32,
    ) -> f32 {
        // This deliberately retains the reported implementation's two
        // attenuation stages. It is a negative control, not an alternative
        // production curve: low activity first moves the shoulder by very
        // little and then blends that small correction back toward identity.
        let tone_level = (tone_strength * master * tone_activity).clamp(0.0, 1.0);
        let shoulder_start = 1.0 - 0.24 * tone_level;
        let remaining = (1.0 - shoulder_start).max(1.0 / 1024.0);
        let over = (peak - shoulder_start).max(0.0);
        let compressed_peak = peak - over + over * remaining / (remaining + over);
        let compression_scale = if over > 0.0 {
            compressed_peak / peak.max(0.000_01)
        } else {
            1.0
        };
        let tone_gate = smooth01_reference(tone_level * 4.0);
        1.0 + (compression_scale - 1.0) * tone_gate
    }

    fn spatial_weight_reference(x: usize, y: usize) -> f32 {
        let uv = [(x as f32 + 0.5) * 0.25, (y as f32 + 0.5) * 0.25];
        let centered = [uv[0] * 2.0 - 1.0, uv[1] * 2.0 - 1.0];
        let radius = (centered[0] * centered[0] + centered[1] * centered[1]) * 0.5;
        1.0 + (0.40 - 1.0) * radius.clamp(0.0, 1.0)
    }

    fn winsorized_meter_reference(
        samples: [f32; 16],
        previous_log_luminance: Option<f32>,
    ) -> Option<f32> {
        let meter_weight = |luminance: f32, x: usize, y: usize| {
            let black = smooth01_reference((luminance - 1.0 / 255.0) / (4.0 / 255.0 - 1.0 / 255.0));
            black * spatial_weight_reference(x, y)
        };
        let log_luma = |value: f32| value.max(1.0 / 1024.0).log2().clamp(-10.0, 0.0);

        let mut sum = 0.0;
        let mut total_weight = 0.0;
        for (index, sample) in samples.into_iter().enumerate() {
            let luminance = sample.clamp(0.0, 1.0);
            let weight = meter_weight(luminance, index % 4, index / 4);
            let mut log = log_luma(luminance);
            if let Some(previous) = previous_log_luminance {
                log = log.clamp(previous - 2.5, previous + 2.5);
            }
            sum += log * weight;
            total_weight += weight;
        }
        (total_weight > 0.0001).then_some(sum / total_weight)
    }

    fn highlight_tail_reference(samples: [f32; 16]) -> f32 {
        let mut sum = 0.0;
        let mut total_weight = 0.0;
        let mut maximum = 0.0_f32;
        for (index, peak) in samples.into_iter().enumerate() {
            let weight = spatial_weight_reference(index % 4, index / 4);
            let soft_highlight = smooth01_reference((peak - 0.72) / 0.26);
            let clip_risk = smooth01_reference((peak - 0.94) / 0.16);
            sum += soft_highlight * weight;
            total_weight += weight;
            maximum = maximum.max(clip_risk * (weight * 1.5).clamp(0.0, 1.0));
        }
        (sum / total_weight * 0.55 + maximum * 0.65).clamp(0.0, 1.0)
    }

    fn neutral_tone_reference(input: [f32; 3], strength: f32) -> [f32; 3] {
        let display_luma = luma(input).max(0.0);
        let linear_luma = display_luma.powf(2.2);
        let reinhard_ratio = (1.0 + linear_luma / 6.25) / (1.0 + linear_luma);
        let response_scale = reinhard_ratio.max(0.000_01).powf(strength / 2.2);
        input.map(|channel| channel * response_scale)
    }

    #[test]
    fn embedded_bloom_shaders_compile() {
        crate::shaders::assert_hlsl_compiles("bloom_hdr_extract.hlsl", EXTRACT_SHADER, "ps_3_0");
        crate::shaders::assert_hlsl_compiles("bloom_hdr_blur.hlsl", BLUR_SHADER, "ps_3_0");
        crate::shaders::assert_hlsl_compiles("bloom_hdr_compose.hlsl", COMPOSE_SHADER, "ps_3_0");
        crate::shaders::assert_hlsl_compiles(
            "bloom_hdr_compose_static.hlsl",
            &compose_variant_source(COMPOSE_VARIANT_STATIC),
            "ps_3_0",
        );
        crate::shaders::assert_hlsl_compiles(
            "bloom_hdr_compose_adaptive.hlsl",
            &compose_variant_source(COMPOSE_VARIANT_ADAPTIVE),
            "ps_3_0",
        );
        crate::shaders::assert_hlsl_compiles("adaptive_tone.hlsl", ADAPTIVE_TONE_SHADER, "ps_3_0");
    }

    #[test]
    fn every_final_color_pass_stays_within_fixed_gpu_budgets() {
        let static_compose = compose_variant_source(COMPOSE_VARIANT_STATIC);
        let adaptive_compose = compose_variant_source(COMPOSE_VARIANT_ADAPTIVE);
        for (name, source, max_instructions, max_samples) in [
            ("bloom_hdr_extract_budget.hlsl", EXTRACT_SHADER, 220, 10),
            ("bloom_hdr_blur_budget.hlsl", BLUR_SHADER, 80, 9),
            ("bloom_hdr_compose_budget.hlsl", COMPOSE_SHADER, 500, 14),
            (
                "bloom_hdr_compose_static_budget.hlsl",
                static_compose.as_slice(),
                530,
                14,
            ),
            (
                "bloom_hdr_compose_adaptive_budget.hlsl",
                adaptive_compose.as_slice(),
                515,
                15,
            ),
            ("adaptive_tone_budget.hlsl", ADAPTIVE_TONE_SHADER, 420, 4),
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

        let meter = std::str::from_utf8(ADAPTIVE_TONE_SHADER).expect("meter UTF-8");
        assert!(meter.contains("for (int y = 0; y < 4; ++y)"));
        assert!(meter.contains("for (int x = 0; x < 4; ++x)"));
        assert!(!meter.contains("robustY"));
        assert_eq!(meter.matches("tex2Dlod(SceneColor").count(), 1);
        assert_eq!(meter.matches("tex2Dlod(BloomTexture").count(), 1);
        assert_eq!(
            ADAPTIVE_RESPONSE_WIDTH * (4 * 4 + 4 * 4 + 1),
            4_224,
            "response generation has a small, resolution-independent fetch budget"
        );
        let implementation = include_str!("blooming_hdr.rs");
        for sampler in [0, 1] {
            let call = format!("configure_adaptive_sampler(device, {sampler}");
            assert_eq!(
                implementation
                    .lines()
                    .filter(|line| line.trim_start().starts_with(call.as_str()))
                    .count(),
                0,
                "transaction-wide sampler state must not be rebound for s{sampler}"
            );
        }

        let (legacy_instructions, _) = shader_budget("legacy_delta.hlsl", COMPOSE_SHADER);
        let (adaptive_instructions, _) = shader_budget(
            "adaptive_delta.hlsl",
            &compose_variant_source(COMPOSE_VARIANT_ADAPTIVE),
        );
        assert!(
            adaptive_instructions <= legacy_instructions + 16,
            "adaptive compose adds {} instructions to the full-resolution legacy path",
            adaptive_instructions.saturating_sub(legacy_instructions)
        );
    }

    #[test]
    fn adaptive_work_is_one_response_draw_and_legacy_disable_is_exact() {
        let mut embedded = EmbeddedEffectsConfig::default();
        embedded.blooming_hdr.enabled = false;
        embedded.color_grade.color_grading_enabled = false;
        embedded.color_grade.lut_enabled = false;
        embedded.color_grade.deband_enabled = false;
        embedded.color_grade.film_grain_enabled = false;
        embedded.color_grade.vignette_enabled = false;
        embedded.color_grade.halation_enabled = false;
        embedded.color_grade.chromatic_aberration_enabled = false;

        let automatic = AdaptiveToneConfig::default();
        let sources = shaders::merge_embedded_sources_with_luts_and_adaptive(
            &embedded,
            &automatic,
            &[],
            &[],
            Vec::new(),
        );
        let source = sources
            .iter()
            .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade))
            .expect("final-color source");
        let plan = FinalColorWorkPlan::from_sources(None, Some(source));
        assert_eq!(plan.effect_draw_count(), 2);
        assert_eq!(plan.quarter_resolution_draw_count(), 0);
        let automatic_settings = AdaptiveToneSettings::from_source(Some(source));
        assert_eq!(
            automatic_settings.compose_variant(),
            ComposeVariant::Adaptive
        );
        assert!(automatic_settings.without_history().is_active());

        let mut auto_only = automatic;
        auto_only.tone_mapper_mode = ToneMapperMode::Off;
        let sources = shaders::merge_embedded_sources_with_luts_and_adaptive(
            &embedded,
            &auto_only,
            &[],
            &[],
            Vec::new(),
        );
        let source = sources
            .iter()
            .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade))
            .expect("final-color source");
        let settings = AdaptiveToneSettings::from_source(Some(source));
        assert!(settings.requires_history());
        assert!(!settings.without_history().is_active());

        let mut neutral = automatic;
        neutral.auto_exposure_enabled = false;
        neutral.tone_mapper_mode = ToneMapperMode::Neutral;
        let sources = shaders::merge_embedded_sources_with_luts_and_adaptive(
            &embedded,
            &neutral,
            &[],
            &[],
            Vec::new(),
        );
        let source = sources
            .iter()
            .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade))
            .expect("final-color source");
        let plan = FinalColorWorkPlan::from_sources(None, Some(source));
        assert_eq!(plan.effect_draw_count(), 1);
        assert_eq!(
            AdaptiveToneSettings::from_source(Some(source)).compose_variant(),
            ComposeVariant::Static
        );

        let mut zero_range = automatic;
        zero_range.exposure_range_ev = 0.0;
        zero_range.tone_mapper_mode = ToneMapperMode::Off;
        let sources = shaders::merge_embedded_sources_with_luts_and_adaptive(
            &embedded,
            &zero_range,
            &[],
            &[],
            Vec::new(),
        );
        let source = sources
            .iter()
            .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade))
            .expect("final-color source");
        assert!(!FinalColorWorkPlan::from_sources(None, Some(source)).has_work());

        let sources = shaders::merge_embedded_sources(&embedded, Vec::new());
        let source = sources
            .iter()
            .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade))
            .expect("final-color source");
        let settings = AdaptiveToneSettings::from_source(Some(source));
        assert_eq!(settings.compose_variant(), ComposeVariant::Legacy);
        assert!(!FinalColorWorkPlan::from_sources(None, Some(source)).has_work());
    }

    #[test]
    fn transient_exposure_is_smooth_bounded_convergent_and_frame_rate_stable() {
        let integrate = |adapted_start: f32, measured: f32, hz: u32, seconds: u32| {
            let mut adapted = adapted_start;
            let mut exposure = 0.0;
            for _ in 0..hz * seconds {
                (adapted, exposure) = transient_exposure_step_reference(
                    adapted,
                    exposure,
                    measured,
                    1.0 / hz as f32,
                    1.0,
                    0.75,
                );
            }
            (adapted, exposure)
        };
        let bright_30 = integrate(-2.0, -0.30, 30, 1).1;
        let bright_60 = integrate(-2.0, -0.30, 60, 1).1;
        let bright_120 = integrate(-2.0, -0.30, 120, 1).1;
        assert!((bright_30 - bright_60).abs() < 0.008);
        assert!((bright_60 - bright_120).abs() < 0.008);
        assert!(bright_60 > 0.0 && bright_60 <= 0.75);

        let dark_60 = integrate(-0.30, -2.0, 60, 1).1;
        assert!(dark_60 < 0.0 && dark_60 >= -0.75);
        assert!(
            dark_60.abs() > bright_60.abs(),
            "dark adaptation deliberately releases more slowly than bright adaptation"
        );

        let first_bright =
            transient_exposure_step_reference(-2.0, 0.0, -0.30, 1.0 / 60.0, 1.0, 0.75).1;
        assert!(first_bright > 0.0 && first_bright < 0.10);
        assert_eq!(
            transient_exposure_step_reference(-1.0, 0.0, -0.98, 1.0 / 60.0, 1.0, 0.75,).1,
            0.0,
            "sub-deadband camera noise must not pump exposure"
        );

        let settled_bright = integrate(-2.0, -0.30, 60, 10);
        let settled_dark = integrate(-0.30, -2.0, 60, 14);
        assert!((settled_bright.0 + 0.30).abs() < 0.001);
        assert!(settled_bright.1.abs() < 0.001);
        assert!((settled_dark.0 + 2.0).abs() < 0.001);
        assert!(settled_dark.1.abs() < 0.001);
    }

    #[test]
    fn adaptation_uses_transient_contrast_instead_of_inverting_camera_motion() {
        let old_absolute_target = |luminance: f32| {
            (0.36_f32.log2() - luminance.max(1.0 / 1024.0).log2()).clamp(-0.75, 0.75)
        };
        assert!(
            old_absolute_target(0.80) < 0.0 && old_absolute_target(0.30) > 0.0,
            "negative control must reproduce the reported sky-dark/ground-bright response"
        );

        let transient_target = |measured_luminance: f32, adapted_luminance: f32| {
            (measured_luminance.log2() - adapted_luminance.log2()).clamp(-0.75, 0.75)
        };
        assert!(transient_target(0.80, 0.30) > 0.0);
        assert!(transient_target(0.30, 0.80) < 0.0);
        assert_eq!(transient_target(0.55, 0.55), 0.0);

        let meter = std::str::from_utf8(ADAPTIVE_TONE_SHADER).expect("meter UTF-8");
        assert!(meter.contains("meteredMean - adaptedLog"));
        assert!(!meter.contains("DisplayKey"));
        assert!(!meter.contains("weightedHighlights"));
    }

    #[test]
    fn winsorized_meter_rejects_black_and_bounds_extremes_without_stalling() {
        assert_eq!(winsorized_meter_reference([0.0; 16], None), None);
        let uniform_dark = winsorized_meter_reference([0.30; 16], None).expect("dark meter");
        let uniform_bright = winsorized_meter_reference([0.80; 16], None).expect("bright meter");
        assert!((uniform_dark - 0.30_f32.log2()).abs() < 1.0e-6);
        assert!((uniform_bright - 0.80_f32.log2()).abs() < 1.0e-6);

        let anchor = 0.10_f32.log2();
        let mut edge_outlier = [0.10; 16];
        edge_outlier[0] = 1.0;
        let bounded = winsorized_meter_reference(edge_outlier, Some(anchor)).expect("meter");
        let unweighted = (15.0 * anchor + 1.0_f32.log2()) / 16.0;
        assert!((bounded - anchor).abs() < (unweighted - anchor).abs());

        let whole_view = winsorized_meter_reference([0.80; 16], Some(anchor)).expect("meter");
        assert!((whole_view - (anchor + 2.5)).abs() < 1.0e-6);
        assert!(
            whole_view > anchor,
            "a real transition must never be rejected"
        );
    }

    #[test]
    fn automatic_tone_uses_an_independent_native_highlight_tail() {
        assert_eq!(highlight_tail_reference([0.40; 16]), 0.0);
        assert!(highlight_tail_reference([0.80; 16]) > 0.10);
        assert!(highlight_tail_reference([1.0; 16]) > 0.70);

        let mut edge = [0.40; 16];
        edge[0] = 1.0;
        let mut center = [0.40; 16];
        center[5] = 1.0;
        assert!(highlight_tail_reference(center) > highlight_tail_reference(edge));

        let meter = std::str::from_utf8(ADAPTIVE_TONE_SHADER).expect("meter UTF-8");
        assert!(meter.contains("float3 combined = scene"));
        assert!(meter.contains("softHighlight"));
        assert!(meter.contains("clipRisk"));
        assert!(!meter.contains("combinedPeak - 1.0f"));
    }

    #[test]
    fn tone_adaptation_and_response_curves_are_smooth_and_hue_safe() {
        let integrate_tone = |start: f32, target: f32, hz: u32| {
            let mut value = start;
            for _ in 0..hz {
                value = adapt_tone_reference(value, target, 1.0 / hz as f32, 1.0);
            }
            value
        };
        let rise_30 = integrate_tone(0.0, 0.8, 30);
        let rise_60 = integrate_tone(0.0, 0.8, 60);
        let rise_120 = integrate_tone(0.0, 0.8, 120);
        assert!((rise_30 - rise_60).abs() < 0.004);
        assert!((rise_60 - rise_120).abs() < 0.004);
        assert!(rise_60 > 0.76 && rise_60 < 0.8);
        let fall = integrate_tone(0.8, 0.0, 60);
        assert!(fall > 0.29 && fall < 0.33);

        let input = [1.25, 0.62, 0.20];
        assert_eq!(neutral_tone_reference(input, 0.0), input);
        let midtone = [0.50, 0.30, 0.10];
        let mapped_midtone = neutral_tone_reference(midtone, 1.0);
        assert!(mapped_midtone[0] < midtone[0]);
        let ratio_preserving = neutral_tone_reference(input, 1.0);
        assert!((ratio_preserving[1] / ratio_preserving[0] - input[1] / input[0]).abs() < 1.0e-6);
        assert!((ratio_preserving[2] / ratio_preserving[0] - input[2] / input[0]).abs() < 1.0e-6);
        let mapped = neutral_tone_reference(input, 0.65);
        assert!(mapped[0] > mapped[1] && mapped[1] > mapped[2]);
        assert!(
            mapped
                .iter()
                .all(|value| value.is_finite() && *value >= 0.0)
        );
        assert!(mapped[0] < input[0]);

        let expanded_strengths =
            [0.0, 0.65, 1.0, 2.0, 3.0].map(|strength| neutral_tone_reference(midtone, strength)[0]);
        assert!(
            expanded_strengths
                .windows(2)
                .all(|pair| pair[1].is_finite() && pair[1] < pair[0]),
            "the widened tone range must add smooth, monotonic authority"
        );

        let ordinary_response = automatic_response_scale_reference(0.80, 0.0, 0.65, 0.0);
        assert!(ordinary_response < 0.95);
        let response = automatic_response_scale_reference(1.25, 0.0, 0.65, 1.0);
        assert!(response < ordinary_response);
        let automatic = input.map(|channel| channel * response);
        assert!(automatic[0] < 1.0);
        assert!((automatic[1] / automatic[0] - input[1] / input[0]).abs() < 1.0e-6);
        assert!((automatic[2] / automatic[0] - input[2] / input[0]).abs() < 1.0e-6);
    }

    #[test]
    fn automatic_tone_survives_the_final_display_clamp_at_shipped_defaults() {
        // The shipped Bloom equation produces roughly this peak for a uniform
        // white input. Its old over-white-only detector settles near 0.244.
        // Those values reproduce the user's invisible automatic mode without
        // depending on an arbitrary exaggerated HDR fixture.
        let peak = 1.092;
        let master = 0.68;
        let strength = 0.65;
        let activity = 0.244;
        let old_mapped = peak
            * invisible_automatic_response_scale_negative_control(peak, master, strength, activity);
        assert_eq!(
            unorm8_code(old_mapped),
            unorm8_code(peak),
            "negative control must reproduce tone being erased by output saturation"
        );

        let mapped = peak * automatic_response_scale_reference(peak, 0.0, strength, activity);
        assert!(
            unorm8_code(mapped) <= 250,
            "default automatic tone must reserve visible display headroom; mapped={mapped}"
        );

        let compose = std::str::from_utf8(COMPOSE_SHADER).expect("compose UTF-8");
        let main = compose
            .rsplit_once("float4 Main")
            .map(|(_, main)| main)
            .expect("compose entry point");
        let finishing = main.find("ApplyFinishing(").expect("finishing call");
        let tone = main
            .find("ApplyAdaptiveDisplayMapping(")
            .expect("tone call");
        let grain = main.find("FilmGrainNoise(").expect("grain call");
        let clamp = main
            .rfind("saturate(color + noise)")
            .expect("display clamp");
        assert!(finishing < tone && tone < grain && grain < clamp);
    }

    #[test]
    fn automatic_tone_is_visible_at_the_reported_playtest_settings() {
        // The last playtest used automatic tone at 0.995 with the unrelated
        // Color Grade master at 0.68. A broad bright sky commonly remains
        // around 0.80 after Fallout's native HDR blend, so a curve which only
        // changes over-white fixtures is not observably functioning.
        let input = 0.80;
        let activity = highlight_tail_reference([input; 16]);
        let mapped = input * automatic_response_scale_reference(input, 0.0, 0.995, activity);
        assert!(
            unorm8_code(mapped) + 8 <= unorm8_code(input),
            "automatic tone changed a representative sky value by less than eight codes: {input} -> {mapped}"
        );
    }

    #[test]
    fn adaptive_display_controls_do_not_inherit_color_grade_master_strength() {
        let mut embedded = EmbeddedEffectsConfig::default();
        embedded.blooming_hdr.enabled = false;
        embedded.color_grade.strength = 0.0;
        embedded.color_grade.color_grading_enabled = false;
        embedded.color_grade.lut_enabled = false;
        embedded.color_grade.deband_enabled = false;
        embedded.color_grade.film_grain_enabled = false;
        embedded.color_grade.vignette_enabled = false;
        embedded.color_grade.halation_enabled = false;
        embedded.color_grade.chromatic_aberration_enabled = false;

        let sources = shaders::merge_embedded_sources_with_luts_and_adaptive(
            &embedded,
            &AdaptiveToneConfig::default(),
            &[],
            &[],
            Vec::new(),
        );
        let source = sources
            .iter()
            .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade))
            .expect("final-color source");
        let settings = AdaptiveToneSettings::from_source(Some(source));
        assert!(FinalColorWorkPlan::from_sources(None, Some(source)).has_work());
        assert!(settings.is_active());
        assert!(settings.requires_history());
    }

    #[test]
    fn adaptive_scheduler_caps_work_without_changing_elapsed_time() {
        let update_count = |hz: u32| {
            let mut clock = AdaptiveUpdateClock::default();
            let mut updates = 0;
            let mut integrated_seconds = 0.0_f32;
            for _ in 0..hz {
                let (next, elapsed) = schedule_adaptive_update(clock, true, 1.0 / hz as f32);
                clock = next;
                if let Some(elapsed) = elapsed {
                    updates += 1;
                    integrated_seconds += elapsed;
                }
            }
            (updates, integrated_seconds + clock.elapsed_seconds)
        };

        for (hz, expected_updates) in [
            (30, 30),
            (60, 60),
            (75, 60),
            (90, 60),
            (120, 60),
            (144, 60),
            (240, 60),
        ] {
            let (updates, elapsed) = update_count(hz);
            assert_eq!(updates, expected_updates, "unexpected cadence at {hz} Hz");
            assert!((elapsed - 1.0).abs() < 1.0e-5);
        }
        assert_eq!(
            schedule_adaptive_update(AdaptiveUpdateClock::default(), false, 1.0 / 120.0,),
            (AdaptiveUpdateClock::default(), Some(1.0 / 120.0)),
            "invalid history must be initialized on the current frame"
        );
    }

    #[test]
    fn filtered_response_curve_tracks_the_analytic_mapping_without_band_steps() {
        let response_at = |luma| automatic_response_scale_reference(luma, 0.32, 0.65, 0.85);
        let curve: Vec<f32> = (0..ADAPTIVE_RESPONSE_WIDTH)
            .map(|index| response_at((index as f32 + 0.5) * 4.0 / ADAPTIVE_RESPONSE_WIDTH as f32))
            .collect();
        let sample_curve = |luma: f32| {
            let position = (luma.clamp(0.0, 4.0) * 0.25 * ADAPTIVE_RESPONSE_WIDTH as f32 - 0.5)
                .clamp(0.0, ADAPTIVE_RESPONSE_WIDTH as f32 - 1.0);
            let low = position.floor() as usize;
            let high = (low + 1).min(curve.len() - 1);
            curve[low] + (curve[high] - curve[low]) * position.fract()
        };

        let mut maximum_error = 0.0_f32;
        for step in 0..=4096 {
            let luma = step as f32 * 4.0 / 4096.0;
            maximum_error = maximum_error.max((sample_curve(luma) - response_at(luma)).abs());
        }
        assert!(maximum_error < 0.002, "curve error was {maximum_error}");
    }

    #[test]
    fn adaptive_render_boundary_sanitizes_untrusted_menu_values() {
        let mut embedded = EmbeddedEffectsConfig::default();
        embedded.color_grade.strength = 1.0;
        let adaptive = AdaptiveToneConfig {
            auto_exposure_enabled: true,
            exposure_range_ev: f32::NAN,
            adaptation_speed: f32::INFINITY,
            tone_mapper_mode: ToneMapperMode::Automatic,
            tone_mapper_strength: -99.0,
        };
        let sources = shaders::merge_embedded_sources_with_luts_and_adaptive(
            &embedded,
            &adaptive,
            &[],
            &[],
            Vec::new(),
        );
        let source = sources
            .iter()
            .find(|source| source.embedded_effect_kind() == Some(EmbeddedEffectKind::ColorGrade))
            .expect("final-color source");
        let settings = AdaptiveToneSettings::from_source(Some(source));
        assert_eq!(settings.exposure_range_ev, 0.75);
        assert_eq!(settings.adaptation_speed, 1.0);
        assert_eq!(settings.tone_mapper_strength, 0.0);
        assert_eq!(settings.compose_variant(), ComposeVariant::Adaptive);
        assert_eq!(
            settings.response_constants(f32::NAN, false, None, false)[0][0],
            1.0 / 60.0
        );
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
        assert_eq!(grade_only.effect_draw_count(), 2);
        assert_eq!(grade_only.quarter_resolution_draw_count(), 0);
        assert_eq!(halation_grade.effect_draw_count(), 5);
        assert_eq!(halation_grade.quarter_resolution_draw_count(), 3);
        assert_eq!(fused.effect_draw_count(), 5);
        assert_eq!(fused.quarter_resolution_draw_count(), 3);
        for plan in [neither, bloom_only, grade_only, halation_grade, fused] {
            assert_eq!(plan.internal_full_resolution_copy_count(), 0);
        }

        let shipped = crate::luts::shipped_luts_for_test();
        let catalog_bytes: usize = shipped
            .iter()
            .map(|lut| lut.pixels.len() * std::mem::size_of::<u32>())
            .sum();
        assert_eq!(catalog_bytes, 5_505_024);
        assert_eq!(
            shipped[0].pixels.len() * std::mem::size_of::<u32>(),
            131_072
        );
        assert_eq!(
            (FILM_GRAIN_TEXTURE_SIZE * FILM_GRAIN_TEXTURE_SIZE) as usize
                * std::mem::size_of::<u32>(),
            1_048_576
        );
        assert_eq!(
            2_u64 * ADAPTIVE_RESPONSE_WIDTH as u64 * 8,
            2_048,
            "two 128x1 RGBA16F response curves"
        );
        assert_eq!(
            3840_u64 * 2160 * std::mem::size_of::<u32>() as u64,
            33_177_600,
            "4K chromatic chaining retains one additional ARGB target",
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
            "render_target_slots.prepare_target_change(device)?",
        ] {
            assert!(
                source.contains(required),
                "missing final-color state: {required}"
            );
        }
        assert!(source.contains("crate::backend::AlphaCoverageMode::Nvidia"));
        assert!(source.contains("crate::backend::AlphaCoverageMode::Amd"));
        assert!(source.contains("for sampler in 0..=6"));
        assert!(
            source.contains(
                "device.set_sampler_state(6, D3DSAMP_ADDRESSU, D3DTADDRESS_WRAP.0 as u32)?"
            )
        );
        assert!(
            source.contains(
                "device.set_sampler_state(6, D3DSAMP_ADDRESSV, D3DTADDRESS_WRAP.0 as u32)?"
            )
        );
        assert!(source.contains("device.clear_texture(6)?"));
        assert!(source.contains("device.clear_texture(7)?"));
        assert!(source.contains("configure_adaptive_sampler(device, 7, false)?"));
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
            &prepared.compose_legacy,
            &prepared.compose_static,
            &prepared.compose_adaptive,
            &prepared.adaptive_tone,
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
    fn cinematic_luts_render_bounded_reference_frames_without_erasing_detail() {
        const WIDTH: usize = 41;
        const HEIGHT: usize = 23;
        let shipped_luts = crate::luts::shipped_luts_for_test();
        for lut in &shipped_luts[14..] {
            let mut changed = 0usize;
            let mut input_detail = 0.0f32;
            let mut output_detail = 0.0f32;
            let mut luma_bias = 0.0f32;
            for y in 0..HEIGHT {
                let vertical = y as f32 / (HEIGHT - 1) as f32;
                let mut previous = None;
                for x in 0..WIDTH {
                    let horizontal = x as f32 / (WIDTH - 1) as f32;
                    let micro_detail = if (x + y) % 2 == 0 {
                        1.5 / 255.0
                    } else {
                        -1.5 / 255.0
                    };
                    let input = if y < HEIGHT / 3 {
                        [
                            0.05 + horizontal * 0.42,
                            0.10 + horizontal * 0.46,
                            0.20 + horizontal * 0.62,
                        ]
                    } else if y < HEIGHT * 2 / 3 {
                        [
                            0.16 + horizontal * 0.68,
                            0.10 + horizontal * 0.50,
                            0.06 + horizontal * 0.28,
                        ]
                    } else {
                        [
                            0.08 + horizontal * 0.54,
                            0.16 + horizontal * 0.45,
                            0.09 + horizontal * 0.34,
                        ]
                    }
                    .map(|channel| {
                        (channel + micro_detail * (0.4 + vertical * 0.6)).clamp(0.0, 1.0)
                    });
                    let output = sample_lut(&lut.pixels, input);
                    assert!(
                        output
                            .iter()
                            .all(|value| value.is_finite() && (0.0..=1.0).contains(value)),
                        "{} produced an invalid reference pixel",
                        lut.file_name
                    );
                    changed += (color_distance(input, output) > 2.0 / 255.0) as usize;
                    luma_bias += luma(output) - luma(input);
                    if let Some((previous_input, previous_output)) = previous {
                        input_detail += (luma(input) - luma(previous_input)).abs();
                        output_detail += (luma(output) - luma(previous_output)).abs();
                    }
                    previous = Some((input, output));
                }
            }

            let pixels = (WIDTH * HEIGHT) as f32;
            assert!(
                changed >= WIDTH * HEIGHT * 4 / 5,
                "{} changes only {changed}/{} reference pixels",
                lut.file_name,
                WIDTH * HEIGHT
            );
            assert!(
                output_detail >= input_detail * 0.45,
                "{} retains only {:.1}% of reference detail energy",
                lut.file_name,
                output_detail / input_detail * 100.0
            );
            assert!(
                output_detail <= input_detail * 1.8,
                "{} creates excessive reference edge energy",
                lut.file_name
            );
            assert!(
                (luma_bias / pixels).abs() <= 0.16,
                "{} is dominated by a {:.3} global luma shift",
                lut.file_name,
                luma_bias / pixels
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
        assert_eq!(defaults.film_grain_size, FILM_GRAIN_DEFAULT_SIZE);
        let grain_pixels = film_grain_pixels();
        let width = 4096usize;
        let input = [128.0 / 255.0; 3];
        let input_code = unorm8_code(input[0]) as i16;
        let deltas: Vec<i16> = (0..width)
            .map(|x| {
                let output = film_grain_reference(
                    input,
                    &grain_pixels,
                    [x as f32 + 0.5, 37.5],
                    41.0,
                    defaults.film_grain,
                    defaults.strength,
                    FILM_GRAIN_DEFAULT_SIZE,
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
            changed >= width / 2,
            "default grain changed only {changed}/{width} quantized midtone pixels"
        );
        assert!(
            (1.75..=2.50).contains(&rms),
            "default grain reaches only {rms:.3} code-value RMS after quantization"
        );
        let mean = deltas.iter().map(|delta| *delta as f32).sum::<f32>() / width as f32;
        assert!(
            mean.abs() <= 0.15,
            "default grain biases the image by {mean:.3} code values"
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
    fn film_grain_texture_is_gaussian_balanced_and_deterministic() {
        let first = film_grain_pixels();
        let second = film_grain_pixels();
        assert_eq!(first, second);
        assert_eq!(
            first.len(),
            (FILM_GRAIN_TEXTURE_SIZE * FILM_GRAIN_TEXTURE_SIZE) as usize
        );
        assert!(first.iter().all(|pixel| {
            let red = (pixel >> 16) & 0xFF;
            let green = (pixel >> 8) & 0xFF;
            let blue = pixel & 0xFF;
            red == green && green == blue && pixel >> 24 == 0xFF
        }));
        let values: Vec<f32> = first
            .iter()
            .map(|pixel| (((pixel >> 16) & 0xFF) as f32 / 255.0) * 2.0 - 1.0)
            .collect();
        let mean = values.iter().sum::<f32>() / values.len() as f32;
        let rms =
            (values.iter().map(|value| value * value).sum::<f32>() / values.len() as f32).sqrt();
        let positive = values.iter().filter(|value| **value > 0.0).count();
        let tails = values
            .iter()
            .filter(|value| value.abs() > 2.0 / 3.0)
            .count();
        assert!(mean.abs() <= 0.005, "grain texture mean is {mean:.5}");
        assert!(
            (0.30..=0.36).contains(&rms),
            "grain texture RMS is {rms:.5}"
        );
        assert!((49..=51).contains(&(positive * 100 / values.len())));
        assert!((3..=7).contains(&(tails * 100 / values.len())));
    }

    #[test]
    fn film_grain_is_coherent_temporal_endpoint_safe_and_rejects_the_blocky_model() {
        fn adjacent_correlation(samples: &[f32], width: usize, height: usize) -> f32 {
            let mut products = 0.0;
            let mut left_energy = 0.0;
            let mut right_energy = 0.0;
            for y in 0..height {
                for x in 0..width - 1 {
                    let left = samples[y * width + x];
                    let right = samples[y * width + x + 1];
                    products += left * right;
                    left_energy += left * left;
                    right_energy += right * right;
                }
            }
            products / (left_energy * right_energy).sqrt()
        }

        let grain_pixels = film_grain_pixels();
        let width = 256usize;
        let height = 64usize;
        let coherent: Vec<f32> = (0..height)
            .flat_map(|y| {
                let grain_pixels = &grain_pixels;
                (0..width).map(move |x| {
                    film_grain_noise(
                        grain_pixels,
                        [x as f32 + 0.5, y as f32 + 0.5],
                        41.0,
                        FILM_GRAIN_DEFAULT_SIZE,
                    )
                })
            })
            .collect();
        let legacy: Vec<f32> = (0..height)
            .flat_map(|y| {
                (0..width).map(move |x| {
                    let pixel = [x as f32 + 0.5, y as f32 + 0.5];
                    let cluster_pixel = [(pixel[0] * 0.5).floor(), (pixel[1] * 0.5).floor()];
                    golden_noise(cluster_pixel, 41.0) - 0.5
                })
            })
            .collect();
        let sign_changes = coherent
            .windows(2)
            .filter(|pair| pair[0].is_sign_positive() != pair[1].is_sign_positive())
            .count();
        let coherent_correlation = adjacent_correlation(&coherent, width, height);
        let repeated_coherent = coherent
            .chunks_exact(width)
            .map(|row| row.windows(2).filter(|pair| pair[0] == pair[1]).count())
            .sum::<usize>();
        let repeated_legacy = legacy
            .chunks_exact(width)
            .map(|row| row.windows(2).filter(|pair| pair[0] == pair[1]).count())
            .sum::<usize>();
        assert!(
            sign_changes >= coherent.len() / 4,
            "coherent grain changes sign only {sign_changes}/{} times",
            coherent.len()
        );
        assert!(
            (0.15..=0.65).contains(&coherent_correlation),
            "grain has unsuitable adjacent correlation {coherent_correlation:.3}"
        );
        assert!(
            repeated_coherent <= coherent.len() / 100,
            "coherent grain repeats {repeated_coherent} adjacent samples"
        );
        assert!(
            repeated_legacy >= legacy.len() * 2 / 5,
            "negative control repeats only {repeated_legacy} adjacent samples"
        );

        let sample = film_grain_noise(&grain_pixels, [31.5, 17.5], 41.0, FILM_GRAIN_DEFAULT_SIZE);
        assert_eq!(
            sample,
            film_grain_noise(&grain_pixels, [31.5, 17.5], 41.0, FILM_GRAIN_DEFAULT_SIZE,)
        );
        assert_ne!(
            sample,
            film_grain_noise(&grain_pixels, [31.5, 17.5], 42.0, FILM_GRAIN_DEFAULT_SIZE,)
        );
        assert!((-1.0..=1.0).contains(&sample));
        assert_eq!(
            film_grain_reference(
                [0.0; 3],
                &grain_pixels,
                [31.5, 17.5],
                41.0,
                2.0,
                1.0,
                FILM_GRAIN_DEFAULT_SIZE,
            ),
            [0.0; 3]
        );
        assert_eq!(
            film_grain_reference(
                [1.0; 3],
                &grain_pixels,
                [31.5, 17.5],
                41.0,
                2.0,
                1.0,
                FILM_GRAIN_DEFAULT_SIZE,
            ),
            [1.0; 3]
        );

        let input = [0.2, 0.4, 0.6];
        let output = film_grain_reference(
            input,
            &grain_pixels,
            [31.5, 17.5],
            41.0,
            0.32,
            0.68,
            FILM_GRAIN_DEFAULT_SIZE,
        );
        let red_scale = output[0] / input[0];
        assert!((output[1] / input[1] - red_scale).abs() < 1.0e-6);
        assert!((output[2] / input[2] - red_scale).abs() < 1.0e-6);
    }

    #[test]
    fn finishing_dither_noise_remains_deterministic_and_bounded() {
        let pixels = [[0.5, 0.5], [12.5, 8.5], [1919.5, 1079.5]];
        for pixel in pixels {
            let first = golden_noise(pixel, 41.0);
            assert_eq!(first, golden_noise(pixel, 41.0));
            assert!((0.0..1.0).contains(&first));
            assert_ne!(first, golden_noise(pixel, 42.0));
            let maximum_dither = (first - 0.5).abs() * DEBAND_DITHER_NOISE_CODES / 255.0;
            assert!(maximum_dither <= 2.0 / 255.0 + 1.0e-7);
        }
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
        config.color_grade.film_grain_size = 99.0;
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
        assert_eq!(settings.film_grain, 2.0);
        assert_eq!(settings.film_grain_size, 3.0);
        assert_eq!(settings.vignette, 1.0);
        assert_eq!(settings.halation, 1.0);
        assert_eq!(settings.chromatic_aberration, 12.0);
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
            film_grain_size: 0.71,
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
                [1.0, 1.0, 1.0, 0.71],
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
            "float4 AdaptiveToneData : register(c19);",
            "sampler2D ColorLut : register(s5);",
            "sampler2D FilmGrainTexture : register(s6);",
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
            "static const float DebandDitherNoiseScaleCodes = 4.0f;",
            "? GradeData2.z * GradeData0.x * debandFlatWeight * DebandDitherNoiseScaleCodes",
            "uv * ScreenData.xy / (GradeData6.w * FilmGrainTextureSize) + frameOffset;",
            "float grainResponse = 1.0f - sqrt(saturate(Luma(color)));",
            "color += color * grain;",
        ] {
            assert!(
                source.contains(equation),
                "CPU reference lost shader equation: {equation}"
            );
        }
        assert!(source.contains("GradeData3.z > 0.5f"));
        assert!(source.contains("GradeData4.x > 0.5f"));
        assert!(source.contains("GradeData4.y > 0.5f"));
        assert!(!source.contains("clusterPixel"));
        assert!(!source.contains("FilmGrainNoiseScaleCodes"));
    }

    #[test]
    fn final_color_contract_preserves_alpha_and_keeps_adaptation_low_resolution() {
        let source = std::str::from_utf8(COMPOSE_SHADER).expect("compose UTF-8");
        assert!(source.contains("baseSample.a"));
        assert!(source.contains("SampleColorLut"));
        assert_eq!(source.matches("tex2Dlod(ColorLut").count(), 2);
        assert!(!source.contains("averageLuma"));
        assert!(!source.contains("for (int y"));
        assert!(!source.contains("ddx("));
        assert!(!source.contains("ddy("));
        assert!(source.contains("color = input.uv.x < 0.5f ? ungraded : color"));
        assert!(source.contains("sampler2D AdaptiveToneResponse : register(s7);"));
        assert!(source.contains("float responseUv = saturate(displayLuma * 0.25f);"));
        assert!(source.contains("return inputColor * responseScale;"));
        assert!(!source.contains("AdaptiveToneData.z * GradeData0.x"));

        let meter = std::str::from_utf8(ADAPTIVE_TONE_SHADER).expect("meter UTF-8");
        assert!(meter.contains("sampler2D BloomTexture : register(s4);"));
        assert!(meter.contains("float exposureScale = exp2(exposureEv);"));
        assert!(meter.contains("float curveLuma = input.uv.x * ResponseCurveMaxLuma;"));
        assert!(meter.contains("linearLuma / ToneWhitePointSquared"));
        assert!(!meter.contains("compensationEv"));
        assert!(source.contains("float3 color = inputColor * exp2(GradeData0.y);"));
        assert!(
            meter.contains("return float4(responseScale, adaptedLog, exposureEv, toneActivity);")
        );
        assert!(meter.contains("float softHighlight = Smooth01((peak - 0.72f) / 0.26f);"));
        assert!(meter.contains("float clipRisk = Smooth01((peak - 0.94f) / 0.16f);"));
        assert!(meter.contains("previous.g <= 0.5f"));
        assert!(meter.contains(": (temporalStateValid ? previous.g : 1.0f);"));
        assert!(!meter.contains("ddx("));
        assert!(!meter.contains("ddy("));

        let chromatic = std::str::from_utf8(CHROMATIC_SHADER).expect("chromatic UTF-8");
        assert_eq!(chromatic.matches("SampleScene(").count(), 4);
        assert!(chromatic.contains("radialDirection * ScreenData.zw * ChromaticData.x"));
        assert!(chromatic.contains("length((input.uv - 0.5f) * 2.0f)"));
        assert!(chromatic.contains("return float4(red, center.g, blue, center.a);"));
        assert!(!chromatic.contains("ddx("));
        assert!(!chromatic.contains("ddy("));

        let implementation = include_str!("blooming_hdr.rs");
        assert!(implementation.contains("if composed && work.chromatic_aberration {"));
        assert!(implementation.contains("if work.bloom_intermediate {"));
        assert!(implementation.contains("bind_bloom_effect_constants"));
        assert!(implementation.contains("&grade.constants(bloom_enabled)"));
        let draw_signature = ["pub(crate) fn dr", "aw("].concat();
        let draw_body = implementation
            .rsplit_once(&draw_signature)
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\n    fn "))
            .map(|(body, _)| body)
            .expect("final-color draw body");
        assert!(
            draw_body.find("if work.bloom_intermediate {")
                < draw_body.find("let adaptive = if requested_adaptive.requires_history()"),
            "Bloom must exist before automatic tone measures OMV-created headroom"
        );
        assert!(!draw_body.contains("copy_scene_color_for_sampling("));
        assert!(!draw_body.contains("device.stretch_rect("));
        assert!(draw_body.contains("self.ensure_composed_target(device, desc)?"));
        assert!(draw_body.contains("&composed_target.texture"));
        assert!(implementation.contains("self.draw_chromatic_aberration("));
        assert!(implementation.contains("draw_quad(device, ADAPTIVE_RESPONSE_WIDTH, 1)"));
    }
}

pub(crate) struct BloomingHdrEffect {
    extract_shader: PixelShader9,
    blur_shader: PixelShader9,
    compose_legacy_shader: PixelShader9,
    compose_static_shader: PixelShader9,
    adaptive_pipeline: Option<AdaptiveTonePipeline>,
    chromatic_shader: PixelShader9,
    neutral_bloom: Texture9,
    lut_texture: Texture9,
    film_grain_texture: Texture9,
    lut_revision: Option<(u32, u64)>,
    targets: Option<BloomTargets>,
    composed_target: Option<FullResolutionTarget>,
    adaptive_history: Option<AdaptiveToneHistory>,
    adaptive_update_clock: AdaptiveUpdateClock,
    adaptive_target_creation_failed: bool,
    render_target_slots: RenderTargetSlots,
}

impl BloomingHdrEffect {
    /// Create device-owned final-color shaders and persistent managed assets.
    ///
    /// FP16 display adaptation is optional. The response texture must support
    /// both rendering and linear filtering; unsupported formats or adaptive
    /// shader creation failures preserve Bloom, legacy grading, and the fixed
    /// neutral tone mapper instead of rejecting the whole pipeline.
    pub(crate) fn create(
        device: &Device9Ref<'_>,
        shaders: &FinalColorShaderBytecode,
        render_target_slots: RenderTargetSlots,
    ) -> Direct3DResult<Self> {
        let adaptive_pipeline = match device
            .supports_linearly_filtered_render_target_texture(D3DFMT_A16B16G16R16F)
        {
            Ok(true) => {
                let pipeline: Direct3DResult<AdaptiveTonePipeline> = (|| {
                    Ok(AdaptiveTonePipeline {
                        response_shader: device.create_pixel_shader(&shaders.adaptive_tone)?,
                        compose_shader: device.create_pixel_shader(&shaders.compose_adaptive)?,
                    })
                })();
                match pipeline {
                    Ok(pipeline) => Some(pipeline),
                    Err(err) => {
                        log::warn!(
                            "[FINAL_COLOR] Automatic exposure/tone shaders unavailable; fixed final color remains active: {err}"
                        );
                        None
                    }
                }
            }
            Ok(false) => {
                log::warn!(
                    "[FINAL_COLOR] Linearly filtered FP16 render targets unavailable; automatic exposure/tone falls back to fixed neutral mapping"
                );
                None
            }
            Err(err) => {
                log::warn!(
                    "[FINAL_COLOR] Could not query FP16 response-curve support; automatic exposure/tone will use fixed fallback: {err}"
                );
                None
            }
        };

        Ok(Self {
            extract_shader: device.create_pixel_shader(&shaders.extract)?,
            blur_shader: device.create_pixel_shader(&shaders.blur)?,
            compose_legacy_shader: device.create_pixel_shader(&shaders.compose_legacy)?,
            compose_static_shader: device.create_pixel_shader(&shaders.compose_static)?,
            adaptive_pipeline,
            chromatic_shader: device.create_pixel_shader(&shaders.chromatic)?,
            neutral_bloom: create_argb_texture(device, 1, 1, &[0xFF00_0000])?,
            lut_texture: create_argb_texture(device, 4, 2, &identity_lut_pixels(2))?,
            film_grain_texture: create_argb_texture(
                device,
                FILM_GRAIN_TEXTURE_SIZE,
                FILM_GRAIN_TEXTURE_SIZE,
                &film_grain_pixels(),
            )?,
            lut_revision: None,
            targets: None,
            composed_target: None,
            adaptive_history: None,
            adaptive_update_clock: AdaptiveUpdateClock::default(),
            adaptive_target_creation_failed: false,
            render_target_slots,
        })
    }

    /// Execute the bounded final-color transaction for one display frame.
    ///
    /// `frame_seconds` is the previous consecutive presentation-callback
    /// interval and `timing_continuous` identifies a consecutive render epoch.
    /// A gap invalidates exposure history; ordinary camera motion never does.
    /// The return value is true only when at least one effect draw wrote
    /// output, allowing the phase color graph to remain correct after
    /// fail-soft adaptive fallback.
    pub(crate) fn draw(
        &mut self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &FrameInputs,
        bloom_source: Option<&ScreenShaderSource>,
        color_grade_source: Option<&ScreenShaderSource>,
        selected_lut: Option<&LutAsset>,
        scene_color: &Texture9,
        frame_index: u32,
        frame_seconds: f32,
        timing_continuous: bool,
    ) -> Direct3DResult<bool> {
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
        let requested_adaptive = AdaptiveToneSettings::from_source(color_grade_source);
        if !work.has_work() {
            self.invalidate_adaptive_history();
            return Ok(false);
        }

        if grade.lut_enabled {
            self.ensure_lut(device, selected_lut)?;
        }
        bind_pipeline_state(device)?;
        bind_depth_inputs(device, &frame_inputs.depth.first_person_texture)?;

        if work.bloom_intermediate {
            self.ensure_targets(device, desc)?;
            let Some(targets) = self.targets.as_ref() else {
                return Ok(false);
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

        let adaptive = if requested_adaptive.requires_history() {
            if self.draw_adaptation(
                device,
                desc,
                scene_color,
                bloom_source,
                requested_adaptive,
                work.bloom,
                frame_seconds,
                timing_continuous,
            )? {
                requested_adaptive
            } else {
                requested_adaptive.without_history()
            }
        } else {
            self.invalidate_adaptive_history();
            requested_adaptive
        };

        let composed = work.bloom || grade.is_active() || adaptive.is_active();
        if composed && work.chromatic_aberration {
            self.ensure_composed_target(device, desc)?;
            let Some(composed_target) = self.composed_target.as_ref() else {
                return Ok(false);
            };
            self.draw_compose(
                device,
                &composed_target.surface,
                desc,
                frame_inputs,
                bloom_source,
                &grade,
                adaptive,
                work.bloom_intermediate,
                work.bloom,
                scene_color,
                frame_index,
            )?;
            self.draw_chromatic_aberration(
                device,
                backbuffer,
                desc,
                &composed_target.texture,
                grade.chromatic_aberration * grade.strength,
            )?;
        } else {
            if composed {
                self.draw_compose(
                    device,
                    backbuffer,
                    desc,
                    frame_inputs,
                    bloom_source,
                    &grade,
                    adaptive,
                    work.bloom_intermediate,
                    work.bloom,
                    scene_color,
                    frame_index,
                )?;
            }
            if work.chromatic_aberration {
                self.draw_chromatic_aberration(
                    device,
                    backbuffer,
                    desc,
                    scene_color,
                    grade.chromatic_aberration * grade.strength,
                )?;
            }
        }
        Ok(composed || work.chromatic_aberration)
    }

    fn invalidate_adaptive_history(&mut self) {
        if let Some(history) = self.adaptive_history.as_mut() {
            history.valid = false;
        }
        self.adaptive_update_clock = AdaptiveUpdateClock::default();
    }

    /// Invalidate temporal display state when the fused final-color stage is
    /// not scheduled for this frame.
    ///
    /// DOF may keep the shared Present clock continuous while adaptive color
    /// is disabled. Explicit invalidation prevents a later re-enable from
    /// applying stale exposure captured before that disabled interval.
    pub(crate) fn note_skipped(&mut self) {
        self.invalidate_adaptive_history();
    }

    /// Meter the current image and, when due, publish the next response curve.
    ///
    /// The previous and output targets are always distinct. D3D9 retains
    /// texture bindings across draws and frames, so both history sampler slots
    /// are explicitly cleared before the alternating output becomes RT0.
    /// Updates are capped at 60 Hz and carry their accumulated elapsed time,
    /// preserving the configured temporal half-lives at higher display rates.
    /// The tone meter observes native highlights and the already prepared Bloom
    /// contribution through separate logic from exposure's outlier handling.
    fn draw_adaptation(
        &mut self,
        device: &Device9Ref<'_>,
        desc: &D3DSURFACE_DESC,
        scene_color: &Texture9,
        bloom_source: Option<&ScreenShaderSource>,
        settings: AdaptiveToneSettings,
        bloom_enabled: bool,
        frame_seconds: f32,
        timing_continuous: bool,
    ) -> Direct3DResult<bool> {
        let Some(pipeline) = self.adaptive_pipeline.as_ref() else {
            return Ok(false);
        };
        if self.adaptive_target_creation_failed {
            return Ok(false);
        }
        if self.adaptive_history.is_none() {
            match AdaptiveToneHistory::create(device) {
                Ok(history) => {
                    self.adaptive_history = Some(history);
                    // This one-time device-lifetime event proves that the
                    // automatic route passed format checks, created both FP16
                    // targets, and reached a real render frame. The former
                    // generic pipeline log could not distinguish that state
                    // from fixed/legacy composition during field playtests.
                    log::info!(
                        "[FINAL_COLOR] Automatic exposure/tone response initialized ({}x1 FP16)",
                        ADAPTIVE_RESPONSE_WIDTH
                    );
                }
                Err(err) => {
                    self.adaptive_target_creation_failed = true;
                    log::warn!(
                        "[FINAL_COLOR] Automatic exposure/tone response targets unavailable; fixed neutral mapping remains active: {err}"
                    );
                    return Ok(false);
                }
            }
        }
        let Some(history) = self.adaptive_history.as_mut() else {
            return Ok(false);
        };
        let bloom_texture = if bloom_enabled {
            self.targets
                .as_ref()
                .map(|targets| &targets.extract.texture)
                .unwrap_or(&self.neutral_bloom)
        } else {
            &self.neutral_bloom
        };
        history.begin_frame(desc, timing_continuous);
        let history_valid = history.valid;
        let (next_clock, update_seconds) =
            schedule_adaptive_update(self.adaptive_update_clock, history_valid, frame_seconds);
        self.adaptive_update_clock = next_clock;
        let Some(update_seconds) = update_seconds else {
            // A valid prior curve remains bound by compose. Skipping here saves
            // both the response draw and its render-target transition.
            return Ok(true);
        };
        let (previous, output) = history.write_pair();

        device.clear_texture(1)?;
        device.clear_texture(7)?;
        bind_target(
            device,
            &output.surface,
            ADAPTIVE_RESPONSE_WIDTH,
            1,
            self.render_target_slots,
        )?;
        // bind_pipeline_state already establishes linear scene sampling on s0
        // and point history sampling on s1 for the complete transaction.
        device.set_texture(0, scene_color)?;
        device.set_texture(1, &previous.texture)?;
        device.set_texture(4, bloom_texture)?;
        device.set_pixel_shader_constant_f(
            0,
            &settings.response_constants(
                update_seconds,
                history_valid,
                bloom_source,
                bloom_enabled,
            ),
        )?;
        device.set_pixel_shader(&pipeline.response_shader)?;
        let draw_result = draw_quad(device, ADAPTIVE_RESPONSE_WIDTH, 1);
        device.clear_texture(0)?;
        device.clear_texture(1)?;
        device.clear_texture(4)?;
        draw_result?;
        history.commit_write();
        Ok(true)
    }

    /// Ensure the full-resolution composition output used by chromatic
    /// aberration matches the engine target exactly.
    ///
    /// D3D9 forbids sampling a texture while one of its levels is bound for
    /// rendering. Writing composition into this separate target preserves the
    /// established two-pass equation while removing the old backbuffer copy
    /// and its driver synchronization point.
    fn ensure_composed_target(
        &mut self,
        device: &Device9Ref<'_>,
        desc: &D3DSURFACE_DESC,
    ) -> Direct3DResult<()> {
        let needs_target = self
            .composed_target
            .as_ref()
            .is_none_or(|target| !target.matches(desc));
        if needs_target {
            self.composed_target = Some(FullResolutionTarget::create(device, desc)?);
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
            self.render_target_slots,
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

        bind_target(
            device,
            output,
            targets.width,
            targets.height,
            self.render_target_slots,
        )?;
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
        adaptive: AdaptiveToneSettings,
        bloom_texture_ready: bool,
        bloom_enabled: bool,
        scene_color: &Texture9,
        frame_index: u32,
    ) -> Direct3DResult<()> {
        bind_target(
            device,
            backbuffer,
            desc.Width,
            desc.Height,
            self.render_target_slots,
        )?;
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
        device.set_texture(6, &self.film_grain_texture)?;
        if adaptive.compose_variant() == ComposeVariant::Adaptive {
            let Some(pipeline) = self.adaptive_pipeline.as_ref() else {
                return Ok(());
            };
            let Some(history) = self.adaptive_history.as_ref() else {
                return Ok(());
            };
            configure_adaptive_sampler(device, 7, false)?;
            device.set_texture(7, history.current_texture())?;
            device.set_pixel_shader(&pipeline.compose_shader)?;
        } else {
            // Never retain a history texture in a sampler slot when the next
            // draw may alternate that same texture into RT0.
            device.clear_texture(7)?;
        }
        bind_compose_constants(
            device,
            desc,
            frame_inputs,
            bloom_source,
            grade,
            adaptive,
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
        match adaptive.compose_variant() {
            ComposeVariant::Legacy => device.set_pixel_shader(&self.compose_legacy_shader)?,
            ComposeVariant::Static => device.set_pixel_shader(&self.compose_static_shader)?,
            ComposeVariant::Adaptive => {}
        }
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
        bind_target(
            device,
            backbuffer,
            desc.Width,
            desc.Height,
            self.render_target_slots,
        )?;
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
    for sampler in 0..=6 {
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
    device.set_sampler_state(6, D3DSAMP_ADDRESSU, D3DTADDRESS_WRAP.0 as u32)?;
    device.set_sampler_state(6, D3DSAMP_ADDRESSV, D3DTADDRESS_WRAP.0 as u32)?;
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
    render_target_slots: RenderTargetSlots,
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
    device.clear_texture(6)?;
    render_target_slots.prepare_target_change(device)?;
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
    adaptive: AdaptiveToneSettings,
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
    )?;
    device.set_pixel_shader_constant_f(19, &[adaptive.compose_constants()])
}

fn configure_adaptive_sampler(
    device: &Device9Ref<'_>,
    sampler: u32,
    point_sampled: bool,
) -> Direct3DResult<()> {
    let filter = if point_sampled {
        D3DTEXF_POINT
    } else {
        D3DTEXF_LINEAR
    };
    device.set_sampler_state(sampler, D3DSAMP_ADDRESSU, D3DTADDRESS_CLAMP.0 as u32)?;
    device.set_sampler_state(sampler, D3DSAMP_ADDRESSV, D3DTADDRESS_CLAMP.0 as u32)?;
    device.set_sampler_state(sampler, D3DSAMP_MINFILTER, filter.0 as u32)?;
    device.set_sampler_state(sampler, D3DSAMP_MAGFILTER, filter.0 as u32)?;
    device.set_sampler_state(sampler, D3DSAMP_MIPFILTER, D3DTEXF_NONE.0 as u32)?;
    device.set_sampler_state(sampler, D3DSAMP_SRGBTEXTURE, 0)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ComposeVariant {
    Legacy,
    Static,
    Adaptive,
}

/// Sanitized adaptive-display values read from the live shader catalog.
///
/// The catalog is mutable menu input, so the render boundary independently
/// validates every numeric lane even though configuration loading also
/// sanitizes persisted values. Keeping this type `Copy` lets the draw path
/// choose a fallback without allocating or mutating the shared source.
#[derive(Clone, Copy, Debug, PartialEq)]
struct AdaptiveToneSettings {
    source_enabled: bool,
    auto_exposure_enabled: bool,
    exposure_range_ev: f32,
    adaptation_speed: f32,
    tone_mapper_mode: ToneMapperMode,
    tone_mapper_strength: f32,
}

impl AdaptiveToneSettings {
    fn from_source(source: Option<&ScreenShaderSource>) -> Self {
        let Some(source) = source else {
            return Self::disabled();
        };
        Self {
            source_enabled: source.enabled,
            auto_exposure_enabled: source_option_bool(source, "auto_exposure_enabled", false),
            exposure_range_ev: source_option_float(source, "exposure_range_ev", 0.75)
                .clamp(0.0, AdaptiveToneConfig::MAX_EXPOSURE_RANGE_EV),
            adaptation_speed: source_option_float(source, "adaptation_speed", 1.0).clamp(
                AdaptiveToneConfig::MIN_ADAPTATION_SPEED,
                AdaptiveToneConfig::MAX_ADAPTATION_SPEED,
            ),
            tone_mapper_mode: ToneMapperMode::from_index(source_option_integer(
                source,
                "tone_mapper_mode",
                0,
            )),
            tone_mapper_strength: source_option_float(source, "tone_mapper_strength", 0.65)
                .clamp(0.0, AdaptiveToneConfig::MAX_TONE_MAPPER_STRENGTH),
        }
    }

    const fn disabled() -> Self {
        Self {
            source_enabled: false,
            auto_exposure_enabled: false,
            exposure_range_ev: 0.75,
            adaptation_speed: 1.0,
            tone_mapper_mode: ToneMapperMode::Off,
            tone_mapper_strength: 0.65,
        }
    }

    fn is_active(self) -> bool {
        self.source_enabled
            && (self.auto_exposure_active()
                || (self.tone_mapper_mode != ToneMapperMode::Off
                    && self.tone_mapper_strength > 1.0e-5))
    }

    fn requires_history(self) -> bool {
        self.is_active()
            && (self.auto_exposure_active()
                || (self.tone_mapper_mode == ToneMapperMode::Automatic
                    && self.tone_mapper_strength > 1.0e-5))
    }

    fn compose_variant(self) -> ComposeVariant {
        if self.requires_history() {
            ComposeVariant::Adaptive
        } else if self.is_active() {
            ComposeVariant::Static
        } else {
            ComposeVariant::Legacy
        }
    }

    fn auto_exposure_active(self) -> bool {
        self.auto_exposure_enabled && self.exposure_range_ev > 1.0e-5
    }

    /// Preserve useful fixed tone mapping when FP16 adaptation is unavailable.
    ///
    /// Automatic tone mapping needs the filtered response texture. Falling
    /// back to the calibrated fixed-neutral curve preserves bounded highlight
    /// shaping without dropping the rest of final-color work.
    fn without_history(mut self) -> Self {
        self.auto_exposure_enabled = false;
        if self.tone_mapper_mode == ToneMapperMode::Automatic {
            self.tone_mapper_mode = ToneMapperMode::Neutral;
        }
        self
    }

    fn response_constants(
        self,
        frame_seconds: f32,
        history_valid: bool,
        bloom_source: Option<&ScreenShaderSource>,
        bloom_enabled: bool,
    ) -> [[f32; 4]; 4] {
        // Automatic tone measures compose's bounded Bloom equation before its
        // localized first-person attenuation. This conservative estimate
        // avoids adding a depth neighborhood to the tiny response generator.
        // Re-read and clamp the live menu lanes here because shader sources
        // are mutable runtime input; relying only on TOML sanitation would let
        // an in-session edit publish non-finite GPU constants.
        let bloom_enabled = bloom_enabled && bloom_source.is_some();
        let bloom = bloom_source.map_or([0.0; 6], |source| {
            [
                source_option_float(source, "bloom_intensity", 0.0).clamp(0.0, 1.5),
                source_option_float(source, "exposure_bias", 0.0).clamp(-0.5, 0.5),
                source_option_float(source, "highlight_shoulder", 0.0).clamp(0.0, 1.0),
                source_option_float(source, "saturation", 1.0).clamp(0.0, 1.5),
                source_option_float(source, "warmth", 0.0).clamp(-1.0, 1.0),
                source_option_float(source, "shadow_lift", 0.0).clamp(0.0, 1.0),
            ]
        });
        [
            [
                if frame_seconds.is_finite() {
                    frame_seconds.clamp(1.0 / 240.0, 1.0 / 20.0)
                } else {
                    1.0 / 60.0
                },
                self.exposure_range_ev,
                self.adaptation_speed,
                history_valid as u8 as f32,
            ],
            [
                self.auto_exposure_active() as u8 as f32,
                (self.tone_mapper_mode == ToneMapperMode::Automatic) as u8 as f32,
                self.tone_mapper_strength,
                0.0,
            ],
            [0.0, bloom_enabled as u8 as f32, bloom[0], bloom[1]],
            [bloom[2], bloom[3], bloom[4], bloom[5]],
        ]
    }

    fn compose_constants(self) -> [f32; 4] {
        [
            self.auto_exposure_active() as u8 as f32,
            self.tone_mapper_mode.index() as f32,
            self.tone_mapper_strength,
            0.0,
        ]
    }
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
    film_grain_size: f32,
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
            film_grain: source_option_float(source, "film_grain", 0.0).clamp(0.0, 2.0),
            film_grain_size: source_option_float(source, "film_grain_size", 1.743_985)
                .clamp(0.3, 3.0),
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
                .clamp(0.0, 12.0),
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
            film_grain_size: 1.743_985,
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
                self.film_grain_size,
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

fn source_option_integer(source: &ScreenShaderSource, key: &str, fallback: i32) -> i32 {
    source
        .options
        .iter()
        .find(|option| option.key == key)
        .and_then(|option| match option.value {
            ShaderOptionValue::Integer(value) => Some(value),
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

fn film_grain_pixels() -> Vec<u32> {
    let mut state = FILM_GRAIN_TEXTURE_SEED;
    (0..FILM_GRAIN_TEXTURE_SIZE * FILM_GRAIN_TEXTURE_SIZE)
        .map(|_| {
            let gaussian = (0..12).map(|_| next_grain_random(&mut state)).sum::<f32>() - 6.0;
            let encoded = (0.5 + gaussian.clamp(-3.0, 3.0) / 6.0).clamp(0.0, 1.0);
            let code = (encoded * 255.0).round() as u32;
            0xFF00_0000 | (code << 16) | (code << 8) | code
        })
        .collect()
}

fn next_grain_random(state: &mut u32) -> f32 {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    ((*state >> 8) as f32 + 0.5) / 16_777_216.0
}

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

struct AdaptiveTonePipeline {
    response_shader: PixelShader9,
    compose_shader: PixelShader9,
}

/// Two FP16 response curves carrying scale plus replicated temporal state.
///
/// Ping-pong storage is required because D3D9 forbids a texture from being an
/// input and render target simultaneously. `current_is_first` identifies the
/// most recently committed target. Each R lane stores a luminance-indexed RGB scale;
/// G/B/A replicate adapted log luminance, applied transient EV, and automatic
/// tone activity. The shader may keep positive G as an unmetered-black sentinel;
/// `valid` separately describes CPU render-epoch continuity.
struct AdaptiveToneHistory {
    first: EffectTarget,
    second: EffectTarget,
    current_is_first: bool,
    valid: bool,
    source_dimensions: Option<[u32; 2]>,
}

impl AdaptiveToneHistory {
    fn create(device: &Device9Ref<'_>) -> Direct3DResult<Self> {
        Ok(Self {
            first: EffectTarget::create(device, ADAPTIVE_RESPONSE_WIDTH, 1, D3DFMT_A16B16G16R16F)?,
            second: EffectTarget::create(device, ADAPTIVE_RESPONSE_WIDTH, 1, D3DFMT_A16B16G16R16F)?,
            current_is_first: true,
            valid: false,
            source_dimensions: None,
        })
    }

    fn begin_frame(&mut self, desc: &D3DSURFACE_DESC, timing_continuous: bool) {
        let dimensions = [desc.Width, desc.Height];
        if !timing_continuous || self.source_dimensions != Some(dimensions) {
            self.valid = false;
        }
        self.source_dimensions = Some(dimensions);
    }

    fn write_pair(&self) -> (&EffectTarget, &EffectTarget) {
        if self.current_is_first {
            (&self.first, &self.second)
        } else {
            (&self.second, &self.first)
        }
    }

    fn commit_write(&mut self) {
        self.current_is_first = !self.current_is_first;
        self.valid = true;
    }

    fn current_texture(&self) -> &Texture9 {
        if self.current_is_first {
            &self.first.texture
        } else {
            &self.second.texture
        }
    }
}

/// Full-resolution intermediate used only when one final-color pass feeds a
/// second pass in the same phase.
///
/// Storing the source description prevents reuse across Reset, resolution,
/// HDR-format, or swap-chain changes. The texture is persistent device-owned
/// memory; no allocation occurs in the steady-state draw path.
struct FullResolutionTarget {
    width: u32,
    height: u32,
    format: D3DFORMAT,
    texture: Texture9,
    surface: Surface9,
}

impl FullResolutionTarget {
    fn create(device: &Device9Ref<'_>, desc: &D3DSURFACE_DESC) -> Direct3DResult<Self> {
        let texture = device.create_render_target_texture(desc.Width, desc.Height, desc.Format)?;
        let surface = texture.surface_level(0)?;
        Ok(Self {
            width: desc.Width,
            height: desc.Height,
            format: desc.Format,
            texture,
            surface,
        })
    }

    fn matches(&self, desc: &D3DSURFACE_DESC) -> bool {
        self.width == desc.Width && self.height == desc.Height && self.format == desc.Format
    }
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
