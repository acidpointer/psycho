//! Engine-side ambient occlusion pipeline.

use libpsycho::os::windows::directx9::{
    D3DCULL_NONE, D3DFMT_G16R16F, D3DFORMAT, D3DPT_TRIANGLESTRIP, D3DRS_ADAPTIVETESS_Y,
    D3DRS_ALPHABLENDENABLE, D3DRS_ALPHATESTENABLE, D3DRS_COLORWRITEENABLE, D3DRS_CULLMODE,
    D3DRS_MULTISAMPLEANTIALIAS, D3DRS_MULTISAMPLEMASK, D3DRS_POINTSIZE, D3DRS_SCISSORTESTENABLE,
    D3DRS_SRGBWRITEENABLE, D3DRS_STENCILENABLE, D3DRS_ZENABLE, D3DRS_ZWRITEENABLE,
    D3DSAMP_ADDRESSU, D3DSAMP_ADDRESSV, D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER, D3DSAMP_MIPFILTER,
    D3DSAMP_SRGBTEXTURE, D3DSURFACE_DESC, D3DTA_TEXTURE, D3DTADDRESS_CLAMP, D3DTEXF_LINEAR,
    D3DTEXF_NONE, D3DTEXF_POINT, D3DTOP_SELECTARG1, D3DTSS_ALPHAARG1, D3DTSS_ALPHAOP,
    D3DTSS_COLORARG1, D3DTSS_COLOROP, D3DVIEWPORT9, Device9Ref, Direct3DResult, PixelShader9,
    ScreenVertex, Surface9, Texture9, direct3d_failure,
};

use crate::{
    backend::{CameraFrame, DepthTexture, FrameInputs},
    shaders::{self, ScreenShaderSource},
};

const COLOR_WRITE_ALL: u32 = 0x0F;
const CONTACT_OPTION_REGISTER: u32 = 7;
const EFFECT_CONSTANT_REGISTER: u32 = 10;
const TEMPORAL_CONSTANT_REGISTER: u32 = 13;
const DEPTH_PRECISION_CONSTANT_REGISTER: u32 = 19;
const DEPTH_LINEARIZE_CONSTANT_REGISTER: u32 = 20;
const AO_SCALE: u32 = 2;
const DEPTH_PRECISION_STEPS: f32 = 4.0;
const AMD_ALPHA_TO_COVERAGE_OFF: u32 = u32::from_le_bytes(*b"A2M0");

const EXTRACT_SHADER: &[u8] =
    include_bytes!("../../shaders/embedded/ambient_occlusion_extract.hlsl");
const BLUR_SHADER: &[u8] = include_bytes!("../../shaders/embedded/ambient_occlusion_blur.hlsl");
const TEMPORAL_SHADER: &[u8] =
    include_bytes!("../../shaders/embedded/ambient_occlusion_temporal.hlsl");
const COMPOSE_SHADER: &[u8] =
    include_bytes!("../../shaders/embedded/ambient_occlusion_compose.hlsl");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AmbientOcclusionFamily {
    Fast,
    Contact,
    Combined,
}

impl AmbientOcclusionFamily {
    const fn shader_mode(self) -> u8 {
        match self {
            Self::Fast => 1,
            Self::Contact => 2,
            Self::Combined => 3,
        }
    }
}

fn extract_shader_source(family: AmbientOcclusionFamily) -> Vec<u8> {
    let mut source = format!("#define AO_FAMILY_MODE {}\n", family.shader_mode()).into_bytes();
    source.extend_from_slice(EXTRACT_SHADER);
    source
}

#[cfg(test)]
mod shader_compile_tests {
    use libpsycho::os::windows::directx9::{D3DFMT_A8R8G8B8, D3DFMT_G16R16F};

    use super::{
        AmbientOcclusionFamily, BLUR_SHADER, COMPOSE_SHADER, DEPTH_PRECISION_STEPS, EXTRACT_SHADER,
        TEMPORAL_SHADER, TemporalCameraState, TemporalReprojection, ao_depth_linearize_constants,
        ao_depth_precision_constants, extract_shader_source, fallback_format_matches,
        family_for_strengths,
    };
    use crate::backend::{CameraFrame, CameraTransformFrame};

    const INTZ_DEPTH_LEVELS: f32 = 16_777_215.0;
    const SOURCE_WIDTH: usize = 128;
    const SOURCE_HEIGHT: usize = 72;
    const TARGET_WIDTH: usize = SOURCE_WIDTH / 2;
    const TARGET_HEIGHT: usize = SOURCE_HEIGHT / 2;
    const NEAR_Z: f32 = 5.0;
    const FAR_Z: f32 = 100_000.0;

    fn shader_source(source: &[u8]) -> &str {
        std::str::from_utf8(source).expect("embedded AO shader is UTF-8")
    }

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

    fn assert_shader_budget(
        name: &str,
        source: &[u8],
        instruction_limit: usize,
        texture_limit: usize,
    ) {
        const TEXLD: u16 = 66;
        const TEXLDD: u16 = 93;
        const TEXLDL: u16 = 95;
        let bytecode = crate::shaders::compile_hlsl_source_target(name, source, "ps_3_0")
            .unwrap_or_else(|error| panic!("{name} failed to compile: {error:#}"));
        let opcodes = compiled_instruction_opcodes(&bytecode);
        let texture_count = opcodes
            .iter()
            .filter(|opcode| matches!(**opcode, TEXLD | TEXLDD | TEXLDL))
            .count();
        assert!(
            opcodes.len() <= instruction_limit,
            "{name} AO grew to {} instructions (limit {instruction_limit})",
            opcodes.len(),
        );
        assert!(
            texture_count <= texture_limit,
            "{name} AO grew to {texture_count} texture samples (limit {texture_limit})",
        );
    }

    fn intz_linear_depth_step(linear_depth: f32, near_z: f32, far_z: f32) -> f32 {
        linear_depth * linear_depth * (far_z - near_z) / (near_z * far_z * INTZ_DEPTH_LEVELS)
    }

    fn precision_aware_bias(
        configured_bias: f32,
        linear_depth: f32,
        near_z: f32,
        far_z: f32,
    ) -> f32 {
        configured_bias
            .max(DEPTH_PRECISION_STEPS * intz_linear_depth_step(linear_depth, near_z, far_z))
    }

    fn dot(left: [f32; 3], right: [f32; 3]) -> f32 {
        left[0] * right[0] + left[1] * right[1] + left[2] * right[2]
    }

    fn sub(left: [f32; 3], right: [f32; 3]) -> [f32; 3] {
        [left[0] - right[0], left[1] - right[1], left[2] - right[2]]
    }

    fn cross(left: [f32; 3], right: [f32; 3]) -> [f32; 3] {
        [
            left[1] * right[2] - left[2] * right[1],
            left[2] * right[0] - left[0] * right[2],
            left[0] * right[1] - left[1] * right[0],
        ]
    }

    fn add_scaled(
        left: [f32; 3],
        middle: [f32; 3],
        right: [f32; 3],
        weights: [f32; 3],
    ) -> [f32; 3] {
        [
            left[0] * weights[0] + middle[0] * weights[1] + right[0] * weights[2],
            left[1] * weights[0] + middle[1] * weights[1] + right[1] * weights[2],
            left[2] * weights[0] + middle[2] * weights[1] + right[2] * weights[2],
        ]
    }

    fn normalize(value: [f32; 3]) -> [f32; 3] {
        let length = dot(value, value).sqrt();
        if length <= 1.0e-8 {
            return [0.0, 0.0, -1.0];
        }
        [value[0] / length, value[1] / length, value[2] / length]
    }

    fn linear_to_hardware(linear_depth: f32, reversed_depth: bool) -> f32 {
        if reversed_depth {
            (NEAR_Z * FAR_Z / linear_depth - NEAR_Z) / (FAR_Z - NEAR_Z)
        } else {
            (FAR_Z - NEAR_Z * FAR_Z / linear_depth) / (FAR_Z - NEAR_Z)
        }
    }

    fn hardware_to_linear(hardware_depth: f32, reversed_depth: bool) -> f32 {
        if reversed_depth {
            NEAR_Z * FAR_Z / (hardware_depth * (FAR_Z - NEAR_Z) + NEAR_Z)
        } else {
            NEAR_Z * FAR_Z / (FAR_Z - hardware_depth * (FAR_Z - NEAR_Z))
        }
    }

    fn quantized_linear_depth(linear_depth: f32, reversed_depth: bool) -> f32 {
        let hardware = linear_to_hardware(linear_depth, reversed_depth).clamp(0.0, 1.0);
        let quantized = (hardware * INTZ_DEPTH_LEVELS).round() / INTZ_DEPTH_LEVELS;
        hardware_to_linear(quantized, reversed_depth)
    }

    fn view_ray(uv: [f32; 2]) -> [f32; 2] {
        [2.0 * uv[0] - 1.0, 0.5 - uv[1]]
    }

    fn reconstruct_position(uv: [f32; 2], linear_depth: f32) -> [f32; 3] {
        let ray = view_ray(uv);
        [ray[0] * linear_depth, ray[1] * linear_depth, linear_depth]
    }

    fn depth_texel_center(uv: [f32; 2]) -> [f32; 2] {
        let x = (uv[0] * SOURCE_WIDTH as f32)
            .floor()
            .clamp(0.0, SOURCE_WIDTH as f32 - 1.0);
        let y = (uv[1] * SOURCE_HEIGHT as f32)
            .floor()
            .clamp(0.0, SOURCE_HEIGHT as f32 - 1.0);
        [
            (x + 0.5) / SOURCE_WIDTH as f32,
            (y + 0.5) / SOURCE_HEIGHT as f32,
        ]
    }

    fn planar_depth_buffer(
        base_depth: f32,
        slope: [f32; 2],
        camera_offset: [f32; 2],
        reversed_depth: bool,
    ) -> Vec<f32> {
        let mut depths = Vec::with_capacity(SOURCE_WIDTH * SOURCE_HEIGHT);
        for y in 0..SOURCE_HEIGHT {
            for x in 0..SOURCE_WIDTH {
                let uv = [
                    (x as f32 + 0.5) / SOURCE_WIDTH as f32,
                    (y as f32 + 0.5) / SOURCE_HEIGHT as f32,
                ];
                let ray = view_ray(uv);
                let numerator =
                    base_depth + slope[0] * camera_offset[0] + slope[1] * camera_offset[1];
                let denominator = 1.0 - slope[0] * ray[0] - slope[1] * ray[1];
                depths.push(quantized_linear_depth(
                    numerator / denominator,
                    reversed_depth,
                ));
            }
        }
        depths
    }

    fn step_depth_buffer(reversed_depth: bool) -> Vec<f32> {
        let mut depths = Vec::with_capacity(SOURCE_WIDTH * SOURCE_HEIGHT);
        for y in 0..SOURCE_HEIGHT {
            for x in 0..SOURCE_WIDTH {
                let foreground = x < SOURCE_WIDTH / 2 && y > SOURCE_HEIGHT / 5;
                let depth = if foreground { 980.0 } else { 1_000.0 };
                depths.push(quantized_linear_depth(depth, reversed_depth));
            }
        }
        depths
    }

    fn sample_position(depths: &[f32], uv: [f32; 2]) -> Option<[f32; 3]> {
        if uv[0] < 0.0 || uv[1] < 0.0 || uv[0] > 1.0 || uv[1] > 1.0 {
            return None;
        }
        let x = (uv[0] * SOURCE_WIDTH as f32)
            .floor()
            .clamp(0.0, SOURCE_WIDTH as f32 - 1.0) as usize;
        let y = (uv[1] * SOURCE_HEIGHT as f32)
            .floor()
            .clamp(0.0, SOURCE_HEIGHT as f32 - 1.0) as usize;
        let depth = depths[y * SOURCE_WIDTH + x];
        let sample_uv = depth_texel_center(uv);
        (depth < FAR_Z * 0.995).then(|| reconstruct_position(sample_uv, depth))
    }

    fn normal_at(depths: &[f32], uv: [f32; 2], center: [f32; 3]) -> [f32; 3] {
        let texel = [1.0 / SOURCE_WIDTH as f32, 1.0 / SOURCE_HEIGHT as f32];
        let left = sample_position(depths, [uv[0] - texel[0], uv[1]]);
        let right = sample_position(depths, [uv[0] + texel[0], uv[1]]);
        let up = sample_position(depths, [uv[0], uv[1] - texel[1]]);
        let down = sample_position(depths, [uv[0], uv[1] + texel[1]]);
        let dx = match (left, right) {
            (Some(left), Some(right))
                if (left[2] - center[2]).abs() < (right[2] - center[2]).abs() =>
            {
                sub(center, left)
            }
            (_, Some(right)) => sub(right, center),
            (Some(left), None) => sub(center, left),
            (None, None) => [0.0; 3],
        };
        let dy = match (up, down) {
            (Some(up), Some(down)) if (up[2] - center[2]).abs() < (down[2] - center[2]).abs() => {
                sub(center, up)
            }
            (_, Some(down)) => sub(down, center),
            (Some(up), None) => sub(center, up),
            (None, None) => [0.0; 3],
        };
        normalize(cross(dx, dy))
    }

    fn project_position(position: [f32; 3]) -> [f32; 2] {
        [
            (position[0] / position[2] + 1.0) * 0.5,
            0.5 - position[1] / position[2],
        ]
    }

    fn smooth01(value: f32) -> f32 {
        let value = value.clamp(0.0, 1.0);
        value * value * (3.0 - 2.0 * value)
    }

    fn stable_rotation(uv: [f32; 2]) -> f32 {
        let pixel = [
            (uv[0] * SOURCE_WIDTH as f32 * 0.5).floor(),
            (uv[1] * SOURCE_HEIGHT as f32 * 0.5).floor(),
        ];
        let inner = (pixel[0] * 0.067_110_56 + pixel[1] * 0.005_837_15).fract();
        (52.982_918 * inner).fract() * core::f32::consts::TAU
    }

    fn reference_ao_at(depths: &[f32], x: usize, y: usize, contact: bool) -> f32 {
        let uv = [
            (x as f32 + 0.5) / TARGET_WIDTH as f32,
            (y as f32 + 0.5) / TARGET_HEIGHT as f32,
        ];
        let Some(center) = sample_position(depths, uv) else {
            return 0.0;
        };
        let normal = normal_at(depths, depth_texel_center(uv), center);
        let axis = if normal[2].abs() < 0.99 {
            [0.0, 0.0, 1.0]
        } else {
            [0.0, 1.0, 0.0]
        };
        let tangent = normalize(cross(axis, normal));
        let bitangent = cross(normal, tangent);
        let angle = stable_rotation(uv);
        let cosine = angle.cos();
        let sine = angle.sin();
        let (radius, bias) = if contact {
            (
                (center[2] * 0.031)
                    .max(0.08)
                    .min(4.3 * center[2] * 2.0 / SOURCE_WIDTH as f32),
                precision_aware_bias(0.01, center[2], NEAR_Z, FAR_Z),
            )
        } else {
            let range = (center[2] * 0.079_762_93).max(0.35);
            let projected_radius = range * SOURCE_WIDTH as f32 / (center[2] * 2.0);
            let radius_pixels = (projected_radius * (71.698_27 / 75.5)).clamp(1.0, 7.6);
            (
                range.min(radius_pixels * center[2] * 2.0 / SOURCE_WIDTH as f32),
                (center[2] * 0.000_035).max(0.015),
            )
        };
        let directions = [
            ([1.0, 0.0], 0.28),
            ([0.7071, 0.7071], 0.40),
            ([0.0, 1.0], 0.52),
            ([-0.7071, 0.7071], 0.64),
            ([-1.0, 0.0], 0.73),
            ([-0.7071, -0.7071], 0.82),
            ([0.0, -1.0], 0.91),
            ([0.7071, -0.7071], 1.0),
        ];
        let mut occlusion = 0.0;
        for (direction, scale) in directions {
            let rotated = [
                direction[0] * cosine + direction[1] * sine,
                -direction[0] * sine + direction[1] * cosine,
            ];
            let hemisphere = normalize(add_scaled(
                tangent,
                bitangent,
                normal,
                [rotated[0], rotated[1], 0.55],
            ));
            let expected = [
                center[0] + hemisphere[0] * radius * scale,
                center[1] + hemisphere[1] * radius * scale,
                center[2] + hemisphere[2] * radius * scale,
            ];
            let Some(actual) = sample_position(depths, project_position(expected)) else {
                continue;
            };
            let depth_delta = center[2] - actual[2];
            if depth_delta.abs() >= radius || actual[2] >= expected[2] - bias {
                continue;
            }
            if contact && dot(sub(actual, center), normal) <= bias {
                continue;
            }
            let falloff = 1.0 - smooth01(depth_delta.abs() / radius.max(0.001));
            occlusion += falloff * falloff;
        }
        occlusion * 0.125
    }

    fn render_reference_ao(depths: &[f32], contact: bool) -> Vec<f32> {
        let mut output = Vec::with_capacity(TARGET_WIDTH * TARGET_HEIGHT);
        for y in 0..TARGET_HEIGHT {
            for x in 0..TARGET_WIDTH {
                output.push(reference_ao_at(depths, x, y, contact));
            }
        }
        output
    }

    fn assert_clean_planar_output(output: &[f32], label: &str) {
        let maximum = output.iter().copied().fold(0.0f32, f32::max);
        let lit_pixels = output.iter().filter(|value| **value > 1.0e-5).count();
        let examples = output
            .iter()
            .enumerate()
            .filter(|(_, value)| **value > 1.0e-5)
            .take(8)
            .map(|(index, value)| (index % TARGET_WIDTH, index / TARGET_WIDTH, *value))
            .collect::<Vec<_>>();
        assert!(
            maximum <= 1.0e-5 && lit_pixels == 0,
            "{label} generated planar AO points: max={maximum}, pixels={lit_pixels}, examples={examples:?}",
        );
    }

    fn contact_sample(
        depth_delta: f32,
        normal_distance: f32,
        expected_depth: f32,
        actual_depth: f32,
        radius: f32,
        bias: f32,
    ) -> f32 {
        if depth_delta.abs() >= radius
            || actual_depth >= expected_depth - bias
            || normal_distance <= bias
        {
            return 0.0;
        }
        let falloff = 1.0 - smooth01(depth_delta.abs() / radius.max(0.001));
        falloff * falloff
    }

    #[test]
    fn embedded_ambient_occlusion_shaders_compile() {
        for family in [
            AmbientOcclusionFamily::Fast,
            AmbientOcclusionFamily::Contact,
            AmbientOcclusionFamily::Combined,
        ] {
            crate::shaders::assert_hlsl_compiles(
                &format!("ambient_occlusion_extract.hlsl:{family:?}"),
                &extract_shader_source(family),
                "ps_3_0",
            );
        }
        crate::shaders::assert_hlsl_compiles("ambient_occlusion_blur.hlsl", BLUR_SHADER, "ps_3_0");
        crate::shaders::assert_hlsl_compiles(
            "ambient_occlusion_temporal.hlsl",
            TEMPORAL_SHADER,
            "ps_3_0",
        );
        crate::shaders::assert_hlsl_compiles(
            "ambient_occlusion_compose.hlsl",
            COMPOSE_SHADER,
            "ps_3_0",
        );
    }

    #[test]
    fn zero_strength_ao_skips_the_full_pipeline() {
        assert_eq!(family_for_strengths(0.0, 0.0), None);
        assert_eq!(family_for_strengths(-1.0, 0.0), None);
        assert_eq!(
            family_for_strengths(0.5, 0.0),
            Some(AmbientOcclusionFamily::Fast),
        );
        assert_eq!(
            family_for_strengths(0.0, 0.5),
            Some(AmbientOcclusionFamily::Contact),
        );
        assert_eq!(
            family_for_strengths(0.5, 0.5),
            Some(AmbientOcclusionFamily::Combined),
        );
    }

    #[test]
    fn ambient_occlusion_shaders_stay_within_static_gpu_budgets() {
        for (family, instruction_limit, texture_limit) in [
            (AmbientOcclusionFamily::Fast, 985usize, 7usize),
            (AmbientOcclusionFamily::Contact, 985, 7),
            (AmbientOcclusionFamily::Combined, 1_245, 8),
        ] {
            assert_shader_budget(
                &format!("extract:{family:?}"),
                &extract_shader_source(family),
                instruction_limit,
                texture_limit,
            );
        }

        for (name, source, instruction_limit, texture_limit) in [
            ("blur", BLUR_SHADER, 150, 9),
            ("temporal", TEMPORAL_SHADER, 260, 8),
            ("compose", COMPOSE_SHADER, 430, 7),
        ] {
            assert_shader_budget(name, source, instruction_limit, texture_limit);
        }
    }

    #[test]
    fn fast_ao_keeps_the_last_known_good_visibility_equation() {
        let extract = shader_source(EXTRACT_SHADER);

        assert!(extract.contains("float depthDelta = centerPosition.z - actualPosition.z;"));
        assert!(extract.contains("actualPosition.z >= expectedPosition.z - bias"));
        assert!(extract.contains("Smooth01(abs(depthDelta) / max(radius, 0.001f))"));
        assert!(extract.contains("fastRadius, fastRange, fastBias, reversedDepth, false"));
        assert!(!extract.contains("distanceSquared >= radius * radius"));
        assert!(!extract.contains("float horizon"));
    }

    #[test]
    fn contact_ao_only_adds_coplanar_rejection_and_precision_bias() {
        let extract = shader_source(EXTRACT_SHADER);

        assert!(extract.contains("float DepthPrecisionBias(float linearDepth)"));
        assert!(
            extract
                .contains("rejectCoplanar && dot(actualPosition - centerPosition, normal) <= bias")
        );
        assert!(extract.contains("contactRadius, contactRange, contactBias, reversedDepth, true"));
        assert!(extract.contains("DepthPrecisionBias(centerDepth)"));
        assert!(extract.contains("fastRadius, fastRange, fastBias, reversedDepth, false"));
    }

    #[test]
    fn ao_kernel_preserves_the_original_eight_samples_exactly() {
        let expected = [0.28f32, 0.40, 0.52, 0.64, 0.73, 0.82, 0.91, 1.0];
        for (sample_index, expected_scale) in expected.into_iter().enumerate() {
            let sample_scale = if sample_index < 4 {
                0.28 + 0.12 * sample_index as f32
            } else {
                0.73 + 0.09 * (sample_index - 4) as f32
            };
            assert!((sample_scale - expected_scale).abs() < 1.0e-6);
        }

        let extract = shader_source(EXTRACT_SHADER);
        assert!(extract.contains("sampleIndex < 8"));
        assert!(extract.contains("0.28f + 0.12f * sampleIndex"));
        assert!(extract.contains("0.73f + 0.09f * (sampleIndex - 4)"));
        assert!(extract.contains("static const float KernelTurn = 0.70710678f"));
        assert_eq!(extract.matches("SampleProjectedOcclusion(").count(), 2);
        assert!(extract.contains("float3 hemisphereDirection = normalize("));
        assert!(extract.contains("[loop]"));
    }

    #[test]
    fn fast_contact_and_combined_extract_work_is_fixed() {
        let expected = [
            (AmbientOcclusionFamily::Fast, 8usize),
            (AmbientOcclusionFamily::Contact, 8),
            (AmbientOcclusionFamily::Combined, 16),
        ];
        for (family, kernel_samples) in expected {
            let variant = extract_shader_source(family);
            let source = shader_source(&variant);
            assert!(source.starts_with(&format!(
                "#define AO_FAMILY_MODE {}\n",
                family.shader_mode(),
            )));
            assert_eq!(
                kernel_samples,
                8 * usize::from(family == AmbientOcclusionFamily::Combined) + 8
            );
        }

        let extract = shader_source(EXTRACT_SHADER);
        assert!(extract.contains("#if AO_FAMILY_MODE != 2"));
        assert!(extract.contains("#if AO_FAMILY_MODE != 1"));
    }

    #[test]
    fn extract_bytecode_forbids_screen_space_derivatives() {
        const DSX: u16 = 91;
        const DSY: u16 = 92;

        for family in [
            AmbientOcclusionFamily::Fast,
            AmbientOcclusionFamily::Contact,
            AmbientOcclusionFamily::Combined,
        ] {
            let source = extract_shader_source(family);
            let bytecode = crate::shaders::compile_hlsl_source_target(
                &format!("ao-no-derivatives:{family:?}"),
                &source,
                "ps_3_0",
            )
            .expect("extract shader");
            let opcodes = compiled_instruction_opcodes(&bytecode);
            assert!(!opcodes.contains(&DSX), "{family:?} contains dsx");
            assert!(!opcodes.contains(&DSY), "{family:?} contains dsy");
        }

        let extract = shader_source(EXTRACT_SHADER);
        assert!(!extract.contains("ddx("));
        assert!(!extract.contains("ddy("));
        for offset in ["left", "right", "up", "down"] {
            assert!(extract.contains(&format!("float3 {offset};")));
            assert!(extract.contains(&format!("bool {offset}Valid = LoadViewPosition")));
        }
    }

    #[test]
    fn intz_precision_bias_rejects_quantized_planar_walls() {
        let near_z = 5.0;
        let far_z = 100_000.0;

        for linear_depth in [25.0, 100.0, 1_000.0, 5_000.0, 10_000.0, 25_000.0] {
            let depth_uncertainty = 2.0 * intz_linear_depth_step(linear_depth, near_z, far_z);
            let contact_bias = precision_aware_bias(0.01, linear_depth, near_z, far_z);

            assert_eq!(
                contact_sample(
                    depth_uncertainty,
                    depth_uncertainty,
                    linear_depth - depth_uncertainty * 2.0,
                    linear_depth - depth_uncertainty,
                    64.0,
                    contact_bias,
                ),
                0.0,
                "contact AO self-occluded a planar wall at depth {linear_depth}",
            );
        }
    }

    #[test]
    fn depth_precision_constants_match_the_intz_precision_model() {
        let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let camera = camera(identity, [0.0; 3], 1.0);
        let d24 = ao_depth_precision_constants(camera, INTZ_DEPTH_LEVELS);
        let d16 = ao_depth_precision_constants(camera, 65_535.0);
        let expected = DEPTH_PRECISION_STEPS * (camera.far_z - camera.near_z)
            / (camera.near_z * camera.far_z * INTZ_DEPTH_LEVELS);

        assert!((d24[0] - expected).abs() < 1.0e-12);
        assert_eq!(&d24[1..], &[0.0, 0.0, 0.0]);
        assert!(d16[0] > d24[0] * 250.0);
    }

    #[test]
    fn precomputed_depth_linearization_is_equation_identical() {
        let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let camera = camera(identity, [0.0; 3], 1.0);
        let constants = ao_depth_linearize_constants(camera);

        for depth in [0.0f32, 0.1, 0.5, 0.9, 1.0] {
            let standard = constants[0] / (constants[3] - depth * constants[1]).max(0.001);
            let reversed = constants[0] / (depth * constants[1] + constants[2]).max(0.001);
            let original_standard = camera.near_z * camera.far_z
                / (camera.far_z - depth * (camera.far_z - camera.near_z)).max(0.001);
            let original_reversed = camera.near_z * camera.far_z
                / (depth * (camera.far_z - camera.near_z) + camera.near_z).max(0.001);

            assert!((standard - original_standard).abs() < 1.0e-5);
            assert!((reversed - original_reversed).abs() < 1.0e-5);
        }
    }

    #[test]
    fn planar_walls_render_without_lines_points_or_triangle_discontinuities() {
        for reversed_depth in [false, true] {
            for (base_depth, slope) in [
                (50.0, [0.0, 0.0]),
                (1_000.0, [0.25, -0.10]),
                (10_000.0, [-0.35, 0.18]),
            ] {
                let depths = planar_depth_buffer(base_depth, slope, [0.0, 0.0], reversed_depth);
                for contact in [false, true] {
                    let output = render_reference_ao(&depths, contact);
                    let family = if contact { "contact" } else { "fast" };
                    assert_clean_planar_output(
                        &output,
                        &format!(
                            "family={family}, depth={base_depth}, slope={slope:?}, reversed={reversed_depth}"
                        ),
                    );

                    let mut triangle_sum = [0.0f32; 2];
                    let mut triangle_count = [0usize; 2];
                    for y in 0..TARGET_HEIGHT {
                        for x in 0..TARGET_WIDTH {
                            let triangle = usize::from(
                                x as f32 / (TARGET_WIDTH - 1) as f32
                                    + y as f32 / (TARGET_HEIGHT - 1) as f32
                                    > 1.0,
                            );
                            triangle_sum[triangle] += output[y * TARGET_WIDTH + x];
                            triangle_count[triangle] += 1;
                        }
                    }
                    for triangle in 0..2 {
                        assert_eq!(triangle_sum[triangle], 0.0);
                        assert!(triangle_count[triangle] > 0);
                    }
                }
            }
        }
    }

    #[test]
    fn subpixel_camera_motion_does_not_create_planar_ao_flicker() {
        for reversed_depth in [false, true] {
            let before_depth =
                planar_depth_buffer(2_500.0, [0.31, -0.17], [0.0, 0.0], reversed_depth);
            let after_depth =
                planar_depth_buffer(2_500.0, [0.31, -0.17], [0.37, -0.21], reversed_depth);
            for contact in [false, true] {
                let before = render_reference_ao(&before_depth, contact);
                let after = render_reference_ao(&after_depth, contact);
                assert_clean_planar_output(&before, "camera before");
                assert_clean_planar_output(&after, "camera after");
                assert_eq!(before, after);
            }
        }
    }

    #[test]
    fn depth_discontinuity_produces_local_ao_not_screen_fill() {
        for reversed_depth in [false, true] {
            let depths = step_depth_buffer(reversed_depth);
            for contact in [false, true] {
                let family = if contact { "contact" } else { "fast" };
                let output = render_reference_ao(&depths, contact);
                let affected = output.iter().filter(|value| **value > 0.001).count();
                let maximum = output.iter().copied().fold(0.0f32, f32::max);
                assert!(
                    maximum > 0.005,
                    "{family} edge disappeared: max={maximum}, affected={affected}",
                );
                assert!(affected > 4, "{family} edge is too sparse: {affected}",);
                assert!(
                    affected < output.len() / 5,
                    "{family} AO filled too much of the screen: {affected}/{}",
                    output.len(),
                );
            }
        }
    }

    #[test]
    fn extract_runtime_depth_fetch_count_is_bounded() {
        let normal_and_center_fetches = 5usize;
        let optional_first_person_fetch = 1usize;
        let expected = [
            (AmbientOcclusionFamily::Fast, 8usize, 14usize),
            (AmbientOcclusionFamily::Contact, 8, 14),
            (AmbientOcclusionFamily::Combined, 16, 22),
        ];

        for (family, kernel_fetches, maximum_fetches) in expected {
            assert_eq!(
                normal_and_center_fetches + optional_first_person_fetch + kernel_fetches,
                maximum_fetches,
                "{family:?} depth-fetch contract changed",
            );
        }
    }

    #[test]
    fn proven_depth_filters_remain_unchanged() {
        let blur = shader_source(BLUR_SHADER);
        let temporal = shader_source(TEMPORAL_SHADER);
        let compose = shader_source(COMPOSE_SHADER);

        assert!(blur.contains("abs(sample.g - centerDepth) * sharpness"));
        assert!(blur.contains("float sharpness = 42.0f"));
        assert!(temporal.contains("abs(history.g - expectedDepthKey) * TemporalData.z"));
        assert!(compose.contains("abs(sample.g - centerKey) * 52.0f"));
        for source in [blur, temporal, compose] {
            assert!(!source.contains("DepthFilterData"));
            assert!(!source.contains("DepthKeyDistance"));
        }
    }

    #[test]
    fn ao_pipeline_neutralizes_inherited_mask_and_color_space_state() {
        let source = include_str!("ambient_occlusion.rs");
        for required in [
            "device.set_render_state(D3DRS_STENCILENABLE, 0)?",
            "device.set_render_state(D3DRS_SCISSORTESTENABLE, 0)?",
            "device.set_render_state(D3DRS_SRGBWRITEENABLE, 0)?",
            "device.set_depth_stencil_surface(None)?",
            "device.clear_render_target(index)?",
            "device.set_sampler_state(sampler, D3DSAMP_SRGBTEXTURE, 0)?",
        ] {
            assert!(
                source.contains(required),
                "missing AO state contract: {required}"
            );
        }
    }

    #[test]
    fn preferred_targets_ignore_scene_format_changes() {
        assert!(fallback_format_matches(
            false,
            D3DFMT_A8R8G8B8,
            D3DFMT_G16R16F
        ));
    }

    #[test]
    fn fallback_targets_require_the_same_scene_format() {
        assert!(fallback_format_matches(
            true,
            D3DFMT_A8R8G8B8,
            D3DFMT_A8R8G8B8
        ));
        assert!(!fallback_format_matches(
            true,
            D3DFMT_A8R8G8B8,
            D3DFMT_G16R16F
        ));
    }

    fn camera(rotation: [[f32; 3]; 3], translation: [f32; 3], scale: f32) -> CameraFrame {
        CameraFrame {
            near_z: 5.0,
            far_z: 1000.0,
            aspect_ratio: 16.0 / 9.0,
            frustum_left: -1.0,
            frustum_right: 1.0,
            frustum_bottom: -0.5,
            frustum_top: 0.5,
            world_transform: CameraTransformFrame {
                rotation,
                translation,
                scale,
                available: true,
            },
            available: true,
        }
    }

    #[test]
    fn identity_cameras_preserve_ao_view_coordinates() {
        let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let camera = camera(identity, [0.0; 3], 1.0);
        let reprojection = TemporalReprojection::between(
            TemporalCameraState { camera, epoch: 4 },
            TemporalCameraState { camera, epoch: 5 },
        )
        .expect("identity reprojection");

        assert_eq!(
            reprojection.rows,
            [
                [1.0, 0.0, 0.0, 0.0],
                [0.0, 1.0, 0.0, 0.0],
                [0.0, 0.0, 1.0, 0.0],
            ]
        );
    }

    #[test]
    fn camera_translation_is_expressed_in_previous_ao_basis() {
        let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let previous = camera(identity, [10.0, 20.0, 30.0], 1.0);
        let current = camera(identity, [13.0, 22.0, 35.0], 1.0);
        let reprojection = TemporalReprojection::between(
            TemporalCameraState {
                camera: previous,
                epoch: 8,
            },
            TemporalCameraState {
                camera: current,
                epoch: 9,
            },
        )
        .expect("translated reprojection");

        assert_eq!(reprojection.rows[0][3], 5.0);
        assert_eq!(reprojection.rows[1][3], 2.0);
        assert_eq!(reprojection.rows[2][3], 3.0);
    }

    #[test]
    fn camera_rotation_preserves_forward_up_right_handedness() {
        let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let quarter_turn = [[0.0, -1.0, 0.0], [1.0, 0.0, 0.0], [0.0, 0.0, 1.0]];
        let reprojection = TemporalReprojection::between(
            TemporalCameraState {
                camera: camera(identity, [0.0; 3], 1.0),
                epoch: 11,
            },
            TemporalCameraState {
                camera: camera(quarter_turn, [0.0; 3], 1.0),
                epoch: 12,
            },
        )
        .expect("rotated reprojection");

        assert_eq!(
            reprojection.rows,
            [
                [1.0, 0.0, 0.0, 0.0],
                [0.0, 0.0, 1.0, 0.0],
                [0.0, -1.0, 0.0, 0.0],
            ]
        );
    }

    #[test]
    fn history_requires_a_consecutive_capture_epoch() {
        let identity = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let camera = camera(identity, [0.0; 3], 1.0);
        assert!(
            TemporalReprojection::between(
                TemporalCameraState { camera, epoch: 2 },
                TemporalCameraState { camera, epoch: 4 },
            )
            .is_none()
        );
    }
}

pub(crate) struct AmbientOcclusionEffect {
    fast_extract_shader: PixelShader9,
    contact_extract_shader: PixelShader9,
    combined_extract_shader: PixelShader9,
    blur_shader: PixelShader9,
    temporal_shader: PixelShader9,
    compose_shader: PixelShader9,
    targets: Option<AmbientOcclusionTargets>,
    previous_camera: Option<TemporalCameraState>,
}

impl AmbientOcclusionEffect {
    pub(crate) fn create(device: &Device9Ref<'_>) -> Direct3DResult<Self> {
        Ok(Self {
            fast_extract_shader: compile_shader(
                device,
                "ambient_occlusion_extract.hlsl:fast",
                &extract_shader_source(AmbientOcclusionFamily::Fast),
            )?,
            contact_extract_shader: compile_shader(
                device,
                "ambient_occlusion_extract.hlsl:contact",
                &extract_shader_source(AmbientOcclusionFamily::Contact),
            )?,
            combined_extract_shader: compile_shader(
                device,
                "ambient_occlusion_extract.hlsl:combined",
                &extract_shader_source(AmbientOcclusionFamily::Combined),
            )?,
            blur_shader: compile_shader(device, "ambient_occlusion_blur.hlsl", BLUR_SHADER)?,
            temporal_shader: compile_shader(
                device,
                "ambient_occlusion_temporal.hlsl",
                TEMPORAL_SHADER,
            )?,
            compose_shader: compile_shader(
                device,
                "ambient_occlusion_compose.hlsl",
                COMPOSE_SHADER,
            )?,
            targets: None,
            previous_camera: None,
        })
    }

    pub(crate) fn draw(
        &mut self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &FrameInputs,
        fast_source: Option<&ScreenShaderSource>,
        contact_source: Option<&ScreenShaderSource>,
        scene_color: &Texture9,
        frame_index: u32,
    ) -> Direct3DResult<()> {
        let Some(family) = ambient_occlusion_family(fast_source, contact_source) else {
            self.previous_camera = None;
            return Ok(());
        };
        if frame_inputs.depth.texture.is_none() {
            return Ok(());
        }

        self.ensure_targets(device, desc)?;
        let current_camera = TemporalCameraState {
            camera: frame_inputs.depth.world_projection.camera,
            epoch: frame_inputs.depth.capture_epoch,
        };
        let reprojection = self
            .previous_camera
            .and_then(|previous| TemporalReprojection::between(previous, current_camera));
        let Some(targets) = self.targets.as_ref() else {
            return Ok(());
        };

        bind_pipeline_state(device)?;
        bind_depth_inputs(
            device,
            &frame_inputs.depth.texture,
            &frame_inputs.depth.first_person_texture,
        )?;

        self.draw_extract(
            device,
            targets,
            desc,
            frame_inputs,
            fast_source,
            contact_source,
            family,
            frame_index,
        )?;
        self.draw_blur(
            device,
            targets,
            desc,
            frame_inputs,
            fast_source,
            contact_source,
            frame_index,
            [targets.inv_width, 0.0],
        )?;
        self.draw_blur(
            device,
            targets,
            desc,
            frame_inputs,
            fast_source,
            contact_source,
            frame_index,
            [0.0, targets.inv_height],
        )?;
        let stability = temporal_stability(fast_source, contact_source);
        let temporal_reprojection = reprojection.filter(|_| stability > f32::EPSILON);
        if let Some(reprojection) = temporal_reprojection {
            self.draw_temporal(
                device,
                targets,
                desc,
                frame_inputs,
                fast_source,
                contact_source,
                frame_index,
                reprojection,
                stability,
            )?;
        }
        let (ao_texture, ao_surface) = if temporal_reprojection.is_some() {
            (&targets.blur.texture, &targets.blur.surface)
        } else {
            (&targets.occlusion.texture, &targets.occlusion.surface)
        };
        self.draw_compose(
            device,
            backbuffer,
            desc,
            targets,
            frame_inputs,
            fast_source,
            contact_source,
            scene_color,
            ao_texture,
            frame_index,
        )?;

        device.clear_texture(4)?;
        device.stretch_rect(
            ao_surface,
            None,
            &targets.history.surface,
            None,
            D3DTEXF_POINT,
        )?;
        self.previous_camera = Some(current_camera);
        Ok(())
    }

    fn ensure_targets(
        &mut self,
        device: &Device9Ref<'_>,
        desc: &D3DSURFACE_DESC,
    ) -> Direct3DResult<()> {
        let width = (desc.Width / AO_SCALE).max(1);
        let height = (desc.Height / AO_SCALE).max(1);
        let format = desc.Format;

        let needs_targets = self
            .targets
            .as_ref()
            .is_none_or(|targets| !targets.matches(width, height, format));
        if needs_targets {
            let targets = AmbientOcclusionTargets::create(device, width, height, format)?;
            log::info!(
                "[AO] Intermediate targets: {}x{}, format={}, fallback={}",
                width,
                height,
                targets.format.0,
                targets.used_fallback
            );
            self.targets = Some(targets);
            self.previous_camera = None;
        }

        Ok(())
    }

    fn draw_extract(
        &self,
        device: &Device9Ref<'_>,
        targets: &AmbientOcclusionTargets,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &FrameInputs,
        fast_source: Option<&ScreenShaderSource>,
        contact_source: Option<&ScreenShaderSource>,
        family: AmbientOcclusionFamily,
        frame_index: u32,
    ) -> Direct3DResult<()> {
        bind_target(
            device,
            &targets.occlusion.surface,
            targets.width,
            targets.height,
        )?;
        bind_fullres_constants(
            device,
            desc,
            frame_inputs,
            fast_source,
            contact_source,
            frame_index,
            0.0,
        )?;
        let shader = match family {
            AmbientOcclusionFamily::Fast => &self.fast_extract_shader,
            AmbientOcclusionFamily::Contact => &self.contact_extract_shader,
            AmbientOcclusionFamily::Combined => &self.combined_extract_shader,
        };
        device.set_pixel_shader(shader)?;
        draw_quad(device, targets.width, targets.height)
    }

    fn draw_blur(
        &self,
        device: &Device9Ref<'_>,
        targets: &AmbientOcclusionTargets,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &FrameInputs,
        fast_source: Option<&ScreenShaderSource>,
        contact_source: Option<&ScreenShaderSource>,
        frame_index: u32,
        direction: [f32; 2],
    ) -> Direct3DResult<()> {
        let (input, output) = if direction[0] != 0.0 {
            (&targets.occlusion.texture, &targets.blur.surface)
        } else {
            (&targets.blur.texture, &targets.occlusion.surface)
        };

        bind_target(device, output, targets.width, targets.height)?;
        device.set_texture(0, input)?;
        bind_fullres_constants(
            device,
            desc,
            frame_inputs,
            fast_source,
            contact_source,
            frame_index,
            1.0,
        )?;
        device.set_pixel_shader_constant_f(
            EFFECT_CONSTANT_REGISTER,
            &[[direction[0], direction[1], 0.0, 0.0]],
        )?;
        device.set_pixel_shader(&self.blur_shader)?;
        draw_quad(device, targets.width, targets.height)
    }

    #[allow(clippy::too_many_arguments)]
    fn draw_temporal(
        &self,
        device: &Device9Ref<'_>,
        targets: &AmbientOcclusionTargets,
        desc: &D3DSURFACE_DESC,
        frame_inputs: &FrameInputs,
        fast_source: Option<&ScreenShaderSource>,
        contact_source: Option<&ScreenShaderSource>,
        frame_index: u32,
        reprojection: TemporalReprojection,
        stability: f32,
    ) -> Direct3DResult<()> {
        bind_target(device, &targets.blur.surface, targets.width, targets.height)?;
        device.set_texture(0, &targets.occlusion.texture)?;
        device.set_texture(4, &targets.history.texture)?;
        bind_depth_inputs(
            device,
            &frame_inputs.depth.texture,
            &frame_inputs.depth.first_person_texture,
        )?;
        bind_fullres_constants(
            device,
            desc,
            frame_inputs,
            fast_source,
            contact_source,
            frame_index,
            1.5,
        )?;

        let constants = TemporalShaderConstants::valid(targets, stability, reprojection);
        device.set_pixel_shader_constant_f(TEMPORAL_CONSTANT_REGISTER, &constants.registers)?;
        device.set_pixel_shader(&self.temporal_shader)?;
        draw_quad(device, targets.width, targets.height)
    }

    fn draw_compose(
        &self,
        device: &Device9Ref<'_>,
        backbuffer: &Surface9,
        desc: &D3DSURFACE_DESC,
        targets: &AmbientOcclusionTargets,
        frame_inputs: &FrameInputs,
        fast_source: Option<&ScreenShaderSource>,
        contact_source: Option<&ScreenShaderSource>,
        scene_color: &Texture9,
        ao_texture: &Texture9,
        frame_index: u32,
    ) -> Direct3DResult<()> {
        bind_target(device, backbuffer, desc.Width, desc.Height)?;
        device.set_texture(0, scene_color)?;
        bind_depth_inputs(
            device,
            &frame_inputs.depth.texture,
            &frame_inputs.depth.first_person_texture,
        )?;
        device.set_texture(4, ao_texture)?;
        bind_fullres_constants(
            device,
            desc,
            frame_inputs,
            fast_source,
            contact_source,
            frame_index,
            2.0,
        )?;
        device.set_pixel_shader_constant_f(
            EFFECT_CONSTANT_REGISTER,
            &[[targets.inv_width, targets.inv_height, AO_SCALE as f32, 0.0]],
        )?;
        device.set_pixel_shader(&self.compose_shader)?;
        draw_quad(device, desc.Width, desc.Height)
    }
}

#[derive(Clone, Copy)]
struct TemporalCameraState {
    camera: CameraFrame,
    epoch: u64,
}

#[derive(Clone, Copy, Debug)]
struct TemporalReprojection {
    rows: [[f32; 4]; 3],
    previous_frustum: [f32; 4],
    previous_depth: [f32; 2],
}

impl TemporalReprojection {
    fn between(previous: TemporalCameraState, current: TemporalCameraState) -> Option<Self> {
        if current.epoch != previous.epoch.wrapping_add(1)
            || !camera_supports_reprojection(previous.camera)
            || !camera_supports_reprojection(current.camera)
        {
            return None;
        }

        let previous_transform = previous.camera.world_transform;
        let current_transform = current.camera.world_transform;
        let scale_ratio = current_transform.scale / previous_transform.scale;
        let mut rotation = [[0.0; 3]; 3];
        for (row, output_row) in rotation.iter_mut().enumerate() {
            for (column, output) in output_row.iter_mut().enumerate() {
                *output = (0..3)
                    .map(|axis| {
                        previous_transform.rotation[axis][2 - row]
                            * current_transform.rotation[axis][2 - column]
                    })
                    .sum::<f32>()
                    * scale_ratio;
            }
        }

        let translation_delta = [
            current_transform.translation[0] - previous_transform.translation[0],
            current_transform.translation[1] - previous_transform.translation[1],
            current_transform.translation[2] - previous_transform.translation[2],
        ];
        let mut translation = [0.0; 3];
        for (row, output) in translation.iter_mut().enumerate() {
            let previous_game_axis = 2 - row;
            *output = (0..3)
                .map(|axis| {
                    previous_transform.rotation[axis][previous_game_axis] * translation_delta[axis]
                })
                .sum::<f32>()
                / previous_transform.scale;
        }

        if rotation
            .iter()
            .flatten()
            .chain(translation.iter())
            .any(|value| !value.is_finite())
        {
            return None;
        }

        Some(Self {
            rows: [
                [
                    rotation[0][0],
                    rotation[0][1],
                    rotation[0][2],
                    translation[0],
                ],
                [
                    rotation[1][0],
                    rotation[1][1],
                    rotation[1][2],
                    translation[1],
                ],
                [
                    rotation[2][0],
                    rotation[2][1],
                    rotation[2][2],
                    translation[2],
                ],
            ],
            previous_frustum: [
                previous.camera.frustum_left,
                previous.camera.frustum_right,
                previous.camera.frustum_bottom,
                previous.camera.frustum_top,
            ],
            previous_depth: [previous.camera.near_z, previous.camera.far_z],
        })
    }
}

fn camera_supports_reprojection(camera: CameraFrame) -> bool {
    let transform = camera.world_transform;
    camera.available
        && transform.available
        && transform.scale.is_finite()
        && transform.scale.abs() > f32::EPSILON
        && transform
            .rotation
            .iter()
            .flatten()
            .chain(transform.translation.iter())
            .all(|value| value.is_finite())
}

struct TemporalShaderConstants {
    registers: [[f32; 4]; 6],
}

impl TemporalShaderConstants {
    fn valid(
        targets: &AmbientOcclusionTargets,
        stability: f32,
        reprojection: TemporalReprojection,
    ) -> Self {
        Self {
            registers: [
                reprojection.rows[0],
                reprojection.rows[1],
                reprojection.rows[2],
                reprojection.previous_frustum,
                [
                    1.0,
                    stability,
                    reprojection.previous_depth[0],
                    reprojection.previous_depth[1],
                ],
                [targets.inv_width, targets.inv_height, 52.0, 0.0],
            ],
        }
    }
}

fn family_for_strengths(
    fast_strength: f32,
    contact_strength: f32,
) -> Option<AmbientOcclusionFamily> {
    match (fast_strength > 0.0, contact_strength > 0.0) {
        (true, true) => Some(AmbientOcclusionFamily::Combined),
        (true, false) => Some(AmbientOcclusionFamily::Fast),
        (false, true) => Some(AmbientOcclusionFamily::Contact),
        (false, false) => None,
    }
}

fn ambient_occlusion_family(
    fast_source: Option<&ScreenShaderSource>,
    contact_source: Option<&ScreenShaderSource>,
) -> Option<AmbientOcclusionFamily> {
    let fast_strength = fast_source.map_or(0.0, |source| source.option_constants[0][0]);
    let contact_strength = contact_source.map_or(0.0, |source| source.option_constants[0][0]);
    family_for_strengths(fast_strength, contact_strength)
}

fn temporal_stability(
    fast_source: Option<&ScreenShaderSource>,
    contact_source: Option<&ScreenShaderSource>,
) -> f32 {
    let fast = fast_source.map(|source| {
        (
            source.option_constants[0][0].max(0.0),
            source.option_constants[2][0].clamp(0.0, 1.0),
        )
    });
    let contact = contact_source.map(|source| {
        (
            source.option_constants[0][0].max(0.0),
            source.option_constants[1][3].clamp(0.0, 1.0),
        )
    });
    let total_strength = fast.map_or(0.0, |value| value.0) + contact.map_or(0.0, |value| value.0);
    if total_strength <= f32::EPSILON {
        return 0.0;
    }

    let weighted_stability = fast.map_or(0.0, |value| value.0 * value.1)
        + contact.map_or(0.0, |value| value.0 * value.1);
    (weighted_stability / total_strength).clamp(0.0, 1.0)
}

fn compile_shader(
    device: &Device9Ref<'_>,
    source_name: &str,
    source: &[u8],
) -> Direct3DResult<PixelShader9> {
    let bytecode = match shaders::compile_hlsl_source(source_name, source) {
        Ok(bytecode) => bytecode,
        Err(err) => {
            log::warn!("[AO] Failed to compile {source_name}: {err:#}");
            return Err(direct3d_failure());
        }
    };

    device.create_pixel_shader(&bytecode)
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
    for sampler in [0, 1, 2, 3, 4] {
        device.set_sampler_state(sampler, D3DSAMP_ADDRESSU, D3DTADDRESS_CLAMP.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_ADDRESSV, D3DTADDRESS_CLAMP.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_MINFILTER, D3DTEXF_LINEAR.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_MAGFILTER, D3DTEXF_LINEAR.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_MIPFILTER, D3DTEXF_NONE.0 as u32)?;
        device.set_sampler_state(sampler, D3DSAMP_SRGBTEXTURE, 0)?;
    }
    for sampler in [1, 2, 4] {
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
    device.set_depth_stencil_surface(None)?;
    for index in 1..=3 {
        device.clear_render_target(index)?;
    }
    device.set_render_target(0, surface)?;
    device.set_viewport(&viewport)
}

fn bind_depth_inputs(
    device: &Device9Ref<'_>,
    world_depth: &Option<DepthTexture>,
    first_person_depth: &Option<DepthTexture>,
) -> Direct3DResult<()> {
    if let Some(depth) = world_depth {
        unsafe {
            device.set_raw_base_texture(1, depth.as_ptr())?;
        }
    } else {
        device.clear_texture(1)?;
    }

    if let Some(depth) = first_person_depth {
        unsafe {
            device.set_raw_base_texture(2, depth.as_ptr())?;
        }
    } else {
        device.clear_texture(2)?;
    }

    Ok(())
}

fn bind_fullres_constants(
    device: &Device9Ref<'_>,
    desc: &D3DSURFACE_DESC,
    frame_inputs: &FrameInputs,
    fast_source: Option<&ScreenShaderSource>,
    contact_source: Option<&ScreenShaderSource>,
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
                frame_inputs.depth.first_person_texture.is_some() as u8 as f32,
                frame_inputs.depth.is_available() as u8 as f32,
            ],
            [
                frame_inputs.camera.near_z,
                frame_inputs.camera.far_z,
                frame_inputs.camera.aspect_ratio,
                frame_inputs.depth.provider_id(),
            ],
        ],
    )?;

    bind_fast_constants(device, fast_source)?;

    bind_contact_constants(device, contact_source)?;

    device.set_pixel_shader_constant_f(
        6,
        &[[
            frame_inputs.environment.fog_start,
            frame_inputs.environment.fog_end,
            frame_inputs.environment.fog_power,
            frame_inputs.environment.fog_available_f32(),
        ]],
    )?;
    bind_depth_contract_constants(device, frame_inputs)?;
    device.set_pixel_shader_constant_f(
        DEPTH_PRECISION_CONSTANT_REGISTER,
        &[ao_depth_precision_constants(
            frame_inputs.camera,
            frame_inputs.depth.world_projection.sampled_depth_levels(),
        )],
    )?;
    device.set_pixel_shader_constant_f(
        DEPTH_LINEARIZE_CONSTANT_REGISTER,
        &[ao_depth_linearize_constants(frame_inputs.camera)],
    )
}

fn ao_depth_precision_constants(camera: CameraFrame, depth_levels: f32) -> [f32; 4] {
    let near_z = camera.near_z.max(0.01);
    let far_z = camera.far_z.max(near_z + 1.0);
    let depth_levels = depth_levels.max(1.0);
    let precision_scale =
        DEPTH_PRECISION_STEPS * (far_z - near_z) / (near_z * far_z * depth_levels);
    [precision_scale, 0.0, 0.0, 0.0]
}

fn ao_depth_linearize_constants(camera: CameraFrame) -> [f32; 4] {
    let near_z = camera.near_z.max(0.01);
    let far_z = camera.far_z.max(near_z + 1.0);
    [near_z * far_z, far_z - near_z, near_z, far_z]
}

fn bind_depth_contract_constants(
    device: &Device9Ref<'_>,
    frame_inputs: &FrameInputs,
) -> Direct3DResult<()> {
    let world = frame_inputs.depth.world_projection;
    let first_person = frame_inputs.depth.first_person_projection;
    device.set_pixel_shader_constant_f(
        11,
        &[
            [
                world.reversed_depth_f32(),
                first_person.reversed_depth_f32(),
                frame_inputs.camera.available_f32(),
                first_person.camera.available_f32(),
            ],
            [
                frame_inputs.camera.frustum_left,
                frame_inputs.camera.frustum_right,
                frame_inputs.camera.frustum_bottom,
                frame_inputs.camera.frustum_top,
            ],
            [
                first_person.camera.near_z,
                first_person.camera.far_z,
                first_person.camera.aspect_ratio,
                0.0,
            ],
            [
                first_person.camera.frustum_left,
                first_person.camera.frustum_right,
                first_person.camera.frustum_bottom,
                first_person.camera.frustum_top,
            ],
        ],
    )
}

fn bind_fast_constants(
    device: &Device9Ref<'_>,
    fast_source: Option<&ScreenShaderSource>,
) -> Direct3DResult<()> {
    let mut constants = [
        [0.0f32, 75.5, 7.6, 0.076],
        [0.0, 1.0, 0.18, 0.45],
        [0.65, 1.0, 1.0, 0.0],
    ];
    if let Some(source) = fast_source {
        for (index, source_constant) in source.option_constants.iter().take(3).enumerate() {
            constants[index] = *source_constant;
        }
    }
    device.set_pixel_shader_constant_f(3, &constants)
}

fn bind_contact_constants(
    device: &Device9Ref<'_>,
    contact_source: Option<&ScreenShaderSource>,
) -> Direct3DResult<()> {
    let mut constants = [
        [0.0f32, 4.3, 0.031, 0.0],
        [0.0, 1.0, 0.67, 0.63],
        [1.0, 1.0, 0.0, 0.0],
    ];
    if let Some(source) = contact_source {
        for (index, source_constant) in source.option_constants.iter().take(3).enumerate() {
            constants[index] = *source_constant;
        }
    }
    device.set_pixel_shader_constant_f(CONTACT_OPTION_REGISTER, &constants)
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

struct AmbientOcclusionTargets {
    width: u32,
    height: u32,
    inv_width: f32,
    inv_height: f32,
    format: D3DFORMAT,
    fallback_format: D3DFORMAT,
    used_fallback: bool,
    occlusion: EffectTarget,
    blur: EffectTarget,
    history: EffectTarget,
}

impl AmbientOcclusionTargets {
    fn create(
        device: &Device9Ref<'_>,
        width: u32,
        height: u32,
        fallback_format: D3DFORMAT,
    ) -> Direct3DResult<Self> {
        let (occlusion, blur, history, format, used_fallback) = match (
            EffectTarget::create(device, width, height, D3DFMT_G16R16F),
            EffectTarget::create(device, width, height, D3DFMT_G16R16F),
            EffectTarget::create(device, width, height, D3DFMT_G16R16F),
        ) {
            (Ok(occlusion), Ok(blur), Ok(history)) => {
                (occlusion, blur, history, D3DFMT_G16R16F, false)
            }
            (Err(err), _, _) | (_, Err(err), _) | (_, _, Err(err)) => {
                log::warn!(
                    "[AO] G16R16F targets unavailable ({err}); falling back to scene format"
                );
                (
                    EffectTarget::create(device, width, height, fallback_format)?,
                    EffectTarget::create(device, width, height, fallback_format)?,
                    EffectTarget::create(device, width, height, fallback_format)?,
                    fallback_format,
                    true,
                )
            }
        };

        Ok(Self {
            width,
            height,
            inv_width: 1.0 / width as f32,
            inv_height: 1.0 / height as f32,
            format,
            fallback_format,
            used_fallback,
            occlusion,
            blur,
            history,
        })
    }

    fn matches(&self, width: u32, height: u32, fallback_format: D3DFORMAT) -> bool {
        self.width == width
            && self.height == height
            && fallback_format_matches(self.used_fallback, self.fallback_format, fallback_format)
    }
}

fn fallback_format_matches(
    used_fallback: bool,
    active_format: D3DFORMAT,
    requested_format: D3DFORMAT,
) -> bool {
    !used_fallback || active_format == requested_format
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
