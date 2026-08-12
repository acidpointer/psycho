use super::shaders::{
    BLUR_PIXEL_SOURCE, COMPOSITE_PIXEL_SOURCE, CUBE_PIXEL_SOURCE, CUBE_VERTEX_SOURCE,
    DIRECTIONAL_PIXEL_SOURCE, DIRECTIONAL_VERTEX_SOURCE, FAR_CLEAR_PIXEL_SOURCE,
    NORMAL_RECONSTRUCTION_SOURCE, POINT_ACCUMULATION_SOURCE,
};

fn instruction_count(bytecode: &[u32]) -> usize {
    const COMMENT: u16 = 0xfffe;
    const END: u16 = 0xffff;
    let mut offset = 1;
    let mut count = 0;
    while offset < bytecode.len() {
        let token = bytecode[offset];
        let opcode = token as u16;
        if opcode == END {
            return count;
        }
        if opcode == COMMENT {
            offset += 1 + ((token >> 16) & 0x7fff) as usize;
            continue;
        }
        offset += 1 + ((token >> 24) & 0x0F) as usize;
        count += 1;
    }
    panic!("shader bytecode has no END token");
}

fn texture_instruction_count(bytecode: &[u32]) -> usize {
    const COMMENT: u16 = 0xfffe;
    const END: u16 = 0xffff;
    const TEXLD: u16 = 66;
    const TEXLDD: u16 = 93;
    const TEXLDL: u16 = 95;
    let mut offset = 1;
    let mut count = 0;
    while offset < bytecode.len() {
        let token = bytecode[offset];
        let opcode = token as u16;
        if opcode == END {
            return count;
        }
        if opcode == COMMENT {
            offset += 1 + ((token >> 16) & 0x7fff) as usize;
            continue;
        }
        count += usize::from(matches!(opcode, TEXLD | TEXLDD | TEXLDL));
        offset += 1 + ((token >> 24) & 0x0f) as usize;
    }
    panic!("shader bytecode has no END token");
}

#[test]
fn every_shadow_shader_compiles_for_shader_model_three_with_static_budgets() {
    let variants = [
        (
            "shadow_directional.vs",
            DIRECTIONAL_VERTEX_SOURCE,
            "vs_3_0",
            430,
        ),
        (
            "shadow_directional.ps",
            DIRECTIONAL_PIXEL_SOURCE,
            "ps_3_0",
            96,
        ),
        ("shadow_cube.vs", CUBE_VERTEX_SOURCE, "vs_3_0", 190),
        ("shadow_cube.ps", CUBE_PIXEL_SOURCE, "ps_3_0", 64),
        ("shadow_blur.ps", BLUR_PIXEL_SOURCE, "ps_3_0", 96),
        ("shadow_far_clear.ps", FAR_CLEAR_PIXEL_SOURCE, "ps_3_0", 8),
        (
            "shadow_normal_reconstruct.ps",
            NORMAL_RECONSTRUCTION_SOURCE,
            "ps_3_0",
            256,
        ),
        (
            "shadow_point_accumulate.ps",
            POINT_ACCUMULATION_SOURCE,
            "ps_3_0",
            512,
        ),
        ("shadow_composite.ps", COMPOSITE_PIXEL_SOURCE, "ps_3_0", 640),
    ];
    let mut compiled_programs: Vec<(&str, Vec<u32>)> = Vec::with_capacity(variants.len());
    for (name, source, target, budget) in variants {
        let bytecode = crate::shaders::compile_hlsl_source_target(name, source, target)
            .unwrap_or_else(|error| panic!("{name} must compile: {error:#}"));
        assert_eq!(
            bytecode[0],
            if target.starts_with("vs") {
                0xfffe_0300
            } else {
                0xffff_0300
            }
        );
        let instructions = instruction_count(&bytecode);
        assert!(
            instructions <= budget,
            "{name} uses {instructions} instructions, above its {budget}-instruction budget"
        );
        assert!(
            compiled_programs
                .iter()
                .all(|(other_name, other)| other != &bytecode || other_name == &name),
            "{name} unexpectedly aliases another shadow program"
        );
        compiled_programs.push((name, bytecode));
    }
    assert_eq!(compiled_programs.len(), 9);
}

#[test]
fn directional_generation_preserves_all_complex_geometry_routes() {
    let vertex = std::str::from_utf8(DIRECTIONAL_VERTEX_SOURCE).expect("vertex UTF-8");
    assert!(vertex.contains("float4x4 ShadowWorld : register(c0)"));
    assert!(vertex.contains("float4x4 ShadowViewProjection : register(c4)"));
    assert!(vertex.contains("float4 GeometryData : register(c8)"));
    assert!(vertex.contains("float4 BoneRows[54] : register(c9)"));
    assert!(vertex.contains("float4 SpeedTreeRows[77] : register(c63)"));
    assert!(vertex.contains("float4 TerrainRows[6] : register(c140)"));
    for route in [
        "GEOMETRY_SKINNED",
        "GEOMETRY_SPEEDTREE",
        "GEOMETRY_TERRAIN_LOD",
    ] {
        assert!(vertex.contains(route), "missing generation route {route}");
    }
    assert!(vertex.contains("input.blendIndices.zyxw * 765.01001f"));
    assert!(vertex.contains("1.0f - dot(input.blendWeight.xyz, 1.0f)"));

    let pixel = std::str::from_utf8(DIRECTIONAL_PIXEL_SOURCE).expect("pixel UTF-8");
    assert!(pixel.contains("clip(diffuse.a - 0.5f)"));
    assert!(pixel.contains("float2 warped = WarpDepth"));
    assert!(pixel.contains("float4(warped, warped * warped)"));
    assert!(!pixel.contains("ddx("));
    assert!(!pixel.contains("ddy("));

    let cube = std::str::from_utf8(CUBE_PIXEL_SOURCE).expect("cube pixel UTF-8");
    assert!(
        cube.contains("float4 Main(PixelInput input) : COLOR0"),
        "the legacy Microsoft D3D compiler requires four-component COLOR0 output"
    );
    assert!(cube.contains("clip(diffuse.a - 0.2f)"));
}

#[test]
fn consumer_reconstructs_normals_and_samples_all_maps_without_screen_space_contact_rays() {
    let normals = std::str::from_utf8(NORMAL_RECONSTRUCTION_SOURCE).expect("normal UTF-8");
    assert!(normals.contains("ReconstructNormal"));
    assert!(normals.contains("dot(left - center, left - center)"));
    assert!(normals.contains("dot(up - center, up - center)"));
    assert!(!normals.contains("ddx("));
    assert!(!normals.contains("ddy("));

    let point = std::str::from_utf8(POINT_ACCUMULATION_SOURCE).expect("point UTF-8");
    assert!(point.contains("samplerCUBE ShadowCube0 : register(s1)"));
    assert!(point.contains("samplerCUBE ShadowCube5 : register(s6)"));
    assert!(point.contains("sampler2D NormalBuffer : register(s7)"));
    assert!(point.contains("contribution * (1.0f - visibility)"));
    assert!(point.contains("smoothstep(0.0f, 0.2f, normalizedDistance)"));
    assert!(!point.contains("PointControl.w"));
    assert_eq!(point.matches("SamplePointShadow(").count(), 7);

    let composite = std::str::from_utf8(COMPOSITE_PIXEL_SOURCE).expect("composite UTF-8");
    assert!(composite.contains("sampler2D ShadowAtlas : register(s2)"));
    assert!(composite.contains("AtlasUv"));
    assert!(composite.contains("cascadeIndex == 0"));
    assert!(composite.contains("float4 CascadeSpheres[4] : register(c27)"));
    assert!(composite.contains("smoothstep(radius * 0.9f, radius, distanceToCenter)"));
    assert!(composite.contains("ContactFilteredVisibility"));
    assert!(composite.contains("ContactControl.x <= 0.5f"));
    assert!(
        !composite.contains("sampler2D Contact") && !composite.contains("ScreenSpaceShadow"),
        "screen-depth contact rays create camera-following occluders"
    );
    assert!(composite.contains("PointShadowBuffer"));
    assert!(
        composite.contains("return float4(saturate(pointShadow.rgb * ShadowControl.z), 1.0f);"),
        "interiors publish RGB occluded light energy for subtractive blending"
    );
    assert!(
        !composite.contains("float values[4]"),
        "every pixel must sample only its selected cascade and an optional boundary neighbor"
    );
    assert!(composite.contains("CascadeMatrices[cascade]"));
    assert_eq!(
        composite.matches("tex2Dlod(ShadowAtlas").count(),
        1,
        "one shared lookup body prevents eager per-cascade texture traffic"
    );
    let composite_bytecode = crate::shaders::compile_hlsl_source_target(
        "shadow_composite_sample_budget.ps",
        COMPOSITE_PIXEL_SOURCE,
        "ps_3_0",
    )
    .expect("shadow composite must compile");
    let texture_samples = texture_instruction_count(&composite_bytecode);
    assert!(
        texture_samples <= 8,
        "compiled composition uses {texture_samples} samples, above the bounded atlas-refinement budget"
    );
    assert!(!composite.contains("sampler2D FirstPersonDepth"));
    assert!(
        composite.contains("static const float EvsmReceiverBias = 0.01f"),
        "the receiver variance floor must match NVR instead of flickering at a 500x smaller value"
    );
    assert!(
        composite.contains("float CascadeBleedReduction(int cascadeIndex)")
            && composite.contains("0.6f")
            && composite.contains("0.8f"),
        "far and LOD receivers need NVR's stronger variance-tail rejection on broad surfaces"
    );
    assert!(
        !composite.contains("DirectionalControl.xyz * DirectionalControl.w"),
        "an inferred world-space receiver translation changes far silhouettes and is not part of NVR's consumer contract"
    );
    assert!(
        composite.contains("float raw = DirectionalVisibility(worldPosition, viewDepth);"),
        "exteriors must sample only the directional map family"
    );
    assert!(!composite.contains("ddx("));
    assert!(!composite.contains("ddy("));
}

#[test]
fn blur_is_separable_quadrant_free_and_never_declares_an_in_place_target() {
    let blur = std::str::from_utf8(BLUR_PIXEL_SOURCE).expect("blur UTF-8");
    assert!(blur.contains("float2 BlurDirection : register(c0)"));
    assert!(blur.contains("sampler2D SourceMap : register(s0)"));
    assert!(blur.contains("float4 SourceScaleBias : register(c2)"));
    assert!(blur.contains("input.uv * SourceScaleBias.xy + SourceScaleBias.zw"));
    assert!(!blur.contains("upperLeft"));
    assert!(!blur.contains("lowerRight"));
    assert_eq!(blur.matches("tex2Dlod(").count(), 5);
}

#[test]
fn evsm_clear_and_atlas_edges_keep_unrendered_pixels_fully_lit() {
    let clear = std::str::from_utf8(FAR_CLEAR_PIXEL_SOURCE).expect("clear UTF-8");
    assert!(clear.contains("float4 FarMoments : register(c0)"));
    assert!(clear.contains("return FarMoments"));

    let composite = std::str::from_utf8(COMPOSITE_PIXEL_SOURCE).expect("composite UTF-8");
    assert!(composite.contains("float4 CascadeTexel : register(c25)"));
    assert!(composite.contains("clamp(localUv, CascadeTexel.xx, CascadeTexel.yy)"));
}
