use super::shaders::{
    BLUR_PIXEL_SOURCE, COMPOSITE_PIXEL_SOURCE, CONTACT_BLUR_PIXEL_SOURCE, CONTACT_PIXEL_SOURCE,
    CUBE_PIXEL_SOURCE, CUBE_VERTEX_SOURCE, DIRECTIONAL_PIXEL_SOURCE, DIRECTIONAL_VERTEX_SOURCE,
    FAR_CLEAR_PIXEL_SOURCE, NORMAL_RECONSTRUCTION_SOURCE, POINT_ACCUMULATION_SOURCE,
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
        ("shadow_contact.ps", CONTACT_PIXEL_SOURCE, "ps_3_0", 320),
        (
            "shadow_contact_blur.ps",
            CONTACT_BLUR_PIXEL_SOURCE,
            "ps_3_0",
            160,
        ),
        (
            "shadow_point_accumulate.ps",
            POINT_ACCUMULATION_SOURCE,
            "ps_3_0",
            512,
        ),
        ("shadow_composite.ps", COMPOSITE_PIXEL_SOURCE, "ps_3_0", 640),
    ];
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
    }
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

    let pixel = std::str::from_utf8(DIRECTIONAL_PIXEL_SOURCE).expect("pixel UTF-8");
    assert!(pixel.contains("clip(diffuse.a - 0.5f)"));
    assert!(pixel.contains("float2 warped = WarpDepth"));
    assert!(pixel.contains("float4(warped, warped * warped)"));
    assert!(!pixel.contains("ddx("));
    assert!(!pixel.contains("ddy("));

    let cube = std::str::from_utf8(CUBE_PIXEL_SOURCE).expect("cube pixel UTF-8");
    assert!(cube.contains("clip(diffuse.a - 0.2f)"));
}

#[test]
fn consumer_reconstructs_normals_and_samples_all_maps_without_derivatives() {
    let normals = std::str::from_utf8(NORMAL_RECONSTRUCTION_SOURCE).expect("normal UTF-8");
    assert!(normals.contains("ReconstructNormal"));
    assert!(normals.contains("dot(left - center, left - center)"));
    assert!(normals.contains("dot(up - center, up - center)"));
    assert!(!normals.contains("ddx("));
    assert!(!normals.contains("ddy("));

    let contact = std::str::from_utf8(CONTACT_PIXEL_SOURCE).expect("contact UTF-8");
    assert!(contact.contains("sampleIndex <= 4"));
    assert!(contact.contains("ContactSample(center + stepVector * sampleIndex"));
    assert!(contact.contains("InterleavedGradientNoise"));
    assert!(!contact.contains("ddx("));
    assert!(!contact.contains("ddy("));

    let contact_blur = std::str::from_utf8(CONTACT_BLUR_PIXEL_SOURCE).expect("contact blur UTF-8");
    assert!(contact_blur.contains("tap <= 2"));
    assert_eq!(contact_blur.matches("WeightedTap(").count(), 2);
    assert!(contact_blur.contains("abs(sampleDepth - centerDepth)"));

    let point = std::str::from_utf8(POINT_ACCUMULATION_SOURCE).expect("point UTF-8");
    assert!(point.contains("samplerCUBE ShadowCube0 : register(s1)"));
    assert!(point.contains("samplerCUBE ShadowCube5 : register(s6)"));
    assert!(point.contains("sampler2D NormalBuffer : register(s7)"));
    assert!(point.contains("PointControl.w < 0.5f"));
    assert_eq!(point.matches("SamplePointShadow(").count(), 7);

    let composite = std::str::from_utf8(COMPOSITE_PIXEL_SOURCE).expect("composite UTF-8");
    assert!(composite.contains("sampler2D ShadowAtlas : register(s2)"));
    assert!(composite.contains("AtlasUv"));
    assert!(composite.contains("cascadeIndex == 0"));
    assert!(composite.contains("CascadeBlendWidth"));
    assert!(composite.contains("PointShadowBuffer"));
    assert!(composite.contains("raw = min(DirectionalVisibility(worldPosition, viewDepth), raw)"));
    assert!(!composite.contains("pointShadow.x / pointShadow.y"));
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
