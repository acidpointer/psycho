use super::shaders::{
    COMPOSITE_PIXEL_SOURCE, CONTACT_BLUR_SOURCE, CONTACT_SOURCE, CONTACT_TEMPORAL_SOURCE,
    CUBE_PIXEL_SOURCE, CUBE_VERTEX_SOURCE, DIRECTIONAL_PIXEL_SOURCE, DIRECTIONAL_VERTEX_SOURCE,
    FAR_CLEAR_PIXEL_SOURCE, POINT_ACCUMULATION_SOURCE, POINT_GEOMETRY_SOURCE,
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

/// Decode only instruction opcodes from a D3D shader token stream.
///
/// This is deliberately a bytecode assertion rather than an HLSL text search:
/// compiler-generated derivatives are just as harmful to screen-depth rays as
/// derivatives written explicitly in the source.
fn compiled_opcodes(bytecode: &[u32]) -> Vec<u16> {
    const COMMENT: u16 = 0xfffe;
    const END: u16 = 0xffff;
    let mut offset = 1;
    let mut opcodes = Vec::new();
    while offset < bytecode.len() {
        let token = bytecode[offset];
        let opcode = token as u16;
        if opcode == END {
            return opcodes;
        }
        if opcode == COMMENT {
            offset += 1 + ((token >> 16) & 0x7fff) as usize;
            continue;
        }
        opcodes.push(opcode);
        offset += 1 + ((token >> 24) & 0x0f) as usize;
    }
    panic!("shader bytecode has no END token");
}

#[test]
fn compositor_has_no_quad_derivatives_or_triangle_diagonal_dependency() {
    // D3DSIO_DSX/D3DSIO_DSY. Derivatives in a two-triangle fullscreen pass
    // can disagree at the shared diagonal and are invalid after receiver
    // rejection branches, producing exactly the reported moving wall lines.
    const DSX: u16 = 91;
    const DSY: u16 = 92;
    let bytecode = crate::shaders::compile_hlsl_source_target(
        "shadow_composite_no_derivatives.ps",
        COMPOSITE_PIXEL_SOURCE,
        "ps_3_0",
    )
    .expect("shadow compositor must compile");
    let opcodes = compiled_opcodes(&bytecode);
    assert!(!opcodes.contains(&DSX), "compositor contains D3DSIO_DSX");
    assert!(!opcodes.contains(&DSY), "compositor contains D3DSIO_DSY");
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
        ("shadow_far_clear.ps", FAR_CLEAR_PIXEL_SOURCE, "ps_3_0", 8),
        (
            "shadow_point_geometry.ps",
            POINT_GEOMETRY_SOURCE,
            "ps_3_0",
            260,
        ),
        (
            "shadow_point_accumulate.ps",
            POINT_ACCUMULATION_SOURCE,
            "ps_3_0",
            // Exact RGB total plus deficit MRT output compiles to 708
            // instructions; 736 leaves narrow compiler-alignment headroom.
            736,
        ),
        ("shadow_contact.ps", CONTACT_SOURCE, "ps_3_0", 320),
        ("shadow_contact_blur.ps", CONTACT_BLUR_SOURCE, "ps_3_0", 320),
        (
            "shadow_contact_temporal.ps",
            CONTACT_TEMPORAL_SOURCE,
            "ps_3_0",
            // Four individually depth-rejected history taps compile to 248
            // instructions; 256 leaves only measured alignment headroom.
            256,
        ),
        (
            "shadow_composite.ps",
            COMPOSITE_PIXEL_SOURCE,
            "ps_3_0",
            // D3DCompile expands the four mutually exclusive cascade choices
            // and both branch-lazy receiver-bias evaluations. The executable
            // path remains bounded separately below; this static ceiling has
            // narrow headroom over the measured 1865 instructions.
            1920,
        ),
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
    assert_eq!(compiled_programs.len(), 11);
}

#[test]
fn generation_shader_register_abi_matches_the_native_upload_contract() {
    let vertex = std::str::from_utf8(DIRECTIONAL_VERTEX_SOURCE).expect("vertex UTF-8");
    assert!(vertex.contains("float4x4 ShadowWorld : register(c0)"));
    assert!(vertex.contains("float4x4 ShadowViewProjection : register(c4)"));
    assert!(vertex.contains("float4 GeometryData : register(c8)"));
    assert!(vertex.contains("float4 BoneRows[54] : register(c9)"));
    assert!(vertex.contains("float4 SpeedTreeRows[77] : register(c63)"));
    assert!(vertex.contains("float4 TerrainRows[6] : register(c140)"));
}

#[test]
fn consumer_shader_abis_compile_with_bounded_texture_work() {
    let point = std::str::from_utf8(POINT_ACCUMULATION_SOURCE).expect("point UTF-8");
    assert!(point.contains("sampler2D ReceiverGeometry : register(s0)"));
    assert!(point.contains("float4 deficit : COLOR0"));
    assert!(point.contains("float4 total : COLOR1"));
    assert!(point.contains("samplerCUBE ShadowCube0 : register(s1)"));
    assert!(point.contains("samplerCUBE ShadowCube5 : register(s6)"));
    assert!(point.contains("LightPositionRadius[6] : register(c7)"));
    assert!(point.contains("LightColorIntensity[6] : register(c13)"));
    let geometry = std::str::from_utf8(POINT_GEOMETRY_SOURCE).expect("geometry UTF-8");
    assert!(geometry.contains("sampler2D SceneDepth : register(s0)"));
    assert!(geometry.contains("PointControl : register(c6)"));

    let composite = std::str::from_utf8(COMPOSITE_PIXEL_SOURCE).expect("composite UTF-8");
    assert!(composite.contains("sampler2D SourceColor : register(s0)"));
    assert!(composite.contains("sampler2D SceneDepth : register(s1)"));
    assert!(composite.contains("sampler2D ShadowAtlas : register(s2)"));
    assert!(composite.contains("sampler2D PointShadowBuffer : register(s3)"));
    assert!(composite.contains("sampler2D ContactVisibility : register(s4)"));
    assert!(composite.contains("sampler2D ActorMoments : register(s5)"));
    assert!(composite.contains("sampler2D PointLightTotal : register(s6)"));
    assert!(composite.contains("float4 CascadeSpheres[4] : register(c27)"));
    assert!(composite.contains("float4 ContactControl : register(c31)"));
    assert!(composite.contains("float4 PointControl : register(c32)"));
    assert!(composite.contains("float4 SunDirection : register(c33)"));
    assert!(composite.contains("float4 ActorControl : register(c34)"));

    let contact = std::str::from_utf8(CONTACT_SOURCE).expect("contact UTF-8");
    assert!(contact.contains("sampler2D SceneDepth : register(s0)"));
    assert!(contact.contains("ViewLightDirection : register(c7)"));
    assert!(contact.contains("ContactSampleOffsets : register(c8)"));
    let blur = std::str::from_utf8(CONTACT_BLUR_SOURCE).expect("contact blur UTF-8");
    assert!(blur.contains("sampler2D ContactMap : register(s0)"));
    let temporal = std::str::from_utf8(CONTACT_TEMPORAL_SOURCE).expect("contact temporal UTF-8");
    assert!(temporal.contains("sampler2D CurrentContact : register(s0)"));
    assert!(temporal.contains("sampler2D HistoryContact : register(s1)"));
    assert!(temporal.contains("float4 HistoryControl : register(c7)"));

    let point_bytecode = crate::shaders::compile_hlsl_source_target(
        "shadow_point_scissor_budget.ps",
        POINT_ACCUMULATION_SOURCE,
        "ps_3_0",
    )
    .expect("point accumulation must compile");
    assert!(texture_instruction_count(&point_bytecode) <= 7);
    let geometry_bytecode = crate::shaders::compile_hlsl_source_target(
        "shadow_point_geometry_budget.ps",
        POINT_GEOMETRY_SOURCE,
        "ps_3_0",
    )
    .expect("point geometry must compile");
    assert!(texture_instruction_count(&geometry_bytecode) <= 5);
    let temporal_bytecode = crate::shaders::compile_hlsl_source_target(
        "shadow_contact_temporal_budget.ps",
        CONTACT_TEMPORAL_SOURCE,
        "ps_3_0",
    )
    .expect("contact temporal resolve must compile");
    assert_eq!(
        texture_instruction_count(&temporal_bytecode),
        5,
        "contact history must use one current sample and four depth-rejected bilinear history taps"
    );
    let composite_bytecode = crate::shaders::compile_hlsl_source_target(
        "shadow_composite_sample_budget.ps",
        COMPOSITE_PIXEL_SOURCE,
        "ps_3_0",
    )
    .expect("shadow composite must compile");
    let texture_samples = texture_instruction_count(&composite_bytecode);
    assert!(
        texture_samples <= 32,
        "compiled composition uses {texture_samples} samples, above the bounded atlas-refinement budget"
    );
    for (name, source) in [
        ("point", POINT_ACCUMULATION_SOURCE),
        ("point geometry", POINT_GEOMETRY_SOURCE),
        ("contact", CONTACT_SOURCE),
        ("contact blur", CONTACT_BLUR_SOURCE),
        ("contact temporal", CONTACT_TEMPORAL_SOURCE),
    ] {
        let bytecode = crate::shaders::compile_hlsl_source_target(name, source, "ps_3_0")
            .unwrap_or_else(|error| panic!("{name} must compile: {error:#}"));
        let opcodes = compiled_opcodes(&bytecode);
        assert!(!opcodes.contains(&91), "{name} contains dsx");
        assert!(!opcodes.contains(&92), "{name} contains dsy");
    }
    let composite_opcodes = compiled_opcodes(
        &crate::shaders::compile_hlsl_source_target(
            "composite derivative budget",
            COMPOSITE_PIXEL_SOURCE,
            "ps_3_0",
        )
        .expect("composite must compile"),
    );
    assert!(!composite_opcodes.contains(&91));
    assert!(!composite_opcodes.contains(&92));
}

#[test]
fn clear_and_composite_register_abi_matches_the_native_upload_contract() {
    let clear = std::str::from_utf8(FAR_CLEAR_PIXEL_SOURCE).expect("clear UTF-8");
    assert!(clear.contains("float4 FarMoments : register(c0)"));

    let composite = std::str::from_utf8(COMPOSITE_PIXEL_SOURCE).expect("composite UTF-8");
    assert!(composite.contains("float4 CascadeTexel : register(c25)"));
}
