use super::contract::contact_consumer_work;
use super::shaders::{
    COMPOSITE_PIXEL_SOURCE, CONTACT_SOURCE, CUBE_PIXEL_SOURCE, CUBE_VERTEX_SOURCE,
    DIRECTIONAL_MASK_SOURCE, DIRECTIONAL_PIXEL_SOURCE, DIRECTIONAL_VERTEX_SOURCE,
    FAR_CLEAR_PIXEL_SOURCE, POINT_ACCUMULATION_SOURCE, directional_composite_source,
    exterior_composite_source, interior_composite_source, point_accumulation_source,
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
    let point_one = point_accumulation_source(1);
    let point_six = point_accumulation_source(6);
    let point_twelve = point_accumulation_source(12);
    let directional_composite = directional_composite_source();
    let interior_composite = interior_composite_source();
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
            "shadow_point_accumulate_1.ps",
            point_one.as_slice(),
            "ps_3_0",
            // The additive receiver-depth ownership pair costs six scalar
            // instructions over the former one-light program.
            360,
        ),
        (
            "shadow_point_accumulate_6.ps",
            point_six.as_slice(),
            "ps_3_0",
            // Same ownership pair with narrow compiler headroom.
            896,
        ),
        (
            "shadow_point_accumulate_12.ps",
            point_twelve.as_slice(),
            "ps_3_0",
            // The exact edge-aware receiver plus twelve RGB light evaluations
            // retains narrow compiler-alignment headroom while eliminating
            // two redundant full-resolution passes.
            1_544,
        ),
        (
            "shadow_contact.ps",
            CONTACT_SOURCE,
            "ps_3_0",
            // Exact texel addressing, quantization-bounded receiver-plane
            // validation, and four NVR ray taps stay below this measured cap.
            464,
        ),
        (
            "shadow_directional_mask.ps",
            DIRECTIONAL_MASK_SOURCE,
            "ps_3_0",
            // NVR-quality EVSM and actor coverage run for every receiver; the
            // compositor is budgeted independently below.
            1_856,
        ),
        (
            "shadow_composite.ps",
            COMPOSITE_PIXEL_SOURCE,
            "ps_3_0",
            // The final pass owns exact receiver lookup and source-color
            // composition. It never samples an EVSM atlas or cube map.
            504,
        ),
        (
            "shadow_composite_interior.ps",
            interior_composite.as_slice(),
            "ps_3_0",
            // Fractional local-light occlusion remains a branch-free
            // specialization rather than adding dynamic work to exteriors.
            504,
        ),
        (
            "shadow_composite_directional.ps",
            directional_composite.as_slice(),
            "ps_3_0",
            // Directional EVSM evaluation is fused into this already-required
            // source pass. The old two-pass total was up to 2,168 tokens.
            2_050,
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
    assert_eq!(compiled_programs.len(), 13);
}

#[test]
fn full_resolution_exterior_receiver_work_has_a_fixed_shader_budget() {
    let directional_source = directional_composite_source();
    let directional = crate::shaders::compile_hlsl_source_target(
        "shadow_composite_directional_budget.ps",
        &directional_source,
        "ps_3_0",
    )
    .expect("point-free exterior composite must compile");
    let mixed = crate::shaders::compile_hlsl_source_target(
        "shadow_composite_mixed_budget.ps",
        &exterior_composite_source(),
        "ps_3_0",
    )
    .expect("mixed-light composite must compile");
    let directional_instructions = instruction_count(&directional);
    let mixed_instructions = instruction_count(&mixed);
    let directional_mask = crate::shaders::compile_hlsl_source_target(
        "shadow_directional_mask_weighted_budget.ps",
        DIRECTIONAL_MASK_SOURCE,
        "ps_3_0",
    )
    .expect("deferred directional mask must compile");
    let receiver_instructions = instruction_count(&directional_mask);
    assert!(
        directional_instructions <= 2_050,
        "point-free exterior path uses {directional_instructions} instructions"
    );
    assert!(
        directional_instructions < receiver_instructions + 312,
        "fused exterior path retained the old mask-plus-composite cost ({directional_instructions} versus {})",
        receiver_instructions + 312,
    );
    assert!(
        directional_instructions + 32 <= mixed_instructions,
        "specialization removed only {} instructions",
        mixed_instructions.saturating_sub(directional_instructions)
    );
    assert!(
        texture_instruction_count(&directional) + 2 <= texture_instruction_count(&mixed),
        "point-free exterior path retained local-light buffer reads"
    );
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
    assert!(point.contains("sampler2D SceneDepth : register(s0)"));
    assert!(point.contains("float4 deficit : COLOR0"));
    assert!(point.contains("float4 total : COLOR1"));
    assert!(point.contains("samplerCUBE ShadowCube0 : register(s1)"));
    assert!(point.contains("samplerCUBE ShadowCube5 : register(s6)"));
    assert!(point.contains("samplerCUBE ShadowCube11 : register(s12)"));
    assert!(point.contains("LightPositionRadius[12] : register(c7)"));
    assert!(point.contains("LightColorIntensity[12] : register(c19)"));

    let composite = std::str::from_utf8(COMPOSITE_PIXEL_SOURCE).expect("composite UTF-8");
    assert!(composite.contains("sampler2D SourceColor : register(s0)"));
    assert!(composite.contains("sampler2D SceneDepth : register(s1)"));
    assert!(composite.contains("sampler2D DirectionalVisibilityMap : register(s2)"));
    assert!(composite.contains("sampler2D PointShadowBuffer : register(s3)"));
    assert!(composite.contains("sampler2D ContactVisibility : register(s4)"));
    assert!(composite.contains("sampler2D PointLightTotal : register(s6)"));
    assert!(composite.contains("float4 ContactControl : register(c31)"));
    assert!(composite.contains("float4 PointControl : register(c32)"));
    assert!(!composite.contains("DeferredTexel"));
    assert!(composite.contains("#if OMV_INTERIOR"));
    assert!(composite.contains("float3 occludedFraction"));
    assert!(composite.contains("0.25f"));
    assert!(
        composite.contains("float ExactContactVisibility"),
        "contact filtering must execute inside the existing source-owned composite"
    );
    assert_eq!(
        composite.matches("tex2Dlod(").count(),
        7,
        "full-resolution composition owns only source, depth, exact visibility, fused contact, and exact point-buffer reads"
    );
    assert!(!composite.contains("VisibilityTap"));
    assert!(!composite.contains("PointTap"));

    let directional_mask =
        std::str::from_utf8(DIRECTIONAL_MASK_SOURCE).expect("directional mask UTF-8");
    assert!(directional_mask.contains("#if OMV_FUSED_DIRECTIONAL"));
    assert!(directional_mask.contains("sampler2D SceneDepth : register(s1)"));
    assert!(directional_mask.contains("sampler2D ShadowAtlas : register(s2)"));
    assert!(directional_mask.contains("sampler2D ActorNearMiddleMoments : register(s3)"));
    assert!(directional_mask.contains("sampler2D ActorFarMoments : register(s4)"));
    assert!(directional_mask.contains("sampler2D ShadowAtlas : register(s1)"));
    assert!(directional_mask.contains("sampler2D ActorNearMiddleMoments : register(s2)"));
    assert!(directional_mask.contains("sampler2D ActorFarMoments : register(s3)"));
    assert!(directional_mask.contains("float4 SunDirection : register(c27)"));
    assert!(directional_mask.contains("float4 ActorControl : register(c28)"));
    assert!(directional_mask.contains("float4 ActorCrops[3] : register(c29)"));
    assert!(directional_mask.contains("float4 ActorTexel : register(c32)"));

    let fused = String::from_utf8(exterior_composite_source()).expect("fused exterior UTF-8");
    assert!(fused.contains("#define OMV_FUSED_DIRECTIONAL 1"));
    assert!(fused.contains("sampler2D PointShadowBuffer : register(s5)"));
    assert!(fused.contains("sampler2D ContactVisibility : register(s7)"));
    assert!(fused.contains("float4 ContactControl : register(c33)"));
    assert!(fused.contains("float4 PointControl : register(c34)"));

    let contact = std::str::from_utf8(CONTACT_SOURCE).expect("contact UTF-8");
    assert!(contact.contains("sampler2D SceneDepth : register(s0)"));
    assert!(contact.contains("ViewLightDirection : register(c7)"));
    assert!(contact.contains("ContactSampleOffsets : register(c8)"));
    assert!(contact.contains("ContactDepthPrecision : register(c9)"));

    for (capacity, texture_budget) in [(1, 6), (6, 11), (12, 17)] {
        let point_bytecode = crate::shaders::compile_hlsl_source_target(
            &format!("shadow_point_scissor_{capacity}_budget.ps"),
            &point_accumulation_source(capacity),
            "ps_3_0",
        )
        .unwrap_or_else(|error| panic!("{capacity}-light point shader must compile: {error:#}"));
        assert!(
            texture_instruction_count(&point_bytecode) <= texture_budget,
            "{capacity}-light specialization retained unused cube samples"
        );
    }
    let directional_mask_bytecode = crate::shaders::compile_hlsl_source_target(
        "shadow_directional_mask_budget.ps",
        DIRECTIONAL_MASK_SOURCE,
        "ps_3_0",
    )
    .expect("deferred directional mask must compile");
    let directional_texture_samples = texture_instruction_count(&directional_mask_bytecode);
    assert!(
        // Static bytecode contains mutually exclusive cascade/actor branches;
        // each output pixel executes one cascade plus at most one transition.
        directional_texture_samples <= 25,
        "deferred directional mask uses {directional_texture_samples} compiled texture instructions"
    );
    for (name, source, maximum_samples) in [
        (
            "shadow_composite_sample_budget.ps",
            exterior_composite_source(),
            35,
        ),
        (
            "shadow_directional_composite_sample_budget.ps",
            directional_composite_source(),
            33,
        ),
        (
            "shadow_interior_composite_sample_budget.ps",
            interior_composite_source(),
            5,
        ),
    ] {
        let bytecode = crate::shaders::compile_hlsl_source_target(name, &source, "ps_3_0")
            .unwrap_or_else(|error| panic!("{name} must compile: {error:#}"));
        assert!(
            texture_instruction_count(&bytecode) <= maximum_samples,
            "{name} exceeds its {maximum_samples}-sample static bytecode ceiling"
        );
    }
    for (name, source) in [
        ("point", POINT_ACCUMULATION_SOURCE),
        ("contact", CONTACT_SOURCE),
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
fn contact_filter_fusion_keeps_one_generation_pass_and_bounded_depth_work() {
    let raw = crate::shaders::compile_hlsl_source_target(
        "shadow_contact_work.ps",
        CONTACT_SOURCE,
        "ps_3_0",
    )
    .expect("contact generation must compile");
    // Compilation proves the executable stage fits SM3. The workload model
    // counts loop trip counts, which a static TEXLD opcode count cannot see.
    assert!(texture_instruction_count(&raw) > 0);
    let work = contact_consumer_work();
    assert_eq!(
        work.passes, 1,
        "contact filtering must not allocate a second fullscreen pass"
    );
    assert_eq!(
        work.texture_samples, 7,
        "contact generation owns one receiver, two plane, and four ray reads"
    );
}

#[test]
fn clear_and_composite_register_abi_matches_the_native_upload_contract() {
    let clear = std::str::from_utf8(FAR_CLEAR_PIXEL_SOURCE).expect("clear UTF-8");
    assert!(clear.contains("float4 FarMoments : register(c0)"));

    let directional = std::str::from_utf8(DIRECTIONAL_MASK_SOURCE).expect("directional mask UTF-8");
    assert!(directional.contains("float4 CascadeTexel : register(c25)"));
    let composite = std::str::from_utf8(COMPOSITE_PIXEL_SOURCE).expect("composite UTF-8");
    assert!(!composite.contains("DeferredTexel"));
}
