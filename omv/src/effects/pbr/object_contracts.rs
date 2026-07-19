//! Object shader-row contracts derived from NVR's PBR collection.
//!
//! This module is the eligibility boundary for object PBR. Hooks provide native
//! table rows; this table decides whether the row pair is an implemented NVR
//! object contract or a deterministic fallback.

use super::shader_registry::{self, ShaderStage};

#[derive(Clone, Copy, Debug)]
pub(super) struct ObjectContractDecision {
    pub(super) state: ObjectContractState,
    pub(super) normalized_vertex_index: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ObjectContractState {
    None,
    ImplementedBase,
    ImplementedLod,
    ImplementedSi,
    ImplementedProjectedShadow,
    ImplementedStbb,
    ImplementedHair,
    ImplementedLights,
    ImplementedSpecular,
    ImplementedHighLights,
    ImplementedOnlyLight,
    ImplementedDiffusePoint,
    ImplementedOnlySpecular,
    BlockedTerrain,
    BlockedEnvMap,
    BlockedMissingTemplate,
    BlockedUnknown,
    BlockedPassEntryTerrain,
    BlockedMissingD3DState,
    BlockedMissingShaderRecord,
    BlockedMissingTableIdentity,
    BlockedTableIdentityMismatch,
    BlockedMissingReplacementResource,
    BlockedHandleStateMismatch,
    BlockedMissingSampler,
}

#[derive(Clone, Copy, Debug)]
struct ObjectPairContract {
    vertex_index: u32,
    pixel_index: u32,
    state: ObjectContractState,
}

const IMPLEMENTED_OBJECT_CONTRACTS: &[ObjectPairContract] = &[
    pair(0, 0, ObjectContractState::ImplementedBase),
    pair(0, 1, ObjectContractState::ImplementedBase),
    pair(0, 2, ObjectContractState::ImplementedLod),
    pair(0, 4, ObjectContractState::ImplementedSi),
    pair(0, 9, ObjectContractState::ImplementedHair),
    pair(1, 2, ObjectContractState::ImplementedLod),
    pair(4, 5, ObjectContractState::ImplementedProjectedShadow),
    pair(4, 7, ObjectContractState::ImplementedProjectedShadow),
    pair(4, 10, ObjectContractState::ImplementedHair),
    pair(7, 8, ObjectContractState::ImplementedStbb),
    pair(8, 11, ObjectContractState::ImplementedLights),
    pair(8, 12, ObjectContractState::ImplementedSi),
    pair(8, 13, ObjectContractState::ImplementedHair),
    pair(10, 14, ObjectContractState::ImplementedProjectedShadow),
    pair(10, 15, ObjectContractState::ImplementedProjectedShadow),
    pair(10, 16, ObjectContractState::ImplementedHair),
    pair(12, 17, ObjectContractState::ImplementedSpecular),
    pair(12, 18, ObjectContractState::ImplementedSi),
    pair(12, 19, ObjectContractState::ImplementedHair),
    pair(14, 20, ObjectContractState::ImplementedProjectedShadow),
    pair(14, 21, ObjectContractState::ImplementedProjectedShadow),
    pair(14, 22, ObjectContractState::ImplementedHair),
    pair(16, 23, ObjectContractState::ImplementedSpecular),
    pair(16, 24, ObjectContractState::ImplementedSi),
    pair(18, 26, ObjectContractState::ImplementedProjectedShadow),
    pair(18, 27, ObjectContractState::ImplementedProjectedShadow),
    pair(20, 29, ObjectContractState::ImplementedHighLights),
    pair(20, 30, ObjectContractState::ImplementedSi),
    pair(22, 31, ObjectContractState::ImplementedHighLights),
    pair(22, 33, ObjectContractState::ImplementedSi),
    pair(23, 32, ObjectContractState::ImplementedHighLights),
    pair(25, 34, ObjectContractState::ImplementedSpecular),
    pair(25, 36, ObjectContractState::ImplementedSi),
    pair(26, 35, ObjectContractState::ImplementedSpecular),
    pair(28, 37, ObjectContractState::ImplementedOnlyLight),
    pair(28, 38, ObjectContractState::ImplementedOnlyLight),
    pair(30, 39, ObjectContractState::ImplementedProjectedShadow),
    pair(30, 40, ObjectContractState::ImplementedProjectedShadow),
    pair(32, 41, ObjectContractState::ImplementedOnlyLight),
    pair(32, 42, ObjectContractState::ImplementedOnlyLight),
    pair(34, 43, ObjectContractState::ImplementedProjectedShadow),
    pair(34, 44, ObjectContractState::ImplementedProjectedShadow),
    pair(36, 45, ObjectContractState::ImplementedDiffusePoint),
    pair(38, 46, ObjectContractState::ImplementedDiffusePoint),
    pair(40, 47, ObjectContractState::ImplementedOnlySpecular),
    pair(40, 48, ObjectContractState::ImplementedHair),
    pair(42, 49, ObjectContractState::ImplementedProjectedShadow),
    pair(42, 50, ObjectContractState::ImplementedHair),
    pair(44, 51, ObjectContractState::ImplementedOnlySpecular),
    pair(44, 52, ObjectContractState::ImplementedHair),
    pair(46, 53, ObjectContractState::ImplementedOnlySpecular),
    pair(46, 54, ObjectContractState::ImplementedHair),
    pair(48, 55, ObjectContractState::ImplementedOnlySpecular),
    pair(48, 56, ObjectContractState::ImplementedHair),
];

const fn pair(
    vertex_index: u32,
    pixel_index: u32,
    state: ObjectContractState,
) -> ObjectPairContract {
    ObjectPairContract {
        vertex_index,
        pixel_index,
        state,
    }
}

pub(super) fn classify_pair(vertex_index: u32, pixel_index: u32) -> ObjectContractDecision {
    if stage_table_slot_is_terrain(ShaderStage::Vertex, vertex_index)
        || stage_table_slot_is_terrain(ShaderStage::Pixel, pixel_index)
    {
        return decision(ObjectContractState::BlockedTerrain, vertex_index);
    }
    if stage_table_slot_is_envmap(ShaderStage::Vertex, vertex_index)
        || stage_table_slot_is_envmap(ShaderStage::Pixel, pixel_index)
    {
        return decision(ObjectContractState::BlockedEnvMap, vertex_index);
    }

    let normalized_vertex_index = normalize_skin_vertex_index(vertex_index);
    if !stage_template_exists(ShaderStage::Vertex, normalized_vertex_index)
        || !stage_template_exists(ShaderStage::Pixel, pixel_index)
    {
        return decision(
            ObjectContractState::BlockedMissingTemplate,
            normalized_vertex_index,
        );
    }

    if let Ok(index) = IMPLEMENTED_OBJECT_CONTRACTS
        .binary_search_by_key(&(normalized_vertex_index, pixel_index), |contract| {
            (contract.vertex_index, contract.pixel_index)
        })
    {
        return decision(
            IMPLEMENTED_OBJECT_CONTRACTS[index].state,
            normalized_vertex_index,
        );
    }

    decision(ObjectContractState::BlockedUnknown, normalized_vertex_index)
}

pub(super) fn stage_table_slot_is_terrain(stage: ShaderStage, index: u32) -> bool {
    match stage {
        ShaderStage::Vertex => matches!(index, 2 | 5 | 53..=62 | 76..=83 | 100..=101),
        ShaderStage::Pixel => matches!(index, 3 | 6 | 60..=69 | 80..=86 | 92..=149),
    }
}

pub(super) fn stage_table_slot_is_envmap(stage: ShaderStage, index: u32) -> bool {
    match stage {
        ShaderStage::Vertex => matches!(index, 50..=52),
        ShaderStage::Pixel => matches!(index, 57..=59),
    }
}

pub(super) fn state_from_code(code: u32) -> ObjectContractState {
    match code {
        1 => ObjectContractState::ImplementedBase,
        2 => ObjectContractState::ImplementedLod,
        3 => ObjectContractState::ImplementedSi,
        4 => ObjectContractState::ImplementedProjectedShadow,
        5 => ObjectContractState::ImplementedStbb,
        6 => ObjectContractState::ImplementedHair,
        7 => ObjectContractState::ImplementedLights,
        8 => ObjectContractState::ImplementedSpecular,
        9 => ObjectContractState::ImplementedHighLights,
        10 => ObjectContractState::ImplementedOnlyLight,
        11 => ObjectContractState::ImplementedDiffusePoint,
        12 => ObjectContractState::ImplementedOnlySpecular,
        40 => ObjectContractState::BlockedTerrain,
        41 => ObjectContractState::BlockedEnvMap,
        42 => ObjectContractState::BlockedMissingTemplate,
        43 => ObjectContractState::BlockedUnknown,
        44 => ObjectContractState::BlockedPassEntryTerrain,
        45 => ObjectContractState::BlockedMissingD3DState,
        46 => ObjectContractState::BlockedMissingShaderRecord,
        47 => ObjectContractState::BlockedMissingTableIdentity,
        48 => ObjectContractState::BlockedTableIdentityMismatch,
        49 => ObjectContractState::BlockedMissingReplacementResource,
        50 => ObjectContractState::BlockedHandleStateMismatch,
        51 => ObjectContractState::BlockedMissingSampler,
        _ => ObjectContractState::None,
    }
}

pub(super) fn state_code(state: ObjectContractState) -> u32 {
    match state {
        ObjectContractState::None => 0,
        ObjectContractState::ImplementedBase => 1,
        ObjectContractState::ImplementedLod => 2,
        ObjectContractState::ImplementedSi => 3,
        ObjectContractState::ImplementedProjectedShadow => 4,
        ObjectContractState::ImplementedStbb => 5,
        ObjectContractState::ImplementedHair => 6,
        ObjectContractState::ImplementedLights => 7,
        ObjectContractState::ImplementedSpecular => 8,
        ObjectContractState::ImplementedHighLights => 9,
        ObjectContractState::ImplementedOnlyLight => 10,
        ObjectContractState::ImplementedDiffusePoint => 11,
        ObjectContractState::ImplementedOnlySpecular => 12,
        ObjectContractState::BlockedTerrain => 40,
        ObjectContractState::BlockedEnvMap => 41,
        ObjectContractState::BlockedMissingTemplate => 42,
        ObjectContractState::BlockedUnknown => 43,
        ObjectContractState::BlockedPassEntryTerrain => 44,
        ObjectContractState::BlockedMissingD3DState => 45,
        ObjectContractState::BlockedMissingShaderRecord => 46,
        ObjectContractState::BlockedMissingTableIdentity => 47,
        ObjectContractState::BlockedTableIdentityMismatch => 48,
        ObjectContractState::BlockedMissingReplacementResource => 49,
        ObjectContractState::BlockedHandleStateMismatch => 50,
        ObjectContractState::BlockedMissingSampler => 51,
    }
}

pub(super) fn state_label(state: ObjectContractState) -> &'static str {
    match state {
        ObjectContractState::None => "none",
        ObjectContractState::ImplementedBase => "implemented base object",
        ObjectContractState::ImplementedLod => "implemented object LOD",
        ObjectContractState::ImplementedSi => "implemented SI object",
        ObjectContractState::ImplementedProjectedShadow => "implemented projected-shadow object",
        ObjectContractState::ImplementedStbb => "implemented STBB object",
        ObjectContractState::ImplementedHair => "implemented hair object",
        ObjectContractState::ImplementedLights => "implemented multi-light object",
        ObjectContractState::ImplementedSpecular => "implemented specular object",
        ObjectContractState::ImplementedHighLights => "implemented high-light object",
        ObjectContractState::ImplementedOnlyLight => "implemented only-light object",
        ObjectContractState::ImplementedDiffusePoint => "implemented diffuse point-light object",
        ObjectContractState::ImplementedOnlySpecular => "implemented only-specular object",
        ObjectContractState::BlockedTerrain => "blocked terrain row",
        ObjectContractState::BlockedEnvMap => "blocked EnvMap/reflection row",
        ObjectContractState::BlockedMissingTemplate => "blocked missing NVR template",
        ObjectContractState::BlockedUnknown => "blocked unknown object row",
        ObjectContractState::BlockedPassEntryTerrain => "blocked terrain pass entry",
        ObjectContractState::BlockedMissingD3DState => "blocked missing D3D state",
        ObjectContractState::BlockedMissingShaderRecord => "blocked missing shader record",
        ObjectContractState::BlockedMissingTableIdentity => "blocked missing table identity",
        ObjectContractState::BlockedTableIdentityMismatch => "blocked table identity mismatch",
        ObjectContractState::BlockedMissingReplacementResource => {
            "blocked missing replacement resource"
        }
        ObjectContractState::BlockedHandleStateMismatch => "blocked shader handle mismatch",
        ObjectContractState::BlockedMissingSampler => "blocked missing object sampler",
    }
}

pub(super) fn state_label_from_code(code: u32) -> &'static str {
    state_label(state_from_code(code))
}

pub(super) fn state_is_implemented(state: ObjectContractState) -> bool {
    matches!(
        state,
        ObjectContractState::ImplementedBase
            | ObjectContractState::ImplementedLod
            | ObjectContractState::ImplementedSi
            | ObjectContractState::ImplementedProjectedShadow
            | ObjectContractState::ImplementedStbb
            | ObjectContractState::ImplementedHair
            | ObjectContractState::ImplementedLights
            | ObjectContractState::ImplementedSpecular
            | ObjectContractState::ImplementedHighLights
            | ObjectContractState::ImplementedOnlyLight
            | ObjectContractState::ImplementedDiffusePoint
            | ObjectContractState::ImplementedOnlySpecular
    )
}

fn decision(state: ObjectContractState, normalized_vertex_index: u32) -> ObjectContractDecision {
    ObjectContractDecision {
        state,
        normalized_vertex_index,
    }
}

fn stage_template_exists(stage: ShaderStage, table_index: u32) -> bool {
    u16::try_from(table_index)
        .ok()
        .and_then(|index| 2000u16.checked_add(index))
        .and_then(|sls_number| shader_registry::object_template_id(stage, sls_number))
        .is_some()
}

fn normalize_skin_vertex_index(index: u32) -> u32 {
    match index {
        3 => 0,
        6 => 4,
        9 => 8,
        11 => 10,
        13 => 12,
        15 => 14,
        17 => 16,
        19 => 18,
        21 => 20,
        24 => 22,
        29 => 28,
        31 => 30,
        33 => 32,
        35 => 34,
        37 => 36,
        39 => 38,
        41 => 40,
        43 => 42,
        45 => 44,
        47 => 46,
        49 => 48,
        _ => index,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        IMPLEMENTED_OBJECT_CONTRACTS, ObjectContractState, classify_pair,
        normalize_skin_vertex_index,
    };
    use crate::effects::pbr::shader_registry::{self, ShaderStage};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct LightAbi {
        lights: u32,
        high: bool,
        optimized: bool,
        projected_shadow: bool,
        specular: bool,
        only_light: bool,
        diffuse: bool,
        point: bool,
        only_specular: bool,
    }

    fn has_define(defines: &str, name: &str) -> bool {
        defines.lines().any(|line| {
            let mut parts = line.split_whitespace();
            parts.next() == Some("#define") && parts.next() == Some(name)
        })
    }

    fn define_u32(defines: &str, name: &str) -> Option<u32> {
        defines.lines().find_map(|line| {
            let mut parts = line.split_whitespace();
            if parts.next() == Some("#define") && parts.next() == Some(name) {
                parts.next().and_then(|value| value.parse().ok())
            } else {
                None
            }
        })
    }

    fn light_abi(stage: ShaderStage, table_index: u32) -> LightAbi {
        let sls_number = u16::try_from(2000 + table_index).unwrap();
        let template = shader_registry::object_template_id(stage, sls_number)
            .unwrap_or_else(|| panic!("missing {stage:?} SLS{sls_number}"))
            .template;
        let defines = template.defines;

        LightAbi {
            lights: define_u32(defines, "PBR_OBJECT_LIGHTS").unwrap_or(1),
            high: has_define(defines, "PBR_OBJECT_HIGH"),
            optimized: has_define(defines, "PBR_OBJECT_OPT"),
            projected_shadow: has_define(defines, "PBR_OBJECT_SHADOW"),
            specular: has_define(defines, "PBR_OBJECT_SPECULAR"),
            only_light: has_define(defines, "PBR_OBJECT_ONLY_LIGHT"),
            diffuse: has_define(defines, "PBR_OBJECT_DIFFUSE"),
            point: has_define(defines, "PBR_OBJECT_POINT"),
            only_specular: has_define(defines, "PBR_OBJECT_ONLY_SPECULAR"),
        }
    }

    #[test]
    fn implemented_object_pairs_are_sorted_and_unique() {
        for pair in IMPLEMENTED_OBJECT_CONTRACTS.windows(2) {
            let left = (pair[0].vertex_index, pair[0].pixel_index);
            let right = (pair[1].vertex_index, pair[1].pixel_index);
            assert!(
                left < right,
                "object pair table is not strictly sorted: {left:?} then {right:?}"
            );
        }
    }

    #[test]
    fn every_implemented_object_pair_has_one_matching_light_abi() {
        for contract in IMPLEMENTED_OBJECT_CONTRACTS {
            let vertex = light_abi(ShaderStage::Vertex, contract.vertex_index);
            let pixel = light_abi(ShaderStage::Pixel, contract.pixel_index);

            assert_eq!(
                vertex.lights, pixel.lights,
                "light count mismatch for {contract:?}"
            );
            assert_eq!(
                vertex.high, pixel.high,
                "high-light family mismatch for {contract:?}"
            );
            assert_eq!(
                vertex.projected_shadow, pixel.projected_shadow,
                "shadow ABI mismatch for {contract:?}"
            );
            assert_eq!(
                vertex.specular, pixel.specular,
                "specular ABI mismatch for {contract:?}"
            );
            assert_eq!(
                vertex.only_light, pixel.only_light,
                "only-light ABI mismatch for {contract:?}"
            );
            assert_eq!(
                vertex.diffuse, pixel.diffuse,
                "diffuse ABI mismatch for {contract:?}"
            );
            assert_eq!(
                vertex.point, pixel.point,
                "point-light ABI mismatch for {contract:?}"
            );
            assert_eq!(
                vertex.only_specular, pixel.only_specular,
                "only-specular ABI mismatch for {contract:?}"
            );
            if vertex.high {
                assert_eq!(
                    vertex.optimized, pixel.optimized,
                    "high-light constant offset mismatch for {contract:?}"
                );
            }

            let decision = classify_pair(contract.vertex_index, contract.pixel_index);
            assert_eq!(decision.state, contract.state);
            assert_eq!(decision.normalized_vertex_index, contract.vertex_index);
        }
    }

    #[test]
    fn skin_vertex_rows_share_their_base_light_contract() {
        let skin_rows = [
            (3, 0),
            (6, 4),
            (9, 8),
            (11, 10),
            (13, 12),
            (15, 14),
            (17, 16),
            (19, 18),
            (21, 20),
            (24, 22),
            (29, 28),
            (31, 30),
            (33, 32),
            (35, 34),
            (37, 36),
            (39, 38),
            (41, 40),
            (43, 42),
            (45, 44),
            (47, 46),
            (49, 48),
        ];

        for (skin, base) in skin_rows {
            assert_eq!(normalize_skin_vertex_index(skin), base);
            for pixel in 0..=56 {
                if super::stage_table_slot_is_terrain(ShaderStage::Pixel, pixel) {
                    continue;
                }
                let skin_decision = classify_pair(skin, pixel);
                let base_decision = classify_pair(base, pixel);
                assert_eq!(
                    skin_decision.state,
                    base_decision.state,
                    "skin SLS{} and base SLS{} disagree for pixel SLS{}",
                    2000 + skin,
                    2000 + base,
                    2000 + pixel
                );
                assert_eq!(skin_decision.normalized_vertex_index, base);
            }
        }
    }

    #[test]
    fn unknown_object_pairs_remain_deterministic_fallbacks() {
        assert_eq!(
            classify_pair(0, 11).state,
            ObjectContractState::BlockedUnknown
        );
        assert_eq!(
            classify_pair(22, 35).state,
            ObjectContractState::BlockedUnknown
        );
        assert_eq!(
            classify_pair(50, 57).state,
            ObjectContractState::BlockedEnvMap
        );
        assert_eq!(
            classify_pair(53, 92).state,
            ObjectContractState::BlockedTerrain
        );
    }
}
