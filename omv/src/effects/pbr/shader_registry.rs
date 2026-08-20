//! Declarative shader registry derived from NVR's collections.
//!
//! The object collection is keyed by the shader wrapper's own SLS template.
//! `SetShaders` must use records captured from shader creation/adoption, not a
//! terrain-style pair classifier.
//!
//! Close terrain deliberately gives the already-owned even/odd pixel resources
//! a second internal meaning. Even resources compile the native-only fast path;
//! odd resources compile the supplemental-light path. OMV does not consume the
//! native canopy projection in either program, so both engine row identities
//! may select either internal resource without changing terrain pixels. This
//! specialization preserves the logical catalog and device-resource count while
//! keeping supplemental sampler and register pressure out of ordinary draws.

use std::borrow::Cow;

const NVR_OBJECT_TEMPLATE_SOURCE: &str =
    include_str!("../../../shaders/embedded/nvr_pbr_object/ObjectTemplate.hlsl");
const NVR_OBJECT_INCLUDE_SOURCE: &str =
    include_str!("../../../shaders/embedded/nvr_pbr_object/Object.hlsl");
const NVR_PBR_INCLUDE_SOURCE: &str =
    include_str!("../../../shaders/embedded/nvr_pbr_object/PBR.hlsl");
const NVR_POINTLIGHTS_INCLUDE_SOURCE: &str =
    include_str!("../../../shaders/embedded/nvr_pbr_object/Pointlights.hlsl");
const NVR_HELPERS_INCLUDE_SOURCE: &str =
    include_str!("../../../shaders/embedded/nvr_pbr_object/Helpers.hlsl");
const NVR_SKIN_HELPERS_INCLUDE_SOURCE: &str =
    include_str!("../../../shaders/embedded/nvr_pbr_object/SkinHelpers.hlsl");
const LAND_LOD_VERTEX_SOURCE: &str =
    include_str!("../../../shaders/embedded/native_pbr_pplighting_landlod.vs.hlsl");
const LAND_LOD_PIXEL_SOURCE: &str =
    include_str!("../../../shaders/embedded/native_pbr_pplighting_landlod.hlsl");
const TERRAIN_FADE_VERTEX_SOURCE: &str =
    include_str!("../../../shaders/embedded/native_pbr_pplighting_terrainfade.vs.hlsl");
const TERRAIN_FADE_PIXEL_SOURCE: &str =
    include_str!("../../../shaders/embedded/native_pbr_pplighting_terrainfade.hlsl");
const CLOSE_TERRAIN_VERTEX_SOURCE: &str =
    include_str!("../../../shaders/embedded/native_pbr_pplighting_close_terrain.vs.hlsl");
const CLOSE_TERRAIN_PIXEL_SOURCE: &str =
    include_str!("../../../shaders/embedded/native_pbr_pplighting_close_terrain.hlsl");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ShaderStage {
    Vertex,
    Pixel,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ShaderTemplate {
    pub(super) stage: ShaderStage,
    pub(super) sls_number: u16,
    pub(super) label: &'static str,
    pub(super) defines: &'static str,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct TemplateRef {
    pub(super) id: u16,
    pub(super) template: &'static ShaderTemplate,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct RegistrySummary {
    pub(super) object_records: usize,
    pub(super) land_lod_records: usize,
    pub(super) terrain_fade_records: usize,
    pub(super) close_terrain_records: usize,
}

const fn vertex(sls_number: u16, label: &'static str, defines: &'static str) -> ShaderTemplate {
    ShaderTemplate {
        stage: ShaderStage::Vertex,
        sls_number,
        label,
        defines,
    }
}

const fn pixel(sls_number: u16, label: &'static str, defines: &'static str) -> ShaderTemplate {
    ShaderTemplate {
        stage: ShaderStage::Pixel,
        sls_number,
        label,
        defines,
    }
}

// Source-derived from NVR PBRShaders::Templates().
const OBJECT_VERTEX_TEMPLATES: &[ShaderTemplate] = &[
    vertex(2000, "SLS2000_v", "#define PBR_OBJECT_LIGHTS 1"),
    vertex(2001, "SLS2001_v", "#define PBR_OBJECT_LIGHTS 1"),
    vertex(
        2003,
        "SLS2003_v_skin",
        "#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SKIN 1",
    ),
    vertex(
        2004,
        "SLS2004_v_shadow",
        "#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SHADOW 1",
    ),
    vertex(
        2006,
        "SLS2006_v_shadow_skin",
        "#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SHADOW 1\n#define PBR_OBJECT_SKIN 1",
    ),
    vertex(2007, "SLS2007_v", "#define PBR_OBJECT_LIGHTS 1"),
    vertex(2008, "SLS2008_v_lights2", "#define PBR_OBJECT_LIGHTS 2"),
    vertex(
        2009,
        "SLS2009_v_lights2_skin",
        "#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SKIN 1",
    ),
    vertex(
        2010,
        "SLS2010_v_lights2_shadow",
        "#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SHADOW 1",
    ),
    vertex(
        2011,
        "SLS2011_v_lights2_shadow_skin",
        "#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SHADOW 1\n#define PBR_OBJECT_SKIN 1",
    ),
    vertex(
        2012,
        "SLS2012_v_specular",
        "#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SPECULAR 1",
    ),
    vertex(
        2013,
        "SLS2013_v_specular_skin",
        "#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SKIN 1",
    ),
    vertex(
        2014,
        "SLS2014_v_specular_shadow",
        "#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SHADOW 1",
    ),
    vertex(
        2015,
        "SLS2015_v_specular_shadow_skin",
        "#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SHADOW 1\n#define PBR_OBJECT_SKIN 1",
    ),
    vertex(
        2016,
        "SLS2016_v_specular_lights2",
        "#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SPECULAR 1",
    ),
    vertex(
        2017,
        "SLS2017_v_specular_lights2_skin",
        "#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SKIN 1",
    ),
    vertex(
        2018,
        "SLS2018_v_specular_lights2_shadow",
        "#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SHADOW 1",
    ),
    vertex(
        2019,
        "SLS2019_v_specular_lights2_shadow_skin",
        "#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SHADOW 1\n#define PBR_OBJECT_SKIN 1",
    ),
    vertex(
        2020,
        "SLS2020_v_lights9",
        "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 9",
    ),
    vertex(
        2021,
        "SLS2021_v_lights9_skin",
        "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 9\n#define PBR_OBJECT_SKIN 1",
    ),
    vertex(
        2022,
        "SLS2022_v_lights4",
        "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 4",
    ),
    vertex(
        2023,
        "SLS2023_v_lights4_opt",
        "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 4\n#define PBR_OBJECT_OPT 1",
    ),
    vertex(
        2024,
        "SLS2024_v_lights4_skin",
        "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 4\n#define PBR_OBJECT_SKIN 1",
    ),
    vertex(
        2025,
        "SLS2025_v_specular_lights4",
        "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 4\n#define PBR_OBJECT_SPECULAR 1",
    ),
    vertex(
        2026,
        "SLS2026_v_specular_lights4_opt",
        "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 4\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_OPT 1",
    ),
    vertex(
        2027,
        "SLS2027_v_specular_lights4_skin",
        "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 4\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SKIN 1",
    ),
    vertex(
        2028,
        "SLS2028_v_only_light_lights2",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_LIGHTS 2",
    ),
    vertex(
        2029,
        "SLS2029_v_only_light_lights2_skin",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SKIN 1",
    ),
    vertex(
        2030,
        "SLS2030_v_only_light_lights2_shadow",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SHADOW 1",
    ),
    vertex(
        2031,
        "SLS2031_v_only_light_lights2_shadow_skin",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SHADOW 1\n#define PBR_OBJECT_SKIN 1",
    ),
    vertex(
        2032,
        "SLS2032_v_only_light_lights3",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_LIGHTS 3",
    ),
    vertex(
        2033,
        "SLS2033_v_only_light_lights3_skin",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_LIGHTS 3\n#define PBR_OBJECT_SKIN 1",
    ),
    vertex(
        2034,
        "SLS2034_v_only_light_lights3_shadow",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_LIGHTS 3\n#define PBR_OBJECT_SHADOW 1",
    ),
    vertex(
        2035,
        "SLS2035_v_only_light_lights3_shadow_skin",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_LIGHTS 3\n#define PBR_OBJECT_SHADOW 1\n#define PBR_OBJECT_SKIN 1",
    ),
    vertex(
        2036,
        "SLS2036_v_diffuse_lights2",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_DIFFUSE 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 2",
    ),
    vertex(
        2037,
        "SLS2037_v_diffuse_lights2_skin",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_DIFFUSE 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SKIN 1",
    ),
    vertex(
        2038,
        "SLS2038_v_diffuse_lights3",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_DIFFUSE 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 3",
    ),
    vertex(
        2039,
        "SLS2039_v_diffuse_lights3_skin",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_DIFFUSE 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 3\n#define PBR_OBJECT_SKIN 1",
    ),
    vertex(
        2040,
        "SLS2040_v_only_specular",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_LIGHTS 1",
    ),
    vertex(
        2041,
        "SLS2041_v_only_specular_skin",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SKIN 1",
    ),
    vertex(
        2042,
        "SLS2042_v_only_specular_shadow",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SHADOW 1",
    ),
    vertex(
        2043,
        "SLS2043_v_only_specular_shadow_skin",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SHADOW 1\n#define PBR_OBJECT_SKIN 1",
    ),
    vertex(
        2044,
        "SLS2044_v_only_specular_point",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 1",
    ),
    vertex(
        2045,
        "SLS2045_v_only_specular_point_skin",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SKIN 1",
    ),
    vertex(
        2046,
        "SLS2046_v_only_specular_point_lights2",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 2",
    ),
    vertex(
        2047,
        "SLS2047_v_only_specular_point_lights2_skin",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SKIN 1",
    ),
    vertex(
        2048,
        "SLS2048_v_only_specular_point_lights3",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 3",
    ),
    vertex(
        2049,
        "SLS2049_v_only_specular_point_lights3_skin",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 3\n#define PBR_OBJECT_SKIN 1",
    ),
];

const OBJECT_PIXEL_TEMPLATES: &[ShaderTemplate] = &[
    pixel(2000, "SLS2000_p", "#define PBR_OBJECT_LIGHTS 1"),
    pixel(
        2001,
        "SLS2001_p_opt",
        "#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_LIGHTS 1",
    ),
    pixel(
        2002,
        "SLS2002_p_opt_lod",
        "#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_LOD 1",
    ),
    pixel(
        2004,
        "SLS2004_p_si",
        "#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SI 1",
    ),
    pixel(
        2005,
        "SLS2005_p_shadow",
        "#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SHADOW 1",
    ),
    pixel(
        2007,
        "SLS2007_p_si_shadow",
        "#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SI 1\n#define PBR_OBJECT_SHADOW 1",
    ),
    pixel(
        2008,
        "SLS2008_p_stbb",
        "#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_STBB 1",
    ),
    pixel(
        2009,
        "SLS2009_p_hair",
        "#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_HAIR 1",
    ),
    pixel(
        2010,
        "SLS2010_p_hair_shadow",
        "#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_HAIR 1\n#define PBR_OBJECT_SHADOW 1",
    ),
    pixel(2011, "SLS2011_p_lights2", "#define PBR_OBJECT_LIGHTS 2"),
    pixel(
        2012,
        "SLS2012_p_lights2_si",
        "#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SI 1",
    ),
    pixel(
        2013,
        "SLS2013_p_lights2_hair",
        "#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_HAIR 1",
    ),
    pixel(
        2014,
        "SLS2014_p_lights2_shadow",
        "#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SHADOW 1",
    ),
    pixel(
        2015,
        "SLS2015_p_lights2_si_shadow",
        "#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SI 1\n#define PBR_OBJECT_SHADOW 1",
    ),
    pixel(
        2016,
        "SLS2016_p_lights2_hair_shadow",
        "#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_HAIR 1\n#define PBR_OBJECT_SHADOW 1",
    ),
    pixel(
        2017,
        "SLS2017_p_specular",
        "#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SPECULAR 1",
    ),
    pixel(
        2018,
        "SLS2018_p_specular_si",
        "#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SI 1",
    ),
    pixel(
        2019,
        "SLS2019_p_specular_hair",
        "#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_HAIR 1",
    ),
    pixel(
        2020,
        "SLS2020_p_specular_shadow",
        "#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SHADOW 1",
    ),
    pixel(
        2021,
        "SLS2021_p_specular_si_shadow",
        "#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SI 1\n#define PBR_OBJECT_SHADOW 1",
    ),
    pixel(
        2022,
        "SLS2022_p_specular_hair_shadow",
        "#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_HAIR 1\n#define PBR_OBJECT_SHADOW 1",
    ),
    pixel(
        2023,
        "SLS2023_p_specular_lights2",
        "#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SPECULAR 1",
    ),
    pixel(
        2024,
        "SLS2024_p_specular_lights2_si",
        "#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SI 1",
    ),
    pixel(
        2026,
        "SLS2026_p_specular_lights2_shadow",
        "#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SHADOW 1",
    ),
    pixel(
        2027,
        "SLS2027_p_specular_lights2_si_shadow",
        "#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SI 1\n#define PBR_OBJECT_SHADOW 1",
    ),
    pixel(
        2029,
        "SLS2029_p_lights9",
        "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 9",
    ),
    pixel(
        2030,
        "SLS2030_p_lights9_si",
        "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 9\n#define PBR_OBJECT_SI 1",
    ),
    pixel(
        2031,
        "SLS2031_p_lights4",
        "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 4",
    ),
    pixel(
        2032,
        "SLS2032_p_lights4_opt",
        "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 4\n#define PBR_OBJECT_OPT 1",
    ),
    pixel(
        2033,
        "SLS2033_p_lights4_si",
        "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 4\n#define PBR_OBJECT_SI 1",
    ),
    pixel(
        2034,
        "SLS2034_p_specular_lights4",
        "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 4\n#define PBR_OBJECT_SPECULAR 1",
    ),
    pixel(
        2035,
        "SLS2035_p_specular_lights4_opt",
        "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 4\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_OPT 1",
    ),
    pixel(
        2036,
        "SLS2036_p_specular_lights4_si",
        "#define PBR_OBJECT_HIGH 1\n#define PBR_OBJECT_LIGHTS 4\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_SI 1",
    ),
    pixel(
        2037,
        "SLS2037_p_only_light_lights2",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_LIGHTS 2",
    ),
    pixel(
        2038,
        "SLS2038_p_only_light_lights2_si",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SI 1",
    ),
    pixel(
        2039,
        "SLS2039_p_only_light_lights2_shadow",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SHADOW 1",
    ),
    pixel(
        2040,
        "SLS2040_p_only_light_lights2_si_shadow",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_SI 1\n#define PBR_OBJECT_SHADOW 1",
    ),
    pixel(
        2041,
        "SLS2041_p_only_light_lights3",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_LIGHTS 3",
    ),
    pixel(
        2042,
        "SLS2042_p_only_light_lights3_si",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_LIGHTS 3\n#define PBR_OBJECT_SI 1",
    ),
    pixel(
        2043,
        "SLS2043_p_only_light_lights3_shadow",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_LIGHTS 3\n#define PBR_OBJECT_SHADOW 1",
    ),
    pixel(
        2044,
        "SLS2044_p_only_light_lights3_si_shadow",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_LIGHTS 3\n#define PBR_OBJECT_SI 1\n#define PBR_OBJECT_SHADOW 1",
    ),
    pixel(
        2045,
        "SLS2045_p_diffuse_lights2",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_DIFFUSE 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 2",
    ),
    pixel(
        2046,
        "SLS2046_p_diffuse_lights3",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_OPT 1\n#define PBR_OBJECT_DIFFUSE 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 3",
    ),
    pixel(
        2047,
        "SLS2047_p_only_specular",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_LIGHTS 1",
    ),
    pixel(
        2048,
        "SLS2048_p_only_specular_hair",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_HAIR 1",
    ),
    pixel(
        2049,
        "SLS2049_p_only_specular_shadow",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_SHADOW 1",
    ),
    pixel(
        2050,
        "SLS2050_p_only_specular_hair_shadow",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_HAIR 1\n#define PBR_OBJECT_SHADOW 1",
    ),
    pixel(
        2051,
        "SLS2051_p_only_specular_point",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 1",
    ),
    pixel(
        2052,
        "SLS2052_p_only_specular_point_hair",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 1\n#define PBR_OBJECT_HAIR 1",
    ),
    pixel(
        2053,
        "SLS2053_p_only_specular_point_lights2",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 2",
    ),
    pixel(
        2054,
        "SLS2054_p_only_specular_point_lights2_hair",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 2\n#define PBR_OBJECT_HAIR 1",
    ),
    pixel(
        2055,
        "SLS2055_p_only_specular_point_lights3",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 3",
    ),
    pixel(
        2056,
        "SLS2056_p_only_specular_point_lights3_hair",
        "#define PBR_OBJECT_ONLY_LIGHT 1\n#define PBR_OBJECT_ONLY_SPECULAR 1\n#define PBR_OBJECT_SPECULAR 1\n#define PBR_OBJECT_POINT 1\n#define PBR_OBJECT_LIGHTS 3\n#define PBR_OBJECT_HAIR 1",
    ),
];

const LAND_LOD_TEMPLATES: &[ShaderTemplate] = &[
    vertex(2002, "SLS2002_v_landlod", ""),
    pixel(2003, "SLS2003_p_landlod", ""),
];

const TERRAIN_FADE_TEMPLATES: &[ShaderTemplate] = &[
    vertex(2080, "SLS2080_v_terrain_fade", ""),
    pixel(2082, "SLS2082_p_terrain_fade", ""),
];

const CLOSE_TERRAIN_TEMPLATES: &[ShaderTemplate] = &[
    vertex(2100, "SLS2100_v_close_terrain", ""),
    pixel(
        2092,
        "SLS2092_p_terrain_t1_l0",
        "#define PBR_TERRAIN_TEX_COUNT 1",
    ),
    pixel(
        2093,
        "SLS2093_p_terrain_t1_l0_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 1",
    ),
    pixel(
        2094,
        "SLS2094_p_terrain_t1_l6",
        "#define PBR_TERRAIN_TEX_COUNT 1\n#define PBR_TERRAIN_POINT_LIGHTS 6",
    ),
    pixel(
        2095,
        "SLS2095_p_terrain_t1_l6_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 1\n#define PBR_TERRAIN_POINT_LIGHTS 6",
    ),
    pixel(
        2096,
        "SLS2096_p_terrain_t1_l12",
        "#define PBR_TERRAIN_TEX_COUNT 1\n#define PBR_TERRAIN_POINT_LIGHTS 12",
    ),
    pixel(
        2097,
        "SLS2097_p_terrain_t1_l12_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 1\n#define PBR_TERRAIN_POINT_LIGHTS 12",
    ),
    pixel(
        2098,
        "SLS2098_p_terrain_t1_l24",
        "#define PBR_TERRAIN_TEX_COUNT 1\n#define PBR_TERRAIN_POINT_LIGHTS 24",
    ),
    pixel(
        2099,
        "SLS2099_p_terrain_t1_l24_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 1\n#define PBR_TERRAIN_POINT_LIGHTS 24",
    ),
    pixel(
        2100,
        "SLS2100_p_terrain_t2_l0",
        "#define PBR_TERRAIN_TEX_COUNT 2",
    ),
    pixel(
        2101,
        "SLS2101_p_terrain_t2_l0_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 2",
    ),
    pixel(
        2102,
        "SLS2102_p_terrain_t2_l6",
        "#define PBR_TERRAIN_TEX_COUNT 2\n#define PBR_TERRAIN_POINT_LIGHTS 6",
    ),
    pixel(
        2103,
        "SLS2103_p_terrain_t2_l6_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 2\n#define PBR_TERRAIN_POINT_LIGHTS 6",
    ),
    pixel(
        2104,
        "SLS2104_p_terrain_t2_l12",
        "#define PBR_TERRAIN_TEX_COUNT 2\n#define PBR_TERRAIN_POINT_LIGHTS 12",
    ),
    pixel(
        2105,
        "SLS2105_p_terrain_t2_l12_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 2\n#define PBR_TERRAIN_POINT_LIGHTS 12",
    ),
    pixel(
        2106,
        "SLS2106_p_terrain_t2_l24",
        "#define PBR_TERRAIN_TEX_COUNT 2\n#define PBR_TERRAIN_POINT_LIGHTS 24",
    ),
    pixel(
        2107,
        "SLS2107_p_terrain_t2_l24_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 2\n#define PBR_TERRAIN_POINT_LIGHTS 24",
    ),
    pixel(
        2108,
        "SLS2108_p_terrain_t3_l0",
        "#define PBR_TERRAIN_TEX_COUNT 3",
    ),
    pixel(
        2109,
        "SLS2109_p_terrain_t3_l0_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 3",
    ),
    pixel(
        2110,
        "SLS2110_p_terrain_t3_l6",
        "#define PBR_TERRAIN_TEX_COUNT 3\n#define PBR_TERRAIN_POINT_LIGHTS 6",
    ),
    pixel(
        2111,
        "SLS2111_p_terrain_t3_l6_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 3\n#define PBR_TERRAIN_POINT_LIGHTS 6",
    ),
    pixel(
        2112,
        "SLS2112_p_terrain_t3_l12",
        "#define PBR_TERRAIN_TEX_COUNT 3\n#define PBR_TERRAIN_POINT_LIGHTS 12",
    ),
    pixel(
        2113,
        "SLS2113_p_terrain_t3_l12_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 3\n#define PBR_TERRAIN_POINT_LIGHTS 12",
    ),
    pixel(
        2114,
        "SLS2114_p_terrain_t3_l24",
        "#define PBR_TERRAIN_TEX_COUNT 3\n#define PBR_TERRAIN_POINT_LIGHTS 24",
    ),
    pixel(
        2115,
        "SLS2115_p_terrain_t3_l24_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 3\n#define PBR_TERRAIN_POINT_LIGHTS 24",
    ),
    pixel(
        2116,
        "SLS2116_p_terrain_t4_l0",
        "#define PBR_TERRAIN_TEX_COUNT 4",
    ),
    pixel(
        2117,
        "SLS2117_p_terrain_t4_l0_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 4",
    ),
    pixel(
        2118,
        "SLS2118_p_terrain_t4_l6",
        "#define PBR_TERRAIN_TEX_COUNT 4\n#define PBR_TERRAIN_POINT_LIGHTS 6",
    ),
    pixel(
        2119,
        "SLS2119_p_terrain_t4_l6_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 4\n#define PBR_TERRAIN_POINT_LIGHTS 6",
    ),
    pixel(
        2120,
        "SLS2120_p_terrain_t4_l12",
        "#define PBR_TERRAIN_TEX_COUNT 4\n#define PBR_TERRAIN_POINT_LIGHTS 12",
    ),
    pixel(
        2121,
        "SLS2121_p_terrain_t4_l12_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 4\n#define PBR_TERRAIN_POINT_LIGHTS 12",
    ),
    pixel(
        2122,
        "SLS2122_p_terrain_t4_l24",
        "#define PBR_TERRAIN_TEX_COUNT 4\n#define PBR_TERRAIN_POINT_LIGHTS 24",
    ),
    pixel(
        2123,
        "SLS2123_p_terrain_t4_l24_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 4\n#define PBR_TERRAIN_POINT_LIGHTS 24",
    ),
    pixel(
        2124,
        "SLS2124_p_terrain_t5_l0",
        "#define PBR_TERRAIN_TEX_COUNT 5",
    ),
    pixel(
        2125,
        "SLS2125_p_terrain_t5_l0_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 5",
    ),
    pixel(
        2126,
        "SLS2126_p_terrain_t5_l6",
        "#define PBR_TERRAIN_TEX_COUNT 5\n#define PBR_TERRAIN_POINT_LIGHTS 6",
    ),
    pixel(
        2127,
        "SLS2127_p_terrain_t5_l6_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 5\n#define PBR_TERRAIN_POINT_LIGHTS 6",
    ),
    pixel(
        2128,
        "SLS2128_p_terrain_t5_l12",
        "#define PBR_TERRAIN_TEX_COUNT 5\n#define PBR_TERRAIN_POINT_LIGHTS 12",
    ),
    pixel(
        2129,
        "SLS2129_p_terrain_t5_l12_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 5\n#define PBR_TERRAIN_POINT_LIGHTS 12",
    ),
    pixel(
        2130,
        "SLS2130_p_terrain_t5_l24",
        "#define PBR_TERRAIN_TEX_COUNT 5\n#define PBR_TERRAIN_POINT_LIGHTS 24",
    ),
    pixel(
        2131,
        "SLS2131_p_terrain_t5_l24_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 5\n#define PBR_TERRAIN_POINT_LIGHTS 24",
    ),
    pixel(
        2132,
        "SLS2132_p_terrain_t6_l0",
        "#define PBR_TERRAIN_TEX_COUNT 6",
    ),
    pixel(
        2133,
        "SLS2133_p_terrain_t6_l0_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 6",
    ),
    pixel(
        2134,
        "SLS2134_p_terrain_t6_l6",
        "#define PBR_TERRAIN_TEX_COUNT 6\n#define PBR_TERRAIN_POINT_LIGHTS 6",
    ),
    pixel(
        2135,
        "SLS2135_p_terrain_t6_l6_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 6\n#define PBR_TERRAIN_POINT_LIGHTS 6",
    ),
    pixel(
        2136,
        "SLS2136_p_terrain_t6_l12",
        "#define PBR_TERRAIN_TEX_COUNT 6\n#define PBR_TERRAIN_POINT_LIGHTS 12",
    ),
    pixel(
        2137,
        "SLS2137_p_terrain_t6_l12_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 6\n#define PBR_TERRAIN_POINT_LIGHTS 12",
    ),
    pixel(
        2138,
        "SLS2138_p_terrain_t6_l24",
        "#define PBR_TERRAIN_TEX_COUNT 6\n#define PBR_TERRAIN_POINT_LIGHTS 24",
    ),
    pixel(
        2139,
        "SLS2139_p_terrain_t6_l24_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 6\n#define PBR_TERRAIN_POINT_LIGHTS 24",
    ),
    pixel(
        2140,
        "SLS2140_p_terrain_t7_l0",
        "#define PBR_TERRAIN_TEX_COUNT 7",
    ),
    pixel(
        2141,
        "SLS2141_p_terrain_t7_l0_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 7",
    ),
    pixel(
        2142,
        "SLS2142_p_terrain_t7_l6",
        "#define PBR_TERRAIN_TEX_COUNT 7\n#define PBR_TERRAIN_POINT_LIGHTS 6",
    ),
    pixel(
        2143,
        "SLS2143_p_terrain_t7_l6_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 7\n#define PBR_TERRAIN_POINT_LIGHTS 6",
    ),
    pixel(
        2144,
        "SLS2144_p_terrain_t7_l12",
        "#define PBR_TERRAIN_TEX_COUNT 7\n#define PBR_TERRAIN_POINT_LIGHTS 12",
    ),
    pixel(
        2145,
        "SLS2145_p_terrain_t7_l12_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 7\n#define PBR_TERRAIN_POINT_LIGHTS 12",
    ),
    pixel(
        2146,
        "SLS2146_p_terrain_t7_l24",
        "#define PBR_TERRAIN_TEX_COUNT 7\n#define PBR_TERRAIN_POINT_LIGHTS 24",
    ),
    pixel(
        2147,
        "SLS2147_p_terrain_t7_l24_canopy",
        "#define PBR_TERRAIN_TEX_COUNT 7\n#define PBR_TERRAIN_POINT_LIGHTS 24",
    ),
];

pub(super) fn summary() -> RegistrySummary {
    RegistrySummary {
        object_records: object_template_count(),
        land_lod_records: LAND_LOD_TEMPLATES.len(),
        terrain_fade_records: TERRAIN_FADE_TEMPLATES.len(),
        close_terrain_records: CLOSE_TERRAIN_TEMPLATES.len(),
    }
}

pub(super) fn object_template_count() -> usize {
    OBJECT_VERTEX_TEMPLATES.len() + OBJECT_PIXEL_TEMPLATES.len()
}

pub(super) fn template_count() -> usize {
    object_template_count()
        + LAND_LOD_TEMPLATES.len()
        + TERRAIN_FADE_TEMPLATES.len()
        + CLOSE_TERRAIN_TEMPLATES.len()
}

pub(super) fn object_template_at(id: u16) -> Option<&'static ShaderTemplate> {
    let index = id as usize;
    if index < OBJECT_VERTEX_TEMPLATES.len() {
        return OBJECT_VERTEX_TEMPLATES.get(index);
    }

    OBJECT_PIXEL_TEMPLATES.get(index - OBJECT_VERTEX_TEMPLATES.len())
}

pub(super) fn template_at(id: u16) -> Option<&'static ShaderTemplate> {
    let index = id as usize;
    if index < object_template_count() {
        return object_template_at(id);
    }

    let mut family_index = index - object_template_count();
    if family_index < LAND_LOD_TEMPLATES.len() {
        return LAND_LOD_TEMPLATES.get(family_index);
    }
    family_index -= LAND_LOD_TEMPLATES.len();
    if family_index < TERRAIN_FADE_TEMPLATES.len() {
        return TERRAIN_FADE_TEMPLATES.get(family_index);
    }
    family_index -= TERRAIN_FADE_TEMPLATES.len();
    CLOSE_TERRAIN_TEMPLATES.get(family_index)
}

pub(super) fn land_lod_template_id(stage: ShaderStage) -> u16 {
    let offset = match stage {
        ShaderStage::Vertex => 0,
        ShaderStage::Pixel => 1,
    };
    (object_template_count() + offset) as u16
}

pub(super) fn template_is_land_lod(id: u16) -> bool {
    let index = id as usize;
    let first = object_template_count();
    index >= first && index < first + LAND_LOD_TEMPLATES.len()
}

pub(super) fn terrain_fade_template_id(stage: ShaderStage) -> u16 {
    let offset = match stage {
        ShaderStage::Vertex => 0,
        ShaderStage::Pixel => 1,
    };
    (object_template_count() + LAND_LOD_TEMPLATES.len() + offset) as u16
}

pub(super) fn close_terrain_template_id(stage: ShaderStage, sls_number: u16) -> Option<u16> {
    let local_index = CLOSE_TERRAIN_TEMPLATES
        .iter()
        .position(|template| template.stage == stage && template.sls_number == sls_number)?;
    Some(
        (object_template_count()
            + LAND_LOD_TEMPLATES.len()
            + TERRAIN_FADE_TEMPLATES.len()
            + local_index) as u16,
    )
}

/// Return the internal native-only resource paired with a close-terrain row.
pub(super) const fn close_terrain_fast_sls(sls_number: u16) -> u16 {
    sls_number & !1
}

/// Return the internal supplemental-light resource paired with a terrain row.
pub(super) const fn close_terrain_supplemental_sls(sls_number: u16) -> u16 {
    close_terrain_fast_sls(sls_number) + 1
}

pub(super) fn template_is_terrain_fade(id: u16) -> bool {
    let index = id as usize;
    let first = object_template_count() + LAND_LOD_TEMPLATES.len();
    index >= first && index < first + TERRAIN_FADE_TEMPLATES.len()
}

pub(super) fn template_is_close_terrain(id: u16) -> bool {
    let index = id as usize;
    let first = object_template_count() + LAND_LOD_TEMPLATES.len() + TERRAIN_FADE_TEMPLATES.len();
    index >= first && index < template_count()
}

pub(super) fn object_template_id(stage: ShaderStage, sls_number: u16) -> Option<TemplateRef> {
    let templates = match stage {
        ShaderStage::Vertex => OBJECT_VERTEX_TEMPLATES,
        ShaderStage::Pixel => OBJECT_PIXEL_TEMPLATES,
    };
    let base = match stage {
        ShaderStage::Vertex => 0,
        ShaderStage::Pixel => OBJECT_VERTEX_TEMPLATES.len(),
    };
    let local_index = templates
        .iter()
        .position(|template| template.sls_number == sls_number)?;

    let id = (base + local_index) as u16;
    Some(TemplateRef {
        id,
        template: &templates[local_index],
    })
}

pub(super) fn object_template_source(template: &ShaderTemplate) -> Cow<'static, [u8]> {
    let mut source = String::new();
    append_nvr_defines(&mut source, template);
    source.push_str("#define main Main\n");
    append_source_without_includes(&mut source, NVR_HELPERS_INCLUDE_SOURCE);
    append_source_without_includes(&mut source, NVR_POINTLIGHTS_INCLUDE_SOURCE);
    append_source_without_includes(&mut source, NVR_PBR_INCLUDE_SOURCE);
    append_source_without_includes(&mut source, NVR_OBJECT_INCLUDE_SOURCE);
    append_source_without_includes(&mut source, NVR_SKIN_HELPERS_INCLUDE_SOURCE);
    append_source_without_includes(&mut source, NVR_OBJECT_TEMPLATE_SOURCE);
    Cow::Owned(source.into_bytes())
}

pub(super) fn object_template_uses_native_specular_fade(template_id: u16) -> bool {
    let Some(template) = object_template_at(template_id) else {
        return false;
    };
    template.stage == ShaderStage::Pixel
        && has_define(template.defines, "PBR_OBJECT_SPECULAR")
        && !has_define(template.defines, "PBR_OBJECT_ONLY_SPECULAR")
}

pub(super) fn object_template_light_count(template_id: u16) -> u32 {
    object_template_at(template_id)
        .and_then(|template| define_u32(template.defines, "PBR_OBJECT_LIGHTS"))
        .unwrap_or(1)
}

pub(super) fn template_source(id: u16, template: &ShaderTemplate) -> Cow<'static, [u8]> {
    if (id as usize) < object_template_count() {
        return object_template_source(template);
    }

    if template_is_land_lod(id) {
        return match template.stage {
            ShaderStage::Vertex => Cow::Borrowed(LAND_LOD_VERTEX_SOURCE.as_bytes()),
            ShaderStage::Pixel => Cow::Borrowed(LAND_LOD_PIXEL_SOURCE.as_bytes()),
        };
    }
    if template_is_terrain_fade(id) {
        return match template.stage {
            ShaderStage::Vertex => Cow::Borrowed(TERRAIN_FADE_VERTEX_SOURCE.as_bytes()),
            ShaderStage::Pixel => Cow::Borrowed(TERRAIN_FADE_PIXEL_SOURCE.as_bytes()),
        };
    }

    match template.stage {
        ShaderStage::Vertex => Cow::Borrowed(CLOSE_TERRAIN_VERTEX_SOURCE.as_bytes()),
        ShaderStage::Pixel => {
            let mut source = String::with_capacity(
                template.defines.len() + CLOSE_TERRAIN_PIXEL_SOURCE.len() + 48,
            );
            // The paired odd resource is no longer a bytecode alias. It is the
            // supplemental program selected only after CPU light capture proves
            // a nonempty payload. No new logical template or D3D resource is
            // introduced, which keeps the established resource catalog stable.
            if template.sls_number & 1 != 0 {
                source.push_str("#define OMV_SUPPLEMENTAL_LIGHTS 1\n");
            }
            source.push_str(template.defines);
            source.push('\n');
            source.push_str(CLOSE_TERRAIN_PIXEL_SOURCE);
            Cow::Owned(source.into_bytes())
        }
    }
}

fn append_nvr_defines(output: &mut String, template: &ShaderTemplate) {
    // NVR's shader loader adds this macro for New Vegas at compile time.
    output.push_str("#define REVERSED_DEPTH 1\n");
    match template.stage {
        ShaderStage::Vertex => output.push_str("#define VS 1\n"),
        ShaderStage::Pixel => output.push_str("#define PS 1\n"),
    }

    let diffuse = has_define(template.defines, "PBR_OBJECT_DIFFUSE");
    let only_specular = has_define(template.defines, "PBR_OBJECT_ONLY_SPECULAR");
    let point = has_define(template.defines, "PBR_OBJECT_POINT") && !diffuse;

    if has_define(template.defines, "PBR_OBJECT_SKIN") {
        output.push_str("#define SKIN 1\n");
    }
    if has_define(template.defines, "PBR_OBJECT_SHADOW") {
        output.push_str("#define PROJ_SHADOW 1\n");
    }
    if has_define(template.defines, "PBR_OBJECT_OPT") && !diffuse {
        output.push_str("#define OPT 1\n");
    }
    if has_define(template.defines, "PBR_OBJECT_ONLY_LIGHT") && !diffuse && !only_specular {
        output.push_str("#define ONLY_LIGHT 1\n");
    }
    if diffuse {
        output.push_str("#define DIFFUSE 1\n");
    }
    if only_specular {
        output.push_str("#define ONLY_SPECULAR 1\n");
    } else if has_define(template.defines, "PBR_OBJECT_SPECULAR") {
        output.push_str("#define SPECULAR 1\n");
    }
    if point {
        output.push_str("#define POINT 1\n");
    }
    if has_define(template.defines, "PBR_OBJECT_SI") {
        output.push_str("#define SI 1\n");
    }
    if has_define(template.defines, "PBR_OBJECT_HAIR") {
        output.push_str("#define HAIR 1\n");
    }
    if has_define(template.defines, "PBR_OBJECT_STBB") {
        output.push_str("#define STBB 1\n");
    }
    if has_define(template.defines, "PBR_OBJECT_LOD") {
        output.push_str("#define LOD 1\n");
    }

    if let Some(lights) = define_u32(template.defines, "PBR_OBJECT_LIGHTS") {
        if only_specular && point {
            if lights > 1 {
                output.push_str(&format!("#define NUM_PT_LIGHTS {lights}\n"));
            }
        } else if lights > 1 {
            output.push_str(&format!("#define LIGHTS {lights}\n"));
        }
    }

    output.push('\n');
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

fn append_source_without_includes(output: &mut String, source: &str) {
    for line in source.lines() {
        if line.trim_start().starts_with("#include") {
            continue;
        }
        output.push_str(line);
        output.push('\n');
    }
    output.push('\n');
}

pub(super) fn shader_profile(stage: ShaderStage) -> &'static str {
    match stage {
        ShaderStage::Vertex => "vs_3_0",
        ShaderStage::Pixel => "ps_3_0",
    }
}

pub(super) fn shader_cache_suffix(stage: ShaderStage) -> &'static str {
    match stage {
        ShaderStage::Vertex => "vso",
        ShaderStage::Pixel => "pso",
    }
}

#[cfg(test)]
mod shader_compile_tests {
    use super::{
        CLOSE_TERRAIN_PIXEL_SOURCE, LAND_LOD_PIXEL_SOURCE, NVR_OBJECT_INCLUDE_SOURCE,
        NVR_OBJECT_TEMPLATE_SOURCE, NVR_PBR_INCLUDE_SOURCE, NVR_POINTLIGHTS_INCLUDE_SOURCE,
        ShaderStage, TERRAIN_FADE_PIXEL_SOURCE, close_terrain_template_id, object_template_at,
        object_template_count, object_template_id, object_template_uses_native_specular_fade,
        shader_profile, template_at, template_count, template_source,
    };

    const VANILLA_ONLY_LIGHT_2_PIXEL: &str =
        include_str!("../../../../analysis/shaders_disasm/shaderpackage019/SLS2037.pso.dis");
    const VANILLA_ONLY_LIGHT_2_VERTEX: &str =
        include_str!("../../../../analysis/shaders_disasm/shaderpackage019/SLS2028.vso.dis");
    const VANILLA_ONLY_LIGHT_3_PIXEL: &str =
        include_str!("../../../../analysis/shaders_disasm/shaderpackage019/SLS2041.pso.dis");
    const VANILLA_ONLY_LIGHT_3_VERTEX: &str =
        include_str!("../../../../analysis/shaders_disasm/shaderpackage019/SLS2032.vso.dis");
    const VANILLA_DIFFUSE_POINT_PIXEL: &str =
        include_str!("../../../../analysis/shaders_disasm/shaderpackage019/SLS2045.pso.dis");
    const VANILLA_DIFFUSE_POINT_VERTEX: &str =
        include_str!("../../../../analysis/shaders_disasm/shaderpackage019/SLS2036.vso.dis");
    const VANILLA_TERRAIN_1_PIXEL: &str =
        include_str!("../../../../analysis/shaders_disasm/shaderpackage019/SLS2092.pso.dis");
    const VANILLA_TERRAIN_1_CANOPY_PIXEL: &str =
        include_str!("../../../../analysis/shaders_disasm/shaderpackage019/SLS2093.pso.dis");
    const VANILLA_TERRAIN_2_PIXEL: &str =
        include_str!("../../../../analysis/shaders_disasm/shaderpackage019/SLS2100.pso.dis");
    const VANILLA_TERRAIN_7_PIXEL: &str =
        include_str!("../../../../analysis/shaders_disasm/shaderpackage019/SLS2140.pso.dis");
    const VPT_TERRAIN_PIXEL_SOURCE: &str = include_str!(
        "../../../../.research/fnv-vanilla-plus-terrain-main/shaders/TerrainTemplate.hlsl"
    );

    mod object_shader_behavior {
        //! D3D9 readback gate for shipped object-to-bloom behavior.
        //!
        //! The fixture renders native package bytecode and the shipped PBR
        //! replacement with identical inputs, then runs both images through the
        //! shipped bloom shader. Assertions are made only on GPU pixels.

        use super::super::{ShaderStage, object_template_id, object_template_source};
        use libpsycho::os::windows::{
            directx9::{
                D3DBLEND_ONE, D3DCLEAR_TARGET, D3DCLEAR_ZBUFFER, D3DCMP_LESSEQUAL, D3DCULL_NONE,
                D3DDEVTYPE_HAL, D3DDEVTYPE_NULLREF, D3DFMT_A8R8G8B8, D3DFMT_A16B16G16R16F,
                D3DFMT_D24S8, D3DFVF_XYZ, D3DMULTISAMPLE_NONE, D3DPOOL_MANAGED, D3DPT_TRIANGLELIST,
                D3DRS_ALPHABLENDENABLE, D3DRS_COLORWRITEENABLE, D3DRS_CULLMODE, D3DRS_DESTBLEND,
                D3DRS_SRCBLEND, D3DRS_ZENABLE, D3DRS_ZFUNC, D3DRS_ZWRITEENABLE, D3DSAMP_ADDRESSU,
                D3DSAMP_ADDRESSV, D3DSAMP_MAGFILTER, D3DSAMP_MINFILTER, D3DSAMP_MIPFILTER,
                D3DTADDRESS_CLAMP, D3DTEXF_NONE, D3DTEXF_POINT, D3DVIEWPORT9, Device9, Device9Ref,
                Surface9, create_direct3d9,
            },
            winapi::{get_active_window, get_desktop_window, get_foreground_window},
        };

        const TEST_SIZE: u32 = 32;
        // Exact native pixel bytecode extracted from the installed
        // high-quality package. Embedding the affected helper rows keeps the
        // GPU oracle independent of a local Fallout installation.
        const NATIVE_2037: &[u32] = &[
            0xFFFF0201, 0x004BFFFE, 0x42415443, 0x0000001C, 0x000000F7, 0xFFFF0201, 0x00000005,
            0x0000001C, 0x20000100, 0x000000F0, 0x00000080, 0x00010002, 0x00060001, 0x00000090,
            0x00000000, 0x000000A0, 0x00040003, 0x00120001, 0x000000B0, 0x00000000, 0x000000C0,
            0x00000003, 0x00020001, 0x000000B0, 0x00000000, 0x000000C8, 0x00010003, 0x00060001,
            0x000000B0, 0x00000000, 0x000000D2, 0x00030002, 0x000E0002, 0x000000E0, 0x00000000,
            0x69626D41, 0x43746E65, 0x726F6C6F, 0xABABAB00, 0x00030001, 0x00040001, 0x00000001,
            0x00000000, 0x65747441, 0x7461756E, 0x4D6E6F69, 0xAB007061, 0x000C0004, 0x00010001,
            0x00000001, 0x00000000, 0x65736142, 0x0070614D, 0x6D726F4E, 0x614D6C61, 0x53500070,
            0x6867694C, 0x6C6F4374, 0xAB00726F, 0x00030001, 0x00040001, 0x0000000A, 0x00000000,
            0x325F7370, 0x4D00625F, 0x6F726369, 0x74666F73, 0x29522820, 0x534C4820, 0x6853204C,
            0x72656461, 0x6D6F4320, 0x656C6970, 0x2E392072, 0x392E3332, 0x322E3934, 0x00383733,
            0x05000051, 0xA00F0000, 0xBF000000, 0x3F800000, 0x00000000, 0x00000000, 0x0200001F,
            0x80000000, 0xB0670001, 0x0200001F, 0x80000000, 0xB0670002, 0x0200001F, 0x80000000,
            0xB02F0004, 0x0200001F, 0x80000000, 0xB0230000, 0x0200001F, 0x90000000, 0xA00F0800,
            0x0200001F, 0x90000000, 0xA00F0801, 0x0200001F, 0x90000000, 0xA00F0804, 0x02000001,
            0x80210000, 0xB0AA0004, 0x02000001, 0x80220000, 0xB0FF0004, 0x03000042, 0x802F0000,
            0x80E40000, 0xA0E40804, 0x03000042, 0x802F0001, 0xB0E40004, 0xA0E40804, 0x03000042,
            0x802F0002, 0xB0E40000, 0xA0E40801, 0x03000042, 0x802F0003, 0xB0E40000, 0xA0E40800,
            0x03000002, 0x80280002, 0x81000001, 0xA0550000, 0x03000002, 0x80380002, 0x81000000,
            0x80FF0002, 0x03000002, 0x80070000, 0x80E40002, 0xA0000000, 0x03000002, 0x80270000,
            0x80E40000, 0x80E40000, 0x02000024, 0x80270001, 0x80E40000, 0x02000024, 0x80270000,
            0xB0E40002, 0x03000008, 0x80380001, 0x80E40001, 0x80E40000, 0x03000008, 0x80310000,
            0x80E40001, 0xB0E40001, 0x03000005, 0x802E0000, 0x80FF0001, 0xA01B0004, 0x03000005,
            0x802E0000, 0x80FF0002, 0x80E40000, 0x04000004, 0x80270000, 0xA0E40003, 0x80000000,
            0x801B0000, 0x03000002, 0x80270003, 0x80E40000, 0xA0E40001, 0x02000001, 0x802F0800,
            0x80E40003, 0x0000FFFF,
        ];
        const NATIVE_2038: &[u32] = &[
            0xFFFF0201, 0x005BFFFE, 0x42415443, 0x0000001C, 0x00000137, 0xFFFF0201, 0x00000007,
            0x0000001C, 0x20000100, 0x00000130, 0x000000A8, 0x00010002, 0x00060001, 0x000000B8,
            0x00000000, 0x000000C8, 0x00040003, 0x00120001, 0x000000D8, 0x00000000, 0x000000E8,
            0x00000003, 0x00020001, 0x000000D8, 0x00000000, 0x000000F0, 0x00020002, 0x000A0001,
            0x000000B8, 0x00000000, 0x000000FF, 0x00030003, 0x000E0001, 0x000000D8, 0x00000000,
            0x00000107, 0x00010003, 0x00060001, 0x000000D8, 0x00000000, 0x00000111, 0x00030002,
            0x000E0002, 0x00000120, 0x00000000, 0x69626D41, 0x43746E65, 0x726F6C6F, 0xABABAB00,
            0x00030001, 0x00040001, 0x00000001, 0x00000000, 0x65747441, 0x7461756E, 0x4D6E6F69,
            0xAB007061, 0x000C0004, 0x00010001, 0x00000001, 0x00000000, 0x65736142, 0x0070614D,
            0x74696D45, 0x636E6174, 0x6C6F4365, 0x4700726F, 0x4D776F6C, 0x4E007061, 0x616D726F,
            0x70614D6C, 0x4C535000, 0x74686769, 0x6F6C6F43, 0xABAB0072, 0x00030001, 0x00040001,
            0x0000000A, 0x00000000, 0x325F7370, 0x4D00625F, 0x6F726369, 0x74666F73, 0x29522820,
            0x534C4820, 0x6853204C, 0x72656461, 0x6D6F4320, 0x656C6970, 0x2E392072, 0x392E3332,
            0x322E3934, 0x00383733, 0x05000051, 0xA00F0000, 0xBF000000, 0x3F800000, 0x00000000,
            0x00000000, 0x0200001F, 0x80000000, 0xB0670001, 0x0200001F, 0x80000000, 0xB0670002,
            0x0200001F, 0x80000000, 0xB02F0004, 0x0200001F, 0x80000000, 0xB0230000, 0x0200001F,
            0x90000000, 0xA00F0800, 0x0200001F, 0x90000000, 0xA00F0801, 0x0200001F, 0x90000000,
            0xA00F0803, 0x0200001F, 0x90000000, 0xA00F0804, 0x02000001, 0x80210000, 0xB0AA0004,
            0x02000001, 0x80220000, 0xB0FF0004, 0x03000042, 0x802F0000, 0x80E40000, 0xA0E40804,
            0x03000042, 0x802F0001, 0xB0E40004, 0xA0E40804, 0x03000042, 0x802F0002, 0xB0E40000,
            0xA0E40801, 0x03000042, 0x800F0003, 0xB0E40000, 0xA0E40803, 0x03000042, 0x802F0004,
            0xB0E40000, 0xA0E40800, 0x03000002, 0x80280002, 0x81000001, 0xA0550000, 0x03000002,
            0x80380002, 0x81000000, 0x80FF0002, 0x03000002, 0x80070000, 0x80E40002, 0xA0000000,
            0x03000002, 0x80270000, 0x80E40000, 0x80E40000, 0x02000024, 0x80270001, 0x80E40000,
            0x02000024, 0x80270000, 0xB0E40002, 0x03000008, 0x80380001, 0x80E40001, 0x80E40000,
            0x03000008, 0x80380003, 0x80E40001, 0xB0E40001, 0x03000005, 0x80270000, 0x80FF0001,
            0xA0E40004, 0x03000005, 0x80270000, 0x80FF0002, 0x80E40000, 0x04000004, 0x80270000,
            0xA0E40003, 0x80FF0003, 0x80E40000, 0x02000001, 0x80070001, 0xA0E40002, 0x04000004,
            0x80270001, 0x80E40001, 0x80E40003, 0xA0E40001, 0x03000002, 0x80270004, 0x80E40000,
            0x80E40001, 0x02000001, 0x802F0800, 0x80E40004, 0x0000FFFF,
        ];
        // Executable tokens from installed high-quality package 019 SLS2034.
        // The non-semantic CTAB comment is omitted; all shader instructions
        // remain byte-for-byte native.
        const NATIVE_2034: &[u32] = &[
            0xFFFF0201, 0x05000051, 0xA00F0000, 0x40000000, 0x00000000, 0x3F800000, 0x00000000,
            0x05000051, 0xA00F0006, 0xBF000000, 0x3F800000, 0x3E4CCCCD, 0x3F000000, 0x0200001F,
            0x80000000, 0xB0070002, 0x0200001F, 0x80000000, 0xB0070003, 0x0200001F, 0x80000000,
            0xB0070004, 0x0200001F, 0x80000000, 0xB0070005, 0x0200001F, 0x80000000, 0xB0070006,
            0x0200001F, 0x80000000, 0xB0070007, 0x0200001F, 0x80000000, 0xB0030000, 0x0200001F,
            0x80000000, 0xB00F0001, 0x0200001F, 0x80000000, 0x90070000, 0x0200001F, 0x80000000,
            0x900F0001, 0x0200001F, 0x90000000, 0xA00F0800, 0x0200001F, 0x90000000, 0xA00F0801,
            0x03000042, 0x802F0000, 0xB0E40000, 0xA0E40800, 0x02000001, 0x80280001, 0xA0550006,
            0x03000002, 0x80010001, 0x81FF0001, 0xA0FF0001, 0x04000058, 0x80010001, 0x80000001,
            0xA0550000, 0xA0AA0000, 0x03000002, 0x80020001, 0x80FF0000, 0xA1FF001B, 0x03000005,
            0x800F0002, 0x80000001, 0x80550001, 0x01000041, 0x800F0002, 0x03000042, 0x802F0002,
            0xB0E40000, 0xA0E40801, 0x03000005, 0x80270001, 0x80E40000, 0x90E40000, 0x04000058,
            0x80270000, 0xA100001B, 0x80E40000, 0x80E40001, 0x03000005, 0x80280003, 0x80FF0000,
            0xA0FF0001, 0x03000002, 0x80070001, 0xB1E40001, 0xA0E40013, 0x02000006, 0x80080000,
            0xA0FF0013, 0x03000005, 0x80270001, 0x80E40001, 0x80FF0000, 0x03000008, 0x80320001,
            0x80E40001, 0x80E40001, 0x03000002, 0x80070004, 0xB1E40001, 0xA0E40014, 0x02000006,
            0x80080000, 0xA0FF0014, 0x03000005, 0x80270004, 0x80E40004, 0x80FF0000, 0x03000008,
            0x80340001, 0x80E40004, 0x80E40004, 0x03000002, 0x80260001, 0x81E40001, 0xA0550006,
            0x02000024, 0x80270004, 0xB0E40005, 0x03000002, 0x80070002, 0x80E40002, 0xA0000006,
            0x03000002, 0x80270002, 0x80E40002, 0x80E40002, 0x02000024, 0x80270005, 0x80E40002,
            0x03000008, 0x80380000, 0x80E40005, 0x80E40004, 0x0200000F, 0x80210002, 0x80FF0000,
            0x02000024, 0x80270004, 0xB0E40006, 0x03000008, 0x80380000, 0x80E40005, 0x80E40004,
            0x0200000F, 0x80220002, 0x80FF0000, 0x02000024, 0x80270004, 0xB0E40007, 0x03000008,
            0x80380000, 0x80E40005, 0x80E40004, 0x0200000F, 0x80240002, 0x80FF0000, 0x03000005,
            0x80270002, 0x80E40002, 0xA0AA001B, 0x0200000E, 0x80210004, 0x80000002, 0x0200000E,
            0x80220004, 0x80550002, 0x0200000E, 0x80240004, 0x80AA0002, 0x03000005, 0x80270002,
            0x80FF0002, 0x80E40004, 0x02000001, 0x80210001, 0xA0550006, 0x03000005, 0x80270002,
            0x80E40001, 0x80E40002, 0x03000008, 0x80220004, 0x80E40005, 0xB0E40003, 0x03000008,
            0x80240004, 0x80E40005, 0xB0E40004, 0x03000008, 0x80210004, 0x80E40005, 0xB0E40002,
            0x02000001, 0x80380000, 0x80000004, 0x03000005, 0x80270006, 0x80FF0000, 0xA0E40003,
            0x03000002, 0x80370007, 0x80E40004, 0xA0FF0006, 0x03000002, 0x80070004, 0x81E40004,
            0xA0AA0006, 0x03000005, 0x80270007, 0x80E40002, 0x80E40007, 0x04000058, 0x80270002,
            0x80E40004, 0x80E40007, 0x80E40002, 0x03000005, 0x80270004, 0x80000002, 0xA0E40003,
            0x04000004, 0x80270007, 0x80550002, 0xA0E40004, 0x80E40004, 0x03000002, 0x80080000,
            0x80FF0001, 0xA1FF0002, 0x04000058, 0x80270004, 0x80FF0000, 0x80E40004, 0x80E40007,
            0x04000004, 0x80270002, 0x80AA0002, 0xA0E40005, 0x80E40004, 0x02000001, 0x80280002,
            0xA0000000, 0x03000002, 0x80080002, 0x80FF0002, 0xA1FF0002, 0x04000058, 0x80270002,
            0x80FF0002, 0x80E40004, 0x80E40002, 0x03000005, 0x80270002, 0x80E40002, 0xB0FF0001,
            0x02000024, 0x80270004, 0xB0E40003, 0x03000008, 0x80380005, 0x80E40005, 0x80E40004,
            0x03000005, 0x80270004, 0x80FF0005, 0xA0E40004, 0x04000004, 0x80270004, 0x80E40004,
            0x80550001, 0x80E40006, 0x04000058, 0x80270004, 0x80FF0000, 0x80E40006, 0x80E40004,
            0x02000024, 0x80270006, 0xB0E40004, 0x03000008, 0x80380000, 0x80E40005, 0x80E40006,
            0x03000005, 0x80270005, 0x80FF0000, 0xA0E40005, 0x04000004, 0x80270001, 0x80E40005,
            0x80AA0001, 0x80E40004, 0x04000058, 0x80270001, 0x80FF0002, 0x80E40004, 0x80E40001,
            0x03000002, 0x80270001, 0x80E40001, 0xA0E40001, 0x0300000B, 0x80270004, 0x80E40001,
            0xA0550000, 0x04000004, 0x80270000, 0x80E40004, 0x80E40000, 0x80E40002, 0x04000012,
            0x80270001, 0x90FF0001, 0x90E40001, 0x80E40000, 0x04000058, 0x80270003, 0xA155001B,
            0x80E40000, 0x80E40001, 0x02000001, 0x802F0800, 0x80E40003, 0x0000FFFF,
        ];
        const NATIVE_2045: &[u32] = &[
            0xFFFF0201, 0x0037FFFE, 0x42415443, 0x0000001C, 0x000000A7, 0xFFFF0201, 0x00000003,
            0x0000001C, 0x20000100, 0x000000A0, 0x00000058, 0x00030003, 0x000E0001, 0x00000068,
            0x00000000, 0x00000078, 0x00000003, 0x00020001, 0x00000068, 0x00000000, 0x00000082,
            0x00030002, 0x000E0002, 0x00000090, 0x00000000, 0x65747441, 0x7461756E, 0x4D6E6F69,
            0xAB007061, 0x000C0004, 0x00010001, 0x00000001, 0x00000000, 0x6D726F4E, 0x614D6C61,
            0x53500070, 0x6867694C, 0x6C6F4374, 0xAB00726F, 0x00030001, 0x00040001, 0x0000000A,
            0x00000000, 0x325F7370, 0x4D00625F, 0x6F726369, 0x74666F73, 0x29522820, 0x534C4820,
            0x6853204C, 0x72656461, 0x6D6F4320, 0x656C6970, 0x2E392072, 0x392E3332, 0x322E3934,
            0x00383733, 0x05000051, 0xA00F0000, 0xBF000000, 0x3F800000, 0x00000000, 0x00000000,
            0x0200001F, 0x80000000, 0xB0670001, 0x0200001F, 0x80000000, 0xB0670002, 0x0200001F,
            0x80000000, 0xB02F0004, 0x0200001F, 0x80000000, 0xB02F0005, 0x0200001F, 0x80000000,
            0xB0230000, 0x0200001F, 0x90000000, 0xA00F0800, 0x0200001F, 0x90000000, 0xA00F0803,
            0x02000001, 0x80210000, 0xB0AA0005, 0x02000001, 0x80220000, 0xB0FF0005, 0x02000001,
            0x80210001, 0xB0AA0004, 0x02000001, 0x80220001, 0xB0FF0004, 0x03000042, 0x802F0000,
            0x80E40000, 0xA0E40803, 0x03000042, 0x802F0002, 0xB0E40005, 0xA0E40803, 0x03000042,
            0x802F0003, 0xB0E40000, 0xA0E40800, 0x03000042, 0x802F0001, 0x80E40001, 0xA0E40803,
            0x03000042, 0x802F0004, 0xB0E40004, 0xA0E40803, 0x03000002, 0x80280003, 0x81000002,
            0xA0550000, 0x03000002, 0x80380003, 0x81000000, 0x80FF0003, 0x03000002, 0x80070000,
            0x80E40003, 0xA0000000, 0x03000002, 0x80270000, 0x80E40000, 0x80E40000, 0x02000024,
            0x80270002, 0x80E40000, 0x02000024, 0x80270000, 0xB0E40002, 0x03000008, 0x80380002,
            0x80E40002, 0x80E40000, 0x03000005, 0x80270000, 0x80FF0002, 0xA0E40004, 0x03000005,
            0x80270000, 0x80FF0003, 0x80E40000, 0x03000002, 0x80280000, 0x81000004, 0xA0550000,
            0x03000002, 0x80380000, 0x81000001, 0x80FF0000, 0x02000024, 0x80270001, 0xB0E40001,
            0x03000008, 0x80310001, 0x80E40002, 0x80E40001, 0x03000005, 0x80270001, 0x80000001,
            0xA0E40003, 0x04000004, 0x80270000, 0x80E40001, 0x80FF0000, 0x80E40000, 0x02000001,
            0x80280000, 0xA0550000, 0x02000001, 0x802F0800, 0x80E40000, 0x0000FFFF,
        ];
        const NATIVE_2046: &[u32] = &[
            0xFFFF0201, 0x0037FFFE, 0x42415443, 0x0000001C, 0x000000A7, 0xFFFF0201, 0x00000003,
            0x0000001C, 0x20000100, 0x000000A0, 0x00000058, 0x00030003, 0x000E0001, 0x00000068,
            0x00000000, 0x00000078, 0x00000003, 0x00020001, 0x00000068, 0x00000000, 0x00000082,
            0x00030002, 0x000E0003, 0x00000090, 0x00000000, 0x65747441, 0x7461756E, 0x4D6E6F69,
            0xAB007061, 0x000C0004, 0x00010001, 0x00000001, 0x00000000, 0x6D726F4E, 0x614D6C61,
            0x53500070, 0x6867694C, 0x6C6F4374, 0xAB00726F, 0x00030001, 0x00040001, 0x0000000A,
            0x00000000, 0x325F7370, 0x4D00625F, 0x6F726369, 0x74666F73, 0x29522820, 0x534C4820,
            0x6853204C, 0x72656461, 0x6D6F4320, 0x656C6970, 0x2E392072, 0x392E3332, 0x322E3934,
            0x00383733, 0x05000051, 0xA00F0000, 0xBF000000, 0x3F800000, 0x00000000, 0x00000000,
            0x0200001F, 0x80000000, 0xB0670001, 0x0200001F, 0x80000000, 0xB0670002, 0x0200001F,
            0x80000000, 0xB0670003, 0x0200001F, 0x80000000, 0xB02F0004, 0x0200001F, 0x80000000,
            0xB02F0005, 0x0200001F, 0x80000000, 0xB02F0006, 0x0200001F, 0x80000000, 0xB0230000,
            0x0200001F, 0x90000000, 0xA00F0800, 0x0200001F, 0x90000000, 0xA00F0803, 0x02000001,
            0x80210000, 0xB0AA0004, 0x02000001, 0x80220000, 0xB0FF0004, 0x02000001, 0x80210001,
            0xB0AA0005, 0x02000001, 0x80220001, 0xB0FF0005, 0x02000001, 0x80210002, 0xB0AA0006,
            0x02000001, 0x80220002, 0xB0FF0006, 0x03000042, 0x802F0000, 0x80E40000, 0xA0E40803,
            0x03000042, 0x802F0003, 0xB0E40004, 0xA0E40803, 0x03000042, 0x802F0001, 0x80E40001,
            0xA0E40803, 0x03000042, 0x802F0004, 0xB0E40005, 0xA0E40803, 0x03000042, 0x802F0005,
            0xB0E40000, 0xA0E40800, 0x03000042, 0x802F0002, 0x80E40002, 0xA0E40803, 0x03000042,
            0x802F0006, 0xB0E40006, 0xA0E40803, 0x03000002, 0x80280005, 0x81000003, 0xA0550000,
            0x03000002, 0x80380005, 0x81000000, 0x80FF0005, 0x03000002, 0x80210000, 0x81000004,
            0xA0550000, 0x03000002, 0x80310000, 0x81000001, 0x80000000, 0x02000024, 0x80270001,
            0xB0E40002, 0x03000002, 0x800E0000, 0x801B0005, 0xA0000000, 0x03000002, 0x80270003,
            0x801B0000, 0x801B0000, 0x02000024, 0x80270004, 0x80E40003, 0x03000008, 0x80380004,
            0x80E40004, 0x80E40001, 0x03000005, 0x802E0000, 0x80FF0004, 0xA01B0004, 0x03000005,
            0x80270000, 0x80000000, 0x801B0000, 0x02000024, 0x80270001, 0xB0E40001, 0x03000008,
            0x80380000, 0x80E40004, 0x80E40001, 0x03000005, 0x80270001, 0x80FF0000, 0xA0E40003,
            0x04000004, 0x80270000, 0x80E40001, 0x80FF0005, 0x80E40000, 0x03000002, 0x80280000,
            0x81000006, 0xA0550000, 0x03000002, 0x80380000, 0x81000002, 0x80FF0000, 0x02000024,
            0x80270001, 0xB0E40003, 0x03000008, 0x80310001, 0x80E40004, 0x80E40001, 0x03000005,
            0x80270001, 0x80000001, 0xA0E40005, 0x04000004, 0x80270000, 0x80E40001, 0x80FF0000,
            0x80E40000, 0x02000001, 0x80280000, 0xA0550000, 0x02000001, 0x802F0800, 0x80E40000,
            0x0000FFFF,
        ];
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct PositionVertex {
            position: [f32; 3],
        }

        fn raster_device() -> Device9 {
            let window = [
                get_active_window(),
                get_foreground_window(),
                get_desktop_window().unwrap_or(std::ptr::null_mut()),
            ]
            .into_iter()
            .find(|window| !window.is_null())
            .expect("Wine must expose a window for object shader validation");
            let direct3d = create_direct3d9().expect("D3D9 runtime");
            direct3d
                .create_windowed_device(window, TEST_SIZE, TEST_SIZE, D3DDEVTYPE_HAL)
                .or_else(|_| {
                    direct3d.create_windowed_device(
                        window,
                        TEST_SIZE,
                        TEST_SIZE,
                        D3DDEVTYPE_NULLREF,
                    )
                })
                .expect("HAL or NULLREF D3D9 device")
        }

        fn set_point_clamp_sampler(device: &Device9Ref<'_>, stage: u32) {
            device
                .set_sampler_state(stage, D3DSAMP_ADDRESSU, D3DTADDRESS_CLAMP.0 as u32)
                .expect("clamp U");
            device
                .set_sampler_state(stage, D3DSAMP_ADDRESSV, D3DTADDRESS_CLAMP.0 as u32)
                .expect("clamp V");
            device
                .set_sampler_state(stage, D3DSAMP_MINFILTER, D3DTEXF_POINT.0 as u32)
                .expect("point minification");
            device
                .set_sampler_state(stage, D3DSAMP_MAGFILTER, D3DTEXF_POINT.0 as u32)
                .expect("point magnification");
            device
                .set_sampler_state(stage, D3DSAMP_MIPFILTER, D3DTEXF_NONE.0 as u32)
                .expect("no mip filter");
        }

        fn read_pixels(device: &Device9Ref<'_>, surface: &Surface9) -> Vec<[f32; 4]> {
            let staging = device
                .create_system_memory_surface(TEST_SIZE, TEST_SIZE, D3DFMT_A16B16G16R16F)
                .expect("object shader readback surface");
            device
                .copy_render_target_data(surface, &staging)
                .expect("object shader render-target readback");
            staging.read_rgba16f().expect("object shader HDR pixels")
        }

        fn only_light_fixture_vertex_source() -> &'static [u8] {
            br#"
struct Input { float4 position : POSITION; };
struct Output {
    float4 position : POSITION;
    float4 fogColor : COLOR1;
    float2 uv : TEXCOORD0;
    float4 lightDir : TEXCOORD1;
    float4 light2Dir : TEXCOORD2;
    float4 light3Dir : TEXCOORD3;
    float4 light2Attenuation : TEXCOORD4;
    float4 light3Attenuation : TEXCOORD5;
    float3 viewDir : TEXCOORD6;
};
Output Main(Input input) {
    Output output;
    output.position = input.position;
    output.fogColor = 0.0;
    output.uv = 0.5;
    output.lightDir = float4(0.0, 0.0, 1.0, 0.0);
    output.light2Dir = float4(0.0, 0.0, 1.0, 0.0);
    output.light3Dir = 0.0;
    output.light2Attenuation = 0.5;
    output.light3Attenuation = 0.5;
    output.viewDir = float3(0.0, 0.0, 1.0);
    return output;
}
"#
        }

        fn render_only_light_pixel_shader(
            device: &Device9Ref<'_>,
            native: bool,
            self_illuminated: bool,
        ) -> (Vec<[f32; 4]>, Vec<[f32; 4]>) {
            let vertex_bytecode = crate::shaders::compile_hlsl_source_target(
                "only_light_behavior.vs",
                only_light_fixture_vertex_source(),
                "vs_3_0",
            )
            .expect("only-light fixture vertex shader");
            let sls = if self_illuminated { 2038 } else { 2037 };
            let pixel_bytecode = if native {
                if self_illuminated {
                    NATIVE_2038.to_vec()
                } else {
                    NATIVE_2037.to_vec()
                }
            } else {
                let template = object_template_id(ShaderStage::Pixel, sls)
                    .expect("only-light object pixel template")
                    .template;
                crate::shaders::compile_hlsl_source_target(
                    "pbr_only_light_behavior.ps",
                    object_template_source(template).as_ref(),
                    "ps_3_0",
                )
                .expect("shipped PBR only-light pixel shader")
            };
            let vertex_shader = device
                .create_vertex_shader(&vertex_bytecode)
                .expect("only-light fixture vertex object");
            let pixel_shader = device
                .create_pixel_shader(&pixel_bytecode)
                .expect("only-light pixel object");

            let base = device
                .create_texture(1, 1, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)
                .expect("only-light base texture");
            base.write_level0_argb_pixel(0xFF08_0410)
                .expect("only-light base texel");
            let normal = device
                .create_texture(1, 1, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)
                .expect("only-light normal texture");
            normal
                .write_level0_argb_pixel(0xFF80_80FF)
                .expect("only-light normal texel");
            let glow = device
                .create_texture(1, 1, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)
                .expect("only-light glow texture");
            glow.write_level0_argb_pixel(0xFF40_4020)
                .expect("only-light glow texel");
            let attenuation = device
                .create_texture(1, 1, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)
                .expect("only-light attenuation texture");
            attenuation
                .write_level0_argb_pixel(0xFF00_0000)
                .expect("only-light attenuation texel");
            let output = device
                .create_render_target_texture(TEST_SIZE, TEST_SIZE, D3DFMT_A16B16G16R16F)
                .expect("only-light HDR target");
            let surface = output.surface_level(0).expect("only-light HDR surface");

            device
                .set_render_target(0, &surface)
                .expect("only-light HDR binding");
            device
                .set_depth_stencil_surface(None)
                .expect("no only-light depth surface");
            device
                .set_viewport(&D3DVIEWPORT9 {
                    X: 0,
                    Y: 0,
                    Width: TEST_SIZE,
                    Height: TEST_SIZE,
                    MinZ: 0.0,
                    MaxZ: 1.0,
                })
                .expect("only-light viewport");
            device
                .clear_attachments(D3DCLEAR_TARGET as u32, 0, 1.0, 0)
                .expect("clear only-light target");
            device.set_fvf(D3DFVF_XYZ).expect("only-light position FVF");
            device
                .set_vertex_shader(&vertex_shader)
                .expect("only-light fixture vertex shader");
            device
                .set_pixel_shader(&pixel_shader)
                .expect("only-light pixel shader");
            device
                .set_texture(0, &base)
                .expect("only-light base sampler");
            device
                .set_texture(1, &normal)
                .expect("only-light normal sampler");
            device
                .set_texture(3, &glow)
                .expect("only-light glow sampler");
            device
                .set_texture(4, &attenuation)
                .expect("only-light attenuation sampler");
            for stage in [0, 1, 3, 4] {
                set_point_clamp_sampler(device, stage);
            }
            device
                .set_render_state(D3DRS_ZENABLE, 0)
                .expect("disable only-light depth test");
            device
                .set_render_state(D3DRS_ZWRITEENABLE, 0)
                .expect("disable only-light depth writes");
            device
                .set_render_state(D3DRS_ALPHABLENDENABLE, 0)
                .expect("disable only-light blending");
            device
                .set_render_state(D3DRS_COLORWRITEENABLE, 0xF)
                .expect("enable only-light color writes");
            device
                .set_render_state(D3DRS_CULLMODE, D3DCULL_NONE.0 as u32)
                .expect("disable only-light culling");

            let mut constants = [[0.0f32; 4]; 34];
            constants[1] = [0.02, 0.015, 0.01, 1.0];
            constants[2] = [0.15, 0.08, 0.04, 1.0];
            constants[3] = [0.42, 0.18, 0.08, 0.0];
            constants[4] = [0.36, 0.15, 0.06, 0.0];
            constants[32] = [0.0, 0.751_681_4, 1.315_789, 0.865_497_1];
            constants[33] = [1.0, 0.0, 0.0, 0.0];
            device
                .set_pixel_shader_constant_f(0, &constants)
                .expect("only-light pixel constants");

            let triangle = [
                PositionVertex {
                    position: [-1.0, -1.0, 0.5],
                },
                PositionVertex {
                    position: [3.0, -1.0, 0.5],
                },
                PositionVertex {
                    position: [-1.0, 3.0, 0.5],
                },
            ];
            device
                .begin_scene()
                .expect("begin only-light behavior draw");
            unsafe {
                device
                    .draw_primitive_up(D3DPT_TRIANGLELIST, 1, &triangle)
                    .expect("only-light behavior draw");
            }
            device.end_scene().expect("end only-light behavior draw");
            let object_pixels = read_pixels(device, &surface);
            let bloom_pixels = render_bloom_extract(device, &output);
            (object_pixels, bloom_pixels)
        }

        fn diffuse_point_fixture_vertex_source() -> &'static [u8] {
            br#"
float4 FixtureLight : register(c0);
float4 FixtureView : register(c1);

struct Input { float4 position : POSITION; };
struct Output {
    float4 position : POSITION;
    float4 fogColor : COLOR1;
    float2 uv : TEXCOORD0;
    float4 lightDir : TEXCOORD1;
    float4 light2Dir : TEXCOORD2;
    float4 light3Dir : TEXCOORD3;
    float4 lightAttenuation : TEXCOORD4;
    float4 light2Attenuation : TEXCOORD5;
    float4 light3Attenuation : TEXCOORD6;
    float3 viewDir : TEXCOORD7;
};

Output Main(Input input) {
    Output output;
    float3 view = normalize(FixtureView.xyz);
    output.position = input.position;
    output.fogColor = 0.0;
    output.uv = 0.5;
    output.lightDir = FixtureLight;
    output.light2Dir = FixtureLight;
    output.light3Dir = FixtureLight;
    output.lightAttenuation = 0.5;
    output.light2Attenuation = 0.5;
    output.light3Attenuation = 0.5;
    output.viewDir = view;
    return output;
}
"#
        }

        fn high_light_fixture_vertex_source() -> &'static [u8] {
            br#"
float4 FixtureLight : register(c0);
float4 FixtureView : register(c1);

struct Input { float4 position : POSITION; };
struct Output {
    float4 position : POSITION;
    float4 vertexColor : COLOR0;
    float4 fogColor : COLOR1;
    float2 uv : TEXCOORD0;
    float4 localPosition : TEXCOORD1;
    float4 lightDir : TEXCOORD2;
    float4 light2Dir : TEXCOORD3;
    float4 light3Dir : TEXCOORD4;
    float3 halfway : TEXCOORD5;
    float3 halfway2 : TEXCOORD6;
    float3 halfway3 : TEXCOORD7;
};

Output Main(Input input) {
    Output output;
    float3 light = normalize(FixtureLight.xyz);
    // Match the native high-row contract: view is normalized per vertex and
    // its halfway vectors are then interpolated independently of the packed
    // view components consumed by OMV's per-pixel PBR response.
    float3 localPosition = float3(input.position.xy, 0.0);
    float3 view = normalize(FixtureView.xyz * FixtureView.w - localPosition);
    output.position = input.position;
    output.vertexColor = 1.0;
    output.fogColor = 0.0;
    output.uv = 0.5;
    output.localPosition = float4(0.0, 0.0, 0.0, FixtureLight.w);
    output.lightDir = float4(light, view.x);
    output.light2Dir = float4(light, view.y);
    output.light3Dir = float4(light, view.z);
    output.halfway = normalize(light + view);
    output.halfway2 = output.halfway;
    output.halfway3 = output.halfway;
    return output;
}
"#
        }

        fn append_fence_bar(vertices: &mut Vec<PositionVertex>, rising: bool, offset: f32) {
            let x0 = -1.6;
            let x1 = 1.6;
            let half_width = 0.025;
            let slope = if rising { 1.0 } else { -1.0 };
            let p0 = PositionVertex {
                position: [x0, slope * x0 + offset - half_width, 0.2],
            };
            let p1 = PositionVertex {
                position: [x1, slope * x1 + offset - half_width, 0.2],
            };
            let p2 = PositionVertex {
                position: [x1, slope * x1 + offset + half_width, 0.2],
            };
            let p3 = PositionVertex {
                position: [x0, slope * x0 + offset + half_width, 0.2],
            };
            vertices.extend_from_slice(&[p0, p1, p2, p0, p2, p3]);
        }

        fn render_diffuse_point_fence_scene(
            device: &Device9Ref<'_>,
            native: bool,
            light_count: u32,
            camera_angle_degrees: f32,
        ) -> (Vec<[f32; 4]>, Vec<[f32; 4]>) {
            let fixture_vertex_bytecode = crate::shaders::compile_hlsl_source_target(
                "diffuse_point_fence_behavior.vs",
                diffuse_point_fixture_vertex_source(),
                "vs_3_0",
            )
            .expect("only-specular fence fixture vertex shader");
            let solid_vertex_bytecode = crate::shaders::compile_hlsl_source_target(
                "object_fence_depth.vs",
                br#"
struct Input { float4 position : POSITION; };
float4 Main(Input input) : POSITION { return input.position; }
"#,
                "vs_3_0",
            )
            .expect("fence depth vertex shader");
            let solid_pixel_bytecode = crate::shaders::compile_hlsl_source_target(
                "object_fence_depth.ps",
                br#"float4 Main() : COLOR0 { return float4(0.035, 0.035, 0.035, 1.0); }"#,
                "ps_3_0",
            )
            .expect("fence depth pixel shader");
            let sls = match light_count {
                2 => 2045,
                3 => 2046,
                _ => panic!("unsupported diffuse-point light count"),
            };
            let pixel_bytecode = if native {
                if light_count == 2 {
                    NATIVE_2045.to_vec()
                } else {
                    NATIVE_2046.to_vec()
                }
            } else {
                let template = object_template_id(ShaderStage::Pixel, sls)
                    .expect("diffuse-point object pixel template")
                    .template;
                crate::shaders::compile_hlsl_source_target(
                    "pbr_diffuse_point_fence_behavior.ps",
                    object_template_source(template).as_ref(),
                    "ps_3_0",
                )
                .expect("shipped PBR two-light diffuse-point pixel shader")
            };
            let fixture_vertex_shader = device
                .create_vertex_shader(&fixture_vertex_bytecode)
                .expect("diffuse-point fixture vertex object");
            let solid_vertex_shader = device
                .create_vertex_shader(&solid_vertex_bytecode)
                .expect("fence depth vertex object");
            let solid_pixel_shader = device
                .create_pixel_shader(&solid_pixel_bytecode)
                .expect("fence depth pixel object");
            let pixel_shader = device
                .create_pixel_shader(&pixel_bytecode)
                .expect("diffuse-point pixel object");

            let normal = device
                .create_texture(1, 1, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)
                .expect("diffuse-point normal texture");
            normal
                .write_level0_argb_pixel(0xFF80_80FF)
                .expect("diffuse-point normal texel");
            let attenuation = device
                .create_texture(1, 1, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)
                .expect("diffuse-point attenuation texture");
            attenuation
                .write_level0_argb_pixel(0xFF00_0000)
                .expect("diffuse-point attenuation texel");
            let output = device
                .create_render_target_texture(TEST_SIZE, TEST_SIZE, D3DFMT_A16B16G16R16F)
                .expect("only-specular fence HDR target");
            let surface = output
                .surface_level(0)
                .expect("only-specular fence HDR surface");
            let depth = device
                .create_depth_stencil_surface(
                    TEST_SIZE,
                    TEST_SIZE,
                    D3DFMT_D24S8,
                    D3DMULTISAMPLE_NONE,
                    0,
                    true,
                )
                .expect("only-specular fence depth surface");

            device
                .set_render_target(0, &surface)
                .expect("only-specular fence HDR binding");
            device
                .set_depth_stencil_surface(Some(&depth))
                .expect("only-specular fence depth binding");
            device
                .set_viewport(&D3DVIEWPORT9 {
                    X: 0,
                    Y: 0,
                    Width: TEST_SIZE,
                    Height: TEST_SIZE,
                    MinZ: 0.0,
                    MaxZ: 1.0,
                })
                .expect("only-specular fence viewport");
            device
                .clear_attachments(
                    D3DCLEAR_TARGET as u32 | D3DCLEAR_ZBUFFER as u32,
                    0xFF10_1010,
                    1.0,
                    0,
                )
                .expect("clear only-specular fence scene");
            device
                .set_fvf(D3DFVF_XYZ)
                .expect("only-specular fence position FVF");
            device
                .set_render_state(D3DRS_COLORWRITEENABLE, 0xF)
                .expect("enable only-specular fence color writes");
            device
                .set_render_state(D3DRS_CULLMODE, D3DCULL_NONE.0 as u32)
                .expect("disable only-specular fence culling");
            device
                .set_render_state(D3DRS_ZENABLE, 1)
                .expect("enable only-specular fence depth test");
            device
                .set_render_state(D3DRS_ZFUNC, D3DCMP_LESSEQUAL.0 as u32)
                .expect("only-specular fence depth function");

            let mut fence = Vec::with_capacity(36);
            for offset in [-1.0, 0.0, 1.0] {
                append_fence_bar(&mut fence, true, offset);
                append_fence_bar(&mut fence, false, offset);
            }

            device
                .begin_scene()
                .expect("begin only-specular fence scene");
            device
                .set_vertex_shader(&solid_vertex_shader)
                .expect("fence depth vertex shader");
            device
                .set_pixel_shader(&solid_pixel_shader)
                .expect("fence depth pixel shader");
            device
                .set_render_state(D3DRS_ZWRITEENABLE, 1)
                .expect("enable fence depth writes");
            device
                .set_render_state(D3DRS_ALPHABLENDENABLE, 0)
                .expect("disable fence blending");
            unsafe {
                device
                    .draw_primitive_up(D3DPT_TRIANGLELIST, (fence.len() / 3) as u32, &fence)
                    .expect("fence depth draw");
            }

            device
                .set_vertex_shader(&fixture_vertex_shader)
                .expect("only-specular fixture vertex shader");
            device
                .set_pixel_shader(&pixel_shader)
                .expect("only-specular pixel shader");
            device
                .set_texture(0, &normal)
                .expect("diffuse-point normal sampler");
            device
                .set_texture(3, &attenuation)
                .expect("diffuse-point attenuation sampler");
            for stage in [0, 3] {
                set_point_clamp_sampler(device, stage);
            }
            device
                .set_render_state(D3DRS_ZWRITEENABLE, 0)
                .expect("disable only-specular depth writes");
            device
                .set_render_state(D3DRS_ALPHABLENDENABLE, 1)
                .expect("enable native additive blending");
            device
                .set_render_state(D3DRS_SRCBLEND, D3DBLEND_ONE.0 as u32)
                .expect("only-specular source blend");
            device
                .set_render_state(D3DRS_DESTBLEND, D3DBLEND_ONE.0 as u32)
                .expect("only-specular destination blend");

            let radians = camera_angle_degrees.to_radians();
            let light = [radians.sin(), 0.0, radians.cos(), 1.0];
            let view = [-radians.sin(), 0.0, radians.cos(), 0.0];
            device
                .set_vertex_shader_constant_f(0, &[light, view])
                .expect("only-specular camera/light fixture constants");
            let mut constants = [[0.0f32; 4]; 34];
            constants[3] = [0.4, 0.4, 0.4, 0.0];
            constants[4] = [0.4, 0.4, 0.4, 0.0];
            constants[5] = [0.4, 0.4, 0.4, 0.0];
            constants[27] = [0.0, 0.0, 60.0, 0.0];
            constants[32] = [0.0, 0.751_681_4, 1.315_789, 0.865_497_1];
            constants[33] = [1.0, 0.0, 0.0, 0.0];
            device
                .set_pixel_shader_constant_f(0, &constants)
                .expect("only-specular pixel constants");

            let wearable = [
                PositionVertex {
                    position: [-1.0, -1.0, 0.7],
                },
                PositionVertex {
                    position: [3.0, -1.0, 0.7],
                },
                PositionVertex {
                    position: [-1.0, 3.0, 0.7],
                },
            ];
            unsafe {
                device
                    .draw_primitive_up(D3DPT_TRIANGLELIST, 1, &wearable)
                    .expect("only-specular wearable draw");
            }
            device.end_scene().expect("end only-specular fence scene");
            let scene_pixels = read_pixels(device, &surface);
            let bloom_pixels = render_bloom_extract(device, &output);
            (scene_pixels, bloom_pixels)
        }

        fn render_high_light_fence_scene(
            device: &Device9Ref<'_>,
            native: bool,
            camera_angle_degrees: f32,
            camera_distance: f32,
            specular_fade: f32,
        ) -> (Vec<[f32; 4]>, Vec<[f32; 4]>) {
            let fixture_vertex_bytecode = crate::shaders::compile_hlsl_source_target(
                "high_light_fence_behavior.vs",
                high_light_fixture_vertex_source(),
                "vs_3_0",
            )
            .expect("high-light fence fixture vertex shader");
            let solid_vertex_bytecode = crate::shaders::compile_hlsl_source_target(
                "object_only_specular_fence_depth.vs",
                br#"
struct Input { float4 position : POSITION; };
float4 Main(Input input) : POSITION { return input.position; }
"#,
                "vs_3_0",
            )
            .expect("only-specular fence depth vertex shader");
            let solid_pixel_bytecode = crate::shaders::compile_hlsl_source_target(
                "object_only_specular_fence_depth.ps",
                br#"float4 Main() : COLOR0 { return float4(0.035, 0.035, 0.035, 1.0); }"#,
                "ps_3_0",
            )
            .expect("only-specular fence depth pixel shader");
            let pixel_bytecode = if native {
                NATIVE_2034.to_vec()
            } else {
                let template = object_template_id(ShaderStage::Pixel, 2034)
                    .expect("three-light specular object pixel template")
                    .template;
                crate::shaders::compile_hlsl_source_target(
                    "pbr_high_light_fence_behavior.ps",
                    object_template_source(template).as_ref(),
                    "ps_3_0",
                )
                .expect("shipped PBR high-light pixel shader")
            };
            let fixture_vertex_shader = device
                .create_vertex_shader(&fixture_vertex_bytecode)
                .expect("only-specular fixture vertex object");
            let solid_vertex_shader = device
                .create_vertex_shader(&solid_vertex_bytecode)
                .expect("only-specular fence depth vertex object");
            let solid_pixel_shader = device
                .create_pixel_shader(&solid_pixel_bytecode)
                .expect("only-specular fence depth pixel object");
            let pixel_shader = device
                .create_pixel_shader(&pixel_bytecode)
                .expect("only-specular pixel object");

            let base = device
                .create_texture(1, 1, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)
                .expect("high-light base texture");
            base.write_level0_argb_pixel(0xFFB0_8040)
                .expect("high-light base texel");
            let normal = device
                .create_texture(1, 1, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED)
                .expect("high-light normal texture");
            normal
                .write_level0_argb_pixel(0xFF80_80FF)
                .expect("high-light normal texel");
            let output = device
                .create_render_target_texture(TEST_SIZE, TEST_SIZE, D3DFMT_A16B16G16R16F)
                .expect("only-specular fence HDR target");
            let surface = output
                .surface_level(0)
                .expect("only-specular fence HDR surface");
            let depth = device
                .create_depth_stencil_surface(
                    TEST_SIZE,
                    TEST_SIZE,
                    D3DFMT_D24S8,
                    D3DMULTISAMPLE_NONE,
                    0,
                    true,
                )
                .expect("only-specular fence depth surface");

            device
                .set_render_target(0, &surface)
                .expect("only-specular fence HDR binding");
            device
                .set_depth_stencil_surface(Some(&depth))
                .expect("only-specular fence depth binding");
            device
                .set_viewport(&D3DVIEWPORT9 {
                    X: 0,
                    Y: 0,
                    Width: TEST_SIZE,
                    Height: TEST_SIZE,
                    MinZ: 0.0,
                    MaxZ: 1.0,
                })
                .expect("only-specular fence viewport");
            device
                .clear_attachments(
                    D3DCLEAR_TARGET as u32 | D3DCLEAR_ZBUFFER as u32,
                    0xFF10_1010,
                    1.0,
                    0,
                )
                .expect("clear only-specular fence scene");
            device.set_fvf(D3DFVF_XYZ).expect("only-specular fence FVF");
            device
                .set_render_state(D3DRS_COLORWRITEENABLE, 0xF)
                .expect("enable only-specular fence color writes");
            device
                .set_render_state(D3DRS_CULLMODE, D3DCULL_NONE.0 as u32)
                .expect("disable only-specular fence culling");
            device
                .set_render_state(D3DRS_ZENABLE, 1)
                .expect("enable only-specular fence depth test");
            device
                .set_render_state(D3DRS_ZFUNC, D3DCMP_LESSEQUAL.0 as u32)
                .expect("only-specular fence depth function");

            let mut fence = Vec::with_capacity(36);
            for offset in [-1.0, 0.0, 1.0] {
                append_fence_bar(&mut fence, true, offset);
                append_fence_bar(&mut fence, false, offset);
            }
            let wearable = [
                PositionVertex {
                    position: [-1.0, -1.0, 0.7],
                },
                PositionVertex {
                    position: [3.0, -1.0, 0.7],
                },
                PositionVertex {
                    position: [-1.0, 3.0, 0.7],
                },
            ];

            device
                .begin_scene()
                .expect("begin only-specular fence scene");
            device
                .set_vertex_shader(&solid_vertex_shader)
                .expect("only-specular fence depth vertex shader");
            device
                .set_pixel_shader(&solid_pixel_shader)
                .expect("only-specular fence depth pixel shader");
            device
                .set_render_state(D3DRS_ZWRITEENABLE, 1)
                .expect("enable only-specular fence depth writes");
            device
                .set_render_state(D3DRS_ALPHABLENDENABLE, 0)
                .expect("disable only-specular fence blending");
            unsafe {
                device
                    .draw_primitive_up(D3DPT_TRIANGLELIST, (fence.len() / 3) as u32, &fence)
                    .expect("only-specular fence depth draw");
            }

            device
                .set_vertex_shader(&fixture_vertex_shader)
                .expect("only-specular fixture vertex shader");
            device
                .set_pixel_shader(&pixel_shader)
                .expect("high-light pixel shader");
            device
                .set_texture(0, &base)
                .expect("high-light base sampler");
            device
                .set_texture(1, &normal)
                .expect("high-light normal sampler");
            for stage in [0, 1] {
                set_point_clamp_sampler(device, stage);
            }
            device
                .set_render_state(D3DRS_ZWRITEENABLE, 0)
                .expect("disable only-specular depth writes");
            device
                .set_render_state(D3DRS_ALPHABLENDENABLE, 0)
                .expect("disable high-light blending");

            let radians = camera_angle_degrees.to_radians();
            let light = [radians.sin(), 0.0, radians.cos(), specular_fade];
            let view = [-radians.sin(), 0.0, radians.cos(), camera_distance];
            device
                .set_vertex_shader_constant_f(0, &[light, view])
                .expect("only-specular camera/light fixture constants");
            let mut constants = [[0.0f32; 4]; 34];
            constants[1] = [0.04, 0.04, 0.04, 1.0];
            constants[2] = [0.0, 0.0, 0.0, 3.0];
            constants[3] = [0.75, 0.55, 0.35, 0.0];
            constants[4] = [0.65, 0.42, 0.24, 0.0];
            constants[5] = [0.55, 0.34, 0.18, 0.0];
            constants[19] = [0.0, 0.0, 1.0, 1.0];
            constants[20] = [0.0, 0.0, 1.0, 1.0];
            constants[27] = [0.0, 0.0, 60.0, 0.0];
            constants[32] = [0.0, 0.751_681_4, 1.315_789, 0.865_497_1];
            constants[33] = [1.0, 0.0, 0.0, 0.0];
            device
                .set_pixel_shader_constant_f(0, &constants)
                .expect("high-light pixel constants");
            unsafe {
                device
                    .draw_primitive_up(D3DPT_TRIANGLELIST, 1, &wearable)
                    .expect("high-light wearable draw");
            }
            device.end_scene().expect("end only-specular fence scene");
            let scene_pixels = read_pixels(device, &surface);
            let bloom_pixels = render_bloom_extract(device, &output);
            (scene_pixels, bloom_pixels)
        }

        fn render_bloom_extract(
            device: &Device9Ref<'_>,
            scene: &libpsycho::os::windows::directx9::Texture9,
        ) -> Vec<[f32; 4]> {
            let vertex_bytecode = crate::shaders::compile_hlsl_source_target(
                "object_neon_bloom_extract.vs",
                br#"
struct Input { float4 position : POSITION; };
struct Output { float4 position : POSITION; float2 uv : TEXCOORD0; };
Output Main(Input input) {
    Output output;
    output.position = input.position;
    output.uv = float2(input.position.x * 0.5 + 0.5, 0.5 - input.position.y * 0.5);
    return output;
}
"#,
                "vs_3_0",
            )
            .expect("bloom-extract fixture vertex shader");
            let pixel_bytecode = crate::shaders::compile_hlsl_source_target(
                "bloom_hdr_extract.hlsl",
                include_bytes!("../../../shaders/embedded/bloom_hdr_extract.hlsl"),
                "ps_3_0",
            )
            .expect("shipped bloom-extract pixel shader");
            let vertex_shader = device
                .create_vertex_shader(&vertex_bytecode)
                .expect("bloom-extract vertex object");
            let pixel_shader = device
                .create_pixel_shader(&pixel_bytecode)
                .expect("bloom-extract pixel object");
            let output = device
                .create_render_target_texture(TEST_SIZE, TEST_SIZE, D3DFMT_A16B16G16R16F)
                .expect("bloom-extract HDR target");
            let surface = output.surface_level(0).expect("bloom-extract HDR surface");

            device
                .set_render_target(0, &surface)
                .expect("bloom-extract target binding");
            device
                .set_depth_stencil_surface(None)
                .expect("detach bloom-extract depth surface");
            device
                .clear_attachments(D3DCLEAR_TARGET as u32, 0, 1.0, 0)
                .expect("clear bloom-extract target");
            device
                .set_vertex_shader(&vertex_shader)
                .expect("bloom-extract vertex shader");
            device
                .set_pixel_shader(&pixel_shader)
                .expect("bloom-extract pixel shader");
            device.set_texture(0, scene).expect("bloom scene sampler");
            set_point_clamp_sampler(device, 0);
            device
                .set_render_state(D3DRS_ZENABLE, 0)
                .expect("disable bloom-extract depth test");
            device
                .set_render_state(D3DRS_ZWRITEENABLE, 0)
                .expect("disable bloom-extract depth writes");
            device
                .set_render_state(D3DRS_ALPHABLENDENABLE, 0)
                .expect("disable bloom-extract blending");

            let mut constants = [[0.0f32; 4]; 6];
            constants[0] = [
                TEST_SIZE as f32,
                TEST_SIZE as f32,
                1.0 / TEST_SIZE as f32,
                1.0 / TEST_SIZE as f32,
            ];
            constants[3] = [0.34, 0.62, 0.0, 0.28];
            device
                .set_pixel_shader_constant_f(0, &constants)
                .expect("bloom-extract constants");

            let triangle = [
                PositionVertex {
                    position: [-1.0, -1.0, 0.5],
                },
                PositionVertex {
                    position: [3.0, -1.0, 0.5],
                },
                PositionVertex {
                    position: [-1.0, 3.0, 0.5],
                },
            ];
            device.begin_scene().expect("begin bloom-extract draw");
            unsafe {
                device
                    .draw_primitive_up(D3DPT_TRIANGLELIST, 1, &triangle)
                    .expect("bloom-extract draw");
            }
            device.end_scene().expect("end bloom-extract draw");
            read_pixels(device, &surface)
        }

        #[test]
        fn megaton_only_light_rows_match_native_hdr_and_bloom_energy() {
            let owner = raster_device();
            let device = owner.as_ref();
            device
                .direct3d()
                .expect("D3D9 interface")
                .check_default_render_target_texture_support(D3DFMT_A16B16G16R16F)
                .expect("HDR object targets");

            for self_illuminated in [false, true] {
                let (native, native_bloom) =
                    render_only_light_pixel_shader(&device, true, self_illuminated);
                let (pbr, pbr_bloom) =
                    render_only_light_pixel_shader(&device, false, self_illuminated);
                for (index, (native, pbr)) in native.iter().zip(&pbr).enumerate() {
                    for component in 0..3 {
                        assert!(
                            (pbr[component] - native[component]).abs() <= 0.01,
                            "only-light row changed native HDR energy (SI={self_illuminated}, pixel {index}, component {component}): native={native:?}, pbr={pbr:?}, native_bloom={:?}, pbr_bloom={:?}",
                            native_bloom[index],
                            pbr_bloom[index],
                        );
                    }
                }
                for (index, (native, pbr)) in native_bloom.iter().zip(&pbr_bloom).enumerate() {
                    for component in 0..3 {
                        assert!(
                            (pbr[component] - native[component]).abs() <= 0.01,
                            "only-light row changed shipped bloom energy (SI={self_illuminated}, pixel {index}, component {component}): native={native:?}, pbr={pbr:?}"
                        );
                    }
                }
            }
        }

        #[test]
        fn megaton_diffuse_point_rows_do_not_neon_bloom_through_fence() {
            let owner = raster_device();
            let device = owner.as_ref();
            device
                .direct3d()
                .expect("D3D9 interface")
                .check_default_render_target_texture_support(D3DFMT_A16B16G16R16F)
                .expect("HDR object targets");

            let mut worst_hdr_error = 0.0f32;
            let mut worst_fence_bloom_error = 0.0f32;
            let mut worst_angle = 0.0f32;
            let mut worst_light_count = 0u32;
            let mut occluded_samples = 0usize;
            for light_count in [2u32, 3] {
                for angle in [0.0f32, 35.0, 55.0, 68.0, 78.0] {
                    let (native_scene, native_bloom) =
                        render_diffuse_point_fence_scene(&device, true, light_count, angle);
                    let (pbr_scene, pbr_bloom) =
                        render_diffuse_point_fence_scene(&device, false, light_count, angle);

                    for index in 0..native_scene.len() {
                        let hdr_error = (pbr_scene[index][0] - native_scene[index][0]).abs();
                        if hdr_error > worst_hdr_error {
                            worst_hdr_error = hdr_error;
                            worst_angle = angle;
                            worst_light_count = light_count;
                        }

                        // The depth-writing fence is the only region which
                        // stays below this scene value. Bloom at these pixels
                        // is light leaking spatially from the visible wearable
                        // in its gaps.
                        if native_scene[index][0] < 0.1 {
                            occluded_samples += 1;
                            let native_luma = native_bloom[index][0] * 0.2126
                                + native_bloom[index][1] * 0.7152
                                + native_bloom[index][2] * 0.0722;
                            let pbr_luma = pbr_bloom[index][0] * 0.2126
                                + pbr_bloom[index][1] * 0.7152
                                + pbr_bloom[index][2] * 0.0722;
                            worst_fence_bloom_error =
                                worst_fence_bloom_error.max((pbr_luma - native_luma).abs());
                        }
                    }
                }
            }

            assert!(occluded_samples > 0, "fence did not occlude the wearable");
            assert!(
                worst_hdr_error <= 0.02 && worst_fence_bloom_error <= 0.02,
                "DIFFUSE helper diverged from native additive energy during the camera sweep: HDR error={worst_hdr_error:.4} with {worst_light_count} lights at {worst_angle:.1} degrees, bloom error over depth-occluding fence={worst_fence_bloom_error:.4}"
            );
        }

        #[test]
        fn megaton_high_light_wearable_does_not_neon_bloom_through_fence() {
            let owner = raster_device();
            let device = owner.as_ref();
            device
                .direct3d()
                .expect("D3D9 interface")
                .check_default_render_target_texture_support(D3DFMT_A16B16G16R16F)
                .expect("HDR object targets");

            let mut worst_hdr_excess = 0.0f32;
            let mut worst_fence_bloom_excess = 0.0f32;
            let mut worst_angle = 0.0f32;
            let mut worst_distance = 0.0f32;
            let mut worst_fade = 0.0f32;
            let mut occluded_samples = 0usize;
            for fade in [0.0f32, 0.2, 0.65, 1.0] {
                for distance in [0.75f32, 1.5, 4.0, 12.0] {
                    for angle in [0.0f32, 25.0, 45.0, 60.0, 72.0, 80.0] {
                        let (native_scene, native_bloom) =
                            render_high_light_fence_scene(&device, true, angle, distance, fade);
                        let (pbr_scene, pbr_bloom) =
                            render_high_light_fence_scene(&device, false, angle, distance, fade);

                        for index in 0..native_scene.len() {
                            for component in 0..3 {
                                let excess =
                                    pbr_scene[index][component] - native_scene[index][component];
                                if excess > worst_hdr_excess {
                                    worst_hdr_excess = excess;
                                    worst_angle = angle;
                                    worst_distance = distance;
                                    worst_fade = fade;
                                }
                            }
                            if native_scene[index][0] < 0.1 {
                                occluded_samples += 1;
                                let native_luma = native_bloom[index][0] * 0.2126
                                    + native_bloom[index][1] * 0.7152
                                    + native_bloom[index][2] * 0.0722;
                                let pbr_luma = pbr_bloom[index][0] * 0.2126
                                    + pbr_bloom[index][1] * 0.7152
                                    + pbr_bloom[index][2] * 0.0722;
                                worst_fence_bloom_excess =
                                    worst_fence_bloom_excess.max(pbr_luma - native_luma);
                            }
                        }
                    }
                }
            }

            assert!(occluded_samples > 0, "fence did not occlude the wearable");
            assert!(
                worst_hdr_excess <= 0.02 && worst_fence_bloom_excess <= 0.02,
                "high-light wearable exceeded native HDR energy during the camera sweep: HDR excess={worst_hdr_excess:.4} at fade {worst_fade:.2}, distance {worst_distance:.2}, angle {worst_angle:.1} degrees, bloom excess over depth-occluding fence={worst_fence_bloom_excess:.4}"
            );
        }
    }

    fn dot(left: [f32; 3], right: [f32; 3]) -> f32 {
        left[0] * right[0] + left[1] * right[1] + left[2] * right[2]
    }

    fn stable_vector(value: [f32; 3]) -> [f32; 3] {
        let inverse_length = dot(value, value).max(1.0e-8).sqrt().recip();
        [
            value[0] * inverse_length,
            value[1] * inverse_length,
            value[2] * inverse_length,
        ]
    }

    fn centered_weighted_normal(samples: &[[f32; 3]], weights: &[f32]) -> [f32; 3] {
        let mut normal = [0.0; 3];
        for (sample, weight) in samples.iter().zip(weights) {
            for component in 0..3 {
                normal[component] += (sample[component] - 0.5) * weight;
            }
        }
        stable_vector(normal)
    }

    fn legacy_encoded_weighted_normal(samples: &[[f32; 3]], weights: &[f32]) -> [f32; 3] {
        let mut encoded = [0.0; 3];
        for (sample, weight) in samples.iter().zip(weights) {
            for component in 0..3 {
                encoded[component] += sample[component] * weight;
            }
        }
        stable_vector(encoded.map(|component| component * 2.0 - 1.0))
    }

    fn assert_vector_near(left: [f32; 3], right: [f32; 3]) {
        for component in 0..3 {
            assert!((left[component] - right[component]).abs() <= 1.0e-5);
        }
    }

    fn terrain_diffuse_luminance(
        albedo: [f32; 3],
        metallic: f32,
        normal: [f32; 3],
        light_direction: [f32; 3],
        attenuation: f32,
    ) -> f32 {
        let ndotl = dot(normal, stable_vector(light_direction)).clamp(0.0, 1.0);
        let diffuse =
            albedo.map(|component| component * 0.96 * (1.0 - metallic) * ndotl * attenuation);
        dot(diffuse, [0.299, 0.587, 0.114])
    }

    fn assert_vanilla_centered_normal_contract(source: &str, texture_count: usize) {
        assert!(source.contains("def c0 = -5.00000000e-01"));
        let center_count = source
            .lines()
            .filter(|line| line.starts_with("add ") && line.ends_with(", c0.x"))
            .count();
        assert_eq!(center_count, texture_count);
        assert!(source.find(", c0.x").unwrap() < source.find("mul_pp r0.xyz").unwrap());
        assert!(source.find("mul_pp r0.xyz").unwrap() < source.find("nrm_pp").unwrap());
    }

    fn bounded_object_light(
        gloss_power: f32,
        specular_strength: f32,
        specular_fade: f32,
        attenuation: f32,
        albedo: f32,
        normal: [f32; 3],
        view: [f32; 3],
        light: [f32; 3],
        light_color: f32,
    ) -> (f32, f32) {
        let light = stable_vector(light);
        let halfway = stable_vector([view[0] + light[0], view[1] + light[1], view[2] + light[2]]);
        let ndotl = dot(normal, light).clamp(0.0, 1.0);
        let ndoth = dot(normal, halfway).clamp(0.0, 1.0);
        let ldoth = dot(light, halfway).clamp(0.0, 1.0);
        let fresnel = 0.04 + 0.96 * (1.0 - ldoth).powi(5);
        let distribution = ndoth.powf(gloss_power) * (gloss_power + 2.0) * 0.125;
        let radiance = ndotl * light_color * attenuation;
        let diffuse = (1.0 - fresnel) * albedo * radiance;
        let specular = (fresnel * distribution * radiance * specular_strength.clamp(0.0, 1.0))
            .clamp(0.0, 1.0)
            * specular_fade.clamp(0.0, 1.0);
        (diffuse, specular)
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

            let instruction_length = ((token >> 24) & 0x0f) as usize;
            opcodes.push(opcode);
            offset += 1 + instruction_length;
        }
        assert!(offset < bytecode.len(), "shader bytecode has no END token");
        opcodes
    }

    fn compiled_opcode_count(bytecode: &[u32], opcode: u16) -> usize {
        compiled_instruction_opcodes(bytecode)
            .into_iter()
            .filter(|candidate| *candidate == opcode)
            .count()
    }

    fn compiled_texture_instruction_count(bytecode: &[u32]) -> usize {
        const TEXLD: u16 = 66;
        const TEXLDD: u16 = 93;
        const TEXLDL: u16 = 95;
        compiled_instruction_opcodes(bytecode)
            .into_iter()
            .filter(|opcode| matches!(*opcode, TEXLD | TEXLDD | TEXLDL))
            .count()
    }

    fn compiled_relative_constant_read_count(bytecode: &[u32]) -> usize {
        const COMMENT: u16 = 0xfffe;
        const DEF: u16 = 81;
        const DEFB: u16 = 47;
        const DEFI: u16 = 48;
        const END: u16 = 0xffff;
        const PARAMETER_ADDRESS_RELATIVE: u32 = 1 << 13;
        const REGISTER_TYPE_MASK: u32 = 0x7000_0000;
        const REGISTER_TYPE_MASK2: u32 = 0x0000_1800;
        const REGISTER_TYPE_CONST: u32 = 2;

        let mut relative_reads = 0usize;
        let mut offset = 1usize;
        while offset < bytecode.len() {
            let instruction = bytecode[offset];
            let opcode = instruction as u16;
            if opcode == END {
                break;
            }
            if opcode == COMMENT {
                offset += 1 + ((instruction >> 16) & 0x7fff) as usize;
                continue;
            }

            let instruction_length = ((instruction >> 24) & 0x0f) as usize;
            // DEF operands contain arbitrary IEEE-754 or integer bits rather
            // than parameter tokens. Excluding them keeps the register-token
            // decoder from treating an immediate value as a relative c# read.
            if !matches!(opcode, DEF | DEFB | DEFI) {
                for parameter in &bytecode[offset + 1..offset + 1 + instruction_length] {
                    let register_type = ((parameter & REGISTER_TYPE_MASK) >> 28)
                        | ((parameter & REGISTER_TYPE_MASK2) >> 8);
                    if register_type == REGISTER_TYPE_CONST
                        && parameter & PARAMETER_ADDRESS_RELATIVE != 0
                    {
                        relative_reads += 1;
                    }
                }
            }
            offset += 1 + instruction_length;
        }
        assert!(offset < bytecode.len(), "shader bytecode has no END token");
        relative_reads
    }

    fn compiled_temporary_register_count(bytecode: &[u32]) -> usize {
        const COMMENT: u16 = 0xfffe;
        const END: u16 = 0xffff;
        const REGISTER_NUMBER_MASK: u32 = 0x7ff;
        const REGISTER_TYPE_MASK: u32 = 0x7000_0000;
        const REGISTER_TYPE_MASK2: u32 = 0x0000_1800;
        const REGISTER_TYPE_TEMP: u32 = 0;

        let mut maximum = None;
        let mut offset = 1usize;
        while offset < bytecode.len() {
            let instruction = bytecode[offset];
            let opcode = instruction as u16;
            if opcode == END {
                break;
            }
            if opcode == COMMENT {
                offset += 1 + ((instruction >> 16) & 0x7fff) as usize;
                continue;
            }
            let instruction_length = ((instruction >> 24) & 0x0f) as usize;
            // Every temporary is defined before use. Inspecting destinations
            // avoids misreading CALL/LABEL identifiers and immediate DEF words
            // as register tokens while still finding the highest allocated r#.
            let writes_destination = matches!(opcode, 1..=24 | 32..=37 | 64..=80 | 88..=95);
            if writes_destination && instruction_length != 0 {
                let parameter = bytecode[offset + 1];
                let register_type = ((parameter & REGISTER_TYPE_MASK) >> 28)
                    | ((parameter & REGISTER_TYPE_MASK2) >> 8);
                if register_type == REGISTER_TYPE_TEMP {
                    let register = (parameter & REGISTER_NUMBER_MASK) as usize;
                    maximum =
                        Some(maximum.map_or(register, |current: usize| current.max(register)));
                }
            }
            offset += 1 + instruction_length;
        }
        assert!(offset < bytecode.len(), "shader bytecode has no END token");
        maximum.map_or(0, |register| register + 1)
    }

    #[test]
    fn object_pbr_preserves_the_native_specular_transition_contract() {
        assert!(!NVR_PBR_INCLUDE_SOURCE.contains("ddx("));
        assert!(!NVR_PBR_INCLUDE_SOURCE.contains("ddy("));
        assert!(!NVR_OBJECT_TEMPLATE_SOURCE.contains("SpecularAA("));
        assert!(!NVR_OBJECT_TEMPLATE_SOURCE.contains("getObjectSpecularTransition"));
        assert!(!NVR_OBJECT_INCLUDE_SOURCE.contains("TESR_PBRData.x"));
        assert!(NVR_PBR_INCLUDE_SOURCE.contains("PBRBounded"));
        assert!(NVR_OBJECT_INCLUDE_SOURCE.contains("getSpecularGlossPower"));
        assert!(NVR_PBR_INCLUDE_SOURCE.contains("PBRBoundedSpecular"));
        assert!(NVR_OBJECT_TEMPLATE_SOURCE.contains("nativeSpecularFade"));
        assert!(NVR_OBJECT_TEMPLATE_SOURCE.contains("normal.a, nativeSpecularFade"));
    }

    #[test]
    fn material_saturation_applies_to_object_direct_and_ambient_albedo() {
        assert!(NVR_OBJECT_TEMPLATE_SOURCE.contains("float3 materialAlbedo = lerp"));
        assert!(
            NVR_OBJECT_TEMPLATE_SOURCE
                .contains("getAmbientLighting(AmbientColor.rgb, materialAlbedo)")
        );
        assert!(
            !NVR_OBJECT_TEMPLATE_SOURCE
                .contains("getAmbientLighting(AmbientColor.rgb, baseColor.rgb)")
        );
    }

    #[test]
    fn object_halfway_vector_is_continuous_when_view_opposes_light() {
        assert!(NVR_PBR_INCLUDE_SOURCE.contains("float3 StableHalfway("));
        assert_eq!(NVR_PBR_INCLUDE_SOURCE.matches("StableHalfway(").count(), 8);
        assert!(
            NVR_PBR_INCLUDE_SOURCE.contains("return halfway * rsqrt(max(lengthSquared, 1e-8));")
        );
        assert!(!NVR_PBR_INCLUDE_SOURCE.contains("SafeNormalize(eyeDir + lightDir, normal)"));
        assert!(!NVR_PBR_INCLUDE_SOURCE.contains("SafeNormalize(eyeDir + sunDir, normal)"));

        fn fresnel(cosine: f32) -> f32 {
            let one_minus_cosine = 1.0 - cosine;
            0.04 + 0.96 * one_minus_cosine.powi(5)
        }

        fn stable_light_halfway_cosine(view: [f32; 3], light: [f32; 3]) -> f32 {
            let halfway = [view[0] + light[0], view[1] + light[1], view[2] + light[2]];
            dot(light, stable_vector(halfway)).clamp(0.0, 1.0)
        }

        let light = [0.0, 0.0, 1.0];
        let exact = stable_light_halfway_cosine([0.0, 0.0, -1.0], light);
        let near_x = 2.0e-4f32;
        let near_z = -(1.0 - near_x * near_x).sqrt();
        let before = stable_light_halfway_cosine([-near_x, 0.0, near_z], light);
        let after = stable_light_halfway_cosine([near_x, 0.0, near_z], light);

        assert_eq!(exact, 0.0);
        assert!((before - after).abs() <= f32::EPSILON);
        assert!((fresnel(before) - fresnel(exact)).abs() < 0.002);
        assert!((fresnel(after) - fresnel(exact)).abs() < 0.002);

        let legacy_exact_fallback = fresnel(1.0);
        assert!((legacy_exact_fallback - fresnel(exact)).abs() > 0.9);

        let mut previous = [0.0; 3];
        let mut maximum_step = 0.0f32;
        for step in 0..=200 {
            let tangent = step as f32 * 1.0e-6;
            let view = [tangent, 0.0, -(1.0 - tangent * tangent).sqrt()];
            let halfway = stable_vector([view[0], view[1], view[2] + 1.0]);
            if step != 0 {
                maximum_step = maximum_step.max(
                    halfway
                        .into_iter()
                        .zip(previous)
                        .map(|(current, last)| (current - last).abs())
                        .fold(0.0, f32::max),
                );
            }
            previous = halfway;
        }
        assert!(
            maximum_step < 0.011,
            "half-vector cutoff introduced a {maximum_step} camera step"
        );
    }

    #[test]
    fn close_terrain_halfway_vector_is_continuous_across_camera_motion() {
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("float3 StableHalfway("));
        assert_eq!(
            CLOSE_TERRAIN_PIXEL_SOURCE.matches("StableHalfway(").count(),
            3
        );
        assert!(
            CLOSE_TERRAIN_PIXEL_SOURCE
                .contains("return halfway * rsqrt(max(length_squared, 1.0e-8f));")
        );
        assert!(
            !CLOSE_TERRAIN_PIXEL_SOURCE.contains("SafeNormalize(view_dir + light_dir, normal)")
        );
        assert!(!CLOSE_TERRAIN_PIXEL_SOURCE.contains("SafeNormalize(view_dir + sun_dir, normal)"));

        fn dielectric_diffuse_response(halfway_cosine: f32) -> f32 {
            let fresnel = 0.04 + 0.96 * (1.0 - halfway_cosine.clamp(0.0, 1.0)).powi(5);
            1.0 - fresnel
        }

        fn camera_view(tangent: f32) -> [f32; 3] {
            [tangent, 0.0, -(1.0 - tangent * tangent).sqrt()]
        }

        fn legacy_response(view: [f32; 3]) -> f32 {
            let light = [0.0, 0.0, 1.0];
            let halfway = [view[0], view[1], view[2] + light[2]];
            let halfway = if dot(halfway, halfway) > 1.0e-6 {
                stable_vector(halfway)
            } else {
                light
            };
            dielectric_diffuse_response(dot(light, halfway))
        }

        fn stable_response(view: [f32; 3]) -> f32 {
            let light = [0.0, 0.0, 1.0];
            let halfway = stable_vector([view[0], view[1], view[2] + light[2]]);
            dielectric_diffuse_response(dot(light, halfway))
        }

        let inside_cutoff = camera_view(0.0009);
        let outside_cutoff = camera_view(0.0011);
        let legacy_step = (legacy_response(inside_cutoff) - legacy_response(outside_cutoff)).abs();
        let stable_step = (stable_response(inside_cutoff) - stable_response(outside_cutoff)).abs();

        assert!(
            legacy_step > 0.9,
            "negative control no longer reproduces the terrain brightness blink"
        );
        assert!(
            stable_step < 0.001,
            "camera motion still changes terrain diffuse response by {stable_step}"
        );
    }

    #[test]
    fn terrain_lod_halfway_vectors_are_continuous_across_camera_motion() {
        for (label, source) in [
            ("land LOD", LAND_LOD_PIXEL_SOURCE),
            ("terrain fade", TERRAIN_FADE_PIXEL_SOURCE),
        ] {
            assert!(
                source.contains("float3 StableHalfway("),
                "{label} has no continuous half-vector helper"
            );
            assert!(
                source.contains("return halfway * rsqrt(max(length_squared, 1.0e-8f));"),
                "{label} does not use the proven zero-safe normalization"
            );
            assert!(
                !source.contains("SafeNormalize(eye_dir + sun_dir, normal)")
                    && !source.contains("SafeNormalize(view_dir + sun_dir, normal)"),
                "{label} still falls back discontinuously to the surface normal"
            );
        }

        fn dielectric_diffuse_response(halfway_cosine: f32) -> f32 {
            let fresnel = 0.04 + 0.96 * (1.0 - halfway_cosine.clamp(0.0, 1.0)).powi(5);
            1.0 - fresnel
        }

        fn camera_view(tangent: f32) -> [f32; 3] {
            [tangent, 0.0, -(1.0 - tangent * tangent).sqrt()]
        }

        fn legacy_response(view: [f32; 3]) -> f32 {
            let light = [0.0, 0.0, 1.0];
            let halfway = [view[0], view[1], view[2] + light[2]];
            let halfway = if dot(halfway, halfway) > 1.0e-6 {
                stable_vector(halfway)
            } else {
                light
            };
            dielectric_diffuse_response(dot(light, halfway))
        }

        fn stable_response(view: [f32; 3]) -> f32 {
            let light = [0.0, 0.0, 1.0];
            let halfway = stable_vector([view[0], view[1], view[2] + light[2]]);
            dielectric_diffuse_response(dot(light, halfway))
        }

        let inside_cutoff = camera_view(0.0009);
        let outside_cutoff = camera_view(0.0011);
        let legacy_step = (legacy_response(inside_cutoff) - legacy_response(outside_cutoff)).abs();
        let stable_step = (stable_response(inside_cutoff) - stable_response(outside_cutoff)).abs();

        assert!(
            legacy_step > 0.9,
            "negative control no longer reproduces the terrain LOD lighting blink"
        );
        assert!(
            stable_step < 0.001,
            "camera motion still changes terrain LOD diffuse response by {stable_step}"
        );
    }

    #[test]
    fn point_light_attenuation_is_finite_and_matches_vanilla_inside_valid_radii() {
        assert!(
            NVR_POINTLIGHTS_INCLUDE_SOURCE
                .contains("dot(lightVector, lightVector) / max(radius * radius, 1e-8)")
        );
        let vanilla_attenuation = NVR_POINTLIGHTS_INCLUDE_SOURCE
            .split_once("float vanillaAtt")
            .unwrap()
            .1
            .split_once('}')
            .unwrap()
            .0;
        assert!(!vanilla_attenuation.contains("lightVector / radius"));

        fn attenuation(light: [f32; 3], radius: f32) -> f32 {
            (1.0 - dot(light, light) / (radius * radius).max(1.0e-8)).clamp(0.0, 1.0)
        }

        for radius in [0.0f32, 1.0e-8, 1.0e-4, 0.5, 64.0, 4096.0] {
            let mut previous = 1.0;
            for step in 0..=64 {
                let distance = radius.max(1.0) * step as f32 / 64.0;
                let value = attenuation([distance, 0.0, 0.0], radius);
                assert!(value.is_finite());
                assert!((0.0..=1.0).contains(&value));
                assert!(value <= previous + f32::EPSILON);
                previous = value;
            }
        }

        for radius in [0.5f32, 64.0, 4096.0] {
            for ratio in [0.0, 0.125, 0.5, 0.875, 1.0, 2.0] {
                let distance = radius * ratio;
                let legacy = (1.0 - (distance / radius).powi(2)).clamp(0.0, 1.0);
                assert!((attenuation([distance, 0.0, 0.0], radius) - legacy).abs() < 1.0e-6);
            }
        }
    }

    #[test]
    fn special_object_rows_preserve_native_attenuation_lookup_contract() {
        for source in [VANILLA_ONLY_LIGHT_2_PIXEL, VANILLA_ONLY_LIGHT_3_PIXEL] {
            assert!(source.contains("dcl_2d s4"));
            assert!(source.matches("s4").count() >= 3);
        }
        for source in [VANILLA_ONLY_LIGHT_2_VERTEX, VANILLA_ONLY_LIGHT_3_VERTEX] {
            assert!(source.contains("mad oT4.xyz"));
            assert!(source.contains("mov oT4.w"));
        }
        assert!(VANILLA_ONLY_LIGHT_3_VERTEX.contains("mad oT5.xyz"));
        assert!(VANILLA_DIFFUSE_POINT_PIXEL.contains("dcl_2d s3"));
        assert!(VANILLA_DIFFUSE_POINT_PIXEL.matches("s3").count() >= 3);
        assert!(VANILLA_DIFFUSE_POINT_VERTEX.contains("mad oT4.xyz"));
        assert!(VANILLA_DIFFUSE_POINT_VERTEX.contains("mad oT5.xyz"));

        assert!(NVR_OBJECT_TEMPLATE_SOURCE.contains("sampler2D AttenuationMap"));
        assert!(NVR_OBJECT_TEMPLATE_SOURCE.contains("float sampleObjectAttenuation("));
        assert!(NVR_OBJECT_TEMPLATE_SOURCE.contains("float4 lightAttenuation : TEXCOORD4"));
        assert!(NVR_OBJECT_TEMPLATE_SOURCE.contains("float4 light2Attenuation : TEXCOORD4"));
        assert!(NVR_OBJECT_TEMPLATE_SOURCE.contains("float4 light3Attenuation : TEXCOORD6"));
        assert!(
            NVR_OBJECT_TEMPLATE_SOURCE.contains("sampleObjectAttenuation(IN.lightAttenuation)")
        );
        assert!(
            NVR_OBJECT_TEMPLATE_SOURCE.contains("sampleObjectAttenuation(IN.light2Attenuation)")
        );
        assert!(
            NVR_OBJECT_TEMPLATE_SOURCE.contains("sampleObjectAttenuation(IN.light3Attenuation)")
        );
    }

    #[test]
    fn high_light_count_gates_match_the_native_contract() {
        for light_index in 0..=5 {
            assert!(
                NVR_OBJECT_TEMPLATE_SOURCE
                    .contains(&format!("{light_index} < lightsThreshold ? 1.0 : 0.0"))
            );
        }
        for threshold in 1..=5 {
            assert!(NVR_OBJECT_TEMPLATE_SOURCE.contains(&format!("if (lightsUsed > {threshold})")));
            assert!(
                !NVR_OBJECT_TEMPLATE_SOURCE
                    .contains(&format!("({threshold} >= lightsUsed ? 0.0 : 1.0)"))
            );
        }

        for light_count in 0..=6 {
            for light_index in 1..=5 {
                let vertex_activates = light_index < light_count;
                let pixel_activates = !(light_index >= light_count);
                assert_eq!(
                    vertex_activates, pixel_activates,
                    "light {light_index} disagrees at integer count {light_count}"
                );
            }
        }
    }

    #[test]
    fn object_registry_covers_the_complete_source_derived_family() {
        const EXPECTED_VERTEX_ROWS: &[u16] = &[
            2000, 2001, 2003, 2004, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015,
            2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026, 2027, 2028, 2029,
            2030, 2031, 2032, 2033, 2034, 2035, 2036, 2037, 2038, 2039, 2040, 2041, 2042, 2043,
            2044, 2045, 2046, 2047, 2048, 2049,
        ];
        const EXPECTED_PIXEL_ROWS: &[u16] = &[
            2000, 2001, 2002, 2004, 2005, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015,
            2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2026, 2027, 2029, 2030, 2031,
            2032, 2033, 2034, 2035, 2036, 2037, 2038, 2039, 2040, 2041, 2042, 2043, 2044, 2045,
            2046, 2047, 2048, 2049, 2050, 2051, 2052, 2053, 2054, 2055, 2056,
        ];

        let mut vertex_rows = Vec::new();
        let mut pixel_rows = Vec::new();
        for template_id in 0..object_template_count() {
            let template = object_template_at(template_id as u16).unwrap();
            match template.stage {
                ShaderStage::Vertex => vertex_rows.push(template.sls_number),
                ShaderStage::Pixel => pixel_rows.push(template.sls_number),
            }
        }
        assert_eq!(vertex_rows, EXPECTED_VERTEX_ROWS);
        assert_eq!(pixel_rows, EXPECTED_PIXEL_ROWS);
    }

    #[test]
    fn combined_specular_handoff_converges_to_the_non_specular_equation() {
        assert!(NVR_PBR_INCLUDE_SOURCE.contains(
            "const float3 diffuse = (1 - fresnel) * surface.diffuseColor * radiance * PI;"
        ));
        assert!(NVR_PBR_INCLUDE_SOURCE.contains(
            "return diffuse + saturate(specular * surface.specularStrength) * surface.specularFade;"
        ));
        assert!(NVR_PBR_INCLUDE_SOURCE.contains("return diffuse * NdotL * lightColor * PI;"));
        assert!(
            NVR_OBJECT_INCLUDE_SOURCE.contains(
                "return att * PBRDiffuse(surface, normal, viewDir, lightDir, lightColor);"
            )
        );
        assert!(
            NVR_OBJECT_TEMPLATE_SOURCE
                .contains("lighting += getAmbientLighting(AmbientColor.rgb, materialAlbedo);")
        );
        let ambient = NVR_OBJECT_INCLUDE_SOURCE
            .split_once("float3 getAmbientLighting")
            .unwrap()
            .1;
        assert!(!ambient.contains("specularFade"));

        for diffuse in [0.0f32, 0.125, 0.5, 2.0] {
            for bounded_specular in [0.0f32, 0.25, 1.0] {
                let non_specular_row = diffuse;
                let combined_row_at_handoff = diffuse + bounded_specular.clamp(0.0, 1.0) * 0.0;
                assert_eq!(combined_row_at_handoff, non_specular_row);
            }
        }
    }

    #[test]
    fn bounded_object_brdf_is_finite_bounded_and_fade_monotonic() {
        assert!(NVR_PBR_INCLUDE_SOURCE.contains(
            "return saturate(specular * surface.specularStrength) * surface.specularFade;"
        ));
        assert!(NVR_PBR_INCLUDE_SOURCE.contains(
            "return diffuse + saturate(specular * surface.specularStrength) * surface.specularFade;"
        ));

        let normals = [[0.0, 0.0, 1.0], [0.6, 0.0, 0.8], [-0.8, 0.2, 0.565_685_45]];
        let directions = [
            [0.0, 0.0, 0.0],
            [0.0, 0.0, 1.0],
            [0.0, 0.0, -1.0],
            [1.0e-6, 0.0, -1.0],
            [-1.0e-6, 0.0, -1.0],
            [1.0, 0.0, 0.0],
            [-0.6, 0.2, 0.774_596_7],
        ];

        for normal in normals {
            for view in directions {
                let view = if dot(view, view) > 1.0e-8 {
                    stable_vector(view)
                } else {
                    normal
                };
                for light in directions {
                    for gloss_power in [1.0, 2.0, 16.0, 128.0, 4_096.0, 70_000.0] {
                        for specular_strength in [0.0, 0.25, 1.0, 4.0] {
                            for attenuation in [0.0, 0.01, 0.5, 1.0] {
                                for (albedo, light_color) in [(0.0, 0.0), (0.5, 1.0), (1.0, 8.0)] {
                                    let mut previous_specular = 0.0;
                                    let (diffuse_at_zero, specular_at_zero) = bounded_object_light(
                                        gloss_power,
                                        specular_strength,
                                        0.0,
                                        attenuation,
                                        albedo,
                                        normal,
                                        view,
                                        light,
                                        light_color,
                                    );
                                    assert_eq!(specular_at_zero, 0.0);

                                    for fade in [0.0, 0.125, 0.5, 0.875, 1.0] {
                                        let (diffuse, specular) = bounded_object_light(
                                            gloss_power,
                                            specular_strength,
                                            fade,
                                            attenuation,
                                            albedo,
                                            normal,
                                            view,
                                            light,
                                            light_color,
                                        );
                                        assert!(diffuse.is_finite() && specular.is_finite());
                                        assert!(diffuse >= 0.0 && specular >= 0.0);
                                        assert!(specular <= fade + f32::EPSILON);
                                        assert!(specular + f32::EPSILON >= previous_specular);
                                        assert_eq!(diffuse, diffuse_at_zero);
                                        assert!(
                                            diffuse + specular
                                                <= albedo * light_color * attenuation
                                                    + fade
                                                    + 1.0e-5
                                        );
                                        previous_specular = specular;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn pbr_light_directions_are_zero_safe() {
        assert!(!NVR_PBR_INCLUDE_SOURCE.contains("lightDir = normalize(lightDir);"));
        assert_eq!(
            NVR_PBR_INCLUDE_SOURCE
                .matches("lightDir = StableNormalize(lightDir);")
                .count(),
            7
        );
        assert!(NVR_PBR_INCLUDE_SOURCE.contains("return value * rsqrt(max(lengthSquared, 1e-8));"));
    }

    #[test]
    fn zero_terrain_controls_are_not_replaced_with_neutral_values() {
        for source in [
            LAND_LOD_PIXEL_SOURCE,
            TERRAIN_FADE_PIXEL_SOURCE,
            CLOSE_TERRAIN_PIXEL_SOURCE,
        ] {
            assert!(source.contains("return TESR_TerrainData.z;"));
            assert!(source.contains("return TESR_TerrainData.w;"));
            assert!(source.contains("return TESR_TerrainExtraData.y;"));
        }
    }

    #[test]
    fn close_terrain_portable_light_shader_abi_is_exact() {
        assert!(
            CLOSE_TERRAIN_PIXEL_SOURCE
                .contains("float4 PointLightColor[PBR_TERRAIN_POINT_LIGHTS] : register(c39);")
        );
        assert!(
            CLOSE_TERRAIN_PIXEL_SOURCE
                .contains("float4 PointLightPosition[PBR_TERRAIN_POINT_LIGHTS] : register(c63);")
        );
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("float PointLightCount : register(c88);"));
        assert!(
            CLOSE_TERRAIN_PIXEL_SOURCE
                .contains("float OMV_SupplementalPointLightCount : register(c91);")
        );
        assert!(
            CLOSE_TERRAIN_PIXEL_SOURCE
                .contains("sampler2D OMV_SupplementalPointLightTexture : register(s14);")
        );
        assert!(!CLOSE_TERRAIN_PIXEL_SOURCE.contains("OMV_SupplementalPointLightData"));
        assert!(
            CLOSE_TERRAIN_PIXEL_SOURCE.contains(
                "native_point_count = min((int)PointLightCount, PBR_TERRAIN_POINT_LIGHTS);"
            )
        );
        assert!(!CLOSE_TERRAIN_PIXEL_SOURCE.contains("light_color.rgb * saturate(light_color.a)"));
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains(
            "int supplemental_point_count = min((int)OMV_SupplementalPointLightCount, 24 - native_point_count);"
        ));
        assert!(
            CLOSE_TERRAIN_PIXEL_SOURCE
                .contains("int total_point_count = native_point_count + supplemental_point_count;")
        );
        assert!(
            CLOSE_TERRAIN_PIXEL_SOURCE
                .contains("LoadNativePointLight(point_index, light_position, light_color);")
        );
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains(
            "LoadSupplementalPointLight(supplemental_index, light_position, light_color);"
        ));
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("((float)(index * 2) + 0.5f) / 64.0f"));
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("((float)(index * 2) + 1.5f) / 64.0f"));
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("float4(position_u, 0.5f, 0.0f, 0.0f)"));
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("float4(color_u, 0.5f, 0.0f, 0.0f)"));
        assert!(!CLOSE_TERRAIN_PIXEL_SOURCE.contains("PointLightColor[point_index]"));
        assert!(!CLOSE_TERRAIN_PIXEL_SOURCE.contains("PointLightPosition[point_index]"));
    }

    #[test]
    fn close_terrain_selection_is_legacy_preprocessor_safe() {
        assert!(!CLOSE_TERRAIN_PIXEL_SOURCE.contains("#define OMV_SELECT_"));
        assert!(!CLOSE_TERRAIN_PIXEL_SOURCE.contains("OMV_SELECT_"));
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("[branch] if (index < 12)"));
        assert!(!CLOSE_TERRAIN_PIXEL_SOURCE.contains("OMV_LOAD_SUPPLEMENTAL_POINT_LIGHT"));
        assert_eq!(CLOSE_TERRAIN_PIXEL_SOURCE.matches("tex2Dlod(").count(), 2);
        for index in 0..24 {
            assert!(
                CLOSE_TERRAIN_PIXEL_SOURCE
                    .contains(&format!("OMV_LOAD_NATIVE_POINT_LIGHT({index})")),
                "native selector omitted index {index}"
            );
        }
    }

    #[test]
    fn close_terrain_constant_selection_rejects_the_linear_compiler_cascade() {
        let template_id = close_terrain_template_id(ShaderStage::Pixel, 2093).unwrap();
        let template = template_at(template_id).unwrap();
        let optimized_source = template_source(template_id, template);
        let optimized_text = std::str::from_utf8(optimized_source.as_ref()).unwrap();
        let negative_source = optimized_text
            .replace(
                "sampler2D OMV_SupplementalPointLightTexture : register(s14);",
                "float4 OMV_SupplementalPointLightData[48] : register(c92);",
            )
            .replace(
                r#"    // Adjacent position/color texels keep one light's complete record in the
    // same short cache span. The 64-wide power-of-two layout also makes both
    // texel centers exactly representable in shader-model-3 arithmetic.
    float position_u = ((float)(index * 2) + 0.5f) / 64.0f;
    float color_u = ((float)(index * 2) + 1.5f) / 64.0f;
    light_position = tex2Dlod(
        OMV_SupplementalPointLightTexture,
        float4(position_u, 0.5f, 0.0f, 0.0f)
    );
    light_color = tex2Dlod(
        OMV_SupplementalPointLightTexture,
        float4(color_u, 0.5f, 0.0f, 0.0f)
    );"#,
                r#"    light_position = OMV_SupplementalPointLightData[index * 2];
    light_color = OMV_SupplementalPointLightData[index * 2 + 1];"#,
            );
        assert_ne!(negative_source, optimized_text);

        let optimized = crate::shaders::compile_hlsl_source_target(
            "close-terrain-texture-light-lookup",
            optimized_source.as_ref(),
            "ps_3_0",
        )
        .unwrap();
        let negative = crate::shaders::compile_hlsl_source_target(
            "close-terrain-linear-selector-negative-control",
            negative_source.as_bytes(),
            "ps_3_0",
        )
        .unwrap();
        const CMP: u16 = 88;
        let optimized_compare_selects = compiled_opcode_count(&optimized, CMP);
        let negative_compare_selects = compiled_opcode_count(&negative, CMP);

        assert_eq!(compiled_texture_instruction_count(&optimized), 4);
        assert_eq!(compiled_relative_constant_read_count(&optimized), 0);
        assert!(optimized_compare_selects <= 40);
        assert!(
            negative_compare_selects >= optimized_compare_selects + 80,
            "dynamic constant indexing no longer reproduces the compiler cascade: optimized={optimized_compare_selects}, negative={negative_compare_selects}"
        );
    }

    #[test]
    fn dynamic_constant_arrays_do_not_compile_to_relative_reads() {
        const SPLIT_SOURCE: &[u8] = br#"
float4 LightPosition[24] : register(c0);
float4 LightColor[24] : register(c24);
float LightCount : register(c48);

float4 Main(float2 uv : TEXCOORD0) : COLOR0
{
    float4 result = 0.0f;
    [loop] for (int light_index = 0; light_index < 24; light_index++)
    {
        [branch] if (light_index >= (int)LightCount) break;
        result += LightPosition[light_index] * LightColor[light_index];
    }
    return result + uv.x;
}
"#;
        const INTERLEAVED_SOURCE: &[u8] = br#"
float4 LightData[48] : register(c0);
float LightCount : register(c48);

float4 Main(float2 uv : TEXCOORD0) : COLOR0
{
    float4 result = 0.0f;
    [loop] for (int light_index = 0; light_index < 24; light_index++)
    {
        [branch] if (light_index >= (int)LightCount) break;
        result += LightData[light_index * 2] * LightData[light_index * 2 + 1];
    }
    return result + uv.x;
}
"#;

        let split = crate::shaders::compile_hlsl_source_target(
            "close-terrain-split-array-prototype",
            SPLIT_SOURCE,
            "ps_3_0",
        )
        .unwrap();
        let interleaved = crate::shaders::compile_hlsl_source_target(
            "close-terrain-interleaved-array-negative-control",
            INTERLEAVED_SOURCE,
            "ps_3_0",
        )
        .unwrap();
        const CMP: u16 = 88;
        let split_relative_reads = compiled_relative_constant_read_count(&split);

        // Pixel shader 3.0 does not permit relative c# addressing. The aL loop
        // register can relatively address input registers, not float constants.
        // Both supported compilers therefore lower these HLSL arrays to
        // compare/select instructions. Keep the negative control so source
        // appearance cannot be mistaken for a legal constant-time c# load.
        assert_eq!(split_relative_reads, 0);
        assert!(compiled_opcode_count(&split, CMP) >= 40);
        assert_eq!(compiled_relative_constant_read_count(&interleaved), 0);
        assert!(
            compiled_opcode_count(&interleaved, CMP) >= compiled_opcode_count(&split, CMP) + 40,
            "interleaved index*2 access no longer reproduces the compare/select cascade"
        );
    }

    #[test]
    fn close_terrain_supplemental_lookup_has_no_constant_selector() {
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("void LoadNativePointLight("));
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("void LoadSupplementalPointLight("));
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("[loop] for (int point_index"));
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("float3 PointLightContribution("));
        assert!(!CLOSE_TERRAIN_PIXEL_SOURCE.contains("#define OMV_LOAD_SUPPLEMENTAL"));
        assert!(!CLOSE_TERRAIN_PIXEL_SOURCE.contains("register(c92)"));
        assert_eq!(CLOSE_TERRAIN_PIXEL_SOURCE.matches("tex2Dlod(").count(), 2);
    }

    #[test]
    fn close_terrain_fast_program_has_no_hidden_supplemental_gpu_work() {
        for (fast_sls, supplemental_sls, material_samples) in
            [(2092, 2093, 2usize), (2140, 2141, 14usize)]
        {
            let fast_id = close_terrain_template_id(ShaderStage::Pixel, fast_sls).unwrap();
            let supplemental_id =
                close_terrain_template_id(ShaderStage::Pixel, supplemental_sls).unwrap();
            let fast_template = template_at(fast_id).unwrap();
            let supplemental_template = template_at(supplemental_id).unwrap();
            let fast_source = template_source(fast_id, fast_template);
            let supplemental_source = template_source(supplemental_id, supplemental_template);
            assert!(
                !std::str::from_utf8(fast_source.as_ref())
                    .unwrap()
                    .contains("#define OMV_SUPPLEMENTAL_LIGHTS 1")
            );
            assert!(
                std::str::from_utf8(supplemental_source.as_ref())
                    .unwrap()
                    .contains("#define OMV_SUPPLEMENTAL_LIGHTS 1")
            );

            let fast = crate::shaders::compile_hlsl_source_target(
                fast_template.label,
                fast_source.as_ref(),
                "ps_3_0",
            )
            .unwrap();
            let supplemental = crate::shaders::compile_hlsl_source_target(
                supplemental_template.label,
                supplemental_source.as_ref(),
                "ps_3_0",
            )
            .unwrap();
            assert_eq!(compiled_texture_instruction_count(&fast), material_samples);
            assert_eq!(
                compiled_texture_instruction_count(&supplemental),
                material_samples + 2
            );
            assert!(
                compiled_instruction_opcodes(&fast).len() + 50
                    < compiled_instruction_opcodes(&supplemental).len(),
                "SLS{fast_sls} did not eliminate the supplemental program"
            );
            assert!(
                compiled_temporary_register_count(&fast) + 4
                    <= compiled_temporary_register_count(&supplemental),
                "SLS{fast_sls} retained supplemental register pressure: fast={} supplemental={}",
                compiled_temporary_register_count(&fast),
                compiled_temporary_register_count(&supplemental)
            );
        }
    }

    #[test]
    fn close_terrain_native_light_membership_does_not_change_visibility() {
        assert!(
            VPT_TERRAIN_PIXEL_SOURCE
                .contains("getPointLightingAtt(pointlightDir, att, PointLightColor[i].rgb,")
        );
        assert!(!VPT_TERRAIN_PIXEL_SOURCE.contains("PointLightColor[i].a"));

        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("light_color.rgb,"));
        assert!(!CLOSE_TERRAIN_PIXEL_SOURCE.contains("light_color.rgb * saturate(light_color.a)"));

        let staged_rgb_luminance = 0.25f32 * 0.299 + 0.5 * 0.587 + 1.0 * 0.114;
        let legacy_native_luminance = staged_rgb_luminance * 0.0;
        let supplemental_luminance = staged_rgb_luminance * 1.0;
        assert_eq!(legacy_native_luminance, 0.0);
        assert!(supplemental_luminance > 0.0);
    }

    #[test]
    fn close_terrain_normal_blending_matches_vanilla_center_before_weight_contract() {
        assert_vanilla_centered_normal_contract(VANILLA_TERRAIN_1_PIXEL, 1);
        assert_vanilla_centered_normal_contract(VANILLA_TERRAIN_2_PIXEL, 2);
        assert_vanilla_centered_normal_contract(VANILLA_TERRAIN_7_PIXEL, 7);

        assert!(
            CLOSE_TERRAIN_PIXEL_SOURCE
                .contains("blended_normal += (normal_sample.rgb - 0.5f) * blend;")
        );
        assert!(!CLOSE_TERRAIN_PIXEL_SOURCE.contains("ExpandNormal(blended_normal)"));

        let samples = [[0.75, 0.30, 0.95], [0.20, 0.80, 0.70]];
        let normalized_weights = [0.35, 0.65];
        assert_vector_near(
            centered_weighted_normal(&samples, &normalized_weights),
            legacy_encoded_weighted_normal(&samples, &normalized_weights),
        );

        let unnormalized_weights = [0.10, 0.15];
        let corrected = centered_weighted_normal(&samples, &unnormalized_weights);
        let explicit_vanilla = stable_vector([
            (samples[0][0] - 0.5) * unnormalized_weights[0]
                + (samples[1][0] - 0.5) * unnormalized_weights[1],
            (samples[0][1] - 0.5) * unnormalized_weights[0]
                + (samples[1][1] - 0.5) * unnormalized_weights[1],
            (samples[0][2] - 0.5) * unnormalized_weights[0]
                + (samples[1][2] - 0.5) * unnormalized_weights[1],
        ]);
        assert_vector_near(corrected, explicit_vanilla);
        assert!(
            dot(
                corrected,
                legacy_encoded_weighted_normal(&samples, &unnormalized_weights)
            ) < 0.0
        );
    }

    #[test]
    fn partial_terrain_weights_preserve_overhead_pbr_response() {
        let flat_normal_sample = [[0.5, 0.5, 1.0]];
        let partial_weight = [0.25];
        let corrected = centered_weighted_normal(&flat_normal_sample, &partial_weight);
        let legacy = legacy_encoded_weighted_normal(&flat_normal_sample, &partial_weight);

        assert_vector_near(corrected, [0.0, 0.0, 1.0]);
        assert!(dot(legacy, [0.0, 0.0, 1.0]) < 0.0);
        for metallic in [0.0, 0.3143275] {
            let corrected_light = terrain_diffuse_luminance(
                [0.18, 0.12, 0.08],
                metallic,
                corrected,
                [0.0, 0.0, 1.0],
                0.75,
            );
            let legacy_light = terrain_diffuse_luminance(
                [0.18, 0.12, 0.08],
                metallic,
                legacy,
                [0.0, 0.0, 1.0],
                0.75,
            );
            assert!(corrected_light > 0.05);
            assert_eq!(legacy_light, 0.0);
        }
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("return PointLighting("));
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("lighting += PointLightContribution("));
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("PbrDirect("));
    }

    #[test]
    fn paired_terrain_programs_neutralize_canopy_projection_and_specialize_supplements() {
        assert!(VANILLA_TERRAIN_1_CANOPY_PIXEL.contains("dcl_2d s14"));
        assert!(VANILLA_TERRAIN_1_CANOPY_PIXEL.contains("dcl_2d s15"));
        assert!(VANILLA_TERRAIN_1_CANOPY_PIXEL.contains("texld_pp r1.xyzw, r1.xyzw, s15"));
        assert!(VANILLA_TERRAIN_1_CANOPY_PIXEL.contains("texld_pp r2.xyzw, t6.xyzw, s14"));
        assert!(!CLOSE_TERRAIN_PIXEL_SOURCE.contains("CanopyShadowMap"));
        assert!(!CLOSE_TERRAIN_PIXEL_SOURCE.contains("CanopyShadowMask"));
        assert!(!CLOSE_TERRAIN_PIXEL_SOURCE.contains("CanopyVisibility"));

        for texture_count in 1..=7u16 {
            for row_offset in [0u16, 2, 4, 6] {
                let base_sls = 2092 + (texture_count - 1) * 8 + row_offset;
                let canopy_sls = base_sls + 1;
                let base_id = close_terrain_template_id(ShaderStage::Pixel, base_sls).unwrap();
                let canopy_id = close_terrain_template_id(ShaderStage::Pixel, canopy_sls).unwrap();
                let base = template_at(base_id).unwrap();
                let canopy = template_at(canopy_id).unwrap();
                let base_source = template_source(base_id, base);
                let canopy_source = template_source(canopy_id, canopy);
                let base_bytecode = crate::shaders::compile_hlsl_source_target(
                    base.label,
                    base_source.as_ref(),
                    shader_profile(base.stage),
                )
                .unwrap();
                let canopy_bytecode = crate::shaders::compile_hlsl_source_target(
                    canopy.label,
                    canopy_source.as_ref(),
                    shader_profile(canopy.stage),
                )
                .unwrap();

                assert_ne!(canopy_bytecode, base_bytecode);
                assert_eq!(
                    compiled_texture_instruction_count(&base_bytecode),
                    usize::from(texture_count) * 2,
                    "SLS{base_sls} fast path carries hidden supplemental fetches"
                );
                assert_eq!(
                    compiled_texture_instruction_count(&canopy_bytecode),
                    usize::from(texture_count) * 2 + 2,
                    "SLS{canopy_sls} supplemental path lost its two data fetches"
                );
            }
        }
    }

    #[test]
    fn close_terrain_registry_matches_every_vpt_row() {
        for texture_count in 1..=7u16 {
            for (row_offset, point_light_capacity) in [
                (0u16, 0u16),
                (1, 0),
                (2, 6),
                (3, 6),
                (4, 12),
                (5, 12),
                (6, 24),
                (7, 24),
            ] {
                let sls_number = 2092 + (texture_count - 1) * 8 + row_offset;
                let template_id = close_terrain_template_id(ShaderStage::Pixel, sls_number)
                    .unwrap_or_else(|| panic!("missing close-terrain SLS{sls_number}"));
                let template = template_at(template_id).unwrap();

                assert_eq!(template.sls_number, sls_number);
                assert!(
                    template
                        .defines
                        .contains(&format!("#define PBR_TERRAIN_TEX_COUNT {texture_count}"))
                );
                if point_light_capacity == 0 {
                    assert!(
                        !template
                            .defines
                            .contains("#define PBR_TERRAIN_POINT_LIGHTS")
                    );
                } else {
                    assert!(template.defines.contains(&format!(
                        "#define PBR_TERRAIN_POINT_LIGHTS {point_light_capacity}"
                    )));
                }
                assert!(!template.defines.contains("PBR_TERRAIN_CANOPY_SHADOWS"));
            }
        }
    }

    #[test]
    fn only_combined_specular_templates_use_native_fade() {
        let combined = object_template_id(super::ShaderStage::Pixel, 2017).unwrap();
        let combined_si = object_template_id(super::ShaderStage::Pixel, 2018).unwrap();
        let only_specular = object_template_id(super::ShaderStage::Pixel, 2047).unwrap();
        let diffuse = object_template_id(super::ShaderStage::Pixel, 2000).unwrap();

        assert!(object_template_uses_native_specular_fade(combined.id));
        assert!(object_template_uses_native_specular_fade(combined_si.id));
        assert!(!object_template_uses_native_specular_fade(only_specular.id));
        assert!(!object_template_uses_native_specular_fade(diffuse.id));
    }

    #[test]
    fn all_registered_pbr_shader_variants_compile() {
        let mut failures = Vec::new();

        for template_id in 0..template_count() {
            let template = template_at(template_id as u16)
                .unwrap_or_else(|| panic!("PBR template {template_id} is missing"));
            let source = template_source(template_id as u16, template);
            let profile = shader_profile(template.stage);
            match crate::shaders::compile_hlsl_source_target(
                template.label,
                source.as_ref(),
                profile,
            ) {
                Ok(bytecode) => {
                    let expected_version = match template.stage {
                        ShaderStage::Vertex => 0xfffe_0300,
                        ShaderStage::Pixel => 0xffff_0300,
                    };
                    assert_eq!(
                        bytecode.first().copied(),
                        Some(expected_version),
                        "{} compiled to the wrong shader stage/version",
                        template.label
                    );
                }
                Err(error) => failures.push(format!(
                    "{} ({profile}, SLS{}): {error:#}",
                    template.label, template.sls_number
                )),
            }
        }

        assert!(
            failures.is_empty(),
            "{} PBR shader variant(s) failed to compile:\n{}",
            failures.len(),
            failures.join("\n\n")
        );
    }

    #[test]
    fn every_object_shader_stays_within_static_gpu_budget() {
        let representative_limits = [
            ("SLS2017_p_specular", 2_204, 115, 2),
            ("SLS2034_p_specular_lights4", 5_320, 322, 2),
            ("SLS2035_p_specular_lights4_opt", 5_192, 320, 2),
        ];
        for template_id in 0..object_template_count() {
            let template = object_template_at(template_id as u16).unwrap();
            let source = template_source(template_id as u16, template);
            let bytecode = crate::shaders::compile_hlsl_source_target(
                template.label,
                source.as_ref(),
                shader_profile(template.stage),
            )
            .unwrap();
            let byte_size = bytecode.len() * 4;
            let opcodes = compiled_instruction_opcodes(&bytecode);
            let texture_count = compiled_texture_instruction_count(&bytecode);
            let broad_limit = match template.stage {
                ShaderStage::Vertex if template.defines.contains("PBR_OBJECT_SKIN") => 8_100,
                ShaderStage::Vertex => 3_700,
                ShaderStage::Pixel if template.defines.contains("PBR_OBJECT_HIGH") => 5_500,
                ShaderStage::Pixel if template.defines.contains("PBR_OBJECT_ONLY_SPECULAR") => {
                    3_000
                }
                ShaderStage::Pixel if template.defines.contains("PBR_OBJECT_ONLY_LIGHT") => 3_300,
                ShaderStage::Pixel => 3_400,
            };
            assert!(
                byte_size <= broad_limit,
                "{} grew to {} bytes (family limit {})",
                template.label,
                byte_size,
                broad_limit
            );

            let instruction_limit = match template.stage {
                ShaderStage::Vertex if template.defines.contains("PBR_OBJECT_SKIN") => 530,
                ShaderStage::Vertex => 225,
                ShaderStage::Pixel if template.defines.contains("PBR_OBJECT_HIGH") => 340,
                ShaderStage::Pixel if template.defines.contains("PBR_OBJECT_ONLY_SPECULAR") => 175,
                ShaderStage::Pixel if template.defines.contains("PBR_OBJECT_ONLY_LIGHT") => 170,
                ShaderStage::Pixel => 185,
            };
            assert!(
                opcodes.len() <= instruction_limit,
                "{} grew to {} instructions (family limit {})",
                template.label,
                opcodes.len(),
                instruction_limit
            );
            if template.stage == ShaderStage::Pixel {
                assert!(
                    texture_count <= 9,
                    "{} grew to {} texture samples",
                    template.label,
                    texture_count
                );
            }

            if let Some((_, byte_limit, instruction_limit, texture_limit)) = representative_limits
                .iter()
                .find(|(label, ..)| *label == template.label)
            {
                assert!(
                    byte_size <= *byte_limit,
                    "{} grew to {} bytes (limit {})",
                    template.label,
                    byte_size,
                    byte_limit
                );
                assert!(
                    opcodes.len() <= *instruction_limit,
                    "{} grew to {} instructions (limit {})",
                    template.label,
                    opcodes.len(),
                    instruction_limit
                );
                assert_eq!(
                    texture_count, *texture_limit,
                    "{} texture samples",
                    template.label
                );
            }

            if template.stage == ShaderStage::Pixel && template.defines.contains("PBR_OBJECT_HIGH")
            {
                const IF: u16 = 40;
                const IFC: u16 = 41;
                let conditional_count =
                    compiled_opcode_count(&bytecode, IF) + compiled_opcode_count(&bytecode, IFC);
                let expected = if template.defines.contains("PBR_OBJECT_LIGHTS 9") {
                    5
                } else if template.defines.contains("PBR_OBJECT_SPECULAR") {
                    2
                } else {
                    3
                };
                assert!(
                    conditional_count >= expected,
                    "{} lost uniform inactive-light branches: {} found, {} required",
                    template.label,
                    conditional_count,
                    expected
                );
            }
        }
    }

    #[test]
    fn object_lights_reuse_prepared_material_terms() {
        assert!(NVR_PBR_INCLUDE_SOURCE.contains("struct PbrObjectSurface"));
        assert!(NVR_PBR_INCLUDE_SOURCE.contains("PreparePbrObjectSurface("));
        assert_eq!(
            NVR_OBJECT_TEMPLATE_SOURCE
                .matches("PreparePbrObjectSurface(")
                .count(),
            2,
            "each mutually exclusive object pixel-shader family must prepare material terms once"
        );
        assert_eq!(
            NVR_PBR_INCLUDE_SOURCE
                .matches("saturate(specularStrength)")
                .count(),
            1
        );
        assert_eq!(
            NVR_PBR_INCLUDE_SOURCE
                .matches("saturate(specularFade)")
                .count(),
            1
        );
    }

    #[test]
    fn prepared_object_material_terms_match_the_original_equation() {
        const PI: f32 = std::f32::consts::PI;
        for albedo in [0.02f32, 0.18, 0.8] {
            for fresnel in [0.04f32, 0.35, 0.95] {
                for gloss_power in [1.0f32, 16.0, 128.0] {
                    for ndoth in [0.0f32, 0.25, 0.75, 1.0] {
                        for ndotl in [0.0f32, 0.1, 0.6, 1.0] {
                            for attenuation in [0.0f32, 0.3, 1.0] {
                                for specular_strength in [0.0f32, 0.5, 1.25] {
                                    for specular_fade in [0.0f32, 0.7, 1.5] {
                                        let radiance = ndotl * attenuation;
                                        let distribution =
                                            ndoth.powf(gloss_power) * (gloss_power + 2.0) * 0.125;
                                        let original_diffuse =
                                            (1.0 - fresnel) * albedo / PI * radiance * PI;
                                        let original_specular = (fresnel
                                            * distribution
                                            * radiance
                                            * specular_strength.clamp(0.0, 1.0))
                                        .clamp(0.0, 1.0)
                                            * specular_fade.clamp(0.0, 1.0);

                                        let diffuse_color = albedo / PI;
                                        let distribution_scale = (gloss_power + 2.0) * 0.125;
                                        let prepared_distribution =
                                            ndoth.powf(gloss_power) * distribution_scale;
                                        let prepared_diffuse =
                                            (1.0 - fresnel) * diffuse_color * radiance * PI;
                                        let prepared_specular = (fresnel
                                            * prepared_distribution
                                            * radiance
                                            * specular_strength.clamp(0.0, 1.0))
                                        .clamp(0.0, 1.0)
                                            * specular_fade.clamp(0.0, 1.0);

                                        let diffuse_tolerance =
                                            original_diffuse.abs().max(1.0) * 0.000_001;
                                        let specular_tolerance =
                                            original_specular.abs().max(1.0) * 0.000_001;
                                        assert!(
                                            (prepared_diffuse - original_diffuse).abs()
                                                <= diffuse_tolerance
                                        );
                                        assert!(
                                            (prepared_specular - original_specular).abs()
                                                <= specular_tolerance
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn representative_terrain_bytecode_stays_bounded() {
        let limits = [
            ("SLS2002_v_landlod", 1_708, 90, 0, 4),
            ("SLS2003_p_landlod", 3_996, 211, 5, 11),
            ("SLS2080_v_terrain_fade", 1_584, 87, 0, 2),
            ("SLS2082_p_terrain_fade", 3_520, 192, 3, 12),
            ("SLS2092_p_terrain_t1_l0", 4_368, 248, 2, 11),
            ("SLS2093_p_terrain_t1_l0_canopy", 6_952, 419, 4, 24),
            ("SLS2098_p_terrain_t1_l24", 8_756, 574, 2, 24),
            ("SLS2099_p_terrain_t1_l24_canopy", 9_428, 612, 4, 28),
            ("SLS2140_p_terrain_t7_l0", 5_724, 333, 14, 11),
            ("SLS2141_p_terrain_t7_l0_canopy", 8_308, 504, 16, 23),
            ("SLS2146_p_terrain_t7_l24", 10_112, 659, 14, 24),
            ("SLS2147_p_terrain_t7_l24_canopy", 10_784, 697, 16, 28),
        ];
        for template_id in 0..template_count() {
            let template = template_at(template_id as u16).unwrap();
            if let Some((_, byte_limit, instruction_limit, texture_limit, temporary_limit)) =
                limits.iter().find(|(label, ..)| *label == template.label)
            {
                let source = template_source(template_id as u16, template);
                let bytecode = crate::shaders::compile_hlsl_source_target(
                    template.label,
                    source.as_ref(),
                    shader_profile(template.stage),
                )
                .unwrap();
                let opcodes = compiled_instruction_opcodes(&bytecode);
                let texture_count = compiled_texture_instruction_count(&bytecode);
                let temporary_count = compiled_temporary_register_count(&bytecode);
                assert!(
                    bytecode.len() * 4 <= *byte_limit,
                    "{} grew to {} bytes (limit {})",
                    template.label,
                    bytecode.len() * 4,
                    byte_limit
                );
                assert!(
                    opcodes.len() <= *instruction_limit,
                    "{} grew to {} instructions (limit {})",
                    template.label,
                    opcodes.len(),
                    instruction_limit
                );
                assert_eq!(
                    texture_count, *texture_limit,
                    "{} texture samples",
                    template.label
                );
                assert!(
                    temporary_count <= *temporary_limit,
                    "{} grew to {} temporary registers (limit {})",
                    template.label,
                    temporary_count,
                    temporary_limit
                );
            }
        }
    }

    #[test]
    fn terrain_pbr_normalizes_surface_inputs_once_per_pixel() {
        for (label, source) in [
            ("close terrain", CLOSE_TERRAIN_PIXEL_SOURCE),
            ("terrain fade", TERRAIN_FADE_PIXEL_SOURCE),
            ("land LOD", LAND_LOD_PIXEL_SOURCE),
        ] {
            assert!(
                !source.contains("normal = SafeNormalize(normal"),
                "{label} repeats invariant normal normalization inside its BRDF"
            );
            assert!(
                !source.contains("view_dir = SafeNormalize(view_dir"),
                "{label} repeats invariant view normalization inside its BRDF"
            );
        }
    }

    #[test]
    fn terrain_replacements_do_not_carry_an_unreachable_vanilla_brdf() {
        for (label, source) in [
            ("close terrain", CLOSE_TERRAIN_PIXEL_SOURCE),
            ("terrain fade", TERRAIN_FADE_PIXEL_SOURCE),
        ] {
            assert!(
                !source.contains("TerrainPbrEnabled"),
                "{label} still branches on the replacement-only PBR marker"
            );
            assert!(
                !source.contains("VanillaDirect"),
                "{label} still compiles the unreachable vanilla BRDF"
            );
        }
        assert!(
            !CLOSE_TERRAIN_PIXEL_SOURCE.contains("spec_exponent"),
            "close terrain still computes vanilla-only weighted gloss exponents"
        );
        assert!(!CLOSE_TERRAIN_PIXEL_SOURCE.contains("CopyTerrainWeights"));
        assert!(!CLOSE_TERRAIN_PIXEL_SOURCE.contains("float weights[7]"));
    }

    #[test]
    fn close_terrain_prepares_loop_invariant_brdf_state_once() {
        assert_eq!(
            CLOSE_TERRAIN_PIXEL_SOURCE
                .matches("PreparePbrSurface(")
                .count(),
            2
        );
        let prepare = CLOSE_TERRAIN_PIXEL_SOURCE
            .rfind("PreparePbrSurface(")
            .expect("missing prepared terrain BRDF state call");
        let point_loop = CLOSE_TERRAIN_PIXEL_SOURCE.find("[loop]").unwrap();
        assert!(prepare < point_loop);
        assert_eq!(
            CLOSE_TERRAIN_PIXEL_SOURCE
                .matches("PbrMetallicness()")
                .count(),
            2
        );
        assert_eq!(
            CLOSE_TERRAIN_PIXEL_SOURCE
                .matches("PbrRoughnessScale()")
                .count(),
            2
        );
    }

    #[test]
    fn prepared_terrain_brdf_matches_the_original_equation() {
        const PI: f32 = std::f32::consts::PI;
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("float geometry_numerator ="));
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("float geometry_denominator ="));
        assert!(!CLOSE_TERRAIN_PIXEL_SOURCE.contains("float view_shadowing ="));
        for roughness in [0.043f32, 0.2, 0.55, 1.0] {
            for metallic in [0.0f32, 0.35, 1.0] {
                for albedo in [0.02f32, 0.18, 0.8] {
                    for ndotv in [0.000_01f32, 0.1, 0.6, 1.0] {
                        for ndotl in [0.000_01f32, 0.05, 0.5, 1.0] {
                            for ndoth in [0.0f32, 0.25, 0.75, 1.0] {
                                let ldoth = (0.35f32 + ndoth * 0.5).clamp(0.0, 1.0);
                                let reflectance = 0.04 + (albedo - 0.04) * metallic;
                                let fresnel =
                                    reflectance + (1.0 - reflectance) * (1.0 - ldoth).powi(5);

                                let alpha2 = roughness.powi(4);
                                let distribution_denominator =
                                    (ndoth * alpha2 - ndoth) * ndoth + 1.0;
                                let distribution =
                                    alpha2 / (PI * distribution_denominator.powi(2)).max(0.000_01);
                                let geometry_k = (roughness + 1.0).powi(2) * 0.125;
                                let view_shadowing = ndotv
                                    / (ndotv * (1.0 - geometry_k) + geometry_k).max(0.000_000_01);
                                let light_shadowing = ndotl
                                    / (ndotl * (1.0 - geometry_k) + geometry_k).max(0.000_000_01);

                                let original_geometry = view_shadowing * light_shadowing;
                                let original_specular = distribution * original_geometry * fresnel
                                    / (4.0 * ndotv * ndotl).max(0.000_01);
                                let original_diffuse =
                                    (1.0 - fresnel) * albedo / PI * (1.0 - metallic);
                                let original = (original_diffuse + original_specular) * ndotl * PI;

                                let prepared_diffuse_color = albedo * (1.0 - metallic) / PI;
                                let view_denominator =
                                    (ndotv * (1.0 - geometry_k) + geometry_k).max(0.000_000_01);
                                let light_denominator =
                                    (ndotl * (1.0 - geometry_k) + geometry_k).max(0.000_000_01);
                                let geometry_numerator = ndotv * ndotl;
                                let geometry_denominator = view_denominator
                                    * light_denominator
                                    * (4.0 * geometry_numerator).max(0.000_01);
                                let prepared_specular = distribution * fresnel * geometry_numerator
                                    / geometry_denominator;
                                let prepared = ((1.0 - fresnel) * prepared_diffuse_color
                                    + prepared_specular)
                                    * ndotl
                                    * PI;
                                let tolerance = original.abs().max(1.0) * 0.000_001;
                                assert!((prepared - original).abs() <= tolerance);
                            }
                        }
                    }
                }
            }
        }
    }
}
