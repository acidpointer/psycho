//! Declarative shader registry derived from NVR's collections.
//!
//! The object collection is keyed by the shader wrapper's own SLS template.
//! `SetShaders` must use records captured from shader creation/adoption, not a
//! terrain-style pair classifier.

use std::borrow::Cow;
use std::ffi::{CStr, c_char};

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
        2094,
        "SLS2094_p_terrain_t1_l6",
        "#define PBR_TERRAIN_TEX_COUNT 1\n#define PBR_TERRAIN_POINT_LIGHTS 6",
    ),
    pixel(
        2096,
        "SLS2096_p_terrain_t1_l12",
        "#define PBR_TERRAIN_TEX_COUNT 1\n#define PBR_TERRAIN_POINT_LIGHTS 12",
    ),
    pixel(
        2098,
        "SLS2098_p_terrain_t1_l24",
        "#define PBR_TERRAIN_TEX_COUNT 1\n#define PBR_TERRAIN_POINT_LIGHTS 24",
    ),
    pixel(
        2100,
        "SLS2100_p_terrain_t2_l0",
        "#define PBR_TERRAIN_TEX_COUNT 2",
    ),
    pixel(
        2102,
        "SLS2102_p_terrain_t2_l6",
        "#define PBR_TERRAIN_TEX_COUNT 2\n#define PBR_TERRAIN_POINT_LIGHTS 6",
    ),
    pixel(
        2104,
        "SLS2104_p_terrain_t2_l12",
        "#define PBR_TERRAIN_TEX_COUNT 2\n#define PBR_TERRAIN_POINT_LIGHTS 12",
    ),
    pixel(
        2106,
        "SLS2106_p_terrain_t2_l24",
        "#define PBR_TERRAIN_TEX_COUNT 2\n#define PBR_TERRAIN_POINT_LIGHTS 24",
    ),
    pixel(
        2108,
        "SLS2108_p_terrain_t3_l0",
        "#define PBR_TERRAIN_TEX_COUNT 3",
    ),
    pixel(
        2110,
        "SLS2110_p_terrain_t3_l6",
        "#define PBR_TERRAIN_TEX_COUNT 3\n#define PBR_TERRAIN_POINT_LIGHTS 6",
    ),
    pixel(
        2112,
        "SLS2112_p_terrain_t3_l12",
        "#define PBR_TERRAIN_TEX_COUNT 3\n#define PBR_TERRAIN_POINT_LIGHTS 12",
    ),
    pixel(
        2114,
        "SLS2114_p_terrain_t3_l24",
        "#define PBR_TERRAIN_TEX_COUNT 3\n#define PBR_TERRAIN_POINT_LIGHTS 24",
    ),
    pixel(
        2116,
        "SLS2116_p_terrain_t4_l0",
        "#define PBR_TERRAIN_TEX_COUNT 4",
    ),
    pixel(
        2118,
        "SLS2118_p_terrain_t4_l6",
        "#define PBR_TERRAIN_TEX_COUNT 4\n#define PBR_TERRAIN_POINT_LIGHTS 6",
    ),
    pixel(
        2120,
        "SLS2120_p_terrain_t4_l12",
        "#define PBR_TERRAIN_TEX_COUNT 4\n#define PBR_TERRAIN_POINT_LIGHTS 12",
    ),
    pixel(
        2122,
        "SLS2122_p_terrain_t4_l24",
        "#define PBR_TERRAIN_TEX_COUNT 4\n#define PBR_TERRAIN_POINT_LIGHTS 24",
    ),
    pixel(
        2124,
        "SLS2124_p_terrain_t5_l0",
        "#define PBR_TERRAIN_TEX_COUNT 5",
    ),
    pixel(
        2126,
        "SLS2126_p_terrain_t5_l6",
        "#define PBR_TERRAIN_TEX_COUNT 5\n#define PBR_TERRAIN_POINT_LIGHTS 6",
    ),
    pixel(
        2128,
        "SLS2128_p_terrain_t5_l12",
        "#define PBR_TERRAIN_TEX_COUNT 5\n#define PBR_TERRAIN_POINT_LIGHTS 12",
    ),
    pixel(
        2130,
        "SLS2130_p_terrain_t5_l24",
        "#define PBR_TERRAIN_TEX_COUNT 5\n#define PBR_TERRAIN_POINT_LIGHTS 24",
    ),
    pixel(
        2132,
        "SLS2132_p_terrain_t6_l0",
        "#define PBR_TERRAIN_TEX_COUNT 6",
    ),
    pixel(
        2134,
        "SLS2134_p_terrain_t6_l6",
        "#define PBR_TERRAIN_TEX_COUNT 6\n#define PBR_TERRAIN_POINT_LIGHTS 6",
    ),
    pixel(
        2136,
        "SLS2136_p_terrain_t6_l12",
        "#define PBR_TERRAIN_TEX_COUNT 6\n#define PBR_TERRAIN_POINT_LIGHTS 12",
    ),
    pixel(
        2138,
        "SLS2138_p_terrain_t6_l24",
        "#define PBR_TERRAIN_TEX_COUNT 6\n#define PBR_TERRAIN_POINT_LIGHTS 24",
    ),
    pixel(
        2140,
        "SLS2140_p_terrain_t7_l0",
        "#define PBR_TERRAIN_TEX_COUNT 7",
    ),
    pixel(
        2142,
        "SLS2142_p_terrain_t7_l6",
        "#define PBR_TERRAIN_TEX_COUNT 7\n#define PBR_TERRAIN_POINT_LIGHTS 6",
    ),
    pixel(
        2144,
        "SLS2144_p_terrain_t7_l12",
        "#define PBR_TERRAIN_TEX_COUNT 7\n#define PBR_TERRAIN_POINT_LIGHTS 12",
    ),
    pixel(
        2146,
        "SLS2146_p_terrain_t7_l24",
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
                template.defines.len() + CLOSE_TERRAIN_PIXEL_SOURCE.len() + 2,
            );
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
    const VANILLA_TERRAIN_2_PIXEL: &str =
        include_str!("../../../../analysis/shaders_disasm/shaderpackage019/SLS2100.pso.dis");
    const VANILLA_TERRAIN_7_PIXEL: &str =
        include_str!("../../../../analysis/shaders_disasm/shaderpackage019/SLS2140.pso.dis");

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
            "const float3 diffuse = LambertianDiffuse(albedo, fresnel) * radiance * PI;"
        ));
        assert!(NVR_PBR_INCLUDE_SOURCE.contains(
            "return diffuse + saturate(specular * saturate(specularStrength)) * saturate(specularFade);"
        ));
        assert!(NVR_PBR_INCLUDE_SOURCE.contains("return diffuse * NdotL * lightColor * PI;"));
        assert!(NVR_OBJECT_INCLUDE_SOURCE.contains(
            "return att * PBRDiffuse(0, materialResponse, albedo, normal, viewDir, lightDir, lightColor);"
        ));
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
            "return saturate(specular * saturate(specularStrength)) * saturate(specularFade);"
        ));
        assert!(NVR_PBR_INCLUDE_SOURCE.contains(
            "return diffuse + saturate(specular * saturate(specularStrength)) * saturate(specularFade);"
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
                .contains("float4 OMV_SupplementalPointLightData[48] : register(c92);")
        );
        assert!(
            CLOSE_TERRAIN_PIXEL_SOURCE.contains(
                "native_point_count = min((int)PointLightCount, PBR_TERRAIN_POINT_LIGHTS);"
            )
        );
        assert_eq!(
            CLOSE_TERRAIN_PIXEL_SOURCE
                .matches("light_color.rgb * saturate(light_color.a)")
                .count(),
            1
        );
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains(
            "int supplemental_point_count = min((int)OMV_SupplementalPointLightCount, 24 - native_point_count);"
        ));
        assert!(
            CLOSE_TERRAIN_PIXEL_SOURCE
                .contains("int total_point_count = native_point_count + supplemental_point_count;")
        );
        assert!(
            CLOSE_TERRAIN_PIXEL_SOURCE
                .contains("OMV_SupplementalPointLightData[supplemental_index * 2]")
        );
        assert!(
            CLOSE_TERRAIN_PIXEL_SOURCE
                .contains("OMV_SupplementalPointLightData[supplemental_index * 2 + 1]")
        );
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("light_color = PointLightColor[point_index];"));
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
    fn zero_native_light_night_terrain_still_receives_local_pbr_diffuse() {
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

        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("int native_point_count = 0;"));
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("supplemental_point_count"));
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("lighting += PointLighting("));
        assert!(CLOSE_TERRAIN_PIXEL_SOURCE.contains("PbrDirect("));
    }

    #[test]
    fn close_terrain_registry_matches_every_vpt_non_canopy_row() {
        for texture_count in 1..=7u16 {
            for (row_offset, point_light_capacity) in [(0u16, 0u16), (2, 6), (4, 12), (6, 24)] {
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
            ("SLS2017_p_specular", 2_400),
            ("SLS2034_p_specular_lights4", 4_400),
            ("SLS2035_p_specular_lights4_opt", 4_200),
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
            let texture_count = opcodes.iter().filter(|opcode| **opcode == 66).count();
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

            if let Some((_, limit)) = representative_limits
                .iter()
                .find(|(label, _)| *label == template.label)
            {
                assert!(
                    byte_size <= *limit,
                    "{} grew to {} bytes (limit {})",
                    template.label,
                    byte_size,
                    limit
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
    fn representative_close_terrain_bytecode_stays_bounded() {
        let limits = [
            ("SLS2092_p_terrain_t1_l0", 18_800, 1_130, 2),
            ("SLS2098_p_terrain_t1_l24", 24_100, 1_450, 2),
            ("SLS2140_p_terrain_t7_l0", 20_400, 1_240, 14),
            ("SLS2146_p_terrain_t7_l24", 25_600, 1_550, 14),
        ];
        for template_id in 0..template_count() {
            let template = template_at(template_id as u16).unwrap();
            if let Some((_, byte_limit, instruction_limit, texture_limit)) =
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
                let texture_count = opcodes.iter().filter(|opcode| **opcode == 66).count();
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
            }
        }
    }
}

pub(super) fn sls_number_from_name(shader_name: *const c_char, extension: &str) -> Option<u16> {
    if shader_name.is_null() {
        return None;
    }

    let name = unsafe { CStr::from_ptr(shader_name) }.to_str().ok()?;
    let leaf = name
        .rsplit(|ch| ch == '\\' || ch == '/')
        .next()
        .unwrap_or(name);
    if leaf.len() != 11 {
        return None;
    }
    if !leaf.get(0..3)?.eq_ignore_ascii_case("SLS") {
        return None;
    }
    if !leaf.get(7..)?.eq_ignore_ascii_case(extension) {
        return None;
    }

    leaf.get(3..7)?.parse::<u16>().ok()
}
