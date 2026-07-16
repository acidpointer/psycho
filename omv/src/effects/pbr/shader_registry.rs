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
    use super::{shader_profile, template_at, template_count, template_source};

    #[test]
    fn all_registered_pbr_shader_variants_compile() {
        let mut failures = Vec::new();

        for template_id in 0..template_count() {
            let template = template_at(template_id as u16)
                .unwrap_or_else(|| panic!("PBR template {template_id} is missing"));
            let source = template_source(template_id as u16, template);
            let profile = shader_profile(template.stage);
            if let Err(error) =
                crate::shaders::compile_hlsl_source_target(template.label, source.as_ref(), profile)
            {
                failures.push(format!(
                    "{} ({profile}, SLS{}): {error:#}",
                    template.label, template.sls_number
                ));
            }
        }

        assert!(
            failures.is_empty(),
            "{} PBR shader variant(s) failed to compile:\n{}",
            failures.len(),
            failures.join("\n\n")
        );
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
