//! OMV-owned close-terrain light supplementation.
//!
//! The engine's general active-light iterator includes shadow-classified
//! portable lights. Landscape pass builders based on the non-shadow iterator
//! can omit those lights. OMV merges only missing native identities into its
//! replacement shader constants and never mutates the engine render pass.

use std::{ffi::c_void, mem::size_of};

use libpsycho::ffi::fnptr::FnPtr;

use super::engine_contracts;

pub(super) const MAX_TERRAIN_POINT_LIGHTS: usize = 24;
pub(super) const MAX_SUPPLEMENTAL_CONSTANTS: usize = MAX_TERRAIN_POINT_LIGHTS * 2 + 1;

const GENERAL_LIGHT_FIRST_ADDR: usize = 0x00B70590;
const GENERAL_LIGHT_NEXT_ADDR: usize = 0x00B70680;
const AABB_CHECK_BOUND_ADDR: usize = 0x00C382B0;
const BUILD_GEOMETRY_MATRIX_ADDR: usize = 0x00C4C2D0;
const SHADOW_SCENE_NODE_SLOT_ADDR: usize = 0x011F91C8;
const HDR_ENABLED_ADDR: usize = 0x011F941E;
const POINT_LIGHT_OVERRIDE_COLOR_ADDR: usize = 0x011F4998;

const GEOMETRY_PARENT_OFFSET: usize = 0x18;
const GEOMETRY_WORLD_TRANSFORM_OFFSET: usize = 0x68;
const GEOMETRY_WORLD_SCALE_OFFSET: usize = 0x98;
const GEOMETRY_LIGHTING_PROPERTY_OFFSET: usize = 0xA8;
const GEOMETRY_MATRIX_CONTEXT_OFFSET: usize = 0xBC;
const LIGHTING_PROPERTY_LIGHT_SCALE_OFFSET: usize = 0x6C;

const RENDER_PASS_LIGHT_COUNT_OFFSET: usize = 0x09;
const RENDER_PASS_LIGHT_ARRAY_OFFSET: usize = 0x0C;
const MAX_RENDER_PASS_LIGHTS: usize = MAX_TERRAIN_POINT_LIGHTS + 1;

const SCENE_LIGHT_LOD_DIMMER_OFFSET: usize = 0xD0;
const SCENE_LIGHT_POINT_OFFSET: usize = 0xF4;
const SCENE_LIGHT_AMBIENT_OFFSET: usize = 0xF5;
const SCENE_LIGHT_NATIVE_LIGHT_OFFSET: usize = 0xF8;

const NATIVE_LIGHT_POSITION_OFFSET: usize = 0x8C;
const NATIVE_LIGHT_DIMMER_OFFSET: usize = 0xC4;
const NATIVE_LIGHT_DIFFUSE_OFFSET: usize = 0xD4;
const NATIVE_LIGHT_RADIUS_OFFSET: usize = 0xE0;
const NATIVE_LIGHT_DISABLED_FLAGS_OFFSET: usize = 0x30;

const SHADOW_SCENE_NODE_LIGHTING_OFFSET: usize = 0x1E4;
const NIOBJECT_IS_MULTIBOUND_NODE_VTABLE_OFFSET: usize = 0x14;
const MULTIBOUND_NODE_MULTIBOUND_OFFSET: usize = 0xAC;
const MULTIBOUND_SHAPE_OFFSET: usize = 0x0C;
const MAX_GENERAL_LIGHT_SCAN: usize = 64;
const MIN_ENGINE_PTR: usize = 0x10000;
const LIGHT_COMPONENT_MIN: f32 = 1.0 / 255.0;

type GeneralLightFirstFn =
    unsafe extern "thiscall" fn(*mut c_void, *mut *mut c_void) -> *mut c_void;
type GeneralLightNextFn = unsafe extern "thiscall" fn(*mut c_void, *mut *mut c_void) -> *mut c_void;
type IsMultiBoundNodeFn = unsafe extern "thiscall" fn(*mut c_void) -> *mut c_void;
type CheckBoundFn = unsafe extern "thiscall" fn(*mut c_void, *const NiBound) -> i32;
type BuildGeometryMatrixFn =
    unsafe extern "cdecl" fn(*const c_void, *const c_void, *mut [[f32; 4]; 4]);

#[repr(C)]
struct NiBound {
    center: [f32; 3],
    radius: f32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct GeometryTransform {
    world_to_local: [[f32; 4]; 4],
    scale: f32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct TerrainLightCandidate {
    identity: usize,
    point: bool,
    ambient: bool,
    relative_position: [f32; 3],
    radius: f32,
    diffuse: [f32; 3],
    dimmer: f32,
    lod_dimmer: f32,
    in_multibound: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct ShaderTerrainLight {
    position_radius: [f32; 4],
    color_visibility: [f32; 4],
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct TerrainLightContext {
    transform: GeometryTransform,
    lighting_offset: [f32; 3],
    property_light_scale: f32,
    point_light_override_color: [f32; 3],
    hdr: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct SupplementalTerrainLights {
    lights: [ShaderTerrainLight; MAX_TERRAIN_POINT_LIGHTS],
    identities: [usize; MAX_TERRAIN_POINT_LIGHTS],
    count: usize,
}

impl Default for SupplementalTerrainLights {
    fn default() -> Self {
        Self {
            lights: [ShaderTerrainLight::default(); MAX_TERRAIN_POINT_LIGHTS],
            identities: [0; MAX_TERRAIN_POINT_LIGHTS],
            count: 0,
        }
    }
}

impl SupplementalTerrainLights {
    pub(super) fn write_shader_constants(&self, output: &mut [[f32; 4]]) -> usize {
        debug_assert!(output.len() >= MAX_SUPPLEMENTAL_CONSTANTS);
        output[0] = [self.count as f32, 0.0, 0.0, 0.0];
        for (index, light) in self.lights[..self.count].iter().enumerate() {
            output[1 + index * 2] = light.position_radius;
            output[2 + index * 2] = light.color_visibility;
        }
        1 + self.count * 2
    }

    #[cfg(test)]
    fn lights(&self) -> &[ShaderTerrainLight] {
        &self.lights[..self.count]
    }
}

struct TerrainLightMerge<'a> {
    native_identities: &'a [usize],
    remaining_capacity: usize,
    context: TerrainLightContext,
    output: SupplementalTerrainLights,
}

impl<'a> TerrainLightMerge<'a> {
    fn new(
        native_identities: &'a [usize],
        native_point_count: usize,
        context: TerrainLightContext,
    ) -> Self {
        Self {
            native_identities,
            remaining_capacity: MAX_TERRAIN_POINT_LIGHTS
                .saturating_sub(native_point_count.min(MAX_TERRAIN_POINT_LIGHTS)),
            context,
            output: SupplementalTerrainLights::default(),
        }
    }

    fn consider(&mut self, candidate: TerrainLightCandidate) -> bool {
        if !self.needs_identity(candidate.identity) {
            return false;
        }
        let Some(light) = shader_light(candidate, self.context) else {
            return false;
        };

        let index = self.output.count;
        self.output.identities[index] = candidate.identity;
        self.output.lights[index] = light;
        self.output.count += 1;
        true
    }

    fn finish(self) -> SupplementalTerrainLights {
        self.output
    }

    fn is_full(&self) -> bool {
        self.output.count >= self.remaining_capacity
    }

    fn needs_identity(&self, identity: usize) -> bool {
        !self.is_full()
            && identity >= MIN_ENGINE_PTR
            && !self.native_identities.contains(&identity)
            && !self.output.identities[..self.output.count].contains(&identity)
    }
}

pub(super) fn capture_current() -> SupplementalTerrainLights {
    unsafe { capture_current_unchecked() }.unwrap_or_default()
}

unsafe fn capture_current_unchecked() -> Option<SupplementalTerrainLights> {
    let geometry = engine_contracts::current_geometry_fast()?;
    let render_pass = engine_contracts::current_pass_fast()?;
    let property = unsafe { read_ptr_offset(geometry, GEOMETRY_LIGHTING_PROPERTY_OFFSET) }?;
    let mut native_identities = [0usize; MAX_RENDER_PASS_LIGHTS];
    let (native_identity_count, native_point_count) =
        unsafe { read_native_light_identities(render_pass, &mut native_identities) };
    if native_point_count >= MAX_TERRAIN_POINT_LIGHTS {
        return Some(SupplementalTerrainLights::default());
    }

    let property_light_scale =
        unsafe { read_copy::<f32>(property, LIGHTING_PROPERTY_LIGHT_SCALE_OFFSET) };
    if !property_light_scale.is_finite() {
        return Some(SupplementalTerrainLights::default());
    }
    let scene_node = unsafe { read_shadow_scene_node() }?;
    let context = TerrainLightContext {
        transform: unsafe { read_geometry_transform(geometry) }?,
        lighting_offset: unsafe { read_vec3(scene_node, SHADOW_SCENE_NODE_LIGHTING_OFFSET) },
        property_light_scale,
        point_light_override_color: unsafe {
            read_vec3(POINT_LIGHT_OVERRIDE_COLOR_ADDR as *mut c_void, 0)
        },
        hdr: unsafe { (HDR_ENABLED_ADDR as *const u8).read() != 0 },
    };

    let mut merge = TerrainLightMerge::new(
        &native_identities[..native_identity_count],
        native_point_count,
        context,
    );
    if merge.is_full() {
        return Some(merge.finish());
    }

    let multibound_shape = unsafe { geometry_multibound_shape(geometry) };
    let first = unsafe {
        FnPtr::<GeneralLightFirstFn>::from_address_unchecked(GENERAL_LIGHT_FIRST_ADDR).as_fn()
    };
    let next = unsafe {
        FnPtr::<GeneralLightNextFn>::from_address_unchecked(GENERAL_LIGHT_NEXT_ADDR).as_fn()
    };
    let mut iterator = std::ptr::null_mut();
    let mut scene_light = unsafe { first(property, &mut iterator) };
    let mut scanned = 0usize;
    while !scene_light.is_null() && scanned < MAX_GENERAL_LIGHT_SCAN && !merge.is_full() {
        scanned += 1;
        let native_identity = unsafe {
            read_ptr_offset(scene_light, SCENE_LIGHT_NATIVE_LIGHT_OFFSET)
                .map(|light| light as usize)
        };
        if native_identity.is_some_and(|identity| merge.needs_identity(identity))
            && let Some(candidate) = unsafe { read_candidate(scene_light, multibound_shape) }
        {
            merge.consider(candidate);
        }
        scene_light = unsafe { next(property, &mut iterator) };
    }

    // A zero-point row can expose no property-local candidate even though the
    // scene manager owns an active portable light.
    if manager_fallback_needed(native_point_count, merge.output.count) && !merge.is_full() {
        supplement_manager_lights(multibound_shape, &mut merge);
    }

    Some(merge.finish())
}

fn supplement_manager_lights(
    multibound_shape: Option<*mut c_void>,
    merge: &mut TerrainLightMerge<'_>,
) {
    let _ = crate::fnv_local_lights::try_with_current_terrain_lights(|lights| {
        supplement_captured_manager_lights(lights, multibound_shape, merge);
    });
}

fn supplement_captured_manager_lights(
    lights: &[crate::fnv_local_lights::TerrainSceneLight],
    multibound_shape: Option<*mut c_void>,
    merge: &mut TerrainLightMerge<'_>,
) {
    for light in lights {
        if merge.is_full() {
            break;
        }
        let candidate = TerrainLightCandidate {
            identity: light.native_light_identity,
            point: light.point,
            ambient: light.ambient,
            relative_position: light.relative_position,
            radius: light.radius,
            diffuse: light.diffuse,
            dimmer: light.dimmer,
            lod_dimmer: light.lod_dimmer,
            in_multibound: unsafe {
                light_intersects_multibound(light.relative_position, light.radius, multibound_shape)
            },
        };
        merge.consider(candidate);
    }
}

fn manager_fallback_needed(native_point_count: usize, supplemental_point_count: usize) -> bool {
    native_point_count == 0 && supplemental_point_count == 0
}

fn shader_light(
    candidate: TerrainLightCandidate,
    context: TerrainLightContext,
) -> Option<ShaderTerrainLight> {
    if !candidate.point
        || candidate.ambient
        || !candidate.in_multibound
        || context.transform.scale <= f32::EPSILON
    {
        return None;
    }
    if !candidate
        .relative_position
        .iter()
        .chain(candidate.diffuse.iter())
        .chain(
            [
                candidate.radius,
                candidate.dimmer,
                candidate.lod_dimmer,
                context.property_light_scale,
                context.transform.scale,
            ]
            .iter(),
        )
        .chain(context.point_light_override_color.iter())
        .chain(context.lighting_offset.iter())
        .chain(context.transform.world_to_local.iter().flatten())
        .all(|value| value.is_finite())
    {
        return None;
    }
    if candidate.radius <= 0.0 || candidate.dimmer < 0.0 || candidate.lod_dimmer < 0.0 {
        return None;
    }

    let world_position = add3(candidate.relative_position, context.lighting_offset);
    let local_position = inverse_transform_point(world_position, context.transform)?;
    let radius = candidate.radius / context.transform.scale;
    let color = if context.property_light_scale < 1.0 {
        context.point_light_override_color
    } else {
        let dimmer = if !context.hdr && candidate.dimmer > 1.0 {
            1.0
        } else {
            candidate.dimmer
        } * context.property_light_scale
            * candidate.lod_dimmer;
        candidate.diffuse.map(|component| component * dimmer)
    };
    if !radius.is_finite()
        || radius <= 0.0
        || !color.iter().all(|component| component.is_finite())
        || !color
            .iter()
            .any(|component| *component > LIGHT_COMPONENT_MIN)
    {
        return None;
    }

    Some(ShaderTerrainLight {
        position_radius: [
            local_position[0],
            local_position[1],
            local_position[2],
            radius,
        ],
        // This path exists only for a point light omitted by the native
        // non-shadow terrain pass. ShadowSceneLight+0xD4 can be zero while
        // that light remains valid illumination, and VPT terrain consumes
        // the staged RGB without using alpha. Keep native-row alpha fading in
        // the shader, but make OMV-owned supplemental visibility explicit.
        color_visibility: [color[0], color[1], color[2], 1.0],
    })
}

fn inverse_transform_point(point: [f32; 3], transform: GeometryTransform) -> Option<[f32; 3]> {
    let matrix = transform.world_to_local;
    let w =
        point[0] * matrix[0][3] + point[1] * matrix[1][3] + point[2] * matrix[2][3] + matrix[3][3];
    if !w.is_finite() || w.abs() <= f32::EPSILON {
        return None;
    }
    let local = [
        (point[0] * matrix[0][0]
            + point[1] * matrix[1][0]
            + point[2] * matrix[2][0]
            + matrix[3][0])
            / w,
        (point[0] * matrix[0][1]
            + point[1] * matrix[1][1]
            + point[2] * matrix[2][1]
            + matrix[3][1])
            / w,
        (point[0] * matrix[0][2]
            + point[1] * matrix[1][2]
            + point[2] * matrix[2][2]
            + matrix[3][2])
            / w,
    ];
    local.iter().all(|value| value.is_finite()).then_some(local)
}

unsafe fn read_native_light_identities(
    render_pass: *mut c_void,
    identities: &mut [usize; MAX_RENDER_PASS_LIGHTS],
) -> (usize, usize) {
    let light_count =
        usize::from(unsafe { read_copy::<u8>(render_pass, RENDER_PASS_LIGHT_COUNT_OFFSET) })
            .min(MAX_RENDER_PASS_LIGHTS);
    let Some(light_array) =
        (unsafe { read_ptr_offset(render_pass, RENDER_PASS_LIGHT_ARRAY_OFFSET) })
    else {
        return (0, 0);
    };

    let mut identity_count = 0usize;
    let mut point_count = 0usize;
    for index in 0..light_count {
        let scene_light = unsafe { read_ptr_offset(light_array, index * size_of::<usize>()) };
        let Some(scene_light) = scene_light else {
            continue;
        };
        let native_light = unsafe { read_ptr_offset(scene_light, SCENE_LIGHT_NATIVE_LIGHT_OFFSET) };
        let Some(native_light) = native_light else {
            continue;
        };
        identities[identity_count] = native_light as usize;
        identity_count += 1;

        let point = unsafe { read_copy::<u8>(scene_light, SCENE_LIGHT_POINT_OFFSET) } != 0;
        let ambient = unsafe { read_copy::<u8>(scene_light, SCENE_LIGHT_AMBIENT_OFFSET) } != 0;
        if point && !ambient {
            point_count += 1;
        }
    }
    (identity_count, point_count)
}

unsafe fn read_candidate(
    scene_light: *mut c_void,
    multibound_shape: Option<*mut c_void>,
) -> Option<TerrainLightCandidate> {
    if (scene_light as usize) < MIN_ENGINE_PTR {
        return None;
    }
    let native_light = unsafe { read_ptr_offset(scene_light, SCENE_LIGHT_NATIVE_LIGHT_OFFSET) }?;
    if (native_light as usize) < MIN_ENGINE_PTR
        || unsafe { read_copy::<u8>(native_light, NATIVE_LIGHT_DISABLED_FLAGS_OFFSET) } & 1 != 0
    {
        return None;
    }

    let relative_position = unsafe { read_vec3(native_light, NATIVE_LIGHT_POSITION_OFFSET) };
    let radius = unsafe { read_copy::<f32>(native_light, NATIVE_LIGHT_RADIUS_OFFSET) };
    Some(TerrainLightCandidate {
        identity: native_light as usize,
        point: unsafe { read_copy::<u8>(scene_light, SCENE_LIGHT_POINT_OFFSET) } != 0,
        ambient: unsafe { read_copy::<u8>(scene_light, SCENE_LIGHT_AMBIENT_OFFSET) } != 0,
        relative_position,
        radius,
        diffuse: unsafe { read_vec3(native_light, NATIVE_LIGHT_DIFFUSE_OFFSET) },
        dimmer: unsafe { read_copy::<f32>(native_light, NATIVE_LIGHT_DIMMER_OFFSET) },
        lod_dimmer: unsafe { read_copy::<f32>(scene_light, SCENE_LIGHT_LOD_DIMMER_OFFSET) },
        in_multibound: unsafe {
            light_intersects_multibound(relative_position, radius, multibound_shape)
        },
    })
}

unsafe fn geometry_multibound_shape(geometry: *mut c_void) -> Option<*mut c_void> {
    let parent = unsafe { read_ptr_offset(geometry, GEOMETRY_PARENT_OFFSET) }?;
    let vtable = unsafe { read_ptr_offset(parent, 0) }?;
    let method = unsafe { read_ptr_offset(vtable, NIOBJECT_IS_MULTIBOUND_NODE_VTABLE_OFFSET) }?;
    let is_multibound_node = unsafe { FnPtr::<IsMultiBoundNodeFn>::from_raw(method).ok()? }.as_fn();
    let node = unsafe { is_multibound_node(parent) };
    if node.is_null() {
        return None;
    }
    let multibound = unsafe { read_ptr_offset(node, MULTIBOUND_NODE_MULTIBOUND_OFFSET) }?;
    unsafe { read_ptr_offset(multibound, MULTIBOUND_SHAPE_OFFSET) }
}

unsafe fn light_intersects_multibound(
    center: [f32; 3],
    radius: f32,
    shape: Option<*mut c_void>,
) -> bool {
    let Some(shape) = shape else {
        return true;
    };
    let check_bound =
        unsafe { FnPtr::<CheckBoundFn>::from_address_unchecked(AABB_CHECK_BOUND_ADDR).as_fn() };
    let bound = NiBound { center, radius };
    unsafe { check_bound(shape, &bound) != 0 }
}

unsafe fn read_geometry_transform(geometry: *mut c_void) -> Option<GeometryTransform> {
    let build_matrix = unsafe {
        FnPtr::<BuildGeometryMatrixFn>::from_address_unchecked(BUILD_GEOMETRY_MATRIX_ADDR).as_fn()
    };
    let mut world_to_local = [[0.0; 4]; 4];
    let (world_transform, matrix_context) = unsafe { geometry_matrix_inputs(geometry) };
    unsafe {
        build_matrix(world_transform, matrix_context, &mut world_to_local);
    }
    let transform = GeometryTransform {
        world_to_local,
        scale: unsafe { read_copy::<f32>(geometry, GEOMETRY_WORLD_SCALE_OFFSET) },
    };
    transform
        .world_to_local
        .iter()
        .flatten()
        .chain([transform.scale].iter())
        .all(|value| value.is_finite())
        .then_some(transform)
}

unsafe fn geometry_matrix_inputs(geometry: *mut c_void) -> (*const c_void, *const c_void) {
    let world_transform = (geometry as usize + GEOMETRY_WORLD_TRANSFORM_OFFSET) as *const c_void;
    let matrix_context = unsafe {
        ((geometry as usize + GEOMETRY_MATRIX_CONTEXT_OFFSET) as *const *const c_void)
            .read_unaligned()
    };
    (world_transform, matrix_context)
}

unsafe fn read_shadow_scene_node() -> Option<*mut c_void> {
    let node = unsafe { (SHADOW_SCENE_NODE_SLOT_ADDR as *const usize).read() };
    if node < MIN_ENGINE_PTR {
        return None;
    }
    Some(node as *mut c_void)
}

unsafe fn read_ptr_offset(base: *mut c_void, offset: usize) -> Option<*mut c_void> {
    if (base as usize) < MIN_ENGINE_PTR {
        return None;
    }
    let value = unsafe { ((base as usize + offset) as *const usize).read() };
    (value >= MIN_ENGINE_PTR).then_some(value as *mut c_void)
}

unsafe fn read_copy<T: Copy>(base: *mut c_void, offset: usize) -> T {
    unsafe { ((base as usize + offset) as *const T).read() }
}

unsafe fn read_vec3(base: *mut c_void, offset: usize) -> [f32; 3] {
    [
        unsafe { read_copy(base, offset) },
        unsafe { read_copy(base, offset + size_of::<f32>()) },
        unsafe { read_copy(base, offset + 2 * size_of::<f32>()) },
    ]
}

fn add3(left: [f32; 3], right: [f32; 3]) -> [f32; 3] {
    [left[0] + right[0], left[1] + right[1], left[2] + right[2]]
}

#[cfg(test)]
mod tests {
    use std::mem::{size_of, size_of_val};

    use super::{
        GEOMETRY_MATRIX_CONTEXT_OFFSET, GEOMETRY_WORLD_TRANSFORM_OFFSET, GeometryTransform,
        MAX_SUPPLEMENTAL_CONSTANTS, MAX_TERRAIN_POINT_LIGHTS, SupplementalTerrainLights,
        TerrainLightCandidate, TerrainLightContext, TerrainLightMerge, geometry_matrix_inputs,
        inverse_transform_point, manager_fallback_needed, supplement_captured_manager_lights,
    };
    use crate::fnv_local_lights::TerrainSceneLight;

    const MANAGER_EPOCH_AUDIT: &str = include_str!(
        "../../../../analysis/ghidra/output/perf/graphics_fnv_volumetric_local_manager_epoch_contract_followup.txt"
    );
    const MANAGER_EPOCH_CONTRACT: &str =
        include_str!("../../../../docs/graphics_fnv_volumetric_fog_lighting_plan.md");
    const LIGHT_STAGING_AUDIT: &str = include_str!(
        "../../../../analysis/ghidra/output/perf/graphics_fnv_pbr_light_selection_continuity_closure.txt"
    );
    const PIPBOY_LIGHT_AUDIT: &str = include_str!(
        "../../../../analysis/ghidra/output/perf/graphics_fnv_close_terrain_pipboy_light_0147_shadow_path_audit.txt"
    );

    fn context() -> TerrainLightContext {
        TerrainLightContext {
            transform: GeometryTransform {
                world_to_local: [
                    [0.5, 0.0, 0.0, 0.0],
                    [0.0, 0.5, 0.0, 0.0],
                    [0.0, 0.0, 0.5, 0.0],
                    [-50.0, -100.0, -150.0, 1.0],
                ],
                scale: 2.0,
            },
            lighting_offset: [1000.0, 2000.0, 3000.0],
            property_light_scale: 1.0,
            point_light_override_color: [0.2, 0.4, 0.6],
            hdr: true,
        }
    }

    fn captured_manager_light(identity: usize) -> TerrainSceneLight {
        let candidate = candidate(identity);
        TerrainSceneLight {
            native_light_identity: candidate.identity,
            point: candidate.point,
            ambient: candidate.ambient,
            relative_position: candidate.relative_position,
            radius: candidate.radius,
            diffuse: candidate.diffuse,
            dimmer: candidate.dimmer,
            lod_dimmer: candidate.lod_dimmer,
            fade: 0.75,
        }
    }

    fn candidate(identity: usize) -> TerrainLightCandidate {
        TerrainLightCandidate {
            identity,
            point: true,
            ambient: false,
            relative_position: [102.0, 204.0, 306.0],
            radius: 80.0,
            diffuse: [0.5, 0.25, 0.125],
            dimmer: 2.0,
            lod_dimmer: 0.5,
            in_multibound: true,
        }
    }

    fn payload_light_input_luminance(
        constants: &[[f32; 4]],
        fragment_position: [f32; 3],
        normal: [f32; 3],
    ) -> f32 {
        assert_eq!(constants[0][0], 1.0);
        let position_radius = constants[1];
        let color_visibility = constants[2];
        let light_vector = [
            position_radius[0] - fragment_position[0],
            position_radius[1] - fragment_position[1],
            position_radius[2] - fragment_position[2],
        ];
        let distance_squared = light_vector.iter().map(|value| value * value).sum::<f32>();
        let distance = distance_squared.sqrt();
        let attenuation = (1.0 - distance_squared / position_radius[3].powi(2)).clamp(0.0, 1.0);
        let light_direction = light_vector.map(|value| value / distance);
        let ndotl = light_direction
            .iter()
            .zip(normal)
            .map(|(light, normal)| light * normal)
            .sum::<f32>()
            .clamp(0.0, 1.0);
        let visibility = color_visibility[3].clamp(0.0, 1.0);
        let luminance =
            color_visibility[0] * 0.299 + color_visibility[1] * 0.587 + color_visibility[2] * 0.114;
        luminance * visibility * attenuation * ndotl
    }

    unsafe fn write_buffer<T>(buffer: &mut [usize], offset: usize, value: T) {
        assert!(offset + size_of::<T>() <= size_of_val(buffer));
        unsafe {
            buffer
                .as_mut_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<T>()
                .write_unaligned(value);
        }
    }

    #[test]
    fn old_non_shadow_pass_gets_the_missing_general_light() {
        let mut merge = TerrainLightMerge::new(&[0x11000], 1, context());
        assert!(merge.consider(candidate(0x22000)));
        let output = merge.finish();

        assert_eq!(output.identities[0], 0x22000);
        assert_eq!(output.lights().len(), 1);
    }

    #[test]
    fn captured_manager_light_reaches_the_production_merge_without_engine_pointers() {
        let mut merge = TerrainLightMerge::new(&[], 0, context());
        supplement_captured_manager_lights(&[captured_manager_light(0x22000)], None, &mut merge);

        let output = merge.finish();
        assert_eq!(&output.identities[..output.count], &[0x22000]);
        assert_eq!(output.lights()[0].color_visibility, [0.5, 0.25, 0.125, 1.0]);
    }

    #[test]
    fn zero_native_row_manager_pipboy_light_survives_zero_shadow_fade() {
        let mut pipboy = captured_manager_light(0x22000);
        pipboy.fade = 0.0;
        let mut merge = TerrainLightMerge::new(&[], 0, context());
        supplement_captured_manager_lights(&[pipboy], None, &mut merge);
        let output = merge.finish();
        let mut constants = [[0.0; 4]; MAX_SUPPLEMENTAL_CONSTANTS];
        let constant_count = output.write_shader_constants(&mut constants);

        assert_eq!(constant_count, 3);
        assert_eq!(constants[0], [1.0, 0.0, 0.0, 0.0]);
        assert_eq!(constants[2][3], 1.0);
        assert!(
            payload_light_input_luminance(
                &constants[..constant_count],
                [501.0, 1002.0, 1483.0],
                [0.0, 0.0, 1.0],
            ) > 0.1
        );

        assert!(PIPBOY_LIGHT_AUDIT.contains("local_98 = 0.0;"));
        assert!(PIPBOY_LIGHT_AUDIT.contains("*(float *)(param_1 + 0xd4) = local_98;"));
    }

    #[test]
    fn captured_manager_order_and_identity_deduplication_are_preserved() {
        let mut merge = TerrainLightMerge::new(&[], 0, context());
        supplement_captured_manager_lights(
            &[
                captured_manager_light(0x33000),
                captured_manager_light(0x22000),
                captured_manager_light(0x33000),
            ],
            None,
            &mut merge,
        );
        let output = merge.finish();

        assert_eq!(output.count, 2);
        assert_eq!(&output.identities[..2], &[0x33000, 0x22000]);
    }

    #[test]
    fn captured_manager_filter_rejects_non_point_and_ambient_entries() {
        let mut not_point = captured_manager_light(0x22000);
        not_point.point = false;
        let mut ambient = captured_manager_light(0x33000);
        ambient.ambient = true;
        let mut merge = TerrainLightMerge::new(&[], 0, context());
        supplement_captured_manager_lights(&[not_point, ambient], None, &mut merge);

        assert!(merge.finish().lights().is_empty());
    }

    #[test]
    fn manager_scan_is_limited_to_unlit_zero_point_rows() {
        assert!(manager_fallback_needed(0, 0));
        assert!(!manager_fallback_needed(1, 0));
        assert!(!manager_fallback_needed(0, 1));
        assert!(!manager_fallback_needed(24, 0));
    }

    #[test]
    fn manager_fallback_uses_the_proven_copied_world_epoch() {
        let source = include_str!("terrain_lights.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert!(production.contains("try_with_current_terrain_lights"));
        assert!(!production.contains("SHADOW_SCENE_NODE_LIGHT_LIST_OFFSET"));
        assert!(MANAGER_EPOCH_AUDIT.contains("never retains a manager list node"));
        assert!(MANAGER_EPOCH_AUDIT.contains("scene-wide light removal candidate @ 0x00b5d180"));
        assert!(
            MANAGER_EPOCH_CONTRACT.contains("stable across the world light/shadow transaction")
        );
    }

    #[test]
    fn future_pass_that_already_contains_the_light_gets_no_supplement() {
        let mut merge = TerrainLightMerge::new(&[0x22000], 1, context());
        let _ = merge.consider(candidate(0x22000));

        assert!(merge.finish().lights().is_empty());
    }

    #[test]
    fn merge_deduplicates_candidates_and_preserves_iterator_order() {
        let mut merge = TerrainLightMerge::new(&[], 0, context());
        assert!(merge.consider(candidate(0x33000)));
        assert!(merge.consider(candidate(0x22000)));
        let _ = merge.consider(candidate(0x33000));
        let output = merge.finish();

        assert_eq!(&output.identities[..2], &[0x33000, 0x22000]);
        assert_eq!(output.lights().len(), 2);
    }

    #[test]
    fn native_and_supplemental_lights_share_the_24_light_cap() {
        let mut merge = TerrainLightMerge::new(&[], 23, context());
        assert!(merge.consider(candidate(0x20000)));
        let _ = merge.consider(candidate(0x20004));

        assert_eq!(merge.finish().lights().len(), 1);
    }

    #[test]
    fn invalid_light_classes_and_values_are_rejected() {
        let mut cases = [candidate(0x20000); 8];
        cases[0].point = false;
        cases[1].ambient = true;
        cases[2].in_multibound = false;
        cases[3].radius = 0.0;
        cases[4].dimmer = f32::NAN;
        cases[5].lod_dimmer = -1.0;
        cases[6].diffuse = [0.0; 3];
        cases[7].identity = 1;

        for (index, case) in cases.into_iter().enumerate() {
            let mut merge = TerrainLightMerge::new(&[], 0, context());
            let _ = merge.consider(case);
            assert!(merge.finish().lights().is_empty(), "case {index}");
        }
    }

    #[test]
    fn property_scale_below_one_uses_the_native_point_light_override_color() {
        let mut native_dark_path = context();
        native_dark_path.property_light_scale = 0.999;
        native_dark_path.point_light_override_color = [0.125, 0.25, 0.5];
        let mut dark_candidate = candidate(0x20000);
        dark_candidate.diffuse = [0.0; 3];
        dark_candidate.dimmer = 0.0;
        dark_candidate.lod_dimmer = 0.0;
        let mut merge = TerrainLightMerge::new(&[], 0, native_dark_path);

        assert!(merge.consider(dark_candidate));
        assert_eq!(
            merge.finish().lights()[0].color_visibility,
            [0.125, 0.25, 0.5, 1.0]
        );
        assert!(LIGHT_STAGING_AUDIT.contains("else if (param_3 < 1.0)"));
        assert!(LIGHT_STAGING_AUDIT.contains("local_20 = DAT_011f4998"));
        assert!(LIGHT_STAGING_AUDIT.contains("local_1c = DAT_011f499c"));
        assert!(LIGHT_STAGING_AUDIT.contains("local_18 = DAT_011f49a0"));
    }

    #[test]
    fn transform_matches_inverse_nitransform_and_camera_relative_offset() {
        let mut merge = TerrainLightMerge::new(&[], 0, context());
        assert!(merge.consider(candidate(0x20000)));
        let light = merge.finish().lights()[0];

        assert_eq!(light.position_radius, [501.0, 1002.0, 1503.0, 40.0]);
        assert_eq!(light.color_visibility, [0.5, 0.25, 0.125, 1.0]);
    }

    #[test]
    fn inverse_transform_uses_the_native_d3d_matrix_convention() {
        let transform = GeometryTransform {
            world_to_local: [
                [0.0, -0.5, 0.0, 0.0],
                [0.5, 0.0, 0.0, 0.0],
                [0.0, 0.0, 0.5, 0.0],
                [-10.0, 5.0, -15.0, 1.0],
            ],
            scale: 2.0,
        };

        assert_eq!(
            inverse_transform_point([10.0, 22.0, 34.0], transform),
            Some([1.0, 0.0, 2.0])
        );
    }

    #[test]
    fn geometry_matrix_builder_receives_the_native_geometry_context_argument() {
        let mut geometry = [0usize; 64];
        let expected_context = 0x22000usize;
        unsafe {
            write_buffer(
                &mut geometry,
                GEOMETRY_MATRIX_CONTEXT_OFFSET,
                expected_context,
            );
        }
        let geometry_ptr = geometry.as_mut_ptr().cast::<std::ffi::c_void>();
        let (world_transform, matrix_context) = unsafe { geometry_matrix_inputs(geometry_ptr) };

        assert_eq!(
            world_transform as usize,
            geometry_ptr as usize + GEOMETRY_WORLD_TRANSFORM_OFFSET
        );
        assert_eq!(matrix_context as usize, expected_context);
    }

    #[test]
    fn non_hdr_dimmer_is_clamped_before_native_multipliers() {
        let mut non_hdr = context();
        non_hdr.hdr = false;
        non_hdr.property_light_scale = 1.5;
        let mut merge = TerrainLightMerge::new(&[], 0, non_hdr);
        assert!(merge.consider(candidate(0x20000)));

        assert_eq!(
            merge.finish().lights()[0].color_visibility,
            [0.375, 0.1875, 0.09375, 1.0]
        );
    }

    #[test]
    fn shader_payload_is_count_followed_by_interleaved_pairs() {
        let mut merge = TerrainLightMerge::new(&[], 0, context());
        assert!(merge.consider(candidate(0x20000)));
        let output = merge.finish();
        let mut constants = [[0.0; 4]; MAX_SUPPLEMENTAL_CONSTANTS];

        assert_eq!(output.write_shader_constants(&mut constants), 3);
        assert_eq!(constants[0], [1.0, 0.0, 0.0, 0.0]);
        assert_eq!(constants[1], output.lights()[0].position_radius);
        assert_eq!(constants[2], output.lights()[0].color_visibility);
        assert_eq!(MAX_SUPPLEMENTAL_CONSTANTS, MAX_TERRAIN_POINT_LIGHTS * 2 + 1);
    }

    #[test]
    fn empty_payload_resets_the_supplemental_count() {
        let output = SupplementalTerrainLights::default();
        let mut constants = [[9.0; 4]; MAX_SUPPLEMENTAL_CONSTANTS];

        assert_eq!(output.write_shader_constants(&mut constants), 1);
        assert_eq!(constants[0], [0.0; 4]);
    }
}
