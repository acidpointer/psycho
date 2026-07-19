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

const GEOMETRY_PARENT_OFFSET: usize = 0x18;
const GEOMETRY_WORLD_TRANSFORM_OFFSET: usize = 0x68;
const GEOMETRY_WORLD_SCALE_OFFSET: usize = 0x98;
const GEOMETRY_LIGHTING_PROPERTY_OFFSET: usize = 0xA8;
const LIGHTING_PROPERTY_FORCED_DARKNESS_OFFSET: usize = 0x6C;

const RENDER_PASS_LIGHT_COUNT_OFFSET: usize = 0x09;
const RENDER_PASS_LIGHT_ARRAY_OFFSET: usize = 0x0C;
const MAX_RENDER_PASS_LIGHTS: usize = MAX_TERRAIN_POINT_LIGHTS + 1;

const SCENE_LIGHT_LOD_DIMMER_OFFSET: usize = 0xD0;
const SCENE_LIGHT_FADE_OFFSET: usize = 0xD4;
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
    fade: f32,
    in_multibound: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct ShaderTerrainLight {
    position_radius: [f32; 4],
    color_fade: [f32; 4],
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct TerrainLightContext {
    transform: GeometryTransform,
    lighting_offset: [f32; 3],
    forced_darkness: f32,
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
            output[2 + index * 2] = light.color_fade;
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

    fn consider(&mut self, candidate: TerrainLightCandidate) {
        if !self.needs_identity(candidate.identity) {
            return;
        }
        let Some(light) = shader_light(candidate, self.context) else {
            return;
        };

        let index = self.output.count;
        self.output.identities[index] = candidate.identity;
        self.output.lights[index] = light;
        self.output.count += 1;
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

    let forced_darkness =
        unsafe { read_copy::<f32>(property, LIGHTING_PROPERTY_FORCED_DARKNESS_OFFSET) };
    if !forced_darkness.is_finite() || forced_darkness < 1.0 {
        return Some(SupplementalTerrainLights::default());
    }
    let context = TerrainLightContext {
        transform: unsafe { read_geometry_transform(geometry) }?,
        lighting_offset: unsafe { read_lighting_offset() }?,
        forced_darkness,
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

    Some(merge.finish())
}

fn shader_light(
    candidate: TerrainLightCandidate,
    context: TerrainLightContext,
) -> Option<ShaderTerrainLight> {
    if !candidate.point
        || candidate.ambient
        || !candidate.in_multibound
        || context.forced_darkness < 1.0
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
                candidate.fade,
                context.forced_darkness,
                context.transform.scale,
            ]
            .iter(),
        )
        .chain(context.lighting_offset.iter())
        .chain(context.transform.world_to_local.iter().flatten())
        .all(|value| value.is_finite())
        || candidate.radius <= 0.0
        || candidate.dimmer < 0.0
        || candidate.lod_dimmer < 0.0
    {
        return None;
    }
    if !candidate
        .diffuse
        .iter()
        .map(|component| component * candidate.dimmer)
        .any(|component| component > LIGHT_COMPONENT_MIN)
    {
        return None;
    }

    let world_position = add3(candidate.relative_position, context.lighting_offset);
    let local_position = inverse_transform_point(world_position, context.transform)?;
    let radius = candidate.radius / context.transform.scale;
    let dimmer = if !context.hdr && candidate.dimmer > 1.0 {
        1.0
    } else {
        candidate.dimmer
    } * context.forced_darkness
        * candidate.lod_dimmer;
    let color = candidate.diffuse.map(|component| component * dimmer);
    if !radius.is_finite() || radius <= 0.0 || !color.iter().all(|component| component.is_finite())
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
        color_fade: [color[0], color[1], color[2], candidate.fade],
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
        fade: unsafe { read_copy::<f32>(scene_light, SCENE_LIGHT_FADE_OFFSET) },
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
    unsafe {
        build_matrix(
            (geometry as usize + GEOMETRY_WORLD_TRANSFORM_OFFSET) as *const c_void,
            std::ptr::null(),
            &mut world_to_local,
        );
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

unsafe fn read_lighting_offset() -> Option<[f32; 3]> {
    let node = unsafe { (SHADOW_SCENE_NODE_SLOT_ADDR as *const usize).read() };
    if node < MIN_ENGINE_PTR {
        return None;
    }
    Some(unsafe { read_vec3(node as *mut c_void, SHADOW_SCENE_NODE_LIGHTING_OFFSET) })
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
    use super::{
        GeometryTransform, MAX_SUPPLEMENTAL_CONSTANTS, MAX_TERRAIN_POINT_LIGHTS,
        SupplementalTerrainLights, TerrainLightCandidate, TerrainLightContext, TerrainLightMerge,
        inverse_transform_point,
    };

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
            forced_darkness: 1.0,
            hdr: true,
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
            fade: 0.75,
            in_multibound: true,
        }
    }

    #[test]
    fn old_non_shadow_pass_gets_the_missing_general_light() {
        let mut merge = TerrainLightMerge::new(&[0x11000], 1, context());
        merge.consider(candidate(0x22000));
        let output = merge.finish();

        assert_eq!(output.identities[0], 0x22000);
        assert_eq!(output.lights().len(), 1);
    }

    #[test]
    fn future_pass_that_already_contains_the_light_gets_no_supplement() {
        let mut merge = TerrainLightMerge::new(&[0x22000], 1, context());
        merge.consider(candidate(0x22000));

        assert!(merge.finish().lights().is_empty());
    }

    #[test]
    fn merge_deduplicates_candidates_and_preserves_iterator_order() {
        let mut merge = TerrainLightMerge::new(&[], 0, context());
        merge.consider(candidate(0x33000));
        merge.consider(candidate(0x22000));
        merge.consider(candidate(0x33000));
        let output = merge.finish();

        assert_eq!(&output.identities[..2], &[0x33000, 0x22000]);
        assert_eq!(output.lights().len(), 2);
    }

    #[test]
    fn native_and_supplemental_lights_share_the_24_light_cap() {
        let mut merge = TerrainLightMerge::new(&[], 23, context());
        merge.consider(candidate(0x20000));
        merge.consider(candidate(0x20004));

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
            merge.consider(case);
            assert!(merge.finish().lights().is_empty(), "case {index}");
        }
    }

    #[test]
    fn forced_darkness_suppresses_portable_lights_like_native_terrain_staging() {
        let mut dark = context();
        dark.forced_darkness = 0.999;
        let mut merge = TerrainLightMerge::new(&[], 0, dark);
        merge.consider(candidate(0x20000));

        assert!(merge.finish().lights().is_empty());
    }

    #[test]
    fn transform_matches_inverse_nitransform_and_camera_relative_offset() {
        let mut merge = TerrainLightMerge::new(&[], 0, context());
        merge.consider(candidate(0x20000));
        let light = merge.finish().lights()[0];

        assert_eq!(light.position_radius, [501.0, 1002.0, 1503.0, 40.0]);
        assert_eq!(light.color_fade, [0.5, 0.25, 0.125, 0.75]);
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
    fn non_hdr_dimmer_is_clamped_before_native_multipliers() {
        let mut non_hdr = context();
        non_hdr.hdr = false;
        non_hdr.forced_darkness = 1.5;
        let mut merge = TerrainLightMerge::new(&[], 0, non_hdr);
        merge.consider(candidate(0x20000));

        assert_eq!(
            merge.finish().lights()[0].color_fade,
            [0.375, 0.1875, 0.09375, 0.75]
        );
    }

    #[test]
    fn shader_payload_is_count_followed_by_interleaved_pairs() {
        let mut merge = TerrainLightMerge::new(&[], 0, context());
        merge.consider(candidate(0x20000));
        let output = merge.finish();
        let mut constants = [[0.0; 4]; MAX_SUPPLEMENTAL_CONSTANTS];

        assert_eq!(output.write_shader_constants(&mut constants), 3);
        assert_eq!(constants[0], [1.0, 0.0, 0.0, 0.0]);
        assert_eq!(constants[1], output.lights()[0].position_radius);
        assert_eq!(constants[2], output.lights()[0].color_fade);
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
