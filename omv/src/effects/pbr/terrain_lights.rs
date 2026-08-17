//! OMV-owned close-terrain light supplementation.
//!
//! The engine's general active-light iterator includes shadow-classified
//! portable lights. Landscape pass builders based on the non-shadow iterator
//! can omit those lights. OMV merges only missing native identities into an
//! OMV-owned count constant and dynamic shader-data texture; it never mutates
//! the engine render pass or its native point-light constants.
//!
//! One native pass setup can submit the same or several geometries. A
//! four-entry generation-keyed direct map avoids repeating engine-light
//! reconstruction when geometry contracts recur in an A/B/A sequence.
//! Pointer identity alone is insufficient because the
//! engine reuses geometry, property, selector, and pass objects. The key also
//! includes render epoch, D3D device, manager-light, and native-pass
//! membership generations. A miss always runs the complete merge.
//!
//! The cache is statically zero-initialized POD state; it adds no TLS callback,
//! lazy owner, lock, allocation, or plugin-load initialization. Every slot uses
//! an even/odd atomic version to publish complete key and payload snapshots.
//! Contending callers bypass the cache instead of waiting on the render path.

use std::{
    ffi::c_void,
    mem::size_of,
    sync::atomic::{AtomicU32, AtomicUsize, Ordering},
};

use libpsycho::ffi::fnptr::FnPtr;

use super::engine_contracts;

pub(super) const MAX_TERRAIN_POINT_LIGHTS: usize = 24;
pub(super) const SUPPLEMENTAL_LIGHT_TEXTURE_WIDTH: usize = 64;
pub(super) const SUPPLEMENTAL_LIGHT_TEXTURE_HEIGHT: usize = 1;
pub(super) const SUPPLEMENTAL_LIGHT_TEXTURE_TEXELS: usize =
    SUPPLEMENTAL_LIGHT_TEXTURE_WIDTH * SUPPLEMENTAL_LIGHT_TEXTURE_HEIGHT;

const GENERAL_LIGHT_FIRST_ADDR: usize = 0x00B70590;
const GENERAL_LIGHT_NEXT_ADDR: usize = 0x00B70680;
const AABB_CHECK_BOUND_ADDR: usize = 0x00C382B0;
const BUILD_GEOMETRY_MATRIX_ADDR: usize = 0x00C4C2D0;
const SHADOW_SCENE_NODE_SLOT_ADDR: usize = 0x011F91C8;
const HDR_ENABLED_ADDR: usize = 0x011F941E;
const NATIVE_BLACK_COLOR_ADDR: usize = 0x011F4998;

const GEOMETRY_PARENT_OFFSET: usize = 0x18;
const GEOMETRY_WORLD_TRANSFORM_OFFSET: usize = 0x68;
const GEOMETRY_WORLD_SCALE_OFFSET: usize = 0x98;
const GEOMETRY_LIGHTING_PROPERTY_OFFSET: usize = 0xA8;
const GEOMETRY_MATRIX_CONTEXT_OFFSET: usize = 0xBC;
const GEOMETRY_SELECTOR_OFFSET: usize = 0xC0;
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
    native_black_color: [f32; 3],
    hdr: bool,
}

/// Supplemental point lights encoded for the close-terrain shader ABI.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct SupplementalTerrainLights {
    lights: [ShaderTerrainLight; MAX_TERRAIN_POINT_LIGHTS],
    identities: [usize; MAX_TERRAIN_POINT_LIGHTS],
    count: usize,
}

impl Default for SupplementalTerrainLights {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl SupplementalTerrainLights {
    const EMPTY: Self = Self {
        lights: [ShaderTerrainLight {
            position_radius: [0.0; 4],
            color_visibility: [0.0; 4],
        }; MAX_TERRAIN_POINT_LIGHTS],
        identities: [0; MAX_TERRAIN_POINT_LIGHTS],
        count: 0,
    };

    /// Return the `c91` value that bounds supplemental shader texture reads.
    pub(super) fn shader_count_constant(&self) -> [f32; 4] {
        [self.count as f32, 0.0, 0.0, 0.0]
    }

    /// Return whether this draw has no supplemental texture payload.
    pub(super) fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Write the complete 64x1 RGBA32F shader-data texture payload.
    ///
    /// Each light occupies adjacent position/radius and color/reserved-alpha
    /// texels. The unused tail is reset so a corrupt shader count cannot expose
    /// stale data from an earlier draw.
    pub(super) fn write_shader_texture(&self, output: &mut [[f32; 4]]) {
        debug_assert!(output.len() >= SUPPLEMENTAL_LIGHT_TEXTURE_TEXELS);
        output[..SUPPLEMENTAL_LIGHT_TEXTURE_TEXELS].fill([0.0; 4]);
        for (index, light) in self.lights[..self.count].iter().enumerate() {
            output[index * 2] = light.position_radius;
            output[index * 2 + 1] = light.color_visibility;
        }
    }

    /// Compare this payload with a complete cached shader-texture image.
    ///
    /// The comparison is bit-exact and includes the zeroed tail. Resource
    /// ownership can therefore skip both serialization and `LockRect` without
    /// accepting a hash collision or retaining data from a larger prior draw.
    pub(super) fn matches_shader_texture_bits(&self, cached: &[[u32; 4]]) -> bool {
        if cached.len() < SUPPLEMENTAL_LIGHT_TEXTURE_TEXELS {
            return false;
        }
        for index in 0..MAX_TERRAIN_POINT_LIGHTS {
            let (position_radius, color_visibility) = if index < self.count {
                (
                    self.lights[index].position_radius.map(f32::to_bits),
                    self.lights[index].color_visibility.map(f32::to_bits),
                )
            } else {
                ([0; 4], [0; 4])
            };
            if cached[index * 2] != position_radius || cached[index * 2 + 1] != color_visibility {
                return false;
            }
        }
        true
    }

    #[cfg(test)]
    fn lights(&self) -> &[ShaderTerrainLight] {
        &self.lights[..self.count]
    }
}

const DRAW_CACHE_COMPONENTS_PER_LIGHT: usize = 8;
const DRAW_CACHE_COMPONENT_COUNT: usize =
    MAX_TERRAIN_POINT_LIGHTS * DRAW_CACHE_COMPONENTS_PER_LIGHT;
const DRAW_CACHE_ENTRY_COUNT: usize = 4;

struct DrawCacheEntry {
    version: AtomicU32,
    render_epoch: AtomicU32,
    device_generation: AtomicU32,
    manager_generation: AtomicU32,
    geometry: AtomicUsize,
    property: AtomicUsize,
    selector: AtomicUsize,
    render_pass: AtomicUsize,
    // The signature rejects most misses cheaply, but is never accepted as
    // proof. Exact count and identity atoms close the 32-bit collision case.
    native_signature: AtomicU32,
    native_identity_count: AtomicUsize,
    native_point_count: AtomicUsize,
    native_identities: [AtomicUsize; MAX_RENDER_PASS_LIGHTS],
    count: AtomicUsize,
    identities: [AtomicUsize; MAX_TERRAIN_POINT_LIGHTS],
    components: [AtomicU32; DRAW_CACHE_COMPONENT_COUNT],
}

impl DrawCacheEntry {
    const fn new() -> Self {
        Self {
            version: AtomicU32::new(0),
            render_epoch: AtomicU32::new(0),
            device_generation: AtomicU32::new(0),
            manager_generation: AtomicU32::new(0),
            geometry: AtomicUsize::new(0),
            property: AtomicUsize::new(0),
            selector: AtomicUsize::new(0),
            render_pass: AtomicUsize::new(0),
            native_signature: AtomicU32::new(0),
            native_identity_count: AtomicUsize::new(0),
            native_point_count: AtomicUsize::new(0),
            native_identities: [const { AtomicUsize::new(0) }; MAX_RENDER_PASS_LIGHTS],
            count: AtomicUsize::new(0),
            identities: [const { AtomicUsize::new(0) }; MAX_TERRAIN_POINT_LIGHTS],
            components: [const { AtomicU32::new(0) }; DRAW_CACHE_COMPONENT_COUNT],
        }
    }
}

// Each direct-mapped entry has an independent even/odd publication version.
// Every payload word is atomic, so even an unexpected cross-thread D3D call
// cannot create a Rust data race. Four entries retain common A/B/A terrain
// reuse without adding a lazy owner, lock, allocation, or TLS callback.
static DRAW_CACHE: [DrawCacheEntry; DRAW_CACHE_ENTRY_COUNT] =
    [const { DrawCacheEntry::new() }; DRAW_CACHE_ENTRY_COUNT];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TerrainDrawCacheKey {
    render_epoch: u32,
    device_generation: u32,
    manager_generation: u32,
    geometry: usize,
    property: usize,
    selector: usize,
    render_pass: usize,
    native_light_signature: u32,
    native_identity_count: usize,
    native_point_count: usize,
    native_identities: [usize; MAX_RENDER_PASS_LIGHTS],
}

struct TerrainDrawInputs {
    key: TerrainDrawCacheKey,
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

/// Returns the supplemental lights for the current close-terrain geometry.
///
/// `geometry_identity` must be the non-null pointer observed at the same draw
/// boundary. Repeated submissions reuse a result only when every semantic key
/// component still matches.
pub(super) fn capture_current_for_draw(geometry_identity: usize) -> SupplementalTerrainLights {
    let _span =
        crate::graphics_diagnostics::span(crate::graphics_diagnostics::Interval::PbrTerrainLights);
    debug_assert_ne!(geometry_identity, 0);
    let Some(inputs) = (unsafe { prepare_draw_inputs(geometry_identity) }) else {
        return SupplementalTerrainLights::default();
    };
    if let Some(lights) = load_draw_cache(&inputs.key) {
        crate::graphics_diagnostics::add(
            crate::graphics_diagnostics::Counter::TerrainLightCacheHit,
            1,
        );
        record_supplemental_light_count(lights.count);
        return lights;
    }
    crate::graphics_diagnostics::add(
        crate::graphics_diagnostics::Counter::TerrainLightCacheMiss,
        1,
    );

    let lights = unsafe { capture_current_unchecked(&inputs) }.unwrap_or_default();
    publish_draw_cache(&inputs.key, lights);
    record_supplemental_light_count(lights.count);
    lights
}

fn record_supplemental_light_count(count: usize) {
    let counter = match count {
        0 => crate::graphics_diagnostics::Counter::SupplementalLightCountZero,
        1..=6 => crate::graphics_diagnostics::Counter::SupplementalLightCountOneToSix,
        7..=12 => crate::graphics_diagnostics::Counter::SupplementalLightCountSevenToTwelve,
        _ => crate::graphics_diagnostics::Counter::SupplementalLightCountThirteenToTwentyFour,
    };
    crate::graphics_diagnostics::add(counter, 1);
}

fn load_draw_cache(key: &TerrainDrawCacheKey) -> Option<SupplementalTerrainLights> {
    let entry = draw_cache_entry(key);
    let version = entry.version.load(Ordering::Acquire);
    if version & 1 != 0 || !draw_cache_key_matches(entry, key) {
        return None;
    }

    let mut lights = SupplementalTerrainLights::EMPTY;
    lights.count = entry
        .count
        .load(Ordering::Relaxed)
        .min(MAX_TERRAIN_POINT_LIGHTS);
    for (light_index, light) in lights.lights[..lights.count].iter_mut().enumerate() {
        lights.identities[light_index] = entry.identities[light_index].load(Ordering::Relaxed);
        let base = light_index * DRAW_CACHE_COMPONENTS_PER_LIGHT;
        for (component, output) in light.position_radius.iter_mut().enumerate() {
            *output = f32::from_bits(entry.components[base + component].load(Ordering::Relaxed));
        }
        for (component, output) in light.color_visibility.iter_mut().enumerate() {
            *output =
                f32::from_bits(entry.components[base + 4 + component].load(Ordering::Relaxed));
        }
    }

    // A concurrent invalidation or publication makes this snapshot unusable.
    // Returning None merely repeats the bounded scan; the draw never waits.
    (entry.version.load(Ordering::Acquire) == version && draw_cache_key_matches(entry, key))
        .then_some(lights)
}

fn publish_draw_cache(key: &TerrainDrawCacheKey, lights: SupplementalTerrainLights) {
    let entry = draw_cache_entry(key);
    let version = entry.version.load(Ordering::Relaxed);
    if version & 1 != 0
        || entry
            .version
            .compare_exchange(
                version,
                version.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
    {
        // Another publisher owns the cache. Do not spin or block a draw.
        return;
    }

    entry.geometry.store(0, Ordering::Relaxed);
    for (light_index, light) in lights.lights[..lights.count].iter().enumerate() {
        entry.identities[light_index].store(lights.identities[light_index], Ordering::Relaxed);
        let base = light_index * DRAW_CACHE_COMPONENTS_PER_LIGHT;
        for (component, value) in light.position_radius.iter().enumerate() {
            entry.components[base + component].store(value.to_bits(), Ordering::Relaxed);
        }
        for (component, value) in light.color_visibility.iter().enumerate() {
            entry.components[base + 4 + component].store(value.to_bits(), Ordering::Relaxed);
        }
    }
    entry.count.store(lights.count, Ordering::Relaxed);
    entry
        .render_epoch
        .store(key.render_epoch, Ordering::Relaxed);
    entry
        .device_generation
        .store(key.device_generation, Ordering::Relaxed);
    entry
        .manager_generation
        .store(key.manager_generation, Ordering::Relaxed);
    entry.property.store(key.property, Ordering::Relaxed);
    entry.selector.store(key.selector, Ordering::Relaxed);
    entry.render_pass.store(key.render_pass, Ordering::Relaxed);
    entry
        .native_signature
        .store(key.native_light_signature, Ordering::Relaxed);
    for (index, identity) in key.native_identities[..key.native_identity_count]
        .iter()
        .enumerate()
    {
        entry.native_identities[index].store(*identity, Ordering::Relaxed);
    }
    entry
        .native_identity_count
        .store(key.native_identity_count, Ordering::Relaxed);
    entry
        .native_point_count
        .store(key.native_point_count, Ordering::Relaxed);
    entry.geometry.store(key.geometry, Ordering::Release);
    entry
        .version
        .store(version.wrapping_add(2), Ordering::Release);
}

fn draw_cache_entry(key: &TerrainDrawCacheKey) -> &'static DrawCacheEntry {
    &DRAW_CACHE[draw_cache_index(key)]
}

fn draw_cache_index(key: &TerrainDrawCacheKey) -> usize {
    let mut mixed = key.geometry
        ^ key.property.rotate_left(7)
        ^ key.render_pass.rotate_left(13)
        ^ key.native_light_signature as usize;
    // Engine pointers are at least four-byte aligned, so masking their raw low
    // bits would collapse an alternating geometry sequence into one slot. Fold
    // upper pointer bits down before the final mask; the second fold also lets
    // changes in the semantic light signature influence every output bit.
    mixed ^= mixed >> 16;
    mixed = mixed.wrapping_mul(0x7FEB_352D);
    mixed ^= mixed >> 15;
    mixed & (DRAW_CACHE_ENTRY_COUNT - 1)
}

fn draw_cache_key_matches(entry: &DrawCacheEntry, key: &TerrainDrawCacheKey) -> bool {
    if key.native_identity_count > MAX_RENDER_PASS_LIGHTS {
        return false;
    }
    let scalar_key_matches = entry.geometry.load(Ordering::Acquire) == key.geometry
        && entry.render_epoch.load(Ordering::Relaxed) == key.render_epoch
        && entry.device_generation.load(Ordering::Relaxed) == key.device_generation
        && entry.manager_generation.load(Ordering::Relaxed) == key.manager_generation
        && entry.property.load(Ordering::Relaxed) == key.property
        && entry.selector.load(Ordering::Relaxed) == key.selector
        && entry.render_pass.load(Ordering::Relaxed) == key.render_pass
        && entry.native_signature.load(Ordering::Relaxed) == key.native_light_signature
        && entry.native_identity_count.load(Ordering::Relaxed) == key.native_identity_count
        && entry.native_point_count.load(Ordering::Relaxed) == key.native_point_count;
    scalar_key_matches
        && key.native_identities[..key.native_identity_count]
            .iter()
            .enumerate()
            .all(|(index, identity)| {
                entry.native_identities[index].load(Ordering::Relaxed) == *identity
            })
}

/// Invalidates the render-thread close-terrain light cache.
pub(super) fn invalidate_draw_cache() {
    for entry in &DRAW_CACHE {
        entry.geometry.store(0, Ordering::Release);
    }
}

unsafe fn prepare_draw_inputs(geometry_identity: usize) -> Option<TerrainDrawInputs> {
    let geometry = geometry_identity as *mut c_void;
    let render_pass = engine_contracts::current_pass_fast()?;
    let property = unsafe { read_ptr_offset(geometry, GEOMETRY_LIGHTING_PROPERTY_OFFSET) }?;
    let selector = unsafe { read_ptr_offset(geometry, GEOMETRY_SELECTOR_OFFSET) }
        .map_or(0, |selector| selector as usize);
    let mut native_identities = [0usize; MAX_RENDER_PASS_LIGHTS];
    let (native_identity_count, native_point_count) =
        unsafe { read_native_light_identities(render_pass, &mut native_identities) };
    let native_light_signature = native_light_signature(
        &native_identities[..native_identity_count],
        native_point_count,
    );
    Some(TerrainDrawInputs {
        key: TerrainDrawCacheKey {
            render_epoch: crate::hooks::render_epoch(),
            device_generation: crate::backend::d3d_device_generation(),
            manager_generation: crate::fnv_local_lights::terrain_light_generation(),
            geometry: geometry_identity,
            property: property as usize,
            selector,
            render_pass: render_pass as usize,
            native_light_signature,
            native_identity_count,
            native_point_count,
            native_identities,
        },
    })
}

unsafe fn capture_current_unchecked(
    inputs: &TerrainDrawInputs,
) -> Option<SupplementalTerrainLights> {
    let geometry = inputs.key.geometry as *mut c_void;
    let property = inputs.key.property as *mut c_void;
    let native_identity_count = inputs.key.native_identity_count;
    let native_point_count = inputs.key.native_point_count;
    if native_point_count >= MAX_TERRAIN_POINT_LIGHTS {
        return Some(SupplementalTerrainLights::default());
    }

    let property_light_scale =
        unsafe { read_copy::<f32>(property, LIGHTING_PROPERTY_LIGHT_SCALE_OFFSET) };
    if !property_light_scale.is_finite() {
        return Some(SupplementalTerrainLights::default());
    }
    let native_black_color = unsafe { read_vec3(NATIVE_BLACK_COLOR_ADDR as *mut c_void, 0) };
    let scene_node = unsafe { read_shadow_scene_node() }?;
    let context = TerrainLightContext {
        transform: unsafe { read_geometry_transform(geometry) }?,
        lighting_offset: unsafe { read_vec3(scene_node, SHADOW_SCENE_NODE_LIGHTING_OFFSET) },
        property_light_scale,
        native_black_color,
        hdr: unsafe { (HDR_ENABLED_ADDR as *const u8).read() != 0 },
    };

    let mut merge = TerrainLightMerge::new(
        &inputs.key.native_identities[..native_identity_count],
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
    crate::graphics_diagnostics::add(
        crate::graphics_diagnostics::Counter::TerrainPropertyLightEntry,
        scanned as u32,
    );

    // Property-local membership is not authoritative: any row can omit an
    // active portable light even when it already contains unrelated lights.
    if manager_supplement_needed(native_point_count, merge.output.count) {
        supplement_manager_lights(multibound_shape, &mut merge);
    }

    Some(merge.finish())
}

fn native_light_signature(identities: &[usize], native_point_count: usize) -> u32 {
    let mut hash = 0x811C_9DC5u32 ^ native_point_count as u32;
    for identity in identities {
        hash ^= *identity as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash ^ identities.len() as u32
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
        crate::graphics_diagnostics::add(
            crate::graphics_diagnostics::Counter::TerrainManagerLightEntry,
            1,
        );
        if !merge.needs_identity(light.native_light_identity) {
            continue;
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

fn manager_supplement_needed(native_point_count: usize, supplemental_point_count: usize) -> bool {
    native_point_count.saturating_add(supplemental_point_count) < MAX_TERRAIN_POINT_LIGHTS
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
        .chain(context.native_black_color.iter())
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
        context.native_black_color
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
        // VPT terrain consumes point-light RGB without alpha. Keep a neutral
        // fourth component so native and recovered membership remain
        // equivalent if the supplemental ABI is inspected independently.
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
    crate::graphics_diagnostics::add(
        crate::graphics_diagnostics::Counter::TerrainNativeLightEntry,
        light_count as u32,
    );
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
        MAX_RENDER_PASS_LIGHTS, SUPPLEMENTAL_LIGHT_TEXTURE_TEXELS, SupplementalTerrainLights,
        TerrainDrawCacheKey, TerrainLightCandidate, TerrainLightContext, TerrainLightMerge,
        draw_cache_entry, geometry_matrix_inputs, invalidate_draw_cache, inverse_transform_point,
        load_draw_cache, manager_supplement_needed, publish_draw_cache,
        supplement_captured_manager_lights,
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
            native_black_color: [0.0; 3],
            hdr: true,
        }
    }

    fn cache_key(geometry: usize) -> TerrainDrawCacheKey {
        let mut native_identities = [0; MAX_RENDER_PASS_LIGHTS];
        native_identities[0] = 0x77000;
        native_identities[1] = 0x88000;
        TerrainDrawCacheKey {
            render_epoch: 7,
            device_generation: 2,
            manager_generation: 4,
            geometry,
            property: 0x44000,
            selector: 0x55000,
            render_pass: 0x66000,
            native_light_signature: 0x1234_5678,
            native_identity_count: 2,
            native_point_count: 1,
            native_identities,
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
        count_constant: [f32; 4],
        texture: &[[f32; 4]],
        fragment_position: [f32; 3],
        normal: [f32; 3],
    ) -> f32 {
        assert_eq!(count_constant[0], 1.0);
        let position_radius = texture[0];
        let color_visibility = texture[1];
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
        let mut texture = [[0.0; 4]; SUPPLEMENTAL_LIGHT_TEXTURE_TEXELS];
        output.write_shader_texture(&mut texture);

        assert_eq!(output.shader_count_constant(), [1.0, 0.0, 0.0, 0.0]);
        assert_eq!(texture[1][3], 1.0);
        assert!(
            payload_light_input_luminance(
                output.shader_count_constant(),
                &texture,
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
    fn manager_scan_is_used_whenever_point_light_capacity_remains() {
        assert!(manager_supplement_needed(0, 0));
        assert!(manager_supplement_needed(1, 0));
        assert!(manager_supplement_needed(0, 1));
        assert!(!manager_supplement_needed(24, 0));
    }

    #[test]
    fn unrelated_native_light_does_not_hide_a_missing_manager_light() {
        let mut merge = TerrainLightMerge::new(&[0x11000], 1, context());
        supplement_captured_manager_lights(&[captured_manager_light(0x22000)], None, &mut merge);

        let output = merge.finish();
        assert_eq!(&output.identities[..output.count], &[0x22000]);
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
    fn terrain_draw_cache_does_not_add_dll_thread_local_startup() {
        let source = include_str!("terrain_lights.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();

        assert!(!production.contains("thread_local!"));
    }

    #[test]
    fn terrain_draw_cache_publishes_complete_atomic_snapshots() {
        let mut merge = TerrainLightMerge::new(&[], 0, context());
        assert!(merge.consider(candidate(0x22000)));
        let expected = merge.finish();
        let geometry = 0x33000;

        invalidate_draw_cache();
        let key = cache_key(geometry);
        publish_draw_cache(&key, expected);
        let cached = load_draw_cache(&key).expect("published semantic key");
        assert_eq!(cached, expected);
        let mut expected_texture = [[0.0; 4]; SUPPLEMENTAL_LIGHT_TEXTURE_TEXELS];
        let mut cached_texture = [[0.0; 4]; SUPPLEMENTAL_LIGHT_TEXTURE_TEXELS];
        cached.write_shader_texture(&mut cached_texture);
        expected.write_shader_texture(&mut expected_texture);
        assert_eq!(
            cached.shader_count_constant(),
            expected.shader_count_constant()
        );
        assert_eq!(cached_texture, expected_texture);

        // A one-entry cache turned alternating A/B/A terrain submissions into
        // three full engine scans. Prove that distinct direct-map slots retain
        // both exact semantic snapshots instead of evicting each other.
        let mut second_key = cache_key(geometry + 4);
        while std::ptr::eq(draw_cache_entry(&key), draw_cache_entry(&second_key)) {
            second_key.geometry = second_key.geometry.wrapping_add(4);
        }
        publish_draw_cache(&second_key, SupplementalTerrainLights::default());
        assert_eq!(load_draw_cache(&key), Some(expected));
        assert_eq!(
            load_draw_cache(&second_key),
            Some(SupplementalTerrainLights::default())
        );

        invalidate_draw_cache();
        assert!(load_draw_cache(&key).is_none());
    }

    #[test]
    fn terrain_draw_cache_rejects_every_stale_key_component() {
        let key = cache_key(0x33000);
        publish_draw_cache(&key, SupplementalTerrainLights::default());

        let mut variants = [key; 11];
        variants[0].render_epoch += 1;
        variants[1].device_generation += 1;
        variants[2].manager_generation += 1;
        variants[3].geometry += 4;
        variants[4].property += 4;
        variants[5].selector += 4;
        variants[6].render_pass += 4;
        variants[7].native_light_signature ^= 1;
        variants[8].native_identity_count += 1;
        variants[9].native_point_count += 1;
        // Preserve the fast signature deliberately: exact membership must
        // still reject a theoretical 32-bit hash collision.
        variants[10].native_identities[0] += 4;
        for variant in variants {
            assert!(load_draw_cache(&variant).is_none());
        }
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
    fn property_scale_below_one_reproduces_the_native_black_point_color() {
        let mut native_dark_path = context();
        native_dark_path.property_light_scale = 0.999;
        let dark_candidate = candidate(0x20000);
        let mut merge = TerrainLightMerge::new(&[], 0, native_dark_path);

        assert!(!merge.consider(dark_candidate));
        assert!(merge.finish().lights().is_empty());
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
    fn shader_payload_interleaves_each_record_and_clears_the_tail() {
        let mut merge = TerrainLightMerge::new(&[], 0, context());
        assert!(merge.consider(candidate(0x20000)));
        let output = merge.finish();
        let mut texture = [[9.0; 4]; SUPPLEMENTAL_LIGHT_TEXTURE_TEXELS];

        output.write_shader_texture(&mut texture);
        assert_eq!(output.shader_count_constant(), [1.0, 0.0, 0.0, 0.0]);
        assert_eq!(texture[0], output.lights()[0].position_radius);
        assert_eq!(texture[1], output.lights()[0].color_visibility);
        assert!(texture[2..].iter().all(|texel| *texel == [0.0; 4]));

        let mut bits = texture.map(|texel| texel.map(f32::to_bits));
        assert!(output.matches_shader_texture_bits(&bits));
        bits[2][0] = 1.0f32.to_bits();
        assert!(
            !output.matches_shader_texture_bits(&bits),
            "the unused tail is part of exact payload identity"
        );
        bits[2][0] = 0;
        bits[0][0] ^= 1;
        assert!(
            !output.matches_shader_texture_bits(&bits),
            "an active component change must require a new upload"
        );
    }

    #[test]
    fn empty_payload_resets_the_supplemental_count() {
        let output = SupplementalTerrainLights::default();
        let mut texture = [[9.0; 4]; SUPPLEMENTAL_LIGHT_TEXTURE_TEXELS];

        output.write_shader_texture(&mut texture);
        assert_eq!(output.shader_count_constant(), [0.0; 4]);
        assert!(output.is_empty());
        assert!(texture.iter().all(|texel| *texel == [0.0; 4]));
    }
}
