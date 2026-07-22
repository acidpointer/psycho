//! NVR-style PBR constant state.
//!
//! Object and terrain settings have separate snapshots because their shader
//! ABIs and material models are not interchangeable. Device uploads belong to
//! the draw replacement path, not to classification code.

use std::{
    array,
    sync::{
        LazyLock,
        atomic::{AtomicU32, Ordering},
    },
};

use super::{
    NativePbrSettings, OBJECT_PBR_PROFILE_VALUE_COUNT, TERRAIN_PBR_PROFILE_VALUE_COUNT,
    terrain_lights::{MAX_SUPPLEMENTAL_CONSTANTS, SupplementalTerrainLights},
};
use libpsycho::os::windows::directx9::Device9Ref;

static OBJECT_PROFILE_BITS: LazyLock<[AtomicU32; OBJECT_PBR_PROFILE_VALUE_COUNT]> =
    LazyLock::new(|| array::from_fn(|_| AtomicU32::new(0)));
static TERRAIN_PROFILE_BITS: LazyLock<[AtomicU32; TERRAIN_PBR_PROFILE_VALUE_COUNT]> =
    LazyLock::new(|| array::from_fn(|_| AtomicU32::new(0)));
static TERRAIN_LOD_NOISE_SCALE: AtomicU32 = AtomicU32::new(1.0f32.to_bits());
static TERRAIN_LOD_NOISE_TILE: AtomicU32 = AtomicU32::new(1.75f32.to_bits());
static OBJECT_CONSTANT_VERSION: AtomicU32 = AtomicU32::new(1);
const PBR_DATA_REGISTER: u32 = 32;
const TERRAIN_DATA_REGISTER: u32 = 89;

pub(super) fn store_settings(settings: NativePbrSettings) {
    let object_profile = settings.object_profile.sanitized_values();
    let mut object_changed = false;
    for (slot, value) in OBJECT_PROFILE_BITS.iter().zip(object_profile) {
        let bits = value.to_bits();
        if slot.swap(bits, Ordering::AcqRel) != bits {
            object_changed = true;
        }
    }

    let terrain_profile = settings.terrain_profile.sanitized_values();
    for (slot, value) in TERRAIN_PROFILE_BITS.iter().zip(terrain_profile) {
        slot.store(value.to_bits(), Ordering::Release);
    }

    TERRAIN_LOD_NOISE_SCALE.store(
        sanitize(settings.terrain_lod_noise_scale, 1.0, 0.0, 1.0).to_bits(),
        Ordering::Release,
    );
    TERRAIN_LOD_NOISE_TILE.store(
        sanitize(settings.terrain_lod_noise_tile, 1.75, 0.05, 16.0).to_bits(),
        Ordering::Release,
    );
    if object_changed {
        OBJECT_CONSTANT_VERSION.fetch_add(1, Ordering::AcqRel);
    }
}

pub(super) fn upload_object_constants(device: &Device9Ref<'_>) -> bool {
    let profile = load_object_profile();
    let constants = object_constants(profile);
    device
        .set_pixel_shader_constant_f(PBR_DATA_REGISTER, &constants)
        .is_ok()
}

fn object_constants(profile: [f32; OBJECT_PBR_PROFILE_VALUE_COUNT]) -> [[f32; 4]; 2] {
    [
        [0.0, profile[0], profile[1], profile[2]],
        [profile[3], 0.0, 0.0, 0.0],
    ]
}

pub(super) fn upload_terrain_constants(
    device: &Device9Ref<'_>,
    supplemental_lights: Option<&SupplementalTerrainLights>,
) -> Option<[[f32; 4]; 2]> {
    let requested = terrain_constants();
    let Some(supplemental_lights) = supplemental_lights else {
        if device
            .set_pixel_shader_constant_f(TERRAIN_DATA_REGISTER, &requested)
            .is_err()
        {
            return None;
        }
        return Some(requested);
    };

    let mut upload = [[0.0; 4]; 2 + MAX_SUPPLEMENTAL_CONSTANTS];
    upload[..2].copy_from_slice(&requested);
    let supplemental_count = supplemental_lights.write_shader_constants(&mut upload[2..]);
    let upload_count = 2 + supplemental_count;
    if device
        .set_pixel_shader_constant_f(TERRAIN_DATA_REGISTER, &upload[..upload_count])
        .is_err()
    {
        return None;
    }

    Some(requested)
}

fn terrain_constants() -> [[f32; 4]; 2] {
    let profile = load_terrain_profile();
    [
        [profile[0], profile[1], profile[2], profile[3]],
        [
            1.0,
            profile[4],
            f32::from_bits(TERRAIN_LOD_NOISE_SCALE.load(Ordering::Acquire)),
            f32::from_bits(TERRAIN_LOD_NOISE_TILE.load(Ordering::Acquire)),
        ],
    ]
}

pub(super) fn read_terrain_constants(device: &Device9Ref<'_>) -> Option<[[f32; 4]; 2]> {
    let mut observed = [[0.0; 4]; 2];
    device
        .pixel_shader_constant_f(TERRAIN_DATA_REGISTER, &mut observed)
        .ok()?;
    Some(observed)
}

pub(super) fn object_constant_version() -> u32 {
    OBJECT_CONSTANT_VERSION.load(Ordering::Acquire)
}

fn load_object_profile() -> [f32; OBJECT_PBR_PROFILE_VALUE_COUNT] {
    let mut values = [0.0; OBJECT_PBR_PROFILE_VALUE_COUNT];
    for (output, slot) in values.iter_mut().zip(OBJECT_PROFILE_BITS.iter()) {
        *output = f32::from_bits(slot.load(Ordering::Acquire));
    }
    values
}

fn load_terrain_profile() -> [f32; TERRAIN_PBR_PROFILE_VALUE_COUNT] {
    let mut values = [0.0; TERRAIN_PBR_PROFILE_VALUE_COUNT];
    for (output, slot) in values.iter_mut().zip(TERRAIN_PROFILE_BITS.iter()) {
        *output = f32::from_bits(slot.load(Ordering::Acquire));
    }
    values
}

fn sanitize(value: f32, fallback: f32, min: f32, max: f32) -> f32 {
    if value.is_finite() {
        value.clamp(min, max)
    } else {
        fallback
    }
}

#[cfg(test)]
mod tests {
    use super::{object_constants, sanitize, terrain_constants};

    #[test]
    fn object_constant_layout_keeps_metallicness_dielectric() {
        let constants = object_constants([0.75, 1.25, 1.5, 0.8]);

        assert_eq!(constants[0], [0.0, 0.75, 1.25, 1.5]);
        assert_eq!(constants[1], [0.8, 0.0, 0.0, 0.0]);
    }

    #[test]
    fn zero_material_controls_remain_zero() {
        assert_eq!(sanitize(0.0, 1.0, 0.0, 4.0), 0.0);
        assert_eq!(sanitize(0.0, 1.0, 0.0, 2.0), 0.0);
    }

    #[test]
    fn distant_detail_strength_is_a_blend_weight() {
        assert_eq!(sanitize(4.0, 1.0, 0.0, 1.0), 1.0);
        assert_eq!(sanitize(0.25, 1.0, 0.0, 1.0), 0.25);
        assert_eq!(sanitize(f32::NAN, 1.0, 0.0, 1.0), 1.0);
    }

    #[test]
    fn terrain_replacement_constants_always_select_pbr() {
        assert_eq!(terrain_constants()[1][0], 1.0);
    }
}
