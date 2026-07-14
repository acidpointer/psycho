//! NVR-style PBR constant state.
//!
//! Constants are stored as sanitized profiles and updated once per frame. Device
//! uploads belong to the shader-record apply path, not to arbitrary draw
//! classification code.

use std::{
    array,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
};

use super::{NativePbrSettings, PBR_PROFILE_VALUE_COUNT};
use libpsycho::os::windows::directx9::Device9Ref;

const PROFILE_COUNT: usize = 5;
const PROFILE_DEFAULT: usize = 0;
const PROFILE_RAIN: usize = 1;
const PROFILE_NIGHT: usize = 2;
const PROFILE_NIGHT_RAIN: usize = 3;
const PROFILE_INTERIOR: usize = 4;

static OBJECT_PROFILES: LazyLock<ProfileStorage> = LazyLock::new(ProfileStorage::new);
static TERRAIN_PROFILES: LazyLock<ProfileStorage> = LazyLock::new(ProfileStorage::new);
static TERRAIN_LOD_NOISE_SCALE: AtomicU32 = AtomicU32::new(1.0f32.to_bits());
static TERRAIN_LOD_NOISE_TILE: AtomicU32 = AtomicU32::new(1.75f32.to_bits());
static TRANSITION_CURVE: AtomicU32 = AtomicU32::new(1.0f32.to_bits());
static EXTERIOR_KNOWN: AtomicBool = AtomicBool::new(false);
static IS_EXTERIOR: AtomicBool = AtomicBool::new(true);
static OBJECT_CONSTANT_VERSION: AtomicU32 = AtomicU32::new(1);
static CURRENT_OBJECT_PROFILE_BITS: LazyLock<[AtomicU32; PBR_PROFILE_VALUE_COUNT]> =
    LazyLock::new(|| array::from_fn(|_| AtomicU32::new(0)));
const PBR_DATA_REGISTER: u32 = 32;
const PBR_EXTRA_DATA_REGISTER: u32 = 33;
const TERRAIN_DATA_REGISTER: u32 = 89;

struct ProfileStorage {
    values: [[AtomicU32; PBR_PROFILE_VALUE_COUNT]; PROFILE_COUNT],
}

impl ProfileStorage {
    fn new() -> Self {
        Self {
            values: array::from_fn(|_| array::from_fn(|_| AtomicU32::new(0))),
        }
    }

    fn store(&self, index: usize, values: [f32; PBR_PROFILE_VALUE_COUNT]) {
        for (slot, value) in self.values[index].iter().zip(values) {
            slot.store(value.to_bits(), Ordering::Release);
        }
    }

    fn load(&self, index: usize) -> [f32; PBR_PROFILE_VALUE_COUNT] {
        let mut values = [0.0; PBR_PROFILE_VALUE_COUNT];
        for (output, slot) in values.iter_mut().zip(self.values[index].iter()) {
            *output = f32::from_bits(slot.load(Ordering::Acquire));
        }
        values
    }
}

pub(super) fn store_settings(settings: NativePbrSettings) {
    OBJECT_PROFILES.store(PROFILE_DEFAULT, settings.object.default.sanitized_values());
    OBJECT_PROFILES.store(PROFILE_RAIN, settings.object.rain.sanitized_values());
    OBJECT_PROFILES.store(PROFILE_NIGHT, settings.object.night.sanitized_values());
    OBJECT_PROFILES.store(
        PROFILE_NIGHT_RAIN,
        settings.object.night_rain.sanitized_values(),
    );
    OBJECT_PROFILES.store(
        PROFILE_INTERIOR,
        settings.object.interior.sanitized_values(),
    );

    TERRAIN_PROFILES.store(PROFILE_DEFAULT, settings.terrain.default.sanitized_values());
    TERRAIN_PROFILES.store(PROFILE_RAIN, settings.terrain.rain.sanitized_values());
    TERRAIN_PROFILES.store(PROFILE_NIGHT, settings.terrain.night.sanitized_values());
    TERRAIN_PROFILES.store(
        PROFILE_NIGHT_RAIN,
        settings.terrain.night_rain.sanitized_values(),
    );
    TERRAIN_PROFILES.store(PROFILE_INTERIOR, [0.0, 1.0, 1.0, 1.0, 1.0]);

    TERRAIN_LOD_NOISE_SCALE.store(
        sanitize(settings.terrain_lod_noise_scale, 1.0, 0.0, 4.0).to_bits(),
        Ordering::Release,
    );
    TERRAIN_LOD_NOISE_TILE.store(
        sanitize(settings.terrain_lod_noise_tile, 1.75, 0.05, 16.0).to_bits(),
        Ordering::Release,
    );
    OBJECT_CONSTANT_VERSION.fetch_add(1, Ordering::AcqRel);
}

pub(super) fn service_frame() {
    let state = crate::backend::material_state_frame();
    TRANSITION_CURVE.store(state.transition_curve.to_bits(), Ordering::Release);
    EXTERIOR_KNOWN.store(state.exterior_known, Ordering::Release);
    IS_EXTERIOR.store(state.is_exterior, Ordering::Release);
    update_object_constant_version();
}

pub(super) fn upload_object_constants(device: &Device9Ref<'_>) -> bool {
    let profile = current_object_profile();
    let pbr_data = [[profile[0], profile[1], profile[2], profile[3]]];
    let pbr_extra_data = [[profile[4], 0.0, 0.0, 0.0]];
    device
        .set_pixel_shader_constant_f(PBR_DATA_REGISTER, &pbr_data)
        .is_ok()
        && device
            .set_pixel_shader_constant_f(PBR_EXTRA_DATA_REGISTER, &pbr_extra_data)
            .is_ok()
}

pub(super) fn upload_terrain_constants(
    device: &Device9Ref<'_>,
) -> Option<([[f32; 4]; 2], [[f32; 4]; 2])> {
    let profile = current_terrain_profile();
    let requested = [
        [profile[0], profile[1], profile[2], profile[3]],
        [
            1.0,
            profile[4],
            f32::from_bits(TERRAIN_LOD_NOISE_SCALE.load(Ordering::Acquire)),
            f32::from_bits(TERRAIN_LOD_NOISE_TILE.load(Ordering::Acquire)),
        ],
    ];
    if device
        .set_pixel_shader_constant_f(TERRAIN_DATA_REGISTER, &requested)
        .is_err()
    {
        return None;
    }

    let mut observed = [[0.0; 4]; 2];
    device
        .pixel_shader_constant_f(TERRAIN_DATA_REGISTER, &mut observed)
        .ok()?;
    Some((requested, observed))
}

pub(super) fn object_constant_version() -> u32 {
    OBJECT_CONSTANT_VERSION.load(Ordering::Acquire)
}

fn update_object_constant_version() {
    let profile = current_object_profile();
    let mut changed = false;
    for (slot, value) in CURRENT_OBJECT_PROFILE_BITS.iter().zip(profile) {
        let bits = value.to_bits();
        if slot.swap(bits, Ordering::AcqRel) != bits {
            changed = true;
        }
    }

    if changed {
        OBJECT_CONSTANT_VERSION.fetch_add(1, Ordering::AcqRel);
    }
}

fn current_object_profile() -> [f32; PBR_PROFILE_VALUE_COUNT] {
    if EXTERIOR_KNOWN.load(Ordering::Acquire) && !IS_EXTERIOR.load(Ordering::Acquire) {
        return OBJECT_PROFILES.load(PROFILE_INTERIOR);
    }

    let t = f32::from_bits(TRANSITION_CURVE.load(Ordering::Acquire)).clamp(0.0, 1.0);
    let night = OBJECT_PROFILES.load(PROFILE_NIGHT);
    let day = OBJECT_PROFILES.load(PROFILE_DEFAULT);
    lerp_profile(night, day, t)
}

fn current_terrain_profile() -> [f32; PBR_PROFILE_VALUE_COUNT] {
    let t = f32::from_bits(TRANSITION_CURVE.load(Ordering::Acquire)).clamp(0.0, 1.0);
    let night = TERRAIN_PROFILES.load(PROFILE_NIGHT);
    let day = TERRAIN_PROFILES.load(PROFILE_DEFAULT);
    lerp_profile(night, day, t)
}

fn lerp_profile(
    a: [f32; PBR_PROFILE_VALUE_COUNT],
    b: [f32; PBR_PROFILE_VALUE_COUNT],
    t: f32,
) -> [f32; PBR_PROFILE_VALUE_COUNT] {
    let mut result = [0.0; PBR_PROFILE_VALUE_COUNT];
    for index in 0..PBR_PROFILE_VALUE_COUNT {
        result[index] = a[index] + ((b[index] - a[index]) * t);
    }
    result
}

fn sanitize(value: f32, fallback: f32, min: f32, max: f32) -> f32 {
    if value.is_finite() {
        value.clamp(min, max)
    } else {
        fallback
    }
}
