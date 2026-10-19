//! Camera field-of-view configuration and tangent-preserving scaling.
//!
//! FNV expresses a camera FOV as a vertical angle, applies it through
//! `BSSceneGraph::SetCameraFOV` at `0x00C52020`, and derives the live NiCamera
//! frustum from `tan(fov / 2)`. Atom therefore treats a configured value as a
//! base-FOV target and scales the *live* native angle by the tangent ratio
//! between the target and the corresponding game setting. Native aiming,
//! scopes, POV transitions, and any compatible external FOV owner keep their
//! relative zoom instead of being replaced by one absolute angle.
//!
//! `0` means native pass-through. A non-zero viewmodel value is an absolute
//! base FOV for the separately rendered hands/weapon camera; `0` lets that
//! camera follow the effective first-person FOV. MCM Extender remains the only
//! writer of `Atom.ini`, and the native callbacks consume one lock-free
//! snapshot without parsing or allocating.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use serde::Deserialize;
use thiserror::Error;

/// Lowest non-zero base FOV accepted from configuration.
///
/// MCM's slider exposes `0` and `5..=150` in five-degree steps. A hand-edited
/// positive value is clamped into the same open perspective range.
const MIN_TARGET_FOV: f32 = 1.0;
/// Highest base FOV accepted from configuration.
const MAX_TARGET_FOV: f32 = 150.0;
/// Native angles must remain inside an open perspective range.
const MIN_NATIVE_FOV: f32 = 1.0;
const MAX_NATIVE_FOV: f32 = 179.0;

/// Complete MCM-owned field-of-view configuration.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CameraFovConfig {
    first_person: f32,
    third_person: f32,
    viewmodel: f32,
    pipboy: f32,
}

impl CameraFovConfig {
    pub(super) const DEFAULT: Self = Self {
        first_person: 0.0,
        third_person: 0.0,
        viewmodel: 0.0,
        pipboy: 0.0,
    };

    /// Deserialize the `[Fov]` section and enforce finite bounded angles.
    ///
    /// Unknown sections and keys remain accepted because MCM Extender owns the
    /// file and Atom never writes it back.
    pub fn from_ini(text: &str) -> Result<Self, CameraFovConfigError> {
        let persisted: PersistedConfig = serini::from_str(text)?;
        let section = persisted.fov;
        Ok(Self {
            first_person: sanitize("Fov:fFirstPerson", section.first_person)?,
            third_person: sanitize("Fov:fThirdPerson", section.third_person)?,
            viewmodel: sanitize("Fov:fViewmodel", section.viewmodel)?,
            pipboy: sanitize("Fov:fPipboy", section.pipboy)?,
        })
    }

    /// Return the requested first-person base FOV, or zero for native.
    #[inline]
    pub const fn first_person(self) -> f32 {
        self.first_person
    }

    /// Return the requested third-person base FOV, or zero for native.
    #[inline]
    pub const fn third_person(self) -> f32 {
        self.third_person
    }

    /// Return the requested viewmodel base FOV, or zero to follow first person.
    #[inline]
    pub const fn viewmodel(self) -> f32 {
        self.viewmodel
    }

    /// Return the requested Pip-Boy base FOV, or zero for native.
    #[inline]
    pub const fn pipboy(self) -> f32 {
        self.pipboy
    }

    /// Return whether every field requests native behavior.
    #[inline]
    pub const fn is_native(self) -> bool {
        self.first_person == 0.0
            && self.third_person == 0.0
            && self.viewmodel == 0.0
            && self.pipboy == 0.0
    }

    /// Return the requested base FOV for the selected world-camera mode.
    #[inline]
    pub(super) const fn world_target(self, first_person: bool) -> f32 {
        if first_person {
            self.first_person
        } else {
            self.third_person
        }
    }
}

impl Default for CameraFovConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Failure to deserialize a recognized field-of-view setting.
#[derive(Debug, Error)]
pub enum CameraFovConfigError {
    /// The shared INI document could not be deserialized.
    #[error("could not deserialize Atom.ini for camera FOV: {0}")]
    Deserialize(#[from] serini::Error),
    /// A recognized setting was NaN or infinite.
    #[error("{field} must be finite, found {value}")]
    NonFinite { field: &'static str, value: f32 },
    /// A recognized setting was negative.
    #[error("{field} must be non-negative, found {value}")]
    Negative { field: &'static str, value: f32 },
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PersistedConfig {
    #[serde(rename = "Fov")]
    fov: FovSection,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct FovSection {
    #[serde(rename = "fFirstPerson")]
    first_person: f32,
    #[serde(rename = "fThirdPerson")]
    third_person: f32,
    #[serde(rename = "fViewmodel")]
    viewmodel: f32,
    #[serde(rename = "fPipboy")]
    pipboy: f32,
}

impl Default for FovSection {
    fn default() -> Self {
        Self {
            first_person: CameraFovConfig::DEFAULT.first_person,
            third_person: CameraFovConfig::DEFAULT.third_person,
            viewmodel: CameraFovConfig::DEFAULT.viewmodel,
            pipboy: CameraFovConfig::DEFAULT.pipboy,
        }
    }
}

fn sanitize(field: &'static str, value: f32) -> Result<f32, CameraFovConfigError> {
    if !value.is_finite() {
        return Err(CameraFovConfigError::NonFinite { field, value });
    }
    if value < 0.0 {
        return Err(CameraFovConfigError::Negative { field, value });
    }
    if value == 0.0 {
        return Ok(0.0);
    }
    Ok(value.clamp(MIN_TARGET_FOV, MAX_TARGET_FOV))
}

/// Return the tangent ratio which maps `base_degrees` to `target_degrees`.
///
/// A zero target is the native sentinel and yields exactly `1.0`. Native and
/// target angles must be finite and inside the open perspective range; any
/// violation returns `None` so the caller can keep native behavior.
pub fn fov_scale(target_degrees: f32, base_degrees: f32) -> Option<f32> {
    if target_degrees == 0.0 {
        return Some(1.0);
    }
    if !target_degrees.is_finite()
        || !base_degrees.is_finite()
        || !(MIN_NATIVE_FOV..MAX_NATIVE_FOV).contains(&target_degrees)
        || !(MIN_NATIVE_FOV..MAX_NATIVE_FOV).contains(&base_degrees)
    {
        return None;
    }
    let half_target = target_degrees.to_radians() * 0.5;
    let half_base = base_degrees.to_radians() * 0.5;
    let scale = half_target.tan() / half_base.tan();
    (scale.is_finite() && scale > 0.0).then_some(scale)
}

/// Apply one tangent ratio to a live native FOV angle in degrees.
///
/// This is the exact inverse of [`fov_scale`] at the base angle. `1.0` returns
/// the original angle unchanged so disabled fields cannot accumulate rounding.
pub fn scale_fov_degrees(fov: f32, scale: f32) -> Option<f32> {
    if !fov.is_finite()
        || !(MIN_NATIVE_FOV..MAX_NATIVE_FOV).contains(&fov)
        || !scale.is_finite()
        || scale <= 0.0
    {
        return None;
    }
    if scale == 1.0 {
        return Some(fov);
    }
    let half = fov.to_radians() * 0.5;
    let scaled = (half.tan() * scale).atan().to_degrees() * 2.0;
    (scaled.is_finite() && scaled > 0.0 && scaled < MAX_NATIVE_FOV).then_some(scaled)
}

/// Native `NiFrustum` prefix consumed by the engine's frustum setter.
///
/// The world camera stores left, right, top, bottom, near, and far at
/// `+0xDC..+0xF4`; `0x00A6FAF0` copies the first six floats and the trailing
/// orthographic byte. Atom scales only the four angular extents and preserves
/// the near/far planes and orthographic flag.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct NativeFrustum {
    pub(super) left: f32,
    pub(super) right: f32,
    pub(super) top: f32,
    pub(super) bottom: f32,
    pub(super) near: f32,
    pub(super) far: f32,
    pub(super) orthographic: u8,
    /// Explicit tail bytes keep the native 0x19-byte prefix layout without
    /// relying on implicit struct padding.
    pub(super) reserved: [u8; 3],
}

/// Scale a perspective frustum about its optical center.
///
/// Keeping the center fixed preserves an off-center projection (for example
/// one produced by a compatible jitter owner) while scaling both half-angles.
/// Symmetric native frustums are unaffected by the distinction.
pub(super) fn scale_frustum(frustum: NativeFrustum, scale: f32) -> Option<NativeFrustum> {
    if !scale.is_finite() || scale <= 0.0 {
        return None;
    }
    if ![
        frustum.left,
        frustum.right,
        frustum.top,
        frustum.bottom,
        frustum.near,
        frustum.far,
    ]
    .into_iter()
    .all(f32::is_finite)
        || frustum.right <= frustum.left
        || frustum.top <= frustum.bottom
        || frustum.near <= 0.0
        || frustum.far <= frustum.near
    {
        return None;
    }
    if scale == 1.0 {
        return Some(frustum);
    }

    let center_x = (frustum.left + frustum.right) * 0.5;
    let center_y = (frustum.top + frustum.bottom) * 0.5;
    let scaled = NativeFrustum {
        left: center_x + (frustum.left - center_x) * scale,
        right: center_x + (frustum.right - center_x) * scale,
        top: center_y + (frustum.top - center_y) * scale,
        bottom: center_y + (frustum.bottom - center_y) * scale,
        near: frustum.near,
        far: frustum.far,
        orthographic: frustum.orthographic,
        reserved: frustum.reserved,
    };
    (scaled.left.is_finite()
        && scaled.right.is_finite()
        && scaled.top.is_finite()
        && scaled.bottom.is_finite()
        && scaled.right > scaled.left
        && scaled.top > scaled.bottom)
        .then_some(scaled)
}

/// Coherent lock-free storage for the live FOV configuration.
pub(super) struct ConfigStore {
    sequence: AtomicU32,
    first_person: AtomicU32,
    third_person: AtomicU32,
    viewmodel: AtomicU32,
    pipboy: AtomicU32,
}

impl ConfigStore {
    pub(super) const fn new() -> Self {
        Self {
            sequence: AtomicU32::new(0),
            first_person: AtomicU32::new(CameraFovConfig::DEFAULT.first_person.to_bits()),
            third_person: AtomicU32::new(CameraFovConfig::DEFAULT.third_person.to_bits()),
            viewmodel: AtomicU32::new(CameraFovConfig::DEFAULT.viewmodel.to_bits()),
            pipboy: AtomicU32::new(CameraFovConfig::DEFAULT.pipboy.to_bits()),
        }
    }

    pub(super) fn publish(&self, config: CameraFovConfig) {
        self.sequence.fetch_add(1, Ordering::AcqRel);
        self.first_person
            .store(config.first_person.to_bits(), Ordering::Relaxed);
        self.third_person
            .store(config.third_person.to_bits(), Ordering::Relaxed);
        self.viewmodel
            .store(config.viewmodel.to_bits(), Ordering::Relaxed);
        self.pipboy
            .store(config.pipboy.to_bits(), Ordering::Relaxed);
        self.sequence.fetch_add(1, Ordering::Release);
    }

    #[inline]
    pub(super) fn load(&self) -> CameraFovConfig {
        loop {
            let before = self.begin_read();
            let config = CameraFovConfig {
                first_person: load_f32(&self.first_person),
                third_person: load_f32(&self.third_person),
                viewmodel: load_f32(&self.viewmodel),
                pipboy: load_f32(&self.pipboy),
            };
            if before == self.sequence.load(Ordering::Acquire) {
                return config;
            }
        }
    }

    fn begin_read(&self) -> u32 {
        loop {
            let sequence = self.sequence.load(Ordering::Acquire);
            if sequence & 1 == 0 {
                return sequence;
            }
            core::hint::spin_loop();
        }
    }
}

fn load_f32(source: &AtomicU32) -> f32 {
    f32::from_bits(source.load(Ordering::Relaxed))
}

static CONFIG: ConfigStore = ConfigStore::new();
static CONFIGURED: AtomicBool = AtomicBool::new(false);

/// Return one coherent copy of the current MCM-owned FOV configuration.
pub(super) fn current_config() -> CameraFovConfig {
    CONFIG.load()
}

/// Return whether any FOV field currently requests a non-native value.
#[inline]
pub(super) fn configured() -> bool {
    CONFIGURED.load(Ordering::Acquire)
}

/// Publish one validated FOV snapshot for the next native camera update.
pub(super) fn publish_config(config: CameraFovConfig) {
    CONFIG.publish(config);
    CONFIGURED.store(!config.is_native(), Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::{CameraFovConfig, NativeFrustum, fov_scale, scale_fov_degrees, scale_frustum};

    const BASE: f32 = 75.0;

    fn close(left: f32, right: f32) -> bool {
        (left - right).abs() < 1.0e-4
    }

    #[test]
    fn target_angle_maps_exactly_through_the_tangent_ratio() {
        let scale = fov_scale(90.0, BASE).expect("valid target");
        let result = scale_fov_degrees(BASE, scale).expect("valid native angle");
        assert!(close(result, 90.0), "{result}");
    }

    #[test]
    fn native_sentinel_is_bit_exact_and_does_not_touch_rounding() {
        let scale = fov_scale(0.0, BASE).expect("native sentinel");
        assert_eq!(scale, 1.0);
        assert_eq!(scale_fov_degrees(75.123_45, scale), Some(75.123_45));
        assert_eq!(fov_scale(0.0, f32::NAN), Some(1.0));
    }

    #[test]
    fn native_ads_zoom_is_preserved_relatively() {
        let scale = fov_scale(90.0, BASE).expect("valid target");
        let diagonal = scale_fov_degrees(50.0, scale).expect("valid ADS angle");

        // The absolute angle changes, but its ratio to the unscaled ADS angle
        // remains the same as the base ratio.
        let base_ratio = (90.0_f32.to_radians() * 0.5).tan() / (75.0_f32.to_radians() * 0.5).tan();
        let ads_ratio = (diagonal.to_radians() * 0.5).tan() / (50.0_f32.to_radians() * 0.5).tan();
        assert!(close(base_ratio, ads_ratio));
        assert!(diagonal > 50.0 && diagonal < 90.0, "{diagonal}");
    }

    #[test]
    fn invalid_angles_and_scales_keep_native_behavior() {
        assert_eq!(fov_scale(90.0, 0.0), None);
        assert_eq!(fov_scale(90.0, 180.0), None);
        assert_eq!(fov_scale(f32::INFINITY, BASE), None);
        assert_eq!(scale_fov_degrees(0.0, 1.3), None);
        assert_eq!(scale_fov_degrees(75.0, 0.0), None);
        assert_eq!(scale_fov_degrees(75.0, f32::NAN), None);
    }

    #[test]
    fn frustum_scaling_preserves_center_planes_and_orthographic_flag() {
        let frustum = NativeFrustum {
            left: -1.2,
            right: 1.0,
            top: 0.6,
            bottom: -0.8,
            near: 5.0,
            far: 50_000.0,
            orthographic: 1,
            reserved: [0; 3],
        };
        let scaled = scale_frustum(frustum, 2.0).expect("valid frustum");

        assert!(close(scaled.left, -2.3));
        assert!(close(scaled.right, 2.1));
        assert!(close(scaled.top, 1.3));
        assert!(close(scaled.bottom, -1.5));
        assert_eq!(scaled.near, frustum.near);
        assert_eq!(scaled.far, frustum.far);
        assert_eq!(scaled.orthographic, frustum.orthographic);
    }

    #[test]
    fn identity_and_invalid_frustums_are_exact_or_rejected() {
        let frustum = NativeFrustum {
            left: -1.0,
            right: 1.0,
            top: 0.5,
            bottom: -0.5,
            near: 1.0,
            far: 100.0,
            orthographic: 0,
            reserved: [0; 3],
        };
        assert_eq!(scale_frustum(frustum, 1.0), Some(frustum));

        let mut invalid = frustum;
        invalid.right = invalid.left;
        assert_eq!(scale_frustum(invalid, 2.0), None);
        invalid = frustum;
        invalid.near = 0.0;
        assert_eq!(scale_frustum(invalid, 2.0), None);
        assert_eq!(scale_frustum(frustum, f32::NAN), None);
    }

    #[test]
    fn configuration_zero_means_native_and_nonzero_values_are_bounded() {
        let native = CameraFovConfig::from_ini("[Fov]\nfFirstPerson=0\n").expect("valid config");
        assert!(native.is_native());

        let bounded =
            CameraFovConfig::from_ini("[Fov]\nfFirstPerson=10\nfThirdPerson=200\nfViewmodel=90\n")
                .expect("valid bounded config");
        assert_eq!(bounded.first_person(), 10.0);
        assert_eq!(bounded.third_person(), 150.0);
        assert_eq!(bounded.viewmodel(), 90.0);
        assert!(!bounded.is_native());
    }

    #[test]
    fn non_finite_and_negative_configuration_is_rejected() {
        assert!(CameraFovConfig::from_ini("[Fov]\nfFirstPerson=NaN\n").is_err());
        assert!(CameraFovConfig::from_ini("[Fov]\nfThirdPerson=-1\n").is_err());
    }

    #[test]
    fn the_config_store_publishes_one_coherent_snapshot() {
        let store = super::ConfigStore::new();
        assert!(store.load().is_native());
        let config =
            CameraFovConfig::from_ini("[Fov]\nfFirstPerson=90\nfThirdPerson=85\nfViewmodel=60\n")
                .expect("valid config");
        store.publish(config);
        assert_eq!(store.load(), config);
    }
}
