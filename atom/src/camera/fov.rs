//! Camera field-of-view configuration.
//!
//! Atom owns the native FNV FOV bases while a non-zero target is configured:
//!
//! - `fDefaultWorldFOV` for the world / first-person world base;
//! - `fDefault1stPersonFOV` for the first-person / viewmodel base;
//! - `fOverShoulderFOV` for the stable third-person base;
//! - `fPipboy1stPersonFOV` for the Pip-Boy / terminal base.
//!
//! The engine's `UpdateFOV`, `UpdateCamera`, ADS/scope, VATS/kill-camera,
//! Pip-Boy, 3D-UI projection, and world-to-screen consumers then observe one
//! coherent native base. Atom does not scale individual camera writer
//! arguments. MCM Extender remains the only writer of `Atom.ini`; the native
//! callbacks consume one lock-free snapshot without parsing or allocating.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use serde::Deserialize;
use thiserror::Error;

/// Lowest non-zero base FOV accepted from configuration.
const MIN_TARGET_FOV: f32 = 1.0;
/// Highest base FOV accepted from configuration.
const MAX_TARGET_FOV: f32 = 150.0;
/// Terminal screen projection scale. This is a multiplier, not an angle.
const MAX_TERMINAL_FOV_SCALE: f32 = 1.0;
/// Longest accepted iron-sight transition time in seconds.
const MAX_IRON_SIGHT_SPEED: f32 = 10.0;
/// Longest accepted dialogue zoom/delay interval in seconds.
const MAX_DIALOG_SECONDS: f32 = 30.0;
/// Largest accepted scope-scissor amount.
const MAX_SCOPE_SCISSOR: f32 = 1.0;
/// Farthest accepted near-clip distance.
const MAX_NEAR_DISTANCE: f32 = 1000.0;

/// Complete MCM-owned field-of-view configuration.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CameraFovConfig {
    first_person: f32,
    third_person: f32,
    viewmodel: f32,
    pipboy: f32,
    terminal: f32,
    iron_sight_fov: f32,
    iron_sight_speed: f32,
    dialog_zoom_in: f32,
    dialog_zoom_out: f32,
    dialog_delay: f32,
    scope_scissor: f32,
    near_distance: f32,
}

impl CameraFovConfig {
    pub(super) const DEFAULT: Self = Self {
        first_person: 0.0,
        third_person: 0.0,
        viewmodel: 0.0,
        pipboy: 0.0,
        terminal: 0.0,
        iron_sight_fov: 0.0,
        iron_sight_speed: 0.0,
        dialog_zoom_in: 0.0,
        dialog_zoom_out: 0.0,
        dialog_delay: 0.0,
        scope_scissor: 0.0,
        near_distance: 0.0,
    };

    /// Deserialize the `[Fov]` section and enforce finite bounded angles.
    ///
    /// Unknown sections and keys remain accepted because MCM Extender owns the
    /// file and Atom never writes it back.
    pub fn from_ini(text: &str) -> Result<Self, CameraFovConfigError> {
        let persisted: PersistedConfig = serini::from_str(text)?;
        let section = persisted.fov;
        Ok(Self {
            first_person: sanitize_angle("Fov:fFirstPerson", section.first_person)?,
            third_person: sanitize_angle("Fov:fThirdPerson", section.third_person)?,
            viewmodel: sanitize_angle("Fov:fViewmodel", section.viewmodel)?,
            pipboy: sanitize_angle("Fov:fPipboy", section.pipboy)?,
            terminal: sanitize_range(
                "Fov:fTerminal",
                section.terminal,
                0.01,
                MAX_TERMINAL_FOV_SCALE,
            )?,
            iron_sight_fov: sanitize_angle("Fov:fIronSightFov", section.iron_sight_fov)?,
            iron_sight_speed: sanitize_range(
                "Fov:fIronSightSpeed",
                section.iron_sight_speed,
                0.01,
                MAX_IRON_SIGHT_SPEED,
            )?,
            dialog_zoom_in: sanitize_range(
                "Fov:fDialogZoomIn",
                section.dialog_zoom_in,
                0.01,
                MAX_DIALOG_SECONDS,
            )?,
            dialog_zoom_out: sanitize_range(
                "Fov:fDialogZoomOut",
                section.dialog_zoom_out,
                0.01,
                MAX_DIALOG_SECONDS,
            )?,
            dialog_delay: sanitize_range(
                "Fov:fDialogDelay",
                section.dialog_delay,
                0.01,
                MAX_DIALOG_SECONDS,
            )?,
            scope_scissor: sanitize_range(
                "Fov:fScopeScissor",
                section.scope_scissor,
                0.01,
                MAX_SCOPE_SCISSOR,
            )?,
            near_distance: sanitize_range(
                "Fov:fNearDistance",
                section.near_distance,
                0.1,
                MAX_NEAR_DISTANCE,
            )?,
        })
    }

    /// Return the requested first-person world base FOV, or zero for native.
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

    /// Return the terminal screen projection scale, or zero for native.
    #[inline]
    pub const fn terminal(self) -> f32 {
        self.terminal
    }

    /// Return the global iron-sight base FOV, or zero for native.
    #[inline]
    pub const fn iron_sight_fov(self) -> f32 {
        self.iron_sight_fov
    }

    /// Return the iron-sight transition time in seconds, or zero for native.
    #[inline]
    pub const fn iron_sight_speed(self) -> f32 {
        self.iron_sight_speed
    }

    /// Return the dialogue zoom-in time in seconds, or zero for native.
    #[inline]
    pub const fn dialog_zoom_in(self) -> f32 {
        self.dialog_zoom_in
    }

    /// Return the dialogue zoom-out time in seconds, or zero for native.
    #[inline]
    pub const fn dialog_zoom_out(self) -> f32 {
        self.dialog_zoom_out
    }

    /// Return the dialogue speech delay in seconds, or zero for native.
    #[inline]
    pub const fn dialog_delay(self) -> f32 {
        self.dialog_delay
    }

    /// Return the scope-scissor amount, or zero for native.
    #[inline]
    pub const fn scope_scissor(self) -> f32 {
        self.scope_scissor
    }

    /// Return the near-clip distance, or zero for native.
    #[inline]
    pub const fn near_distance(self) -> f32 {
        self.near_distance
    }

    /// Return whether every field requests native behavior.
    #[inline]
    pub const fn is_native(self) -> bool {
        self.first_person == 0.0
            && self.third_person == 0.0
            && self.viewmodel == 0.0
            && self.pipboy == 0.0
            && self.terminal == 0.0
            && self.iron_sight_fov == 0.0
            && self.iron_sight_speed == 0.0
            && self.dialog_zoom_in == 0.0
            && self.dialog_zoom_out == 0.0
            && self.dialog_delay == 0.0
            && self.scope_scissor == 0.0
            && self.near_distance == 0.0
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
    #[serde(rename = "fTerminal")]
    terminal: f32,
    #[serde(rename = "fIronSightFov")]
    iron_sight_fov: f32,
    #[serde(rename = "fIronSightSpeed")]
    iron_sight_speed: f32,
    #[serde(rename = "fDialogZoomIn")]
    dialog_zoom_in: f32,
    #[serde(rename = "fDialogZoomOut")]
    dialog_zoom_out: f32,
    #[serde(rename = "fDialogDelay")]
    dialog_delay: f32,
    #[serde(rename = "fScopeScissor")]
    scope_scissor: f32,
    #[serde(rename = "fNearDistance")]
    near_distance: f32,
}

impl Default for FovSection {
    fn default() -> Self {
        Self {
            first_person: CameraFovConfig::DEFAULT.first_person,
            third_person: CameraFovConfig::DEFAULT.third_person,
            viewmodel: CameraFovConfig::DEFAULT.viewmodel,
            pipboy: CameraFovConfig::DEFAULT.pipboy,
            terminal: CameraFovConfig::DEFAULT.terminal,
            iron_sight_fov: CameraFovConfig::DEFAULT.iron_sight_fov,
            iron_sight_speed: CameraFovConfig::DEFAULT.iron_sight_speed,
            dialog_zoom_in: CameraFovConfig::DEFAULT.dialog_zoom_in,
            dialog_zoom_out: CameraFovConfig::DEFAULT.dialog_zoom_out,
            dialog_delay: CameraFovConfig::DEFAULT.dialog_delay,
            scope_scissor: CameraFovConfig::DEFAULT.scope_scissor,
            near_distance: CameraFovConfig::DEFAULT.near_distance,
        }
    }
}

fn sanitize_angle(field: &'static str, value: f32) -> Result<f32, CameraFovConfigError> {
    sanitize_range(field, value, MIN_TARGET_FOV, MAX_TARGET_FOV)
}

fn sanitize_range(
    field: &'static str,
    value: f32,
    minimum: f32,
    maximum: f32,
) -> Result<f32, CameraFovConfigError> {
    if !value.is_finite() {
        return Err(CameraFovConfigError::NonFinite { field, value });
    }
    if value < 0.0 {
        return Err(CameraFovConfigError::Negative { field, value });
    }
    if value == 0.0 {
        return Ok(0.0);
    }
    Ok(value.clamp(minimum, maximum))
}

/// Coherent lock-free storage for the live FOV configuration.
pub(super) struct ConfigStore {
    sequence: AtomicU32,
    first_person: AtomicU32,
    third_person: AtomicU32,
    viewmodel: AtomicU32,
    pipboy: AtomicU32,
    terminal: AtomicU32,
    iron_sight_fov: AtomicU32,
    iron_sight_speed: AtomicU32,
    dialog_zoom_in: AtomicU32,
    dialog_zoom_out: AtomicU32,
    dialog_delay: AtomicU32,
    scope_scissor: AtomicU32,
    near_distance: AtomicU32,
}

impl ConfigStore {
    pub(super) const fn new() -> Self {
        Self {
            sequence: AtomicU32::new(0),
            first_person: AtomicU32::new(CameraFovConfig::DEFAULT.first_person.to_bits()),
            third_person: AtomicU32::new(CameraFovConfig::DEFAULT.third_person.to_bits()),
            viewmodel: AtomicU32::new(CameraFovConfig::DEFAULT.viewmodel.to_bits()),
            pipboy: AtomicU32::new(CameraFovConfig::DEFAULT.pipboy.to_bits()),
            terminal: AtomicU32::new(CameraFovConfig::DEFAULT.terminal.to_bits()),
            iron_sight_fov: AtomicU32::new(CameraFovConfig::DEFAULT.iron_sight_fov.to_bits()),
            iron_sight_speed: AtomicU32::new(CameraFovConfig::DEFAULT.iron_sight_speed.to_bits()),
            dialog_zoom_in: AtomicU32::new(CameraFovConfig::DEFAULT.dialog_zoom_in.to_bits()),
            dialog_zoom_out: AtomicU32::new(CameraFovConfig::DEFAULT.dialog_zoom_out.to_bits()),
            dialog_delay: AtomicU32::new(CameraFovConfig::DEFAULT.dialog_delay.to_bits()),
            scope_scissor: AtomicU32::new(CameraFovConfig::DEFAULT.scope_scissor.to_bits()),
            near_distance: AtomicU32::new(CameraFovConfig::DEFAULT.near_distance.to_bits()),
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
        self.terminal
            .store(config.terminal.to_bits(), Ordering::Relaxed);
        self.iron_sight_fov
            .store(config.iron_sight_fov.to_bits(), Ordering::Relaxed);
        self.iron_sight_speed
            .store(config.iron_sight_speed.to_bits(), Ordering::Relaxed);
        self.dialog_zoom_in
            .store(config.dialog_zoom_in.to_bits(), Ordering::Relaxed);
        self.dialog_zoom_out
            .store(config.dialog_zoom_out.to_bits(), Ordering::Relaxed);
        self.dialog_delay
            .store(config.dialog_delay.to_bits(), Ordering::Relaxed);
        self.scope_scissor
            .store(config.scope_scissor.to_bits(), Ordering::Relaxed);
        self.near_distance
            .store(config.near_distance.to_bits(), Ordering::Relaxed);
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
                terminal: load_f32(&self.terminal),
                iron_sight_fov: load_f32(&self.iron_sight_fov),
                iron_sight_speed: load_f32(&self.iron_sight_speed),
                dialog_zoom_in: load_f32(&self.dialog_zoom_in),
                dialog_zoom_out: load_f32(&self.dialog_zoom_out),
                dialog_delay: load_f32(&self.dialog_delay),
                scope_scissor: load_f32(&self.scope_scissor),
                near_distance: load_f32(&self.near_distance),
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
    use super::CameraFovConfig;

    #[test]
    fn native_defaults_and_zero_targets_keep_every_base() {
        assert!(CameraFovConfig::default().is_native());
        let native = CameraFovConfig::from_ini("[Fov]\nfFirstPerson=0\n").expect("valid config");
        assert!(native.is_native());
    }

    #[test]
    fn four_independent_targets_are_parsed_and_bounded() {
        let config = CameraFovConfig::from_ini(
            "[Fov]\nfFirstPerson=110\nfThirdPerson=105\nfViewmodel=90\nfPipboy=60\n",
        )
        .expect("valid config");
        assert_eq!(config.first_person(), 110.0);
        assert_eq!(config.third_person(), 105.0);
        assert_eq!(config.viewmodel(), 90.0);
        assert_eq!(config.pipboy(), 60.0);
        assert!(!config.is_native());

        let low = CameraFovConfig::from_ini("[Fov]\nfFirstPerson=1\n").expect("clamped");
        assert_eq!(low.first_person(), 1.0);
        let high = CameraFovConfig::from_ini("[Fov]\nfThirdPerson=240\n").expect("clamped");
        assert_eq!(high.third_person(), 150.0);
    }

    #[test]
    fn terminal_iron_sight_dialog_scissor_and_near_settings_are_parsed() {
        let config = CameraFovConfig::from_ini(
            "[Fov]\nfTerminal=0.15\nfIronSightFov=67\nfIronSightSpeed=0.1\n\
             fDialogZoomIn=1.5\nfDialogZoomOut=0.5\nfDialogDelay=2.0\n\
             fScopeScissor=0.25\nfNearDistance=5.0\n",
        )
        .expect("valid detail config");
        assert_eq!(config.terminal(), 0.15);
        assert_eq!(config.iron_sight_fov(), 67.0);
        assert_eq!(config.iron_sight_speed(), 0.1);
        assert_eq!(config.dialog_zoom_in(), 1.5);
        assert_eq!(config.dialog_zoom_out(), 0.5);
        assert_eq!(config.dialog_delay(), 2.0);
        assert_eq!(config.scope_scissor(), 0.25);
        assert_eq!(config.near_distance(), 5.0);
        assert!(!config.is_native());
    }

    #[test]
    fn detail_settings_are_bounded_and_reject_invalid_values() {
        let high = CameraFovConfig::from_ini(
            "[Fov]\nfTerminal=4\nfIronSightFov=400\nfIronSightSpeed=40\nfDialogDelay=90\n\
             fScopeScissor=4\nfNearDistance=5000\n",
        )
        .expect("clamped detail config");
        assert_eq!(high.terminal(), 1.0);
        assert_eq!(high.iron_sight_fov(), 150.0);
        assert_eq!(high.iron_sight_speed(), 10.0);
        assert_eq!(high.dialog_delay(), 30.0);
        assert_eq!(high.scope_scissor(), 1.0);
        assert_eq!(high.near_distance(), 1000.0);

        assert!(CameraFovConfig::from_ini("[Fov]\nfTerminal=-1\n").is_err());
        assert!(CameraFovConfig::from_ini("[Fov]\nfNearDistance=NaN\n").is_err());
    }

    #[test]
    fn non_finite_and_negative_configuration_is_rejected() {
        assert!(CameraFovConfig::from_ini("[Fov]\nfFirstPerson=NaN\n").is_err());
        assert!(CameraFovConfig::from_ini("[Fov]\nfThirdPerson=-1\n").is_err());
        assert!(CameraFovConfig::from_ini("[Fov]\nfViewmodel=inf\n").is_err());
    }

    #[test]
    fn configuration_store_publishes_one_coherent_snapshot() {
        let store = super::ConfigStore::new();
        assert!(store.load().is_native());
        let config =
            CameraFovConfig::from_ini("[Fov]\nfFirstPerson=90\nfThirdPerson=85\nfViewmodel=60\n")
                .expect("valid config");
        store.publish(config);
        assert_eq!(store.load(), config);
    }
}
