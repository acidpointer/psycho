//! MCM-owned first-person presentation settings.
//!
//! Camera and viewmodel gains remain independent. The camera gain controls the
//! conservative world listener, while the weapon gain controls only the
//! separately rendered hands/weapon listener. Either exact zero therefore
//! removes every native write owned by that listener.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use serde::Deserialize;
use thiserror::Error;

/// Complete configuration consumed by the first-person motion generator.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FirstPersonConfig {
    enabled: bool,
    camera_motion: f32,
    weapon_motion: f32,
    landing_motion: f32,
    aim_motion: f32,
}

impl FirstPersonConfig {
    pub(super) const DEFAULT: Self = Self {
        enabled: false,
        camera_motion: 0.65,
        weapon_motion: 0.65,
        landing_motion: 0.45,
        aim_motion: 0.20,
    };

    /// Deserialize the `[FirstPerson]` section and enforce safe numeric bounds.
    ///
    /// Unknown keys and sections remain accepted because MCM Extender owns the
    /// file and Atom never writes it back.
    pub fn from_ini(text: &str) -> Result<Self, FirstPersonConfigError> {
        let persisted: PersistedConfig = serini::from_str(text)?;
        let section = persisted.first_person;
        validate_finite("FirstPerson:fCameraMotion", section.camera_motion)?;
        validate_finite("FirstPerson:fWeaponMotion", section.weapon_motion)?;
        validate_finite("FirstPerson:fLandingMotion", section.landing_motion)?;
        validate_finite("FirstPerson:fAimMotion", section.aim_motion)?;
        Ok(Self {
            enabled: numeric_bool("FirstPerson:bEnabled", section.enabled)?,
            camera_motion: section.camera_motion.clamp(0.0, 1.0),
            weapon_motion: section.weapon_motion.clamp(0.0, 1.0),
            landing_motion: section.landing_motion.clamp(0.0, 1.0),
            aim_motion: section.aim_motion.clamp(0.0, 1.0),
        })
    }

    /// Return whether first-person head and viewmodel presentation is requested.
    #[inline]
    pub const fn enabled(self) -> bool {
        self.enabled
    }

    /// Return the master world-camera head-motion gain in `[0, 1]`.
    #[inline]
    pub const fn camera_motion(self) -> f32 {
        self.camera_motion
    }

    /// Return the master hands/weapon motion gain in `[0, 1]`.
    #[inline]
    pub const fn weapon_motion(self) -> f32 {
        self.weapon_motion
    }

    /// Return the landing contribution gain in `[0, 1]`.
    #[inline]
    pub const fn landing_motion(self) -> f32 {
        self.landing_motion
    }

    /// Return the fraction of ordinary motion retained while aiming.
    #[inline]
    pub const fn aim_motion(self) -> f32 {
        self.aim_motion
    }
}

impl Default for FirstPersonConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Failure to deserialize a recognized first-person setting.
#[derive(Debug, Error)]
pub enum FirstPersonConfigError {
    /// The shared INI document could not be deserialized.
    #[error("could not deserialize Atom.ini for First Person: {0}")]
    Deserialize(#[from] serini::Error),
    /// MCM's numeric boolean contract was violated.
    #[error("{field} must be 0 or 1, found {value}")]
    InvalidBoolean { field: &'static str, value: u8 },
    /// A recognized floating-point setting was NaN or infinite.
    #[error("{field} must be finite, found {value}")]
    NonFinite { field: &'static str, value: f32 },
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PersistedConfig {
    #[serde(rename = "FirstPerson")]
    first_person: FirstPersonSection,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct FirstPersonSection {
    #[serde(rename = "bEnabled")]
    enabled: u8,
    #[serde(rename = "fCameraMotion")]
    camera_motion: f32,
    #[serde(rename = "fWeaponMotion")]
    weapon_motion: f32,
    #[serde(rename = "fLandingMotion")]
    landing_motion: f32,
    #[serde(rename = "fAimMotion")]
    aim_motion: f32,
}

impl Default for FirstPersonSection {
    fn default() -> Self {
        let defaults = FirstPersonConfig::DEFAULT;
        Self {
            enabled: u8::from(defaults.enabled),
            camera_motion: defaults.camera_motion,
            weapon_motion: defaults.weapon_motion,
            landing_motion: defaults.landing_motion,
            aim_motion: defaults.aim_motion,
        }
    }
}

fn numeric_bool(field: &'static str, value: u8) -> Result<bool, FirstPersonConfigError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(FirstPersonConfigError::InvalidBoolean { field, value }),
    }
}

fn validate_finite(field: &'static str, value: f32) -> Result<(), FirstPersonConfigError> {
    if value.is_finite() {
        Ok(())
    } else {
        Err(FirstPersonConfigError::NonFinite { field, value })
    }
}

/// Coherent lock-free storage for the live first-person configuration.
pub(super) struct ConfigStore {
    sequence: AtomicU32,
    enabled: AtomicBool,
    camera_motion: AtomicU32,
    weapon_motion: AtomicU32,
    landing_motion: AtomicU32,
    aim_motion: AtomicU32,
}

impl ConfigStore {
    pub(super) const fn new() -> Self {
        let defaults = FirstPersonConfig::DEFAULT;
        Self {
            sequence: AtomicU32::new(0),
            enabled: AtomicBool::new(defaults.enabled),
            camera_motion: AtomicU32::new(defaults.camera_motion.to_bits()),
            weapon_motion: AtomicU32::new(defaults.weapon_motion.to_bits()),
            landing_motion: AtomicU32::new(defaults.landing_motion.to_bits()),
            aim_motion: AtomicU32::new(defaults.aim_motion.to_bits()),
        }
    }

    pub(super) fn publish(&self, config: FirstPersonConfig) {
        self.sequence.fetch_add(1, Ordering::AcqRel);
        self.enabled.store(config.enabled, Ordering::Relaxed);
        self.camera_motion
            .store(config.camera_motion.to_bits(), Ordering::Relaxed);
        self.weapon_motion
            .store(config.weapon_motion.to_bits(), Ordering::Relaxed);
        self.landing_motion
            .store(config.landing_motion.to_bits(), Ordering::Relaxed);
        self.aim_motion
            .store(config.aim_motion.to_bits(), Ordering::Relaxed);
        self.sequence.fetch_add(1, Ordering::Release);
    }

    #[inline]
    pub(super) fn load(&self) -> FirstPersonConfig {
        loop {
            let before = self.begin_read();
            let config = FirstPersonConfig {
                enabled: self.enabled.load(Ordering::Relaxed),
                camera_motion: load_f32(&self.camera_motion),
                weapon_motion: load_f32(&self.weapon_motion),
                landing_motion: load_f32(&self.landing_motion),
                aim_motion: load_f32(&self.aim_motion),
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
