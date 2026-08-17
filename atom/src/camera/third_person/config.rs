//! MCM-owned third-person camera and locomotion settings.
//!
//! MCM Extender remains the only writer of `Atom.ini`. This module parses the
//! `[Camera]` and `[Movement]` sections into one validated value and publishes
//! it through a small seqlock. Native callbacks therefore never allocate,
//! block, or observe a partially updated group of settings.

use core::sync::atomic::{AtomicU32, Ordering};

use serde::Deserialize;
use thiserror::Error;

/// Complete configuration for Atom's third-person ownership system.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ThirdPersonConfig {
    follow_enabled: bool,
    follow_speed: f32,
    soft_zone: f32,
    look_ahead: f32,
    zoom_step: f32,
    auto_center: bool,
    center_delay: f32,
    center_speed_degrees: f32,
    movement_enabled: bool,
    turn_speed_degrees: f32,
    drawn_360: bool,
}

impl ThirdPersonConfig {
    pub(super) const DEFAULT: Self = Self {
        follow_enabled: false,
        follow_speed: 7.5,
        soft_zone: 12.0,
        look_ahead: 8.0,
        zoom_step: 2.0,
        auto_center: false,
        center_delay: 1.25,
        center_speed_degrees: 120.0,
        movement_enabled: false,
        turn_speed_degrees: 540.0,
        drawn_360: false,
    };

    /// Deserialize the `[Camera]` and `[Movement]` sections.
    ///
    /// Unknown sections and keys are intentionally tolerated because all Atom
    /// modules share one MCM-owned INI document. Non-finite values and numeric
    /// booleans other than zero or one are rejected as one coherent update.
    pub fn from_ini(text: &str) -> Result<Self, ThirdPersonConfigError> {
        let persisted: PersistedConfig = serini::from_str(text)?;
        let camera = persisted.camera;
        let movement = persisted.movement;
        for (field, value) in [
            ("Camera:fFollowSpeed", camera.follow_speed),
            ("Camera:fSoftZone", camera.soft_zone),
            ("Camera:fLookAhead", camera.look_ahead),
            ("Camera:fZoomStep", camera.zoom_step),
            ("Camera:fCenterDelay", camera.center_delay),
            ("Camera:fCenterSpeed", camera.center_speed_degrees),
            ("Movement:fTurnSpeed", movement.turn_speed_degrees),
        ] {
            validate_finite(field, value)?;
        }

        Ok(Self {
            follow_enabled: numeric_bool("Camera:bFollowCamera", camera.follow_enabled)?,
            follow_speed: camera.follow_speed.clamp(1.0, 20.0),
            soft_zone: camera.soft_zone.clamp(0.0, 48.0),
            look_ahead: camera.look_ahead.clamp(0.0, 32.0),
            zoom_step: camera.zoom_step.clamp(1.0, 10.0),
            auto_center: numeric_bool("Camera:bAutoCenter", camera.auto_center)?,
            center_delay: camera.center_delay.clamp(0.0, 5.0),
            center_speed_degrees: camera.center_speed_degrees.clamp(15.0, 360.0),
            movement_enabled: numeric_bool("Movement:b360Movement", movement.enabled)?,
            turn_speed_degrees: movement.turn_speed_degrees.clamp(90.0, 1080.0),
            drawn_360: numeric_bool("Movement:bDrawn360", movement.drawn_360)?,
        })
    }

    /// Return whether either independently configurable feature is requested.
    ///
    /// Follow and 360-degree movement intentionally have no hidden dependency
    /// on one another. This combined predicate is used only for ownership
    /// admission; each output path still checks its own setting.
    #[inline]
    pub const fn enabled(self) -> bool {
        self.follow_enabled || self.movement_enabled
    }

    /// Return whether dynamic third-person follow is requested.
    #[inline]
    pub const fn follow_enabled(self) -> bool {
        self.follow_enabled
    }

    /// Return the critically damped follow rate in reciprocal seconds.
    #[inline]
    pub const fn follow_speed(self) -> f32 {
        self.follow_speed
    }

    /// Return the horizontal soft-zone radius in game units.
    #[inline]
    pub const fn soft_zone(self) -> f32 {
        self.soft_zone
    }

    /// Return the maximum horizontal look-ahead distance in game units.
    #[inline]
    pub const fn look_ahead(self) -> f32 {
        self.look_ahead
    }

    /// Return the desired camera-distance change per mouse-wheel notch.
    #[inline]
    pub const fn zoom_step(self) -> f32 {
        self.zoom_step
    }

    /// Return whether movement may recenter an idle manual orbit.
    #[inline]
    pub const fn auto_center(self) -> bool {
        self.auto_center
    }

    /// Return the no-look delay before recentering, in seconds.
    #[inline]
    pub const fn center_delay(self) -> f32 {
        self.center_delay
    }

    /// Return the recenter speed in degrees per second as persisted by MCM.
    #[inline]
    pub const fn center_speed_degrees(self) -> f32 {
        self.center_speed_degrees
    }

    /// Return the recenter speed in radians per second.
    #[inline]
    pub fn center_speed_radians(self) -> f32 {
        self.center_speed_degrees.to_radians()
    }

    /// Return whether camera-relative 360-degree locomotion is requested.
    #[inline]
    pub const fn movement_enabled(self) -> bool {
        self.movement_enabled
    }

    /// Return the actor turn-speed limit in degrees per second.
    #[inline]
    pub const fn turn_speed_degrees(self) -> f32 {
        self.turn_speed_degrees
    }

    /// Return the actor turn-speed limit in radians per second.
    #[inline]
    pub fn turn_speed_radians(self) -> f32 {
        self.turn_speed_degrees.to_radians()
    }

    /// Return whether relaxed 360 movement remains active with a weapon out.
    #[inline]
    pub const fn drawn_360(self) -> bool {
        self.drawn_360
    }
}

impl Default for ThirdPersonConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Failure to deserialize a recognized third-person setting.
#[derive(Debug, Error)]
pub enum ThirdPersonConfigError {
    /// The shared INI document could not be deserialized.
    #[error("could not deserialize Atom.ini for Third Person: {0}")]
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
    #[serde(rename = "Camera")]
    camera: CameraSection,
    #[serde(rename = "Movement")]
    movement: MovementSection,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct CameraSection {
    #[serde(rename = "bFollowCamera")]
    follow_enabled: u8,
    #[serde(rename = "fFollowSpeed")]
    follow_speed: f32,
    #[serde(rename = "fSoftZone")]
    soft_zone: f32,
    #[serde(rename = "fLookAhead")]
    look_ahead: f32,
    #[serde(rename = "fZoomStep")]
    zoom_step: f32,
    #[serde(rename = "bAutoCenter")]
    auto_center: u8,
    #[serde(rename = "fCenterDelay")]
    center_delay: f32,
    #[serde(rename = "fCenterSpeed")]
    center_speed_degrees: f32,
}

impl Default for CameraSection {
    fn default() -> Self {
        let defaults = ThirdPersonConfig::DEFAULT;
        Self {
            follow_enabled: u8::from(defaults.follow_enabled),
            follow_speed: defaults.follow_speed,
            soft_zone: defaults.soft_zone,
            look_ahead: defaults.look_ahead,
            zoom_step: defaults.zoom_step,
            auto_center: u8::from(defaults.auto_center),
            center_delay: defaults.center_delay,
            center_speed_degrees: defaults.center_speed_degrees,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct MovementSection {
    #[serde(rename = "b360Movement")]
    enabled: u8,
    #[serde(rename = "fTurnSpeed")]
    turn_speed_degrees: f32,
    #[serde(rename = "bDrawn360")]
    drawn_360: u8,
}

impl Default for MovementSection {
    fn default() -> Self {
        let defaults = ThirdPersonConfig::DEFAULT;
        Self {
            enabled: u8::from(defaults.movement_enabled),
            turn_speed_degrees: defaults.turn_speed_degrees,
            drawn_360: u8::from(defaults.drawn_360),
        }
    }
}

fn numeric_bool(field: &'static str, value: u8) -> Result<bool, ThirdPersonConfigError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(ThirdPersonConfigError::InvalidBoolean { field, value }),
    }
}

fn validate_finite(field: &'static str, value: f32) -> Result<(), ThirdPersonConfigError> {
    if value.is_finite() {
        Ok(())
    } else {
        Err(ThirdPersonConfigError::NonFinite { field, value })
    }
}

pub(super) struct ConfigStore {
    sequence: AtomicU32,
    booleans: AtomicU32,
    values: [AtomicU32; 7],
}

impl ConfigStore {
    pub(super) const fn new() -> Self {
        let defaults = ThirdPersonConfig::DEFAULT;
        Self {
            sequence: AtomicU32::new(0),
            booleans: AtomicU32::new(pack_booleans(defaults)),
            values: [
                AtomicU32::new(defaults.follow_speed.to_bits()),
                AtomicU32::new(defaults.soft_zone.to_bits()),
                AtomicU32::new(defaults.look_ahead.to_bits()),
                AtomicU32::new(defaults.zoom_step.to_bits()),
                AtomicU32::new(defaults.center_delay.to_bits()),
                AtomicU32::new(defaults.center_speed_degrees.to_bits()),
                AtomicU32::new(defaults.turn_speed_degrees.to_bits()),
            ],
        }
    }

    pub(super) fn publish(&self, config: ThirdPersonConfig) {
        self.sequence.fetch_add(1, Ordering::AcqRel);
        self.booleans
            .store(pack_booleans(config), Ordering::Relaxed);
        for (target, value) in self.values.iter().zip([
            config.follow_speed,
            config.soft_zone,
            config.look_ahead,
            config.zoom_step,
            config.center_delay,
            config.center_speed_degrees,
            config.turn_speed_degrees,
        ]) {
            target.store(value.to_bits(), Ordering::Relaxed);
        }
        self.sequence.fetch_add(1, Ordering::Release);
    }

    pub(super) fn load(&self) -> ThirdPersonConfig {
        loop {
            let before = self.begin_read();
            let booleans = self.booleans.load(Ordering::Relaxed);
            let values = self
                .values
                .each_ref()
                .map(|value| f32::from_bits(value.load(Ordering::Relaxed)));
            if before == self.sequence.load(Ordering::Acquire) {
                return ThirdPersonConfig {
                    follow_enabled: booleans & 1 != 0,
                    auto_center: booleans & 2 != 0,
                    movement_enabled: booleans & 4 != 0,
                    drawn_360: booleans & 8 != 0,
                    follow_speed: values[0],
                    soft_zone: values[1],
                    look_ahead: values[2],
                    zoom_step: values[3],
                    center_delay: values[4],
                    center_speed_degrees: values[5],
                    turn_speed_degrees: values[6],
                };
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

const fn pack_booleans(config: ThirdPersonConfig) -> u32 {
    config.follow_enabled as u32
        | ((config.auto_center as u32) << 1)
        | ((config.movement_enabled as u32) << 2)
        | ((config.drawn_360 as u32) << 3)
}
