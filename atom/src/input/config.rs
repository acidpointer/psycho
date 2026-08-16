//! MCM-owned Atom Input configuration.
//!
//! MCM Extender is the sole writer of `Data/config/Atom/Atom.ini`. Atom uses
//! `serini` and Serde to deserialize recognized sections, then validates and
//! sanitizes the typed result. It never serializes the value back to disk, so
//! unknown fields remain owned by MCM Extender and future Atom versions.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

use serde::Deserialize;
use thiserror::Error;

use super::controller::ControllerSettings;
use super::mouse::{MouseProfile, MouseProfileError, MouseSettings};

/// Complete user configuration consumed by the Atom Input hot path.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct InputConfig {
    enabled: bool,
    mouse: MouseSettings,
    controller: ControllerSettings,
    telemetry_enabled: bool,
    summary_requested: bool,
}

impl InputConfig {
    const DEFAULT: Self = Self {
        enabled: false,
        mouse: MouseSettings::DEFAULT,
        controller: ControllerSettings::DEFAULT,
        telemetry_enabled: false,
        summary_requested: false,
    };

    /// Deserialize MCM Extender's INI representation and apply safe bounds.
    ///
    /// Unknown sections and keys are accepted by Serde's default behavior.
    /// Recognized boolean fields remain numeric because MCM Extender writes
    /// `0` and `1`, whereas Serde INI backends normally expect textual booleans.
    pub fn from_ini(text: &str) -> Result<Self, ConfigError> {
        let persisted: PersistedConfig = serini::from_str(text)?;
        persisted.try_into()
    }

    /// Return whether Atom's player input bridges are enabled.
    #[inline]
    pub const fn enabled(self) -> bool {
        self.enabled
    }

    /// Return the sanitized mouse settings.
    #[inline]
    pub const fn mouse(self) -> MouseSettings {
        self.mouse
    }

    /// Return the sanitized controller processing settings.
    #[inline]
    pub const fn controller(self) -> ControllerSettings {
        self.controller
    }

    /// Return whether bounded QPC telemetry is enabled.
    #[inline]
    pub const fn telemetry_enabled(self) -> bool {
        self.telemetry_enabled
    }

    /// Return whether MCM requested an out-of-hot-path telemetry report.
    #[inline]
    pub const fn summary_requested(self) -> bool {
        self.summary_requested
    }
}

impl Default for InputConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Typed configuration load failure.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The INI document could not be deserialized into Atom's section model.
    #[error("could not deserialize Atom.ini: {0}")]
    Deserialize(#[from] serini::Error),
    /// MCM's numeric boolean contract was violated.
    #[error("{field} must be 0 or 1, found {value}")]
    InvalidBoolean { field: &'static str, value: u8 },
    /// The persisted mouse profile does not name a supported transform.
    #[error("Mouse:iProfile is invalid: {0}")]
    InvalidMouseProfile(#[from] MouseProfileError),
    /// A recognized floating-point setting was NaN or infinite.
    #[error("{field} must be finite, found {value}")]
    NonFinite { field: &'static str, value: f32 },
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PersistedConfig {
    #[serde(rename = "Input")]
    input: InputSection,
    #[serde(rename = "Mouse")]
    mouse: MouseSection,
    #[serde(rename = "Controller")]
    controller: ControllerSection,
    #[serde(rename = "Diagnostics")]
    diagnostics: DiagnosticsSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct InputSection {
    #[serde(rename = "bEnabled")]
    enabled: u8,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct MouseSection {
    #[serde(rename = "iProfile")]
    profile: u8,
    #[serde(rename = "fSensitivity")]
    sensitivity: f32,
    #[serde(rename = "fHorizontalScale")]
    horizontal_scale: f32,
    #[serde(rename = "fVerticalScale")]
    vertical_scale: f32,
    #[serde(rename = "bInvertX")]
    invert_x: u8,
    #[serde(rename = "bInvertY")]
    invert_y: u8,
}

impl Default for MouseSection {
    fn default() -> Self {
        let defaults = MouseSettings::DEFAULT;
        Self {
            profile: defaults.profile as u8,
            sensitivity: defaults.sensitivity,
            horizontal_scale: defaults.horizontal_scale,
            vertical_scale: defaults.vertical_scale,
            invert_x: u8::from(defaults.invert_x),
            invert_y: u8::from(defaults.invert_y),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct ControllerSection {
    #[serde(rename = "fLeftDeadzone")]
    left_deadzone: f32,
    #[serde(rename = "fRightDeadzone")]
    right_deadzone: f32,
    #[serde(rename = "fResponseExponent")]
    response_exponent: f32,
    #[serde(rename = "fAntiDeadzone")]
    anti_deadzone: f32,
    #[serde(rename = "fOutputSaturation")]
    output_saturation: f32,
    #[serde(rename = "fRightHorizontalScale")]
    right_horizontal_scale: f32,
    #[serde(rename = "fRightVerticalScale")]
    right_vertical_scale: f32,
    #[serde(rename = "bInvertRightX")]
    invert_right_x: u8,
    #[serde(rename = "bInvertRightY")]
    invert_right_y: u8,
    #[serde(rename = "fTriggerPress")]
    trigger_press: f32,
    #[serde(rename = "fTriggerRelease")]
    trigger_release: f32,
}

impl Default for ControllerSection {
    fn default() -> Self {
        let defaults = ControllerSettings::DEFAULT;
        Self {
            left_deadzone: defaults.left_deadzone,
            right_deadzone: defaults.right_deadzone,
            response_exponent: defaults.response_exponent,
            anti_deadzone: defaults.anti_deadzone,
            output_saturation: defaults.output_saturation,
            right_horizontal_scale: defaults.right_horizontal_scale,
            right_vertical_scale: defaults.right_vertical_scale,
            invert_right_x: u8::from(defaults.invert_right_x),
            invert_right_y: u8::from(defaults.invert_right_y),
            trigger_press: defaults.trigger_press,
            trigger_release: defaults.trigger_release,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct DiagnosticsSection {
    #[serde(rename = "bTelemetry")]
    telemetry: u8,
    #[serde(rename = "bWriteSummary")]
    write_summary: u8,
}

impl TryFrom<PersistedConfig> for InputConfig {
    type Error = ConfigError;

    fn try_from(value: PersistedConfig) -> Result<Self, Self::Error> {
        validate_finite("Mouse:fSensitivity", value.mouse.sensitivity)?;
        validate_finite("Mouse:fHorizontalScale", value.mouse.horizontal_scale)?;
        validate_finite("Mouse:fVerticalScale", value.mouse.vertical_scale)?;
        validate_finite("Controller:fLeftDeadzone", value.controller.left_deadzone)?;
        validate_finite("Controller:fRightDeadzone", value.controller.right_deadzone)?;
        validate_finite(
            "Controller:fResponseExponent",
            value.controller.response_exponent,
        )?;
        validate_finite("Controller:fAntiDeadzone", value.controller.anti_deadzone)?;
        validate_finite(
            "Controller:fOutputSaturation",
            value.controller.output_saturation,
        )?;
        validate_finite(
            "Controller:fRightHorizontalScale",
            value.controller.right_horizontal_scale,
        )?;
        validate_finite(
            "Controller:fRightVerticalScale",
            value.controller.right_vertical_scale,
        )?;
        validate_finite("Controller:fTriggerPress", value.controller.trigger_press)?;
        validate_finite(
            "Controller:fTriggerRelease",
            value.controller.trigger_release,
        )?;

        let profile = MouseProfile::try_from(value.mouse.profile)?;
        let mut config = Self {
            enabled: numeric_bool("Input:bEnabled", value.input.enabled)?,
            mouse: MouseSettings {
                profile,
                sensitivity: value.mouse.sensitivity,
                horizontal_scale: value.mouse.horizontal_scale,
                vertical_scale: value.mouse.vertical_scale,
                invert_x: numeric_bool("Mouse:bInvertX", value.mouse.invert_x)?,
                invert_y: numeric_bool("Mouse:bInvertY", value.mouse.invert_y)?,
            },
            controller: ControllerSettings {
                left_deadzone: value.controller.left_deadzone,
                right_deadzone: value.controller.right_deadzone,
                response_exponent: value.controller.response_exponent,
                anti_deadzone: value.controller.anti_deadzone,
                output_saturation: value.controller.output_saturation,
                right_horizontal_scale: value.controller.right_horizontal_scale,
                right_vertical_scale: value.controller.right_vertical_scale,
                invert_right_x: numeric_bool(
                    "Controller:bInvertRightX",
                    value.controller.invert_right_x,
                )?,
                invert_right_y: numeric_bool(
                    "Controller:bInvertRightY",
                    value.controller.invert_right_y,
                )?,
                trigger_press: value.controller.trigger_press,
                trigger_release: value.controller.trigger_release,
            },
            telemetry_enabled: numeric_bool("Diagnostics:bTelemetry", value.diagnostics.telemetry)?,
            summary_requested: numeric_bool(
                "Diagnostics:bWriteSummary",
                value.diagnostics.write_summary,
            )?,
        };
        config.mouse = config.mouse.sanitized();
        config.controller = config.controller.sanitized();
        Ok(config)
    }
}

fn numeric_bool(field: &'static str, value: u8) -> Result<bool, ConfigError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(ConfigError::InvalidBoolean { field, value }),
    }
}

fn validate_finite(field: &'static str, value: f32) -> Result<(), ConfigError> {
    if value.is_finite() {
        Ok(())
    } else {
        Err(ConfigError::NonFinite { field, value })
    }
}

/// Lock-free coherent storage for the live configuration.
///
/// Every payload field is atomic, so the sequence protocol establishes a
/// coherent multi-field snapshot without creating a Rust data race. MCM writes
/// are rare and run on the game thread; native hooks perform only atomic loads.
pub(crate) struct ConfigStore {
    sequence: AtomicU32,
    enabled: AtomicBool,
    mouse_profile: AtomicU8,
    mouse_sensitivity: AtomicU32,
    mouse_horizontal: AtomicU32,
    mouse_vertical: AtomicU32,
    mouse_invert_x: AtomicBool,
    mouse_invert_y: AtomicBool,
    controller_left_deadzone: AtomicU32,
    controller_right_deadzone: AtomicU32,
    controller_exponent: AtomicU32,
    controller_anti_deadzone: AtomicU32,
    controller_saturation: AtomicU32,
    controller_right_horizontal: AtomicU32,
    controller_right_vertical: AtomicU32,
    controller_invert_right_x: AtomicBool,
    controller_invert_right_y: AtomicBool,
    controller_trigger_press: AtomicU32,
    controller_trigger_release: AtomicU32,
    telemetry_enabled: AtomicBool,
    summary_requested: AtomicBool,
}

impl ConfigStore {
    pub(crate) const fn new() -> Self {
        let defaults = InputConfig::DEFAULT;
        Self {
            sequence: AtomicU32::new(0),
            enabled: AtomicBool::new(defaults.enabled),
            mouse_profile: AtomicU8::new(defaults.mouse.profile as u8),
            mouse_sensitivity: AtomicU32::new(defaults.mouse.sensitivity.to_bits()),
            mouse_horizontal: AtomicU32::new(defaults.mouse.horizontal_scale.to_bits()),
            mouse_vertical: AtomicU32::new(defaults.mouse.vertical_scale.to_bits()),
            mouse_invert_x: AtomicBool::new(defaults.mouse.invert_x),
            mouse_invert_y: AtomicBool::new(defaults.mouse.invert_y),
            controller_left_deadzone: AtomicU32::new(defaults.controller.left_deadzone.to_bits()),
            controller_right_deadzone: AtomicU32::new(defaults.controller.right_deadzone.to_bits()),
            controller_exponent: AtomicU32::new(defaults.controller.response_exponent.to_bits()),
            controller_anti_deadzone: AtomicU32::new(defaults.controller.anti_deadzone.to_bits()),
            controller_saturation: AtomicU32::new(defaults.controller.output_saturation.to_bits()),
            controller_right_horizontal: AtomicU32::new(
                defaults.controller.right_horizontal_scale.to_bits(),
            ),
            controller_right_vertical: AtomicU32::new(
                defaults.controller.right_vertical_scale.to_bits(),
            ),
            controller_invert_right_x: AtomicBool::new(defaults.controller.invert_right_x),
            controller_invert_right_y: AtomicBool::new(defaults.controller.invert_right_y),
            controller_trigger_press: AtomicU32::new(defaults.controller.trigger_press.to_bits()),
            controller_trigger_release: AtomicU32::new(
                defaults.controller.trigger_release.to_bits(),
            ),
            telemetry_enabled: AtomicBool::new(defaults.telemetry_enabled),
            summary_requested: AtomicBool::new(defaults.summary_requested),
        }
    }

    pub(crate) fn publish(&self, config: InputConfig) {
        self.sequence.fetch_add(1, Ordering::AcqRel);
        self.enabled.store(config.enabled, Ordering::Relaxed);
        self.mouse_profile
            .store(config.mouse.profile as u8, Ordering::Relaxed);
        store_f32(&self.mouse_sensitivity, config.mouse.sensitivity);
        store_f32(&self.mouse_horizontal, config.mouse.horizontal_scale);
        store_f32(&self.mouse_vertical, config.mouse.vertical_scale);
        self.mouse_invert_x
            .store(config.mouse.invert_x, Ordering::Relaxed);
        self.mouse_invert_y
            .store(config.mouse.invert_y, Ordering::Relaxed);
        store_f32(
            &self.controller_left_deadzone,
            config.controller.left_deadzone,
        );
        store_f32(
            &self.controller_right_deadzone,
            config.controller.right_deadzone,
        );
        store_f32(
            &self.controller_exponent,
            config.controller.response_exponent,
        );
        store_f32(
            &self.controller_anti_deadzone,
            config.controller.anti_deadzone,
        );
        store_f32(
            &self.controller_saturation,
            config.controller.output_saturation,
        );
        store_f32(
            &self.controller_right_horizontal,
            config.controller.right_horizontal_scale,
        );
        store_f32(
            &self.controller_right_vertical,
            config.controller.right_vertical_scale,
        );
        self.controller_invert_right_x
            .store(config.controller.invert_right_x, Ordering::Relaxed);
        self.controller_invert_right_y
            .store(config.controller.invert_right_y, Ordering::Relaxed);
        store_f32(
            &self.controller_trigger_press,
            config.controller.trigger_press,
        );
        store_f32(
            &self.controller_trigger_release,
            config.controller.trigger_release,
        );
        self.telemetry_enabled
            .store(config.telemetry_enabled, Ordering::Relaxed);
        self.summary_requested
            .store(config.summary_requested, Ordering::Relaxed);
        self.sequence.fetch_add(1, Ordering::Release);
    }

    #[inline]
    pub(crate) fn load(&self) -> InputConfig {
        loop {
            let before = self.begin_read();

            let config = InputConfig {
                enabled: self.enabled.load(Ordering::Relaxed),
                mouse: MouseSettings {
                    profile: MouseProfile::try_from(self.mouse_profile.load(Ordering::Relaxed))
                        .unwrap_or(MouseProfile::Native),
                    sensitivity: load_f32(&self.mouse_sensitivity),
                    horizontal_scale: load_f32(&self.mouse_horizontal),
                    vertical_scale: load_f32(&self.mouse_vertical),
                    invert_x: self.mouse_invert_x.load(Ordering::Relaxed),
                    invert_y: self.mouse_invert_y.load(Ordering::Relaxed),
                },
                controller: ControllerSettings {
                    left_deadzone: load_f32(&self.controller_left_deadzone),
                    right_deadzone: load_f32(&self.controller_right_deadzone),
                    response_exponent: load_f32(&self.controller_exponent),
                    anti_deadzone: load_f32(&self.controller_anti_deadzone),
                    output_saturation: load_f32(&self.controller_saturation),
                    right_horizontal_scale: load_f32(&self.controller_right_horizontal),
                    right_vertical_scale: load_f32(&self.controller_right_vertical),
                    invert_right_x: self.controller_invert_right_x.load(Ordering::Relaxed),
                    invert_right_y: self.controller_invert_right_y.load(Ordering::Relaxed),
                    trigger_press: load_f32(&self.controller_trigger_press),
                    trigger_release: load_f32(&self.controller_trigger_release),
                },
                telemetry_enabled: self.telemetry_enabled.load(Ordering::Relaxed),
                summary_requested: self.summary_requested.load(Ordering::Relaxed),
            };

            if before == self.sequence.load(Ordering::Acquire) {
                return config;
            }
        }
    }

    #[inline]
    pub(crate) fn load_mouse(&self) -> (bool, MouseSettings) {
        loop {
            let before = self.begin_read();
            let enabled = self.enabled.load(Ordering::Relaxed);
            let mouse = MouseSettings {
                profile: MouseProfile::try_from(self.mouse_profile.load(Ordering::Relaxed))
                    .unwrap_or(MouseProfile::Native),
                sensitivity: load_f32(&self.mouse_sensitivity),
                horizontal_scale: load_f32(&self.mouse_horizontal),
                vertical_scale: load_f32(&self.mouse_vertical),
                invert_x: self.mouse_invert_x.load(Ordering::Relaxed),
                invert_y: self.mouse_invert_y.load(Ordering::Relaxed),
            };
            if before == self.sequence.load(Ordering::Acquire) {
                return (enabled, mouse);
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

fn store_f32(target: &AtomicU32, value: f32) {
    target.store(value.to_bits(), Ordering::Relaxed);
}

fn load_f32(source: &AtomicU32) -> f32 {
    f32::from_bits(source.load(Ordering::Relaxed))
}
