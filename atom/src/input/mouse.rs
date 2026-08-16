//! Deterministic player-camera mouse transformation.
//!
//! Relative mouse counts already describe motion accumulated by DirectInput.
//! The transform therefore never multiplies by frame time and carries no
//! history. Runtime integration observes counts at the two proven mouse getter
//! calls and applies the final transform at the later float heading consumers.
//! This preserves sub-count precision: a low angular scale never rounds a
//! one-count movement to zero merely because FNV's getter ABI uses integers.
//! Menu cursor, console, fly camera, and the native input snapshot remain
//! untouched.

use thiserror::Error;

/// Fallout 4's shipped PC heading scale in radians per relative mouse count.
///
/// The supplied GOG installation defines a heading sensitivity of `0.0300`
/// and equal X/Y scales of `0.021`. Their product is `0.00063`. Atom treats
/// this as the preset's calibrated nominal transfer, not as a claim that the
/// two engines have identical camera, FOV, or presentation pipelines.
pub const FALLOUT4_RADIANS_PER_COUNT: f32 = 0.000_63;

/// Player-camera mouse behavior selected through MCM Extender.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MouseProfile {
    /// Preserve the predecessor's result bit-for-bit.
    Native = 0,
    /// Apply a direct, no-history scale in native count space.
    Direct = 1,
    /// Apply Atom's Fallout 4-inspired direct profile.
    ///
    /// The profile intentionally does not claim exact Fallout 4 calibration;
    /// both games still require raw-count-to-angle runtime measurement.
    Fallout4Direct = 2,
}

impl TryFrom<u8> for MouseProfile {
    type Error = MouseProfileError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Native),
            1 => Ok(Self::Direct),
            2 => Ok(Self::Fallout4Direct),
            _ => Err(MouseProfileError { value }),
        }
    }
}

/// Persisted value does not identify an Atom mouse profile.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("mouse profile must be 0, 1, or 2, found {value}")]
pub struct MouseProfileError {
    value: u8,
}

impl MouseProfileError {
    /// Return the rejected persisted value.
    pub const fn value(self) -> u8 {
        self.value
    }
}

/// Sanitized mouse values read from MCM Extender's INI.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MouseSettings {
    pub(crate) profile: MouseProfile,
    pub(crate) sensitivity: f32,
    pub(crate) horizontal_scale: f32,
    pub(crate) vertical_scale: f32,
    pub(crate) invert_x: bool,
    pub(crate) invert_y: bool,
}

impl MouseSettings {
    pub(crate) const DEFAULT: Self = Self {
        profile: MouseProfile::Fallout4Direct,
        sensitivity: 1.0,
        horizontal_scale: 1.0,
        vertical_scale: 1.0,
        invert_x: false,
        invert_y: false,
    };

    /// Return the selected profile.
    pub const fn profile(self) -> MouseProfile {
        self.profile
    }

    /// Return the bounded base sensitivity multiplier.
    pub const fn sensitivity(self) -> f32 {
        self.sensitivity
    }

    /// Return the bounded horizontal multiplier.
    pub const fn horizontal_scale(self) -> f32 {
        self.horizontal_scale
    }

    /// Return the bounded vertical multiplier.
    pub const fn vertical_scale(self) -> f32 {
        self.vertical_scale
    }

    /// Return whether the final player-camera X direction is inverted.
    pub const fn invert_x(self) -> bool {
        self.invert_x
    }

    /// Return whether the final player-camera Y direction is inverted.
    pub const fn invert_y(self) -> bool {
        self.invert_y
    }

    pub(crate) fn sanitized(mut self) -> Self {
        self.sensitivity = finite_or(self.sensitivity, 1.0).clamp(0.05, 8.0);
        self.horizontal_scale = finite_or(self.horizontal_scale, 1.0).clamp(0.1, 4.0);
        self.vertical_scale = finite_or(self.vertical_scale, 1.0).clamp(0.1, 4.0);
        self
    }
}

impl Default for MouseSettings {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Axis supplied to the native relative-mouse getter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MouseAxis {
    /// Horizontal relative counts.
    X,
    /// Vertical relative counts.
    Y,
}

/// Inputs available at FNV's final player-heading consumer.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MouseHeadingInput {
    axis: MouseAxis,
    source_delta: i32,
    native_heading: f32,
    native_y_inverted: bool,
}

impl MouseHeadingInput {
    /// Describe one native heading update and the relative count that caused it.
    pub const fn new(
        axis: MouseAxis,
        source_delta: i32,
        native_heading: f32,
        native_y_inverted: bool,
    ) -> Self {
        Self {
            axis,
            source_delta,
            native_heading,
            native_y_inverted,
        }
    }

    /// Return the heading axis.
    pub const fn axis(self) -> MouseAxis {
        self.axis
    }

    /// Return the post-chain relative mouse count.
    pub const fn source_delta(self) -> i32 {
        self.source_delta
    }

    /// Return FNV's heading value before Atom's final transform.
    pub const fn native_heading(self) -> f32 {
        self.native_heading
    }
}

/// Stateless direct mouse transform used by the native camera bridge.
#[derive(Clone, Copy, Debug)]
pub struct MouseTransform {
    settings: MouseSettings,
}

impl MouseTransform {
    /// Build a transform from already-sanitized settings.
    pub const fn new(settings: MouseSettings) -> Self {
        Self { settings }
    }

    /// Transform one signed relative delta without adding temporal history.
    ///
    /// `native_y_inverted` is the current vanilla `bInvertYValues` state. Atom
    /// compensates for the native inversion performed later in the camera
    /// function, which makes the MCM Y option authoritative instead of an
    /// accidental second inversion.
    pub fn apply(self, axis: MouseAxis, delta: i32, native_y_inverted: bool) -> i32 {
        if self.settings.profile == MouseProfile::Native {
            return delta;
        }

        let (axis_scale, invert_before_native) = match axis {
            MouseAxis::X => (self.settings.horizontal_scale, self.settings.invert_x),
            MouseAxis::Y => (
                self.settings.vertical_scale,
                self.settings.invert_y != native_y_inverted,
            ),
        };
        let direction = if invert_before_native { -1.0 } else { 1.0 };
        let scaled = delta as f32 * self.settings.sensitivity * axis_scale * direction;

        // Rust float-to-int conversion saturates, but spelling out the bounds
        // documents that pathological device/stall values cannot wrap through
        // the camera ABI.
        scaled.round().clamp(i32::MIN as f32, i32::MAX as f32) as i32
    }

    /// Transform one final player-heading value without temporal history.
    ///
    /// `Direct` scales FNV's already-computed heading and therefore retains
    /// native camera-context behavior. `Fallout4Direct` instead rebuilds the
    /// nominal heading from the observed relative count using Fallout 4's
    /// shipped PC sensitivity and axis scale. Applying the preset at this
    /// float boundary avoids integer quantization and removes undocumented
    /// FNV mouse-context multipliers from the nominal count-to-angle mapping.
    ///
    /// `Native` returns `native_heading` without arithmetic, including for
    /// non-finite values, because exact predecessor passthrough is its public
    /// compatibility contract.
    pub fn apply_heading(self, input: MouseHeadingInput) -> f32 {
        if self.settings.profile == MouseProfile::Native {
            return input.native_heading;
        }

        let axis_scale = match input.axis {
            MouseAxis::X => self.settings.horizontal_scale,
            MouseAxis::Y => self.settings.vertical_scale,
        };
        let inverted = match self.settings.profile {
            MouseProfile::Native => unreachable!("native profile returned above"),
            MouseProfile::Direct => match input.axis {
                MouseAxis::X => self.settings.invert_x,
                MouseAxis::Y => self.settings.invert_y != input.native_y_inverted,
            },
            MouseProfile::Fallout4Direct => match input.axis {
                MouseAxis::X => self.settings.invert_x,
                MouseAxis::Y => self.settings.invert_y,
            },
        };
        let direction = if inverted { -1.0 } else { 1.0 };
        let base = match self.settings.profile {
            MouseProfile::Native => unreachable!("native profile returned above"),
            MouseProfile::Direct => input.native_heading,
            MouseProfile::Fallout4Direct => input.source_delta as f32 * FALLOUT4_RADIANS_PER_COUNT,
        };
        let heading = base * self.settings.sensitivity * axis_scale * direction;
        if heading.is_finite() { heading } else { 0.0 }
    }
}

fn finite_or(value: f32, fallback: f32) -> f32 {
    if value.is_finite() { value } else { fallback }
}
