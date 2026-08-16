//! Stateless stick shaping and stateful trigger hysteresis.
//!
//! Processing starts from the post-xNVSE XInput snapshot. Atom publishes the
//! shaped state into FNV's current controller slot only after a neutral
//! handoff. Focused camera callsite adapters then bypass FNV's later axial
//! deadzone, exponent, and minimum-speed terms, so two incompatible transfer
//! functions are never composed.

use core::sync::atomic::{AtomicBool, Ordering};

/// Sanitized controller processing values.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ControllerSettings {
    pub(crate) left_deadzone: f32,
    pub(crate) right_deadzone: f32,
    pub(crate) response_exponent: f32,
    pub(crate) anti_deadzone: f32,
    pub(crate) output_saturation: f32,
    pub(crate) right_horizontal_scale: f32,
    pub(crate) right_vertical_scale: f32,
    pub(crate) invert_right_x: bool,
    pub(crate) invert_right_y: bool,
    pub(crate) trigger_press: f32,
    pub(crate) trigger_release: f32,
}

impl ControllerSettings {
    pub(crate) const DEFAULT: Self = Self {
        left_deadzone: 0.15,
        right_deadzone: 0.12,
        response_exponent: 1.0,
        anti_deadzone: 0.0,
        output_saturation: 1.0,
        right_horizontal_scale: 1.0,
        right_vertical_scale: 1.0,
        invert_right_x: false,
        invert_right_y: false,
        trigger_press: 0.12,
        trigger_release: 0.08,
    };

    /// Return the radial left-stick deadzone in normalized units.
    pub const fn left_deadzone(self) -> f32 {
        self.left_deadzone
    }

    /// Return the radial right-stick deadzone in normalized units.
    pub const fn right_deadzone(self) -> f32 {
        self.right_deadzone
    }

    /// Return the monotonic post-deadzone response exponent.
    pub const fn response_exponent(self) -> f32 {
        self.response_exponent
    }

    /// Return the post-deadzone minimum output magnitude.
    pub const fn anti_deadzone(self) -> f32 {
        self.anti_deadzone
    }

    /// Return the input magnitude at which output reaches full scale.
    pub const fn output_saturation(self) -> f32 {
        self.output_saturation
    }

    /// Return the right-stick horizontal multiplier.
    pub const fn right_horizontal_scale(self) -> f32 {
        self.right_horizontal_scale
    }

    /// Return the right-stick vertical multiplier.
    pub const fn right_vertical_scale(self) -> f32 {
        self.right_vertical_scale
    }

    /// Return whether the processed right-stick X axis is inverted.
    pub const fn invert_right_x(self) -> bool {
        self.invert_right_x
    }

    /// Return whether the processed right-stick Y axis is inverted.
    pub const fn invert_right_y(self) -> bool {
        self.invert_right_y
    }

    /// Return the trigger press threshold in normalized units.
    pub const fn trigger_press(self) -> f32 {
        self.trigger_press
    }

    /// Return the trigger release threshold in normalized units.
    pub const fn trigger_release(self) -> f32 {
        self.trigger_release
    }

    pub(crate) fn sanitized(mut self) -> Self {
        self.left_deadzone = finite_or(self.left_deadzone, 0.15).clamp(0.0, 0.95);
        self.right_deadzone = finite_or(self.right_deadzone, 0.12).clamp(0.0, 0.95);
        self.response_exponent = finite_or(self.response_exponent, 1.0).clamp(0.25, 4.0);
        self.anti_deadzone = finite_or(self.anti_deadzone, 0.0).clamp(0.0, 0.75);
        self.output_saturation = finite_or(self.output_saturation, 1.0).clamp(0.25, 1.0);
        self.right_horizontal_scale = finite_or(self.right_horizontal_scale, 1.0).clamp(0.1, 4.0);
        self.right_vertical_scale = finite_or(self.right_vertical_scale, 1.0).clamp(0.1, 4.0);
        self.trigger_press = finite_or(self.trigger_press, 0.12).clamp(0.01, 1.0);
        self.trigger_release =
            finite_or(self.trigger_release, 0.08).clamp(0.0, (self.trigger_press - 0.01).max(0.0));
        self
    }
}

impl Default for ControllerSettings {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Raw XInput gamepad payload captured by FNV's native sampler.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct NativeControllerState {
    packet_number: u32,
    buttons: u16,
    left_trigger: u8,
    right_trigger: u8,
    left_x: i16,
    left_y: i16,
    right_x: i16,
    right_y: i16,
}

impl NativeControllerState {
    /// Construct a raw state for deterministic replay and adapter code.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        packet_number: u32,
        buttons: u16,
        left_trigger: u8,
        right_trigger: u8,
        left_x: i16,
        left_y: i16,
        right_x: i16,
        right_y: i16,
    ) -> Self {
        Self {
            packet_number,
            buttons,
            left_trigger,
            right_trigger,
            left_x,
            left_y,
            right_x,
            right_y,
        }
    }

    /// Return XInput's packet sequence number.
    pub const fn packet_number(self) -> u32 {
        self.packet_number
    }

    /// Return XInput's digital button mask.
    pub const fn buttons(self) -> u16 {
        self.buttons
    }

    /// Return the raw left-trigger value.
    pub const fn left_trigger(self) -> u8 {
        self.left_trigger
    }

    /// Return the raw right-trigger value.
    pub const fn right_trigger(self) -> u8 {
        self.right_trigger
    }

    /// Return the raw left-stick X axis.
    pub const fn left_x(self) -> i16 {
        self.left_x
    }

    /// Return the raw left-stick Y axis.
    pub const fn left_y(self) -> i16 {
        self.left_y
    }

    /// Return the raw right-stick X axis.
    pub const fn right_x(self) -> i16 {
        self.right_x
    }

    /// Return the raw right-stick Y axis.
    pub const fn right_y(self) -> i16 {
        self.right_y
    }

    /// Return whether every gameplay control is physically neutral.
    pub const fn is_neutral(self) -> bool {
        self.buttons == 0
            && self.left_trigger == 0
            && self.right_trigger == 0
            && self.left_x == 0
            && self.left_y == 0
            && self.right_x == 0
            && self.right_y == 0
    }

    pub(crate) fn encode_words(self) -> [u32; 4] {
        [
            self.packet_number,
            u32::from(self.buttons)
                | (u32::from(self.left_trigger) << 16)
                | (u32::from(self.right_trigger) << 24),
            u32::from(self.left_x as u16) | (u32::from(self.left_y as u16) << 16),
            u32::from(self.right_x as u16) | (u32::from(self.right_y as u16) << 16),
        ]
    }

    pub(crate) const fn decode_words(words: [u32; 4]) -> Self {
        Self {
            packet_number: words[0],
            buttons: words[1] as u16,
            left_trigger: (words[1] >> 16) as u8,
            right_trigger: (words[1] >> 24) as u8,
            left_x: words[2] as u16 as i16,
            left_y: (words[2] >> 16) as u16 as i16,
            right_x: words[3] as u16 as i16,
            right_y: (words[3] >> 16) as u16 as i16,
        }
    }
}

/// Direction-preserving normalized stick output.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct StickVector {
    x: f32,
    y: f32,
}

impl StickVector {
    pub(crate) const fn new(x: f32, y: f32) -> Self {
        Self { x, y }
    }

    /// Return the horizontal component in `[-1, 1]`.
    pub const fn x(self) -> f32 {
        self.x
    }

    /// Return the vertical component in `[-1, 1]`.
    pub const fn y(self) -> f32 {
        self.y
    }

    /// Return the normalized vector magnitude.
    pub fn magnitude(self) -> f32 {
        self.x.hypot(self.y)
    }
}

/// One trigger's normalized value and hysteretic digital transitions.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct TriggerFrame {
    value: f32,
    down: bool,
    pressed: bool,
    released: bool,
}

impl TriggerFrame {
    pub(crate) const fn from_parts(value: f32, down: bool, pressed: bool, released: bool) -> Self {
        Self {
            value,
            down,
            pressed,
            released,
        }
    }

    /// Return the normalized analog value in `[0, 1]`.
    pub const fn value(self) -> f32 {
        self.value
    }

    /// Return the hysteretic digital state.
    pub const fn down(self) -> bool {
        self.down
    }

    /// Return whether this update crossed the press threshold.
    pub const fn pressed(self) -> bool {
        self.pressed
    }

    /// Return whether this update crossed the release threshold.
    pub const fn released(self) -> bool {
        self.released
    }
}

/// Processed controller state associated with one native sample.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ControllerFrame {
    raw: NativeControllerState,
    left_stick: StickVector,
    right_stick: StickVector,
    left_trigger: TriggerFrame,
    right_trigger: TriggerFrame,
}

impl ControllerFrame {
    /// Return the unmodified post-xNVSE XInput state.
    pub const fn raw(self) -> NativeControllerState {
        self.raw
    }

    /// Return the radially processed left stick.
    pub const fn left_stick(self) -> StickVector {
        self.left_stick
    }

    /// Return the radially processed right stick.
    pub const fn right_stick(self) -> StickVector {
        self.right_stick
    }

    /// Return the left trigger result.
    pub const fn left_trigger(self) -> TriggerFrame {
        self.left_trigger
    }

    /// Return the right trigger result.
    pub const fn right_trigger(self) -> TriggerFrame {
        self.right_trigger
    }

    /// Build the XInput state Atom publishes to FNV-owned consumers.
    ///
    /// Buttons and packet identity remain untouched. Sticks use the processed
    /// radial vectors, while triggers become zero only outside their
    /// hysteretic active range. Retaining the physical trigger magnitude while
    /// active preserves analog information for consumers that use it directly.
    pub fn native_output(self) -> NativeControllerState {
        NativeControllerState {
            packet_number: self.raw.packet_number,
            buttons: self.raw.buttons,
            left_trigger: if self.left_trigger.down {
                self.raw.left_trigger.max(1)
            } else {
                0
            },
            right_trigger: if self.right_trigger.down {
                self.raw.right_trigger.max(1)
            } else {
                0
            },
            left_x: encode_axis(self.left_stick.x),
            left_y: encode_axis(self.left_stick.y),
            right_x: encode_axis(self.right_stick.x),
            right_y: encode_axis(self.right_stick.y),
        }
    }

    pub(crate) const fn from_parts(
        raw: NativeControllerState,
        left_stick: StickVector,
        right_stick: StickVector,
        left_trigger: TriggerFrame,
        right_trigger: TriggerFrame,
    ) -> Self {
        Self {
            raw,
            left_stick,
            right_stick,
            left_trigger,
            right_trigger,
        }
    }
}

/// Stateful controller processor whose only history is trigger hysteresis.
pub struct ControllerProcessor {
    left_trigger_down: AtomicBool,
    right_trigger_down: AtomicBool,
}

impl ControllerProcessor {
    /// Construct a neutral controller processor without allocating.
    pub const fn new() -> Self {
        Self {
            left_trigger_down: AtomicBool::new(false),
            right_trigger_down: AtomicBool::new(false),
        }
    }

    /// Process one native controller state using radial, monotonic transforms.
    pub fn process(
        &self,
        raw: NativeControllerState,
        settings: ControllerSettings,
    ) -> ControllerFrame {
        let left_stick = process_stick(
            raw.left_x,
            raw.left_y,
            settings.left_deadzone,
            settings,
            1.0,
            1.0,
        );
        let right_stick = process_stick(
            raw.right_x,
            raw.right_y,
            settings.right_deadzone,
            settings,
            signed_scale(settings.right_horizontal_scale, settings.invert_right_x),
            signed_scale(settings.right_vertical_scale, settings.invert_right_y),
        );
        let left_trigger = process_trigger(
            &self.left_trigger_down,
            raw.left_trigger,
            settings.trigger_press,
            settings.trigger_release,
        );
        let right_trigger = process_trigger(
            &self.right_trigger_down,
            raw.right_trigger,
            settings.trigger_press,
            settings.trigger_release,
        );

        ControllerFrame {
            raw,
            left_stick,
            right_stick,
            left_trigger,
            right_trigger,
        }
    }

    /// Reset hysteretic digital state without emitting transitions.
    pub fn reset(&self) {
        self.left_trigger_down.store(false, Ordering::Release);
        self.right_trigger_down.store(false, Ordering::Release);
    }
}

impl Default for ControllerProcessor {
    fn default() -> Self {
        Self::new()
    }
}

fn process_stick(
    raw_x: i16,
    raw_y: i16,
    deadzone: f32,
    settings: ControllerSettings,
    x_scale: f32,
    y_scale: f32,
) -> StickVector {
    let x = normalize_axis(raw_x);
    let y = normalize_axis(raw_y);
    let magnitude = x.hypot(y).min(1.0);
    if magnitude <= deadzone || magnitude == 0.0 {
        return StickVector::default();
    }

    let direction_x = x / magnitude;
    let direction_y = y / magnitude;
    let rescaled = ((magnitude - deadzone) / (1.0 - deadzone)).clamp(0.0, 1.0);
    let curved = rescaled.powf(settings.response_exponent);
    let saturated = (curved / settings.output_saturation).min(1.0);
    let output = settings.anti_deadzone + (1.0 - settings.anti_deadzone) * saturated;

    StickVector {
        x: (direction_x * output * x_scale).clamp(-1.0, 1.0),
        y: (direction_y * output * y_scale).clamp(-1.0, 1.0),
    }
}

fn process_trigger(
    state: &AtomicBool,
    raw: u8,
    press_threshold: f32,
    release_threshold: f32,
) -> TriggerFrame {
    let value = f32::from(raw) / f32::from(u8::MAX);
    let was_down = state.load(Ordering::Acquire);
    let down = if was_down {
        value > release_threshold
    } else {
        value >= press_threshold
    };
    state.store(down, Ordering::Release);

    TriggerFrame {
        value,
        down,
        pressed: !was_down && down,
        released: was_down && !down,
    }
}

fn normalize_axis(value: i16) -> f32 {
    if value >= 0 {
        f32::from(value) / f32::from(i16::MAX)
    } else {
        f32::from(value) / 32_768.0
    }
}

fn encode_axis(value: f32) -> i16 {
    let value = finite_or(value, 0.0).clamp(-1.0, 1.0);
    let scale = if value >= 0.0 {
        f32::from(i16::MAX)
    } else {
        32_768.0
    };
    (value * scale).round() as i16
}

fn signed_scale(scale: f32, inverted: bool) -> f32 {
    if inverted { -scale } else { scale }
}

fn finite_or(value: f32, fallback: f32) -> f32 {
    if value.is_finite() { value } else { fallback }
}
