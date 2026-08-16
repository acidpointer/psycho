//! Coherent post-xNVSE input snapshots.
//!
//! The native sampler writes mutable DirectInput and XInput storage before
//! Atom captures it. Atom converts that storage into value types, derives
//! keyboard, mouse, and trigger edges, and publishes the result through an
//! atomic word store. Readers therefore cannot observe a Rust data race or a
//! frame assembled from two native samples, and the hook path never allocates
//! or takes a blocking lock.

use core::sync::atomic::{AtomicU32, Ordering};

use super::actions::{ActionFrame, ActionResolver};
use super::buffered::KeyboardEventBatch;
use super::controller::{
    ControllerFrame, ControllerProcessor, ControllerSettings, NativeControllerState, StickVector,
    TriggerFrame,
};

const KEYBOARD_BYTES: usize = 256;
const KEYBOARD_WORDS: usize = KEYBOARD_BYTES / u32::BITS as usize;
const CONTROL_COUNT: usize = 28;
const FRAME_WORDS: usize = 41;

/// DirectInput's `DIMOUSESTATE2` payload as captured by FNV.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct NativeMouseState {
    x: i32,
    y: i32,
    wheel: i32,
    buttons: [u8; 8],
}

impl NativeMouseState {
    /// Construct a native mouse state for deterministic replay and adapters.
    pub const fn new(x: i32, y: i32, wheel: i32, buttons: [u8; 8]) -> Self {
        Self {
            x,
            y,
            wheel,
            buttons,
        }
    }

    /// Return horizontal relative counts.
    pub const fn x(self) -> i32 {
        self.x
    }

    /// Return vertical relative counts.
    pub const fn y(self) -> i32 {
        self.y
    }

    /// Return wheel-relative counts.
    pub const fn wheel(self) -> i32 {
        self.wheel
    }

    /// Return DirectInput's eight raw button bytes.
    pub const fn buttons(self) -> [u8; 8] {
        self.buttons
    }
}

/// Complete native state read immediately after FNV's sampler returns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeInputState {
    keyboard_current: [u8; KEYBOARD_BYTES],
    keyboard_previous: [u8; KEYBOARD_BYTES],
    mouse_current: NativeMouseState,
    mouse_previous: NativeMouseState,
    controller_current: NativeControllerState,
    controller_previous: NativeControllerState,
    keyboard_bindings: [u8; CONTROL_COUNT],
    mouse_bindings: [u8; CONTROL_COUNT],
    controller_bindings: [u8; CONTROL_COUNT],
    controller_mode: bool,
    focused: bool,
    menu_mode: bool,
}

impl NativeInputState {
    /// Construct a native sample from the proven FNV storage regions.
    pub const fn new(
        keyboard_current: [u8; KEYBOARD_BYTES],
        keyboard_previous: [u8; KEYBOARD_BYTES],
        mouse_current: NativeMouseState,
        mouse_previous: NativeMouseState,
        controller_current: NativeControllerState,
    ) -> Self {
        Self {
            keyboard_current,
            keyboard_previous,
            mouse_current,
            mouse_previous,
            controller_current,
            controller_previous: NativeControllerState::new(0, 0, 0, 0, 0, 0, 0, 0),
            keyboard_bindings: [u8::MAX; CONTROL_COUNT],
            mouse_bindings: [u8::MAX; CONTROL_COUNT],
            controller_bindings: [u8::MAX; CONTROL_COUNT],
            controller_mode: false,
            focused: true,
            menu_mode: false,
        }
    }

    /// Construct the complete native contract captured from FNV.
    #[allow(clippy::too_many_arguments)]
    pub const fn from_engine(
        keyboard_current: [u8; KEYBOARD_BYTES],
        keyboard_previous: [u8; KEYBOARD_BYTES],
        mouse_current: NativeMouseState,
        mouse_previous: NativeMouseState,
        controller_current: NativeControllerState,
        controller_previous: NativeControllerState,
        keyboard_bindings: [u8; CONTROL_COUNT],
        mouse_bindings: [u8; CONTROL_COUNT],
        controller_bindings: [u8; CONTROL_COUNT],
        controller_mode: bool,
        focused: bool,
        menu_mode: bool,
    ) -> Self {
        Self {
            keyboard_current,
            keyboard_previous,
            mouse_current,
            mouse_previous,
            controller_current,
            controller_previous,
            keyboard_bindings,
            mouse_bindings,
            controller_bindings,
            controller_mode,
            focused,
            menu_mode,
        }
    }

    /// Return the current DirectInput keyboard bytes.
    pub const fn keyboard_current(&self) -> &[u8; KEYBOARD_BYTES] {
        &self.keyboard_current
    }

    /// Return the previous DirectInput keyboard bytes.
    pub const fn keyboard_previous(&self) -> &[u8; KEYBOARD_BYTES] {
        &self.keyboard_previous
    }

    /// Return the current native mouse state.
    pub const fn mouse_current(self) -> NativeMouseState {
        self.mouse_current
    }

    /// Return the previous native mouse state.
    pub const fn mouse_previous(self) -> NativeMouseState {
        self.mouse_previous
    }

    /// Return the current native controller state.
    pub const fn controller_current(self) -> NativeControllerState {
        self.controller_current
    }

    /// Return the preceding native controller state.
    pub const fn controller_previous(self) -> NativeControllerState {
        self.controller_previous
    }

    /// Return FNV's 28 keyboard bindings.
    pub const fn keyboard_bindings(&self) -> &[u8; CONTROL_COUNT] {
        &self.keyboard_bindings
    }

    /// Return FNV's 28 mouse bindings.
    pub const fn mouse_bindings(&self) -> &[u8; CONTROL_COUNT] {
        &self.mouse_bindings
    }

    /// Return FNV's 28 XInput bindings.
    pub const fn controller_bindings(&self) -> &[u8; CONTROL_COUNT] {
        &self.controller_bindings
    }

    /// Return FNV's current controller-presentation mode.
    pub const fn controller_mode(self) -> bool {
        self.controller_mode
    }

    /// Return whether the game input window owns foreground focus.
    pub const fn focused(self) -> bool {
        self.focused
    }

    /// Return whether FNV's authoritative menu-mode query is active.
    pub const fn menu_mode(self) -> bool {
        self.menu_mode
    }
}

/// Mouse deltas and snapshot-derived button edges for one native sample.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MouseFrame {
    x: i32,
    y: i32,
    wheel: i32,
    buttons_down: u8,
    buttons_pressed: u8,
    buttons_released: u8,
}

impl MouseFrame {
    /// Return horizontal relative counts without camera transformation.
    pub const fn x(self) -> i32 {
        self.x
    }

    /// Return vertical relative counts without camera transformation.
    pub const fn y(self) -> i32 {
        self.y
    }

    /// Return wheel-relative counts.
    pub const fn wheel(self) -> i32 {
        self.wheel
    }

    /// Return the current eight-button bit mask.
    pub const fn buttons_down(self) -> u8 {
        self.buttons_down
    }

    /// Return buttons whose DirectInput high bit rose in this sample.
    pub const fn buttons_pressed(self) -> u8 {
        self.buttons_pressed
    }

    /// Return buttons whose DirectInput high bit fell in this sample.
    pub const fn buttons_released(self) -> u8 {
        self.buttons_released
    }
}

/// One coherent input frame published by Atom.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct InputFrame {
    frame_id: u32,
    keyboard_down: [u32; KEYBOARD_WORDS],
    keyboard_pressed: [u32; KEYBOARD_WORDS],
    keyboard_released: [u32; KEYBOARD_WORDS],
    mouse: MouseFrame,
    controller: ControllerFrame,
}

impl InputFrame {
    /// Return Atom's wrapping sample sequence number.
    pub const fn frame_id(self) -> u32 {
        self.frame_id
    }

    /// Return whether a DirectInput scancode is currently down.
    pub fn key_down(&self, scancode: u8) -> bool {
        bit_is_set(&self.keyboard_down, scancode)
    }

    /// Return whether a DirectInput scancode rose in this native sample.
    pub fn key_pressed(&self, scancode: u8) -> bool {
        bit_is_set(&self.keyboard_pressed, scancode)
    }

    /// Return whether a DirectInput scancode fell in this native sample.
    pub fn key_released(&self, scancode: u8) -> bool {
        bit_is_set(&self.keyboard_released, scancode)
    }

    /// Return the native mouse state and snapshot-derived button edges.
    pub const fn mouse(self) -> MouseFrame {
        self.mouse
    }

    /// Return the processed controller result and its native source state.
    pub const fn controller(self) -> ControllerFrame {
        self.controller
    }

    fn encode(self) -> [u32; FRAME_WORDS] {
        let mut words = [0; FRAME_WORDS];
        words[0] = self.frame_id;
        words[1..9].copy_from_slice(&self.keyboard_down);
        words[9..17].copy_from_slice(&self.keyboard_pressed);
        words[17..25].copy_from_slice(&self.keyboard_released);
        words[25] = self.mouse.x as u32;
        words[26] = self.mouse.y as u32;
        words[27] = self.mouse.wheel as u32;
        words[28] = u32::from(self.mouse.buttons_down)
            | (u32::from(self.mouse.buttons_pressed) << 8)
            | (u32::from(self.mouse.buttons_released) << 16);
        words[29..33].copy_from_slice(&self.controller.raw().encode_words());
        words[33] = self.controller.left_stick().x().to_bits();
        words[34] = self.controller.left_stick().y().to_bits();
        words[35] = self.controller.right_stick().x().to_bits();
        words[36] = self.controller.right_stick().y().to_bits();
        words[37] = self.controller.left_trigger().value().to_bits();
        words[38] = encode_trigger_flags(self.controller.left_trigger());
        words[39] = self.controller.right_trigger().value().to_bits();
        words[40] = encode_trigger_flags(self.controller.right_trigger());
        words
    }

    fn decode(words: [u32; FRAME_WORDS]) -> Self {
        let mut keyboard_down = [0; KEYBOARD_WORDS];
        let mut keyboard_pressed = [0; KEYBOARD_WORDS];
        let mut keyboard_released = [0; KEYBOARD_WORDS];
        keyboard_down.copy_from_slice(&words[1..9]);
        keyboard_pressed.copy_from_slice(&words[9..17]);
        keyboard_released.copy_from_slice(&words[17..25]);

        let packed_mouse = words[28];
        let raw_controller =
            NativeControllerState::decode_words([words[29], words[30], words[31], words[32]]);
        Self {
            frame_id: words[0],
            keyboard_down,
            keyboard_pressed,
            keyboard_released,
            mouse: MouseFrame {
                x: words[25] as i32,
                y: words[26] as i32,
                wheel: words[27] as i32,
                buttons_down: packed_mouse as u8,
                buttons_pressed: (packed_mouse >> 8) as u8,
                buttons_released: (packed_mouse >> 16) as u8,
            },
            controller: ControllerFrame::from_parts(
                raw_controller,
                StickVector::new(f32::from_bits(words[33]), f32::from_bits(words[34])),
                StickVector::new(f32::from_bits(words[35]), f32::from_bits(words[36])),
                decode_trigger(f32::from_bits(words[37]), words[38]),
                decode_trigger(f32::from_bits(words[39]), words[40]),
            ),
        }
    }
}

/// Allocation-free processor and coherent publication store.
pub struct InputPipeline {
    next_frame_id: AtomicU32,
    controller: ControllerProcessor,
    actions: ActionResolver,
    store: FrameStore,
}

impl InputPipeline {
    /// Construct a neutral pipeline.
    pub const fn new() -> Self {
        Self {
            next_frame_id: AtomicU32::new(0),
            controller: ControllerProcessor::new(),
            actions: ActionResolver::new(),
            store: FrameStore::new(),
        }
    }

    /// Process and publish one post-xNVSE native sample.
    pub fn capture(
        &self,
        native: NativeInputState,
        controller_settings: ControllerSettings,
    ) -> InputFrame {
        self.capture_with_keyboard_events(native, controller_settings, KeyboardEventBatch::EMPTY)
    }

    /// Process one native sample plus its ordered keyboard event batch.
    pub fn capture_with_keyboard_events(
        &self,
        native: NativeInputState,
        controller_settings: ControllerSettings,
        keyboard_events: KeyboardEventBatch,
    ) -> InputFrame {
        let frame_id = self
            .next_frame_id
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        let (keyboard_down, keyboard_pressed, keyboard_released) =
            keyboard_bits(&native.keyboard_current, &native.keyboard_previous);
        let mouse = mouse_frame(native.mouse_current, native.mouse_previous);
        let controller = self
            .controller
            .process(native.controller_current, controller_settings);
        let frame = InputFrame {
            frame_id,
            keyboard_down,
            keyboard_pressed,
            keyboard_released,
            mouse,
            controller,
        };
        self.store.publish(frame);
        let keyboard_events = keyboard_events.with_frame_id(frame_id);
        self.actions
            .resolve_with_keyboard_events(&native, frame, keyboard_events);
        frame
    }

    /// Load one coherent copy of the most recently published frame.
    pub fn latest(&self) -> InputFrame {
        self.store.load()
    }

    /// Load the coherent logical actions resolved from the latest frame.
    pub fn latest_actions(&self) -> ActionFrame {
        self.actions.latest()
    }

    /// Clear controller hysteresis for a neutral handoff.
    pub fn reset_controller_state(&self) {
        self.controller.reset();
    }
}

impl Default for InputPipeline {
    fn default() -> Self {
        Self::new()
    }
}

struct FrameStore {
    sequence: AtomicU32,
    words: [AtomicU32; FRAME_WORDS],
}

impl FrameStore {
    const fn new() -> Self {
        Self {
            sequence: AtomicU32::new(0),
            words: [const { AtomicU32::new(0) }; FRAME_WORDS],
        }
    }

    fn publish(&self, frame: InputFrame) {
        let words = frame.encode();
        self.sequence.fetch_add(1, Ordering::AcqRel);
        for (target, value) in self.words.iter().zip(words) {
            target.store(value, Ordering::Relaxed);
        }
        self.sequence.fetch_add(1, Ordering::Release);
    }

    fn load(&self) -> InputFrame {
        loop {
            let before = self.sequence.load(Ordering::Acquire);
            if before & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }

            let mut words = [0; FRAME_WORDS];
            for (value, source) in words.iter_mut().zip(&self.words) {
                *value = source.load(Ordering::Relaxed);
            }
            if before == self.sequence.load(Ordering::Acquire) {
                return InputFrame::decode(words);
            }
        }
    }
}

fn keyboard_bits(
    current: &[u8; KEYBOARD_BYTES],
    previous: &[u8; KEYBOARD_BYTES],
) -> (
    [u32; KEYBOARD_WORDS],
    [u32; KEYBOARD_WORDS],
    [u32; KEYBOARD_WORDS],
) {
    let mut down = [0; KEYBOARD_WORDS];
    let mut pressed = [0; KEYBOARD_WORDS];
    let mut released = [0; KEYBOARD_WORDS];
    for scancode in 0..KEYBOARD_BYTES {
        let current_down = current[scancode] & 0x80 != 0;
        let previous_down = previous[scancode] & 0x80 != 0;
        if current_down {
            set_bit(&mut down, scancode);
        }
        if current_down && !previous_down {
            set_bit(&mut pressed, scancode);
        }
        if !current_down && previous_down {
            set_bit(&mut released, scancode);
        }
    }
    (down, pressed, released)
}

fn mouse_frame(current: NativeMouseState, previous: NativeMouseState) -> MouseFrame {
    let down = mouse_button_mask(current.buttons);
    let previous = mouse_button_mask(previous.buttons);
    MouseFrame {
        x: current.x,
        y: current.y,
        wheel: current.wheel,
        buttons_down: down,
        buttons_pressed: down & !previous,
        buttons_released: previous & !down,
    }
}

fn mouse_button_mask(buttons: [u8; 8]) -> u8 {
    buttons.iter().enumerate().fold(0, |mask, (index, value)| {
        mask | u8::from(value & 0x80 != 0) << index
    })
}

fn set_bit(words: &mut [u32; KEYBOARD_WORDS], index: usize) {
    words[index / 32] |= 1 << (index % 32);
}

fn bit_is_set(words: &[u32; KEYBOARD_WORDS], scancode: u8) -> bool {
    let index = usize::from(scancode);
    words[index / 32] & (1 << (index % 32)) != 0
}

fn encode_trigger_flags(trigger: TriggerFrame) -> u32 {
    u32::from(trigger.down())
        | (u32::from(trigger.pressed()) << 1)
        | (u32::from(trigger.released()) << 2)
}

fn decode_trigger(value: f32, flags: u32) -> TriggerFrame {
    TriggerFrame::from_parts(value, flags & 1 != 0, flags & 2 != 0, flags & 4 != 0)
}
