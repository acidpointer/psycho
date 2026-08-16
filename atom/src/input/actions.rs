//! Logical actions resolved from Atom's coherent native snapshot.
//!
//! Fallout: New Vegas stores one keyboard, mouse, and controller binding for
//! each of 28 controls. This module retains that exact binding contract while
//! merging all three devices into a single immutable action frame. Device
//! presentation never gates another device: a keyboard press and a controller
//! press may therefore coexist in the same sample.
//!
//! Focus and context transitions are explicit neutral boundaries. Physically
//! held controls are suppressed until released after a boundary, preventing a
//! focus regain or menu close from manufacturing a gameplay press. Publication
//! uses fixed atomic storage, so the native hook allocates nothing and readers
//! cannot observe a partially written frame.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

use super::buffered::KeyboardEventBatch;
use super::frame::{InputFrame, NativeInputState};

/// Number of controls in FNV's persisted binding table.
pub const ACTION_COUNT: usize = 28;

const ACTION_FRAME_WORDS: usize = 3 + ACTION_COUNT * 2;
const SOURCE_KEYBOARD: u8 = 1 << 0;
const SOURCE_MOUSE: u8 = 1 << 1;
const SOURCE_CONTROLLER: u8 = 1 << 2;

/// One of FNV's 28 persisted gameplay controls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ActionId {
    /// Move forward.
    Forward = 0,
    /// Move backward.
    Back = 1,
    /// Strafe left.
    SlideLeft = 2,
    /// Strafe right.
    SlideRight = 3,
    /// Attack or fire.
    Use = 4,
    /// Activate the targeted object.
    Activate = 5,
    /// Aim or block.
    Block = 6,
    /// Ready or reload the equipped item.
    ReadyItem = 7,
    /// Toggle crouch or sneak.
    Crouch = 8,
    /// Apply the run modifier.
    Run = 9,
    /// Toggle the always-run state.
    AlwaysRun = 10,
    /// Toggle automatic movement.
    AutoMove = 11,
    /// Jump.
    Jump = 12,
    /// Toggle first- and third-person view.
    TogglePov = 13,
    /// Open the Pip-Boy/menu route.
    MenuMode = 14,
    /// Open wait or rest.
    Rest = 15,
    /// Enter VATS.
    Vats = 16,
    /// Use item hotkey 1.
    Hotkey1 = 17,
    /// Swap ammunition; FNV assigns this Hotkey2's ordinal.
    AmmoSwap = 18,
    /// Use item hotkey 3.
    Hotkey3 = 19,
    /// Use item hotkey 4.
    Hotkey4 = 20,
    /// Use item hotkey 5.
    Hotkey5 = 21,
    /// Use item hotkey 6.
    Hotkey6 = 22,
    /// Use item hotkey 7.
    Hotkey7 = 23,
    /// Use item hotkey 8.
    Hotkey8 = 24,
    /// Request a quicksave.
    QuickSave = 25,
    /// Request a quickload.
    QuickLoad = 26,
    /// Grab or manipulate an object.
    Grab = 27,
}

impl ActionId {
    /// Every FNV action in native binding-table order.
    pub const ALL: [Self; ACTION_COUNT] = [
        Self::Forward,
        Self::Back,
        Self::SlideLeft,
        Self::SlideRight,
        Self::Use,
        Self::Activate,
        Self::Block,
        Self::ReadyItem,
        Self::Crouch,
        Self::Run,
        Self::AlwaysRun,
        Self::AutoMove,
        Self::Jump,
        Self::TogglePov,
        Self::MenuMode,
        Self::Rest,
        Self::Vats,
        Self::Hotkey1,
        Self::AmmoSwap,
        Self::Hotkey3,
        Self::Hotkey4,
        Self::Hotkey5,
        Self::Hotkey6,
        Self::Hotkey7,
        Self::Hotkey8,
        Self::QuickSave,
        Self::QuickLoad,
        Self::Grab,
    ];

    const fn index(self) -> usize {
        self as usize
    }
}

/// Engine context associated with an action frame.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum ActionContext {
    /// The game window does not own foreground input.
    Unfocused = 0,
    /// Normal player/gameplay processing is active.
    #[default]
    Gameplay = 1,
    /// FNV reports menu mode; native menu consumers remain authoritative.
    Menu = 2,
}

impl ActionContext {
    const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Unfocused,
            2 => Self::Menu,
            _ => Self::Gameplay,
        }
    }
}

/// Device whose meaningful activity most recently changed presentation hints.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum InputDevice {
    /// DirectInput keyboard or mouse.
    #[default]
    KeyboardMouse = 0,
    /// XInput controller.
    Controller = 1,
}

impl InputDevice {
    const fn from_u8(value: u8) -> Self {
        if value == 1 {
            Self::Controller
        } else {
            Self::KeyboardMouse
        }
    }
}

/// Devices currently contributing to one logical action.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ActionSources(u8);

impl ActionSources {
    /// Return whether a keyboard binding contributes to the action.
    pub const fn keyboard(self) -> bool {
        self.0 & SOURCE_KEYBOARD != 0
    }

    /// Return whether a mouse binding contributes to the action.
    pub const fn mouse(self) -> bool {
        self.0 & SOURCE_MOUSE != 0
    }

    /// Return whether a controller binding contributes to the action.
    pub const fn controller(self) -> bool {
        self.0 & SOURCE_CONTROLLER != 0
    }
}

/// Native bindings associated with one resolved action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionBindings {
    keyboard: u8,
    mouse: u8,
    controller: u8,
}

impl ActionBindings {
    const UNBOUND: Self = Self {
        keyboard: u8::MAX,
        mouse: u8::MAX,
        controller: u8::MAX,
    };

    /// Return the DirectInput keyboard scancode, or `0xFF` when unbound.
    pub const fn keyboard(self) -> u8 {
        self.keyboard
    }

    /// Return the mouse button/pseudo-button code, or `0xFF` when unbound.
    pub const fn mouse(self) -> u8 {
        self.mouse
    }

    /// Return the XInput binding code, or `0xFF` when unbound.
    pub const fn controller(self) -> u8 {
        self.controller
    }
}

/// Resolved state for one action in one input sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionState {
    down: bool,
    pressed: bool,
    released: bool,
    held_samples: u32,
    sources: ActionSources,
    bindings: ActionBindings,
    buffered_pressed: bool,
    buffered_released: bool,
    controller_pressed: bool,
    controller_released: bool,
}

impl ActionState {
    const NEUTRAL: Self = Self {
        down: false,
        pressed: false,
        released: false,
        held_samples: 0,
        sources: ActionSources(0),
        bindings: ActionBindings::UNBOUND,
        buffered_pressed: false,
        buffered_released: false,
        controller_pressed: false,
        controller_released: false,
    };

    /// Return whether at least one bound device is down.
    pub const fn down(self) -> bool {
        self.down
    }

    /// Return whether the merged state rose in this sample.
    pub const fn pressed(self) -> bool {
        self.pressed
    }

    /// Return whether the merged state fell in this sample.
    pub const fn released(self) -> bool {
        self.released
    }

    /// Return consecutive native samples for which the action remained down.
    pub const fn held_samples(self) -> u32 {
        self.held_samples
    }

    /// Return all devices currently contributing to the action.
    pub const fn sources(self) -> ActionSources {
        self.sources
    }

    /// Return the native bindings used to resolve the action.
    pub const fn bindings(self) -> ActionBindings {
        self.bindings
    }

    /// Return whether an ordered keyboard event preserved this press.
    pub const fn buffered_pressed(self) -> bool {
        self.buffered_pressed
    }

    /// Return whether an ordered keyboard event preserved this release.
    pub const fn buffered_released(self) -> bool {
        self.buffered_released
    }

    /// Return whether the controller source rose in this sample.
    pub const fn controller_pressed(self) -> bool {
        self.controller_pressed
    }

    /// Return whether the controller source fell in this sample.
    pub const fn controller_released(self) -> bool {
        self.controller_released
    }
}

/// Coherent logical-action state published for one native input sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionFrame {
    frame_id: u32,
    focus_epoch: u32,
    context: ActionContext,
    last_active_device: InputDevice,
    actions: [ActionState; ACTION_COUNT],
}

impl ActionFrame {
    const NEUTRAL: Self = Self {
        frame_id: 0,
        focus_epoch: 0,
        context: ActionContext::Gameplay,
        last_active_device: InputDevice::KeyboardMouse,
        actions: [ActionState::NEUTRAL; ACTION_COUNT],
    };

    /// Return the matching [`InputFrame`] sequence number.
    pub const fn frame_id(self) -> u32 {
        self.frame_id
    }

    /// Return the epoch incremented on every observed focus loss.
    pub const fn focus_epoch(self) -> u32 {
        self.focus_epoch
    }

    /// Return the engine context captured with this frame.
    pub const fn context(self) -> ActionContext {
        self.context
    }

    /// Return the last device with meaningful, unambiguous activity.
    pub const fn last_active_device(self) -> InputDevice {
        self.last_active_device
    }

    /// Return the state for one native action.
    pub const fn action(&self, action: ActionId) -> ActionState {
        self.actions[action.index()]
    }

    fn encode(self) -> [u32; ACTION_FRAME_WORDS] {
        let mut words = [0; ACTION_FRAME_WORDS];
        words[0] = self.frame_id;
        words[1] = self.focus_epoch;
        words[2] = self.context as u32 | ((self.last_active_device as u32) << 8);
        for (index, action) in self.actions.into_iter().enumerate() {
            let base = 3 + index * 2;
            words[base] = u32::from(action.down)
                | (u32::from(action.pressed) << 1)
                | (u32::from(action.released) << 2)
                | (u32::from(action.sources.0) << 3)
                | (u32::from(action.buffered_pressed) << 6)
                | (u32::from(action.buffered_released) << 7)
                | (u32::from(action.controller_pressed) << 8)
                | (u32::from(action.controller_released) << 9)
                | (action.held_samples.min(0x000F_FFFF) << 12);
            words[base + 1] = u32::from(action.bindings.keyboard)
                | (u32::from(action.bindings.mouse) << 8)
                | (u32::from(action.bindings.controller) << 16);
        }
        words
    }

    fn decode(words: [u32; ACTION_FRAME_WORDS]) -> Self {
        let mut actions = [ActionState::NEUTRAL; ACTION_COUNT];
        for (index, action) in actions.iter_mut().enumerate() {
            let base = 3 + index * 2;
            let state = words[base];
            let bindings = words[base + 1];
            *action = ActionState {
                down: state & 1 != 0,
                pressed: state & 2 != 0,
                released: state & 4 != 0,
                sources: ActionSources(((state >> 3) & 0x7) as u8),
                buffered_pressed: state & (1 << 6) != 0,
                buffered_released: state & (1 << 7) != 0,
                controller_pressed: state & (1 << 8) != 0,
                controller_released: state & (1 << 9) != 0,
                held_samples: state >> 12,
                bindings: ActionBindings {
                    keyboard: bindings as u8,
                    mouse: (bindings >> 8) as u8,
                    controller: (bindings >> 16) as u8,
                },
            };
        }
        Self {
            frame_id: words[0],
            focus_epoch: words[1],
            context: ActionContext::from_u8(words[2] as u8),
            last_active_device: InputDevice::from_u8((words[2] >> 8) as u8),
            actions,
        }
    }
}

/// Stateful mixed-device resolver and coherent action-frame publisher.
pub struct ActionResolver {
    initialized: AtomicBool,
    focused: AtomicBool,
    context: AtomicU8,
    focus_epoch: AtomicU32,
    previous_down: AtomicU32,
    suppressed_until_release: AtomicU32,
    last_active_device: AtomicU8,
    held_samples: [AtomicU32; ACTION_COUNT],
    store: ActionStore,
}

impl ActionResolver {
    /// Construct a neutral resolver with no pending physical state.
    pub const fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            focused: AtomicBool::new(false),
            context: AtomicU8::new(ActionContext::Gameplay as u8),
            focus_epoch: AtomicU32::new(0),
            previous_down: AtomicU32::new(0),
            suppressed_until_release: AtomicU32::new(0),
            last_active_device: AtomicU8::new(InputDevice::KeyboardMouse as u8),
            held_samples: [const { AtomicU32::new(0) }; ACTION_COUNT],
            store: ActionStore::new(),
        }
    }

    /// Resolve and publish one coherent mixed-device frame.
    ///
    /// This method has a single-writer contract: Atom calls it from the normal
    /// game-thread sampler detour. Published frames remain safe to read from
    /// other threads through [`Self::latest`].
    pub fn resolve(&self, native: &NativeInputState, input: InputFrame) -> ActionFrame {
        self.resolve_with_keyboard_events(native, input, KeyboardEventBatch::EMPTY)
    }

    /// Resolve one frame while preserving ordered buffered keyboard edges.
    pub fn resolve_with_keyboard_events(
        &self,
        native: &NativeInputState,
        input: InputFrame,
        keyboard_events: KeyboardEventBatch,
    ) -> ActionFrame {
        let context = classify_context(native);
        let physical = physical_action_state(native, input);
        let physical_down = physical.iter().enumerate().fold(0, |mask, (index, item)| {
            mask | (u32::from(item.sources.0 != 0) << index)
        });

        let initialized = self.initialized.swap(true, Ordering::AcqRel);
        let prior_focused = self.focused.swap(native.focused(), Ordering::AcqRel);
        let prior_context =
            ActionContext::from_u8(self.context.swap(context as u8, Ordering::AcqRel));
        let focus_changed = initialized && prior_focused != native.focused();
        let context_changed = initialized && prior_context != context;

        if focus_changed && !native.focused() {
            self.focus_epoch.fetch_add(1, Ordering::AcqRel);
        }

        let boundary = !initialized || focus_changed || context_changed;
        let mut suppressed = self.suppressed_until_release.load(Ordering::Acquire);
        if boundary {
            suppressed = physical_down;
            self.suppressed_until_release
                .store(suppressed, Ordering::Release);
            self.previous_down.store(0, Ordering::Release);
            reset_held_samples(&self.held_samples);
        } else {
            // A suppressed control becomes eligible only after a complete
            // physical release. This cannot generate a rising edge by itself.
            suppressed &= physical_down;
            self.suppressed_until_release
                .store(suppressed, Ordering::Release);
        }

        let effective_down = if context == ActionContext::Unfocused {
            0
        } else {
            physical_down & !suppressed
        };
        let previous_down = if boundary {
            0
        } else {
            self.previous_down.load(Ordering::Acquire)
        };
        let mut pressed = effective_down & !previous_down;
        let mut released = if boundary {
            0
        } else {
            previous_down & !effective_down
        };
        let (buffered_pressed, buffered_released, buffered_sources) =
            if boundary || context == ActionContext::Unfocused {
                (0, 0, 0)
            } else {
                buffered_keyboard_edges(native, keyboard_events, previous_down, &physical)
            };
        if !boundary && context != ActionContext::Unfocused {
            pressed |= buffered_pressed & !suppressed;
            released |= buffered_released & !suppressed;
        }
        self.previous_down.store(effective_down, Ordering::Release);

        let last_active_device = self.resolve_last_active_device(native, input);
        let mut actions = [ActionState::NEUTRAL; ACTION_COUNT];
        for (index, state) in actions.iter_mut().enumerate() {
            let bit = 1_u32 << index;
            let down = effective_down & bit != 0;
            let controller_binding = native.controller_bindings()[index];
            let controller_down = physical[index].sources.0 & SOURCE_CONTROLLER != 0;
            let controller_was_down =
                controller_binding_down_native(controller_binding, native.controller_previous());
            let held_samples = if down {
                let next = self.held_samples[index]
                    .load(Ordering::Relaxed)
                    .saturating_add(1);
                self.held_samples[index].store(next, Ordering::Relaxed);
                next
            } else {
                self.held_samples[index].store(0, Ordering::Relaxed);
                0
            };
            *state = ActionState {
                down,
                pressed: pressed & bit != 0,
                released: released & bit != 0,
                held_samples,
                sources: ActionSources(
                    (if down { physical[index].sources.0 } else { 0 })
                        | (u8::from(buffered_sources & bit != 0) * SOURCE_KEYBOARD),
                ),
                bindings: physical[index].bindings,
                buffered_pressed: buffered_pressed & !suppressed & bit != 0,
                buffered_released: buffered_released & !suppressed & bit != 0,
                controller_pressed: !boundary && controller_down && !controller_was_down,
                controller_released: !boundary && !controller_down && controller_was_down,
            };
        }

        let frame = ActionFrame {
            frame_id: input.frame_id(),
            focus_epoch: self.focus_epoch.load(Ordering::Acquire),
            context,
            last_active_device,
            actions,
        };
        self.store.publish(frame);
        frame
    }

    /// Load one coherent copy of the latest resolved action frame.
    pub fn latest(&self) -> ActionFrame {
        self.store.load()
    }

    fn resolve_last_active_device(
        &self,
        native: &NativeInputState,
        input: InputFrame,
    ) -> InputDevice {
        let keyboard_changed = native
            .keyboard_current()
            .iter()
            .zip(native.keyboard_previous())
            .any(|(current, previous)| (current ^ previous) & 0x80 != 0);
        let mouse = input.mouse();
        let mouse_changed = mouse.x() != 0
            || mouse.y() != 0
            || mouse.wheel() != 0
            || mouse.buttons_pressed() != 0
            || mouse.buttons_released() != 0;
        let current = native.controller_current();
        let previous = native.controller_previous();
        let controller_button_changed = current.buttons() != previous.buttons()
            || current.left_trigger() != previous.left_trigger()
            || current.right_trigger() != previous.right_trigger();
        let sticks = input.controller();
        // A substantial deflection may claim controller glyph ownership; tiny
        // centered drift cannot. Button/trigger transitions always qualify.
        let controller_changed = controller_button_changed
            || sticks.left_stick().magnitude() >= 0.20
            || sticks.right_stick().magnitude() >= 0.20;

        let previous_device = InputDevice::from_u8(self.last_active_device.load(Ordering::Acquire));
        let resolved = match (keyboard_changed || mouse_changed, controller_changed) {
            (true, false) => InputDevice::KeyboardMouse,
            (false, true) => InputDevice::Controller,
            // Simultaneous activity is ambiguous. Retaining the preceding
            // presentation owner avoids frame-by-frame glyph flicker while
            // both devices still contribute to actions normally.
            _ => previous_device,
        };
        self.last_active_device
            .store(resolved as u8, Ordering::Release);
        resolved
    }
}

fn buffered_keyboard_edges(
    native: &NativeInputState,
    batch: KeyboardEventBatch,
    previous_down: u32,
    physical: &[PhysicalAction; ACTION_COUNT],
) -> (u32, u32, u32) {
    let mut pressed = 0;
    let mut released = 0;
    let mut sources = 0;
    for (index, physical_action) in physical.iter().enumerate() {
        let binding = native.keyboard_bindings()[index];
        if binding == u8::MAX {
            continue;
        }
        let bit = 1_u32 << index;
        let other_device_down = physical_action.sources.0 & (SOURCE_MOUSE | SOURCE_CONTROLLER) != 0;
        let mut merged_down = previous_down & bit != 0;
        for event in batch
            .events()
            .iter()
            .filter(|event| event.offset() == u32::from(binding))
        {
            sources |= bit;
            let next_down = event.pressed() || other_device_down;
            if next_down && !merged_down {
                pressed |= bit;
            } else if !next_down && merged_down {
                released |= bit;
            }
            merged_down = next_down;
        }
    }
    (pressed, released, sources)
}

impl Default for ActionResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
struct PhysicalAction {
    sources: ActionSources,
    bindings: ActionBindings,
}

fn classify_context(native: &NativeInputState) -> ActionContext {
    if !native.focused() {
        ActionContext::Unfocused
    } else if native.menu_mode() {
        ActionContext::Menu
    } else {
        ActionContext::Gameplay
    }
}

fn physical_action_state(
    native: &NativeInputState,
    input: InputFrame,
) -> [PhysicalAction; ACTION_COUNT] {
    let mut actions = [PhysicalAction {
        sources: ActionSources(0),
        bindings: ActionBindings::UNBOUND,
    }; ACTION_COUNT];
    for (index, action) in actions.iter_mut().enumerate() {
        let keyboard = native.keyboard_bindings()[index];
        let mouse = native.mouse_bindings()[index];
        let controller = native.controller_bindings()[index];
        let mut sources = 0;
        if keyboard != u8::MAX && input.key_down(keyboard) {
            sources |= SOURCE_KEYBOARD;
        }
        if mouse_binding_down(mouse, input) {
            sources |= SOURCE_MOUSE;
        }
        if controller_binding_down(controller, input) {
            sources |= SOURCE_CONTROLLER;
        }
        *action = PhysicalAction {
            sources: ActionSources(sources),
            bindings: ActionBindings {
                keyboard,
                mouse,
                controller,
            },
        };
    }
    actions
}

fn mouse_binding_down(binding: u8, input: InputFrame) -> bool {
    match binding {
        0..=7 => input.mouse().buttons_down() & (1 << binding) != 0,
        8 => input.mouse().wheel() > 0,
        9 => input.mouse().wheel() < 0,
        _ => false,
    }
}

fn controller_binding_down(binding: u8, input: InputFrame) -> bool {
    let controller = input.controller();
    match binding {
        1 => controller.raw().buttons() & 0x0001 != 0,
        2 => controller.raw().buttons() & 0x0002 != 0,
        4 => controller.raw().buttons() & 0x0008 != 0,
        5 => controller.raw().buttons() & 0x0004 != 0,
        6 => controller.raw().buttons() & 0x0010 != 0,
        7 => controller.raw().buttons() & 0x0020 != 0,
        8 => controller.raw().buttons() & 0x0040 != 0,
        9 => controller.raw().buttons() & 0x0080 != 0,
        10 => controller.raw().buttons() & 0x1000 != 0,
        11 => controller.raw().buttons() & 0x2000 != 0,
        12 => controller.raw().buttons() & 0x4000 != 0,
        13 => controller.raw().buttons() & 0x8000 != 0,
        14 => controller.raw().buttons() & 0x0200 != 0,
        15 => controller.raw().buttons() & 0x0100 != 0,
        16 => controller.left_trigger().down(),
        17 => controller.right_trigger().down(),
        19 => controller.left_stick().y() > 0.0,
        20 => controller.left_stick().y() < 0.0,
        22 => controller.left_stick().x() > 0.0,
        23 => controller.left_stick().x() < 0.0,
        _ => false,
    }
}

fn controller_binding_down_native(
    binding: u8,
    controller: super::controller::NativeControllerState,
) -> bool {
    match binding {
        1 => controller.buttons() & 0x0001 != 0,
        2 => controller.buttons() & 0x0002 != 0,
        4 => controller.buttons() & 0x0008 != 0,
        5 => controller.buttons() & 0x0004 != 0,
        6 => controller.buttons() & 0x0010 != 0,
        7 => controller.buttons() & 0x0020 != 0,
        8 => controller.buttons() & 0x0040 != 0,
        9 => controller.buttons() & 0x0080 != 0,
        10 => controller.buttons() & 0x1000 != 0,
        11 => controller.buttons() & 0x2000 != 0,
        12 => controller.buttons() & 0x4000 != 0,
        13 => controller.buttons() & 0x8000 != 0,
        14 => controller.buttons() & 0x0200 != 0,
        15 => controller.buttons() & 0x0100 != 0,
        16 => controller.left_trigger() != 0,
        17 => controller.right_trigger() != 0,
        19 => controller.left_y() > 0,
        20 => controller.left_y() < 0,
        22 => controller.left_x() > 0,
        23 => controller.left_x() < 0,
        _ => false,
    }
}

fn reset_held_samples(samples: &[AtomicU32; ACTION_COUNT]) {
    for value in samples {
        value.store(0, Ordering::Relaxed);
    }
}

struct ActionStore {
    sequence: AtomicU32,
    words: [AtomicU32; ACTION_FRAME_WORDS],
}

impl ActionStore {
    const fn new() -> Self {
        Self {
            sequence: AtomicU32::new(0),
            words: [const { AtomicU32::new(0) }; ACTION_FRAME_WORDS],
        }
    }

    fn publish(&self, frame: ActionFrame) {
        let words = frame.encode();
        self.sequence.fetch_add(1, Ordering::AcqRel);
        for (target, value) in self.words.iter().zip(words) {
            target.store(value, Ordering::Relaxed);
        }
        self.sequence.fetch_add(1, Ordering::Release);
    }

    fn load(&self) -> ActionFrame {
        loop {
            let before = self.sequence.load(Ordering::Acquire);
            if before == 0 {
                return ActionFrame::NEUTRAL;
            }
            if before & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }
            let mut words = [0; ACTION_FRAME_WORDS];
            for (target, source) in words.iter_mut().zip(&self.words) {
                *target = source.load(Ordering::Relaxed);
            }
            if before == self.sequence.load(Ordering::Acquire) {
                return ActionFrame::decode(words);
            }
        }
    }
}
