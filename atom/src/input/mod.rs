//! Atom's engine-semantic input wrapper.
//!
//! FNV and xNVSE remain the authoritative device owners. Deferred,
//! ownership-aware hooks publish coherent device and logical-action frames,
//! preserve buffered keyboard transitions, and transform player mouse and
//! controller input only at proven engine boundaries. Menus, console input,
//! fly camera, text entry, and pointer presentation remain native.

pub mod actions;
pub mod buffered;
pub mod controller;
pub mod frame;
pub mod mouse;
pub mod telemetry;

mod config;
mod hooks;
mod native;

pub use actions::{
    ACTION_COUNT, ActionBindings, ActionContext, ActionFrame, ActionId, ActionResolver,
    ActionSources, ActionState, InputDevice,
};
pub use buffered::{
    BufferedKeyboardDiagnostics, DirectInputEvent, KeyboardEventBatch,
    buffered_keyboard_diagnostics, latest_keyboard_events,
};
pub use config::{ConfigError, InputConfig};
pub use controller::{
    ControllerFrame, ControllerProcessor, ControllerSettings, NativeControllerState, StickVector,
    TriggerFrame,
};
pub use frame::{InputFrame, InputPipeline, MouseFrame, NativeInputState, NativeMouseState};
pub use mouse::{
    FALLOUT4_RADIANS_PER_COUNT, MouseAxis, MouseHeadingInput, MouseProfile, MouseProfileError,
    MouseSettings, MouseTransform,
};
pub use telemetry::{MouseHeadingSummary, TelemetrySnapshot};

use config::ConfigStore;
use core::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;

static CONFIG: ConfigStore = ConfigStore::new();
static PIPELINE: InputPipeline = InputPipeline::new();
static CONTROLLER_TRANSFORM_ACTIVE: AtomicBool = AtomicBool::new(false);
static ACTION_BRIDGE_OPEN: AtomicBool = AtomicBool::new(false);

/// Failure to admit Atom's fixed FNV input bridge.
#[derive(Debug, Error)]
pub(crate) enum InputInstallError {
    #[error(transparent)]
    Native(#[from] native::NativeContractError),
    #[error(transparent)]
    Hook(#[from] hooks::HookInstallError),
}

/// Captured hook predecessors for capability-oriented startup diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InputHookStatus {
    pub(crate) sampler_predecessor: usize,
    pub(crate) mouse_x_predecessor: usize,
    pub(crate) mouse_y_predecessor: usize,
    pub(crate) heading_x_predecessor: usize,
    pub(crate) heading_y_predecessor: usize,
    pub(crate) controller_abs_predecessor: usize,
    pub(crate) keyboard_data_predecessor: usize,
    pub(crate) bound_action_predecessor: usize,
}

/// Return one coherent copy of Atom's current MCM-owned settings.
pub fn current_config() -> InputConfig {
    CONFIG.load()
}

/// Return one coherent copy of the most recent post-xNVSE native sample.
pub fn latest_input_frame() -> InputFrame {
    PIPELINE.latest()
}

/// Return one coherent copy of the latest mixed-device action state.
pub fn latest_action_frame() -> ActionFrame {
    PIPELINE.latest_actions()
}

pub(crate) fn publish_config(config: InputConfig) {
    CONFIG.publish(config);
}

pub(crate) fn capture_native_sample(native: NativeInputState, keyboard_events: KeyboardEventBatch) {
    let config = CONFIG.load();
    let frame = PIPELINE.capture_with_keyboard_events(native, config.controller(), keyboard_events);
    buffered::publish(keyboard_events.with_frame_id(frame.frame_id()));
    reconcile_controller_output(config.enabled(), frame.controller());
    telemetry::mark_sample(frame.frame_id());
    ACTION_BRIDGE_OPEN.store(true, Ordering::Release);
}

pub(crate) fn begin_native_sample() {
    // The native sample helper itself clears disabled controls through the
    // bound-action provider. Keeping the adapter closed until its predecessor
    // returns prevents replaying the preceding frame inside that maintenance
    // pass.
    ACTION_BRIDGE_OPEN.store(false, Ordering::Release);
}

pub(crate) fn finish_frame() {
    ACTION_BRIDGE_OPEN.store(false, Ordering::Release);
}

pub(crate) fn action_bridge_open() -> bool {
    ACTION_BRIDGE_OPEN.load(Ordering::Acquire)
}

pub(crate) fn mouse_config() -> (bool, MouseSettings) {
    CONFIG.load_mouse()
}

pub(crate) fn controller_transform_active() -> bool {
    CONTROLLER_TRANSFORM_ACTIVE.load(Ordering::Acquire)
}

pub(crate) fn input_enabled() -> bool {
    CONFIG.load().enabled()
}

fn reconcile_controller_output(requested: bool, controller: ControllerFrame) {
    let mut active = CONTROLLER_TRANSFORM_ACTIVE.load(Ordering::Acquire);
    let neutral = controller.raw().is_neutral();

    // Starting or stopping only on a physically neutral sample prevents a
    // live MCM toggle from creating an artificial press, release, or stick
    // jump in FNV's current/previous controller comparison.
    if !active && requested && neutral {
        active = true;
        CONTROLLER_TRANSFORM_ACTIVE.store(true, Ordering::Release);
    }

    if active {
        native::publish_controller(controller.native_output());
    }

    if active && !requested && neutral {
        CONTROLLER_TRANSFORM_ACTIVE.store(false, Ordering::Release);
        PIPELINE.reset_controller_state();
    }
}

pub(crate) fn install_native_bridge() -> Result<InputHookStatus, InputInstallError> {
    native::validate_data_contract()?;
    let predecessors = hooks::install()?;
    Ok(InputHookStatus {
        sampler_predecessor: predecessors.sampler,
        mouse_x_predecessor: predecessors.mouse_x,
        mouse_y_predecessor: predecessors.mouse_y,
        heading_x_predecessor: predecessors.heading_x,
        heading_y_predecessor: predecessors.heading_y,
        controller_abs_predecessor: predecessors.controller_abs,
        keyboard_data_predecessor: predecessors.keyboard_data,
        bound_action_predecessor: predecessors.bound_action,
    })
}
