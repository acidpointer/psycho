//! Deferred, ownership-aware native input callsite hooks.
//!
//! The supported runtime defines each call's ABI. Hook preparation validates
//! the live instruction and executable target, then captures that target as
//! the typed predecessor. Surrounding code is not compared with vanilla bytes:
//! xNVSE and compatible providers can legitimately replace those instructions.
//! Every callsite, entry trampoline, and pointer-slot write is committed as one
//! rollback-capable transaction.
//!
//! Detours fall back to transmuted vanilla addresses when their container's
//! captured predecessor is somehow unavailable. That path is unreachable by
//! construction: containers are initialized before the transaction that can
//! enable them, and a detour only executes while its hook is enabled. The
//! fallbacks exist because Rust requires a value; they are never an admission
//! path around failed hook preparation.

use core::ffi::c_void;
use core::sync::atomic::{AtomicI32, Ordering};
use std::sync::LazyLock;

use libpsycho::os::windows::hook::{
    callsite::{Rel32CallHookContainer, Rel32CallHookError},
    inline::{errors::InlineHookError, inlinehook::InlineHookContainer},
    pointer::PointerSlotHookError,
    transaction::ModificationTransaction,
};
use thiserror::Error;

use super::mouse::{MouseAxis, MouseHeadingInput, MouseProfile, MouseTransform};
use super::{
    buffered, capture_native_sample, controller_transform_active, mouse_config, native, telemetry,
};
use crate::integrity;

const SAMPLE_CALLSITE: usize = 0x0086_F39E;
const MOUSE_X_CALLSITE: usize = 0x0094_5995;
const MOUSE_Y_CALLSITE: usize = 0x0094_59A8;
const HEADING_X_CALLSITE: usize = 0x0094_5F90;
const HEADING_Y_CALLSITE: usize = 0x0094_5FD8;
const CONTROLLER_ABS_CALLSITES: [usize; 4] = [0x0094_55EC, 0x0094_563B, 0x0094_56E7, 0x0094_5707];
const CONTROLLER_X_EXPONENT_CALLSITE: usize = 0x0094_5839;
const CONTROLLER_Y_EXPONENT_CALLSITE: usize = 0x0094_587C;
const CONTROLLER_MIN_SPEED_CALLSITE: usize = 0x0094_58A4;
const BOUND_ACTION_ADDRESS: usize = 0x00A2_4660;

type SamplerFn = unsafe extern "thiscall" fn(*mut c_void);
type MouseGetterFn = unsafe extern "thiscall" fn(*mut c_void, u32) -> i32;
type HeadingConsumerFn = unsafe extern "thiscall" fn(*mut c_void, f32);
type AbsFn = unsafe extern "C" fn(i32) -> i32;
type IntSettingFn = unsafe extern "thiscall" fn(*mut c_void) -> *const i32;
type FloatSettingFn = unsafe extern "thiscall" fn(*mut c_void) -> *const f32;
type BoundActionFn = unsafe extern "thiscall" fn(*mut c_void, u32, u32) -> i32;

static SAMPLE_HOOK: Rel32CallHookContainer<SamplerFn> = Rel32CallHookContainer::new();
static MOUSE_X_HOOK: Rel32CallHookContainer<MouseGetterFn> = Rel32CallHookContainer::new();
static MOUSE_Y_HOOK: Rel32CallHookContainer<MouseGetterFn> = Rel32CallHookContainer::new();
static HEADING_X_HOOK: Rel32CallHookContainer<HeadingConsumerFn> = Rel32CallHookContainer::new();
static HEADING_Y_HOOK: Rel32CallHookContainer<HeadingConsumerFn> = Rel32CallHookContainer::new();
static CONTROLLER_ABS_HOOKS: [Rel32CallHookContainer<AbsFn>; 4] =
    [const { Rel32CallHookContainer::new() }; 4];
static CONTROLLER_X_EXPONENT_HOOK: Rel32CallHookContainer<IntSettingFn> =
    Rel32CallHookContainer::new();
static CONTROLLER_Y_EXPONENT_HOOK: Rel32CallHookContainer<IntSettingFn> =
    Rel32CallHookContainer::new();
static CONTROLLER_MIN_SPEED_HOOK: Rel32CallHookContainer<FloatSettingFn> =
    Rel32CallHookContainer::new();
// The container allocates its trampoline only when first touched from
// DeferredInit. The lazy cell itself performs no loader-time initialization.
static BOUND_ACTION_HOOK: LazyLock<InlineHookContainer<BoundActionFn>> =
    LazyLock::new(InlineHookContainer::new);

static LAST_MOUSE_X: AtomicI32 = AtomicI32::new(0);
static LAST_MOUSE_Y: AtomicI32 = AtomicI32::new(0);
static DIRECT_CONTROLLER_EXPONENT: i32 = 1;
static DIRECT_CONTROLLER_MIN_SPEED: f32 = 0.0;

/// Failure to validate or transactionally install Atom's input hooks.
#[derive(Debug, Error)]
pub(crate) enum HookInstallError {
    /// A direct call could not be captured, chained, enabled, or rolled back.
    #[error(transparent)]
    Callsite(#[from] Rel32CallHookError),
    /// The live buffered keyboard capability could not be chained.
    #[error(transparent)]
    Buffered(#[from] buffered::BufferedInstallError),
    /// Enabling the buffered keyboard pointer slot failed.
    #[error(transparent)]
    Pointer(#[from] PointerSlotHookError),
    /// The shared bound-action provider could not be chained.
    #[error(transparent)]
    Inline(#[from] InlineHookError),
}

/// Addresses captured as typed predecessors during deferred installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct HookPredecessors {
    pub(super) sampler: usize,
    pub(super) mouse_x: usize,
    pub(super) mouse_y: usize,
    pub(super) heading_x: usize,
    pub(super) heading_y: usize,
    pub(super) controller_abs: usize,
    pub(super) keyboard_data: usize,
    pub(super) bound_action: usize,
}

/// Install the post-sample and player-camera hooks at DeferredInit.
pub(super) fn install() -> Result<HookPredecessors, HookInstallError> {
    unsafe {
        buffered::prepare(native::input_owner())?;
        SAMPLE_HOOK.init(
            "Atom post-xNVSE normal input sample",
            SAMPLE_CALLSITE as *mut c_void,
            sample_detour,
        )?;
        MOUSE_X_HOOK.init(
            "Atom player-camera mouse X",
            MOUSE_X_CALLSITE as *mut c_void,
            mouse_x_detour,
        )?;
        MOUSE_Y_HOOK.init(
            "Atom player-camera mouse Y",
            MOUSE_Y_CALLSITE as *mut c_void,
            mouse_y_detour,
        )?;
        HEADING_X_HOOK.init(
            "Atom player heading X",
            HEADING_X_CALLSITE as *mut c_void,
            heading_x_detour,
        )?;
        HEADING_Y_HOOK.init(
            "Atom player heading Y",
            HEADING_Y_CALLSITE as *mut c_void,
            heading_y_detour,
        )?;
        let abs_detours: [AbsFn; 4] = [
            controller_abs_0_detour,
            controller_abs_1_detour,
            controller_abs_2_detour,
            controller_abs_3_detour,
        ];
        for (index, ((hook, callsite), detour)) in CONTROLLER_ABS_HOOKS
            .iter()
            .zip(CONTROLLER_ABS_CALLSITES)
            .zip(abs_detours)
            .enumerate()
        {
            let name = match index {
                0 => "Atom alternate controller Y deadzone",
                1 => "Atom alternate controller X deadzone",
                2 => "Atom controller X deadzone",
                _ => "Atom controller Y deadzone",
            };
            hook.init(name, callsite as *mut c_void, detour)?;
        }
        CONTROLLER_X_EXPONENT_HOOK.init(
            "Atom controller X exponent",
            CONTROLLER_X_EXPONENT_CALLSITE as *mut c_void,
            controller_x_exponent_detour,
        )?;
        CONTROLLER_Y_EXPONENT_HOOK.init(
            "Atom controller Y exponent",
            CONTROLLER_Y_EXPONENT_CALLSITE as *mut c_void,
            controller_y_exponent_detour,
        )?;
        CONTROLLER_MIN_SPEED_HOOK.init(
            "Atom controller minimum speed",
            CONTROLLER_MIN_SPEED_CALLSITE as *mut c_void,
            controller_min_speed_detour,
        )?;
        BOUND_ACTION_HOOK.init(
            "Atom buffered bound-action bridge",
            BOUND_ACTION_ADDRESS as *mut c_void,
            bound_action_detour,
        )?;
    }

    let predecessors = HookPredecessors {
        sampler: SAMPLE_HOOK.predecessor_address()?,
        mouse_x: MOUSE_X_HOOK.predecessor_address()?,
        mouse_y: MOUSE_Y_HOOK.predecessor_address()?,
        heading_x: HEADING_X_HOOK.predecessor_address()?,
        heading_y: HEADING_Y_HOOK.predecessor_address()?,
        controller_abs: CONTROLLER_ABS_HOOKS[0].predecessor_address()?,
        keyboard_data: buffered::predecessor_address()?,
        bound_action: BOUND_ACTION_HOOK.original()? as *const () as usize,
    };
    let mut transaction = ModificationTransaction::new();
    transaction.enable_callsite(&SAMPLE_HOOK)?;
    transaction.enable_callsite(&MOUSE_X_HOOK)?;
    transaction.enable_callsite(&MOUSE_Y_HOOK)?;
    transaction.enable_callsite(&HEADING_X_HOOK)?;
    transaction.enable_callsite(&HEADING_Y_HOOK)?;
    for hook in &CONTROLLER_ABS_HOOKS {
        transaction.enable_callsite(hook)?;
    }
    transaction.enable_callsite(&CONTROLLER_X_EXPONENT_HOOK)?;
    transaction.enable_callsite(&CONTROLLER_Y_EXPONENT_HOOK)?;
    transaction.enable_callsite(&CONTROLLER_MIN_SPEED_HOOK)?;
    transaction.enable_pointer(buffered::hook())?;
    transaction.enable_inline(&BOUND_ACTION_HOOK)?;
    transaction.commit();
    register_audits();
    Ok(predecessors)
}

/// Register every committed input inline entry for post-activation audits.
///
/// Direct callsites and pointer slots are intentionally not byte-audited;
/// their health is behavioral (the actions they feed) rather than
/// byte-ownership.
fn register_audits() {
    integrity::register_inline("Atom buffered bound-action bridge", &BOUND_ACTION_HOOK);
}

unsafe extern "thiscall" fn sample_detour(input_owner: *mut c_void) {
    super::begin_native_sample();
    let predecessor = SAMPLE_HOOK.original().unwrap_or_else(|_| native_sampler());
    unsafe { predecessor(input_owner) };
    let keyboard_events = if super::input_enabled() {
        buffered::capture(0)
    } else {
        super::KeyboardEventBatch::EMPTY
    };
    if let Some(native) = unsafe { native::capture(input_owner) } {
        capture_native_sample(native, keyboard_events);
    }
}

unsafe extern "thiscall" fn mouse_x_detour(input_owner: *mut c_void, native_axis: u32) -> i32 {
    let predecessor = MOUSE_X_HOOK
        .original()
        .unwrap_or_else(|_| native_mouse_getter());
    let delta = unsafe { predecessor(input_owner, native_axis) };
    LAST_MOUSE_X.store(delta, Ordering::Relaxed);
    telemetry::mark_camera_consumer();
    delta
}

unsafe extern "thiscall" fn mouse_y_detour(input_owner: *mut c_void, native_axis: u32) -> i32 {
    let predecessor = MOUSE_Y_HOOK
        .original()
        .unwrap_or_else(|_| native_mouse_getter());
    let delta = unsafe { predecessor(input_owner, native_axis) };
    LAST_MOUSE_Y.store(delta, Ordering::Relaxed);
    delta
}

unsafe extern "thiscall" fn heading_x_detour(player: *mut c_void, native_heading: f32) {
    let predecessor = HEADING_X_HOOK
        .original()
        .unwrap_or_else(|_| native_heading_x_consumer());
    let heading = unsafe {
        transform_heading(
            player,
            MouseAxis::X,
            LAST_MOUSE_X.load(Ordering::Relaxed),
            native_heading,
        )
    };
    // Explore free orbit diverts yaw only after the camera epoch machine
    // admits stable third person. AIM/Combat retains native Actor yaw, then
    // copies its absolute result into the logical view and compensates the
    // camera-only offset before any later engine consumer can observe drift.
    if !crate::camera::consume_horizontal_heading(player, heading) {
        crate::camera::prepare_native_horizontal_heading(player);
        unsafe { predecessor(player, heading) };
        crate::camera::observe_native_horizontal_heading(player);
    }
}

unsafe extern "thiscall" fn heading_y_detour(player: *mut c_void, native_heading: f32) {
    let predecessor = HEADING_Y_HOOK
        .original()
        .unwrap_or_else(|_| native_heading_y_consumer());
    let heading = unsafe {
        transform_heading(
            player,
            MouseAxis::Y,
            LAST_MOUSE_Y.load(Ordering::Relaxed),
            native_heading,
        )
    };
    // Explore free orbit owns pitch without writing Actor rotX. Combat keeps
    // native Actor pitch so aim presentation and gameplay direction remain
    // coupled, then copies the native-clamped result into logical view state.
    // First-person, native-owned, and contended paths remain unchanged.
    if !crate::camera::consume_vertical_heading(player, heading) {
        crate::camera::prepare_native_vertical_heading(player);
        unsafe { predecessor(player, heading) };
        crate::camera::observe_native_vertical_heading(player);
    }
}

// Safety: player is the live this pointer from either admitted heading call.
unsafe fn transform_heading(
    player: *mut c_void,
    axis: MouseAxis,
    source_delta: i32,
    native_heading: f32,
) -> f32 {
    let (enabled, settings) = mouse_config();
    if !enabled || native::controller_mode() {
        return native_heading;
    }
    if settings.profile() == MouseProfile::Native {
        telemetry::record_mouse_heading(axis, source_delta, native_heading);
        return native_heading;
    }
    // These counts came from the native camera getters, not the keyboard
    // action mirror. Its sample/Present phase and cached context must not
    // select between native and configured mouse sensitivity. Preserve the
    // live look guard because native code can zero its locals after our
    // getter hooks, then still reach the yaw consumer.
    if !unsafe { native::mouse_heading_allowed(player) } {
        return native_heading;
    }
    let native_y_inverted = axis == MouseAxis::Y && native::vanilla_y_inverted();
    let mut input = MouseHeadingInput::new(axis, source_delta, native_heading, native_y_inverted);
    // Identity defaults need no extra HUD/process traversal or virtual call.
    // Optional context loss must not select native sensitivity after the live
    // look guard admitted the configured profile. The default Hip context
    // supplies neutral gain without caching a stale ADS/scope state.
    if settings.needs_context()
        && let Some(context) = unsafe { native::mouse_context(player) }
    {
        input = input.with_context(context);
    }
    let transformed = MouseTransform::new(settings).apply_heading(input);
    telemetry::record_mouse_heading(axis, source_delta, transformed);
    transformed
}

unsafe extern "C" fn controller_abs_0_detour(value: i32) -> i32 {
    controller_abs_result(&CONTROLLER_ABS_HOOKS[0], value)
}

unsafe extern "C" fn controller_abs_1_detour(value: i32) -> i32 {
    controller_abs_result(&CONTROLLER_ABS_HOOKS[1], value)
}

unsafe extern "C" fn controller_abs_2_detour(value: i32) -> i32 {
    controller_abs_result(&CONTROLLER_ABS_HOOKS[2], value)
}

unsafe extern "C" fn controller_abs_3_detour(value: i32) -> i32 {
    controller_abs_result(&CONTROLLER_ABS_HOOKS[3], value)
}

fn controller_abs_result(hook: &Rel32CallHookContainer<AbsFn>, value: i32) -> i32 {
    let predecessor = hook.original().unwrap_or_else(|_| native_abs());
    let absolute = unsafe { predecessor(value) };
    if controller_transform_active() && value != 0 {
        absolute.max(0x21F1)
    } else {
        absolute
    }
}

unsafe extern "thiscall" fn controller_x_exponent_detour(setting: *mut c_void) -> *const i32 {
    setting_int_result(
        &CONTROLLER_X_EXPONENT_HOOK,
        setting,
        &DIRECT_CONTROLLER_EXPONENT,
    )
}

unsafe extern "thiscall" fn controller_y_exponent_detour(setting: *mut c_void) -> *const i32 {
    setting_int_result(
        &CONTROLLER_Y_EXPONENT_HOOK,
        setting,
        &DIRECT_CONTROLLER_EXPONENT,
    )
}

fn setting_int_result(
    hook: &Rel32CallHookContainer<IntSettingFn>,
    setting: *mut c_void,
    direct: &'static i32,
) -> *const i32 {
    if controller_transform_active() {
        direct
    } else {
        let predecessor = hook.original().unwrap_or_else(|_| native_int_setting());
        unsafe { predecessor(setting) }
    }
}

unsafe extern "thiscall" fn controller_min_speed_detour(setting: *mut c_void) -> *const f32 {
    if controller_transform_active() {
        &DIRECT_CONTROLLER_MIN_SPEED
    } else {
        let predecessor = CONTROLLER_MIN_SPEED_HOOK
            .original()
            .unwrap_or_else(|_| native_float_setting());
        unsafe { predecessor(setting) }
    }
}

fn native_sampler() -> SamplerFn {
    unsafe { core::mem::transmute(native::NATIVE_SAMPLER_ADDRESS) }
}

fn native_mouse_getter() -> MouseGetterFn {
    unsafe { core::mem::transmute(native::NATIVE_MOUSE_GETTER_ADDRESS) }
}

fn native_heading_x_consumer() -> HeadingConsumerFn {
    unsafe { core::mem::transmute(0x0093_1D30usize) }
}

fn native_heading_y_consumer() -> HeadingConsumerFn {
    unsafe { core::mem::transmute(0x0093_1E50usize) }
}

fn native_abs() -> AbsFn {
    unsafe { core::mem::transmute(0x00EC_7D40usize) }
}

fn native_int_setting() -> IntSettingFn {
    unsafe { core::mem::transmute(0x0043_D4D0usize) }
}

fn native_float_setting() -> FloatSettingFn {
    unsafe { core::mem::transmute(0x0040_3E20usize) }
}

unsafe extern "thiscall" fn bound_action_detour(
    input_owner: *mut c_void,
    control: u32,
    state: u32,
) -> i32 {
    let native = match BOUND_ACTION_HOOK.original() {
        Ok(predecessor) => unsafe { predecessor(input_owner, control, state) },
        Err(_) => 0,
    };
    if native != 0
        || !super::action_bridge_open()
        || control >= super::ACTION_COUNT as u32
        || control == super::ActionId::MenuMode as u32
        || state > 3
    {
        return native;
    }

    let controller_active = super::controller_transform_active();
    // Held queries have no keyboard supplement. Preserve native priority and
    // avoid settings/frame reads when no controller supplement can answer.
    if state == 0 && !controller_active {
        return native;
    }
    let input_enabled = state != 0 && super::input_enabled();
    if !input_enabled && !controller_active {
        return native;
    }
    let (frame, action) = super::latest_action(super::ActionId::ALL[control as usize]);
    if frame.context() != super::ActionContext::Gameplay {
        return native;
    }
    let controller_down = action.sources().controller();
    let controller_pressed = action.pressed() && action.controller_pressed();
    let controller_released = action.released() && action.controller_released();
    let buffered_pressed = input_enabled && action.buffered_pressed();
    let buffered_released = input_enabled && action.buffered_released();
    match state {
        0 if controller_active => i32::from(controller_down),
        1 => i32::from(buffered_pressed || (controller_active && controller_pressed)),
        2 => i32::from(buffered_released || (controller_active && controller_released)),
        3 => i32::from(
            buffered_pressed
                || buffered_released
                || (controller_active && (controller_pressed || controller_released)),
        ),
        _ => native,
    }
}
