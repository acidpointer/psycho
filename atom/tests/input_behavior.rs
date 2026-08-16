//! Behavioral acceptance tests for Atom's public input boundary.

use atom::input::{
    ActionContext, ActionId, ControllerProcessor, DirectInputEvent, FALLOUT4_RADIANS_PER_COUNT,
    InputConfig, InputDevice, InputPipeline, KeyboardEventBatch, MouseAxis, MouseHeadingInput,
    MouseProfile, MouseTransform, NativeControllerState, NativeInputState, NativeMouseState,
};

fn config_with(body: &str) -> InputConfig {
    InputConfig::from_ini(body).expect("behavioral fixture must be valid MCM INI")
}

#[test]
fn mcm_ini_deserializes_typed_sections_defaults_and_unknown_data() {
    let config = config_with(
        r#"
            RootValue = retained-by-mcm

            [Input]
            bEnabled = 1
            iFutureSetting = 73

            [Mouse]
            iProfile = 1
            fSensitivity = 1.75
            bInvertX = 1

            [FutureSection]
            sOwner = MCM
        "#,
    );

    assert!(config.enabled());
    assert_eq!(config.mouse().profile(), MouseProfile::Direct);
    assert_eq!(config.mouse().sensitivity(), 1.75);
    assert!(config.mouse().invert_x());
    assert_eq!(config.mouse().vertical_scale(), 1.0);
    assert_eq!(config.controller(), InputConfig::default().controller());
}

#[test]
fn malformed_or_non_finite_mcm_values_are_rejected_before_publication() {
    let boolean = InputConfig::from_ini("[Input]\nbEnabled = 2\n")
        .expect_err("numeric MCM booleans are restricted to zero and one");
    assert!(
        boolean
            .to_string()
            .contains("Input:bEnabled must be 0 or 1")
    );

    let profile = InputConfig::from_ini("[Mouse]\niProfile = 9\n")
        .expect_err("unknown transforms must not become native hooks");
    assert!(profile.to_string().contains("profile must be 0, 1, or 2"));

    let non_finite = InputConfig::from_ini("[Mouse]\nfSensitivity = NaN\n")
        .expect_err("NaN would poison camera arithmetic");
    assert!(
        non_finite
            .to_string()
            .contains("fSensitivity must be finite")
    );
}

#[test]
fn recognized_mcm_values_are_bounded_and_trigger_hysteresis_remains_ordered() {
    let config = config_with(
        r#"
            [Mouse]
            fSensitivity = 99
            fHorizontalScale = 0.001

            [Controller]
            fLeftDeadzone = -1
            fRightDeadzone = 2
            fResponseExponent = 99
            fAntiDeadzone = 1
            fOutputSaturation = 0
            fTriggerPress = 0.04
            fTriggerRelease = 0.9
        "#,
    );

    assert_eq!(config.mouse().sensitivity(), 8.0);
    assert_eq!(config.mouse().horizontal_scale(), 0.1);
    assert_eq!(config.controller().left_deadzone(), 0.0);
    assert_eq!(config.controller().right_deadzone(), 0.95);
    assert_eq!(config.controller().response_exponent(), 4.0);
    assert_eq!(config.controller().anti_deadzone(), 0.75);
    assert_eq!(config.controller().output_saturation(), 0.25);
    assert_eq!(config.controller().trigger_press(), 0.04);
    assert_eq!(config.controller().trigger_release(), 0.03);
}

#[test]
fn direct_mouse_is_history_free_symmetric_and_native_is_exact() {
    let direct = config_with(
        r#"
            [Mouse]
            iProfile = 2
            fSensitivity = 1.25
            fHorizontalScale = 1.2
            fVerticalScale = 0.8
        "#,
    );
    let transform = MouseTransform::new(direct.mouse());
    for delta in -2_000..=2_000 {
        assert_eq!(
            transform.apply(MouseAxis::X, -delta, false),
            -transform.apply(MouseAxis::X, delta, false)
        );
    }
    assert_eq!(transform.apply(MouseAxis::X, 1, false), 2);
    assert_eq!(transform.apply(MouseAxis::Y, 1, false), 1);
    assert_eq!(transform.apply(MouseAxis::X, 400, false), 600);
    assert_eq!(transform.apply(MouseAxis::X, 400, false), 600);

    let native = config_with("[Mouse]\niProfile = 0\nfSensitivity = 8\nbInvertX = 1\n");
    let native = MouseTransform::new(native.mouse());
    for delta in [i32::MIN, -1_000_000, -1, 0, 1, 1_000_000, i32::MAX] {
        assert_eq!(native.apply(MouseAxis::X, delta, false), delta);
        assert_eq!(native.apply(MouseAxis::Y, delta, true), delta);
    }
}

#[test]
fn fallout4_mouse_profile_uses_the_calibrated_float_heading_boundary() {
    let transform = MouseTransform::new(InputConfig::default().mouse());
    for delta in -2_000..=2_000 {
        let heading =
            transform.apply_heading(MouseHeadingInput::new(MouseAxis::X, delta, 123.0, false));
        assert_eq!(heading, delta as f32 * FALLOUT4_RADIANS_PER_COUNT);
    }

    let direct =
        MouseTransform::new(config_with("[Mouse]\niProfile = 1\nfSensitivity = 1.5\n").mouse());
    assert_eq!(
        direct.apply_heading(MouseHeadingInput::new(MouseAxis::X, 400, 0.25, false)),
        0.375
    );
}

#[test]
fn mouse_y_compensates_the_later_vanilla_inversion_exactly_once() {
    let normal = MouseTransform::new(config_with("[Mouse]\nbInvertY = 0\n").mouse());
    assert_eq!(normal.apply(MouseAxis::Y, 17, false), 17);
    assert_eq!(normal.apply(MouseAxis::Y, 17, true), -17);

    let inverted = MouseTransform::new(config_with("[Mouse]\nbInvertY = 1\n").mouse());
    assert_eq!(inverted.apply(MouseAxis::Y, 17, false), -17);
    assert_eq!(inverted.apply(MouseAxis::Y, 17, true), 17);
}

#[test]
fn radial_controller_processing_is_monotonic_direction_preserving_and_bounded() {
    let settings = config_with(
        r#"
            [Controller]
            fLeftDeadzone = 0.15
            fRightDeadzone = 0.12
            fResponseExponent = 1.35
            fAntiDeadzone = 0
            fOutputSaturation = 1
        "#,
    )
    .controller();
    let processor = ControllerProcessor::new();

    for angle_index in 0..16 {
        let angle = angle_index as f32 * core::f32::consts::TAU / 16.0;
        let mut previous_magnitude = 0.0;
        for raw_magnitude in (0..=32_767).step_by(257) {
            let raw_x = (angle.cos() * raw_magnitude as f32).round() as i16;
            let raw_y = (angle.sin() * raw_magnitude as f32).round() as i16;
            let frame = processor.process(
                NativeControllerState::new(1, 0, 0, 0, raw_x, raw_y, raw_x, raw_y),
                settings,
            );
            let output = frame.right_stick();
            assert!(output.x().is_finite() && output.y().is_finite());
            assert!(output.magnitude() <= 1.000_01);
            assert!(output.magnitude() + 0.000_01 >= previous_magnitude);
            previous_magnitude = output.magnitude();

            if output.magnitude() > 0.001 {
                let input_x = if raw_x >= 0 {
                    f32::from(raw_x) / f32::from(i16::MAX)
                } else {
                    f32::from(raw_x) / 32_768.0
                };
                let input_y = if raw_y >= 0 {
                    f32::from(raw_y) / f32::from(i16::MAX)
                } else {
                    f32::from(raw_y) / 32_768.0
                };
                let cross = input_x * output.y() - input_y * output.x();
                assert!(cross.abs() < 0.000_1);
            }
        }
    }
}

#[test]
fn trigger_hysteresis_emits_one_press_and_release_across_threshold_noise() {
    let settings = InputConfig::default().controller();
    let processor = ControllerProcessor::new();
    let sample = |raw| {
        processor
            .process(
                NativeControllerState::new(1, 0, raw, 0, 0, 0, 0, 0),
                settings,
            )
            .left_trigger()
    };

    assert!(!sample(29).down());
    let pressed = sample(31);
    assert!(pressed.down() && pressed.pressed() && !pressed.released());
    for raw in [29, 27, 30, 24, 22, 25] {
        let held = sample(raw);
        assert!(held.down() && !held.pressed() && !held.released());
    }
    let released = sample(20);
    assert!(!released.down() && !released.pressed() && released.released());
    assert!(!sample(22).down());
}

#[test]
fn pipeline_publishes_one_coherent_snapshot_with_device_edges() {
    let mut current_keys = [0; 256];
    let mut previous_keys = [0; 256];
    current_keys[30] = 0x80;
    previous_keys[31] = 0x80;
    let current_mouse = NativeMouseState::new(13, -7, 120, [0x80, 0, 0x80, 0, 0, 0, 0, 0]);
    let previous_mouse = NativeMouseState::new(0, 0, 0, [0, 0x80, 0x80, 0, 0, 0, 0, 0]);
    let controller = NativeControllerState::new(42, 0x1000, 64, 0, 16_000, 0, 0, -16_000);
    let pipeline = InputPipeline::new();

    let frame = pipeline.capture(
        NativeInputState::new(
            current_keys,
            previous_keys,
            current_mouse,
            previous_mouse,
            controller,
        ),
        InputConfig::default().controller(),
    );

    assert_eq!(frame.frame_id(), 1);
    assert!(frame.key_down(30) && frame.key_pressed(30));
    assert!(!frame.key_down(31) && frame.key_released(31));
    assert_eq!(frame.mouse().x(), 13);
    assert_eq!(frame.mouse().y(), -7);
    assert_eq!(frame.mouse().wheel(), 120);
    assert_eq!(frame.mouse().buttons_down(), 0b0000_0101);
    assert_eq!(frame.mouse().buttons_pressed(), 0b0000_0001);
    assert_eq!(frame.mouse().buttons_released(), 0b0000_0010);
    assert_eq!(frame.controller().raw(), controller);
    assert_eq!(pipeline.latest(), frame);
}

#[test]
fn action_layer_merges_devices_without_mode_gating_or_duplicate_edges() {
    let pipeline = InputPipeline::new();
    let mut keyboard_bindings = [u8::MAX; 28];
    let mouse_bindings = [u8::MAX; 28];
    let mut controller_bindings = [u8::MAX; 28];
    keyboard_bindings[ActionId::Forward as usize] = 17;
    controller_bindings[ActionId::Forward as usize] = 10;

    pipeline.capture(
        native_with(
            [0; 256],
            [0; 256],
            NativeControllerState::default(),
            NativeControllerState::default(),
            keyboard_bindings,
            mouse_bindings,
            controller_bindings,
            true,
            false,
        ),
        InputConfig::default().controller(),
    );

    let mut keys = [0; 256];
    keys[17] = 0x80;
    pipeline.capture(
        native_with(
            keys,
            [0; 256],
            NativeControllerState::new(1, 0x1000, 0, 0, 0, 0, 0, 0),
            NativeControllerState::default(),
            keyboard_bindings,
            mouse_bindings,
            controller_bindings,
            true,
            false,
        ),
        InputConfig::default().controller(),
    );
    let merged = pipeline.latest_actions();
    let forward = merged.action(ActionId::Forward);
    assert!(forward.down() && forward.pressed() && !forward.released());
    assert!(forward.sources().keyboard() && forward.sources().controller());
    assert_eq!(merged.last_active_device(), InputDevice::KeyboardMouse);

    pipeline.capture(
        native_with(
            [0; 256],
            keys,
            NativeControllerState::new(2, 0x1000, 0, 0, 0, 0, 0, 0),
            NativeControllerState::new(1, 0x1000, 0, 0, 0, 0, 0, 0),
            keyboard_bindings,
            mouse_bindings,
            controller_bindings,
            true,
            false,
        ),
        InputConfig::default().controller(),
    );
    let controller_only = pipeline.latest_actions().action(ActionId::Forward);
    assert!(controller_only.down());
    assert!(!controller_only.pressed() && !controller_only.released());
    assert!(!controller_only.sources().keyboard() && controller_only.sources().controller());

    pipeline.capture(
        native_with(
            [0; 256],
            [0; 256],
            NativeControllerState::new(3, 0, 0, 0, 0, 0, 0, 0),
            NativeControllerState::new(2, 0x1000, 0, 0, 0, 0, 0, 0),
            keyboard_bindings,
            mouse_bindings,
            controller_bindings,
            true,
            false,
        ),
        InputConfig::default().controller(),
    );
    let released = pipeline.latest_actions().action(ActionId::Forward);
    assert!(!released.down() && !released.pressed() && released.released());
}

#[test]
fn processed_stick_actions_begin_at_the_radial_deadzone_boundary() {
    let pipeline = InputPipeline::new();
    let unbound = [u8::MAX; 28];
    let mut controller_bindings = unbound;
    controller_bindings[ActionId::SlideRight as usize] = 22;
    pipeline.capture(
        native_with(
            [0; 256],
            [0; 256],
            NativeControllerState::default(),
            NativeControllerState::default(),
            unbound,
            unbound,
            controller_bindings,
            true,
            false,
        ),
        InputConfig::default().controller(),
    );
    let frame = pipeline.capture(
        native_with(
            [0; 256],
            [0; 256],
            NativeControllerState::new(1, 0, 0, 0, 6_000, 0, 0, 0),
            NativeControllerState::default(),
            unbound,
            unbound,
            controller_bindings,
            true,
            false,
        ),
        InputConfig::default().controller(),
    );
    let encoded = frame.controller().native_output().left_x();
    assert!(encoded > 0 && encoded < 8_689);
    let action = pipeline.latest_actions().action(ActionId::SlideRight);
    assert!(action.down() && action.pressed() && action.controller_pressed());
}

#[test]
fn focus_epochs_neutralize_held_controls_until_a_real_release() {
    let pipeline = InputPipeline::new();
    let mut keyboard_bindings = [u8::MAX; 28];
    keyboard_bindings[ActionId::Use as usize] = 30;
    let unbound = [u8::MAX; 28];
    let released_keys = [0; 256];
    let mut held_keys = [0; 256];
    held_keys[30] = 0x80;

    let sample = |current, previous, focused, menu_mode| {
        native_with(
            current,
            previous,
            NativeControllerState::default(),
            NativeControllerState::default(),
            keyboard_bindings,
            unbound,
            unbound,
            focused,
            menu_mode,
        )
    };
    pipeline.capture(
        sample(released_keys, released_keys, true, false),
        InputConfig::default().controller(),
    );
    pipeline.capture(
        sample(held_keys, released_keys, true, false),
        InputConfig::default().controller(),
    );
    assert!(pipeline.latest_actions().action(ActionId::Use).pressed());

    pipeline.capture(
        sample(held_keys, held_keys, false, false),
        InputConfig::default().controller(),
    );
    let lost = pipeline.latest_actions();
    assert_eq!(lost.context(), ActionContext::Unfocused);
    assert_eq!(lost.focus_epoch(), 1);
    assert!(!lost.action(ActionId::Use).released());

    pipeline.capture(
        sample(held_keys, held_keys, true, false),
        InputConfig::default().controller(),
    );
    let reacquired = pipeline.latest_actions();
    assert!(!reacquired.action(ActionId::Use).down());
    assert!(!reacquired.action(ActionId::Use).pressed());

    pipeline.capture(
        sample(released_keys, held_keys, true, false),
        InputConfig::default().controller(),
    );
    assert!(!pipeline.latest_actions().action(ActionId::Use).released());
    pipeline.capture(
        sample(held_keys, released_keys, true, false),
        InputConfig::default().controller(),
    );
    assert!(pipeline.latest_actions().action(ActionId::Use).pressed());

    pipeline.capture(
        sample(released_keys, held_keys, true, true),
        InputConfig::default().controller(),
    );
    assert_eq!(pipeline.latest_actions().context(), ActionContext::Menu);
}

#[test]
fn buffered_keyboard_taps_preserve_both_edges_in_order() {
    let pipeline = InputPipeline::new();
    let mut keyboard_bindings = [u8::MAX; 28];
    keyboard_bindings[ActionId::Jump as usize] = 57;
    let unbound = [u8::MAX; 28];
    let neutral = native_with(
        [0; 256],
        [0; 256],
        NativeControllerState::default(),
        NativeControllerState::default(),
        keyboard_bindings,
        unbound,
        unbound,
        true,
        false,
    );
    pipeline.capture(neutral, InputConfig::default().controller());

    let events = [
        DirectInputEvent::new(57, 0x80, 100, 10, 0),
        DirectInputEvent::new(57, 0x00, 101, 11, 0),
    ];
    let batch = KeyboardEventBatch::from_events(0, &events);
    pipeline.capture_with_keyboard_events(neutral, InputConfig::default().controller(), batch);
    let jump = pipeline.latest_actions().action(ActionId::Jump);
    assert!(!jump.down());
    assert!(jump.pressed() && jump.released());
    assert!(jump.sources().keyboard());
    assert!(jump.buffered_pressed() && jump.buffered_released());
}

#[test]
fn keyboard_batches_keep_the_newest_native_capacity_after_overflow() {
    let events = (0..40)
        .map(|sequence| DirectInputEvent::new(sequence, 0x80, sequence, sequence, 0))
        .collect::<Vec<_>>();
    let batch = KeyboardEventBatch::from_events(7, &events);
    assert!(batch.overflowed());
    assert_eq!(batch.events().len(), 32);
    assert_eq!(batch.events().first().unwrap().sequence(), 8);
    assert_eq!(batch.events().last().unwrap().sequence(), 39);
}

#[allow(clippy::too_many_arguments)]
fn native_with(
    keyboard_current: [u8; 256],
    keyboard_previous: [u8; 256],
    controller_current: NativeControllerState,
    controller_previous: NativeControllerState,
    keyboard_bindings: [u8; 28],
    mouse_bindings: [u8; 28],
    controller_bindings: [u8; 28],
    focused: bool,
    menu_mode: bool,
) -> NativeInputState {
    NativeInputState::from_engine(
        keyboard_current,
        keyboard_previous,
        NativeMouseState::default(),
        NativeMouseState::default(),
        controller_current,
        controller_previous,
        keyboard_bindings,
        mouse_bindings,
        controller_bindings,
        false,
        focused,
        menu_mode,
    )
}
