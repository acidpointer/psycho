//! Public behavioral acceptance checks for first-person motion.

use atom::camera::{CameraPose, FirstPersonConfig, LocomotionState, MotionGenerator, MotionInput};

fn enabled_config(extra: &str) -> FirstPersonConfig {
    FirstPersonConfig::from_ini(&format!(
        "[FirstPerson]\nbEnabled=1\nfCameraMotion=0.65\nfWeaponMotion=0.65\nfLandingMotion=0.45\nfAimMotion=0.20\n{extra}"
    ))
    .expect("valid first-person config")
}

fn input(dt: f32, velocity: [f32; 3], state: LocomotionState) -> MotionInput {
    MotionInput::new(dt, velocity, state, [0.0; 2], false, false)
}

fn pose_magnitude(pose: CameraPose) -> f32 {
    pose.translation()
        .into_iter()
        .chain(pose.rotation())
        .map(f32::abs)
        .sum()
}

#[test]
fn gait_phase_and_pose_are_stable_across_frame_partitions() {
    let config = enabled_config("");
    let partitions = [
        vec![1.0 / 30.0; 30],
        vec![1.0 / 60.0; 60],
        vec![1.0 / 120.0; 120],
        [0.05, 0.01, 0.02, 0.02].repeat(10),
    ];
    let results = partitions.map(|steps| {
        let mut generator = MotionGenerator::new();
        let motion = steps.into_iter().fold(Default::default(), |_, dt| {
            generator.update(
                input(dt, [120.0, 0.0, 0.0], LocomotionState::Grounded),
                config,
            )
        });
        (generator.gait_phase(), motion)
    });

    let (reference_phase, reference_motion) = results[0];
    for (phase, motion) in results.into_iter().skip(1) {
        assert!((reference_phase - phase).abs() < 1.0e-5);
        for (reference_pose, pose) in [
            (reference_motion.world_pose(), motion.world_pose()),
            (reference_motion.viewmodel_pose(), motion.viewmodel_pose()),
        ] {
            for (left, right) in reference_pose
                .translation()
                .into_iter()
                .chain(reference_pose.rotation())
                .zip(pose.translation().into_iter().chain(pose.rotation()))
            {
                assert!((left - right).abs() < 1.0e-4, "{left} != {right}");
            }
        }
    }
}

#[test]
fn support_relative_stillness_never_manufactures_platform_bob() {
    let config = enabled_config("");
    let mut generator = MotionGenerator::new();
    for _ in 0..120 {
        assert_eq!(
            generator
                .update(
                    input(1.0 / 60.0, [0.0; 3], LocomotionState::Grounded),
                    config,
                )
                .world_pose(),
            CameraPose::IDENTITY
        );
    }
}

#[test]
fn landing_emits_once_and_scales_with_downward_velocity() {
    fn landing_peak(downward_velocity: f32) -> f32 {
        let config = enabled_config("");
        let mut generator = MotionGenerator::new();
        for _ in 0..12 {
            let _ = generator.update(
                input(
                    1.0 / 60.0,
                    [0.0, 0.0, downward_velocity],
                    LocomotionState::Airborne,
                ),
                config,
            );
        }
        let mut minimum = 0.0_f32;
        for _ in 0..48 {
            let pose = generator
                .update(
                    input(1.0 / 60.0, [0.0; 3], LocomotionState::Grounded),
                    config,
                )
                .viewmodel_pose();
            minimum = minimum.min(pose.translation()[1]);
        }
        minimum.abs()
    }

    let soft = landing_peak(-180.0);
    let hard = landing_peak(-520.0);
    assert!(soft > 0.0);
    assert!(hard > soft);
}

#[test]
fn grounded_steps_never_manufacture_a_landing() {
    let config = enabled_config("");
    let mut generator = MotionGenerator::new();
    for _ in 0..120 {
        assert_eq!(
            generator
                .update(
                    input(1.0 / 60.0, [0.0; 3], LocomotionState::Grounded),
                    config,
                )
                .viewmodel_pose(),
            CameraPose::IDENTITY
        );
    }
}

#[test]
fn native_aiming_converges_toward_the_configured_motion_fraction() {
    let config = enabled_config("");
    let mut hip = MotionGenerator::new();
    let mut aim = MotionGenerator::new();
    let mut hip_pose = CameraPose::IDENTITY;
    let mut aim_pose = CameraPose::IDENTITY;
    for _ in 0..90 {
        hip_pose = hip
            .update(
                MotionInput::new(
                    1.0 / 60.0,
                    [120.0, 0.0, 0.0],
                    LocomotionState::Grounded,
                    [0.0; 2],
                    false,
                    false,
                ),
                config,
            )
            .viewmodel_pose();
        aim_pose = aim
            .update(
                MotionInput::new(
                    1.0 / 60.0,
                    [120.0, 0.0, 0.0],
                    LocomotionState::Grounded,
                    [0.0; 2],
                    true,
                    false,
                ),
                config,
            )
            .viewmodel_pose();
    }

    let ratio = pose_magnitude(aim_pose) / pose_magnitude(hip_pose);
    assert!((ratio - config.aim_motion()).abs() < 0.02, "ratio={ratio}");
}

#[test]
fn zero_gain_and_invalid_samples_are_exact_identity_boundaries() {
    let zero = enabled_config("fCameraMotion=0\nfWeaponMotion=0\n");
    let enabled = enabled_config("");
    let mut generator = MotionGenerator::new();

    let _ = generator.update(
        input(1.0 / 60.0, [150.0, 0.0, 0.0], LocomotionState::Grounded),
        enabled,
    );
    assert!(generator.gait_phase() > 0.0);

    assert_eq!(
        generator
            .update(
                input(1.0 / 60.0, [150.0, 0.0, 0.0], LocomotionState::Grounded),
                zero,
            )
            .viewmodel_pose(),
        CameraPose::IDENTITY
    );
    let _ = generator.update(
        input(1.0 / 60.0, [150.0, 0.0, 0.0], LocomotionState::Grounded),
        enabled,
    );
    assert!(generator.gait_phase() > 0.0);
    assert_eq!(
        generator
            .update(
                input(f32::NAN, [150.0, 0.0, 0.0], LocomotionState::Grounded),
                enabled,
            )
            .viewmodel_pose(),
        CameraPose::IDENTITY
    );
    assert_eq!(generator.gait_phase(), 0.0);
}

#[test]
fn configuration_rejects_non_finite_and_invalid_boolean_values() {
    assert!(FirstPersonConfig::from_ini("[FirstPerson]\nbEnabled=2\n").is_err());
    assert!(FirstPersonConfig::from_ini("[FirstPerson]\nfCameraMotion=NaN\n").is_err());
    assert!(FirstPersonConfig::from_ini("[FirstPerson]\nfWeaponMotion=NaN\n").is_err());

    let bounded = FirstPersonConfig::from_ini(
        "[FirstPerson]\nbEnabled=1\nfCameraMotion=8\nfWeaponMotion=8\nfLandingMotion=-2\nfAimMotion=4\n",
    )
    .expect("finite values are bounded");
    assert_eq!(bounded.camera_motion(), 1.0);
    assert_eq!(bounded.weapon_motion(), 1.0);
    assert_eq!(bounded.landing_motion(), 0.0);
    assert_eq!(bounded.aim_motion(), 1.0);
}

#[test]
fn grounded_movement_generates_bounded_world_head_motion() {
    let config = enabled_config("");
    let mut generator = MotionGenerator::new();
    let mut largest = 0.0_f32;

    for _ in 0..180 {
        let pose = generator
            .update(
                input(1.0 / 60.0, [120.0, 0.0, 0.0], LocomotionState::Grounded),
                config,
            )
            .world_pose();
        let [forward, up, right] = pose.translation();
        let [roll, yaw, pitch] = pose.rotation();
        largest = largest.max(forward.abs() + up.abs() + right.abs() + roll.abs());
        assert_eq!(forward, 0.0);
        assert!(up.abs() <= 0.50);
        assert!(right.abs() <= 0.15);
        assert_eq!(roll, 0.0);
        assert_eq!(yaw, 0.0);
        assert_eq!(pitch, 0.0);
    }

    assert!(largest > 0.05, "head motion must be visibly non-identity");
}

#[test]
fn extreme_native_speed_cannot_turn_head_bob_into_rapid_shake() {
    const MAX_FULL_STRIDE_HZ: f64 = 1.6;
    const MAX_WORLD_TRANSLATION_SPEED: f32 = 6.7;

    for dt in [1.0 / 30.0, 1.0 / 60.0, 1.0 / 120.0] {
        let config = enabled_config("fCameraMotion=1\n");
        assert_eq!(config.camera_motion(), 1.0);
        let mut generator = MotionGenerator::new();
        let extreme = input(dt, [20_000.0, 0.0, 0.0], LocomotionState::Grounded);

        // Settle both analytic filters before measuring the steady maximum.
        for _ in 0..(2.0 / dt) as usize {
            let _ = generator.update(extreme, config);
        }

        let mut prior_pose = generator.update(extreme, config).world_pose();
        let mut prior_phase = generator.gait_phase();
        for _ in 0..(2.0 / dt) as usize {
            let pose = generator.update(extreme, config).world_pose();
            let phase = generator.gait_phase();
            let phase_step = (phase - prior_phase).rem_euclid(core::f64::consts::TAU);
            assert!(
                phase_step <= core::f64::consts::TAU * MAX_FULL_STRIDE_HZ * f64::from(dt) + 1.0e-6,
                "phase step {phase_step} exceeded the cadence cap at dt={dt}",
            );

            let [forward, up, right] = pose.translation();
            let [prior_forward, prior_up, prior_right] = prior_pose.translation();
            let translation_speed = ((forward - prior_forward).powi(2)
                + (up - prior_up).powi(2)
                + (right - prior_right).powi(2))
            .sqrt()
                / dt;
            assert!(
                translation_speed <= MAX_WORLD_TRANSLATION_SPEED,
                "world motion speed {translation_speed} exceeded the smoothness bound at dt={dt}",
            );
            assert_eq!(pose.rotation(), [0.0; 3]);

            prior_phase = phase;
            prior_pose = pose;
        }
    }
}

#[test]
fn camera_and_weapon_gains_are_independent_exact_zero_boundaries() {
    let camera_off = enabled_config("fCameraMotion=0\n");
    let weapon_off = enabled_config("fWeaponMotion=0\n");
    let mut camera_off_generator = MotionGenerator::new();
    let mut weapon_off_generator = MotionGenerator::new();
    let mut camera_off_motion = Default::default();
    let mut weapon_off_motion = Default::default();

    for _ in 0..90 {
        camera_off_motion = camera_off_generator.update(
            input(1.0 / 60.0, [120.0, 0.0, 0.0], LocomotionState::Grounded),
            camera_off,
        );
        weapon_off_motion = weapon_off_generator.update(
            input(1.0 / 60.0, [120.0, 0.0, 0.0], LocomotionState::Grounded),
            weapon_off,
        );
    }

    assert_eq!(camera_off_motion.world_pose(), CameraPose::IDENTITY);
    assert!(!camera_off_motion.viewmodel_pose().is_identity());
    assert!(!weapon_off_motion.world_pose().is_identity());
    assert_eq!(weapon_off_motion.viewmodel_pose(), CameraPose::IDENTITY);
}

#[test]
fn aiming_suppresses_world_motion_exactly() {
    let config = enabled_config("");
    let mut generator = MotionGenerator::new();
    for _ in 0..45 {
        let motion = generator.update(
            input(1.0 / 60.0, [120.0, 0.0, 0.0], LocomotionState::Grounded),
            config,
        );
        assert!(!motion.world_pose().is_identity());
    }

    let aiming = generator.update(
        MotionInput::new(
            1.0 / 60.0,
            [120.0, 0.0, 0.0],
            LocomotionState::Grounded,
            [0.0; 2],
            true,
            false,
        ),
        config,
    );
    assert_eq!(aiming.world_pose(), CameraPose::IDENTITY);
    assert!(!aiming.viewmodel_pose().is_identity());
}

#[test]
fn stopped_motion_settles_to_exact_native_identity() {
    let config = enabled_config("");
    let mut generator = MotionGenerator::new();
    for _ in 0..60 {
        let _ = generator.update(
            input(1.0 / 60.0, [120.0, 0.0, 0.0], LocomotionState::Grounded),
            config,
        );
    }

    let mut settled = Default::default();
    for _ in 0..180 {
        settled = generator.update(
            input(1.0 / 60.0, [0.0; 3], LocomotionState::Grounded),
            config,
        );
    }

    assert_eq!(settled.world_pose(), CameraPose::IDENTITY);
    assert_eq!(settled.viewmodel_pose(), CameraPose::IDENTITY);
}
