//! Public behavioral acceptance checks for third-person ownership and math.

use core::f32::consts::{FRAC_PI_2, PI};

use atom::camera::third_person::{
    AimAngles, FacingPolicy, FollowSolver, MovementIntent, OwnershipInput, OwnershipMachine,
    OwnershipState, SpringAxis, ThirdPersonConfig, Vec3, camera_relative_heading, converge_angles,
    remap_movement, step_heading, wrap_angle,
};

fn fnv_world_vector(local: Vec3, actor_yaw: f32) -> Vec3 {
    let (sin_yaw, cos_yaw) = actor_yaw.sin_cos();
    Vec3::new(
        cos_yaw.mul_add(local.x, sin_yaw * local.y),
        (-sin_yaw).mul_add(local.x, cos_yaw * local.y),
        local.z,
    )
}

fn assert_vec3_close(actual: Vec3, expected: Vec3) {
    assert!((actual.x - expected.x).abs() < 0.000_01);
    assert!((actual.y - expected.y).abs() < 0.000_01);
    assert!((actual.z - expected.z).abs() < 0.000_01);
}

fn normal(cell: u32, combat: bool) -> OwnershipInput {
    OwnershipInput::new(true, true, false, true, combat, cell)
}

#[test]
fn native_owners_release_immediately_and_reacquire_through_a_seed_frame() {
    let mut machine = OwnershipMachine::new();
    assert_eq!(
        machine.advance(normal(1, false)).current(),
        OwnershipState::Acquire
    );
    assert_eq!(
        machine.advance(normal(1, false)).current(),
        OwnershipState::Explore
    );
    let owned_epoch = machine.epoch();

    for vats_mode in 1..=4 {
        let vats = OwnershipInput::new(true, true, true, true, false, 1);
        let state = machine.advance(vats).current();
        assert!(
            !state.is_owned(),
            "VATS mode {vats_mode} retained Atom ownership"
        );
        assert_eq!(machine.advance(vats).current(), OwnershipState::Native);
        assert_eq!(
            machine.advance(normal(1, false)).current(),
            OwnershipState::Acquire
        );
        assert_eq!(
            machine.advance(normal(1, true)).current(),
            OwnershipState::Combat
        );
    }
    assert!(machine.epoch().wrapping_sub(owned_epoch) >= 2);
}

#[test]
fn cell_change_and_live_disable_discard_the_owned_epoch() {
    let mut machine = OwnershipMachine::new();
    machine.advance(normal(10, false));
    machine.advance(normal(10, false));
    let first_epoch = machine.epoch();

    assert_eq!(
        machine.advance(normal(11, false)).current(),
        OwnershipState::Release
    );
    assert!(!machine.state().is_owned());
    assert_ne!(machine.epoch(), first_epoch);
    assert_eq!(
        machine
            .advance(OwnershipInput::new(false, true, false, true, false, 11))
            .current(),
        OwnershipState::Native
    );
}

#[test]
fn analytic_spring_is_equivalent_across_common_frame_partitions() {
    fn advance(steps: usize, dt: f32) -> SpringAxis {
        let mut spring = SpringAxis::at(-3.0);
        for _ in 0..steps {
            spring.advance(17.0, 7.5, dt);
        }
        spring
    }

    let reference = advance(1, 1.0 / 30.0);
    for candidate in [advance(2, 1.0 / 60.0), advance(4, 1.0 / 120.0)] {
        assert!((candidate.position() - reference.position()).abs() < 0.000_01);
        assert!((candidate.velocity() - reference.velocity()).abs() < 0.000_1);
    }
}

#[test]
fn camera_relative_mapping_preserves_magnitude_and_unowned_flags() {
    let native = Vec3::new(0.0, 0.75, -0.2);
    let high_flags = 0xA5A5_0000;
    for yaw in [0.0, FRAC_PI_2, PI, -FRAC_PI_2] {
        let explore = remap_movement(native, high_flags | 0x0A, 0.0, yaw, FacingPolicy::Explore);
        assert!((explore.vector().horizontal_length() - 0.75).abs() < 0.000_01);
        assert_eq!(explore.flags() & !0x0F, high_flags);
        assert_eq!(explore.flags() & 0x0F, 0x01);
        assert!((wrap_angle(explore.movement_heading().unwrap() - yaw)).abs() < 0.000_01);

        let combat = remap_movement(native, high_flags | 0x0A, 0.0, yaw, FacingPolicy::Combat);
        assert_eq!(combat.flags(), high_flags | 0x0A);
    }
}

#[test]
fn movement_compensation_uses_the_facing_that_reaches_the_native_request() {
    let native_vectors = [
        Vec3::new(0.0, 1.0, 0.0),
        Vec3::new(-1.0, 0.0, 0.25),
        Vec3::new(0.6, 0.8, -0.5),
    ];
    let headings = [(FRAC_PI_2, -FRAC_PI_2), (-2.3, 0.7), (PI - 0.1, -PI + 0.2)];

    for native in native_vectors {
        for (view_yaw, request_actor_yaw) in headings {
            let output = remap_movement(
                native,
                0x8A00_0005,
                request_actor_yaw,
                view_yaw,
                FacingPolicy::Combat,
            );
            let actual_world = fnv_world_vector(output.vector(), request_actor_yaw);
            let expected_world = fnv_world_vector(native, view_yaw);
            assert_vec3_close(actual_world, expected_world);
            assert!(
                wrap_angle(
                    output.movement_heading().expect("nonzero input heading")
                        - expected_world.x.atan2(expected_world.y),
                )
                .abs()
                    < 0.000_01
            );
        }
    }

    assert!(camera_relative_heading(Vec3::default(), 1.0).is_none());
}

#[test]
fn movement_intent_resolves_against_observed_not_requested_facing() {
    let native = Vec3::new(0.6, 0.8, -0.25);
    let view_yaw = 1.7;
    let old_actor_yaw = -0.9;
    let requested_actor_yaw = 0.4;
    let intent = MovementIntent::new(native, 0xA500_000A, view_yaw, FacingPolicy::Explore);
    assert_eq!(intent.facing_target(), intent.movement_heading());

    // A rejected setter leaves raw rotZ unchanged. Resolution against that
    // observed value still produces the exact intended world vector.
    let rejected = intent.resolve(old_actor_yaw);
    assert_vec3_close(
        fnv_world_vector(rejected.vector(), old_actor_yaw),
        fnv_world_vector(native, view_yaw),
    );

    // A native setter may normalize to a value different from the requested
    // one. Only the observed post-setter heading is authoritative.
    let normalized_actor_yaw = wrap_angle(requested_actor_yaw + 2.0 * PI);
    let normalized = intent.resolve(normalized_actor_yaw);
    assert_vec3_close(
        fnv_world_vector(normalized.vector(), normalized_actor_yaw),
        fnv_world_vector(native, view_yaw),
    );
    assert_eq!(normalized.flags(), 0xA500_0001);
}

#[test]
fn follow_and_movement_settings_are_independent() {
    for (follow, movement) in [(false, false), (true, false), (false, true), (true, true)] {
        let config = ThirdPersonConfig::from_ini(&format!(
            "[Camera]\nbFollowCamera={}\n[Movement]\nb360Movement={}\n",
            u8::from(follow),
            u8::from(movement),
        ))
        .expect("valid feature combination");
        assert_eq!(config.follow_enabled(), follow);
        assert_eq!(config.movement_enabled(), movement);
        assert_eq!(config.enabled(), follow || movement);
    }
}

#[test]
fn follow_solver_lags_settles_and_resets_on_teleport() {
    let config = ThirdPersonConfig::from_ini(
        "[Camera]\n\
         bFollowCamera=1\n\
         fFollowSpeed=7.5\n\
         fSoftZone=0\n\
         fLookAhead=0\n",
    )
    .expect("valid follow settings");
    let mut solver = FollowSolver::new();
    solver.reset(Vec3::new(0.0, 0.0, 0.0));

    let moving = solver.advance(Vec3::new(0.0, 20.0, 0.0), 0.0, 1.0 / 60.0, config);
    assert!(moving.y > 0.0 && moving.y < 20.0);
    for _ in 0..240 {
        solver.advance(Vec3::new(0.0, 20.0, 0.0), 0.0, 1.0 / 60.0, config);
    }
    assert!((solver.position().y - 20.0).abs() < 0.01);

    let teleported = Vec3::new(1024.0, -2048.0, 32.0);
    assert_eq!(
        solver.advance(teleported, 0.0, 1.0 / 60.0, config),
        teleported,
    );
}

#[test]
fn heading_turn_uses_the_shortest_wrapped_arc_without_overshoot() {
    let target = -PI + 0.01;
    let mut heading = PI - 0.01;
    let mut speed = 0.0;
    let initial_distance = wrap_angle(target - heading).abs();
    heading = step_heading(heading, target, &mut speed, 5.0, 20.0, 1.0 / 60.0);
    assert!(wrap_angle(target - heading).abs() < initial_distance);

    for _ in 0..240 {
        heading = step_heading(heading, target, &mut speed, 5.0, 20.0, 1.0 / 60.0);
    }
    assert!(wrap_angle(target - heading).abs() < 0.000_01);
}

#[test]
fn muzzle_convergence_preserves_native_spread_and_rejects_degenerate_geometry() {
    let result = converge_angles(
        Vec3::new(0.0, 0.0, 0.0),
        Vec3::new(0.0, 100.0, 0.0),
        AimAngles::new(0.0, 0.0),
        AimAngles::new(0.08, -0.03),
    )
    .expect("finite muzzle target");
    assert!((result.yaw() - 0.08).abs() < 0.000_01);
    assert!((result.pitch() + 0.03).abs() < 0.000_01);
    assert!(
        converge_angles(
            Vec3::new(1.0, 2.0, 3.0),
            Vec3::new(1.0, 2.0, 3.0),
            AimAngles::new(0.0, 0.0),
            AimAngles::new(0.0, 0.0),
        )
        .is_none()
    );
}

#[test]
fn configuration_is_coherent_bounded_and_strict_for_invalid_values() {
    let config = ThirdPersonConfig::from_ini(
        "[Camera]\n\
         bFollowCamera=1\n\
         fFollowSpeed=200\n\
         fSoftZone=-2\n\
         fLookAhead=80\n\
         bAutoCenter=0\n\
         fCenterDelay=9\n\
         fCenterSpeed=900\n\
         [Movement]\n\
         b360Movement=1\n\
         fTurnSpeed=20\n\
         bDrawn360=1\n",
    )
    .expect("finite settings are bounded");
    assert!(config.follow_enabled());
    assert_eq!(config.follow_speed(), 20.0);
    assert_eq!(config.soft_zone(), 0.0);
    assert_eq!(config.look_ahead(), 32.0);
    assert!(!config.auto_center());
    assert_eq!(config.center_delay(), 5.0);
    assert_eq!(config.center_speed_degrees(), 360.0);
    assert!(config.movement_enabled());
    assert_eq!(config.turn_speed_degrees(), 90.0);
    assert!(config.drawn_360());

    assert!(ThirdPersonConfig::from_ini("[Camera]\nbFollowCamera=2\n").is_err());
    assert!(ThirdPersonConfig::from_ini("[Movement]\nfTurnSpeed=NaN\n").is_err());
}
