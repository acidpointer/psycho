//! Public behavioral acceptance checks for third-person ownership and math.

use core::f32::consts::{FRAC_PI_2, PI};

use atom::camera::third_person::{
    AimAngles, FacingPolicy, FollowSolver, HeadingContinuity, HeadingContinuityEvent, LookRoute,
    MovementIntent, NativeHandoffGuard, OwnershipInput, OwnershipMachine, OwnershipState,
    SpringAxis, ThirdPersonConfig, Vec3, actor_heading_handoff_target,
    advance_actor_pitch_ownership, advance_logical_pitch, axial_follow_offset,
    camera_relative_heading, compensated_camera_heading_offset, compose_follow_camera,
    converge_angles, horizontal_look_route, linear_zoom_delta, logical_heading_after_native_look,
    remap_movement, reticle_and_convergence_admission, step_heading, third_person_view_ray,
    vertical_look_route, view_cast_no_hit_outputs, view_direction, view_reach_interval, wrap_angle,
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

fn cross(lhs: Vec3, rhs: Vec3) -> Vec3 {
    Vec3::new(
        lhs.y * rhs.z - lhs.z * rhs.y,
        lhs.z * rhs.x - lhs.x * rhs.z,
        lhs.x * rhs.y - lhs.y * rhs.x,
    )
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
fn pip_boy_return_requires_consecutive_quiet_time_before_camera_reacquisition() {
    fn advance(
        machine: &mut OwnershipMachine,
        handoff: &mut NativeHandoffGuard,
        normal_state: bool,
        delta_seconds: f32,
    ) -> OwnershipState {
        let ready = handoff.advance(normal_state, delta_seconds);
        machine
            .advance(OwnershipInput::new(true, true, !ready, true, false, 1))
            .current()
    }

    let mut machine = OwnershipMachine::new();
    let mut handoff = NativeHandoffGuard::new();
    for _ in 0..12 {
        advance(&mut machine, &mut handoff, true, 1.0 / 60.0);
    }
    assert_eq!(machine.state(), OwnershipState::Explore);

    assert_eq!(
        advance(&mut machine, &mut handoff, false, 1.0 / 60.0),
        OwnershipState::Release,
        "Pip-Boy ownership must revoke Atom in the first observed frame",
    );
    assert_eq!(
        advance(&mut machine, &mut handoff, false, 1.0 / 60.0),
        OwnershipState::Native,
    );

    // A nominally normal edge immediately after AccessDown is insufficient:
    // native has started the return animation before clearing its UI owner.
    for _ in 0..8 {
        assert_eq!(
            advance(&mut machine, &mut handoff, true, 1.0 / 60.0),
            OwnershipState::Native,
        );
    }
    // Any late owner flap restarts the complete quiet interval.
    assert_eq!(
        advance(&mut machine, &mut handoff, false, 1.0 / 60.0),
        OwnershipState::Native,
    );
    for _ in 0..8 {
        assert_eq!(
            advance(&mut machine, &mut handoff, true, 1.0 / 60.0),
            OwnershipState::Native,
        );
    }
    assert_eq!(
        advance(&mut machine, &mut handoff, true, 1.0 / 60.0),
        OwnershipState::Acquire,
        "only a continuous settled interval may begin the no-write seed frame",
    );
    assert_eq!(
        advance(&mut machine, &mut handoff, true, 1.0 / 60.0),
        OwnershipState::Explore,
    );
    assert!(
        !handoff.advance(true, f32::NAN),
        "invalid engine time must fail back to native ownership",
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
fn camera_relative_mapping_preserves_magnitude_and_complete_native_flags() {
    let native = Vec3::new(0.0, 0.75, -0.2);
    let native_flags = 0xA5A5_000A;
    for yaw in [0.0, FRAC_PI_2, PI, -FRAC_PI_2] {
        let explore = remap_movement(native, native_flags, 0.0, yaw, FacingPolicy::Explore);
        assert!((explore.vector().horizontal_length() - 0.75).abs() < 0.000_01);
        assert_eq!(explore.flags(), native_flags);
        assert!((wrap_angle(explore.movement_heading().unwrap() - yaw)).abs() < 0.000_01);

        let combat = remap_movement(native, native_flags, 0.0, yaw, FacingPolicy::Combat);
        assert_eq!(combat.flags(), native_flags);
    }
}

#[test]
fn held_diagonal_keeps_one_world_heading_while_camera_and_actor_turn() {
    let native = Vec3::new(0.75, 0.75, -0.2);
    let native_flags = 0xA500_0009;
    let latched_world_heading = 1.2;
    for (view_yaw, actor_yaw) in [(-1.0, -0.8), (-0.4, -0.1), (0.2, 0.5), (0.9, 1.0)] {
        let output = MovementIntent::with_world_heading(
            native,
            native_flags,
            view_yaw,
            FacingPolicy::Explore,
            latched_world_heading,
        )
        .resolve(actor_yaw);
        let world = fnv_world_vector(output.vector(), actor_yaw);
        assert!(wrap_angle(world.x.atan2(world.y) - latched_world_heading).abs() < 0.000_01);
        assert!((world.horizontal_length() - native.horizontal_length()).abs() < 0.000_01);
        assert_eq!(world.z, native.z);
        assert_eq!(output.flags(), native_flags);
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
    assert_eq!(normalized.flags(), 0xA500_000A);
}

#[test]
fn transient_heading_gaps_preserve_view_then_hard_owners_release_it() {
    let mut continuity = HeadingContinuity::new();
    assert!(continuity.advance(HeadingContinuityEvent::Stable, 1.0 / 60.0));

    for frame in 1..=7 {
        assert!(
            continuity.advance(HeadingContinuityEvent::SoftGap, 1.0 / 60.0),
            "soft gap frame {frame} must retain the last rendered heading",
        );
    }
    assert!(
        !continuity.advance(HeadingContinuityEvent::SoftGap, 1.0 / 60.0),
        "a prolonged observation failure must fail back to native ownership",
    );

    assert!(continuity.advance(HeadingContinuityEvent::Stable, 1.0 / 60.0));
    assert!(
        !continuity.advance(HeadingContinuityEvent::HardOwner, 1.0 / 60.0),
        "menus, VATS, POV, scripted cameras, and other hard owners cannot inherit Atom yaw",
    );
    assert!(
        !continuity.advance(HeadingContinuityEvent::SoftGap, f32::NAN),
        "invalid engine time must invalidate continuity",
    );
}

#[test]
fn transient_movement_fallback_keeps_the_camera_relative_world_direction() {
    let native = Vec3::new(0.35, 0.90, -0.25);
    let actor_yaw = -0.82;
    let retained_view_yaw = 1.31;
    let output = remap_movement(
        native,
        0xA500_0005,
        actor_yaw,
        retained_view_yaw,
        FacingPolicy::Explore,
    );

    assert_vec3_close(
        fnv_world_vector(output.vector(), actor_yaw),
        fnv_world_vector(native, retained_view_yaw),
    );
    assert!(
        wrap_angle(
            actor_yaw
                + compensated_camera_heading_offset(actor_yaw, 0.0, retained_view_yaw)
                    .expect("finite retained camera heading")
                - retained_view_yaw,
        )
        .abs()
            < 0.000_01,
        "movement fallback must not rotate the rendered view to actor facing",
    );
}

#[test]
fn fine_zoom_produces_constant_world_unit_notches_across_the_native_range() {
    for desired_distance in [30.0, 60.0, 120.0] {
        for (raw_delta, multiplier) in [(120, 0.05), (-120, 0.10)] {
            let mut residual = 0.0;
            let adjusted =
                linear_zoom_delta(raw_delta, desired_distance, multiplier, 2.0, &mut residual)
                    .expect("valid native zoom values");
            let native_change = adjusted as f32 / 120.0 * desired_distance * multiplier;
            assert!((native_change - raw_delta.signum() as f32 * 2.0).abs() < 0.000_01);
            assert!(residual.abs() < 0.000_01);
        }
    }
}

#[test]
fn fine_zoom_preserves_batched_and_high_resolution_wheel_input() {
    let mut batched_residual = 0.0;
    let batched = linear_zoom_delta(240, 60.0, 0.05, 2.0, &mut batched_residual)
        .expect("batched wheel input");
    let mut split_residual = 0.0;
    let split = (0..2)
        .map(|_| {
            linear_zoom_delta(120, 60.0, 0.05, 2.0, &mut split_residual).expect("split wheel input")
        })
        .sum::<i32>();
    assert_eq!(batched, split);
    assert_eq!(batched_residual, split_residual);

    let mut residual = 0.0;
    let positive = linear_zoom_delta(15, 120.0, 0.10, 2.0, &mut residual)
        .expect("high-resolution positive input");
    let negative =
        linear_zoom_delta(-15, 120.0, 0.10, 2.0, &mut residual).expect("high-resolution reversal");
    assert_eq!(positive + negative, 0);
    assert_eq!(residual, 0.0);
}

#[test]
fn camera_feature_toggles_are_independent_and_each_admits_runtime_ownership() {
    for mask in 0_u8..16 {
        let follow = mask & 1 != 0;
        let movement = mask & 2 != 0;
        let framing = mask & 4 != 0;
        let motion = mask & 8 != 0;
        let config = ThirdPersonConfig::from_ini(&format!(
            "[Camera]\n\
             bFollowCamera={}\n\
             bFraming={}\n\
             bMotion={}\n\
             [Movement]\n\
             b360Movement={}\n",
            u8::from(follow),
            u8::from(framing),
            u8::from(motion),
            u8::from(movement),
        ))
        .expect("valid feature combination");
        assert_eq!(config.follow_enabled(), follow);
        assert_eq!(config.movement_enabled(), movement);
        assert_eq!(config.framing_enabled(), framing);
        assert_eq!(config.motion_enabled(), motion);
        assert_eq!(config.enabled(), follow || movement || framing || motion);
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
fn follow_solver_holds_zero_time_and_bounds_long_frame_integration() {
    let config = ThirdPersonConfig::from_ini(
        "[Camera]\n\
         bFollowCamera=1\n\
         fFollowSpeed=7.5\n\
         fSoftZone=0\n\
         fLookAhead=0\n",
    )
    .expect("valid follow settings");
    let mut solver = FollowSolver::new();
    solver.reset(Vec3::default());
    let moving = solver.advance(Vec3::new(0.0, 20.0, 0.0), 0.0, 1.0 / 60.0, config);
    assert_eq!(
        solver.advance(Vec3::new(0.0, 30.0, 0.0), 0.0, 0.0, config),
        moving
    );

    let after_hitch = solver.advance(Vec3::new(0.0, 40.0, 0.0), 0.0, 0.25, config);
    assert!(after_hitch.is_finite());
    assert!(after_hitch.y > moving.y && after_hitch.y < 40.0);
}

#[test]
fn vertical_look_routes_explore_orbit_away_from_actor_pitch_but_preserves_aim() {
    assert_eq!(
        vertical_look_route(OwnershipState::Explore, true, false),
        LookRoute::CameraOnly,
    );
    assert_eq!(
        vertical_look_route(OwnershipState::Explore, true, true),
        LookRoute::NativeAndSynchronize,
    );
    for native_aiming in [false, true] {
        assert_eq!(
            vertical_look_route(OwnershipState::Combat, true, native_aiming),
            LookRoute::NativeAndSynchronize,
        );
    }
    for state in [
        OwnershipState::Native,
        OwnershipState::Acquire,
        OwnershipState::Release,
    ] {
        assert_eq!(
            vertical_look_route(state, true, false),
            LookRoute::NativeOnly,
        );
    }
    for state in [
        OwnershipState::Native,
        OwnershipState::Acquire,
        OwnershipState::Explore,
        OwnershipState::Combat,
        OwnershipState::Release,
    ] {
        assert_eq!(
            vertical_look_route(state, false, true),
            LookRoute::NativeOnly,
        );
    }
}

#[test]
fn aim_entry_aligns_body_without_blinking_the_camera_and_native_look_stays_coupled() {
    let logical_heading = 1.1;
    let initial_actor_heading = -0.7;
    let initial_offset = wrap_angle(logical_heading - initial_actor_heading);
    let route = horizontal_look_route(OwnershipState::Explore, true, true);
    assert_eq!(route, LookRoute::NativeAndSynchronize);
    assert_eq!(
        horizontal_look_route(OwnershipState::Combat, true, false),
        LookRoute::NativeAndSynchronize,
        "Combat must preserve the same actor/view coupling even before aim is sampled",
    );

    // AIM entry must rotate the body to the already-rendered world heading.
    // The old camera-only offset is still present immediately after that
    // native setter, so recompute it from the live post-setter state before
    // UpdateCamera can observe a doubled heading.
    let actor_heading = actor_heading_handoff_target(route, initial_actor_heading, logical_heading)
        .expect("misaligned AIM entry requires an Actor handoff");
    assert!(wrap_angle(actor_heading - logical_heading).abs() < 0.000_01);
    let adjusted_after_actor_turn = wrap_angle(actor_heading + initial_offset);
    let camera_offset = compensated_camera_heading_offset(
        adjusted_after_actor_turn,
        initial_offset,
        logical_heading,
    )
    .expect("finite post-handoff compensation");
    assert!(
        wrap_angle(actor_heading + camera_offset - logical_heading).abs() < 0.000_01,
        "the body handoff must not blink the camera away from its world heading",
    );

    // 0x00931D30 next reads adjusted heading, adds input, and writes that
    // absolute result as raw Actor yaw. Atom must adopt that raw value (not
    // adjusted heading plus the stale offset) and keep body/view coupled.
    let native_delta = 0.23;
    let native_actor_heading = wrap_angle(actor_heading + camera_offset + native_delta);
    let next_logical_heading = logical_heading_after_native_look(native_actor_heading)
        .expect("native Actor yaw is finite");
    let adjusted_after_native_look = wrap_angle(native_actor_heading + camera_offset);
    let next_camera_offset = compensated_camera_heading_offset(
        adjusted_after_native_look,
        camera_offset,
        next_logical_heading,
    )
    .expect("finite native-look compensation");
    assert!(wrap_angle(native_actor_heading - next_logical_heading).abs() < 0.000_01);
    assert!(
        wrap_angle(native_actor_heading + next_camera_offset - next_logical_heading).abs()
            < 0.000_01,
        "subsequent native aim input must turn body and camera together",
    );

    let explore_route = horizontal_look_route(OwnershipState::Explore, true, false);
    assert_eq!(explore_route, LookRoute::CameraOnly);
    assert!(
        actor_heading_handoff_target(explore_route, initial_actor_heading, logical_heading,)
            .is_none(),
        "free orbit must remain camera-only outside AIM",
    );
    assert!(
        actor_heading_handoff_target(
            LookRoute::NativeOnly,
            initial_actor_heading,
            logical_heading,
        )
        .is_none(),
        "native-owned epochs must never receive an Atom body write",
    );
}

#[test]
fn logical_pitch_accumulates_in_both_directions_and_stays_bounded() {
    assert!(
        (advance_logical_pitch(0.25, 0.5).expect("finite positive pitch") - 0.75).abs()
            < f32::EPSILON
    );
    assert!(
        (advance_logical_pitch(0.25, -0.5).expect("finite negative pitch") + 0.25).abs()
            < f32::EPSILON
    );
    assert!(
        (advance_logical_pitch(1.5, 100.0).expect("upper pitch clamp") - 1.553_343).abs()
            < f32::EPSILON
    );
    assert!(
        (advance_logical_pitch(-1.5, -100.0).expect("lower pitch clamp") + 1.553_343).abs()
            < f32::EPSILON
    );
    assert!(advance_logical_pitch(f32::NAN, 0.1).is_none());
    assert!(advance_logical_pitch(0.1, f32::INFINITY).is_none());
}

#[test]
fn leaving_aim_neutralizes_actor_pitch_once_without_changing_camera_pitch() {
    let camera_pitch = -0.85;
    let mut native_pitch_owned = false;

    assert!(!advance_actor_pitch_ownership(
        &mut native_pitch_owned,
        LookRoute::NativeAndSynchronize,
        camera_pitch,
    ));
    assert!(native_pitch_owned);
    assert!(!advance_actor_pitch_ownership(
        &mut native_pitch_owned,
        LookRoute::NativeAndSynchronize,
        camera_pitch,
    ));

    assert!(advance_actor_pitch_ownership(
        &mut native_pitch_owned,
        LookRoute::CameraOnly,
        camera_pitch,
    ));
    assert!(!native_pitch_owned);
    assert_eq!(
        camera_pitch, -0.85,
        "the logical view must retain aim pitch"
    );
    assert!(!advance_actor_pitch_ownership(
        &mut native_pitch_owned,
        LookRoute::CameraOnly,
        0.0,
    ));

    native_pitch_owned = true;
    assert!(!advance_actor_pitch_ownership(
        &mut native_pitch_owned,
        LookRoute::NativeOnly,
        camera_pitch,
    ));
    assert!(
        !native_pitch_owned,
        "native states must not receive an Atom reset"
    );
}

#[test]
fn native_ui_interruption_cannot_erase_stale_actor_pitch_cleanup() {
    let logical_camera_pitch = 0.82;
    let stale_actor_pitch = 0.82;
    let mut native_pitch_owned = false;

    // Release/Native intentionally discard temporal ownership flags. On the
    // first reacquired camera-only frame the live Actor value must still make
    // the stale pose observable and request one authoritative neutralization.
    assert!(advance_actor_pitch_ownership(
        &mut native_pitch_owned,
        LookRoute::CameraOnly,
        stale_actor_pitch,
    ));
    assert_eq!(
        logical_camera_pitch, 0.82,
        "pose cleanup must not alter the logical camera pitch",
    );
    assert!(!advance_actor_pitch_ownership(
        &mut native_pitch_owned,
        LookRoute::CameraOnly,
        0.0,
    ));
    assert!(!advance_actor_pitch_ownership(
        &mut native_pitch_owned,
        LookRoute::NativeOnly,
        stale_actor_pitch,
    ));
}

#[test]
fn existing_projectile_owner_cannot_disable_crosshair_object_alignment() {
    assert_eq!(
        reticle_and_convergence_admission(true, false),
        (true, false),
        "a non-native spawn owner must leave the independent reticle admitted",
    );
    assert_eq!(reticle_and_convergence_admission(true, true), (true, true),);
    assert_eq!(
        reticle_and_convergence_admission(false, true),
        (false, false),
    );
}

#[test]
fn object_selection_ray_uses_rendered_camera_origin_and_logical_axes() {
    let native_eye = Vec3::new(-24.0, 0.0, 70.0);
    let render_camera = Vec3::new(18.0, -110.0, 78.0);
    let yaw = 0.35;
    let pitch = -0.2;
    let ray = third_person_view_ray(native_eye, render_camera, yaw, pitch)
        .expect("finite third-person selection ray");

    assert_eq!(ray.origin(), render_camera);
    assert_vec3_close(
        ray.direction(),
        view_direction(yaw, pitch).expect("finite logical direction"),
    );
    let object_under_crosshair = ray.point_at(160.0).expect("finite target point");
    let native_eye_point = native_eye + ray.direction() * 160.0;
    assert_vec3_close(
        object_under_crosshair,
        render_camera + ray.direction() * 160.0,
    );
    assert!(
        (object_under_crosshair - native_eye_point).length() > 40.0,
        "the vanilla eye ray must not masquerade as the rendered camera ray",
    );
    assert!(ray.point_at(-1.0).is_none());
    assert!(third_person_view_ray(native_eye, Vec3::new(f32::NAN, 0.0, 0.0), yaw, pitch).is_none());
}

#[test]
fn distant_camera_cursor_reaches_only_objects_inside_the_native_eye_sphere() {
    let native_eye = Vec3::default();
    let camera = Vec3::new(0.0, -240.0, 0.0);
    let direction = Vec3::new(0.0, 1.0, 0.0);
    let interval = view_reach_interval(native_eye, camera, direction, 150.0)
        .expect("the rendered ray crosses the native interaction sphere");

    assert!((interval.entry() - 90.0).abs() < 0.000_01);
    assert!((interval.exit() - 390.0).abs() < 0.000_01);
    assert!(interval.accepts_hit(240.0));
    assert!(!interval.accepts_hit(40.0));
    assert!(!interval.accepts_hit(400.0));
    let accepted = camera + direction * 240.0;
    assert!((accepted - native_eye).length() <= 150.0);
    assert!(
        interval.exit() > 150.0,
        "camera distance must not consume the player's interaction reach",
    );
}

#[test]
fn cursor_reach_rejects_misses_and_preserves_native_no_hit_outputs() {
    assert!(
        view_reach_interval(
            Vec3::default(),
            Vec3::new(300.0, -240.0, 0.0),
            Vec3::new(0.0, 1.0, 0.0),
            150.0,
        )
        .is_none(),
        "a camera ray which misses the eye-centered reach sphere must not extend interaction",
    );
    let inside = view_reach_interval(
        Vec3::default(),
        Vec3::new(0.0, -60.0, 0.0),
        Vec3::new(0.0, 1.0, 0.0),
        150.0,
    )
    .expect("camera inside the reach sphere");
    assert_eq!(inside.entry(), 0.0);
    assert!((inside.exit() - 210.0).abs() < 0.000_01);
    assert_eq!(view_cast_no_hit_outputs(), (f32::MAX, 0));
}

#[test]
fn sustained_lateral_facing_changes_cannot_rotate_the_camera() {
    let logical_heading = 1.15;
    let mut actor_base_heading = -0.4;
    let mut camera_offset = 0.25;

    // Ten minutes at 60 Hz covers repeated actor turns and native camera
    // offset drift while the player holds a lateral movement direction.
    for frame in 0..36_000 {
        actor_base_heading = wrap_angle(actor_base_heading - 0.0025);
        let native_drift = ((frame % 181) as f32 - 90.0) * 0.000_02;
        camera_offset = wrap_angle(camera_offset + native_drift);
        let native_adjusted = wrap_angle(actor_base_heading + camera_offset);
        camera_offset =
            compensated_camera_heading_offset(native_adjusted, camera_offset, logical_heading)
                .expect("finite camera compensation");
        let effective_heading = wrap_angle(actor_base_heading + camera_offset);
        assert!(wrap_angle(effective_heading - logical_heading).abs() < 0.000_01);
    }

    assert!(compensated_camera_heading_offset(f32::NAN, 0.0, logical_heading).is_none());
}

#[test]
fn lateral_follow_lag_cannot_steer_the_camera_at_any_view_angle() {
    for yaw in [-PI, -FRAC_PI_2, 0.0, FRAC_PI_2, PI] {
        let (sin_yaw, cos_yaw) = yaw.sin_cos();
        let lateral_lag = Vec3::new(cos_yaw * 24.0, -sin_yaw * 24.0, 0.0);
        for pitch in [-1.0, -0.25, 0.0, 0.75, 1.0] {
            let projected =
                axial_follow_offset(lateral_lag, yaw, pitch).expect("finite follow projection");
            assert!(
                projected.length() < 0.000_01,
                "lateral lag leaked into the camera at yaw={yaw}, pitch={pitch}: {projected:?}",
            );
        }
    }
}

#[test]
fn published_follow_response_changes_only_chase_distance() {
    for (yaw, pitch) in [(0.0, 0.0), (0.7, -0.4), (-2.4, 0.8)] {
        let axis = view_direction(yaw, pitch).expect("finite view axis");
        let solved_lag = Vec3::new(7.0, -11.0, 5.0);
        let projected =
            axial_follow_offset(solved_lag, yaw, pitch).expect("finite follow projection");
        assert!(cross(projected, axis).length() < 0.000_01);

        let native_camera = axis * -120.0;
        let followed_camera = compose_follow_camera(native_camera, Vec3::default(), projected)
            .expect("valid native camera ray");
        let direction_to_pivot = (Vec3::default() - followed_camera).normalized();
        assert_vec3_close(direction_to_pivot, axis);
    }

    assert!(axial_follow_offset(Vec3::new(f32::NAN, 0.0, 0.0), 0.0, 0.0).is_none());
    assert!(axial_follow_offset(Vec3::default(), f32::NAN, 0.0).is_none());
}

#[test]
fn native_shoulder_ray_is_preserved_and_cannot_cross_the_pivot() {
    let pivot = Vec3::new(100.0, -50.0, 20.0);
    let native_camera = Vec3::new(82.0, -148.0, 34.0);
    let native_ray = native_camera - pivot;
    let native_direction = native_ray.normalized();
    let follow = Vec3::new(-7.0, 16.0, 3.0);
    let composed = compose_follow_camera(native_camera, pivot, follow).expect("valid shoulder ray");
    let composed_ray = composed - pivot;

    assert_vec3_close(composed_ray.normalized(), native_direction);
    assert!(cross(composed_ray, native_ray).length() < 0.001);
    assert_eq!(
        compose_follow_camera(native_camera, pivot, Vec3::default()),
        Some(native_camera),
    );

    let crossing_follow = native_direction * -(native_ray.length() + 1.0);
    assert!(compose_follow_camera(native_camera, pivot, crossing_follow).is_none());
    assert!(compose_follow_camera(pivot, pivot, follow).is_none());
    assert!(
        compose_follow_camera(native_camera, pivot, Vec3::new(0.0, f32::INFINITY, 0.0),).is_none()
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
         fZoomStep=99\n\
         bAutoCenter=0\n\
         fCenterDelay=9\n\
         fCenterSpeed=900\n\
         bFraming=1\n\
         fMinDistance=200\n\
         fMaxDistance=60\n\
         fStartDistance=300\n\
         fSideOffset=300\n\
         fHeightOffset=-200\n\
         bMotion=1\n\
         fMotionStrength=2\n\
         fLandMotion=-1\n\
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
    assert_eq!(config.zoom_step(), 10.0);
    assert!(!config.auto_center());
    assert_eq!(config.center_delay(), 5.0);
    assert_eq!(config.center_speed_degrees(), 360.0);
    assert!(config.framing_enabled());
    assert_eq!(config.minimum_distance(), 150.0);
    assert_eq!(config.maximum_distance(), 150.0);
    assert_eq!(config.start_distance(), 150.0);
    assert_eq!(config.side_offset(), 200.0);
    assert_eq!(config.height_offset(), -100.0);
    assert!(config.motion_enabled());
    assert_eq!(config.motion_strength(), 1.0);
    assert_eq!(config.landing_motion(), 0.0);
    assert!(config.movement_enabled());
    assert_eq!(config.turn_speed_degrees(), 90.0);
    assert!(config.drawn_360());

    assert!(ThirdPersonConfig::from_ini("[Camera]\nbFollowCamera=2\n").is_err());
    assert!(ThirdPersonConfig::from_ini("[Camera]\nbFraming=2\n").is_err());
    assert!(ThirdPersonConfig::from_ini("[Camera]\nbMotion=2\n").is_err());
    assert!(ThirdPersonConfig::from_ini("[Movement]\nfTurnSpeed=NaN\n").is_err());
    assert!(ThirdPersonConfig::from_ini("[Camera]\nfZoomStep=NaN\n").is_err());
    assert!(ThirdPersonConfig::from_ini("[Camera]\nfMinDistance=NaN\n").is_err());
    assert!(ThirdPersonConfig::from_ini("[Camera]\nfMotionStrength=NaN\n").is_err());
}
