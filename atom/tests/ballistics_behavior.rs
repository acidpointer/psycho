//! Public behavior checks for data-driven Ballistics admission and config.

use atom::ballistics::{
    BallisticsConfigError, ProjectileCapability, ProjectileProfile, ShadowFlight,
    ShadowFlightError, classify_profile,
};
use atom::config::AtomConfig;

const MISSILE: u32 = 0x0001_0000;
const GRENADE: u32 = 0x0002_0000;
const BEAM: u32 = 0x0004_0000;
const FLAME: u32 = 0x0008_0000;
const CONTINUOUS_BEAM: u32 = 0x0010_0000;

fn profile(type_bits: u32, flags: u16, has_explosion: bool) -> ProjectileProfile {
    ProjectileProfile::new(0x1234, type_bits, flags, 0.1, 1000.0, 5000.0, has_explosion)
}

#[test]
fn capability_classification_depends_on_live_behavior_not_form_origin() {
    assert_eq!(
        classify_profile(profile(MISSILE, 1, false)),
        ProjectileCapability::DiscreteHitscan
    );
    assert_eq!(
        classify_profile(profile(MISSILE, 0, false)),
        ProjectileCapability::DiscretePhysical
    );
    assert_eq!(
        classify_profile(profile(MISSILE, 0, true)),
        ProjectileCapability::ExplosiveMissile
    );
    assert_eq!(
        classify_profile(profile(GRENADE, 0, false)),
        ProjectileCapability::GrenadeOrThrown
    );
    assert_eq!(
        classify_profile(profile(BEAM, 0, false)),
        ProjectileCapability::Beam
    );
    assert_eq!(
        classify_profile(profile(FLAME, 0, false)),
        ProjectileCapability::Flame
    );
    assert_eq!(
        classify_profile(profile(CONTINUOUS_BEAM, 0, false)),
        ProjectileCapability::ContinuousBeam
    );
    assert_eq!(
        classify_profile(profile(0x001F_0000, 0, false)),
        ProjectileCapability::Unknown
    );
}

#[test]
fn shared_ini_publishes_independent_input_and_ballistics_snapshots() {
    let config = AtomConfig::from_ini(
        "[Input]\nbEnabled=1\n\
         [Ballistics]\nbEnabled=1\n\
         [Diagnostics]\nbTelemetry=0\nbWriteSummary=0\n\
         bBallisticsTrace=1\nbBallisticsSummary=1\n\
         [Future]\nvalue=42\n",
    )
    .unwrap();

    assert!(config.input().enabled());
    assert!(config.ballistics().enabled());
    assert!(config.ballistics().trace_enabled());
    assert!(config.ballistics().summary_requested());
}

#[test]
fn invalid_ballistics_boolean_rejects_the_whole_candidate_snapshot() {
    let error = AtomConfig::from_ini("[Diagnostics]\nbBallisticsTrace=9\n").unwrap_err();
    assert!(matches!(
        error,
        atom::config::AtomConfigError::Ballistics(BallisticsConfigError::InvalidBoolean { .. })
    ));

    let error = AtomConfig::from_ini("[Ballistics]\nbEnabled=7\n").unwrap_err();
    assert!(matches!(
        error,
        atom::config::AtomConfigError::Ballistics(BallisticsConfigError::InvalidBoolean { .. })
    ));
}

#[test]
fn constant_acceleration_shadow_is_frame_partition_invariant() {
    let mut one_step = ShadowFlight::new([1.0, 2.0, 3.0], [0.0, 2.0, 0.0], 100.0).unwrap();
    one_step.advance([0.0, 0.0, -10.0], 1.0, 0.1).unwrap();

    let mut partitioned = ShadowFlight::new([1.0, 2.0, 3.0], [0.0, 2.0, 0.0], 100.0).unwrap();
    for _ in 0..4 {
        partitioned.advance([0.0, 0.0, -10.0], 0.25, 0.1).unwrap();
    }

    assert_vector_close(one_step.position(), partitioned.position(), 0.0001);
    assert_vector_close(one_step.velocity(), partitioned.velocity(), 0.0001);
    assert_vector_close(one_step.position(), [1.0, 102.0, -2.0], 0.0001);
    assert_vector_close(one_step.velocity(), [0.0, 100.0, -10.0], 0.0001);
}

#[test]
fn shadow_chords_are_bounded_and_invalid_steps_do_not_mutate_state() {
    let mut flight = ShadowFlight::new([0.0; 3], [1.0, 0.0, 0.0], 10.0).unwrap();
    let step = flight.advance([0.0, 0.0, -1000.0], 1.0, 0.001).unwrap();
    assert_eq!(step.chord_segments(), 8);
    assert!(step.chord_limit_reached());
    assert_eq!(step.chord(8), None);
    assert_eq!(step.chord(0).unwrap().0, [0.0; 3]);

    let before = flight;
    assert_eq!(
        flight.advance([0.0; 3], f32::NAN, 0.1),
        Err(ShadowFlightError::InvalidDelta)
    );
    assert_eq!(flight, before);
}

fn assert_vector_close(actual: [f32; 3], expected: [f32; 3], tolerance: f32) {
    for (actual, expected) in actual.into_iter().zip(expected) {
        assert!((actual - expected).abs() <= tolerance);
    }
}
