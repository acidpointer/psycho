//! Behavioral acceptance for camera FOV configuration.
//!
//! The native base application is exercised only inside the game process. These
//! checks execute the production configuration parser and validate the four
//! independent targets, native sentinels, bounds, and invalid-input rejection.

use atom::camera::CameraFovConfig;
use atom::config::AtomConfig;

#[test]
fn missing_fov_section_keeps_every_camera_native() {
    let config = AtomConfig::from_ini("[FirstPerson]\nbEnabled=0\n").expect("valid config");
    assert!(config.fov().is_native());
    assert_eq!(config.fov().first_person(), 0.0);
    assert_eq!(config.fov().third_person(), 0.0);
    assert_eq!(config.fov().viewmodel(), 0.0);
    assert_eq!(config.fov().pipboy(), 0.0);
}

#[test]
fn fov_section_is_recognized_with_the_other_atom_subsystems() {
    let config = AtomConfig::from_ini(
        "[FirstPerson]\nbEnabled=1\n\
         [Camera]\nbFollowCamera=1\n\
         [Movement]\nb360Movement=1\n\
         [Fov]\nfFirstPerson=90\nfThirdPerson=85\nfViewmodel=60\nfPipboy=70\n",
    )
    .expect("valid config");

    assert_eq!(config.fov().first_person(), 90.0);
    assert_eq!(config.fov().third_person(), 85.0);
    assert_eq!(config.fov().viewmodel(), 60.0);
    assert_eq!(config.fov().pipboy(), 70.0);
    assert!(config.first_person().enabled());
    assert!(config.third_person().follow_enabled());
    assert!(config.third_person().movement_enabled());
}

#[test]
fn zero_is_the_native_sentinel_for_each_independent_target() {
    for text in [
        "[Fov]\nfFirstPerson=0\n",
        "[Fov]\nfThirdPerson=0\n",
        "[Fov]\nfViewmodel=0\n",
        "[Fov]\nfPipboy=0\n",
    ] {
        let config = CameraFovConfig::from_ini(text).expect("valid config");
        assert!(config.is_native(), "{text}");
    }
}

#[test]
fn each_target_is_bounded_and_independent() {
    let config = CameraFovConfig::from_ini(
        "[Fov]\nfFirstPerson=110\nfThirdPerson=105\nfViewmodel=90\nfPipboy=60\n",
    )
    .expect("valid config");
    assert_eq!(config.first_person(), 110.0);
    assert_eq!(config.third_person(), 105.0);
    assert_eq!(config.viewmodel(), 90.0);
    assert_eq!(config.pipboy(), 60.0);

    let low = CameraFovConfig::from_ini("[Fov]\nfFirstPerson=1\n").expect("valid config");
    assert_eq!(low.first_person(), 1.0);
    let high = CameraFovConfig::from_ini("[Fov]\nfThirdPerson=240\n").expect("valid config");
    assert_eq!(high.third_person(), 150.0);
}

#[test]
fn negative_and_non_finite_targets_are_rejected() {
    assert!(CameraFovConfig::from_ini("[Fov]\nfViewmodel=-10\n").is_err());
    assert!(CameraFovConfig::from_ini("[Fov]\nfViewmodel=NaN\n").is_err());
    assert!(CameraFovConfig::from_ini("[Fov]\nfFirstPerson=inf\n").is_err());
}
