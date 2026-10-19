//! Behavioral acceptance for camera FOV configuration and tangent scaling.
//!
//! The native writers are exercised only inside the game process. These checks
//! execute the production configuration parser and the exact arithmetic used by
//! the deferred wrappers, including native pass-through, live-ADS preservation,
//! and the independent viewmodel ratio.

use atom::camera::{CameraFovConfig, fov_scale, scale_fov_degrees};
use atom::config::AtomConfig;

const NATIVE_BASE: f32 = 75.0;

fn close(left: f32, right: f32) -> bool {
    (left - right).abs() < 1.0e-4
}

#[test]
fn missing_fov_section_keeps_every_camera_native() {
    let config = AtomConfig::from_ini("[FirstPerson]\nbEnabled=0\n").expect("valid config");
    assert!(config.fov().is_native());
    assert_eq!(config.fov().first_person(), 0.0);
    assert_eq!(config.fov().third_person(), 0.0);
    assert_eq!(config.fov().viewmodel(), 0.0);
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
fn native_sentinel_is_exact_for_every_world_mode() {
    for target in [0.0_f32, 0.0] {
        let scale = fov_scale(target, NATIVE_BASE).expect("native sentinel");
        assert_eq!(scale, 1.0);
        for native in [50.0_f32, 75.0, 91.25] {
            assert_eq!(scale_fov_degrees(native, scale), Some(native));
        }
    }
}

#[test]
fn base_targets_are_reached_from_the_live_native_angle() {
    for (target, base) in [(90.0, 75.0), (90.0, 55.0), (85.0, 75.0), (110.0, 75.0)] {
        let scale = fov_scale(target, base).expect("valid base");
        let rendered = scale_fov_degrees(base, scale).expect("valid native angle");
        assert!(
            close(rendered, target),
            "{base} -> {rendered}, expected {target}"
        );
    }
}

#[test]
fn aiming_and_scope_zoom_keep_the_same_tangent_ratio() {
    let scale = fov_scale(90.0, NATIVE_BASE).expect("valid base");
    let base_ratio = (90.0_f32.to_radians() * 0.5).tan() / (NATIVE_BASE.to_radians() * 0.5).tan();

    for native in [50.0_f32, 35.0, 20.0] {
        let rendered = scale_fov_degrees(native, scale).expect("valid zoomed angle");
        let ratio = (rendered.to_radians() * 0.5).tan() / (native.to_radians() * 0.5).tan();
        assert!(close(ratio, base_ratio), "{native} -> {rendered}");
        assert!(
            rendered > native && rendered < 90.0,
            "{native} -> {rendered}"
        );
    }
}

#[test]
fn independent_viewmodel_target_reaches_its_absolute_base() {
    let first_scale = fov_scale(90.0, NATIVE_BASE).expect("first target");
    let viewmodel_scale = fov_scale(60.0, NATIVE_BASE).expect("viewmodel target");
    let additional = viewmodel_scale / first_scale;

    // The viewmodel copy already contains the first-person scaling because the
    // world frustum is scaled before the native copy at 0x008752F2.
    let copied = scale_fov_degrees(NATIVE_BASE, first_scale).expect("first-scaled copy");
    let rendered = scale_fov_degrees(copied, additional).expect("viewmodel scale");
    assert!(
        close(rendered, 60.0),
        "copied={copied}, rendered={rendered}"
    );
}

#[test]
fn pipboy_target_is_absolute_from_the_live_native_field() {
    let native = 75.0;
    let target = 70.0;
    let scale = fov_scale(target, native).expect("pipboy target");
    let rendered = scale_fov_degrees(native, scale).expect("pipboy field");
    assert!(
        close(rendered, target),
        "native={native}, rendered={rendered}"
    );
}

#[test]
fn viewmodel_zero_follows_the_effective_first_person_angle() {
    let first_scale = fov_scale(90.0, NATIVE_BASE).expect("first target");
    let viewmodel_scale = first_scale;
    let additional = viewmodel_scale / first_scale;
    assert_eq!(additional, 1.0);

    let copied = scale_fov_degrees(NATIVE_BASE, first_scale).expect("first-scaled copy");
    let rendered = scale_fov_degrees(copied, additional).expect("follow first");
    assert!(close(rendered, 90.0));
}

#[test]
fn configured_targets_are_bounded_and_negative_values_are_rejected() {
    let low = CameraFovConfig::from_ini("[Fov]\nfFirstPerson=5\n").expect("clamped config");
    assert_eq!(low.first_person(), 5.0);

    let high = CameraFovConfig::from_ini("[Fov]\nfThirdPerson=240\n").expect("clamped config");
    assert_eq!(high.third_person(), 150.0);

    assert!(CameraFovConfig::from_ini("[Fov]\nfViewmodel=-10\n").is_err());
    assert!(CameraFovConfig::from_ini("[Fov]\nfViewmodel=NaN\n").is_err());
}

#[test]
fn invalid_native_input_cannot_write_a_camera_value() {
    assert_eq!(fov_scale(90.0, 0.0), None);
    assert_eq!(fov_scale(90.0, 179.0), None);
    assert_eq!(fov_scale(f32::NAN, NATIVE_BASE), None);
    assert_eq!(scale_fov_degrees(75.0, 0.0), None);
    assert_eq!(scale_fov_degrees(75.0, f32::INFINITY), None);
    assert_eq!(scale_fov_degrees(180.0, 1.5), None);
}
