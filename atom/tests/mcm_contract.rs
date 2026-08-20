//! Behavioral checks for the MCM JSON artifact shipped to players.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use atom::config::AtomConfig;
use serde_json::Value;

#[test]
fn shipped_mcm_menu_exposes_every_runtime_setting_with_matching_defaults() {
    let document = load_mcm();

    assert_eq!(document["modName"], "Atom");
    assert_eq!(document["saveFile"], "Atom/Atom.ini");
    assert_eq!(document["requirements"][0]["type"], "dll");
    assert_eq!(document["requirements"][0]["file"], "Atom");
    assert_eq!(document["requirements"][0]["version"], 2);

    let actual = collect_persisted_defaults(&document);
    let defaults = AtomConfig::default();
    let input = defaults.input();
    let ballistics = defaults.ballistics();
    let first_person = defaults.first_person();
    let third_person = defaults.third_person();
    let mouse = input.mouse();
    let controller = input.controller();
    let expected = BTreeMap::from([
        ("Ballistics:bEnabled", f64::from(ballistics.enabled())),
        ("Camera:bAutoCenter", f64::from(third_person.auto_center())),
        ("Camera:bFraming", f64::from(third_person.framing_enabled())),
        (
            "Camera:bFollowCamera",
            f64::from(third_person.follow_enabled()),
        ),
        ("Camera:bMotion", f64::from(third_person.motion_enabled())),
        (
            "Camera:fCenterDelay",
            f64::from(third_person.center_delay()),
        ),
        (
            "Camera:fCenterSpeed",
            f64::from(third_person.center_speed_degrees()),
        ),
        (
            "Camera:fFollowSpeed",
            f64::from(third_person.follow_speed()),
        ),
        (
            "Camera:fHeightOffset",
            f64::from(third_person.height_offset()),
        ),
        (
            "Camera:fLandMotion",
            f64::from(third_person.landing_motion()),
        ),
        ("Camera:fLookAhead", f64::from(third_person.look_ahead())),
        (
            "Camera:fMaxDistance",
            f64::from(third_person.maximum_distance()),
        ),
        (
            "Camera:fMinDistance",
            f64::from(third_person.minimum_distance()),
        ),
        (
            "Camera:fMotionStrength",
            f64::from(third_person.motion_strength()),
        ),
        ("Camera:fSideOffset", f64::from(third_person.side_offset())),
        ("Camera:fSoftZone", f64::from(third_person.soft_zone())),
        (
            "Camera:fStartDistance",
            f64::from(third_person.start_distance()),
        ),
        ("Camera:fZoomStep", f64::from(third_person.zoom_step())),
        (
            "Controller:bInvertRightX",
            f64::from(controller.invert_right_x()),
        ),
        (
            "Controller:bInvertRightY",
            f64::from(controller.invert_right_y()),
        ),
        (
            "Controller:fAntiDeadzone",
            f64::from(controller.anti_deadzone()),
        ),
        (
            "Controller:fLeftDeadzone",
            f64::from(controller.left_deadzone()),
        ),
        (
            "Controller:fOutputSaturation",
            f64::from(controller.output_saturation()),
        ),
        (
            "Controller:fResponseExponent",
            f64::from(controller.response_exponent()),
        ),
        (
            "Controller:fRightDeadzone",
            f64::from(controller.right_deadzone()),
        ),
        (
            "Controller:fRightHorizontalScale",
            f64::from(controller.right_horizontal_scale()),
        ),
        (
            "Controller:fRightVerticalScale",
            f64::from(controller.right_vertical_scale()),
        ),
        (
            "Controller:fTriggerPress",
            f64::from(controller.trigger_press()),
        ),
        (
            "Controller:fTriggerRelease",
            f64::from(controller.trigger_release()),
        ),
        (
            "Diagnostics:bBallisticsSummary",
            f64::from(ballistics.summary_requested()),
        ),
        (
            "Diagnostics:bBallisticsTrace",
            f64::from(ballistics.trace_enabled()),
        ),
        (
            "Diagnostics:bTelemetry",
            f64::from(input.telemetry_enabled()),
        ),
        (
            "Diagnostics:bWriteSummary",
            f64::from(input.summary_requested()),
        ),
        ("FirstPerson:bEnabled", f64::from(first_person.enabled())),
        (
            "FirstPerson:fCameraMotion",
            f64::from(first_person.camera_motion()),
        ),
        (
            "FirstPerson:fAimMotion",
            f64::from(first_person.aim_motion()),
        ),
        (
            "FirstPerson:fLandingMotion",
            f64::from(first_person.landing_motion()),
        ),
        (
            "FirstPerson:fWeaponMotion",
            f64::from(first_person.weapon_motion()),
        ),
        ("Input:bEnabled", f64::from(input.enabled())),
        ("Mouse:bInvertX", f64::from(mouse.invert_x())),
        ("Mouse:bInvertY", f64::from(mouse.invert_y())),
        (
            "Mouse:fHorizontalScale",
            f64::from(mouse.horizontal_scale()),
        ),
        ("Mouse:fSensitivity", f64::from(mouse.sensitivity())),
        ("Mouse:fVerticalScale", f64::from(mouse.vertical_scale())),
        ("Mouse:iProfile", f64::from(mouse.profile() as u8)),
        (
            "Movement:b360Movement",
            f64::from(third_person.movement_enabled()),
        ),
        ("Movement:bDrawn360", f64::from(third_person.drawn_360())),
        (
            "Movement:fTurnSpeed",
            f64::from(third_person.turn_speed_degrees()),
        ),
    ]);

    assert_eq!(
        actual.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>()
    );
    for (key, expected) in expected {
        let actual = actual[&key];
        assert!(
            (actual - expected).abs() < 0.000_001,
            "MCM default for {key} is {actual}, runtime default is {expected}"
        );
    }
}

#[test]
fn atom_ships_exactly_one_mcm_menu() {
    let mcm_directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("mcm");
    let mut menus = fs::read_dir(mcm_directory)
        .expect("the Atom MCM directory must be readable")
        .map(|entry| entry.expect("MCM directory entry must be readable").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .map(|path| {
            path.file_name()
                .expect("MCM menu needs a file name")
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    menus.sort();
    assert_eq!(menus, ["Atom.json"]);
}

#[test]
fn shipped_mcm_uses_feature_categories_without_filler_rows() {
    let document = load_mcm();
    let submenus = document["submenus"]
        .as_object()
        .expect("submenus must be an object");
    let expected = [
        (
            "1",
            "Input",
            &["General", "Mouse", "Controller", "Triggers"][..],
            &["Input:", "Mouse:", "Controller:"][..],
        ),
        (
            "2",
            "Camera",
            &[
                "First Person",
                "Third Person",
                "Third Orbit",
                "Third Movement",
            ][..],
            &["FirstPerson:", "Camera:", "Movement:"][..],
        ),
        (
            "3",
            "Ballistics",
            &["Projectiles"][..],
            &["Ballistics:"][..],
        ),
        (
            "4",
            "Diagnostics",
            &["Runtime", "Ballistics"][..],
            &["Diagnostics:"][..],
        ),
    ];
    assert_eq!(submenus.len(), expected.len());

    for (submenu_id, title, expected_sections, allowed_prefixes) in expected {
        let submenu = &submenus[submenu_id];
        assert_eq!(submenu["listTitle"], title);
        assert_eq!(submenu["pageTitle"], title);
        let options = submenu["options"]
            .as_object()
            .expect("submenu options must be an object");
        let mut sections = Vec::new();
        for option_id in 1..=options.len() {
            let option_id = option_id.to_string();
            let option = options
                .get(&option_id)
                .expect("option identifiers must be contiguous");
            let option_type = option["type"].as_f64().expect("numeric option type");
            if option_type == 0.0 {
                sections.push(option["title"].as_str().expect("section title"));
                assert!(
                    option.get("vars").is_none(),
                    "section cannot persist a value"
                );
                continue;
            }

            assert_ne!(option_type, 7.0, "informational filler rows are prohibited");
            let variables = option["vars"]
                .as_array()
                .expect("every interactive row must persist a setting");
            assert_eq!(variables.len(), 1, "one row must own one setting");
            let key = variables[0]["configINI"]
                .as_str()
                .expect("persisted variables need configINI");
            assert!(
                allowed_prefixes
                    .iter()
                    .any(|prefix| key.starts_with(prefix)),
                "{key} is filed under the wrong MCM feature category"
            );
        }
        assert_eq!(sections, expected_sections);
    }

    assert_eq!(submenus["1"]["active"], 1);
    for submenu_id in ["2", "3", "4"] {
        assert!(submenus[submenu_id].get("active").is_none());
    }
}

#[test]
fn shipped_mcm_text_fits_the_laconic_viewport_contract() {
    let document = load_mcm();
    assert_laconic("displayName", &document["displayName"]);
    assert_laconic("description", &document["description"]);

    for (submenu_id, submenu) in document["submenus"]
        .as_object()
        .expect("submenus must be an object")
    {
        assert_laconic(
            &format!("submenu {submenu_id} listTitle"),
            &submenu["listTitle"],
        );
        assert_laconic(
            &format!("submenu {submenu_id} pageTitle"),
            &submenu["pageTitle"],
        );

        for (option_id, option) in submenu["options"]
            .as_object()
            .expect("submenu options must be an object")
        {
            for field in ["title", "mouse", "string"] {
                if let Some(text) = option.get(field) {
                    assert_laconic(
                        &format!("submenu {submenu_id} option {option_id} {field}"),
                        text,
                    );
                }
            }
            if let Some(choices) = option.get("strings") {
                for (choice_id, text) in choices
                    .as_array()
                    .expect("option strings must be an array")
                    .iter()
                    .enumerate()
                {
                    assert_laconic(
                        &format!("submenu {submenu_id} option {option_id} choice {choice_id}"),
                        text,
                    );
                }
            }
        }
    }
}

fn load_mcm() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("mcm")
        .join("Atom.json");
    serde_json::from_str(
        &fs::read_to_string(path).expect("the shipped MCM artifact must be readable"),
    )
    .expect("the shipped MCM artifact must be valid JSON")
}

fn assert_laconic(label: &str, value: &Value) {
    let text = value.as_str().expect("MCM display text must be a string");
    let words = text.split_whitespace().count();
    assert!(
        (1..=3).contains(&words),
        "{label} contains {words} words: {text:?}"
    );
}

fn collect_persisted_defaults(document: &Value) -> BTreeMap<&str, f64> {
    let mut defaults = BTreeMap::new();
    for submenu in document["submenus"]
        .as_object()
        .expect("submenus must be an object")
        .values()
    {
        for option in submenu["options"]
            .as_object()
            .expect("submenu options must be an object")
            .values()
        {
            let Some(vars) = option.get("vars") else {
                continue;
            };
            for variable in vars.as_array().expect("vars must be an array") {
                let key = variable["configINI"]
                    .as_str()
                    .expect("persisted variables need configINI");
                let value = variable["default"]
                    .as_f64()
                    .expect("Atom MCM defaults are numeric");
                assert!(
                    defaults.insert(key, value).is_none(),
                    "duplicate MCM key {key}"
                );

                if let Some(scale) = option.get("scale") {
                    let minimum = scale["valueMin"].as_f64().expect("slider minimum");
                    let maximum = scale["valueMax"].as_f64().expect("slider maximum");
                    assert!(
                        (minimum..=maximum).contains(&value),
                        "MCM default for {key} is outside its slider bounds"
                    );
                }
            }
        }
    }
    defaults
}
