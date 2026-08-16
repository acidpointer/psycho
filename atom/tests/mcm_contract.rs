//! Behavioral checks for the MCM JSON artifact shipped to players.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use atom::input::InputConfig;
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
    let defaults = InputConfig::default();
    let mouse = defaults.mouse();
    let controller = defaults.controller();
    let expected = BTreeMap::from([
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
            "Diagnostics:bTelemetry",
            f64::from(defaults.telemetry_enabled()),
        ),
        (
            "Diagnostics:bWriteSummary",
            f64::from(defaults.summary_requested()),
        ),
        ("Input:bEnabled", f64::from(defaults.enabled())),
        ("Mouse:bInvertX", f64::from(mouse.invert_x())),
        ("Mouse:bInvertY", f64::from(mouse.invert_y())),
        (
            "Mouse:fHorizontalScale",
            f64::from(mouse.horizontal_scale()),
        ),
        ("Mouse:fSensitivity", f64::from(mouse.sensitivity())),
        ("Mouse:fVerticalScale", f64::from(mouse.vertical_scale())),
        ("Mouse:iProfile", f64::from(mouse.profile() as u8)),
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
