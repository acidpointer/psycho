//! Profile regressions execute the shipped UI, runtime handlers and workers.
//! File-owning cases run in isolated child processes so their game-relative
//! paths cannot affect the repository, an installation, or other tests.

use super::*;
use crate::test_workspace::isolated;
use std::{fs, time::Duration};

#[test]
fn builtin_activation_disables_debugging_and_persists_it() {
    let Some(_workspace) =
        isolated("runtime::profile_tests::builtin_activation_disables_debugging_and_persists_it")
    else {
        return;
    };
    libpsycho::logger::Logger::new()
        .with_file_rotating("default-debug.log")
        .with_level(log::LevelFilter::Debug)
        .init()
        .unwrap();
    let mut runtime = runtime();
    runtime.settings.menu_config.debug_log = true;
    runtime.settings.menu_config.native_pbr.debug_log_draws = true;
    let effects = &mut runtime.settings.menu_config.embedded_effects;
    effects.fast_ao.debug_depth = true;
    effects.volumetric_fog.debug_view = 8;
    effects.volumetric_lighting.debug_view = 8;
    effects.blooming_hdr.debug_bloom = true;
    effects.color_grade.debug_split = true;
    effects.sunshafts.debug_mask = true;
    effects.nfaa.debug_view = 1;
    effects.dlaa.debug_view = 1;
    effects.smaa.debug_view = 1;
    let mut shadows = crate::effects::shadows::runtime_config();
    shadows.debug_logging = true;
    shadows.interior_darkness = 0.37;
    crate::effects::shadows::configure_runtime_options(shadows.into());
    crate::graphics_diagnostics::set_profiler_active(true);
    let user_key = create(&mut runtime, "Debug Session");
    let user_index = runtime
        .preset_ui
        .catalog
        .entries
        .iter()
        .position(|entry| entry.key().as_ref() == Some(&user_key))
        .unwrap();
    runtime.activate_preset(user_index);
    assert!(runtime.settings.menu_config.debug_log);
    assert!(runtime.settings.menu_config.native_pbr.debug_log_draws);
    assert!(crate::effects::shadows::runtime_config().debug_logging);
    assert!(crate::graphics_diagnostics::profiler_active());
    crate::config::save_menu_config(&runtime.settings.menu_config).unwrap();
    runtime.current_look_service = Some(CurrentLookService::start().unwrap());

    let default = runtime
        .preset_ui
        .catalog
        .entries
        .iter()
        .position(|e| e.built_in)
        .unwrap();
    runtime.activate_preset(default);
    assert!(
        runtime.preset_ui.error.is_none(),
        "{:?}",
        runtime.preset_ui.error
    );
    wait_for_durable(&mut runtime);
    let saved: toml::Value =
        toml::from_str(&fs::read_to_string(crate::config::CONFIG_PATH).unwrap()).unwrap();
    fn assert_debug_off(value: &toml::Value) {
        if let Some(table) = value.as_table() {
            for (key, value) in table {
                if key.starts_with("debug") {
                    assert!(
                        value.as_bool() == Some(false) || value.as_integer() == Some(0),
                        "{key} = {value}"
                    );
                }
                assert_debug_off(value);
            }
        }
    }
    assert_debug_off(&saved);
    assert!(!crate::graphics_diagnostics::profiler_active());
    assert_eq!(
        crate::effects::shadows::runtime_config().interior_darkness,
        0.37
    );
    assert!(
        !crate::config::load_native_shadows_config_from_disk()
            .unwrap()
            .debug_logging
    );
    assert!(!log::log_enabled!(log::Level::Debug));
    log::warn!("actionable warnings remain enabled");
    libpsycho::logger::Logger::shutdown();
    assert!(
        fs::read_to_string("default-debug.log")
            .unwrap()
            .contains("actionable warnings remain enabled")
    );
}

fn runtime() -> ScreenShaderRuntime {
    let mut runtime = ScreenShaderRuntime::default();
    runtime.color_luts.assets = crate::luts::shipped_luts_for_test()
        .into_iter()
        .map(Arc::new)
        .collect();
    runtime.shader_catalog_generation = 1;
    runtime.lut_catalog_generation = 1;
    runtime.preset_ui.service = Some(PresetService::start().unwrap());
    wait(&mut runtime, |runtime| {
        !runtime.preset_ui.catalog.entries.is_empty()
    });
    runtime
}

fn wait(runtime: &mut ScreenShaderRuntime, ready: impl Fn(&ScreenShaderRuntime) -> bool) {
    let end = Instant::now() + Duration::from_secs(15);
    loop {
        runtime.poll_preset_service();
        if ready(runtime) {
            return;
        }
        assert!(
            Instant::now() < end,
            "profile worker timed out: {:?}",
            runtime.preset_ui.error
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn queue_create(runtime: &mut ScreenShaderRuntime, name: &str) {
    write_text_buffer(&mut runtime.preset_ui.creator().name, name);
    runtime.create_preset_from_current();
    assert!(
        runtime.preset_ui.create_pending,
        "{:?}",
        runtime.preset_ui.error
    );
}

fn create(runtime: &mut ScreenShaderRuntime, name: &str) -> PresetKey {
    queue_create(runtime, name);
    wait(runtime, |runtime| !runtime.preset_ui.create_pending);
    runtime
        .preset_ui
        .active
        .as_ref()
        .expect("published preset active")
        .key
        .clone()
}

fn library_frame(
    context: &mut psycho_imgui::test_support::TestContext,
    state: &mut PresetUiState,
) -> Option<MenuAction> {
    let action;
    {
        let mut ui = context.new_frame(1280.0, 900.0);
        ui.set_next_window_pos(10.0, 10.0, psycho_imgui::Condition::Always);
        ui.set_next_window_size(1100.0, 800.0, psycho_imgui::Condition::Always);
        let window = ui.window(c"Profiles", None);
        assert!(window.is_visible());
        action = draw_presets_tab(&mut ui, state);
    }
    context.render();
    action
}

#[test]
fn update_action_is_visible_and_clickable_in_the_library() {
    let mut context = psycho_imgui::test_support::TestContext::default();
    let mut state = PresetUiState::default();
    library_frame(&mut context, &mut state);
    library_frame(&mut context, &mut state);
    let [x, y] = context
        .button_center(c"Update Preset##profile_update")
        .expect("Update must stay visible for a custom look and explain the create-copy route");
    context.pointer(x, y, true);
    library_frame(&mut context, &mut state);
    context.pointer(x, y, false);
    library_frame(&mut context, &mut state);
    assert!(state.view == PresetUiView::Create);
}

#[test]
fn publication_completion_preserves_subsequent_edits() {
    let Some(_workspace) =
        isolated("runtime::profile_tests::publication_completion_preserves_subsequent_edits")
    else {
        return;
    };
    let mut runtime = runtime();
    queue_create(&mut runtime, "Cinema");
    runtime.settings.menu_config.native_sky.atmosphere_thickness = 1.75;
    runtime.current_look_autosave.note_change(Instant::now());
    wait(&mut runtime, |runtime| !runtime.preset_ui.create_pending);
    assert!(
        runtime.preset_ui.active.as_ref().unwrap().modified,
        "a completed snapshot must not mark subsequent edits clean"
    );
}

#[test]
fn publication_completion_preserves_a_later_activation() {
    let Some(_workspace) =
        isolated("runtime::profile_tests::publication_completion_preserves_a_later_activation")
    else {
        return;
    };
    let mut runtime = runtime();
    let first = create(&mut runtime, "First");
    queue_create(&mut runtime, "Second");
    let index = runtime
        .preset_ui
        .catalog
        .entries
        .iter()
        .position(|entry| entry.key().as_ref() == Some(&first))
        .unwrap();
    runtime.activate_preset(index);
    wait(&mut runtime, |runtime| !runtime.preset_ui.create_pending);
    assert_eq!(runtime.preset_ui.active.as_ref().unwrap().key, first);
}

#[test]
fn restoration_cannot_replace_a_later_activation() {
    let Some(_workspace) =
        isolated("runtime::profile_tests::restoration_cannot_replace_a_later_activation")
    else {
        return;
    };
    let mut runtime = runtime();
    let first = create(&mut runtime, "First");
    let first_revision = runtime.preset_ui.active.as_ref().unwrap().payload_revision;
    let second = create(&mut runtime, "Second");
    runtime.preset_ui.pending_saved_state = Some(PresetActiveState::new(&first, first_revision));
    runtime.preset_ui.saved_state_loaded = true;
    let index = runtime
        .preset_ui
        .catalog
        .entries
        .iter()
        .position(|entry| entry.key().as_ref() == Some(&second))
        .unwrap();
    runtime.activate_preset(index);
    runtime.reconcile_saved_preset_state();
    assert_eq!(runtime.preset_ui.active.as_ref().unwrap().key, second);
}

#[test]
fn refresh_does_not_authorize_overwriting_an_external_preset_edit() {
    let Some(_workspace) = isolated(
        "runtime::profile_tests::refresh_does_not_authorize_overwriting_an_external_preset_edit",
    ) else {
        return;
    };
    let mut runtime = runtime();
    let key = create(&mut runtime, "Cinema");
    let path = runtime
        .preset_ui
        .catalog
        .entries
        .iter()
        .find(|entry| entry.key().as_ref() == Some(&key))
        .unwrap()
        .path
        .clone()
        .unwrap();
    let previous_hash = runtime
        .preset_ui
        .catalog
        .entries
        .iter()
        .find(|entry| entry.key().as_ref() == Some(&key))
        .unwrap()
        .content_hash;
    let mut changed: toml::Value = fs::read_to_string(&path).unwrap().parse().unwrap();
    changed["settings"]["native_sky"]["atmosphere_thickness"] = toml::Value::Float(2.0);
    let external = toml::to_string_pretty(&changed).unwrap();
    fs::write(&path, &external).unwrap();
    runtime
        .preset_ui
        .service
        .as_ref()
        .unwrap()
        .request_refresh()
        .unwrap();
    wait(&mut runtime, |runtime| {
        runtime
            .preset_ui
            .catalog
            .entries
            .iter()
            .any(|entry| entry.key().as_ref() == Some(&key) && entry.content_hash != previous_hash)
    });
    runtime.settings.menu_config.native_sky.atmosphere_thickness = 1.5;
    runtime.refresh_active_preset_status();
    write_text_buffer(&mut runtime.preset_ui.update_version, "1.0.1");
    runtime.publish_active_preset_version();
    wait(&mut runtime, |runtime| !runtime.preset_ui.update_pending);
    assert_eq!(
        fs::read_to_string(path).unwrap(),
        external,
        "refresh cannot silently rebase overwrite permission"
    );
}

#[test]
fn multiline_description_can_be_captured_and_loaded() {
    let mut runtime = ScreenShaderRuntime::default();
    runtime.color_luts.assets = crate::luts::shipped_luts_for_test()
        .into_iter()
        .map(Arc::new)
        .collect();
    let result = PresetPublishRequest::capture(
        "Cinema",
        "1.0.0",
        "Author",
        "First line\nSecond line",
        &runtime.settings.menu_config,
        &runtime.sources,
        &runtime.color_luts,
    );
    assert!(
        result.is_ok(),
        "the multiline editor must accept a multiline description: {result:?}"
    );
}

fn click(
    context: &mut psycho_imgui::test_support::TestContext,
    state: &mut PresetUiState,
    label: &std::ffi::CStr,
) -> Option<MenuAction> {
    let [x, y] = context.button_center(label).expect("visible native widget");
    context.pointer(x, y, true);
    library_frame(context, state);
    context.pointer(x, y, false);
    library_frame(context, state)
}

fn enter(
    context: &mut psycho_imgui::test_support::TestContext,
    state: &mut PresetUiState,
    label: &std::ffi::CStr,
    text: &str,
) {
    click(context, state, label);
    context.text(&cstring(text));
    library_frame(context, state);
}

fn wait_for_durable(runtime: &mut ScreenShaderRuntime) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        runtime.poll_preset_service();
        runtime.service_current_look();
        let session = runtime.preset_ui.session();
        if !session.state_dirty
            && !session.state_in_flight
            && runtime.current_look_autosave.is_settled()
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "persistence timed out: {:?} {:?}",
            runtime.menu_config_error,
            runtime.preset_ui.error
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn native_creator_preserves_unicode_and_multiline_input() {
    let Some(_workspace) =
        isolated("runtime::profile_tests::native_creator_preserves_unicode_and_multiline_input")
    else {
        return;
    };
    let mut runtime = runtime();
    let mut context = psycho_imgui::test_support::TestContext::default();
    library_frame(&mut context, &mut runtime.preset_ui);
    library_frame(&mut context, &mut runtime.preset_ui);
    click(
        &mut context,
        &mut runtime.preset_ui,
        c"Create a New Preset##profile_create",
    );
    library_frame(&mut context, &mut runtime.preset_ui);
    let name = "\u{1f31e}".repeat(80);
    let author = "\u{0416}".repeat(80);
    let description = format!("{}\n{}", "\u{6c34}".repeat(255), "\u{6c34}".repeat(256));
    enter(
        &mut context,
        &mut runtime.preset_ui,
        c"##preset_name",
        &name,
    );
    enter(
        &mut context,
        &mut runtime.preset_ui,
        c"##preset_author",
        &author,
    );
    enter(
        &mut context,
        &mut runtime.preset_ui,
        c"##preset_description",
        &description,
    );
    assert_eq!(text_buffer(&runtime.preset_ui.creator().name), name);
    assert_eq!(text_buffer(&runtime.preset_ui.creator().author), author);
    assert_eq!(
        text_buffer(&runtime.preset_ui.creator().description),
        description
    );
    assert!(matches!(
        click(
            &mut context,
            &mut runtime.preset_ui,
            c"Create Preset & Use It##preset_create"
        ),
        Some(MenuAction::CreatePreset)
    ));
    runtime.create_preset_from_current();
    wait(&mut runtime, |runtime| !runtime.preset_ui.create_pending);
    let key = &runtime.preset_ui.active.as_ref().unwrap().key;
    let entry = runtime
        .preset_ui
        .catalog
        .entries
        .iter()
        .find(|entry| entry.key().as_ref() == Some(key))
        .unwrap();
    assert_eq!(entry.display_name, name);
    assert_eq!(entry.author, author);
    assert_eq!(entry.description, description);
}

#[test]
fn update_keeps_path_family_and_metadata_and_restores_after_restart() {
    let Some(_workspace) = isolated(
        "runtime::profile_tests::update_keeps_path_family_and_metadata_and_restores_after_restart",
    ) else {
        return;
    };
    let mut runtime = runtime();
    crate::config::save_menu_config(&runtime.settings.menu_config).unwrap();
    runtime.current_look_service = Some(CurrentLookService::start().unwrap());
    write_text_buffer(&mut runtime.preset_ui.creator().author, "Author");
    write_text_buffer(
        &mut runtime.preset_ui.creator().description,
        "First line\nSecond line",
    );
    let key = create(&mut runtime, "Cinema");
    let path = runtime
        .preset_ui
        .catalog
        .entries
        .iter()
        .find(|entry| entry.key().as_ref() == Some(&key))
        .unwrap()
        .path
        .clone()
        .unwrap();
    runtime.settings.menu_config.native_sky.atmosphere_thickness = 1.75;
    runtime.refresh_active_preset_status();
    runtime.current_look_autosave.note_change(Instant::now());
    write_text_buffer(&mut runtime.preset_ui.update_version, "1.0.1");
    runtime.publish_active_preset_version();
    assert!(runtime.preset_ui.update_pending);
    wait(&mut runtime, |runtime| !runtime.preset_ui.update_pending);
    assert!(
        runtime.preset_ui.error.is_none(),
        "{:?}",
        runtime.preset_ui.error
    );
    wait_for_durable(&mut runtime);
    let updated = runtime.preset_ui.active.as_ref().unwrap().key.clone();
    assert_eq!(updated.id, key.id);
    assert_eq!(updated.version, "1.0.1");
    let entry = runtime
        .preset_ui
        .catalog
        .entries
        .iter()
        .find(|entry| entry.key().as_ref() == Some(&updated))
        .unwrap();
    assert_eq!(entry.path.as_ref(), Some(&path));
    assert_eq!(entry.author, "Author");
    assert_eq!(entry.description, "First line\nSecond line");
    assert_eq!(
        fs::read_dir(crate::presets::PRESET_DIRECTORY)
            .unwrap()
            .count(),
        1
    );
    drop(runtime);
    let mut restarted = ScreenShaderRuntime::default();
    restarted.settings.menu_config = crate::config::load_menu_config_from_disk().unwrap();
    restarted.color_luts.assets = crate::luts::shipped_luts_for_test()
        .into_iter()
        .map(Arc::new)
        .collect();
    restarted.shader_catalog_generation = 1;
    restarted.lut_catalog_generation = 1;
    restarted.preset_ui.service = Some(PresetService::start().unwrap());
    wait(&mut restarted, |runtime| runtime.preset_ui.active.is_some());
    assert_eq!(
        restarted
            .settings
            .menu_config
            .native_sky
            .atmosphere_thickness,
        1.75
    );
    assert_eq!(restarted.preset_ui.active.as_ref().unwrap().key, updated);
    assert!(!restarted.preset_ui.active.as_ref().unwrap().modified);
}

#[test]
fn local_settings_and_reverted_edits_do_not_offer_a_visual_update() {
    let Some(_workspace) = isolated(
        "runtime::profile_tests::local_settings_and_reverted_edits_do_not_offer_a_visual_update",
    ) else {
        return;
    };
    let mut runtime = runtime();
    create(&mut runtime, "Cinema");
    let sky = runtime.settings.menu_config.native_sky.atmosphere_thickness;
    runtime.settings.menu_config.shader_scan_interval_ms = 1234;
    runtime.settings.menu_config.menu_toggle_key = 0x24;
    runtime.refresh_active_preset_status();
    assert!(!runtime.preset_ui.active.as_ref().unwrap().modified);
    runtime.settings.menu_config.native_sky.atmosphere_thickness = 1.75;
    runtime.refresh_active_preset_status();
    assert!(runtime.preset_ui.active.as_ref().unwrap().modified);
    runtime.settings.menu_config.native_sky.atmosphere_thickness = sky;
    runtime.refresh_active_preset_status();
    assert!(!runtime.preset_ui.active.as_ref().unwrap().modified);
    assert!(
        runtime
            .preset_ui
            .update_unavailable()
            .unwrap()
            .contains("No preset changes")
    );
}

#[test]
fn an_installed_target_version_rejects_update_without_replacing_the_source() {
    let Some(_workspace) = isolated(
        "runtime::profile_tests::an_installed_target_version_rejects_update_without_replacing_the_source",
    ) else {
        return;
    };
    let mut runtime = runtime();
    let key = create(&mut runtime, "Cinema");
    let path = runtime
        .preset_ui
        .catalog
        .entries
        .iter()
        .find(|entry| entry.key().as_ref() == Some(&key))
        .unwrap()
        .path
        .clone()
        .unwrap();
    let original = fs::read_to_string(&path).unwrap();
    let mut installed: toml::Value = original.parse().unwrap();
    installed["preset"]["version"] = toml::Value::String("1.0.1".to_owned());
    let installed = toml::to_string_pretty(&installed).unwrap();
    let other = path.with_file_name("installed-update.omvpreset.toml");
    fs::write(&other, &installed).unwrap();
    runtime.settings.menu_config.native_sky.atmosphere_thickness = 1.75;
    runtime.refresh_active_preset_status();
    write_text_buffer(&mut runtime.preset_ui.update_version, "1.0.1");
    runtime.publish_active_preset_version();
    wait(&mut runtime, |runtime| !runtime.preset_ui.update_pending);
    assert!(
        runtime
            .preset_ui
            .error
            .as_ref()
            .unwrap()
            .contains("already installed")
    );
    assert_eq!(fs::read_to_string(path).unwrap(), original);
    assert_eq!(fs::read_to_string(other).unwrap(), installed);
}

#[test]
fn publication_with_a_conflicting_refresh_finishes_and_cannot_activate_later() {
    let Some(_workspace) = isolated(
        "runtime::profile_tests::publication_with_a_conflicting_refresh_finishes_and_cannot_activate_later",
    ) else {
        return;
    };
    let mut runtime = runtime();
    let (reached, resume) = crate::presets::pause_publication_for_test();
    queue_create(&mut runtime, "Cinema");
    reached.recv_timeout(Duration::from_secs(5)).unwrap();
    let path = std::path::Path::new(crate::presets::PRESET_DIRECTORY).join("cinema.omvpreset.toml");
    let mut conflict: toml::Value = fs::read_to_string(&path).unwrap().parse().unwrap();
    conflict["preset"].as_table_mut().unwrap().insert(
        "author".to_owned(),
        toml::Value::String("External author".to_owned()),
    );
    let conflict_path = path.with_file_name("conflict.omvpreset.toml");
    fs::write(&conflict_path, toml::to_string_pretty(&conflict).unwrap()).unwrap();
    resume.send(()).unwrap();
    wait(&mut runtime, |runtime| !runtime.preset_ui.create_pending);
    assert!(
        runtime
            .preset_ui
            .error
            .as_ref()
            .unwrap()
            .contains("was written")
    );
    assert!(runtime.preset_ui.active.is_none());
    fs::remove_file(conflict_path).unwrap();
    runtime.refresh_presets();
    wait(&mut runtime, |runtime| {
        !runtime
            .preset_ui
            .session
            .session
            .as_ref()
            .unwrap()
            .refresh_pending
    });
    assert!(
        runtime.preset_ui.active.is_none(),
        "refresh must not resurrect a failed publication's activation intent"
    );
    create(&mut runtime, "Next");
    assert_eq!(runtime.preset_ui.active.as_ref().unwrap().name, "Next");
}

#[test]
fn provenance_waits_for_autosave_and_retries_failed_state_writes() {
    let Some(_workspace) = isolated(
        "runtime::profile_tests::provenance_waits_for_autosave_and_retries_failed_state_writes",
    ) else {
        return;
    };
    let mut runtime = runtime();
    crate::config::save_menu_config(&runtime.settings.menu_config).unwrap();
    runtime.current_look_service = Some(CurrentLookService::start().unwrap());
    let state_path =
        std::path::Path::new(crate::config::CONFIG_PATH).with_file_name("omv-state.toml");
    fs::create_dir(&state_path).unwrap();
    create(&mut runtime, "Cinema");
    runtime.current_look_autosave.note_change(Instant::now());
    runtime.service_current_look();
    assert!(runtime.current_look_autosave.is_dirty());
    assert!(
        !runtime.preset_ui.session().state_in_flight,
        "provenance cannot precede a durable working revision"
    );
    runtime.current_look_autosave.flush_pending(Instant::now());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        runtime.poll_preset_service();
        runtime.service_current_look();
        if runtime.preset_ui.session().state_error.is_some() {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    fs::remove_dir(&state_path).unwrap();
    wait_for_durable(&mut runtime);
    assert!(state_path.is_file());
    assert!(
        runtime.preset_ui.error.is_none(),
        "successful retry clears its own error"
    );
}

#[test]
fn a_state_recording_failure_does_not_finish_a_pending_publication() {
    let Some(_workspace) = isolated(
        "runtime::profile_tests::a_state_recording_failure_does_not_finish_a_pending_publication",
    ) else {
        return;
    };
    let mut runtime = runtime();
    let first = create(&mut runtime, "First");
    let state_path =
        std::path::Path::new(crate::config::CONFIG_PATH).with_file_name("omv-state.toml");
    fs::create_dir(&state_path).unwrap();
    let revision = runtime.preset_ui.active.as_ref().unwrap().payload_revision;
    runtime
        .preset_ui
        .service
        .as_ref()
        .unwrap()
        .record_active_state(Some(PresetActiveState::new(&first, revision)))
        .unwrap();
    let (reached, resume) = crate::presets::pause_publication_for_test();
    queue_create(&mut runtime, "Second");
    reached.recv_timeout(Duration::from_secs(5)).unwrap();
    runtime.poll_preset_service();
    assert!(runtime.preset_ui.create_pending);
    resume.send(()).unwrap();
    wait(&mut runtime, |runtime| !runtime.preset_ui.create_pending);
    assert_eq!(runtime.preset_ui.active.as_ref().unwrap().name, "Second");
}

#[test]
fn unreadable_catalog_root_keeps_the_builtin_available() {
    let Some(_workspace) =
        isolated("runtime::profile_tests::unreadable_catalog_root_keeps_the_builtin_available")
    else {
        return;
    };
    let path = std::path::Path::new(crate::presets::PRESET_DIRECTORY);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        path,
        "an invalid installation occupies the preset directory",
    )
    .unwrap();
    let mut runtime = runtime();
    assert!(
        runtime
            .preset_ui
            .catalog
            .entries
            .iter()
            .any(|entry| entry.built_in && entry.document.is_some())
    );
    assert!(
        runtime
            .preset_ui
            .catalog
            .entries
            .iter()
            .any(|entry| entry.error.is_some())
    );
    fs::remove_file(path).unwrap();
    runtime.refresh_presets();
    wait(&mut runtime, |runtime| {
        !runtime
            .preset_ui
            .session
            .session
            .as_ref()
            .unwrap()
            .refresh_pending
    });
    assert_eq!(runtime.preset_ui.catalog.entries.len(), 1);
}

#[test]
fn loose_documents_cannot_make_the_default_family_writable() {
    let Some(_workspace) =
        isolated("runtime::profile_tests::loose_documents_cannot_make_the_default_family_writable")
    else {
        return;
    };
    let mut runtime = runtime();
    let builtin = runtime
        .preset_ui
        .catalog
        .entries
        .iter()
        .find(|entry| entry.built_in)
        .unwrap()
        .key()
        .unwrap();
    let key = create(&mut runtime, "Cinema");
    let path = runtime
        .preset_ui
        .catalog
        .entries
        .iter()
        .find(|entry| entry.key().as_ref() == Some(&key))
        .unwrap()
        .path
        .clone()
        .unwrap();
    let mut document: toml::Value = fs::read_to_string(&path).unwrap().parse().unwrap();
    document["preset"]["id"] = toml::Value::String(builtin.id.clone());
    fs::write(&path, toml::to_string_pretty(&document).unwrap()).unwrap();
    runtime.refresh_presets();
    wait(&mut runtime, |runtime| {
        !runtime
            .preset_ui
            .session
            .session
            .as_ref()
            .unwrap()
            .refresh_pending
    });
    let index = runtime
        .preset_ui
        .catalog
        .entries
        .iter()
        .position(|entry| entry.path.as_ref() == Some(&path))
        .unwrap();
    runtime.activate_preset(index);
    assert!(runtime.preset_ui.active.as_ref().unwrap().built_in);
    runtime.settings.menu_config.native_sky.atmosphere_thickness = 1.75;
    runtime.refresh_active_preset_status();
    assert!(
        runtime
            .preset_ui
            .update_unavailable()
            .unwrap()
            .contains("read-only")
    );
}

#[test]
fn dependency_aliases_cannot_apply_one_external_shader_twice() {
    let Some(_workspace) = isolated(
        "runtime::profile_tests::dependency_aliases_cannot_apply_one_external_shader_twice",
    ) else {
        return;
    };
    fs::create_dir_all(shaders::SHADER_DIR).unwrap();
    let shader = std::path::Path::new(shaders::SHADER_DIR).join("cas.hlsl");
    fs::write(
        &shader,
        include_bytes!("../shaders/runtime/01_depth_aware_cas.hlsl"),
    )
    .unwrap();
    fs::write(
        shader.with_extension("toml"),
        "[shader]\nid = \"35ec76b6-366e-40af-8386-1bd333c9b502\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();
    let mut runtime = runtime();
    runtime.sources = shaders::scan_screen_shaders(&[]).unwrap().sources;
    assert_eq!(runtime.sources.len(), 1);
    assert!(runtime.sources[0].shader_error.is_none());
    let key = create(&mut runtime, "Cinema");
    let path = runtime
        .preset_ui
        .catalog
        .entries
        .iter()
        .find(|entry| entry.key().as_ref() == Some(&key))
        .unwrap()
        .path
        .clone()
        .unwrap();
    let mut document: toml::Value = fs::read_to_string(&path).unwrap().parse().unwrap();
    let dependencies = document["dependencies"]["external_shaders"]
        .as_array_mut()
        .unwrap();
    let mut alias = dependencies[0].clone();
    alias.as_table_mut().unwrap().remove("shader_id");
    dependencies.push(alias);
    document["settings"]["native_sky"]["atmosphere_thickness"] = toml::Value::Float(1.75);
    fs::write(&path, toml::to_string_pretty(&document).unwrap()).unwrap();
    runtime.refresh_presets();
    wait(&mut runtime, |runtime| {
        !runtime
            .preset_ui
            .session
            .session
            .as_ref()
            .unwrap()
            .refresh_pending
    });
    let index = runtime
        .preset_ui
        .catalog
        .entries
        .iter()
        .position(|entry| entry.key().as_ref() == Some(&key))
        .unwrap();
    let before = runtime.settings.menu_config.native_sky.atmosphere_thickness;
    runtime.activate_preset(index);
    assert_eq!(
        runtime.settings.menu_config.native_sky.atmosphere_thickness,
        before
    );
    assert!(
        runtime
            .preset_ui
            .error
            .as_ref()
            .unwrap()
            .contains("multiple dependencies")
    );
}

fn workbench_frame(
    context: &mut psycho_imgui::test_support::TestContext,
    runtime: &mut ScreenShaderRuntime,
) {
    let mut shadows = crate::effects::shadows::runtime_config();
    let before = shadows;
    let result = {
        let mut ui = context.new_frame(1280.0, 900.0);
        draw_shader_menu(
            &mut ui,
            &mut runtime.settings.menu_config,
            &mut shadows,
            &mut runtime.sources,
            &mut runtime.preset_ui,
            &mut runtime.active_menu_tab,
            &mut runtime.selected_menu_item,
            &mut runtime.menu_sidebar_width,
            &FramePacingSnapshot::default(),
            EngineFeatureStatus {
                pbr: pbr::runtime_status(),
                sky: sky::runtime_status(),
                depth: backend::depth_resolve_status(backend::DepthProvider::None),
            },
            None,
            MenuPersistenceView {
                external_change: runtime.current_look_autosave.has_external_change(),
                reloading: runtime.current_look_autosave.is_reloading(),
                error: None,
            },
        )
    };
    context.render();
    runtime.apply_menu_frame(result, before, shadows);
}

fn click_workbench(
    context: &mut psycho_imgui::test_support::TestContext,
    runtime: &mut ScreenShaderRuntime,
    label: &std::ffi::CStr,
) {
    let [x, y] = context
        .button_center(label)
        .unwrap_or_else(|| panic!("native widget is not visible: {label:?}"));
    // Tabs allow overlap and require one hovered frame before a click.
    context.pointer(x, y, false);
    workbench_frame(context, runtime);
    context.pointer(x, y, true);
    workbench_frame(context, runtime);
    context.pointer(x, y, false);
    workbench_frame(context, runtime);
}

#[test]
fn customize_has_an_update_action_and_local_edits_preserve_visual_status() {
    let Some(_workspace) = isolated(
        "runtime::profile_tests::customize_has_an_update_action_and_local_edits_preserve_visual_status",
    ) else {
        return;
    };
    let mut runtime = runtime();
    runtime.settings.menu_config.menu_toggle_key = 0x24;
    create(&mut runtime, "Cinema");
    let mut context = psycho_imgui::test_support::TestContext::default();
    workbench_frame(&mut context, &mut runtime);
    workbench_frame(&mut context, &mut runtime);
    click_workbench(
        &mut context,
        &mut runtime,
        c"Customize##workbench_configuration",
    );
    workbench_frame(&mut context, &mut runtime);
    assert_eq!(runtime.active_menu_tab, MenuTab::Configuration);
    assert!(
        context
            .button_center(c"Update Preset##profile_update")
            .is_some()
    );
    click_workbench(
        &mut context,
        &mut runtime,
        c"Reset##global.menu_toggle_key.reset",
    );
    assert_eq!(
        runtime.settings.menu_config.menu_toggle_key,
        DEFAULT_MENU_TOGGLE_KEY
    );
    assert!(
        runtime.current_look_autosave.is_dirty(),
        "the actual UI edit still needs working-config persistence"
    );
    assert!(
        !runtime.preset_ui.active.as_ref().unwrap().modified,
        "a local preference is not a visual preset edit"
    );
}

#[test]
fn reload_owns_the_workbench_until_its_result_is_applied() {
    let Some(_workspace) =
        isolated("runtime::profile_tests::reload_owns_the_workbench_until_its_result_is_applied")
    else {
        return;
    };
    let mut runtime = runtime();
    let mut context = psycho_imgui::test_support::TestContext::default();
    workbench_frame(&mut context, &mut runtime);
    workbench_frame(&mut context, &mut runtime);
    let [x, y] = context
        .button_center(c"Update Preset##profile_update")
        .unwrap();
    runtime.current_look_autosave.external_change_detected(None);
    assert!(runtime.current_look_autosave.begin_reload());
    workbench_frame(&mut context, &mut runtime);
    assert!(
        context
            .button_center(c"Update Preset##profile_update")
            .is_none()
    );
    context.pointer(x, y, true);
    workbench_frame(&mut context, &mut runtime);
    context.pointer(x, y, false);
    workbench_frame(&mut context, &mut runtime);
    assert!(runtime.preset_ui.view == PresetUiView::Closed);
    runtime.current_look_autosave.reload_failed();
    workbench_frame(&mut context, &mut runtime);
    assert!(
        context
            .button_center(c"Update Preset##profile_update")
            .is_some()
    );
}

#[test]
fn native_shadow_preferences_apply_without_modifying_the_active_preset() {
    let Some(_workspace) = isolated(
        "runtime::profile_tests::native_shadow_preferences_apply_without_modifying_the_active_preset",
    ) else {
        return;
    };
    let mut runtime = runtime();
    create(&mut runtime, "Cinema");
    let mut context = psycho_imgui::test_support::TestContext::default();
    workbench_frame(&mut context, &mut runtime);
    workbench_frame(&mut context, &mut runtime);
    click_workbench(
        &mut context,
        &mut runtime,
        c"Customize##workbench_configuration",
    );
    workbench_frame(&mut context, &mut runtime);
    let before = crate::effects::shadows::runtime_config().enabled;
    let label = cstring(configured_feature_label(
        "Shadows",
        "native_shadows_select",
        before,
    ));
    click_workbench(&mut context, &mut runtime, &label);
    workbench_frame(&mut context, &mut runtime);
    click_workbench(
        &mut context,
        &mut runtime,
        c"Enable shadows##native_shadows.enabled",
    );
    assert_eq!(crate::effects::shadows::runtime_config().enabled, !before);
    assert!(!runtime.preset_ui.active.as_ref().unwrap().modified);
    assert!(runtime.current_look_autosave.is_dirty());
}
