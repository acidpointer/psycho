//! Standalone engine fixes.
//!
//! This module is for game contract fixes that are useful independent of
//! which heap allocator is active. Allocator mechanics and allocator-only
//! safety still live under `heap_replacer`.

use std::fmt::Write as _;

use libc::c_void;

use crate::config::{DiagnosticsConfig, EngineFixesConfig, LodConfig};

mod display;
mod entrydata;
mod extraownership;
mod havok;
mod linkedrefs;
mod lod;
mod lowprocess;
mod memset;
mod navmesh;
mod patching;
mod queued_tasks;
mod ragdoll;
mod save_integrity;
mod statics;
mod types;

pub(crate) struct DiagnosticCounters {
    pub(crate) ragdoll_calls: u64,
    pub(crate) ragdoll_skips: u64,
    pub(crate) extra_owner_load_scrubs: u64,
    pub(crate) extra_owner_access_scrubs: u64,
    pub(crate) extra_owner_unreadable: u64,
    pub(crate) task_dispatch_attempts: u64,
    pub(crate) task_dispatch_calls: u64,
    pub(crate) task_pin_failures: u64,
    pub(crate) task_invalid_dispatches: u64,
    pub(crate) task_release_guards: u64,
    pub(crate) task_tombstones: u64,
}

pub(crate) fn display_diagnostic_snapshot() -> display::DiagnosticSnapshot {
    display::diagnostic_snapshot()
}

pub fn install(
    config: &EngineFixesConfig,
    lod_config: &LodConfig,
    diagnostics: &DiagnosticsConfig,
) -> anyhow::Result<()> {
    install_save_integrity(config)?;
    install_navmesh_low_pointer(config)?;
    install_entrydata_invalid_form(config)?;
    install_extraownership_invalid_owner(config)?;
    install_linked_ref_children_stale_list(config)?;
    install_linked_ref_target_base_form(config)?;
    install_ragdoll_null_bone(config)?;
    install_ragdoll_detached_phantom(config)?;
    install_havok_guards(config)?;
    install_memset_null_dst(config)?;
    install_lowprocess_fix(config)?;
    install_queued_task_guard(config, diagnostics)?;
    lod::install(lod_config, diagnostics);

    Ok(())
}

/// Install the display IAT shim before allocator and other engine hooks.
pub fn install_display(config: &EngineFixesConfig) -> anyhow::Result<()> {
    if !config.display_alt_tab {
        log::info!("[DISPLAY] Fullscreen window fix disabled by config");
        return Ok(());
    }

    if let Err(err) = display::install_display_hooks() {
        log::warn!("[DISPLAY] Fullscreen window fix disabled: {}", err);
    }
    Ok(())
}

pub fn observe_event(kind: u32) {
    lowprocess::observe_event(kind);
}

pub(crate) fn take_diagnostic_counters() -> DiagnosticCounters {
    let ragdoll = ragdoll::take_diagnostic_counters();
    let extra_owner = extraownership::take_diagnostic_counters();
    let task = queued_tasks::diagnostic_snapshot();

    DiagnosticCounters {
        ragdoll_calls: ragdoll.calls,
        ragdoll_skips: ragdoll.skips,
        extra_owner_load_scrubs: extra_owner.load_scrubs,
        extra_owner_access_scrubs: extra_owner.access_scrubs,
        extra_owner_unreadable: extra_owner.unreadable,
        task_dispatch_attempts: task.dispatch_attempts,
        task_dispatch_calls: task.dispatch_calls,
        task_pin_failures: task.pin_failures,
        task_invalid_dispatches: task.invalid_dispatches,
        task_release_guards: task.release_guards,
        task_tombstones: task.tombstones,
    }
}

pub(crate) fn append_diagnostic_report(out: &mut String) {
    let display = display::diagnostic_snapshot();
    let low = lowprocess::diagnostic_snapshot();
    let task = queued_tasks::diagnostic_snapshot();
    let save = save_integrity::diagnostic_snapshot();
    let lod = lod::diagnostic_snapshot();

    push_report_section(out, "Runtime fixes");
    push_feature_pair(
        out,
        "Display",
        display.create_window_installed || display.installed,
        "LowProcess",
        low.enabled,
    );
    push_feature_pair(
        out,
        "Save integrity",
        save.factory_hook
            || save.owner_hook
            || save.activation_hook
            || save.fclose_hook
            || save.load_owner_hook,
        "Task guard",
        task.release_enabled || task.dispatch_enabled,
    );
    push_feature_pair(
        out,
        "LOD prefetch",
        lod.streaming_installed,
        "LOD handoff",
        lod.handoff_installed,
    );
    push_feature_pair(
        out,
        "Tree lifetime",
        lod.speedtree.installed,
        "LOD reset",
        lod.worldspace_reset_installed,
    );

    let covered_move_sites = display
        .site_states
        .iter()
        .filter(|state| display::site_state_name(**state) == "covered")
        .count();
    let display_events = u64::from(display.bootstrap_create_observations)
        .saturating_add(u64::from(display.windowed_parent_passthroughs))
        .saturating_add(u64::from(display.device_reset_observations))
        .saturating_add(u64::from(display.child_resize_passthroughs));
    let display_repairs = u64::from(display.bootstrap_create_corrections)
        .saturating_add(u64::from(display.device_reset_corrections))
        .saturating_add(u64::from(display.loss_suppressions))
        .saturating_add(u64::from(display.regain_normalizations))
        .saturating_add(u64::from(display.lifecycle_normalizations))
        .saturating_add(u64::from(display.catch_up_successes));
    let monitor_picks = u64::from(display.monitor_point_selections)
        .saturating_add(u64::from(display.monitor_window_selections))
        .saturating_add(u64::from(display.monitor_fallbacks));
    let low_repairs = u64::from(low.wraps)
        .saturating_add(u64::from(low.rewraps))
        .saturating_add(u64::from(low.sanitized_entries))
        .saturating_add(u64::from(low.main_boundary_restores));
    let low_slots = low
        .slot_states
        .iter()
        .filter(|state| matches!(lowprocess::slot_state_name(**state), "wrapped" | "chained"))
        .count();
    let low_owners = low.predecessors.iter().filter(|owner| **owner != 0).count();

    push_report_section(out, "Engine activity");
    push_report_value(
        out,
        "Display hooks",
        format!(
            "create {}/{} / move {}/{}",
            on_off(display.create_window_installed),
            native_owner(display.create_window_predecessor_vanilla),
            on_off(display.installed),
            native_owner(display.predecessor_vanilla),
        ),
    );
    push_report_value(
        out,
        "Display owners",
        format!(
            "{:08X} / {:08X}",
            display.create_window_predecessor, display.predecessor,
        ),
    );
    push_report_value(
        out,
        "Display sites",
        format!(
            "create {} / move {covered_move_sites}/6",
            display::site_state_name(display.bootstrap_create_state),
        ),
    );
    push_report_value(
        out,
        "Display work",
        format!("{display_events} events / {display_repairs} repairs"),
    );
    push_report_value(
        out,
        "Display recovery",
        format!(
            "{} tried / {} restore / {} picks",
            display.catch_up_attempts, display.restore_attempts, monitor_picks,
        ),
    );
    push_report_value(
        out,
        "Last display",
        format!(
            "{} ms / {} / err {}",
            display.last_transition_ms,
            result_name(display.last_result),
            display.last_error,
        ),
    );
    push_report_value(
        out,
        "Saves",
        format!(
            "{} tried / {} good / {} aborted",
            save.save_attempts, save.save_commits, save.save_aborts,
        ),
    );
    push_report_value(
        out,
        "Save rejects",
        format!(
            "{} I/O / {} load / {} missing",
            save.short_writes.saturating_add(save.close_failures),
            save.load_rejections,
            save.unresolved_records,
        ),
    );
    push_report_value(
        out,
        "Save hooks",
        format!(
            "{}/5 / owner {:08X}",
            [
                save.factory_hook,
                save.owner_hook,
                save.activation_hook,
                save.fclose_hook,
                save.load_owner_hook,
            ]
            .into_iter()
            .filter(|active| *active)
            .count(),
            save.result_predecessor,
        ),
    );
    push_report_value(
        out,
        "Task hooks",
        format!(
            "release {} / dispatch {}",
            on_off(task.release_enabled),
            on_off(task.dispatch_enabled),
        ),
    );
    push_report_value(
        out,
        "Task dispatch",
        format!(
            "{} good / {} tried / owner {:08X}",
            task.dispatch_calls, task.dispatch_attempts, task.release_predecessor,
        ),
    );
    push_report_value(
        out,
        "Task rejects",
        format!(
            "{} pin / {} invalid / {} base",
            task.pin_failures, task.invalid_dispatches, task.base_vtable_rejections,
        ),
    );
    push_report_value(
        out,
        "Task cleanup",
        format!(
            "{} held / {} finals / {} tombstones",
            task.release_guards, task.queued_texture_finals, task.tombstones,
        ),
    );
    push_report_value(out, "Task trace dumps", task.trace_dumps);
    push_report_value(
        out,
        "LowProcess slots",
        format!("{low_slots}/4 active / {low_owners} owners"),
    );
    push_report_value(
        out,
        "LowProcess work",
        format!("{} seen / {low_repairs} repairs", low.observations,),
    );
    push_report_value(
        out,
        "LowProcess chain",
        format!(
            "{} calls / {} fallback / save {} / main {}",
            low.predecessor_calls,
            low.predecessor_fallbacks,
            on_off(low.save_owner_hook),
            on_off(low.main_boundary_restored),
        ),
    );

    push_report_section(out, "LOD streaming");
    push_report_value(
        out,
        "Ready owner",
        format!(
            "{:08X} / {} mismatch",
            lod.ready_predecessor, lod.ready_predecessor_mismatches,
        ),
    );
    for (label, index) in [("Terrain", 0), ("Objects", 1), ("Trees", 2)] {
        push_report_value(
            out,
            label,
            format!(
                "{} demand / {} early / {} held / {} release",
                lod.demand_calls[index],
                lod.extended_demands[index],
                lod.retained_demands[index],
                lod.release_passthroughs[index],
            ),
        );
    }
    push_report_value(
        out,
        "Tracked",
        format!(
            "{} cells ({} peak) / {} refs ({} peak)",
            lod.state.current_cells,
            lod.state.peak_cells,
            lod.state.current_references,
            lod.state.peak_references,
        ),
    );
    push_report_value(
        out,
        "Membership",
        format!(
            "{} in / {} out / {} mismatch",
            lod.state.membership_inserts,
            lod.state.membership_removals,
            lod.state.membership_mismatches,
        ),
    );
    push_report_value(
        out,
        "Ready events",
        format!(
            "{} good / {} duplicate / {} stale",
            lod.state.ready_publications,
            lod.state.duplicate_publications,
            lod.state.stale_publications,
        ),
    );
    push_report_value(
        out,
        "Handoff gates",
        format!(
            "{} open / {} held / {} differ",
            lod.state.gates_allowed, lod.state.gates_blocked, lod.state.gate_disagreements,
        ),
    );
    push_report_value(
        out,
        "Stale retires stop",
        lod.state.stale_retirements_prevented,
    );
    push_report_value(
        out,
        "Transitions",
        format!(
            "{} uncertain / {} reload / {} teardown / {} world",
            lod.state.uncertain_cells,
            lod.state.cell_reloads,
            lod.state.cell_teardowns,
            lod.state.worldspace_resets,
        ),
    );
    push_report_value(
        out,
        "LOD timing",
        format!(
            "{} ms pending / {} us lock / trace {}",
            lod.state.oldest_pending_ms,
            lod.state.max_lock_us,
            on_off(lod.state.trace_enabled),
        ),
    );

    push_report_section(out, "SpeedTree lifetime");
    push_report_value(
        out,
        "Clone activity",
        format!(
            "{} made / {} destroyed",
            lod.speedtree.clone_constructs, lod.speedtree.clone_destroys,
        ),
    );
    push_report_value(
        out,
        "Live clones",
        format!(
            "{} current / {} peak / {} owner peak",
            lod.speedtree.current_clones, lod.speedtree.peak_clones, lod.speedtree.max_owner_clones,
        ),
    );
    push_report_value(
        out,
        "Rejects",
        format!(
            "{} missing / {} duplicate / {} bounds",
            lod.speedtree.missing_member_rejects,
            lod.speedtree.duplicate_member_rejects,
            lod.speedtree.invalid_bounds_rejects,
        ),
    );
    push_report_value(
        out,
        "Pointer rejects",
        format!(
            "{} stale / {} refcount",
            lod.speedtree.stale_pointer_rejects, lod.speedtree.invalid_refcount_rejects,
        ),
    );
    push_report_value(
        out,
        "Constructor faults",
        lod.speedtree.constructor_postcondition_failures,
    );
    push_report_value(
        out,
        "Tree timing",
        format!(
            "{} us lock / trace {}",
            lod.speedtree.max_lock_wait_us,
            on_off(lod.speedtree.trace_enabled),
        ),
    );

    let display_alerts = u64::from(display.bootstrap_create_failures)
        .saturating_add(u64::from(display.catch_up_failures))
        .saturating_add(u64::from(display.contract_mismatches))
        .saturating_add(u64::from(display.predecessor_failures));
    let save_alerts = u64::from(save.save_aborts)
        .saturating_add(u64::from(save.short_writes))
        .saturating_add(u64::from(save.close_failures))
        .saturating_add(u64::from(save.load_rejections))
        .saturating_add(u64::from(save.unresolved_records));
    let task_alerts = task
        .pin_failures
        .saturating_add(task.invalid_dispatches)
        .saturating_add(task.base_vtable_rejections);
    let low_alerts = u64::from(low.unsupported)
        .saturating_add(u64::from(low.invalid_cleanup_forms))
        .saturating_add(u64::from(low.truncated_cleanup_links))
        .saturating_add(u64::from(low.invalid_save_forms))
        .saturating_add(u64::from(low.invalid_save_nodes))
        .saturating_add(u64::from(low.invalid_save_links))
        .saturating_add(u64::from(low.save_cycles))
        .saturating_add(u64::from(low.save_traversal_limits))
        .saturating_add(u64::from(low.main_boundary_restore_failures))
        .saturating_add(u64::from(low.patch_failures));
    let lod_alerts = lod
        .ready_predecessor_mismatches
        .saturating_add(lod.state.membership_mismatches)
        .saturating_add(lod.state.stale_publications)
        .saturating_add(lod.state.uncertain_cells);
    let tree_alerts = lod
        .speedtree
        .missing_member_rejects
        .saturating_add(lod.speedtree.duplicate_member_rejects)
        .saturating_add(lod.speedtree.invalid_bounds_rejects)
        .saturating_add(lod.speedtree.stale_pointer_rejects)
        .saturating_add(lod.speedtree.invalid_refcount_rejects)
        .saturating_add(lod.speedtree.constructor_postcondition_failures);

    push_report_section(out, "Warnings");
    let alert_total = display_alerts
        .saturating_add(save_alerts)
        .saturating_add(task_alerts)
        .saturating_add(low_alerts)
        .saturating_add(lod_alerts)
        .saturating_add(tree_alerts);
    if alert_total == 0 {
        out.push_str("  No runtime warnings.\n");
    } else {
        push_nonzero(out, "Display", display_alerts);
        push_nonzero(out, "Save system", save_alerts);
        push_nonzero(out, "Queued tasks", task_alerts);
        push_nonzero(out, "LowProcess", low_alerts);
        push_nonzero(out, "LOD handoff", lod_alerts);
        push_nonzero(out, "SpeedTree", tree_alerts);
        out.push_str("  Handled events are listed above.\n");
    }

    lod::append_trace_report(out);
}

fn push_report_section(out: &mut String, title: &str) {
    out.push('\n');
    out.push_str(title);
    out.push('\n');
    out.push_str("--------------------------------------------\n");
}

fn push_report_value(out: &mut String, label: &str, value: impl std::fmt::Display) {
    let _ = writeln!(out, "  {label:<18}{value}");
}

fn push_feature_pair(
    out: &mut String,
    left: &str,
    left_enabled: bool,
    right: &str,
    right_enabled: bool,
) {
    let _ = writeln!(
        out,
        "  {left:<15}{:<5}{right:<15}{}",
        on_off(left_enabled),
        on_off(right_enabled),
    );
}

fn push_nonzero(out: &mut String, label: &str, value: u64) {
    if value != 0 {
        push_report_value(out, label, value);
    }
}

fn on_off(enabled: bool) -> &'static str {
    if enabled { "ON" } else { "OFF" }
}

fn native_owner(native: bool) -> &'static str {
    if native { "native" } else { "chained" }
}

fn result_name(success: bool) -> &'static str {
    if success { "OK" } else { "failed" }
}

fn install_save_integrity(config: &EngineFixesConfig) -> anyhow::Result<()> {
    if !config.save_integrity_fix {
        log::info!("[SAVE] Save integrity fix disabled by config");
        return Ok(());
    }
    if let Err(error) = save_integrity::install() {
        log::warn!("[SAVE] Save integrity hooks unavailable: {error:#}");
    }
    Ok(())
}

fn install_lowprocess_fix(config: &EngineFixesConfig) -> anyhow::Result<()> {
    if !config.lowprocess_generic_locations_fix {
        lowprocess::disable();
        log::info!("[LOWPROCESS] Generic-location fix disabled by config");
        return Ok(());
    }
    if let Err(err) = lowprocess::install_save_containment() {
        log::warn!(
            "[LOWPROCESS] Save payload containment unavailable: {:#}",
            err
        );
    }
    if let Err(err) = lowprocess::install_late_boundary() {
        lowprocess::disable();
        log::warn!("[LOWPROCESS] Root repair disabled: {:#}", err);
    }
    Ok(())
}

fn install_queued_task_guard(
    config: &EngineFixesConfig,
    diagnostics: &DiagnosticsConfig,
) -> anyhow::Result<()> {
    if !config.queued_task_lifetime_guard {
        log::info!("[QUEUED_TASK] Lifetime guard disabled by config");
        return Ok(());
    }
    if let Err(err) = queued_tasks::install(diagnostics.task_lifetime_trace) {
        log::warn!("[QUEUED_TASK] Lifetime guard disabled: {:#}", err);
    }
    Ok(())
}

fn install_navmesh_low_pointer(config: &EngineFixesConfig) -> anyhow::Result<()> {
    if !config.navmesh_low_pointer_guard {
        log::info!("[NAVMESH] Low pointer guard disabled by config");
        return Ok(());
    }

    unsafe {
        statics::NAVMESH_NAME_HELPER_HOOK.init(
            "navmesh_name_helper_guard",
            statics::NAVMESH_NAME_HELPER_ADDR as *mut c_void,
            navmesh::hook_navmesh_name_helper,
        )?;
    }
    statics::NAVMESH_NAME_HELPER_HOOK.enable()?;
    log::info!("[NAVMESH] Low pointer guard active");
    Ok(())
}

fn install_entrydata_invalid_form(config: &EngineFixesConfig) -> anyhow::Result<()> {
    if !config.entrydata_invalid_form_guard {
        log::info!("[ENTRYDATA] Invalid form guard disabled by config");
        return Ok(());
    }

    unsafe {
        statics::ENTRYDATA_LIST_SAVE_HOOK.init(
            "entrydata_list_save_guard",
            statics::ENTRYDATA_LIST_SAVE_ADDR as *mut c_void,
            entrydata::hook_entrydata_list_save,
        )?;
        statics::ENTRYDATA_LOAD_HOOK.init(
            "entrydata_load_guard",
            statics::ENTRYDATA_LOAD_ADDR as *mut c_void,
            entrydata::hook_entrydata_load,
        )?;
    }
    statics::ENTRYDATA_LIST_SAVE_HOOK.enable()?;
    statics::ENTRYDATA_LOAD_HOOK.enable()?;
    log::info!("[ENTRYDATA] Invalid form guard active");
    Ok(())
}

fn install_extraownership_invalid_owner(config: &EngineFixesConfig) -> anyhow::Result<()> {
    if !config.extraownership_invalid_owner_guard {
        log::info!("[EXTRAOWNERSHIP] Invalid owner guard disabled by config");
        return Ok(());
    }

    unsafe {
        statics::BASE_EXTRA_LIST_GET_BY_TYPE_HOOK.init(
            "base_extra_list_get_by_type_ownership_guard",
            statics::BASE_EXTRA_LIST_GET_BY_TYPE_ADDR as *mut c_void,
            extraownership::hook_base_extra_list_get_by_type,
        )?;
    }
    statics::BASE_EXTRA_LIST_GET_BY_TYPE_HOOK.enable()?;
    extraownership::install_load_hook()?;
    log::info!("[EXTRAOWNERSHIP] Invalid owner guard active");
    Ok(())
}

fn install_linked_ref_children_stale_list(config: &EngineFixesConfig) -> anyhow::Result<()> {
    if !config.linked_ref_children_stale_list_guard {
        log::info!("[LINKED_REFS] Stale child-list guard disabled by config");
        return Ok(());
    }

    linkedrefs::install_remove_guard()?;
    log::info!("[LINKED_REFS] Stale child-list guard active");
    Ok(())
}

fn install_linked_ref_target_base_form(config: &EngineFixesConfig) -> anyhow::Result<()> {
    if !config.linked_ref_target_base_form_guard {
        log::info!("[LINKED_REFS] Target base-form guard disabled by config");
        return Ok(());
    }

    linkedrefs::install_target_base_form_guard()?;
    log::info!("[LINKED_REFS] Target base-form guard active");
    Ok(())
}

fn install_ragdoll_null_bone(config: &EngineFixesConfig) -> anyhow::Result<()> {
    if !config.ragdoll_null_bone_guard {
        log::info!("[RAGDOLL] Null bone-array guard disabled by config");
        return Ok(());
    }

    unsafe {
        statics::RAGDOLL_BONE_TRANSFORM_UPDATE_HOOK.init(
            "ragdoll_bone_transform_update_guard",
            statics::RAGDOLL_BONE_TRANSFORM_UPDATE_ADDR as *mut c_void,
            ragdoll::hook_ragdoll_bone_transform_update,
        )?;
        statics::RAGDOLL_ALTERNATE_UPDATE_HOOK.init(
            "ragdoll_alternate_update_guard",
            statics::RAGDOLL_ALTERNATE_UPDATE_ADDR as *mut c_void,
            ragdoll::hook_ragdoll_alternate_update,
        )?;
        statics::RAGDOLL_SAVE_LOAD_WRITEBACK_HOOK.init(
            "ragdoll_save_load_writeback_guard",
            statics::RAGDOLL_SAVE_LOAD_WRITEBACK_ADDR as *mut c_void,
            ragdoll::hook_ragdoll_save_load_writeback,
        )?;
    }
    statics::RAGDOLL_BONE_TRANSFORM_UPDATE_HOOK.enable()?;
    statics::RAGDOLL_ALTERNATE_UPDATE_HOOK.enable()?;
    statics::RAGDOLL_SAVE_LOAD_WRITEBACK_HOOK.enable()?;
    log::info!("[RAGDOLL] Null bone-array guard active");
    log::info!("[RAGDOLL] Controller table guard active");
    Ok(())
}

fn install_ragdoll_detached_phantom(config: &EngineFixesConfig) -> anyhow::Result<()> {
    if !config.ragdoll_detached_phantom_guard {
        log::info!("[RAGDOLL] Detached phantom guard disabled by config");
        return Ok(());
    }

    unsafe {
        statics::RAGDOLL_PENETRATION_RAYCAST_HOOK.init(
            "ragdoll_detached_phantom_guard",
            statics::RAGDOLL_PENETRATION_RAYCAST_ADDR as *mut c_void,
            ragdoll::hook_ragdoll_penetration_raycast,
        )?;
    }
    statics::RAGDOLL_PENETRATION_RAYCAST_HOOK.enable()?;
    log::info!("[RAGDOLL] Detached phantom penetration guard active");
    Ok(())
}

fn install_havok_guards(config: &EngineFixesConfig) -> anyhow::Result<()> {
    if config.havok_add_entity_batch_null_guard {
        unsafe {
            statics::HAVOK_ADD_ENTITY_BATCH_HOOK.init(
                "havok_add_entity_batch_null_guard",
                statics::HAVOK_ADD_ENTITY_BATCH_ADDR as *mut c_void,
                havok::hook_havok_add_entity_batch,
            )?;
        }
        statics::HAVOK_ADD_ENTITY_BATCH_HOOK.enable()?;
        log::info!("[HAVOK] Add-entity batch NULL guard active");
    }

    if config.havok_pending_add_null_guard {
        unsafe {
            statics::HAVOK_PENDING_ADD_FLUSH_HOOK.init(
                "havok_pending_add_null_guard",
                statics::HAVOK_PENDING_ADD_FLUSH_ADDR as *mut c_void,
                havok::hook_havok_pending_add_flush,
            )?;
        }
        statics::HAVOK_PENDING_ADD_FLUSH_HOOK.enable()?;
        havok::install_pending_add_loop_null_guard()?;
        log::info!("[HAVOK] Pending-add NULL guard active");
    }

    if config.havok_narrowphase_invalid_pair_guard {
        unsafe {
            statics::HAVOK_NARROWPHASE_ADD_AGENTS_HOOK.init(
                "havok_narrowphase_invalid_pair_guard",
                statics::HAVOK_NARROWPHASE_ADD_AGENTS_ADDR as *mut c_void,
                havok::hook_havok_narrowphase_add_agents,
            )?;
        }
        statics::HAVOK_NARROWPHASE_ADD_AGENTS_HOOK.enable()?;
        log::info!("[HAVOK] Narrowphase invalid-pair guard active");
    }

    if config.havok_post_add_null_entity_guard {
        unsafe {
            statics::HAVOK_ENTITY_POST_ADD_HOOK.init(
                "havok_post_add_null_entity_guard",
                statics::HAVOK_ENTITY_POST_ADD_ADDR as *mut c_void,
                havok::hook_havok_entity_post_add,
            )?;
        }
        statics::HAVOK_ENTITY_POST_ADD_HOOK.enable()?;
        log::info!("[HAVOK] Post-add NULL entity guard active");
    }

    if config.havok_remove_agent_null_reread_guard {
        havok::install_remove_agent_unlock_guard()?;
    }

    Ok(())
}

fn install_memset_null_dst(config: &EngineFixesConfig) -> anyhow::Result<()> {
    if !config.memset_null_dst_guard {
        log::info!("[OOM] Zero-allocation NULL guards disabled by config");
        return Ok(());
    }

    memset::install_zero_alloc_guards()?;
    log::info!("[OOM] Zero-allocation NULL guards active at allocator vtable consumers");
    Ok(())
}
