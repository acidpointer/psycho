//! Standalone engine fixes.
//!
//! This module is for game contract fixes that are useful independent of
//! which heap allocator is active. Allocator mechanics and allocator-only
//! safety still live under `heap_replacer`.

use libc::c_void;

use crate::config::{DiagnosticsConfig, EngineFixesConfig};

mod display;
mod entrydata;
mod extraownership;
mod havok;
mod linkedrefs;
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

pub fn install(config: &EngineFixesConfig, diagnostics: &DiagnosticsConfig) -> anyhow::Result<()> {
    install_save_integrity(config)?;
    install_navmesh_low_pointer(config)?;
    install_entrydata_invalid_form(config)?;
    install_extraownership_invalid_owner(config)?;
    install_linked_ref_children_stale_list(config)?;
    install_linked_ref_target_base_form(config)?;
    install_ragdoll_null_bone(config)?;
    install_havok_guards(config)?;
    install_memset_null_dst(config)?;
    install_lowprocess_fix(config)?;
    install_queued_task_guard(config, diagnostics)?;

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
    out.push_str("\n==== Engine fixes ====\n");
    out.push_str(&format!(
        "  Display: create=installed:{} predecessor:0x{:08X} vanilla:{} site:{} calls:{}/{}/{} setpos=installed:{} predecessor:0x{:08X} vanilla:{} sites:{}/{}/{}/{}/{}/{} windowed:{} reset:{}/{} child:{} loss:{} regain:{} lifecycle:{} catchup:{}/{}/{} mismatches:{} failures:{} monitors:{}/{}/{} restores:{} last_tick:{} result:{} error:{}\n",
        display.create_window_installed,
        display.create_window_predecessor,
        display.create_window_predecessor_vanilla,
        display::site_state_name(display.bootstrap_create_state),
        display.bootstrap_create_observations,
        display.bootstrap_create_corrections,
        display.bootstrap_create_failures,
        display.installed,
        display.predecessor,
        display.predecessor_vanilla,
        display::site_state_name(display.site_states[0]),
        display::site_state_name(display.site_states[1]),
        display::site_state_name(display.site_states[2]),
        display::site_state_name(display.site_states[3]),
        display::site_state_name(display.site_states[4]),
        display::site_state_name(display.site_states[5]),
        display.windowed_parent_passthroughs,
        display.device_reset_observations,
        display.device_reset_corrections,
        display.child_resize_passthroughs,
        display.loss_suppressions,
        display.regain_normalizations,
        display.lifecycle_normalizations,
        display.catch_up_attempts,
        display.catch_up_successes,
        display.catch_up_failures,
        display.contract_mismatches,
        display.predecessor_failures,
        display.monitor_point_selections,
        display.monitor_window_selections,
        display.monitor_fallbacks,
        display.restore_attempts,
        display.last_transition_ms,
        display.last_result,
        display.last_error,
    ));
    out.push_str(&format!(
        "  LowProcess: enabled={} observations={} slots={}/{}/{}/{} predecessors={:08X?} wraps={} rewraps={} unsupported={} sanitized={} save_nulls={} patch_failures={}\n",
        low.enabled,
        low.observations,
        lowprocess::slot_state_name(low.slot_states[0]),
        lowprocess::slot_state_name(low.slot_states[1]),
        lowprocess::slot_state_name(low.slot_states[2]),
        lowprocess::slot_state_name(low.slot_states[3]),
        low.predecessors,
        low.wraps,
        low.rewraps,
        low.unsupported,
        low.sanitized_entries,
        low.invalid_save_forms,
        low.patch_failures,
    ));
    out.push_str(&format!(
        "  Save integrity: attempts={} commits={} aborts={} short_writes={} close_failures={} malformed_loads={} unavailable_records={} hooks=factory:{} owner:{} activation:{} fclose:{} load_owner:{} result_predecessor:0x{:08X}\n",
        save.save_attempts,
        save.save_commits,
        save.save_aborts,
        save.short_writes,
        save.close_failures,
        save.load_rejections,
        save.unresolved_records,
        save.factory_hook,
        save.owner_hook,
        save.activation_hook,
        save.fclose_hook,
        save.load_owner_hook,
        save.result_predecessor,
    ));
    out.push_str(&format!(
        "  queued tasks: release={} dispatch_guard={} predecessor=0x{:08X} dispatch={}/{} pin_fail={} invalid={} base_vt={} releases_guarded={} qt_finals={} tombstones={} trace_dumps={}\n",
        task.release_enabled,
        task.dispatch_enabled,
        task.release_predecessor,
        task.dispatch_calls,
        task.dispatch_attempts,
        task.pin_failures,
        task.invalid_dispatches,
        task.base_vtable_rejections,
        task.release_guards,
        task.queued_texture_finals,
        task.tombstones,
        task.trace_dumps,
    ));
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
        log::warn!("[LOWPROCESS] Save containment disabled: {:#}", err);
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
