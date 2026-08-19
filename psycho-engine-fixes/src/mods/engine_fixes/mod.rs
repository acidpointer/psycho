//! Standalone engine fixes.
//!
//! This module is for game contract fixes that are useful independent of
//! which heap allocator is active. Allocator mechanics and allocator-only
//! safety still live under `heap_replacer`.

use std::fmt::Write as _;

use libc::c_void;

use crate::config::{DiagnosticsConfig, EngineFixesConfig, IoConfig, LodConfig};

mod actor_container_guard;
mod cell_render_retirement;
mod controller_sequence;
mod display;
mod encounter_zone;
mod entrydata;
mod extraownership;
mod havok;
mod install_paths;
mod io;
mod linkedrefs;
mod lod;
mod lowprocess;
mod memset;
mod model_postprocess;
mod navmesh;
mod patching;
mod patrol_ref_in_use;
mod queued_tasks;
mod ragdoll;
mod save_integrity;
mod statics;
mod types;
mod window_input;

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

pub(crate) const DASHBOARD_FEATURE_DISPLAY: u64 = 1 << 0;
pub(crate) const DASHBOARD_FEATURE_SAVE_INTEGRITY: u64 = 1 << 1;
pub(crate) const DASHBOARD_FEATURE_TASK_GUARD: u64 = 1 << 2;
pub(crate) const DASHBOARD_FEATURE_PARALLEL_IO: u64 = 1 << 3;
pub(crate) const DASHBOARD_FEATURE_LOD_PREFETCH: u64 = 1 << 4;
pub(crate) const DASHBOARD_FEATURE_LOD_HANDOFF: u64 = 1 << 5;
pub(crate) const DASHBOARD_FEATURE_TREE_LIFETIME: u64 = 1 << 6;
pub(crate) const DASHBOARD_FEATURE_VERTEX_BUFFERS: u64 = 1 << 7;
pub(crate) const DASHBOARD_FEATURE_ACTOR_CONTAINER_GUARD: u64 = 1 << 8;
/// Dashboard bit proving that model postprocess serialization installed.
pub(crate) const DASHBOARD_FEATURE_MODEL_POSTPROCESS: u64 = 1 << 9;
/// Dashboard bit proving that shared encounter-zone containment installed.
pub(crate) const DASHBOARD_FEATURE_ENCOUNTER_ZONE_GUARD: u64 = 1 << 10;
/// Dashboard bit proving a retirement cleanup provider remains active.
pub(crate) const DASHBOARD_FEATURE_CELL_RENDER_RETIREMENT: u64 = 1 << 11;
/// Dashboard bit proving that patrol-owner FormID containment installed.
pub(crate) const DASHBOARD_FEATURE_PATROL_OWNER_FORM_ID_GUARD: u64 = 1 << 12;

#[derive(Clone, Copy, Default)]
pub(crate) struct DashboardCounters {
    pub active_features: u64,
    pub save_attempts: u64,
    pub save_commits: u64,
    pub save_aborts: u64,
    pub save_rejections: u64,
    /// Invalid encounter-zone forms rejected at the changed-form load call.
    pub encounter_zone_load_rejections: u64,
    /// Invalid encounter-zone results rejected by the shared runtime resolver.
    pub encounter_zone_access_rejections: u64,
    /// Exact invalid encounter-zone sources removed or cleared at runtime.
    pub encounter_zone_repairs: u64,
    /// False-predicate retirements sent through the canonical native remover.
    pub cell_render_forced_cleanups: u64,
    /// Post-install replacements of the active retirement dispatch block.
    pub cell_render_patch_ownership_losses: u64,
    pub task_dispatches: u64,
    pub task_rejections: u64,
    pub task_release_guards: u64,
    pub task_tombstones: u64,
    pub io_workers: u64,
    pub io_transactions: u64,
    pub io_contentions: u64,
    pub io_fallbacks: u64,
    pub lod_demands: u64,
    pub lod_early_demands: u64,
    pub lod_retained_demands: u64,
    pub lod_current_cells: u64,
    pub lod_current_references: u64,
    pub lod_stale_retirements_prevented: u64,
    pub speedtree_materializations: u64,
    pub speedtree_completions: u64,
    pub speedtree_materialization_contentions: u64,
    pub speedtree_compute_transactions: u64,
    pub speedtree_compute_contentions: u64,
    pub speedtree_waiters: u64,
    pub speedtree_max_materialization_wait_us: u64,
    pub speedtree_max_compute_wait_us: u64,
}

/// Cumulative, read-only counters for the late-bound helper dashboard.
///
/// Unlike the hitch profiler's interval counters, this snapshot never drains
/// producer state. Every source below is atomic and safe to query from the
/// dashboard sampling worker.
pub(crate) fn dashboard_counters() -> DashboardCounters {
    let display = display::diagnostic_snapshot();
    let save = save_integrity::diagnostic_snapshot();
    let task = queued_tasks::diagnostic_snapshot();
    let io = io::diagnostic_snapshot();
    let lod = lod::dashboard_snapshot();
    let encounter_zone = encounter_zone::dashboard_snapshot();
    let cell_render = cell_render_retirement::dashboard_snapshot();

    let mut active_features = 0;
    if display.create_window_installed || display.installed {
        active_features |= DASHBOARD_FEATURE_DISPLAY;
    }
    if save.factory_hook
        || save.owner_hook
        || save.activation_hook
        || save.fclose_hook
        || save.load_owner_hook
        || save.player_load_hook
        || save.actor_container_load_first_hook
        || save.actor_container_load_second_hook
    {
        active_features |= DASHBOARD_FEATURE_SAVE_INTEGRITY;
    }
    if task.release_enabled || task.dispatch_enabled {
        active_features |= DASHBOARD_FEATURE_TASK_GUARD;
    }
    if io.scheduler.parallel_installed {
        active_features |= DASHBOARD_FEATURE_PARALLEL_IO;
    }
    if lod.streaming_installed {
        active_features |= DASHBOARD_FEATURE_LOD_PREFETCH;
    }
    if lod.handoff_installed {
        active_features |= DASHBOARD_FEATURE_LOD_HANDOFF;
    }
    if io.speedtree.installed {
        active_features |= DASHBOARD_FEATURE_TREE_LIFETIME;
    }
    if io.vertex_buffers.installed {
        active_features |= DASHBOARD_FEATURE_VERTEX_BUFFERS;
    }
    if actor_container_guard::is_installed() {
        active_features |= DASHBOARD_FEATURE_ACTOR_CONTAINER_GUARD;
    }
    if model_postprocess::is_ready() {
        active_features |= DASHBOARD_FEATURE_MODEL_POSTPROCESS;
    }
    if encounter_zone.installed {
        active_features |= DASHBOARD_FEATURE_ENCOUNTER_ZONE_GUARD;
    }
    if cell_render.installed {
        active_features |= DASHBOARD_FEATURE_CELL_RENDER_RETIREMENT;
    }
    if patrol_ref_in_use::is_installed() {
        active_features |= DASHBOARD_FEATURE_PATROL_OWNER_FORM_ID_GUARD;
    }

    DashboardCounters {
        active_features,
        save_attempts: u64::from(save.save_attempts),
        save_commits: u64::from(save.save_commits),
        save_aborts: u64::from(save.save_aborts),
        save_rejections: u64::from(save.short_writes)
            .saturating_add(u64::from(save.close_failures))
            .saturating_add(u64::from(save.structure_rejections))
            .saturating_add(u64::from(save.state_mutations))
            .saturating_add(u64::from(save.load_rejections))
            .saturating_add(u64::from(save.unresolved_records)),
        encounter_zone_load_rejections: encounter_zone.load_rejections,
        encounter_zone_access_rejections: encounter_zone.access_rejections,
        encounter_zone_repairs: encounter_zone.repairs,
        cell_render_forced_cleanups: cell_render.forced_cleanups,
        cell_render_patch_ownership_losses: cell_render.patch_ownership_losses,
        task_dispatches: task.dispatch_calls,
        task_rejections: task
            .pin_failures
            .saturating_add(task.invalid_dispatches)
            .saturating_add(task.base_vtable_rejections),
        task_release_guards: task.release_guards,
        task_tombstones: task.tombstones,
        io_workers: u64::from(io.scheduler.observed_workers),
        // These fields remain in the helper ABI. Release hooks deliberately
        // stopped counting successful IO transactions and lock acquisitions.
        io_transactions: 0,
        io_contentions: 0,
        io_fallbacks: io
            .scheduler
            .parallel_fallbacks
            .saturating_add(io.scheduler.cache_fallbacks)
            .saturating_add(io.scheduler.capacity_failures),
        // Retained in the helper ABI without updating atomics in every LOD
        // demand predicate.
        lod_demands: 0,
        lod_early_demands: 0,
        lod_retained_demands: 0,
        lod_current_cells: lod.state.current_cells as u64,
        lod_current_references: lod.state.current_references as u64,
        lod_stale_retirements_prevented: lod.state.stale_retirements_prevented,
        // Retained in the helper ABI without imposing counters or timers on
        // SpeedTree materialization and Compute.
        speedtree_materializations: 0,
        speedtree_completions: 0,
        speedtree_materialization_contentions: 0,
        speedtree_compute_transactions: 0,
        speedtree_compute_contentions: 0,
        speedtree_waiters: 0,
        speedtree_max_materialization_wait_us: 0,
        speedtree_max_compute_wait_us: 0,
    }
}

pub(crate) fn display_diagnostic_snapshot() -> display::DiagnosticSnapshot {
    display::diagnostic_snapshot()
}

pub(crate) struct IoHangSnapshot {
    pub(crate) tree_started: u64,
    pub(crate) tree_completed: u64,
    pub(crate) transaction_waiters: u32,
    pub(crate) active_scope: &'static str,
    pub(crate) active_thread: u32,
}

pub(crate) fn io_hang_snapshot() -> IoHangSnapshot {
    IoHangSnapshot {
        tree_started: 0,
        tree_completed: 0,
        transaction_waiters: 0,
        active_scope: "not-instrumented",
        active_thread: 0,
    }
}

/// Install allocator-independent engine fixes and their dependent IO/LOD safety.
pub fn install(
    config: &EngineFixesConfig,
    io_config: &IoConfig,
    lod_config: &LodConfig,
    diagnostics: &DiagnosticsConfig,
) -> anyhow::Result<()> {
    install_actor_container_guard(config);
    install_controller_sequence_guard(config);
    install_save_integrity(config)?;
    install_navmesh_low_pointer(config)?;
    install_entrydata_invalid_form(config)?;
    install_extraownership_invalid_owner(config)?;
    install_encounter_zone_invalid_form(config)?;
    install_cell_render_retirement(config)?;
    install_linked_ref_children_stale_list(config)?;
    install_linked_ref_target_base_form(config)?;
    install_ragdoll_null_bone(config)?;
    install_ragdoll_detached_phantom(config)?;
    install_havok_guards(config)?;
    install_memset_null_dst(config)?;
    install_lowprocess_fix(config)?;
    let model_postprocess_ready = install_model_postprocess_fix(config);
    install_queued_task_guard(config, diagnostics)?;
    let io_safety = io::install(
        io_config,
        lod_config.enabled && lod_config.prefetch_enabled,
        model_postprocess_ready,
    );
    lod::install(lod_config, diagnostics, io_safety);
    install_patrol_ref_in_use_guard(config);

    Ok(())
}

fn install_patrol_ref_in_use_guard(config: &EngineFixesConfig) {
    if !config.patrol_owner_form_id_guard {
        log::info!("[AI_PATROL] Patrol owner FormID guard disabled by config");
        return;
    }
    if let Err(error) = patrol_ref_in_use::install() {
        log::warn!("[AI_PATROL] Patrol owner FormID guard unavailable: {error:#}");
    }
}

fn install_actor_container_guard(config: &EngineFixesConfig) {
    if !config.actor_container_retirement_guard {
        log::info!("[ACTOR_CONTAINER] Dynamic actor retirement guard disabled by config");
        return;
    }
    if let Err(error) = actor_container_guard::install() {
        log::warn!("[ACTOR_CONTAINER] Dynamic actor retirement guard unavailable: {error:#}");
    }
}

fn install_controller_sequence_guard(config: &EngineFixesConfig) {
    if !config.animation_sequence_idtag_retirement_guard {
        log::info!("[ANIM_SEQUENCE] IDTag retirement guard disabled by config");
        return;
    }
    if let Err(error) = controller_sequence::install() {
        log::warn!("[ANIM_SEQUENCE] IDTag retirement guard unavailable: {error:#}");
    }
}

fn install_model_postprocess_fix(config: &EngineFixesConfig) -> bool {
    if !config.model_postprocess_serialization_fix {
        log::info!("[MODEL_POSTPROCESS] EditorMarker transaction guard disabled by config");
        return false;
    }
    match model_postprocess::install() {
        Ok(()) => true,
        Err(error) => {
            log::warn!("[MODEL_POSTPROCESS] EditorMarker transaction guard unavailable: {error:#}");
            false
        }
    }
}

/// Install configured window and input policies before other engine hooks.
///
/// Fullscreen repair, borderless-windowed styling, cursor confinement, and
/// system-key passthrough are independently selectable. Ownership or
/// fingerprint conflicts are logged and contained here so they cannot abort
/// unrelated engine-fix startup.
pub fn install_display(config: &EngineFixesConfig) -> anyhow::Result<()> {
    window_input::configure_cursor_lock(config.window_cursor_lock);
    if let Err(error) =
        window_input::install_system_key_passthrough(config.input_system_key_passthrough)
    {
        log::warn!("[WINDOW_INPUT] System-key passthrough unavailable: {error:#}");
    }

    if !config.display_alt_tab && !config.display_borderless_windowed && !config.window_cursor_lock
    {
        log::info!("[DISPLAY] Window management disabled by config");
        return Ok(());
    }

    if let Err(err) = display::install_display_hooks(
        config.display_alt_tab,
        config.display_borderless_windowed,
        config.window_cursor_lock,
    ) {
        log::warn!("[DISPLAY] Window management disabled: {}", err);
    }
    Ok(())
}

/// Repair Bethesda installation-path registry values during early startup.
pub fn repair_install_paths(config: &EngineFixesConfig) {
    install_paths::repair(config);
}

/// Forward a host lifecycle event to fixes that audit late hook ownership.
pub fn observe_event(kind: u32) {
    window_input::observe_event(kind);
    lowprocess::observe_event(kind);
    model_postprocess::observe_event(kind);
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
    let window_input = window_input::diagnostic_snapshot();
    let low = lowprocess::diagnostic_snapshot();
    let model = model_postprocess::snapshot();
    let task = queued_tasks::diagnostic_snapshot();
    let save = save_integrity::diagnostic_snapshot();
    let io = io::diagnostic_snapshot();
    let lod = lod::diagnostic_snapshot();
    let encounter_zone = encounter_zone::dashboard_snapshot();
    let cell_render = cell_render_retirement::dashboard_snapshot();

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
            || save.load_owner_hook
            || save.player_load_hook,
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
        io.speedtree.installed,
        "LOD reset",
        lod.worldspace_reset_installed,
    );
    push_feature_pair(
        out,
        "LOD priority",
        lod.scheduler.priority_installed,
        "Parallel IO",
        io.scheduler.parallel_installed,
    );
    push_feature_pair(
        out,
        "Model postprocess",
        model.installed,
        "Actor lifetime",
        actor_container_guard::is_installed(),
    );
    push_feature_pair(
        out,
        "Cell render retirement",
        cell_render.installed,
        "Encounter zones",
        encounter_zone.installed,
    );

    let covered_move_sites = display
        .site_states
        .iter()
        .filter(|state| display::site_state_name(**state) == "covered")
        .count();
    let display_events = u64::from(display.bootstrap_create_observations)
        .saturating_add(u64::from(display.windowed_parent_observations))
        .saturating_add(u64::from(display.device_reset_observations))
        .saturating_add(u64::from(display.child_resize_passthroughs));
    let display_repairs = u64::from(display.bootstrap_create_corrections)
        .saturating_add(u64::from(display.windowed_parent_corrections))
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
        .saturating_add(u64::from(low.reference_scan_wraps))
        .saturating_add(u64::from(low.reference_scan_rewraps))
        .saturating_add(u64::from(low.sanitized_entries))
        .saturating_add(u64::from(low.main_boundary_restores));
    let low_slots = low
        .slot_states
        .iter()
        .filter(|state| matches!(lowprocess::slot_state_name(**state), "wrapped" | "chained"))
        .count();
    let low_owners = low.predecessors.iter().filter(|owner| **owner != 0).count();
    let low_scan_slots = low
        .reference_scan_slot_states
        .iter()
        .filter(|state| matches!(lowprocess::slot_state_name(**state), "wrapped" | "chained"))
        .count();
    let low_scan_owners = low
        .reference_scan_predecessors
        .iter()
        .filter(|owner| **owner != 0)
        .count();

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
        "Windowed policy",
        if display.borderless_windowed_enabled {
            "borderless"
        } else {
            "framed"
        },
    );
    push_report_value(
        out,
        "Display work",
        format!("{display_events} events / {display_repairs} repairs"),
    );
    push_report_value(
        out,
        "Display bootstrap",
        format!(
            "{} seen / {} windowed / {} failed",
            display.bootstrap_create_observations,
            display.bootstrap_windowed_corrections,
            display.bootstrap_create_failures,
        ),
    );
    push_report_value(
        out,
        "Window placement",
        format!(
            "{} seen / {} preserved",
            display.windowed_parent_observations, display.windowed_parent_corrections,
        ),
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
        "Cursor lock",
        format!(
            "{} / attached {} / active {} / {} / timer {}",
            on_off(window_input.cursor_lock_configured),
            on_off(window_input.cursor_window_attached),
            on_off(window_input.cursor_clip_active),
            window_input.cursor_target,
            on_off(window_input.cursor_timer_installed),
        ),
    );
    push_report_value(
        out,
        "Cursor work",
        format!(
            "{} attach ({} recovery) / {} apply / {} release / {} failed",
            window_input.cursor_attachments,
            window_input.cursor_recovery_attachments,
            window_input.cursor_applies,
            window_input.cursor_releases,
            window_input.cursor_failures,
        ),
    );
    push_report_value(
        out,
        "Cursor audit",
        format!(
            "{} ticks / {} repairs / {} normalized / {} safe / {} fail-safe / {} rejected",
            window_input.cursor_timer_audits,
            window_input.cursor_repairs,
            window_input.cursor_normalizations,
            window_input.cursor_safe_adoptions,
            window_input.cursor_fail_safe_releases,
            window_input.cursor_renderer_rejections,
        ),
    );
    push_report_value(
        out,
        "System keys",
        format!(
            "{} / installed {}",
            on_off(window_input.system_key_passthrough_configured),
            on_off(window_input.system_key_passthrough_installed),
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
            "{} I/O / {} format / {} state / {} load / {} missing",
            save.short_writes.saturating_add(save.close_failures),
            save.structure_rejections,
            save.state_mutations,
            save.load_rejections,
            save.unresolved_records,
        ),
    );
    push_report_value(
        out,
        "Player preflight",
        format!("{} rejected", save.player_load_rejections),
    );
    push_report_value(
        out,
        "Actor preflight",
        format!("{} rejected", save.actor_container_load_rejections),
    );
    push_report_value(
        out,
        "Save hooks",
        format!(
            "{}/8 / owner {:08X}",
            [
                save.factory_hook,
                save.owner_hook,
                save.activation_hook,
                save.fclose_hook,
                save.load_owner_hook,
                save.player_load_hook,
                save.actor_container_load_first_hook,
                save.actor_container_load_second_hook,
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
        format!(
            "cleanup {low_slots}/4 ({low_owners} owners) / scan {low_scan_slots}/4 ({low_scan_owners} owners)"
        ),
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
            "cleanup {} / scan {} calls / {}+{} fallback / save {} / main {}",
            low.predecessor_calls,
            low.reference_scan_predecessor_calls,
            low.predecessor_fallbacks,
            low.reference_scan_predecessor_fallbacks,
            on_off(low.save_owner_hook),
            on_off(low.main_boundary_restored),
        ),
    );
    push_report_value(
        out,
        "Model postprocess",
        format!("{} / guard {}", model.owner, on_off(model.installed)),
    );
    push_report_value(out, "Model PP owner", format!("{:08X}", model.predecessor));
    push_report_value(
        out,
        "Cell render cleanup",
        format!(
            "{} forced / {} ownership losses",
            cell_render.forced_cleanups, cell_render.patch_ownership_losses,
        ),
    );

    let requested_workers = if io.scheduler.parallel_requested {
        2
    } else {
        1
    };
    let (barrier_layout_failures, barrier_timeouts) =
        crate::mods::heap_replacer::gheap::engine::globals::io_barrier_diagnostic_counts();

    push_report_section(out, "IOManager");
    push_report_value(
        out,
        "IO workers",
        format!(
            "{} constructed / {} requested / primary {} / supplemental {}",
            io.scheduler.observed_workers,
            requested_workers,
            on_off(io.scheduler.primary_thread_ready),
            on_off(io.scheduler.supplemental_thread_ready),
        ),
    );
    push_report_value(
        out,
        "Exterior guards",
        format!(
            "{} / per-form owner + AutoWater",
            on_off(io.scheduler.cell_loader_serialization_installed),
        ),
    );
    push_report_value(
        out,
        "File cache",
        format!(
            "{} / {} fallback",
            on_off(io.scheduler.cache_fallback_installed),
            io.scheduler.cache_fallbacks,
        ),
    );
    push_report_value(out, "TLS capacity", "native slots + 1");
    push_report_value(out, "IO fallbacks", io.scheduler.parallel_fallbacks);
    push_report_value(out, "Capacity failures", io.scheduler.capacity_failures);
    push_report_value(out, "Barrier layouts", barrier_layout_failures);
    push_report_value(out, "Barrier timeouts", barrier_timeouts);

    push_report_section(out, "LOD scheduler");
    push_report_value(
        out,
        "Priority",
        format!(
            "{} / req {} / visible 0 / speculative native",
            on_off(lod.scheduler.priority_installed),
            on_off(lod.scheduler.priority_requested),
        ),
    );
    push_report_value(
        out,
        "Priority failures",
        lod.scheduler.priority_install_failures,
    );

    push_report_section(out, "IO vertex buffers");
    push_report_value(
        out,
        "Lifetime guard",
        format!(
            "{} / retryable outer allocation",
            on_off(io.vertex_buffers.installed),
        ),
    );
    push_report_value(
        out,
        "Safe retries",
        format!(
            "{} create / {} publish",
            io.vertex_buffers.null_allocation_failures, io.vertex_buffers.invalid_publications,
        ),
    );

    push_report_section(out, "LOD streaming");
    push_report_value(
        out,
        "Remove owner",
        format!(
            "{:08X} / {} exact / {} mismatch",
            lod.alternate_remove_predecessor,
            lod.alternate_removals,
            lod.alternate_remove_mismatches,
        ),
    );
    push_report_value(
        out,
        "Ready owner",
        format!(
            "{:08X} / {} mismatch",
            lod.ready_predecessor, lod.ready_predecessor_mismatches,
        ),
    );
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
            "{} uncertain events / {} current / {} reload / {} teardown / {} world",
            lod.state.uncertain_cells,
            lod.state.current_uncertain_cells,
            lod.state.cell_reloads,
            lod.state.cell_teardowns,
            lod.state.worldspace_resets,
        ),
    );
    push_report_value(
        out,
        "LOD timing",
        format!(
            "{} ms pending / {} ms uncertain / {} us lock / trace {}",
            lod.state.oldest_pending_ms,
            lod.state.oldest_uncertain_ms,
            lod.state.max_lock_us,
            on_off(lod.state.trace_enabled),
        ),
    );

    push_report_section(out, "SpeedTree IO safety");
    push_report_value(
        out,
        "Lifetime guard",
        format!(
            "{} / global transaction fallback",
            on_off(io.speedtree.installed),
        ),
    );
    push_report_value(
        out,
        "Rejects",
        format!(
            "{} missing / {} duplicate / {} bounds",
            io.speedtree.missing_member_rejects,
            io.speedtree.duplicate_member_rejects,
            io.speedtree.invalid_bounds_rejects,
        ),
    );
    push_report_value(
        out,
        "Pointer rejects",
        format!(
            "{} stale / {} refcount",
            io.speedtree.stale_pointer_rejects, io.speedtree.invalid_refcount_rejects,
        ),
    );
    push_report_value(
        out,
        "Constructor faults",
        io.speedtree.constructor_postcondition_failures,
    );
    let display_alerts = u64::from(display.bootstrap_create_failures)
        .saturating_add(u64::from(display.catch_up_failures))
        .saturating_add(u64::from(display.contract_mismatches))
        .saturating_add(u64::from(display.predecessor_failures));
    let save_alerts = u64::from(save.save_aborts)
        .saturating_add(u64::from(save.short_writes))
        .saturating_add(u64::from(save.close_failures))
        .saturating_add(u64::from(save.structure_rejections))
        .saturating_add(u64::from(save.state_mutations))
        .saturating_add(u64::from(save.load_rejections))
        .saturating_add(u64::from(save.unresolved_records));
    let task_alerts = task
        .pin_failures
        .saturating_add(task.invalid_dispatches)
        .saturating_add(task.base_vtable_rejections);
    let low_alerts = u64::from(low.unsupported)
        .saturating_add(u64::from(low.reference_scan_unsupported))
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
        .saturating_add(lod.alternate_remove_mismatches)
        .saturating_add(lod.state.membership_mismatches)
        .saturating_add(lod.state.stale_publications)
        .saturating_add(lod.state.current_uncertain_cells as u64);
    let tree_alerts = io
        .speedtree
        .missing_member_rejects
        .saturating_add(io.speedtree.duplicate_member_rejects)
        .saturating_add(io.speedtree.invalid_bounds_rejects)
        .saturating_add(io.speedtree.stale_pointer_rejects)
        .saturating_add(io.speedtree.invalid_refcount_rejects)
        .saturating_add(io.speedtree.constructor_postcondition_failures);
    let scheduler_alerts = io
        .scheduler
        .parallel_fallbacks
        .saturating_add(lod.scheduler.priority_install_failures)
        .saturating_add(io.scheduler.capacity_failures)
        .saturating_add(io.scheduler.cache_fallbacks)
        .saturating_add(barrier_layout_failures)
        .saturating_add(barrier_timeouts);
    let vertex_buffer_alerts = io
        .vertex_buffers
        .null_allocation_failures
        .saturating_add(io.vertex_buffers.invalid_publications);

    push_report_section(out, "Warnings");
    let alert_total = display_alerts
        .saturating_add(save_alerts)
        .saturating_add(task_alerts)
        .saturating_add(low_alerts)
        .saturating_add(lod_alerts)
        .saturating_add(tree_alerts)
        .saturating_add(scheduler_alerts)
        .saturating_add(vertex_buffer_alerts);
    if alert_total == 0 {
        out.push_str("  No runtime warnings.\n");
    } else {
        push_nonzero(out, "Display", display_alerts);
        push_nonzero(out, "Save system", save_alerts);
        push_nonzero(out, "Queued tasks", task_alerts);
        push_nonzero(out, "LowProcess", low_alerts);
        push_nonzero(out, "LOD handoff", lod_alerts);
        push_nonzero(out, "SpeedTree", tree_alerts);
        push_nonzero(out, "LOD scheduler", scheduler_alerts);
        push_nonzero(out, "Vertex buffers", vertex_buffer_alerts);
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

fn install_encounter_zone_invalid_form(config: &EngineFixesConfig) -> anyhow::Result<()> {
    if !config.encounter_zone_invalid_form_guard {
        log::info!("[ENCOUNTER_ZONE] Invalid form guard disabled by config");
        return Ok(());
    }

    encounter_zone::install()?;
    log::info!("[ENCOUNTER_ZONE] Invalid form guard active");
    Ok(())
}

fn install_cell_render_retirement(config: &EngineFixesConfig) -> anyhow::Result<()> {
    if !config.cell_render_reference_retirement_fix {
        log::info!("[CELL_RENDER_RETIREMENT] Cleanup disabled by config");
        return Ok(());
    }
    if let Err(error) = cell_render_retirement::install() {
        log::warn!("[CELL_RENDER_RETIREMENT] Cleanup unavailable: {error:#}");
    }
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
