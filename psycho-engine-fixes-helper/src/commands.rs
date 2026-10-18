//! Dashboard command exposed through xNVSE.

use std::sync::atomic::{AtomicBool, Ordering};

use libnvse::nvse_command;
use libnvse::plugin::PluginContext;

use crate::dashboard;

/// Whether the helper should draw the occluder debug overlay.
static OCCLUSION_DEBUG: AtomicBool = AtomicBool::new(false);

pub(crate) fn occlusion_debug_enabled() -> bool {
    OCCLUSION_DEBUG.load(Ordering::Acquire)
}

/// Set the overlay from the dashboard checkbox. The core command toggles, so
/// it is only called when the requested state differs from the current one.
pub(crate) fn set_occlusion_debug(enabled: bool) {
    if OCCLUSION_DEBUG.load(Ordering::Acquire) == enabled {
        return;
    }
    match crate::engine_fixes::run_command(crate::engine_fixes::COMMAND_OCCLUSION_DEBUG) {
        Some(text) => OCCLUSION_DEBUG.store(text.contains("debug on"), Ordering::Release),
        None => log::warn!(
            "[HELPER] occlusion debug toggle unavailable: the early psycho_engine_fixes core was not loaded or activated"
        ),
    }
}

nvse_command!(PsychoInfo, _cmd, {
    if !dashboard::request_open() {
        // Never print through the console helper here: it runs a script line and
        // re-enters xNVSE's non-re-entrant parser. Log instead.
        log::warn!(
            "[HELPER] PsychoInfo unavailable: the early psycho_engine_fixes core was not loaded or activated"
        );
    }
    true
});

// This handler intentionally never calls `cmd.print`. The console `print`
// helper runs `print "..."` through `RunScriptLine`, which re-enters xNVSE's
// non-re-entrant script parser from inside the command handler and produces a
// bogus "Mismatched quotes. String literal was not closed" error. The overlay
// and the log carry the state instead.
nvse_command!(PsychoOcclusionDebug, _cmd, {
    match crate::engine_fixes::run_command(crate::engine_fixes::COMMAND_OCCLUSION_DEBUG) {
        Some(text) => {
            let enabled = text.contains("debug on");
            OCCLUSION_DEBUG.store(enabled, Ordering::Release);
            if enabled {
                // The overlay is drawn by the dashboard's ImGui foreground
                // list, so make sure it is open.
                dashboard::request_open();
            }
            log::info!("[HELPER] PsychoOcclusionDebug: {text}");
        }
        None => log::warn!(
            "[HELPER] PsychoOcclusionDebug unavailable: the early psycho_engine_fixes core was not loaded or activated"
        ),
    }
    true
});

/// Register the compatibility command that now opens the in-game dashboard.
pub fn register(ctx: &mut PluginContext) {
    match ctx.register_command(
        "PsychoInfo",
        "psyinfo",
        "Open the Psycho Engine Fixes dashboard",
        false,
        &[],
        PSYCHOINFO_EXECUTE,
    ) {
        Ok(_) => log::info!("[HELPER] Command registered: PsychoInfo"),
        Err(error) => log::error!("[HELPER] Command PsychoInfo failed: {error}"),
    }
    if let Err(error) = ctx.register_command(
        "PsychoOcclusionDebug",
        "psoccl",
        "Toggle the Psycho occlusion-plane debug overlay",
        false,
        &[],
        PSYCHOOCCLUSIONDEBUG_EXECUTE,
    ) {
        log::error!("[HELPER] Command PsychoOcclusionDebug failed: {error}");
    }
}
