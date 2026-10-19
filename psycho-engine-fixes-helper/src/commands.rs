//! Dashboard command exposed through xNVSE.

use libnvse::nvse_command;
use libnvse::plugin::PluginContext;

use crate::dashboard;

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
}
