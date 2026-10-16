//! Dashboard command exposed through xNVSE.

use libnvse::nvse_command;
use libnvse::plugin::PluginContext;

use crate::dashboard;

nvse_command!(PsychoInfo, cmd, {
    if !dashboard::request_open() {
        cmd.print(
            "Psycho dashboard unavailable: the early psycho_engine_fixes core was not loaded or activated. See psycho-engine-fixes-latest.log",
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
