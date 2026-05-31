//! Console commands exposed through xNVSE.
//!
//! Command handlers stay small: collect text from the core DLL and print it to
//! the in-game console.

use libnvse::api::command::CommandContext;
use libnvse::nvse_command;
use libnvse::plugin::PluginContext;

use crate::engine_fixes;

const COMMAND_BUFFER_SIZE: usize = 64 * 1024;

// Keep command metadata static and registration direct. The helper is loaded
// during xNVSE plugin startup, so unnecessary discovery or dynamic command-table
// rewrites can change startup timing and memory layout for other plugins.
#[derive(Clone, Copy)]
struct CommandSpec {
    name: &'static str,
    short: &'static str,
    help: &'static str,
    execute: libnvse::Cmd_Execute,
}

const COMMANDS: [CommandSpec; 1] = [CommandSpec {
    name: "PsychoInfo",
    short: "psyinfo",
    help: "Show Psycho Engine Fixes status",
    execute: PSYCHOINFO_EXECUTE,
}];

nvse_command!(PsychoInfo, cmd, {
    run_text_command(&cmd, engine_fixes::COMMAND_INFO)
});

/// Register all console/script commands owned by the helper.
pub fn register(ctx: &mut PluginContext) {
    for command in COMMANDS {
        register_one(ctx, command);
    }
}

fn register_one(ctx: &mut PluginContext, command: CommandSpec) {
    match ctx.register_command(
        command.name,
        command.short,
        command.help,
        false,
        &[],
        command.execute,
    ) {
        Ok(_) => log::info!("[HELPER] Command registered: {}", command.name),
        Err(err) => log::error!("[HELPER] Command {} failed: {}", command.name, err),
    }
}

fn run_text_command(cmd: &CommandContext, command: u32) -> bool {
    let Some(text) = command_text(command) else {
        cmd.print("psycho command API unavailable");
        return true;
    };

    for line in text.lines() {
        cmd.print(line);
    }

    true
}

fn command_text(command: u32) -> Option<String> {
    // The core writes UTF-8 text into our buffer. A fixed buffer avoids extra
    // cross-DLL allocation ownership rules and is large enough for diagnostics.
    let mut buffer = vec![0u8; COMMAND_BUFFER_SIZE];
    let mut output = engine_fixes::CommandOutput {
        text: buffer.as_mut_ptr(),
        text_len: buffer.len(),
        written: 0,
        result: 0.0,
        flags: 0,
    };

    if !engine_fixes::run_command(command, &mut output) {
        return None;
    }

    let len = output.written.min(buffer.len());
    let text = String::from_utf8_lossy(&buffer[..len]).into_owned();
    Some(text)
}
