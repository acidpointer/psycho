//! Console commands exposed through xNVSE.
//!
//! Command handlers stay small: collect text from the core DLL, print it to the
//! in-game console, and optionally return a numeric result to scripts.

use libnvse::api::command::CommandContext;
use libnvse::api::hud;
use libnvse::nvse_command;
use libnvse::plugin::PluginContext;

use crate::engine_fixes::{self, CommandOutput};

const COMMAND_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Clone, Copy)]
struct CommandSpec {
    name: &'static str,
    short: &'static str,
    help: &'static str,
    execute: libnvse::Cmd_Execute,
}

const COMMANDS: [CommandSpec; 7] = [
    CommandSpec {
        name: "PsychoMem",
        short: "pmem",
        help: "Detailed memory report",
        execute: PSYCHOMEM_EXECUTE,
    },
    CommandSpec {
        name: "PsychoMemMB",
        short: "pmemmb",
        help: "Get committed memory in MB",
        execute: PSYCHOMEMMB_EXECUTE,
    },
    CommandSpec {
        name: "PsychoMemBytes",
        short: "pmemb",
        help: "Get committed memory in bytes",
        execute: PSYCHOMEMBYTES_EXECUTE,
    },
    CommandSpec {
        name: "PsychoScrapHeap",
        short: "pscrap",
        help: "scrap_heap stats",
        execute: PSYCHOSCRAPHEAP_EXECUTE,
    },
    CommandSpec {
        name: "PsychoMemHud",
        short: "pmemh",
        help: "Show memory HUD notification",
        execute: PSYCHOMEMHUD_EXECUTE,
    },
    CommandSpec {
        name: "PsychoQuarantine",
        short: "pquar",
        help: "Show quarantine status",
        execute: PSYCHOQUARANTINE_EXECUTE,
    },
    CommandSpec {
        name: "PsychoCellUnload",
        short: "pcell",
        help: "Force cell unload + memory reclaim",
        execute: PSYCHOCELLUNLOAD_EXECUTE,
    },
];

nvse_command!(PsychoMem, cmd, {
    run_text_command(&cmd, engine_fixes::COMMAND_MEM)
});

nvse_command!(PsychoMemMB, cmd, {
    run_text_command(&cmd, engine_fixes::COMMAND_MEM_MB)
});

nvse_command!(PsychoMemBytes, cmd, {
    run_text_command(&cmd, engine_fixes::COMMAND_MEM_BYTES)
});

nvse_command!(PsychoScrapHeap, cmd, {
    run_text_command(&cmd, engine_fixes::COMMAND_SCRAP_HEAP)
});

nvse_command!(PsychoMemHud, cmd, {
    match command_text(engine_fixes::COMMAND_MEM_HUD) {
        Some((summary, _)) => {
            let _ = hud::hud_message(&summary);
        }
        None => cmd.print("psycho command API unavailable"),
    }
    true
});

nvse_command!(PsychoQuarantine, cmd, {
    run_text_command(&cmd, engine_fixes::COMMAND_QUARANTINE)
});

nvse_command!(PsychoCellUnload, cmd, {
    run_text_command(&cmd, engine_fixes::COMMAND_CELL_UNLOAD)
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
    let Some((text, output)) = command_text(command) else {
        cmd.print("psycho command API unavailable");
        return true;
    };

    for line in text.lines() {
        cmd.print(line);
    }

    if output.flags & engine_fixes::COMMAND_HAS_RESULT != 0 {
        cmd.set_result(output.result);
    }

    true
}

fn command_text(command: u32) -> Option<(String, CommandOutput)> {
    // The core writes UTF-8 text into our buffer. A fixed buffer avoids extra
    // cross-DLL allocation ownership rules and is large enough for diagnostics.
    let mut buffer = vec![0u8; COMMAND_BUFFER_SIZE];
    let mut output = CommandOutput {
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
    Some((text, output))
}
