//! Console commands registered through xNVSE.

use libnvse::api::command::CommandContext;
use libnvse::api::hud;
use libnvse::nvse_command;
use libnvse::plugin::PluginContext;
use psycho_engine_fixes_api::{
    PSYCHO_COMMAND_CELL_UNLOAD, PSYCHO_COMMAND_HAS_RESULT, PSYCHO_COMMAND_MEM,
    PSYCHO_COMMAND_MEM_BYTES, PSYCHO_COMMAND_MEM_HUD, PSYCHO_COMMAND_MEM_MB,
    PSYCHO_COMMAND_QUARANTINE, PSYCHO_COMMAND_SCRAP_HEAP, PsychoCommandOutput,
};

const COMMAND_BUFFER_SIZE: usize = 64 * 1024;

nvse_command!(PsychoMem, cmd, {
    run_text_command(&cmd, PSYCHO_COMMAND_MEM)
});

nvse_command!(PsychoMemMB, cmd, {
    run_text_command(&cmd, PSYCHO_COMMAND_MEM_MB)
});

nvse_command!(PsychoMemBytes, cmd, {
    run_text_command(&cmd, PSYCHO_COMMAND_MEM_BYTES)
});

nvse_command!(PsychoScrapHeap, cmd, {
    run_text_command(&cmd, PSYCHO_COMMAND_SCRAP_HEAP)
});

nvse_command!(PsychoMemHud, cmd, {
    match command_text(PSYCHO_COMMAND_MEM_HUD) {
        Some((summary, _)) => {
            let _ = hud::hud_message(&summary);
        }
        None => cmd.print("psycho command API unavailable"),
    }
    true
});

nvse_command!(PsychoQuarantine, cmd, {
    run_text_command(&cmd, PSYCHO_COMMAND_QUARANTINE)
});

nvse_command!(PsychoCellUnload, cmd, {
    run_text_command(&cmd, PSYCHO_COMMAND_CELL_UNLOAD)
});

pub fn register(ctx: &mut PluginContext) {
    let cmds: &[(&str, &str, &str, libnvse::Cmd_Execute)] = &[
        (
            "PsychoMem",
            "pmem",
            "Detailed memory report",
            PSYCHOMEM_EXECUTE,
        ),
        (
            "PsychoMemMB",
            "pmemmb",
            "Get committed memory in MB",
            PSYCHOMEMMB_EXECUTE,
        ),
        (
            "PsychoMemBytes",
            "pmemb",
            "Get committed memory in bytes",
            PSYCHOMEMBYTES_EXECUTE,
        ),
        (
            "PsychoScrapHeap",
            "pscrap",
            "scrap_heap stats",
            PSYCHOSCRAPHEAP_EXECUTE,
        ),
        (
            "PsychoMemHud",
            "pmemh",
            "Show memory HUD notification",
            PSYCHOMEMHUD_EXECUTE,
        ),
        (
            "PsychoQuarantine",
            "pquar",
            "Show quarantine status",
            PSYCHOQUARANTINE_EXECUTE,
        ),
        (
            "PsychoCellUnload",
            "pcell",
            "Force cell unload + memory reclaim",
            PSYCHOCELLUNLOAD_EXECUTE,
        ),
    ];

    for (name, short, help, execute) in cmds {
        match ctx.register_command(name, short, help, false, &[], *execute) {
            Ok(_) => log::info!("[OK] Command: {}", name),
            Err(e) => log::error!("[FAIL] Command {}: {}", name, e),
        }
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

    if output.flags & PSYCHO_COMMAND_HAS_RESULT != 0 {
        cmd.set_result(output.result);
    }

    true
}

fn command_text(command: u32) -> Option<(String, PsychoCommandOutput)> {
    let api = crate::engine_fixes_api()?;
    let command_fn = api.command?;

    let mut buffer = vec![0u8; COMMAND_BUFFER_SIZE];
    let mut output = PsychoCommandOutput {
        text: buffer.as_mut_ptr(),
        text_len: buffer.len(),
        written: 0,
        result: 0.0,
        flags: 0,
    };

    let ok = unsafe { command_fn(command, &mut output) };
    if ok == 0 {
        return None;
    }

    let len = output.written.min(buffer.len());
    let text = String::from_utf8_lossy(&buffer[..len]).into_owned();
    Some((text, output))
}
