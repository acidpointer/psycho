//! Command ABI for late host adapters.
//!
//! The xNVSE helper owns command registration. The core owns command behavior
//! and returns text through a caller-owned buffer so no allocation crosses DLLs.

use std::{fmt::Write as _, ptr};

use crate::mods::heap_replacer::gheap::engine::cell_unload;
use crate::mods::heap_replacer::gheap::{allocator, block, pool, va_alloc};
use crate::mods::heap_replacer::{AllocatorMode, current_mode, mem_stats, scrap_heap};

const COMMAND_MEM: u32 = 1;
const COMMAND_MEM_MB: u32 = 2;
const COMMAND_MEM_BYTES: u32 = 3;
const COMMAND_SCRAP_HEAP: u32 = 4;
const COMMAND_MEM_HUD: u32 = 5;
const COMMAND_QUARANTINE: u32 = 6;
const COMMAND_CELL_UNLOAD: u32 = 7;

const COMMAND_HAS_RESULT: u32 = 1;

#[derive(Clone, Copy)]
enum Command {
    MemoryReport,
    MemoryMegabytes,
    MemoryBytes,
    ScrapHeap,
    MemoryHud,
    Quarantine,
    CellUnload,
}

impl Command {
    fn from_id(id: u32) -> Option<Self> {
        match id {
            COMMAND_MEM => Some(Self::MemoryReport),
            COMMAND_MEM_MB => Some(Self::MemoryMegabytes),
            COMMAND_MEM_BYTES => Some(Self::MemoryBytes),
            COMMAND_SCRAP_HEAP => Some(Self::ScrapHeap),
            COMMAND_MEM_HUD => Some(Self::MemoryHud),
            COMMAND_QUARANTINE => Some(Self::Quarantine),
            COMMAND_CELL_UNLOAD => Some(Self::CellUnload),
            _ => None,
        }
    }

    fn run(self) -> CommandResponse {
        match self {
            Self::MemoryReport => CommandResponse::text(mem_stats::MemStats::detailed_report()),
            Self::MemoryMegabytes => mem_mb(),
            Self::MemoryBytes => mem_bytes(),
            Self::ScrapHeap => scrap_heap_report(),
            Self::MemoryHud => CommandResponse::text(mem_stats::MemStats::hud_summary()),
            Self::Quarantine => quarantine_report(),
            Self::CellUnload => cell_unload_report(),
        }
    }
}

struct CommandResponse {
    text: String,
    result: Option<f64>,
}

impl CommandResponse {
    fn text(text: String) -> Self {
        Self { text, result: None }
    }

    fn with_result(text: String, result: f64) -> Self {
        Self {
            text,
            result: Some(result),
        }
    }

    unsafe fn write_to(self, output: &mut CommandOutput) {
        let bytes = self.text.as_bytes();
        output.written = bytes.len();
        output.flags = 0;
        output.result = 0.0;

        if !output.text.is_null() && output.text_len > 0 {
            let copy_len = bytes.len().min(output.text_len);
            unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), output.text, copy_len) };
        }

        if let Some(value) = self.result {
            output.result = value;
            output.flags |= COMMAND_HAS_RESULT;
        }
    }
}

/// Caller-owned output buffer for `PsychoEngineFixes_RunCommand`.
///
/// `written` is always the full response length, even when `text_len` is too
/// small and the text is truncated.
#[repr(C)]
pub struct CommandOutput {
    pub text: *mut u8,
    pub text_len: usize,
    pub written: usize,
    pub result: f64,
    pub flags: u32,
}

/// Run a diagnostic/control command requested by a host adapter.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn PsychoEngineFixes_RunCommand(
    command: u32,
    output: *mut CommandOutput,
) -> i32 {
    if output.is_null() {
        return 0;
    }

    if !crate::entry::is_initialized() {
        return 0;
    }

    let Some(command) = Command::from_id(command) else {
        return 0;
    };

    unsafe { command.run().write_to(&mut *output) };
    1
}

fn mem_mb() -> CommandResponse {
    let bytes = mem_stats::current_allocator_bytes();
    let mb = bytes as f64 / 1024.0 / 1024.0;
    CommandResponse::with_result(
        format!("{}: {:.1} MB", mem_stats::current_allocator_name(), mb),
        mb,
    )
}

fn mem_bytes() -> CommandResponse {
    let bytes = mem_stats::current_allocator_bytes();
    CommandResponse::with_result(
        format!("{}: {} bytes", mem_stats::current_allocator_name(), bytes),
        bytes as f64,
    )
}

fn scrap_heap_report() -> CommandResponse {
    let stats = mem_stats::global();
    let scrap = scrap_heap::snapshot();
    let scrap_heap_mb = scrap.live_bytes as f64 / 1024.0 / 1024.0;
    let mut report = String::new();

    let _ = writeln!(report, "=== scrap_heap ===");
    let _ = writeln!(report, "Live capacity: {:.1} MB", scrap_heap_mb);
    let _ = writeln!(
        report,
        "Identities: {} total, {} active",
        scrap.identities, scrap.active_identities
    );
    let _ = writeln!(
        report,
        "Regions: {} | live allocations: {}",
        scrap.regions, scrap.live_allocs
    );

    let pressure_cycles = stats.pressure_cycles();
    if pressure_cycles > 0 {
        let _ = writeln!(
            report,
            "Pressure: {} cycles, {} cells freed (pressure)",
            pressure_cycles,
            stats.pressure_cells_unloaded()
        );
    } else {
        let _ = writeln!(report, "Pressure: no events");
    }

    let unload_cycles = cell_unload::total_cycles();
    if unload_cycles > 0 {
        let _ = writeln!(
            report,
            "Cell unload: {} cells in {} cycles, freed {}MB",
            cell_unload::total_cells_unloaded(),
            unload_cycles,
            cell_unload::total_bytes_freed() / 1024 / 1024,
        );
    }

    CommandResponse::with_result(report, scrap_heap_mb)
}

fn quarantine_report() -> CommandResponse {
    if current_mode() != Some(AllocatorMode::GheapAndScrapHeap) {
        return CommandResponse::text(
            "gheap is disabled; set memory.allocator = 2 to enable gheap + scrap_heap".to_owned(),
        );
    }

    let pool_mb = pool::committed_bytes() as f64 / 1024.0 / 1024.0;
    let block_mb = block::committed_bytes() as f64 / 1024.0 / 1024.0;
    let va_mb = va_alloc::live_bytes() as f64 / 1024.0 / 1024.0;
    let mut report = String::new();

    let _ = writeln!(report, "=== gheap Status ===");
    let _ = writeln!(report, "Pool committed:      {:.1} MB", pool_mb);
    let _ = writeln!(
        report,
        "Pool reserved:       {} MB",
        pool::reserved_bytes() / 1024 / 1024
    );
    let _ = writeln!(report, "Pool live cells:     {}", pool::live_cells());
    let _ = writeln!(
        report,
        "Pool deferred free:  {}",
        pool::deferred_free_cells()
    );
    let _ = writeln!(
        report,
        "Block committed:     {:.1} MB ({} blocks)",
        block_mb,
        block::block_count()
    );
    let _ = writeln!(
        report,
        "Direct VA:           {:.1} MB ({} blocks, {} fails)",
        va_mb,
        va_alloc::live_count(),
        va_alloc::fail_count(),
    );
    let _ = writeln!(
        report,
        "Is main thread:      {}",
        allocator::is_main_thread()
    );

    CommandResponse::text(report)
}

fn cell_unload_report() -> CommandResponse {
    if current_mode() != Some(AllocatorMode::GheapAndScrapHeap) {
        return CommandResponse::text(
            "Cell unload reclaim is gheap-only; set memory.allocator = 2 to enable it".to_owned(),
        );
    }

    let owned_mb = mem_stats::current_allocator_bytes() / 1024 / 1024;
    let pool_mb = pool::committed_bytes() / 1024 / 1024;
    let mut report = String::new();

    let _ = writeln!(report, "=== Cell Unload ===");
    let _ = writeln!(report, "Current: gheap={}MB, pool={}MB", owned_mb, pool_mb);
    let _ = writeln!(
        report,
        "Lifetime: {} cells unloaded in {} cycles, freed {}MB total",
        cell_unload::total_cells_unloaded(),
        cell_unload::total_cycles(),
        cell_unload::total_bytes_freed() / 1024 / 1024,
    );
    let _ = writeln!(report, "Requesting 20 cells at next AI_JOIN...");

    cell_unload::request_deferred(20);
    CommandResponse::text(report)
}
