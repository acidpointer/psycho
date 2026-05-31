//! Command data provider for external host adapters.

use std::{fmt::Write as _, ptr};

use psycho_engine_fixes_api::{
    PSYCHO_COMMAND_CELL_UNLOAD, PSYCHO_COMMAND_HAS_RESULT, PSYCHO_COMMAND_MEM,
    PSYCHO_COMMAND_MEM_BYTES, PSYCHO_COMMAND_MEM_HUD, PSYCHO_COMMAND_MEM_MB,
    PSYCHO_COMMAND_QUARANTINE, PSYCHO_COMMAND_SCRAP_HEAP, PsychoCommandOutput,
};

use crate::mods::heap_replacer::gheap::engine::cell_unload;
use crate::mods::heap_replacer::gheap::{allocator, block, pool, va_alloc};
use crate::mods::heap_replacer::{AllocatorMode, current_mode, mem_stats, scrap_heap};

pub unsafe extern "system" fn run_command(command: u32, output: *mut PsychoCommandOutput) -> i32 {
    if output.is_null() {
        return 0;
    }

    let (text, result) = match command {
        PSYCHO_COMMAND_MEM => (mem_stats::MemStats::detailed_report(), None),
        PSYCHO_COMMAND_MEM_MB => mem_mb(),
        PSYCHO_COMMAND_MEM_BYTES => mem_bytes(),
        PSYCHO_COMMAND_SCRAP_HEAP => scrap_heap_report(),
        PSYCHO_COMMAND_MEM_HUD => (mem_stats::MemStats::hud_summary(), None),
        PSYCHO_COMMAND_QUARANTINE => quarantine_report(),
        PSYCHO_COMMAND_CELL_UNLOAD => cell_unload_report(),
        _ => return 0,
    };

    unsafe { write_output(&mut *output, &text, result) };
    1
}

fn mem_mb() -> (String, Option<f64>) {
    let bytes = mem_stats::current_allocator_bytes();
    let mb = bytes as f64 / 1024.0 / 1024.0;
    (
        format!("{}: {:.1} MB", mem_stats::current_allocator_name(), mb),
        Some(mb),
    )
}

fn mem_bytes() -> (String, Option<f64>) {
    let bytes = mem_stats::current_allocator_bytes();
    (
        format!("{}: {} bytes", mem_stats::current_allocator_name(), bytes),
        Some(bytes as f64),
    )
}

fn scrap_heap_report() -> (String, Option<f64>) {
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

    (report, Some(scrap_heap_mb))
}

fn quarantine_report() -> (String, Option<f64>) {
    if current_mode() != Some(AllocatorMode::GheapAndScrapHeap) {
        return (
            "gheap is disabled; set memory.allocator = 2 to enable gheap + scrap_heap".to_owned(),
            None,
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

    (report, None)
}

fn cell_unload_report() -> (String, Option<f64>) {
    if current_mode() != Some(AllocatorMode::GheapAndScrapHeap) {
        return (
            "Cell unload reclaim is gheap-only; set memory.allocator = 2 to enable it".to_owned(),
            None,
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
    (report, None)
}

unsafe fn write_output(output: &mut PsychoCommandOutput, text: &str, result: Option<f64>) {
    let bytes = text.as_bytes();
    output.written = bytes.len();
    output.flags = 0;
    output.result = 0.0;

    if !output.text.is_null() && output.text_len > 0 {
        let copy_len = bytes.len().min(output.text_len);
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), output.text, copy_len) };
    }

    if let Some(value) = result {
        output.result = value;
        output.flags |= PSYCHO_COMMAND_HAS_RESULT;
    }
}
