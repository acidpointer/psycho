//! Vectored Exception Handler for heap crash diagnostics.
//!
//! Runs BEFORE CrashLogger's SetUnhandledExceptionFilter. On ACCESS_VIOLATION,
//! dumps disassembly, registers, memory region info, VAS pressure, slab state.
//! Returns EXCEPTION_CONTINUE_SEARCH so CrashLogger produces its normal dump.

use std::sync::atomic::{AtomicBool, Ordering};

use windows::Win32::Foundation::EXCEPTION_ACCESS_VIOLATION;
use windows::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, CONTEXT, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
    EXCEPTION_RECORD,
};

use super::allocator;
use super::engine::globals;
use super::slab;

static CAUGHT: AtomicBool = AtomicBool::new(false);

pub fn install() {
    let handle = unsafe { AddVectoredExceptionHandler(1, Some(handler)) };
    if handle.is_null() {
        log::error!("[CRASH] Failed to install diagnostic VEH");
    } else {
        log::info!("[CRASH] Diagnostic VEH installed");
    }
}

unsafe extern "system" fn handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    let info = unsafe { &*info };
    let record = unsafe { &*info.ExceptionRecord };

    if record.ExceptionCode != EXCEPTION_ACCESS_VIOLATION {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if CAUGHT.swap(true, Ordering::SeqCst) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let ctx = unsafe { &*info.ContextRecord };
    let fault_addr = record.ExceptionInformation[1];
    let access = match record.ExceptionInformation[0] {
        0 => "READ", 1 => "WRITE", 8 => "DEP", _ => "???",
    };

    log::error!("================================================================");
    log::error!("  PSYCHO CRASH DIAGNOSTIC -- ACCESS_VIOLATION ({access})");
    log::error!("================================================================");

    log_exception(record, ctx, fault_addr);
    log_disassembly(ctx);
    log_registers(ctx);
    log_fault_analysis(fault_addr, ctx);
    log_game_state();
    log_memory_pressure();
    log_slab_summary();

    log::error!("================================================================");
    EXCEPTION_CONTINUE_SEARCH
}

// -- exception ---------------------------------------------------------------

fn log_exception(_record: &EXCEPTION_RECORD, ctx: &CONTEXT, fault_addr: usize) {
    log::error!("");
    log::error!("  Exception");
    log::error!("  ---------");
    log::error!("  EIP:           0x{:08X}  ({})", ctx.Eip, region_tag(ctx.Eip as usize));
    log::error!("  Fault address: 0x{:08X}  ({})", fault_addr, region_tag(fault_addr));
    if fault_addr < 0x10000 {
        log::error!("  --> NULL pointer dereference at offset 0x{:X}", fault_addr);
    }
}

// -- disassembly -------------------------------------------------------------

fn log_disassembly(ctx: &CONTEXT) {
    log::error!("");
    log::error!("  Faulting Instruction");
    log::error!("  --------------------");

    let eip = ctx.Eip as usize;
    // try to read 15 bytes at EIP (max x86 instruction length)
    let bytes: &[u8] = unsafe {
        // this might fault if EIP itself is in unmapped memory -- we're already
        // crashing so a nested AV is fine (CAUGHT flag prevents re-entry)
        core::slice::from_raw_parts(eip as *const u8, 15)
    };

    let mut decoder = iced_x86::Decoder::with_ip(
        32,
        bytes,
        eip as u64,
        iced_x86::DecoderOptions::NONE,
    );

    if let Some(instr) = decoder.iter().next() {
        let mut output = String::new();
        let mut formatter = iced_x86::FastFormatter::new();
        formatter.format(&instr, &mut output);
        log::error!("  0x{:08X}: {}", eip, output);

        // show which operand likely caused the fault
        for i in 0..instr.op_count() {
            if instr.op_kind(i) == iced_x86::OpKind::Memory {
                let base = instr.memory_base();
                let index = instr.memory_index();
                let disp = instr.memory_displacement32();
                let base_val = reg_value(ctx, base);
                let index_val = reg_value(ctx, index);
                let scale = instr.memory_index_scale();
                let effective = base_val
                    .wrapping_add(index_val.wrapping_mul(scale))
                    .wrapping_add(disp);
                log::error!(
                    "  --> memory operand: [{} + {} * {} + 0x{:X}] = 0x{:08X}",
                    reg_name(base), reg_name(index), scale, disp, effective,
                );
                if let Some(name) = reg_name_opt(base) {
                    log::error!("      {} = 0x{:08X}  ({})", name, base_val, region_tag(base_val as usize));
                }
            }
        }
    } else {
        log::error!("  (failed to decode instruction at 0x{:08X})", eip);
    }
}

// -- registers ---------------------------------------------------------------

fn log_registers(ctx: &CONTEXT) {
    log::error!("");
    log::error!("  Registers");
    log::error!("  ---------");
    log::error!(
        "  EAX={:08X}  EBX={:08X}  ECX={:08X}  EDX={:08X}",
        ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx,
    );
    log::error!(
        "  ESI={:08X}  EDI={:08X}  EBP={:08X}  ESP={:08X}",
        ctx.Esi, ctx.Edi, ctx.Ebp, ctx.Esp,
    );
    for &(name, val) in &[
        ("EAX", ctx.Eax), ("EBX", ctx.Ebx), ("ECX", ctx.Ecx), ("EDX", ctx.Edx),
        ("ESI", ctx.Esi), ("EDI", ctx.Edi),
    ] {
        let tag = region_tag(val as usize);
        if tag != "---" {
            log::error!("  {} = 0x{:08X}  ({})", name, val, tag);
        }
    }
}

// -- fault address -----------------------------------------------------------

fn log_fault_analysis(fault_addr: usize, ctx: &CONTEXT) {
    log::error!("");
    log::error!("  Fault Address Analysis");
    log::error!("  ----------------------");
    log::error!("  Region: {}", region_tag(fault_addr));

    if slab::is_slab_ptr(fault_addr as *const core::ffi::c_void) {
        slab::diagnose_ptr(fault_addr);
    }

    let eip = ctx.Eip as usize;
    if slab::is_slab_ptr(eip as *const core::ffi::c_void) {
        log::error!("  !!! EIP is inside slab heap data -- wild vtable jump");
        slab::diagnose_ptr(eip);
    }
}

// -- game state --------------------------------------------------------------

fn log_game_state() {
    log::error!("");
    log::error!("  Game State");
    log::error!("  ----------");
    log::error!("  Loading:         {}", globals::is_loading());
    log::error!("  LoadingCounter:  {}", globals::loading_state_counter().load(Ordering::Relaxed));
    log::error!("  MainThread:      {}", globals::is_main_thread_by_tid());
    log::error!(
        "  ThreadID:        {}",
        libpsycho::os::windows::winapi::get_current_thread_id(),
    );
}

// -- memory pressure (the indirect crash cause) ------------------------------

fn log_memory_pressure() {
    let mi = libmimalloc::process_info::MiMallocProcessInfo::get();
    let free_vas = allocator::current_free_vas();

    log::error!("");
    log::error!("  Memory Pressure");
    log::error!("  ---------------");
    log::error!("  Process commit:  {}MB (peak {}MB)", mi.get_current_commit() / 1024 / 1024, mi.get_peak_commit() / 1024 / 1024);
    log::error!("  Process RSS:     {}MB (peak {}MB)", mi.get_current_rss() / 1024 / 1024, mi.get_peak_rss() / 1024 / 1024);
    log::error!("  Free VAS:        {}MB", free_vas / 1024 / 1024);
    log::error!("  Page faults:     {}", mi.get_page_faults());

    // VAS health verdict
    if free_vas < 200 * 1024 * 1024 {
        log::error!("  --> VAS EMERGENCY: <200MB free, allocations likely failing");
    } else if free_vas < 400 * 1024 * 1024 {
        log::error!("  --> VAS CRITICAL: <400MB free, D3D/texture allocs may fail");
    } else if free_vas < 800 * 1024 * 1024 {
        log::error!("  --> VAS WARNING: <800MB free, under pressure");
    }
}

// -- slab summary ------------------------------------------------------------

fn log_slab_summary() {
    log::error!("");
    log::error!("  Slab Allocator");
    log::error!("  --------------");
    log::error!("  Committed:  {}MB", slab::committed_bytes() / 1024 / 1024);
    log::error!("  Dirty:      {} pages", slab::dirty_pages());

    // if dirty pages are high during a crash, they're wasting commit
    let dirty = slab::dirty_pages();
    if dirty > 500 {
        log::error!("  --> {} dirty pages sitting committed (potential VAS waste)", dirty);
    }
}

// -- helpers -----------------------------------------------------------------

fn region_tag(addr: usize) -> &'static str {
    if addr < 0x10000 { return "NULL page"; }
    if (0x00400000..0x01500000).contains(&addr) { return "FalloutNV.exe"; }
    if slab::is_slab_ptr(addr as *const core::ffi::c_void) { return "SLAB"; }
    if unsafe { libmimalloc::mi_is_in_heap_region(addr as *const core::ffi::c_void) } {
        return "MIMALLOC";
    }
    if unsafe { libpsycho::os::windows::va_allocator::is_virtual_alloc_ptr(addr as *mut core::ffi::c_void) } {
        return "VA_ALLOC";
    }
    "---"
}

fn reg_value(ctx: &CONTEXT, reg: iced_x86::Register) -> u32 {
    match reg {
        iced_x86::Register::EAX => ctx.Eax,
        iced_x86::Register::EBX => ctx.Ebx,
        iced_x86::Register::ECX => ctx.Ecx,
        iced_x86::Register::EDX => ctx.Edx,
        iced_x86::Register::ESI => ctx.Esi,
        iced_x86::Register::EDI => ctx.Edi,
        iced_x86::Register::EBP => ctx.Ebp,
        iced_x86::Register::ESP => ctx.Esp,
        _ => 0,
    }
}

fn reg_name(reg: iced_x86::Register) -> &'static str {
    match reg {
        iced_x86::Register::EAX => "eax",
        iced_x86::Register::EBX => "ebx",
        iced_x86::Register::ECX => "ecx",
        iced_x86::Register::EDX => "edx",
        iced_x86::Register::ESI => "esi",
        iced_x86::Register::EDI => "edi",
        iced_x86::Register::EBP => "ebp",
        iced_x86::Register::ESP => "esp",
        iced_x86::Register::None => "0",
        _ => "?",
    }
}

fn reg_name_opt(reg: iced_x86::Register) -> Option<&'static str> {
    match reg {
        iced_x86::Register::None => None,
        r => Some(reg_name(r)),
    }
}
