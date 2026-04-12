//! Vectored Exception Handler for heap crash diagnostics.
//!
//! Runs BEFORE CrashLogger's SetUnhandledExceptionFilter. On ACCESS_VIOLATION,
//! builds a complete diagnostic report into one String, emits it as a single
//! log::error! call (atomic -- either the full report is logged or nothing).
//! Returns EXCEPTION_CONTINUE_SEARCH so CrashLogger produces its normal dump.

use core::fmt::Write;
use std::sync::atomic::{AtomicBool, Ordering};

use windows::Win32::Foundation::EXCEPTION_ACCESS_VIOLATION;
use windows::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, CONTEXT, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
};
use windows::Win32::System::Memory::{
    MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_NOACCESS, VirtualQuery,
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

    // build the entire report into one buffer so it's emitted atomically
    let mut r = String::with_capacity(2048);

    let _ = writeln!(r, "\n================================================================");
    let _ = writeln!(r, "  PSYCHO CRASH DIAGNOSTIC -- ACCESS_VIOLATION ({access})");
    let _ = writeln!(r, "================================================================");

    // -- exception ---
    let _ = writeln!(r, "\n  Exception");
    let _ = writeln!(r, "  ---------");
    let _ = writeln!(r, "  EIP:           0x{:08X}  ({})", ctx.Eip, region_tag(ctx.Eip as usize));
    let _ = writeln!(r, "  Fault address: 0x{:08X}  ({})", fault_addr, region_tag(fault_addr));
    if fault_addr < 0x10000 {
        let _ = writeln!(r, "  --> NULL pointer dereference at offset 0x{:X}", fault_addr);
    }

    // -- disassembly (safe: probe memory before reading) ---
    let _ = writeln!(r, "\n  Faulting Instruction");
    let _ = writeln!(r, "  --------------------");
    let eip = ctx.Eip as usize;
    if is_readable(eip, 15) {
        let bytes = unsafe { core::slice::from_raw_parts(eip as *const u8, 15) };
        let mut decoder = iced_x86::Decoder::with_ip(32, bytes, eip as u64, iced_x86::DecoderOptions::NONE);
        if let Some(instr) = decoder.iter().next() {
            let mut asm = String::new();
            iced_x86::FastFormatter::new().format(&instr, &mut asm);
            let _ = writeln!(r, "  0x{:08X}: {}", eip, asm);

            for i in 0..instr.op_count() {
                if instr.op_kind(i) == iced_x86::OpKind::Memory {
                    let base = instr.memory_base();
                    let index = instr.memory_index();
                    let disp = instr.memory_displacement32();
                    let bv = reg_value(ctx, base);
                    let iv = reg_value(ctx, index);
                    let sc = instr.memory_index_scale();
                    let eff = bv.wrapping_add(iv.wrapping_mul(sc)).wrapping_add(disp);
                    let _ = writeln!(r, "  --> mem: [{} + {} * {} + 0x{:X}] = 0x{:08X}",
                        reg_name(base), reg_name(index), sc, disp, eff);
                    if let Some(n) = reg_name_opt(base) {
                        let _ = writeln!(r, "      {} = 0x{:08X}  ({})", n, bv, region_tag(bv as usize));
                    }
                }
            }
        } else {
            let _ = writeln!(r, "  (decode failed at 0x{:08X})", eip);
        }
    } else {
        let _ = writeln!(r, "  (EIP 0x{:08X} is not readable -- wild jump)", eip);
    }

    // -- registers ---
    let _ = writeln!(r, "\n  Registers");
    let _ = writeln!(r, "  ---------");
    let _ = writeln!(r, "  EAX={:08X}  EBX={:08X}  ECX={:08X}  EDX={:08X}",
        ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx);
    let _ = writeln!(r, "  ESI={:08X}  EDI={:08X}  EBP={:08X}  ESP={:08X}",
        ctx.Esi, ctx.Edi, ctx.Ebp, ctx.Esp);
    for &(name, val) in &[
        ("EAX", ctx.Eax), ("EBX", ctx.Ebx), ("ECX", ctx.Ecx), ("EDX", ctx.Edx),
        ("ESI", ctx.Esi), ("EDI", ctx.Edi),
    ] {
        let tag = region_tag(val as usize);
        if tag != "---" {
            let _ = writeln!(r, "  {} = 0x{:08X}  ({})", name, val, tag);
        }
    }

    // -- fault analysis ---
    let _ = writeln!(r, "\n  Fault Address Analysis");
    let _ = writeln!(r, "  ----------------------");
    let _ = writeln!(r, "  Region: {}", region_tag(fault_addr));
    if slab::is_slab_ptr(fault_addr as *const core::ffi::c_void) {
        write_slab_detail(&mut r, fault_addr);
    }
    if slab::is_slab_ptr(eip as *const core::ffi::c_void) {
        let _ = writeln!(r, "  !!! EIP is inside slab -- wild vtable jump");
        write_slab_detail(&mut r, eip);
    }

    // -- game state ---
    let _ = writeln!(r, "\n  Game State");
    let _ = writeln!(r, "  ----------");
    let _ = writeln!(r, "  Loading:         {}", globals::is_loading());
    let _ = writeln!(r, "  LoadingCounter:  {}", globals::loading_state_counter().load(Ordering::Relaxed));
    let _ = writeln!(r, "  MainThread:      {}", globals::is_main_thread_by_tid());
    let _ = writeln!(r, "  ThreadID:        {}", libpsycho::os::windows::winapi::get_current_thread_id());

    // -- memory pressure ---
    let mi = libmimalloc::process_info::MiMallocProcessInfo::get();
    let free_vas = allocator::current_free_vas();
    let _ = writeln!(r, "\n  Memory Pressure");
    let _ = writeln!(r, "  ---------------");
    let _ = writeln!(r, "  Process commit:  {}MB (peak {}MB)", mi.get_current_commit() / 1024 / 1024, mi.get_peak_commit() / 1024 / 1024);
    let _ = writeln!(r, "  Process RSS:     {}MB (peak {}MB)", mi.get_current_rss() / 1024 / 1024, mi.get_peak_rss() / 1024 / 1024);
    let _ = writeln!(r, "  Free VAS:        {}MB", free_vas / 1024 / 1024);
    let _ = writeln!(r, "  Page faults:     {}", mi.get_page_faults());
    if free_vas < 200 * 1024 * 1024 {
        let _ = writeln!(r, "  --> VAS EMERGENCY: <200MB free, allocations likely failing");
    } else if free_vas < 400 * 1024 * 1024 {
        let _ = writeln!(r, "  --> VAS CRITICAL: <400MB free, D3D/texture allocs may fail");
    } else if free_vas < 800 * 1024 * 1024 {
        let _ = writeln!(r, "  --> VAS WARNING: <800MB free, under pressure");
    }

    // -- slab ---
    let dirty = slab::dirty_pages();
    let _ = writeln!(r, "\n  Slab Allocator");
    let _ = writeln!(r, "  --------------");
    let _ = writeln!(r, "  Committed:  {}MB", slab::committed_bytes() / 1024 / 1024);
    let _ = writeln!(r, "  Dirty:      {} pages", dirty);
    if dirty > 500 {
        let _ = writeln!(r, "  --> {} dirty pages sitting committed (potential VAS waste)", dirty);
    }

    let _ = writeln!(r, "\n================================================================");

    // single atomic emit -- either the whole report is in the log or nothing
    log::error!("{}", r);

    EXCEPTION_CONTINUE_SEARCH
}

// -- slab page detail (writes to buffer, not log) ----------------------------

fn write_slab_detail(r: &mut String, addr: usize) {
    slab::diagnose_ptr_buf(addr, r);
}

// -- helpers -----------------------------------------------------------------

fn is_readable(addr: usize, len: usize) -> bool {
    if addr < 0x10000 {
        return false;
    }
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
    let ret = unsafe { VirtualQuery(
        Some(addr as *const core::ffi::c_void),
        &mut mbi,
        core::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
    )};
    if ret == 0 {
        return false;
    }
    // page must be committed and not PAGE_NOACCESS
    let committed = mbi.State == MEM_COMMIT;
    let accessible = mbi.Protect.0 != 0 && mbi.Protect != PAGE_NOACCESS;
    // check the range fits within this region
    let region_end = mbi.BaseAddress as usize + mbi.RegionSize;
    committed && accessible && addr + len <= region_end
}

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
