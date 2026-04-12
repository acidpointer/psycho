//! Vectored Exception Handler for heap crash diagnostics.
//!
//! On ACCESS_VIOLATION, builds a full diagnostic report (disassembly, named
//! stack trace, pointer chain analysis, slab cell dump, memory pressure) into
//! one String and emits it as a single log::error! call (atomic output).

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

// ---- Ghidra-verified function address table (sorted by start address) ------
// (start, size, name). Binary searched via partition_point.
const KNOWN_FUNCS: &[(u32, u32, &str)] = &[
    (0x00401030, 16, "operator_delete"),
    (0x004019A0, 32, "InterlockedDecrement_Wrapper"),
    (0x0040FBF0, 32, "SpinLock_Acquire"),
    (0x0040FC90, 16, "GetThreadId_Wrapper"),
    (0x0043BD10, 208, "QueuedTexture_Ctor1"),
    (0x0043BE30, 44, "QueuedTexture_ScalarDtor"),
    (0x0043BE60, 129, "QueuedTexture_Ctor2"),
    (0x0043BEF0, 140, "QueuedTexture_Ctor3"),
    (0x0043BF80, 95, "QueuedTexture_Dtor"),
    (0x0043C050, 64, "QueuedTexture_vtable8"),
    (0x0043C150, 64, "QueuedTexture_vtable1"),
    (0x0043C550, 64, "QueuedTexture_vtable2"),
    (0x0043C650, 64, "QueuedTexture_vtable3"),
    (0x0044AD70, 128, "NiAVObject_UpdateTransforms"),
    (0x0044DD60, 81, "IOTask_Release"),
    (0x0044EDB0, 32, "GetMainThreadId"),
    (0x00449150, 64, "IOTask_Submit"),
    (0x00452490, 256, "ProcessPendingCleanup"),
    (0x00453A80, 256, "FindCellToUnload"),
    (0x00462290, 256, "DestroyCell"),
    (0x0045CEC0, 64, "cancellation_token_dtor"),
    (0x0054AF40, 53, "CellCleanup_ActorProcess"),
    (0x00633C90, 64, "NiPointer_Init"),
    (0x0066B0D0, 64, "RefSwap"),
    (0x00667470, 2048, "NiNode_ProcessCleanup"),
    (0x00713D80, 32, "GetAIThreadManager"),
    (0x008324E0, 256, "HavokStopStart"),
    (0x00866A90, 512, "OOM_StageExec"),
    (0x00866DA0, 32, "BStask_GetOwner"),
    (0x00866DC0, 32, "BStask_ReleaseSem"),
    (0x00866DE0, 32, "BStask_SignalIdle"),
    (0x00868850, 256, "PerFrameQueueDrain"),
    (0x00868D70, 1037, "ProcessDeferredDestruction"),
    (0x00869190, 64, "SetTlsCleanupFlag"),
    (0x0086B3E3, 32, "InnerLoop_NVSEHook"),
    (0x0086E650, 2272, "InnerLoop"),
    (0x0086EA4E, 128, "InnerLoop_ActorUpdate"),
    (0x0086F940, 256, "CellTransition_Handler"),
    (0x008705D0, 256, "MainLoopMaintenance"),
    (0x00878160, 64, "PreDestructionSetup"),
    (0x00878200, 64, "PostDestructionRestore"),
    (0x00878250, 256, "DeferredCleanupSmall"),
    (0x008774A0, 512, "CellTransitionOrchestrator"),
    (0x00882B90, 1699, "EventProcess_Inner"),
    (0x008860D0, 629, "EventDispatcher"),
    (0x008C3C40, 804, "ProcessUpdate"),
    (0x008C78C0, 198, "AIThreadStart"),
    (0x008C7990, 128, "AIThreadJoin"),
    (0x008C8FD0, 25, "ProcessChangeFlag"),
    (0x0093BEA0, 256, "ConditionalCellTransition"),
    (0x00931850, 64, "HasProcess"),
    (0x009306D0, 46, "GetActorProcess"),
    (0x009334B0, 128, "ShouldDowngrade"),
    (0x0096D470, 256, "ProcessDispatch2"),
    (0x0096E150, 311, "ActorProcess_EventTrigger"),
    (0x0096E6F0, 256, "ActorProcessChange_Dispatch"),
    (0x0096E870, 315, "ActorDowngrade"),
    (0x0096F376, 256, "ActorUpdateOuter"),
    (0x00978550, 122, "ProcessMgr_WithLock"),
    (0x00A5E3A0, 128, "NiTexture_Alloc"),
    (0x00A5FCA0, 256, "NiSourceTexture_Dtor"),
    (0x00A61A60, 256, "TextureCache_Find"),
    (0x00A62030, 256, "TextureCache_PreReset"),
    (0x00AA3E40, 256, "GameHeap_Allocate"),
    (0x00AA4060, 256, "GameHeap_Free"),
    (0x00AA4150, 128, "GameHeap_Realloc1"),
    (0x00AA4200, 128, "GameHeap_Realloc2"),
    (0x00AA44C0, 128, "GameHeap_Msize"),
    (0x00AA5230, 32, "RNG"),
    (0x00AA53F0, 32, "ScrapHeap_InitFix"),
    (0x00AA54A0, 256, "ScrapHeap_Alloc"),
    (0x00AA5610, 128, "ScrapHeap_Free"),
    (0x00AA6E00, 86, "SBM_FreelistLink"),
    (0x00AA6E60, 72, "SBM_FreelistUnlink"),
    (0x00C3CEA0, 64, "IOTask_Cleanup"),
    (0x00C3DBF0, 646, "IOManager_Process"),
    (0x00C3E310, 32, "hkWorld_Lock"),
    (0x00C3E340, 32, "hkWorld_Unlock"),
    (0x00C459D0, 256, "HavokGC"),
];

// ---- known vtable addresses (sorted) ----
const KNOWN_VTABLES: &[(u32, &str)] = &[
    (0x01016788, "QueuedTexture"),
    (0x01016BA4, "QueuedReference"),
    (0x0101DCE4, "NiRefObject"),
    (0x0101FBD4, "NiTObjectArray"),
    (0x010143E8, "ExtraDataList"),
    (0x010158E4, "ExtraHealth"),
    (0x010159C8, "ExtraCombatStyle"),
    (0x01015BB8, "ExtraContainerChanges"),
    (0x01020698, "GridCellArray"),
    (0x0102A588, "TESObjectARMO"),
    (0x0102C51C, "TESObjectWEAP"),
    (0x0102E9B4, "TESObjectCELL"),
    (0x0103195C, "TESWorldSpace"),
    (0x0104A2F4, "TESNPC"),
    (0x0106847C, "TESPackage"),
    (0x01085688, "AILinearTaskThread"),
    (0x01086A6C, "Character"),
    (0x01087864, "HighProcess"),
    (0x010886E4, "LowProcess"),
    (0x0108AA3C, "PlayerCharacter"),
    (0x010A8F90, "BSFadeNode"),
    (0x010C1524, "QueuedFile"),
    (0x010C1604, "IOManager"),
    (0x010C3BC4, "ahkpWorld"),
    (0x010C49C4, "bhkCharacterController"),
    (0x010C69F4, "bhkWorldM"),
    (0x010CA330, "hkScaledMoppBvTreeShape"),
    (0x010CCF28, "hkpSimulationIsland"),
];

// ---- public API ------------------------------------------------------------

pub fn install() {
    let handle = unsafe { AddVectoredExceptionHandler(1, Some(handler)) };
    if handle.is_null() {
        log::error!("[CRASH] Failed to install diagnostic VEH");
    } else {
        log::info!("[CRASH] Diagnostic VEH installed");
    }
}

// ---- VEH handler -----------------------------------------------------------

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
    let fault = record.ExceptionInformation[1] as usize;
    let access = match record.ExceptionInformation[0] {
        0 => "READ", 1 => "WRITE", 8 => "DEP", _ => "???",
    };

    let mut r = String::with_capacity(4096);
    let _ = writeln!(r, "\n================================================================");
    let _ = writeln!(r, "  PSYCHO CRASH DIAGNOSTIC -- ACCESS_VIOLATION ({access})");
    let _ = writeln!(r, "================================================================");

    write_exception(&mut r, ctx, fault);
    write_disassembly(&mut r, ctx);
    write_stack_walk(&mut r, ctx);
    write_registers(&mut r, ctx);
    write_ptr_analysis(&mut r, ctx);
    write_fault_analysis(&mut r, fault, ctx);
    write_game_state(&mut r);
    write_memory_pressure(&mut r);
    write_slab_summary(&mut r);

    let _ = writeln!(r, "================================================================");
    log::error!("{}", r);
    EXCEPTION_CONTINUE_SEARCH
}

// ---- report sections -------------------------------------------------------

fn write_exception(r: &mut String, ctx: &CONTEXT, fault: usize) {
    let _ = writeln!(r, "\n  Exception");
    let _ = writeln!(r, "  ---------");
    let _ = write!(r, "  EIP:           0x{:08X}", ctx.Eip);
    write_func_tag(r, ctx.Eip);
    let _ = writeln!(r);
    let _ = writeln!(r, "  Fault address: 0x{:08X}  ({})", fault, region_tag(fault));
    if fault < 0x10000 {
        let _ = writeln!(r, "  --> NULL pointer dereference at offset 0x{:X}", fault);
    }
}

fn write_disassembly(r: &mut String, ctx: &CONTEXT) {
    let _ = writeln!(r, "\n  Faulting Instruction");
    let _ = writeln!(r, "  --------------------");
    let eip = ctx.Eip as usize;
    if !is_readable(eip, 15) {
        let _ = writeln!(r, "  (EIP 0x{:08X} not readable -- wild jump)", eip);
        return;
    }
    let bytes = unsafe { core::slice::from_raw_parts(eip as *const u8, 15) };
    let mut dec = iced_x86::Decoder::with_ip(32, bytes, eip as u64, iced_x86::DecoderOptions::NONE);
    let Some(instr) = dec.iter().next() else {
        let _ = writeln!(r, "  (decode failed at 0x{:08X})", eip);
        return;
    };
    let mut asm = String::new();
    iced_x86::FastFormatter::new().format(&instr, &mut asm);
    let _ = writeln!(r, "  0x{:08X}: {}", eip, asm);

    for i in 0..instr.op_count() {
        if instr.op_kind(i) == iced_x86::OpKind::Memory {
            let base = instr.memory_base();
            let idx = instr.memory_index();
            let disp = instr.memory_displacement32();
            let bv = reg_value(ctx, base);
            let iv = reg_value(ctx, idx);
            let sc = instr.memory_index_scale();
            let eff = bv.wrapping_add(iv.wrapping_mul(sc)).wrapping_add(disp);
            let _ = writeln!(r, "  --> mem: [{} + {} * {} + 0x{:X}] = 0x{:08X}",
                reg_name(base), reg_name(idx), sc, disp, eff);
            if let Some(n) = reg_name_opt(base) {
                let _ = writeln!(r, "      {} = 0x{:08X}  ({})", n, bv, region_tag(bv as usize));
            }
        }
    }
}

fn write_stack_walk(r: &mut String, ctx: &CONTEXT) {
    let _ = writeln!(r, "\n  Stack Trace");
    let _ = writeln!(r, "  -----------");

    // frame 0 is EIP itself
    let _ = write!(r, "  #0  0x{:08X}", ctx.Eip);
    write_func_tag(r, ctx.Eip);
    let _ = writeln!(r);

    let mut ebp = ctx.Ebp as usize;
    for i in 1..=16u32 {
        if !is_readable(ebp, 8) { break; }
        let ret = unsafe { *((ebp + 4) as *const u32) };
        let next_ebp = unsafe { *(ebp as *const u32) } as usize;
        if ret < 0x10000 { break; }
        let _ = write!(r, "  #{:<2} 0x{:08X}", i, ret);
        write_func_tag(r, ret);
        let _ = writeln!(r);
        if next_ebp <= ebp { break; } // must ascend
        ebp = next_ebp;
    }
}

fn write_registers(r: &mut String, ctx: &CONTEXT) {
    let _ = writeln!(r, "\n  Registers");
    let _ = writeln!(r, "  ---------");
    let _ = writeln!(r, "  EAX={:08X}  EBX={:08X}  ECX={:08X}  EDX={:08X}",
        ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx);
    let _ = writeln!(r, "  ESI={:08X}  EDI={:08X}  EBP={:08X}  ESP={:08X}",
        ctx.Esi, ctx.Edi, ctx.Ebp, ctx.Esp);
}

fn write_ptr_analysis(r: &mut String, ctx: &CONTEXT) {
    let _ = writeln!(r, "\n  Pointer Analysis");
    let _ = writeln!(r, "  ----------------");
    for &(name, val) in &[
        ("EAX", ctx.Eax), ("EBX", ctx.Ebx), ("ECX", ctx.Ecx), ("EDX", ctx.Edx),
        ("ESI", ctx.Esi), ("EDI", ctx.Edi),
    ] {
        let addr = val as usize;
        if addr < 0x10000 || !is_readable(addr, 16) { continue; }
        let _ = writeln!(r, "  {} = 0x{:08X}  ({})", name, val, region_tag(addr));
        for off in [0u32, 4, 8, 12] {
            let v = unsafe { *((addr + off as usize) as *const u32) };
            let _ = write!(r, "    [+0x{:02X}] 0x{:08X}", off, v);
            if off == 0 {
                if let Some(cls) = resolve_vtable(v) {
                    let _ = write!(r, "  vtable: {}", cls);
                } else if v == 0xCDCDCDCD {
                    let _ = write!(r, "  (sentinel -- freshly committed page)");
                } else if v == 0 {
                    let _ = write!(r, "  (NULL vtable -- decommitted or zeroed)");
                }
            }
            if off == 4 && v > 0 && v < 10000 {
                let _ = write!(r, "  (refcount={})", v);
            }
            let _ = writeln!(r);
        }
    }
}

fn write_fault_analysis(r: &mut String, fault: usize, ctx: &CONTEXT) {
    let _ = writeln!(r, "\n  Fault Address Analysis");
    let _ = writeln!(r, "  ----------------------");
    let _ = writeln!(r, "  Region: {}", region_tag(fault));

    if slab::is_slab_ptr(fault as *const core::ffi::c_void) {
        slab::diagnose_ptr_buf(fault, r);
        write_cell_dump(r, fault);
    }

    let eip = ctx.Eip as usize;
    if slab::is_slab_ptr(eip as *const core::ffi::c_void) {
        let _ = writeln!(r, "  !!! EIP inside slab -- wild vtable jump into heap data");
        slab::diagnose_ptr_buf(eip, r);
    }
}

fn write_cell_dump(r: &mut String, addr: usize) {
    // align down to cell boundary (we don't know cell_size here, just dump from addr)
    // dump 32 bytes starting from addr if readable
    if !is_readable(addr, 32) { return; }
    let _ = writeln!(r, "\n  Cell Data (32 bytes at fault address)");
    let _ = writeln!(r, "  -------------------------------------");
    let bytes = unsafe { core::slice::from_raw_parts(addr as *const u8, 32) };
    for row in 0..2 {
        let off = row * 16;
        let _ = write!(r, "  0x{:08X}: ", addr + off);
        for i in 0..16 {
            let _ = write!(r, "{:02X} ", bytes[off + i]);
            if i == 7 { let _ = write!(r, " "); }
        }
        let _ = writeln!(r);
    }
    // interpret first dword
    let dw0 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if let Some(cls) = resolve_vtable(dw0) {
        let _ = writeln!(r, "  --> offset 0: vtable for {}", cls);
    } else if dw0 == 0 {
        let _ = writeln!(r, "  --> offset 0: NULL (decommitted page or zeroed)");
    } else if dw0 == 0xCDCDCDCD {
        let _ = writeln!(r, "  --> offset 0: 0xCDCDCDCD (sentinel -- virgin page, never constructed)");
    } else if dw0 < 0x10000 {
        let _ = writeln!(r, "  --> offset 0: 0x{:08X} (small integer -- recycled cell, different type)", dw0);
    }
}

fn write_game_state(r: &mut String) {
    let _ = writeln!(r, "\n  Game State");
    let _ = writeln!(r, "  ----------");
    let _ = writeln!(r, "  Loading:         {}", globals::is_loading());
    let _ = writeln!(r, "  LoadingCounter:  {}", globals::loading_state_counter().load(Ordering::Relaxed));
    let _ = writeln!(r, "  MainThread:      {}", globals::is_main_thread_by_tid());
    let _ = writeln!(r, "  ThreadID:        {}", libpsycho::os::windows::winapi::get_current_thread_id());
}

fn write_memory_pressure(r: &mut String) {
    let mi = libmimalloc::process_info::MiMallocProcessInfo::get();
    let free_vas = allocator::current_free_vas();
    let _ = writeln!(r, "\n  Memory Pressure");
    let _ = writeln!(r, "  ---------------");
    let _ = writeln!(r, "  Process commit:  {}MB (peak {}MB)", mi.get_current_commit() >> 20, mi.get_peak_commit() >> 20);
    let _ = writeln!(r, "  Process RSS:     {}MB (peak {}MB)", mi.get_current_rss() >> 20, mi.get_peak_rss() >> 20);
    let _ = writeln!(r, "  Free VAS:        {}MB", free_vas >> 20);
    if free_vas < 200 << 20 {
        let _ = writeln!(r, "  --> VAS EMERGENCY: <200MB free");
    } else if free_vas < 400 << 20 {
        let _ = writeln!(r, "  --> VAS CRITICAL: <400MB free");
    } else if free_vas < 800 << 20 {
        let _ = writeln!(r, "  --> VAS WARNING: <800MB free");
    }
}

fn write_slab_summary(r: &mut String) {
    let dirty = slab::dirty_pages();
    let _ = writeln!(r, "\n  Slab Allocator");
    let _ = writeln!(r, "  --------------");
    let _ = writeln!(r, "  Committed:  {}MB", slab::committed_bytes() >> 20);
    let _ = writeln!(r, "  Dirty:      {} pages", dirty);
    if dirty > 500 {
        let _ = writeln!(r, "  --> {} dirty pages committed but unused", dirty);
    }
}

// ---- lookup helpers --------------------------------------------------------

fn resolve_func(addr: u32) -> Option<(&'static str, u32)> {
    let i = KNOWN_FUNCS.partition_point(|&(start, _, _)| start <= addr);
    if i == 0 { return None; }
    let (start, size, name) = KNOWN_FUNCS[i - 1];
    let offset = addr - start;
    if offset < size { Some((name, offset)) } else { None }
}

fn resolve_vtable(addr: u32) -> Option<&'static str> {
    KNOWN_VTABLES.binary_search_by_key(&addr, |&(a, _)| a)
        .ok()
        .map(|i| KNOWN_VTABLES[i].1)
}

fn write_func_tag(r: &mut String, addr: u32) {
    if let Some((name, off)) = resolve_func(addr) {
        let _ = write!(r, "  {}+0x{:X}", name, off);
    } else if (0x00400000..0x01500000).contains(&(addr as usize)) {
        let _ = write!(r, "  FalloutNV.exe+0x{:X}", addr - 0x00400000);
    } else {
        let _ = write!(r, "  ({})", region_tag(addr as usize));
    }
}

// ---- memory / region helpers -----------------------------------------------

fn is_readable(addr: usize, len: usize) -> bool {
    if addr < 0x10000 { return false; }
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
    let ret = unsafe { VirtualQuery(
        Some(addr as *const core::ffi::c_void),
        &mut mbi,
        core::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
    )};
    if ret == 0 { return false; }
    let ok = mbi.State == MEM_COMMIT && mbi.Protect.0 != 0 && mbi.Protect != PAGE_NOACCESS;
    ok && addr + len <= mbi.BaseAddress as usize + mbi.RegionSize
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
