# @category Analysis
# @description Investigate crash at 0x5A8EC0 (FUN_005a8ea0 +0x20).
# ScriptEventList cleanup after script execution. Determine what object
# is being processed, what virtual method is called, and whether the
# vtable pointer at 0x01000000 is valid or indicates heap corruption.
#
# Crash registers: EIP=0x005A8EC0 EAX=0x20 ECX=0x20 ESI=0x1C475300
# ESI deref: [0x1C475300] = 0x01000000 (vtable pointer into .rdata)
# Access violation reading 0x00000020

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import RefType

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []


def write(msg):
    output.append(msg)
    print(msg)


def decompile_at(addr_int, label, max_len=10000):
    addr = toAddr(addr_int)
    func = fm.getFunctionAt(addr)
    if func is None:
        func = fm.getFunctionContaining(addr)
    write("")
    write("=" * 70)
    write("%s @ 0x%08x" % (label, addr_int))
    write("=" * 70)
    if func is None:
        write("  [function not found]")
        return None
    faddr = func.getEntryPoint().getOffset()
    write(
        "  Function: %s @ 0x%08x, Size: %d bytes"
        % (func.getName(), faddr, func.getBody().getNumAddresses())
    )
    if faddr != addr_int:
        write(
            "  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)"
            % (addr_int, func.getName(), faddr)
        )
    result = decomp.decompileFunction(func, 120, monitor)
    if result and result.decompileCompleted():
        code = result.getDecompiledFunction().getC()
        write(code[:max_len])
    else:
        write("  [decompilation failed]")
    return func


def find_refs_to(addr_int, label):
    write("")
    write("-" * 70)
    write("References TO 0x%08x (%s)" % (addr_int, label))
    write("-" * 70)
    refs = ref_mgr.getReferencesTo(toAddr(addr_int))
    count = 0
    while refs.hasNext():
        ref = refs.next()
        from_func = fm.getFunctionContaining(ref.getFromAddress())
        fname = from_func.getName() if from_func else "???"
        write(
            "  %s @ 0x%08x (in %s)"
            % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname)
        )
        count += 1
        if count > 40:
            write("  ... (truncated)")
            break
    write("  Total: %d refs" % count)


def find_and_print_calls_from(addr_int, label):
    func = fm.getFunctionAt(toAddr(addr_int))
    if func is None:
        func = fm.getFunctionContaining(toAddr(addr_int))
    if func is None:
        write("  [function not found at 0x%08x]" % addr_int)
        return
    body = func.getBody()
    inst_iter = currentProgram.getListing().getInstructions(body, True)
    write("")
    write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
    count = 0
    while inst_iter.hasNext():
        inst = inst_iter.next()
        refs = inst.getReferencesFrom()
        for ref in refs:
            if ref.getReferenceType().isCall():
                tgt = ref.getToAddress().getOffset()
                tgt_func = fm.getFunctionAt(toAddr(tgt))
                name = tgt_func.getName() if tgt_func else "???"
                write(
                    "  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name)
                )
                count += 1
    write("  Total: %d calls" % count)


def disassemble_around(addr_int, radius=0x40):
    write("")
    write("-" * 70)
    write("Disassembly around 0x%08x (radius=0x%x)" % (addr_int, radius))
    write("-" * 70)
    start = addr_int - radius
    end = addr_int + radius
    inst = currentProgram.getListing().getInstructionAt(toAddr(start))
    while inst is not None and inst.getAddress().getOffset() <= end:
        a = inst.getAddress().getOffset()
        marker = " <<<< CRASH" if a == addr_int else ""
        write(
            "  0x%08x: %s %s%s"
            % (
                a,
                inst,
                inst.getDefaultOperandRepresentation(0)
                if inst.getNumOperands() > 0
                else "",
                marker,
            )
        )
        inst = inst.getNext()


def check_memory_at(addr_int, label):
    write("")
    write("-" * 70)
    write("Memory at 0x%08x (%s)" % (addr_int, label))
    write("-" * 70)
    mem = currentProgram.getMemory()
    addr = toAddr(addr_int)
    buf = bytearray(64)
    try:
        mem.getBytes(addr, buf)
        for i in range(0, 64, 16):
            hex_str = " ".join("%02x" % b for b in buf[i : i + 16])
            ascii_str = "".join(
                chr(b) if 32 <= b < 127 else "." for b in buf[i : i + 16]
            )
            write("  0x%08x: %s  %s" % (addr_int + i, hex_str, ascii_str))
        # Interpret first dword as potential vtable pointer
        dword0 = buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24)
        write("  First dword: 0x%08x" % dword0)
        if dword0 != 0:
            vt_func = fm.getFunctionAt(toAddr(dword0))
            if vt_func:
                write("  -> Points to function: %s" % vt_func.getName())
            else:
                vt_contain = fm.getFunctionContaining(toAddr(dword0))
                if vt_contain:
                    write(
                        "  -> Points inside function: %s +0x%x"
                        % (
                            vt_contain.getName(),
                            dword0 - vt_contain.getEntryPoint().getOffset(),
                        )
                    )
                else:
                    data = currentProgram.getListing().getDataAt(toAddr(dword0))
                    if data:
                        write("  -> Points to data: %s" % data.getDataType().getName())
                    else:
                        write("  -> No function or data found at this address")
    except Exception as e:
        write("  Error reading memory: %s" % str(e))


def trace_virtual_calls(func):
    """Find instructions that call through vtable pointers ([*this + offset])."""
    write("")
    write("-" * 70)
    write("Virtual calls in %s" % func.getName())
    write("-" * 70)
    body = func.getBody()
    inst_iter = currentProgram.getListing().getInstructions(body, True)
    count = 0
    while inst_iter.hasNext():
        inst = inst_iter.next()
        mnemonic = inst.getMnemonicString()
        if mnemonic in ("CALL", "JMP"):
            refs = inst.getReferencesFrom()
            for ref in refs:
                if ref.getReferenceType() == RefType.UNCONDITIONAL_CALL:
                    tgt = ref.getToAddress().getOffset()
                    tgt_func = fm.getFunctionAt(toAddr(tgt))
                    name = tgt_func.getName() if tgt_func else "???"
                    write(
                        "  0x%08x: CALL %s (0x%08x)"
                        % (inst.getAddress().getOffset(), name, tgt)
                    )
                    count += 1
        # Also check for indirect calls: CALL [reg+offset]
        if mnemonic == "CALL" and inst.getNumOperands() > 0:
            op = inst.getDefaultOperandRepresentation(0)
            if "[" in op and "+" in op:
                write(
                    "  0x%08x: INDIRECT CALL %s" % (inst.getAddress().getOffset(), op)
                )
                count += 1
    write("  Total: %d call sites" % count)


# --- Main Analysis ---

write("CRASH SITE ANALYSIS: 0x005A8EC0 (FUN_005a8ea0 +0x20)")
write("=" * 70)
write("")
write("Crash context:")
write("  EIP = 0x005A8EC0 (in FUN_005a8ea0 at offset +0x20)")
write("  EAX = 0x00000020 (32)")
write("  ECX = 0x00000020 (32)")
write("  ESI = 0x1C475300 -> deref 0x01000000 (vtable into .rdata)")
write("  EDX = 0x00000000")
write("  Access violation reading 0x00000020")
write("")

# 1. Decompile the crash function
func = decompile_at(0x005A8EA0, "FUN_005a8ea0 (crash site)")

# 2. Find all callers of FUN_005a8ea0
find_refs_to(0x005A8EA0, "FUN_005a8ea0 callers")

# 3. Decompile the caller from the crash stack: FUN_005e0d20
decompile_at(0x005E0D20, "FUN_005e0d20 (script processor)")

# 4. Check what's at 0x01000000 (start of .rdata, where the vtable supposedly is)
check_memory_at(0x01000000, "rdata start - possible vtable")

# 5. Disassemble around the crash site
disassemble_around(0x005A8EC0, 0x30)

# 6. Decompile the ScriptEventList destructor
decompile_at(0x005A8BC0, "ScriptEventList_GameDtor")

# 7. Check FUN_00401030 - called from ScriptEventList dtor (possibly a free)
decompile_at(0x00401030, "FUN_00401030 (possible free in dtor chain)")

# 8. Decompile FUN_005e2590 (the script executor wrapper in the crash chain)
decompile_at(0x005E2590, "FUN_005e2590 (script executor wrapper)")

# 9. Find callers of ScriptEventList_GameDtor
find_refs_to(0x005A8BC0, "ScriptEventList_GameDtor callers")

# 10. Decompile FUN_0041af70 (called from FUN_005e0d20 after FUN_005a8ea0)
decompile_at(0x0041AF70, "FUN_0041af70 (post-script cleanup)")

# 11. Trace the script processing call chain
write("")
write("=" * 70)
write("SCRIPT PROCESSING CALL CHAIN (from crash stack)")
write("=" * 70)
write("")
write("The crash stack shows:")
write("  FalloutNV+0x5A8EC0  <- FUN_005a8ea0 (crash)")
write("  FalloutNV+0x5E1058  <- FUN_005e0d20 (script execution)")
write("  FalloutNV+0x5E265B  <- FUN_005e2590 (script executor wrapper)")
write("  FalloutNV+0x5AC29A  <- FUN_005ac1e0 (script dispatcher)")
write("  FalloutNV+0x4D2604  <- script invocation from game loop")
write("  FalloutNV+0x565931  <- game object processing")
write("  FalloutNV+0x4555EA  <- AI/game tick")
write("  FalloutNV+0x86F69C  <- per_frame_queue_drain (ORIGINAL)")
write("  FalloutNV+0x870603  <- our hook returns to game")
write("  psycho_nvse+0x24133 <- hook_per_frame_queue_drain (our code)")
write("")
write("KEY FINDING: The script is running from WITHIN our hooked")
write("per_frame_queue_drain. The original function processes scripts,")
write("and our hook wraps it. The crash happens during normal script")
write("cleanup after script execution.")
write("")

# 12. Check if FUN_005a8ea0 accesses virtual methods
if func is not None:
    trace_virtual_calls(func)

# 13. Decompile FUN_005e0d20 around line 551 where FUN_005a8ea0 is called
write("")
write("-" * 70)
write("Analyzing the call to FUN_005a8ea0 in FUN_005e0d20")
write("-" * 70)
# Check the instruction at the call site
inst = currentProgram.getListing().getInstructionAt(toAddr(0x005E115F))
if inst is None:
    # Try nearby addresses
    for offset in range(-10, 11):
        inst = currentProgram.getListing().getInstructionAt(toAddr(0x005E115F + offset))
        if inst is not None:
            refs = inst.getReferencesFrom()
            for ref in refs:
                if (
                    ref.getReferenceType().isCall()
                    and ref.getToAddress().getOffset() == 0x005A8EA0
                ):
                    write(
                        "  Found call to FUN_005a8ea0 at 0x%08x"
                        % inst.getAddress().getOffset()
                    )
                    # Get surrounding instructions
                    prev_inst = inst.getPrevious()
                    if prev_inst:
                        write(
                            "  Previous: 0x%08x: %s"
                            % (prev_inst.getAddress().getOffset(), prev_inst)
                        )
                    write(
                        "  Current:  0x%08x: %s" % (inst.getAddress().getOffset(), inst)
                    )
                    next_inst = inst.getNext()
                    if next_inst:
                        write(
                            "  Next:     0x%08x: %s"
                            % (next_inst.getAddress().getOffset(), next_inst)
                        )
                    break

# 14. Check what FUN_005e0d20 passes to FUN_005a8ea0
write("")
write("-" * 70)
write("What does FUN_005e0d20 pass to FUN_005a8ea0?")
write("-" * 70)
write("From crash_0040FE96_analysis.txt, line 551:")
write("  FUN_005a8ea0(*(int *)((int)this + 8));")
write("")
write("This means:")
write("  'this' is a script processing context object (FUN_005e0c60)")
write("  +0x08 stores a pointer (ScriptEventList* or similar)")
write("  FUN_005a8ea0 receives that pointer as its parameter")
write("")
write("The ScriptEventList is the OBJECT being cleaned up.")
write("If this object was freed by PDD/cell cleanup while the script")
write("was running, the cleanup function crashes when accessing it.")
write("")

# 15. Check the game's loading_state_counter and NVSE dispatch suppression
write("")
write("=" * 70)
write("PDD + SCRIPT INTERACTION ANALYSIS")
write("=" * 70)
write("")
write("Our Phase 7 hook calls signal_heap_compact(PddPurge) every 250ms.")
write("The game's HeapCompact dispatcher at Phase 6 (SAME FRAME) reads")
write("this signal and runs stage 4 (PDD purge).")
write("")
write("Then the vanilla per_frame_queue_drain runs at Phase 7 (NEXT FRAME)")
write("and processes PDD items AGAIN.")
write("")
write("This means PDD drain runs 2x per frame instead of 1x.")
write("Objects are destroyed faster than the game expects.")
write("")
write("If a script references a form whose underlying data is in the PDD")
write("queue, the accelerated drain can free it while the script still")
write("references it. When the script finishes and cleans up its")
write("ScriptEventList, it accesses freed/corrupted memory -> crash.")
write("")

# --- Output ---
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/crash_5A8EC0_script_cleanup.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
