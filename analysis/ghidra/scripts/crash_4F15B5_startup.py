# @category Analysis
# @description Startup crash at 0x004F15B5. TESAmmo write to slab page.
# CrashLogger: W 0x1CB74064 EIP=0x004F15B5 EAX=3C ECX=1CB73F60 ESI=0
# slab=true. Write to TESAmmo+0x104 fails (page decommitted?).
# Playtime 4s, startup form loading from HopperWeaponPack.esm.

from ghidra.app.decompiler import DecompInterface

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


def disasm_func(addr_int, label):
    func = fm.getFunctionContaining(toAddr(addr_int))
    if func is None:
        write("  [no function at 0x%08x]" % addr_int)
        return
    write("")
    write("-" * 70)
    write("Disassembly %s @ 0x%08x" % (label, addr_int))
    write("-" * 70)
    body = func.getBody()
    inst_iter = currentProgram.getListing().getInstructions(body, True)
    while inst_iter.hasNext():
        inst = inst_iter.next()
        a = inst.getAddress().getOffset()
        marker = ""
        if a == 0x004F15B5:
            marker = " <<<< CRASH"
        refs = inst.getReferencesFrom()
        call_info = ""
        for ref in refs:
            if ref.getReferenceType().isCall():
                tgt = ref.getToAddress().getOffset()
                tgt_func = fm.getFunctionAt(toAddr(tgt))
                name = tgt_func.getName() if tgt_func else "???"
                call_info = " -> %s" % name
        write("  0x%08x: %s%s%s" % (a, inst, call_info, marker))


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


def find_callers(addr_int, label, limit=20):
    write("")
    write("-" * 70)
    write("Callers of 0x%08x (%s)" % (addr_int, label))
    write("-" * 70)
    refs = ref_mgr.getReferencesTo(toAddr(addr_int))
    count = 0
    while refs.hasNext():
        ref = refs.next()
        from_func = fm.getFunctionContaining(ref.getFromAddress())
        fname = from_func.getName() if from_func else "???"
        write("  0x%08x in %s" % (ref.getFromAddress().getOffset(), fname))
        count += 1
        if count >= limit:
            break
    write("  Total: %d" % count)


def disasm_range(start_int, end_int, label):
    write("")
    write("-" * 70)
    write("Disassembly %s: 0x%08x - 0x%08x" % (label, start_int, end_int))
    write("-" * 70)
    inst = currentProgram.getListing().getInstructionAt(toAddr(start_int))
    while inst is not None and inst.getAddress().getOffset() <= end_int:
        a = inst.getAddress().getOffset()
        marker = ""
        if a == 0x004F15B5:
            marker = " <<<< CRASH"
        refs = inst.getReferencesFrom()
        call_info = ""
        for ref in refs:
            if ref.getReferenceType().isCall():
                tgt = ref.getToAddress().getOffset()
                tgt_func = fm.getFunctionAt(toAddr(tgt))
                name = tgt_func.getName() if tgt_func else "???"
                call_info = " -> %s" % name
        write("  0x%08x: %s%s%s" % (a, inst, call_info, marker))
        inst = inst.getNext()


# --- Main ---

write("STARTUP CRASH ANALYSIS: 0x004F15B5")
write("=" * 70)
write("")
write("Crash context:")
write("  EIP = 0x004F15B5")
write("  EAX = 0x0000003C (60)")
write("  ECX = 0x1CB73F60 (TESAmmo - slab allocated)")
write("  ESI = 0x00000000 (NULL)")
write("  Write target: 0x1CB74064 (ECX + 0x104)")
write("  slab=true, mi=false")
write("  Playtime: 4 seconds (startup)")
write("")

# 1. Disassemble around the crash site
disasm_range(0x004F15A0, 0x004F15D0, "around crash site")

# 2. Decompile the crash function
func = decompile_at(0x004F15B5, "crash function")

# 3. Disassemble the full crash function
if func is not None:
    disasm_func(0x004F15B5, "crash function")

# 4. From the crash calltrace:
#    0x4F15B5 -> 0x5030C0 -> 0x4601F0 -> 0x469331 -> 0x467962 -> 0x463986
#    -> 0x86D2A9 -> 0x86B0ED -> main loop
decompile_at(0x005030C0, "caller 1 (0x5030C0)")
decompile_at(0x004601F0, "caller 2 (0x4601F0)")
decompile_at(0x00469331, "caller 3 (0x469331)")

# 5. Check what BSTreeNode cleanup does (0x467962 is in BSTreeNode area)
decompile_at(0x00467962, "caller 4 (0x467962)")
decompile_at(0x00463986, "caller 5 (0x463986)")

# 6. Check the game loop entry (0x86D2A9)
decompile_at(0x0086D2A9, "game loop (0x86D2A9)")

# 7. Check 0x4601F0 callers (the form destruction chain)
find_callers(0x004601F0, "0x4601F0 callers")

# 8. Check if 0x004F15B5 is in a known TESForm function
write("")
write("=" * 70)
write("ANALYSIS SUMMARY")
write("=" * 70)
write("")
write("The crash is a WRITE to TESAmmo+0x104 (0x1CB74064).")
write("ECX holds the TESAmmo pointer. ESI is NULL.")
write("")
write("The instruction at 0x4F15B5 is likely:")
write("  MOV [ECX + offset], reg  ; where ECX = TESAmmo object")
write("  or")
write("  MOV [reg + ESI*4 + offset], reg  ; ESI = NULL, offset = 0x104")
write("")
write("If ESI is used as an index (ESI * scale + base), NULL index")
write("should be valid (accessing base + 0). The crash at ECX+0x104")
write("means the write target is within the TESAmmo object range.")
write("")
write("slab=true means the fault address (0x1CB74064) is in our slab.")
write("If the slab page was decommitted, the write to committed memory")
write("would fail with ACCESS_VIOLATION.")
write("")
write("Key question: was the slab page containing 0x1CB74000 decommitted")
write("while the TESAmmo object was still in use?")

# --- Output ---
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/crash_4F15B5_startup.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
