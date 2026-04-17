# @category Analysis
# @description Chain analysis for crash at 0x5A8EC0.
# Decompile FUN_006815c0, FUN_00726070, FUN_005a9d00, FUN_005aa090,
# FUN_005a9f20, FUN_005abf60, FUN_00401000, FUN_00aa4060.

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


def find_callers(addr_int, label, limit=15):
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
        if a == 0x005A8EC0:
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


# --- Main ---

write("CHAIN ANALYSIS: FUN_005a8ea0 crash at +0x20")
write("=" * 70)

# 1. Disassemble crash function
disasm_func(0x005A8EA0, "FUN_005a8ea0")

# 2. Chain accessor functions
decompile_at(0x006815C0, "FUN_006815c0")
decompile_at(0x00726070, "FUN_00726070")

# 3. Other callers of FUN_005a8ea0
decompile_at(0x005A9D00, "FUN_005a9d00")
decompile_at(0x005AA090, "FUN_005aa090")
decompile_at(0x005A9F20, "FUN_005a9f20")

# 4. Script event list allocator
decompile_at(0x005ABF60, "FUN_005abf60")

# 5. Game allocator
decompile_at(0x00401000, "FUN_00401000")

# 6. Free function
decompile_at(0x00AA4060, "FUN_00aa4060")

# 7. Script context constructor
decompile_at(0x005E0C60, "FUN_005e0c60")

# 8. Callers of FUN_006815c0
find_callers(0x006815C0, "FUN_006815c0")

# --- Output ---
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/crash_5A8EC0_chain_analysis.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
