# @category Analysis
# @description Decompile outer loop and inner loop to map the exact sequence
#   between cell transition, destruction, and NVSE dispatch.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
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
    if func is None:
        write("  [%s] No function at 0x%08X" % (label, addr_int))
        return
    write("  [%s] %s @ 0x%08X (%d bytes)" % (label, func.getName(),
          func.getEntryPoint().getOffset(), func.getBody().getNumAddresses()))
    result = decomp.decompileFunction(func, 120, monitor)
    if result and result.decompileCompleted():
        code = result.getDecompiledFunction().getC()
        write(code[:max_len])
    else:
        write("  [decompile failed]")

def disasm_range(start, end, label):
    write("  [%s] Disasm 0x%08X - 0x%08X:" % (label, start, end))
    listing = currentProgram.getListing()
    inst = listing.getInstructionAt(toAddr(start))
    count = 0
    while inst is not None and inst.getAddress().getOffset() <= end:
        addr = inst.getAddress().getOffset()
        disasm = inst.toString()
        annotation = ""
        if inst.getFlowType().isCall():
            refs_from = inst.getReferencesFrom()
            for r in refs_from:
                target = r.getToAddress().getOffset()
                tfunc = fm.getFunctionAt(r.getToAddress())
                tname = tfunc.getName() if tfunc else "???"
                annotation = " -> %s (0x%08X)" % (tname, target)
        write("    0x%08X  %-40s%s" % (addr, disasm, annotation))
        inst = inst.getNext()
        count += 1
        if count > 150:
            write("    ... (limit)")
            break

def find_calls_in(addr_int, label):
    func = fm.getFunctionAt(toAddr(addr_int))
    if func is None:
        write("  [%s] No function at 0x%08X" % (label, addr_int))
        return
    listing = currentProgram.getListing()
    body = func.getBody()
    inst_iter = listing.getInstructions(body, True)
    calls = []
    while inst_iter.hasNext():
        inst = inst_iter.next()
        if inst.getFlowType().isCall():
            refs_from = inst.getReferencesFrom()
            for r in refs_from:
                target = r.getToAddress().getOffset()
                tfunc = fm.getFunctionAt(r.getToAddress())
                tname = tfunc.getName() if tfunc else "???"
                calls.append((inst.getAddress().getOffset(), target, tname))
    write("  [%s] %d calls:" % (label, len(calls)))
    for site, target, tname in calls:
        write("    0x%08X -> 0x%08X %s" % (site, target, tname))

# ======================================================================
write("=" * 70)
write("OUTER LOOP FULL SEQUENCE")
write("=" * 70)

write("")
write("# PART 1: Outer game loop (FUN_0086a850)")
write("")
decompile_at(0x0086A850, "OuterLoop", max_len=12000)

write("")
write("# PART 2: All calls from outer loop")
write("")
find_calls_in(0x0086A850, "OuterLoop")

write("")
write("# PART 3: Disasm around NVSE hook point (0x0086b3e3)")
write("")
disasm_range(0x0086B3C0, 0x0086B420, "NVSE_hook_area")

write("")
write("# PART 4: Inner per-frame loop (FUN_0086e650) - calls only")
write("")
find_calls_in(0x0086E650, "InnerLoop")

write("")
write("# PART 5: FUN_0086f940 (calls PDD callers from inner loop)")
write("")
decompile_at(0x0086F940, "PDD_Phase", max_len=6000)

write("")
write("# PART 6: CellTransitionHandler (FUN_008774a0)")
write("")
decompile_at(0x008774A0, "CellTransition", max_len=10000)

write("")
write("# PART 7: Script cleanup paths")
write("")
decompile_at(0x00574400, "ScriptCleanup", max_len=5000)
write("")
decompile_at(0x00573F40, "ScriptDataDestroy", max_len=5000)

# ======================================================================
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/outer_loop_full_sequence.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
