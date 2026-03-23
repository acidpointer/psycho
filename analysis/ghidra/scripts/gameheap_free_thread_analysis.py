# @category Analysis
# @description Analyze which threads call GameHeap::Free and what they free.
#   Maps callers of FUN_00aa4060 to understand per-thread free patterns.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
    output.append(msg)
    print(msg)

def decompile_at(addr_int, label, max_len=6000):
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

def find_xrefs_to(addr_int, label, limit=20):
    addr = toAddr(addr_int)
    refs = getReferencesTo(addr)
    callers = []
    count = 0
    for ref in refs:
        if count >= limit:
            write("  ... (truncated at %d)" % limit)
            break
        from_addr = ref.getFromAddress()
        from_func = fm.getFunctionContaining(from_addr)
        if from_func is not None:
            entry = from_func.getEntryPoint().getOffset()
            name = from_func.getName()
            site = from_addr.getOffset()
            callers.append((entry, name, site))
            write("    0x%08X %s (at 0x%08X)" % (entry, name, site))
        count += 1
    write("  [%s] %d refs found" % (label, len(callers)))
    return callers

# ======================================================================
write("=" * 70)
write("GAMEHEAP FREE THREAD ANALYSIS")
write("=" * 70)

write("")
write("# PART 1: Direct callers of GameHeap::Free (FUN_00aa4060)")
write("")
callers = find_xrefs_to(0x00AA4060, "GameHeap::Free")

write("")
write("# PART 2: Trace 2nd-level callers for top entries")
write("# Shows which subsystem/thread context calls each direct caller")
write("")

seen = set()
for entry, name, site in callers[:15]:
    if entry in seen:
        continue
    seen.add(entry)
    write("")
    write("--- %s @ 0x%08X ---" % (name, entry))
    find_xrefs_to(entry, "parents of %s" % name, limit=10)

write("")
write("# PART 3: BSTaskManagerThread free paths")
write("")
write("BSTaskManagerThread run loop:")
decompile_at(0x00C410B0, "BSTaskMgr_Run")

write("")
write("IOTask::Release:")
decompile_at(0x0044DD60, "IOTask_Release", max_len=3000)

write("")
write("# PART 4: NiNode destructor (PDD queue 0x08 - main thread)")
write("")
decompile_at(0x00418D20, "NiNode_dtor", max_len=4000)

write("")
write("# PART 5: Thread ID functions")
write("")
decompile_at(0x0040FC90, "GetThreadId", max_len=2000)
write("")
decompile_at(0x0044EDB0, "GetMainThreadId", max_len=2000)

# ======================================================================
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/gameheap_free_thread_analysis.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
