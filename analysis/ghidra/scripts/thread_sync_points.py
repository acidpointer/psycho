# @category Analysis
# @description Map synchronization points between game threads.
#   Focused analysis: decompile key sync functions, find callers of
#   critical locks. Avoids OOM by limiting xref depth.

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

def find_xrefs_to(addr_int, label, limit=15):
    addr = toAddr(addr_int)
    refs = getReferencesTo(addr)
    count = 0
    for ref in refs:
        if count >= limit:
            write("  ... (truncated at %d)" % limit)
            break
        from_addr = ref.getFromAddress()
        from_func = fm.getFunctionContaining(from_addr)
        fname = from_func.getName() if from_func else "???"
        fentry = from_func.getEntryPoint().getOffset() if from_func else 0
        write("    0x%08X %s (at 0x%08X)" % (fentry, fname, from_addr.getOffset()))
        count += 1
    write("  [%s] %d refs shown" % (label, count))

# ======================================================================
write("=" * 70)
write("THREAD SYNCHRONIZATION POINTS")
write("=" * 70)

write("")
write("# PART 1: PDD locks (protect deferred destruction queues)")
write("")
write("PDD BlockingLock:")
decompile_at(0x00867F50, "PDD_BlockingLock", max_len=3000)
write("")
write("PDD TryLock:")
decompile_at(0x00867F70, "PDD_TryLock", max_len=3000)

write("")
write("Callers of PDD BlockingLock:")
find_xrefs_to(0x00867F50, "PDD_BlockingLock", limit=10)
write("")
write("Callers of PDD TryLock:")
find_xrefs_to(0x00867F70, "PDD_TryLock", limit=10)

write("")
write("# PART 2: hkWorld Lock/Unlock (Havok physics sync)")
write("")
decompile_at(0x00C3E310, "hkWorld_Lock", max_len=3000)
write("")
decompile_at(0x00C3E340, "hkWorld_Unlock", max_len=3000)

write("")
write("# PART 3: HavokStopStart (stop sim + drain AI)")
write("")
decompile_at(0x008324E0, "HavokStopStart", max_len=6000)

write("")
write("# PART 4: AI Start/Join")
write("")
decompile_at(0x008C78C0, "AI_Start", max_len=4000)
write("")
decompile_at(0x008C7990, "AI_Join", max_len=4000)

write("")
write("# PART 5: Async queue flush (blocking IO drain)")
write("")
decompile_at(0x00C459D0, "AsyncFlush", max_len=6000)

write("")
write("# PART 6: IOManager main-thread processing")
write("")
decompile_at(0x00C3DBF0, "IOManager_MainThread", max_len=6000)

write("")
write("# PART 7: Key global flags for thread coordination")
write("")

globals_info = [
    (0x011DFA19, "AI_Active_Flag"),
    (0x011DEA2B, "Loading_Flag"),
    (0x01202D6C, "Loading_State_Counter"),
]

for addr_int, desc in globals_info:
    write("%s (0x%08X):" % (desc, addr_int))
    find_xrefs_to(addr_int, desc, limit=10)
    write("")

# ======================================================================
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/thread_sync_points.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
