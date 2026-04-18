# @category Analysis
# @description Startup crash 0x004F15B5: decompile crash function and callers.

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


# --- Main ---

write("STARTUP CRASH: 0x004F15B5 (TESAmmo write to slab)")
write("=" * 70)

# 1. Decompile crash function
decompile_at(0x004F15B5, "crash site")

# 2. Disassemble crash function
disasm_func(0x004F15B5, "crash function")

# 3. Call chain from crashlog
decompile_at(0x005030C0, "0x5030C0 (form cleanup)")
decompile_at(0x004601F0, "0x4601F0 (form destruction)")
decompile_at(0x00469331, "0x469331 (cell processing)")
decompile_at(0x00467962, "0x467962 (BSTreeNode)")
decompile_at(0x00463986, "0x463986 (form iterator)")

# 4. Callers of the form destruction function
find_callers(0x004601F0, "0x4601F0 callers")

# 5. Check 0x4F15B0 area for context
write("")
write("-" * 70)
write("Bytes around crash site")
write("-" * 70)
mem = currentProgram.getMemory()
buf = bytearray(32)
addr = toAddr(0x004F15A0)
mem.getBytes(addr, buf)
for i in range(0, 32, 16):
    hex_str = " ".join("%02x" % b for b in buf[i : i + 16])
    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in buf[i : i + 16])
    write("  0x%08x: %s  %s" % (0x4F15A0 + i, hex_str, ascii_str))

# --- Output ---
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/crash_4F15B5_decompile.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
