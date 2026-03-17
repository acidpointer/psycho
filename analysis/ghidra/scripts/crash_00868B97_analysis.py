# Ghidra Jython Script: Crash at 0x00868B97
# @category Analysis
# @description Analyze queue processor crash with unloaded cell reference

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
refMgr = currentProgram.getReferenceManager()

decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def decompile_func(addr_int, timeout=60):
    addr = toAddr(addr_int)
    func = fm.getFunctionContaining(addr)
    if func is None:
        return None, None
    result = decomp.decompileFunction(func, timeout, monitor)
    if result and result.decompileCompleted():
        return func, result.getDecompiledFunction().getC()
    return func, None

def disasm_at(addr_int, count=20):
    lines = []
    addr = toAddr(addr_int)
    for i in range(count):
        inst = listing.getInstructionAt(addr)
        if inst is None:
            lines.append("  0x%08x: [no instruction]" % addr.getOffset())
            break
        lines.append("  0x%08x: %s" % (addr.getOffset(), inst.toString()))
        nxt = inst.getNext()
        if nxt is None:
            break
        addr = nxt.getAddress()
    return "\n".join(lines)

def analyze_addr(addr, label):
    output.append("\n--- %s: 0x%08x ---" % (label, addr))
    cfunc = fm.getFunctionContaining(toAddr(addr))
    if cfunc is None:
        output.append("  [no function found]")
        return
    centry = cfunc.getEntryPoint().getOffset()
    sz = cfunc.getBody().getNumAddresses()
    output.append("  Function: %s @ 0x%08x (%d bytes)" % (cfunc.getName(), centry, sz))
    start = addr - 20
    if start < centry:
        start = centry
    output.append("  Disassembly around crash:")
    output.append(disasm_at(start, 20))
    dummy, code = decompile_func(centry, 120)
    if code is not None:
        if len(code) < 8000:
            output.append("  Decompiled:")
            output.append(code)
        else:
            output.append("  Decompiled (first 8000):")
            output.append(code[:8000])

output.append("=" * 70)
output.append("=== CRASH: 0x00868B97 (queue processor, unloaded cell ref) ===")
output.append("=" * 70)

analyze_addr(0x00868B97, "CRASH SITE")
analyze_addr(0x0086EAE4, "CALLER (per-frame update)")

output_text = "\n".join(output)
fout = open("/tmp/crash_00868B97_analysis.txt", "w")
fout.write(output_text)
fout.close()

print("=== Done! /tmp/crash_00868B97_analysis.txt ===")
print("=== %d chars, %d lines ===" % (len(output_text), len(output)))

decomp.dispose()
