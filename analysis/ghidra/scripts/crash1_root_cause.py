# Ghidra Jython Script: Root cause analysis for crash at 0x0040FE96
# @category Analysis
# @description Analyze FUN_00410220 (calls both 0x0044DDC0 and 0x0040FE80)
#              and FUN_005d43c0 (returns garbage pointer value 2)

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
    output.append("  Disassembly (full):")
    output.append(disasm_at(centry, 80))
    dummy, code = decompile_func(centry, 120)
    if code is not None:
        output.append("  Decompiled:")
        output.append(code[:8000])
    output.append("  Called by:")
    for ref in refMgr.getReferencesTo(cfunc.getEntryPoint()):
        c = fm.getFunctionContaining(ref.getFromAddress())
        if c is not None:
            output.append("    %s @ 0x%08x (from 0x%08x)" % (
                c.getName(), c.getEntryPoint().getOffset(), ref.getFromAddress().getOffset()))

output.append("=" * 70)
output.append("=== ROOT CAUSE: crash 0x0040FE96 ===")
output.append("=== Key question: does our guard at 0x0044DDC0 cause this? ===")
output.append("=" * 70)

# FUN_00410220 - calls BOTH 0x0044DDC0 (our guard) and 0x0040FE80 (crash)
analyze_addr(0x00410220, "FUN_00410220 (calls both guarded and crash funcs)")

# FUN_005d43c0 - returns garbage value 2 for unloaded references
analyze_addr(0x005d43c0, "FUN_005d43c0 (returns garbage 3D pointer)")

# FUN_00569140 - calls 005d43c0 then passes result to 004182b0
analyze_addr(0x00569140, "FUN_00569140 (bridge: 005d43c0 -> 004182b0)")

# FUN_0044DDC0 - our patched function (AI path getter)
analyze_addr(0x0044DDC0, "FUN_0044DDC0 (OUR PATCHED GUARD)")

# FUN_005ac190 - called in FUN_00970d50 with the 3D data
analyze_addr(0x005ac190, "FUN_005ac190 (called with 3D data in init)")

output_text = "\n".join(output)
fout = open("/tmp/crash1_root_cause.txt", "w")
fout.write(output_text)
fout.close()

print("=== Done! /tmp/crash1_root_cause.txt ===")
print("=== %d chars, %d lines ===" % (len(output_text), len(output)))

decomp.dispose()
