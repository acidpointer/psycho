# Ghidra Jython Script: Crash at 0x00A6DF48 Analysis
# @category Analysis
# @description Analyze HAVOK physics crash during NPC ragdoll loading

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
    off = addr - centry
    sz = cfunc.getBody().getNumAddresses()
    output.append("  Function: %s @ 0x%08x (%d bytes, crash at +0x%X)" % (
        cfunc.getName(), centry, sz, off))
    start = addr - 20
    if start < centry:
        start = centry
    output.append("  Disassembly:")
    output.append(disasm_at(start, 15))
    dummy, code = decompile_func(centry, 90)
    if code is None:
        output.append("  [decompile failed]")
        return
    if len(code) < 5000:
        output.append("  Decompiled:")
        output.append(code)
    else:
        output.append("  Decompiled (first 5000 chars):")
        output.append(code[:5000])
        output.append("  ... [truncated, total %d]" % len(code))
    # callers
    output.append("  Called by:")
    for ref in refMgr.getReferencesTo(cfunc.getEntryPoint()):
        c = fm.getFunctionContaining(ref.getFromAddress())
        if c is not None:
            output.append("    %s @ 0x%08x (from 0x%08x)" % (
                c.getName(), c.getEntryPoint().getOffset(), ref.getFromAddress().getOffset()))
    # raw bytes (first 32)
    lim = min(sz, 32)
    bstr = []
    for i in range(lim):
        b = getByte(toAddr(centry + i)) & 0xFF
        bstr.append("%02X" % b)
    output.append("  Raw bytes: " + " ".join(bstr))

output.append("=" * 70)
output.append("=== CRASH ANALYSIS: 0x00A6DF48 (HAVOK physics / ragdoll) ===")
output.append("=" * 70)

# Full crash chain
chain = [
    (0x00A6DF48, "CRASH SITE"),
    (0x00C796F7, "HAVOK integration 1"),
    (0x00C7D866, "HAVOK integration 2"),
    (0x00931443, "Actor/NPC processing"),
    (0x0056F8D4, "Reference processing"),
    (0x0045211D, "Queue dispatch"),
    (0x00C3DD8E, "Queued ref processor (FUN_00C3DBF0)"),
    (0x0086E89C, "Per-frame update (FUN_0086E650)"),
    (0x0086B3E8, "Main game loop"),
]

output.append("\n=== CRASH CHAIN ===")
for addr, label in chain:
    analyze_addr(addr, label)

output.append("\n\n=== HAVOK-RELATED SYMBOLS ===")
havok_patterns = ["bhk", "hkp", "Havok", "Ragdoll", "hkWorld", "hkRigidBody"]
for sym in currentProgram.getSymbolTable().getDefinedSymbols():
    nm = sym.getName()
    for pat in havok_patterns:
        if pat.lower() in nm.lower():
            output.append("  %s @ %s" % (nm, sym.getAddress()))
            break

output_text = "\n".join(output)
fout = open("/tmp/crash_00A6DF48_analysis.txt", "w")
fout.write(output_text)
fout.close()

print("=== Done! /tmp/crash_00A6DF48_analysis.txt ===")
print("=== %d chars, %d lines ===" % (len(output_text), len(output)))

decomp.dispose()
