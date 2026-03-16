# Ghidra Jython Script: Crash at 0x0040FE96 Analysis
# @category Analysis
# @description Analyze crash at 0x0040FE96 (ECX=2, ACCESS_VIOLATION)

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

def analyze_crash_site():
    output.append("\n\n=== 1. CRASH SITE: 0x0040FE96 ===\n")
    output.append("--- Disassembly (0x0040FE80 - 0x0040FF20) ---")
    output.append(disasm_at(0x0040FE80, 30))
    func = fm.getFunctionContaining(toAddr(0x0040FE96))
    if func is None:
        output.append("  [No function found at crash address]")
        return
    entry = func.getEntryPoint().getOffset()
    sz = func.getBody().getNumAddresses()
    output.append("\n--- Function: %s @ 0x%08x (%d bytes) ---" % (func.getName(), entry, sz))
    dummy, code = decompile_func(entry, 120)
    if code is not None:
        output.append(code[:6000])
    # callers
    output.append("\n--- Called by: ---")
    for ref in refMgr.getReferencesTo(func.getEntryPoint()):
        c = fm.getFunctionContaining(ref.getFromAddress())
        if c is not None:
            output.append("  %s @ 0x%08x" % (c.getName(), c.getEntryPoint().getOffset()))
    # raw bytes
    output.append("\n--- Raw bytes (first 64): ---")
    bstr = []
    lim = min(sz, 64)
    for i in range(lim):
        b = getByte(toAddr(entry + i)) & 0xFF
        bstr.append("%02X" % b)
    output.append("  " + " ".join(bstr))

def analyze_caller():
    output.append("\n\n=== 2. IMMEDIATE CALLER: 0x004182C3 ===\n")
    output.append(disasm_at(0x004182B0, 15))
    func2 = fm.getFunctionContaining(toAddr(0x004182C3))
    if func2 is None:
        output.append("  [No function found]")
        return
    entry2 = func2.getEntryPoint().getOffset()
    output.append("\n--- Function: %s @ 0x%08x ---" % (func2.getName(), entry2))
    dummy, code = decompile_func(entry2, 120)
    if code is not None:
        output.append(code[:5000])

def analyze_chain_entry(addr):
    cfunc = fm.getFunctionContaining(toAddr(addr))
    if cfunc is None:
        output.append("\n--- 0x%08x: [no function found] ---" % addr)
        return
    centry = cfunc.getEntryPoint().getOffset()
    off = addr - centry
    output.append("\n--- 0x%08x in %s (entry 0x%08x +0x%X) ---" % (addr, cfunc.getName(), centry, off))
    start = addr - 16
    if start < centry:
        start = centry
    output.append(disasm_at(start, 10))
    dummy, code = decompile_func(centry, 60)
    if code is None:
        return
    if len(code) < 4000:
        output.append(code)
    else:
        output.append(code[:4000])
        output.append("  ... [truncated, total %d]" % len(code))

def analyze_chain():
    output.append("\n\n=== 3. FULL CRASH CHAIN ===\n")
    chain = [
        0x0040FE96, 0x004182C3, 0x00569156, 0x005691A6,
        0x005CC178, 0x005E234B, 0x005E101F, 0x005E265B,
        0x005AC29A, 0x00913550, 0x0090AC00, 0x008933BB,
        0x00970ECC,
    ]
    for addr in chain:
        analyze_chain_entry(addr)

def analyze_guard_xref():
    output.append("\n\n=== 4. NULL GUARD CROSS-REFERENCE ===\n")
    guard = fm.getFunctionAt(toAddr(0x0044DDC0))
    if guard is None:
        output.append("  [0x0044DDC0 not found]")
        return
    output.append("Checking if crash chain calls our patched 0x0044DDC0:")
    guard_callers = []
    for ref in refMgr.getReferencesTo(guard.getEntryPoint()):
        c = fm.getFunctionContaining(ref.getFromAddress())
        if c is not None:
            guard_callers.append(c.getEntryPoint().getOffset())
    chain = [
        0x0040FE96, 0x004182C3, 0x00569156, 0x005691A6,
        0x005CC178, 0x005E234B, 0x005E101F, 0x005E265B,
        0x005AC29A, 0x00913550, 0x0090AC00, 0x008933BB,
        0x00970ECC,
    ]
    chain_entries = []
    for addr in chain:
        f = fm.getFunctionContaining(toAddr(addr))
        if f is not None:
            chain_entries.append(f.getEntryPoint().getOffset())
    found = False
    for ge in guard_callers:
        if ge in chain_entries:
            output.append("  MATCH: 0x%08x calls 0x0044DDC0 AND is in crash chain" % ge)
            found = True
    if not found:
        output.append("  No overlap")
    output.append("\n  All callers of 0x0044DDC0:")
    for ge in guard_callers:
        f = fm.getFunctionAt(toAddr(ge))
        nm = "unknown"
        if f is not None:
            nm = f.getName()
        output.append("    %s @ 0x%08x" % (nm, ge))

# === MAIN ===
output.append("=" * 70)
output.append("=== CRASH ANALYSIS: 0x0040FE96 (ECX=2, ACCESS_VIOLATION) ===")
output.append("=" * 70)

analyze_crash_site()
analyze_caller()
analyze_chain()
analyze_guard_xref()

output_text = "\n".join(output)
fout = open("/tmp/crash_0040FE96_analysis.txt", "w")
fout.write(output_text)
fout.close()

print("=== Done! /tmp/crash_0040FE96_analysis.txt ===")
print("=== %d chars, %d lines ===" % (len(output_text), len(output)))

decomp.dispose()
