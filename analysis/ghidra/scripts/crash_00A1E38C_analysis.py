# Ghidra Jython Script: Crash at 0x00A1E38C (shader creation)
# @category Analysis
# @description Analyze shader creation crash (EAX=0, BSShader)

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
    output.append("  Function: %s @ 0x%08x (%d bytes, offset +0x%X)" % (
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
    if len(code) < 6000:
        output.append("  Decompiled:")
        output.append(code)
    else:
        output.append("  Decompiled (first 6000 chars):")
        output.append(code[:6000])
        output.append("  ... [truncated, total %d]" % len(code))
    output.append("  Called by:")
    for ref in refMgr.getReferencesTo(cfunc.getEntryPoint()):
        c = fm.getFunctionContaining(ref.getFromAddress())
        if c is not None:
            output.append("    %s @ 0x%08x (from 0x%08x)" % (
                c.getName(), c.getEntryPoint().getOffset(), ref.getFromAddress().getOffset()))
    lim = min(sz, 32)
    bstr = []
    for i in range(lim):
        b = getByte(toAddr(centry + i)) & 0xFF
        bstr.append("%02X" % b)
    output.append("  Raw bytes: " + " ".join(bstr))

output.append("=" * 70)
output.append("=== CRASH ANALYSIS: 0x00A1E38C (shader creation, EAX=0) ===")
output.append("=" * 70)

chain = [
    (0x00A1E38C, "CRASH SITE"),
    (0x00B74005, "Original caller (BSShader::CreateVertexShader)"),
]

for addr, label in chain:
    analyze_addr(addr, label)

# Also look for shader-related strings near these functions
output.append("\n\n=== SHADER-RELATED SYMBOLS ===")
shader_patterns = ["BSShader", "NiShader", "Shader", "Vertex", "D3DX", "CreateVertex"]
for sym in currentProgram.getSymbolTable().getDefinedSymbols():
    nm = sym.getName()
    for pat in shader_patterns:
        if pat.lower() in nm.lower():
            output.append("  %s @ %s" % (nm, sym.getAddress()))
            break

output_text = "\n".join(output)
fout = open("/tmp/crash_00A1E38C_analysis.txt", "w")
fout.write(output_text)
fout.close()

print("=== Done! /tmp/crash_00A1E38C_analysis.txt ===")
print("=== %d chars, %d lines ===" % (len(output_text), len(output)))

decomp.dispose()
