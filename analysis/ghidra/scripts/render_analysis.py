# Ghidra Jython Script: Render Path & Frame Timing Analysis for FNV
# Run in Ghidra's Script Manager on FalloutNV.exe
#
# Investigates:
# 1. Main game loop structure (WinMain @ 0x0086a850)
# 2. Frame limiter / present calls
# 3. DirectX draw call submission
# 4. Scene graph traversal / culling
# 5. Fog / weather computation
# 6. Actor update loops
# 7. Any spin-waits or busy-loops in the render path

from ghidra.program.model.symbol import SymbolType
from ghidra.app.decompiler import DecompInterface
import re

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
refMgr = currentProgram.getReferenceManager()
symTab = currentProgram.getSymbolTable()

# Setup decompiler
decomp = DecompInterface()
decomp.openProgram(currentProgram)

def decompile_func(addr_int):
    """Decompile function at address, return C string."""
    addr = toAddr(addr_int)
    func = fm.getFunctionContaining(addr)
    if func is None:
        return None, None
    result = decomp.decompileFunction(func, 30, monitor)
    if result and result.decompileCompleted():
        return func, result.getDecompiledFunction().getC()
    return func, None

def find_import_refs(name):
    """Find all references to an imported function by name."""
    refs = []
    for sym in symTab.getSymbols(name):
        for ref in refMgr.getReferencesTo(sym.getAddress()):
            caller = fm.getFunctionContaining(ref.getFromAddress())
            refs.append((ref.getFromAddress(), caller))
    return refs

output = []
output.append("=" * 70)
output.append("=== RENDER PATH & FRAME TIMING ANALYSIS ===")
output.append("=" * 70)

# =====================================================================
# 1. Main game loop (WinMain)
# =====================================================================
output.append("\n\n=== 1. MAIN GAME LOOP (WinMain @ 0x0086a850) ===\n")
func, code = decompile_func(0x0086a850)
if code:
    output.append(code[:6000])  # First 6000 chars
else:
    output.append("  [Could not decompile WinMain]")

# =====================================================================
# 2. DirectX Present / EndScene / frame submission
# =====================================================================
output.append("\n\n=== 2. DirectX Present / EndScene / Frame Submission ===\n")

# Search for IDirect3DDevice9 vtable calls (Present = vtable[17], EndScene = vtable[42])
# Also look for common frame-related imports
dx_funcs = ["Present", "EndScene", "BeginScene", "DrawIndexedPrimitive",
            "DrawPrimitive", "SetRenderState", "SetTexture",
            "Direct3DCreate9", "CreateDevice"]

for name in dx_funcs:
    refs = find_import_refs(name)
    if refs:
        output.append("  {} : {} call sites".format(name, len(refs)))
        for addr, caller in refs[:5]:
            cname = caller.getName() if caller else "unknown"
            output.append("    @ {} (in {})".format(addr, cname))

# =====================================================================
# 3. Known Gamebryo/NiNode render functions
# =====================================================================
output.append("\n\n=== 3. Scene Graph / NiNode Functions ===\n")

# Search for functions with known Gamebryo names
ni_patterns = ["NiNode", "NiCamera", "NiFrustum", "NiCull", "NiRender",
               "BSFadeNode", "NiAccumulator", "NiVisibleArray",
               "BSShader", "NiGeometry", "BSBatch", "NiAlphaAccumulator"]

for pattern in ni_patterns:
    count = 0
    matches = []
    for sym in symTab.getDefinedSymbols():
        if pattern.lower() in sym.getName().lower():
            count += 1
            if count <= 5:
                matches.append("    {} @ {}".format(sym.getName(), sym.getAddress()))
    if count > 0:
        output.append("  {} matches for '{}':".format(count, pattern))
        for m in matches:
            output.append(m)
        if count > 5:
            output.append("    ... and {} more".format(count - 5))

# =====================================================================
# 4. Functions that call both QPC and Sleep (frame limiters)
# =====================================================================
output.append("\n\n=== 4. Frame Limiter Candidates (QPC + Sleep in same function) ===\n")

qpc_refs = find_import_refs("QueryPerformanceCounter")
sleep_refs = find_import_refs("Sleep")

qpc_funcs = set()
for addr, caller in qpc_refs:
    if caller:
        qpc_funcs.add(caller.getEntryPoint().getOffset())

sleep_funcs = set()
for addr, caller in sleep_refs:
    if caller:
        sleep_funcs.add(caller.getEntryPoint().getOffset())

frame_limiter_candidates = qpc_funcs & sleep_funcs
output.append("  Functions with both QPC and Sleep: {}".format(len(frame_limiter_candidates)))
for addr_int in sorted(frame_limiter_candidates):
    func, code = decompile_func(addr_int)
    fname = func.getName() if func else "unknown"
    output.append("\n  --- {} @ 0x{:08x} ---".format(fname, addr_int))
    if code and len(code) < 4000:
        output.append(code)
    elif code:
        output.append(code[:4000])
        output.append("  ... [truncated]")

# =====================================================================
# 5. Fog / Weather update functions
# =====================================================================
output.append("\n\n=== 5. Fog / Weather Functions ===\n")

fog_patterns = ["fog", "weather", "Fog", "Weather", "TESWeather", "Sky"]
for pattern in fog_patterns:
    count = 0
    matches = []
    for sym in symTab.getDefinedSymbols():
        if pattern in sym.getName():
            count += 1
            if count <= 3:
                matches.append("    {} @ {}".format(sym.getName(), sym.getAddress()))
    if count > 0:
        output.append("  {} matches for '{}':".format(count, pattern))
        for m in matches:
            output.append(m)

# =====================================================================
# 6. Key QPC timing functions (decompiled)
# =====================================================================
output.append("\n\n=== 6. QPC Timing Functions (potential frame pacing) ===\n")

# Decompile functions that use QPC but NOT Sleep (pure timing functions)
qpc_only = qpc_funcs - sleep_funcs
output.append("  QPC-only functions (no Sleep): {}".format(len(qpc_only)))
for addr_int in sorted(qpc_only):
    func, code = decompile_func(addr_int)
    fname = func.getName() if func else "unknown"
    output.append("\n  --- {} @ 0x{:08x} ---".format(fname, addr_int))
    if code and len(code) < 3000:
        output.append(code)
    elif code:
        output.append(code[:3000])
        output.append("  ... [truncated]")

# =====================================================================
# 7. GetTickCount usage in potential hot paths
# =====================================================================
output.append("\n\n=== 7. GetTickCount Hot Path Usage ===\n")

gtc_refs = find_import_refs("GetTickCount")
output.append("  Total GetTickCount call sites: {}".format(len(gtc_refs)))

# Find functions that call GetTickCount frequently (multiple times = likely timing loop)
gtc_func_count = {}
for addr, caller in gtc_refs:
    if caller:
        key = caller.getEntryPoint().getOffset()
        gtc_func_count[key] = gtc_func_count.get(key, 0) + 1

multi_gtc = {k: v for k, v in gtc_func_count.items() if v >= 2}
output.append("  Functions with 2+ GetTickCount calls (timing loops): {}".format(len(multi_gtc)))
for addr_int, count in sorted(multi_gtc.items(), key=lambda x: -x[1]):
    func, code = decompile_func(addr_int)
    fname = func.getName() if func else "unknown"
    output.append("\n  --- {} @ 0x{:08x} ({} calls) ---".format(fname, addr_int, count))
    if code and len(code) < 3000:
        output.append(code)
    elif code:
        output.append(code[:3000])
        output.append("  ... [truncated]")

# =====================================================================
# 8. Potential per-frame actor/object update loops
# =====================================================================
output.append("\n\n=== 8. Actor / Object Update Functions ===\n")

actor_patterns = ["Actor", "Character", "Update", "Process", "AIProcess"]
for pattern in actor_patterns:
    count = 0
    for sym in symTab.getDefinedSymbols():
        if pattern in sym.getName() and sym.getSymbolType() == SymbolType.FUNCTION:
            count += 1
    if count > 0:
        output.append("  {} function symbols matching '{}'".format(count, pattern))

# =====================================================================
# 9. SuspendThread / ResumeThread (thread management)
# =====================================================================
output.append("\n\n=== 9. Thread Management ===\n")

thread_funcs = ["CreateThread", "SuspendThread", "ResumeThread",
                "SetThreadPriority", "SetThreadAffinityMask",
                "WaitForSingleObject", "WaitForMultipleObjects"]
for name in thread_funcs:
    refs = find_import_refs(name)
    if refs:
        output.append("  {} : {} call sites".format(name, len(refs)))
        for addr, caller in refs[:3]:
            cname = caller.getName() if caller else "unknown"
            output.append("    @ {} (in {})".format(addr, cname))

# =====================================================================
# 10. Decompile WaitForSingleObject callers (potential stalls)
# =====================================================================
output.append("\n\n=== 10. WaitForSingleObject Callers (potential render stalls) ===\n")

wfso_refs = find_import_refs("WaitForSingleObject")
output.append("  Total WaitForSingleObject sites: {}".format(len(wfso_refs)))
for addr, caller in wfso_refs[:10]:
    if caller:
        fname = caller.getName()
        addr_int = caller.getEntryPoint().getOffset()
        _, code = decompile_func(addr_int)
        output.append("\n  --- {} @ 0x{:08x} ---".format(fname, addr_int))
        if code and len(code) < 2000:
            output.append(code)
        elif code:
            output.append(code[:2000])
            output.append("  ... [truncated]")

# Write output
output_text = "\n".join(output)
f = java.io.File(currentProgram.getExecutablePath()).getParentFile()
outpath = java.io.File(f, "render_analysis.txt").getAbsolutePath()

# Also try writing to the analysis dir
try:
    import os
    script_dir = os.path.dirname(os.path.abspath(sourceFile.getAbsolutePath()))
except:
    pass

fout = open("/tmp/render_analysis.txt", "w")
fout.write(output_text)
fout.close()

print("=== Analysis complete! Output written to /tmp/render_analysis.txt ===")
print("=== Output length: {} chars ===".format(len(output_text)))

decomp.dispose()
