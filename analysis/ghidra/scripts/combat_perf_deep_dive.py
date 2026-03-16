# Ghidra Jython Script: Combat Performance Deep Dive
# Run in Ghidra's Script Manager on FalloutNV.exe
#
# Second-pass analysis targeting specific functions identified in combat_perf_analysis:
# 1. Per-frame actor/AI processor FUN_009777a0
# 2. Cell update functions FUN_0096eb40 / FUN_0096e9b0
# 3. Multi-CPU scene processing FUN_008c80e0 / FUN_008ca070
# 4. Thread pool barrier FUN_008c7da0 / FUN_008c7f50
# 5. Decal manager functions (string xrefs)
# 6. HAVOK physics timing (fMaxTime:HAVOK xrefs)
# 7. Impact sound limiter (DiMaxImpactSoundCount xrefs)
# 8. AI complexity limiter iAINumberActorsComplexScene
# 9. Sub-functions: FUN_0086f940, FUN_0086ef30, FUN_0086ef90, FUN_0086f190
# 10. Scene rendering: FUN_00c52020, FUN_00b5ac90, FUN_00b54000

from ghidra.program.model.symbol import SymbolType
from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
refMgr = currentProgram.getReferenceManager()
symTab = currentProgram.getSymbolTable()

decomp = DecompInterface()
decomp.openProgram(currentProgram)

def decompile_func(addr_int, timeout=60):
    addr = toAddr(addr_int)
    func = fm.getFunctionContaining(addr)
    if func is None:
        return None, None
    result = decomp.decompileFunction(func, timeout, monitor)
    if result and result.decompileCompleted():
        return func, result.getDecompiledFunction().getC()
    return func, None

def find_import_refs(name):
    refs = []
    for sym in symTab.getSymbols(name):
        for ref in refMgr.getReferencesTo(sym.getAddress()):
            caller = fm.getFunctionContaining(ref.getFromAddress())
            refs.append((ref.getFromAddress(), caller))
    return refs

def find_callers(addr_int):
    addr = toAddr(addr_int)
    func = fm.getFunctionContaining(addr)
    if func is None:
        return []
    callers = []
    for ref in refMgr.getReferencesTo(func.getEntryPoint()):
        caller = fm.getFunctionContaining(ref.getFromAddress())
        if caller:
            callers.append((ref.getFromAddress(), caller))
    return callers

def find_callees(addr_int):
    addr = toAddr(addr_int)
    func = fm.getFunctionContaining(addr)
    if func is None:
        return []
    callees = []
    body = func.getBody()
    inst_iter = listing.getInstructions(body, True)
    while inst_iter.hasNext():
        inst = inst_iter.next()
        if inst.getMnemonicString() == "CALL":
            for ref in inst.getReferencesFrom():
                target = fm.getFunctionAt(ref.getToAddress())
                if target:
                    callees.append((inst.getAddress(), target))
    return callees

def find_string_xrefs(string_addr_int):
    """Find all functions that reference a string at the given address."""
    addr = toAddr(string_addr_int)
    results = []
    for ref in refMgr.getReferencesTo(addr):
        caller = fm.getFunctionContaining(ref.getFromAddress())
        if caller:
            results.append((ref.getFromAddress(), caller))
    return results

def decompile_and_output(addr_int, label, max_chars=5000, timeout=60):
    """Decompile function and add to output with label."""
    func, code = decompile_func(addr_int, timeout)
    if func and code:
        output.append("\n  --- {} @ 0x{:08x} (size: {} bytes) ---".format(
            label or func.getName(), addr_int,
            func.getBody().getNumAddresses()))
        # Callers
        callers = find_callers(addr_int)
        if callers:
            output.append("  Called by:")
            for call_addr, caller in callers[:8]:
                output.append("    {} @ 0x{:08x} (from 0x{:08x})".format(
                    caller.getName(), caller.getEntryPoint().getOffset(),
                    call_addr.getOffset()))
        # Code
        output.append(code[:max_chars])
        if len(code) > max_chars:
            output.append("  ... [truncated at {} chars, total {} chars]".format(max_chars, len(code)))
        return True
    else:
        output.append("\n  --- {} @ 0x{:08x} ---".format(label or "unknown", addr_int))
        output.append("  [Could not decompile]")
        return False


output = []
output.append("=" * 70)
output.append("=== COMBAT PERFORMANCE DEEP DIVE ===")
output.append("=" * 70)

# =====================================================================
# 1. Per-frame actor/AI process update
# =====================================================================
output.append("\n\n=== 1. PER-FRAME ACTOR PROCESS UPDATE ===\n")
decompile_and_output(0x009777a0, "ActorProcessUpdate", 8000, 120)

output.append("\n  --- Callees ---")
for call_addr, target in find_callees(0x009777a0):
    output.append("    @ {} -> {} (0x{:08x})".format(
        call_addr, target.getName(), target.getEntryPoint().getOffset()))

# =====================================================================
# 2. Cell update functions
# =====================================================================
output.append("\n\n=== 2. CELL UPDATE FUNCTIONS ===\n")
decompile_and_output(0x0096eb40, "CellUpdate1", 6000, 120)
decompile_and_output(0x0096e9b0, "CellUpdate2", 6000, 120)

# =====================================================================
# 3. Multi-CPU scene processing
# =====================================================================
output.append("\n\n=== 3. MULTI-CPU SCENE PROCESSING ===\n")
decompile_and_output(0x008c80e0, "SceneProcess_MultiCPU", 6000, 120)
decompile_and_output(0x008ca070, "SceneProcess_SingleCPU", 6000, 120)
decompile_and_output(0x008ca300, "SceneProcess2_SingleCPU", 6000, 120)
decompile_and_output(0x008c7990, "SceneProcess2_MultiCPU", 6000, 120)

# =====================================================================
# 4. Thread pool barrier and worker functions
# =====================================================================
output.append("\n\n=== 4. THREAD POOL BARRIER ===\n")
decompile_and_output(0x008c7da0, "ThreadPoolBarrier", 6000)
decompile_and_output(0x008c7f50, "ThreadPoolDispatch", 6000)
decompile_and_output(0x008c78c0, "ThreadPoolKick", 4000)
decompile_and_output(0x008c74b0, "ThreadPoolRelated", 4000)

# =====================================================================
# 5. Decal manager - find the actual processing functions
# =====================================================================
output.append("\n\n=== 5. DECAL MANAGER FUNCTIONS ===\n")

# Find functions referencing decal limit strings
decal_strings = {
    "iMaxDecalsPerFrame": 0x0101e5c0,
    "iMaxSkinDecalsPerFrame": 0x0101e5dc,
    "uMaxDecals": 0x0101e5fc,
    "DECAL: Reached max non-skinned": 0x0101e490,
    "DECAL: Reached max skinned": 0x0101e528,
    "AddGeometryDecalRecurse: Ticks": 0x0101e370,
    "Decal Node": 0x0101e484,
}

for name, addr in decal_strings.items():
    xrefs = find_string_xrefs(addr)
    if xrefs:
        output.append("\n  String '{}' @ 0x{:08x} referenced by:".format(name, addr))
        for ref_addr, caller in xrefs:
            output.append("    {} @ 0x{:08x}".format(
                caller.getName(), caller.getEntryPoint().getOffset()))
            # Decompile the function that checks the decal limit
            if "Reached max" in name or "iMax" in name:
                decompile_and_output(caller.getEntryPoint().getOffset(),
                    "DecalLimit_" + caller.getName(), 4000)

# =====================================================================
# 6. HAVOK physics timing
# =====================================================================
output.append("\n\n=== 6. HAVOK PHYSICS TIMING ===\n")

# fMaxTime:HAVOK string at 0x010c42d8
havok_xrefs = find_string_xrefs(0x010c42d8)
output.append("  fMaxTime:HAVOK referenced by:")
for ref_addr, caller in havok_xrefs:
    output.append("    {} @ 0x{:08x}".format(
        caller.getName(), caller.getEntryPoint().getOffset()))
    decompile_and_output(caller.getEntryPoint().getOffset(),
        "HAVOK_MaxTime_" + caller.getName(), 5000)

# =====================================================================
# 7. Impact sound limiter
# =====================================================================
output.append("\n\n=== 7. IMPACT SOUND LIMITER ===\n")

# DiMaxImpactSoundCount:Audio at 0x0107d9a3
sound_xrefs = find_string_xrefs(0x0107d9a3)
output.append("  DiMaxImpactSoundCount:Audio referenced by:")
for ref_addr, caller in sound_xrefs:
    output.append("    {} @ 0x{:08x}".format(
        caller.getName(), caller.getEntryPoint().getOffset()))
    decompile_and_output(caller.getEntryPoint().getOffset(),
        "ImpactSound_" + caller.getName(), 4000)

# =====================================================================
# 8. AI complexity limiter
# =====================================================================
output.append("\n\n=== 8. AI COMPLEXITY LIMITER ===\n")

# iAINumberActorsComplexScene at 0x01050a30
ai_xrefs = find_string_xrefs(0x01050a30)
output.append("  iAINumberActorsComplexScene referenced by:")
for ref_addr, caller in ai_xrefs:
    output.append("    {} @ 0x{:08x}".format(
        caller.getName(), caller.getEntryPoint().getOffset()))
    decompile_and_output(caller.getEntryPoint().getOffset(),
        "AIComplexity_" + caller.getName(), 5000)

# =====================================================================
# 9. Frame update sub-functions
# =====================================================================
output.append("\n\n=== 9. FRAME UPDATE SUB-FUNCTIONS ===\n")

frame_subs = [
    (0x0086f940, "FrameSetup"),
    (0x0086ef30, "FrameSub1"),
    (0x0086ef90, "FrameSub2"),
    (0x0086f190, "FrameSub3"),
    (0x0086efe0, "FrameSub_PostQueue"),
    (0x0086f450, "FrameSub_PostIO"),
    (0x0086fbe0, "FrameSub_PreScene"),
    (0x0086fc60, "FrameSub_PostScene"),
    (0x0086f6a0, "FrameSub_PostScene2"),
    (0x00978550, "ProcessDataUpdate"),
    (0x008d0600, "MultiCPU_ExtraStep"),
]

for addr, label in frame_subs:
    decompile_and_output(addr, label, 4000)

# =====================================================================
# 10. Render/scene functions called during frame
# =====================================================================
output.append("\n\n=== 10. RENDER / SCENE FUNCTIONS ===\n")

render_funcs = [
    (0x00c52020, "SceneRender"),
    (0x00b5ac90, "RenderSubmit"),
    (0x00b54000, "RenderRelated"),
    (0x00950090, "PostUpdate"),
    (0x00868850, "FrameFunc_868850"),
    (0x00868d10, "FrameFunc_868d10"),
]

for addr, label in render_funcs:
    decompile_and_output(addr, label, 4000)

# =====================================================================
# 11. FUN_0086f260 and FUN_0086f390 - called every frame before cell processing
# =====================================================================
output.append("\n\n=== 11. PRE-CELL-PROCESSING FUNCTIONS ===\n")
decompile_and_output(0x0086f260, "PreCellProcess1", 4000)
decompile_and_output(0x0086f390, "PreCellProcess2", 4000)

# =====================================================================
# OUTPUT
# =====================================================================
output_text = "\n".join(output)
fout = open("/tmp/combat_perf_deep_dive.txt", "w")
fout.write(output_text)
fout.close()

print("=== Combat Performance Deep Dive complete! ===")
print("=== Output: /tmp/combat_perf_deep_dive.txt ===")
print("=== Length: {} chars ({} lines) ===".format(len(output_text), len(output)))

decomp.dispose()
