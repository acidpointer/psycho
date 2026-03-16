# Ghidra Jython Script: Combat Performance Analysis for FNV
# Run in Ghidra's Script Manager on FalloutNV.exe
#
# Investigates stutter causes during heavy combat:
# 1. Particle system functions (NiParticle*, BSParticle*)
# 2. Projectile processing (Projectile, Beam, Missile, etc.)
# 3. Actor/NPC AI processing during combat
# 4. Animation controller updates
# 5. Sound system processing
# 6. Per-frame object update loop (FUN_0096b050) and its callees
# 7. Main frame update function (FUN_0086e650)
# 8. Shadow / lighting processing
# 9. Additional Sleep/Wait sites not yet patched

from ghidra.program.model.symbol import SymbolType
from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
refMgr = currentProgram.getReferenceManager()
symTab = currentProgram.getSymbolTable()

decomp = DecompInterface()
decomp.openProgram(currentProgram)

def decompile_func(addr_int, timeout=60):
    """Decompile function at address, return (func, C_string)."""
    addr = toAddr(addr_int)
    func = fm.getFunctionContaining(addr)
    if func is None:
        return None, None
    result = decomp.decompileFunction(func, timeout, monitor)
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

def find_callers(addr_int):
    """Find all functions that call the function at addr_int."""
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
    """Find all functions called by the function at addr_int."""
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

def find_symbols_matching(patterns):
    """Find symbol names matching any of the given patterns (case-insensitive)."""
    results = {}
    for sym in symTab.getDefinedSymbols():
        name = sym.getName()
        name_lower = name.lower()
        for pattern in patterns:
            if pattern.lower() in name_lower:
                if pattern not in results:
                    results[pattern] = []
                results[pattern].append((name, sym.getAddress()))
                break
    return results

def find_strings_matching(patterns):
    """Find defined strings matching patterns."""
    results = []
    data_iter = listing.getDefinedData(True)
    while data_iter.hasNext():
        data = data_iter.next()
        if data.hasStringValue():
            val = data.getValue()
            if val:
                val_str = str(val)
                for pat in patterns:
                    if pat.lower() in val_str.lower():
                        results.append((data.getAddress(), val_str, pat))
                        break
    return results

output = []
output.append("=" * 70)
output.append("=== COMBAT PERFORMANCE ANALYSIS ===")
output.append("=== Targets: particle systems, projectiles, AI, animation, sound ===")
output.append("=" * 70)

# =====================================================================
# 1. PARTICLE SYSTEM SYMBOLS
# =====================================================================
output.append("\n\n=== 1. PARTICLE SYSTEM SYMBOLS & FUNCTIONS ===\n")

particle_patterns = [
    "Particle", "NiPSys", "BSParticle", "Emitter", "NiParticle",
    "BSDecal", "Decal", "Effect", "BSEffect"
]
particle_syms = find_symbols_matching(particle_patterns)
for pattern, matches in sorted(particle_syms.items()):
    output.append("  '{}' - {} matches:".format(pattern, len(matches)))
    for name, addr in matches[:10]:
        output.append("    {} @ {}".format(name, addr))
    if len(matches) > 10:
        output.append("    ... and {} more".format(len(matches) - 10))

# =====================================================================
# 2. PROJECTILE SYMBOLS & FUNCTIONS
# =====================================================================
output.append("\n\n=== 2. PROJECTILE SYMBOLS & FUNCTIONS ===\n")

projectile_patterns = [
    "Projectile", "Missile", "Beam", "Grenade", "Flame",
    "Barrier", "Explosion", "Impact"
]
proj_syms = find_symbols_matching(projectile_patterns)
for pattern, matches in sorted(proj_syms.items()):
    output.append("  '{}' - {} matches:".format(pattern, len(matches)))
    for name, addr in matches[:10]:
        output.append("    {} @ {}".format(name, addr))
    if len(matches) > 10:
        output.append("    ... and {} more".format(len(matches) - 10))

# =====================================================================
# 3. ACTOR / AI PROCESSING SYMBOLS
# =====================================================================
output.append("\n\n=== 3. ACTOR / AI PROCESSING SYMBOLS ===\n")

ai_patterns = [
    "AIProcess", "ActorProcess", "CombatController", "CombatGroup",
    "CombatTarget", "Pathfinding", "PathGrid", "NavMesh",
    "DetectionState", "Actor::Update", "HighProcess", "MiddleProcess",
    "LowProcess"
]
ai_syms = find_symbols_matching(ai_patterns)
for pattern, matches in sorted(ai_syms.items()):
    output.append("  '{}' - {} matches:".format(pattern, len(matches)))
    for name, addr in matches[:10]:
        output.append("    {} @ {}".format(name, addr))
    if len(matches) > 10:
        output.append("    ... and {} more".format(len(matches) - 10))

# =====================================================================
# 4. ANIMATION SYMBOLS
# =====================================================================
output.append("\n\n=== 4. ANIMATION SYMBOLS ===\n")

anim_patterns = [
    "AnimGroup", "NiControllerManager", "NiSequence",
    "BSAnimGroup", "AnimData", "NiInterpolator",
    "NiTimeController", "NiBlend", "BSAnimation"
]
anim_syms = find_symbols_matching(anim_patterns)
for pattern, matches in sorted(anim_syms.items()):
    output.append("  '{}' - {} matches:".format(pattern, len(matches)))
    for name, addr in matches[:10]:
        output.append("    {} @ {}".format(name, addr))
    if len(matches) > 10:
        output.append("    ... and {} more".format(len(matches) - 10))

# =====================================================================
# 5. SOUND SYSTEM SYMBOLS
# =====================================================================
output.append("\n\n=== 5. SOUND SYSTEM SYMBOLS ===\n")

sound_patterns = [
    "BSAudio", "BSSoundHandle", "BSSound", "NiAudio",
    "AudioManager", "SoundOutput"
]
sound_syms = find_symbols_matching(sound_patterns)
for pattern, matches in sorted(sound_syms.items()):
    output.append("  '{}' - {} matches:".format(pattern, len(matches)))
    for name, addr in matches[:10]:
        output.append("    {} @ {}".format(name, addr))
    if len(matches) > 10:
        output.append("    ... and {} more".format(len(matches) - 10))

# =====================================================================
# 6. SHADOW / LIGHTING SYMBOLS
# =====================================================================
output.append("\n\n=== 6. SHADOW / LIGHTING SYMBOLS ===\n")

shadow_patterns = [
    "Shadow", "NiShadow", "BSShadow", "ShadowScene",
    "NiLight", "BSLight", "Lighting"
]
shadow_syms = find_symbols_matching(shadow_patterns)
for pattern, matches in sorted(shadow_syms.items()):
    output.append("  '{}' - {} matches:".format(pattern, len(matches)))
    for name, addr in matches[:10]:
        output.append("    {} @ {}".format(name, addr))
    if len(matches) > 10:
        output.append("    ... and {} more".format(len(matches) - 10))

# =====================================================================
# 7. STRING REFERENCES - find particle/projectile/combat related strings
# =====================================================================
output.append("\n\n=== 7. COMBAT-RELATED STRING REFERENCES ===\n")

combat_string_patterns = [
    "particle", "projectile", "beam", "laser", "explosion",
    "shadow", "decal", "combat", "attack", "weapon",
    "fMaxParticle", "iMaxDecal", "fTimeBudget",
    "iMaxParticlePerFrame", "fParticle"
]
string_matches = find_strings_matching(combat_string_patterns)
output.append("  Found {} combat-related strings:".format(len(string_matches)))
for addr, val, pat in string_matches[:50]:
    output.append("    @ {} [{}]: \"{}\"".format(addr, pat, val[:80]))

# =====================================================================
# 8. DECOMPILE: Main per-frame update FUN_0086e650
# =====================================================================
output.append("\n\n=== 8. MAIN PER-FRAME UPDATE: FUN_0086e650 ===\n")
func, code = decompile_func(0x0086e650, 120)
if code:
    output.append(code[:8000])
    if len(code) > 8000:
        output.append("  ... [truncated at 8000 chars, total {} chars]".format(len(code)))
else:
    output.append("  [Could not decompile FUN_0086e650]")

# List callees of FUN_0086e650
output.append("\n  --- Callees of FUN_0086e650 ---")
callees = find_callees(0x0086e650)
for call_addr, target in callees:
    output.append("    @ {} -> {} (0x{:08x})".format(
        call_addr, target.getName(), target.getEntryPoint().getOffset()))

# =====================================================================
# 9. DECOMPILE: Cell object processor FUN_0096b050 callees
# =====================================================================
output.append("\n\n=== 9. CELL OBJECT PROCESSOR CALLEES ===\n")
output.append("  FUN_0096b050 calls these functions on each cell object:\n")

callees_96 = find_callees(0x0096b050)
for call_addr, target in callees_96:
    output.append("    @ {} -> {} (0x{:08x})".format(
        call_addr, target.getName(), target.getEntryPoint().getOffset()))

# Decompile key callees that filter/process objects
key_callees = [0x00576d30, 0x00440da0, 0x00440d80, 0x00907650, 0x007df1f0,
               0x00437bb0, 0x0045cd60, 0x00968670]
for addr in key_callees:
    func, code = decompile_func(addr)
    if func and code:
        output.append("\n  --- {} @ 0x{:08x} ---".format(func.getName(), addr))
        output.append(code[:3000])
        if len(code) > 3000:
            output.append("  ... [truncated]")

# =====================================================================
# 10. DECOMPILE: Functions with Sleep(0) that may hit during combat
# =====================================================================
output.append("\n\n=== 10. SLEEP(0) AND SLEEP(1) SITES (potential combat stalls) ===\n")

# FUN_00b02460 - task worker with Sleep(0) - already in perf_scan
# FUN_00b00ec0 - has Sleep(0)
# FUN_00c3e7d0, FUN_00c3e750 - spin-waits with Sleep(1)
# FUN_00ec29d0 - spin-wait with Sleep(1)
# FUN_00ae74b0 - infinite loop with Sleep(1)

unpatched_sleep = [0x00b00ec0, 0x00c3e7d0, 0x00c3e750, 0x00ec29d0, 0x00ae74b0, 0x00b02460]
for addr in unpatched_sleep:
    func, code = decompile_func(addr)
    if func and code:
        output.append("\n  --- {} @ 0x{:08x} ---".format(func.getName(), addr))
        output.append(code[:2000])
        if len(code) > 2000:
            output.append("  ... [truncated]")

# =====================================================================
# 11. DECOMPILE: Key functions in the combat update chain
# =====================================================================
output.append("\n\n=== 11. COMBAT UPDATE CHAIN FUNCTIONS ===\n")

# These are educated guesses based on FNV engine knowledge:
# FUN_008a8150 - appears in init, possibly ProcessManager
# FUN_00970d50 - appears in init with 0x11e0e80 (global process data)
# FUN_004614e0 - called with DAT_011c3f2c
# FUN_00830660 / FUN_00832ad0 - called during frame update in inactive->active transition

combat_funcs = [
    0x008a8150,   # ProcessManager init?
    0x00970d50,   # Process data init with global
    0x00830660,   # Frame transition func 1
    0x00832ad0,   # Frame transition func 2
    0x00866ff0,   # Called during init after AI setup
    0x0078d020,   # Called in main loop when DAT_011dea0c flag set
]

for addr in combat_funcs:
    func, code = decompile_func(addr, 60)
    if func and code:
        output.append("\n  --- {} @ 0x{:08x} ---".format(func.getName(), addr))
        output.append(code[:4000])
        if len(code) > 4000:
            output.append("  ... [truncated]")

# =====================================================================
# 12. WaitForSingleObject callers in non-I/O paths
# =====================================================================
output.append("\n\n=== 12. WaitForSingleObject IN POTENTIAL COMBAT PATHS ===\n")

# From the perf scan, these WaitForSingleObject sites are interesting:
# FUN_008c7a70 - called during multi-CPU init path
# FUN_00830b30 - large function, WaitForSingleObject at 0x0083124e
# FUN_007149b0 - unknown
# FUN_00c410b0 - has 3 WaitForSingleObject calls!

wait_funcs = [0x008c7a70, 0x00830b30, 0x007149b0, 0x00c410b0, 0x00c44b70, 0x00c44d30]
for addr in wait_funcs:
    func, code = decompile_func(addr, 60)
    if func and code:
        output.append("\n  --- {} @ 0x{:08x} ---".format(func.getName(), addr))
        # Also find who calls this
        callers = find_callers(addr)
        output.append("  Called by:")
        for call_addr, caller in callers[:5]:
            output.append("    {} (0x{:08x})".format(
                caller.getName(), caller.getEntryPoint().getOffset()))
        output.append("")
        output.append(code[:4000])
        if len(code) > 4000:
            output.append("  ... [truncated]")

# =====================================================================
# 13. INI SETTING STRINGS (game config that affects perf)
# =====================================================================
output.append("\n\n=== 13. PERFORMANCE-RELATED INI SETTINGS (strings) ===\n")

ini_patterns = [
    "fMaxParticle", "iMaxParticle", "fTimeBudget", "iMaxDecal",
    "fUpdateBudget", "iMaxSortedObject", "bActorShadow",
    "fShadow", "iShadow", "iMaxAllocatedMemory",
    "fLOD", "fBlockLoad", "fAIProcess", "iAI",
    "fMaxTime", "iMaxImpact", "fQueueBudget"
]
ini_strings = find_strings_matching(ini_patterns)
output.append("  Found {} INI setting strings:".format(len(ini_strings)))
for addr, val, pat in ini_strings:
    output.append("    @ {} [{}]: \"{}\"".format(addr, pat, val[:100]))
    # Find who references this string
    for ref in refMgr.getReferencesTo(addr):
        caller = fm.getFunctionContaining(ref.getFromAddress())
        if caller:
            output.append("      used by {} @ 0x{:08x}".format(
                caller.getName(), caller.getEntryPoint().getOffset()))

# =====================================================================
# 14. LOOK FOR HARDCODED LIMITS (immediate comparisons in hot paths)
# =====================================================================
output.append("\n\n=== 14. POTENTIAL HARDCODED LIMITS IN OBJECT PROCESSING ===\n")

# Scan FUN_0096b050 (cell processor) for CMP instructions with immediates
addr = toAddr(0x0096b050)
func = fm.getFunctionContaining(addr)
if func:
    body = func.getBody()
    inst_iter = listing.getInstructions(body, True)
    cmp_count = 0
    while inst_iter.hasNext():
        inst = inst_iter.next()
        mnemonic = inst.getMnemonicString()
        if mnemonic in ["CMP", "TEST", "JA", "JB", "JG", "JL", "JGE", "JLE"]:
            cmp_count += 1
            # Check for interesting immediate values
            for i in range(inst.getNumOperands()):
                op = inst.getDefaultOperandRepresentation(i)
                if op.startswith("0x") or op.isdigit():
                    try:
                        val = int(op, 0)
                        if val > 1 and val < 0x10000:
                            output.append("    {} @ {} : {} {}".format(
                                mnemonic, inst.getAddress(), inst.toString(),
                                "  (value={})".format(val)))
                    except:
                        pass

# =====================================================================
# 15. TryEnterCriticalSection sites (non-blocking lock attempts)
# =====================================================================
output.append("\n\n=== 15. TryEnterCriticalSection SITES (lock contention indicators) ===\n")

tryenter_refs = find_import_refs("TryEnterCriticalSection")
output.append("  Total TryEnterCriticalSection sites: {}".format(len(tryenter_refs)))
for addr, caller in tryenter_refs:
    if caller:
        output.append("\n  --- {} @ 0x{:08x} ---".format(
            caller.getName(), caller.getEntryPoint().getOffset()))
        _, code = decompile_func(caller.getEntryPoint().getOffset())
        if code:
            output.append(code[:3000])
            if len(code) > 3000:
                output.append("  ... [truncated]")

# =====================================================================
# OUTPUT
# =====================================================================
output_text = "\n".join(output)
fout = open("/tmp/combat_perf_analysis.txt", "w")
fout.write(output_text)
fout.close()

print("=== Combat Performance Analysis complete! ===")
print("=== Output: /tmp/combat_perf_analysis.txt ===")
print("=== Length: {} chars ({} lines) ===".format(len(output_text), len(output)))

decomp.dispose()
