# @category Analysis
# @description Research the game's OWN CellTransitionHandler Havok race.
# The crash is on AI Linear Task Thread 2 in Havok physics (hkpSimulationIsland)
# during the game's own cell transition — NOT our pressure relief.
# CellTransitionHandler calls BLOCKING PDD without hkWorld_Lock.
# Goal: Find how to hook/patch CellTransitionHandler to add hkWorld_Lock,
# or find another way to prevent the AI thread race.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=8000):
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
		return
	faddr = func.getEntryPoint().getOffset()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, func.getBody().getNumAddresses()))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def find_refs_to(addr_int, label):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("  %s @ %s (in %s)" % (ref.getReferenceType(), ref.getFromAddress(), fname))
		count += 1
		if count > 40:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

write("=" * 70)
write("CELL TRANSITION HAVOK RACE ANALYSIS")
write("The game's OWN CellTransitionHandler does BLOCKING PDD")
write("without hkWorld_Lock. AI threads crash on freed physics data.")
write("Goal: Fix this ENGINE BUG by adding hkWorld_Lock to the")
write("game's cell transition path.")
write("=" * 70)

# ===================================================================
# PART 1: CellTransitionHandler — the buggy function
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: CellTransitionHandler (FUN_008774a0)")
write("# Line 75: FUN_00868d70('\\0') — BLOCKING PDD without hkWorld_Lock!")
write("# Line 76: FUN_00c459d0('\\0') — BLOCKING async flush")
write("# Neither is protected by hkWorld_Lock.")
write("#" * 70)

decompile_at(0x008774A0, "CellTransitionHandler (561 bytes)", 10000)

# ===================================================================
# PART 2: Who calls CellTransitionHandler?
# We need to know all entry points to patch
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: All callers of CellTransitionHandler")
write("#" * 70)

find_refs_to(0x008774A0, "CellTransitionHandler")

# ===================================================================
# PART 3: The crash function — what Havok operation crashed?
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: Crash at 0x00C94DA5 — Havok physics operation")
write("# hkpSimulationIsland processing on AI thread")
write("#" * 70)

decompile_at(0x00C94DA5, "Havok_Crash_Function")

# The caller chain from crash log
decompile_at(0x00C90350, "Havok_SimIsland_Process")

# ===================================================================
# PART 4: When does CellTransitionHandler run relative to AI threads?
# The main loop calls it at line 273 (FUN_0086f940)
# But AI threads may be active from post-render signal
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: Frame timing of CellTransitionHandler")
write("# Called from FUN_0086f940 at main loop line 273")
write("# AI post-render signal fires at line 497")
write("# Is there a window where AI is active when CT runs?")
write("#" * 70)

# FUN_0093bea0 — CellTransition_Conditional, calls CellTransitionHandler
decompile_at(0x0093BEA0, "CellTransition_Conditional (832 bytes)", 10000)

# ===================================================================
# PART 5: Can we hook CellTransitionHandler to add hkWorld_Lock?
# Option A: Hook the function entry, add lock before, unlock after
# Option B: Patch the BLOCKING PDD call to be non-blocking
# Option C: Patch to add hkWorld_Lock before the PDD call
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: CellTransitionHandler hookability")
write("# Function is 561 bytes at 0x008774a0")
write("# PDD call is at offset ~75 from entry")
write("# Can we inline-hook the function?")
write("#" * 70)

# Check function prologue for hookability
listing = currentProgram.getListing()
inst_iter = listing.getInstructions(toAddr(0x008774A0), True)
write("\nFirst 10 instructions of CellTransitionHandler:")
count = 0
while inst_iter.hasNext() and count < 10:
	inst = inst_iter.next()
	write("  0x%s: %s %s" % (inst.getAddress(), inst.getMnemonicString(), inst.toString().split(" ", 1)[-1] if " " in inst.toString() else ""))
	count += 1

# ===================================================================
# PART 6: FUN_0093cdf0 — another cell transition path
# Does it also do PDD without hkWorld_Lock?
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: FUN_0093cdf0 — cell transition with PDD")
write("# This is Caller3 — does it use PreDestructionSetup?")
write("#" * 70)

decompile_at(0x0093CDF0, "CellTransition_WithPDD (1779 bytes)", 12000)

# ===================================================================
# PART 7: All callers of BLOCKING PDD — FUN_00868d70 with param=0
# Which ones DON'T use hkWorld_Lock?
# ===================================================================
write("")
write("#" * 70)
write("# PART 7: All callers of PDD (FUN_00868d70)")
write("# param=0 is BLOCKING, param=1 is NON-BLOCKING")
write("# Which callers use BLOCKING without hkWorld_Lock?")
write("#" * 70)

find_refs_to(0x00868D70, "ProcessDeferredDestruction")

# ===================================================================
# PART 8: AI thread lifecycle during cell transition
# Is AI dispatched before CellTransitionHandler returns?
# ===================================================================
write("")
write("#" * 70)
write("# PART 8: AI dispatch during cell transition")
write("# FUN_008c80e0 — AI_StartFrame")
write("# When does it fire relative to CellTransitionHandler?")
write("#" * 70)

# The main loop flow around cell transition:
# Line 273: FUN_0086f940 → FUN_0093bea0 → CellTransitionHandler
# Line 431: AI dispatch (FUN_008c80e0)
# Line 486: Render (our hook)
# Line 497: AI post-render signal

# But what about PREVIOUS frame's post-render AI?
# If frame N dispatched post-render AI, frame N+1's CellTransition
# runs while those AI threads are still active.

decompile_at(0x008C80E0, "AI_StartFrame (46 bytes)")

# Check if CellTransitionHandler waits for AI completion
# FUN_00877700 — called at start of CellTransitionHandler
decompile_at(0x00877700, "CT_WaitForPlayer (30 bytes)")

# ===================================================================
# PART 9: FUN_008324e0 — called by CellTransitionHandler
# We know this is the MUSIC system, NOT Havok stop
# But does it do ANYTHING to pause physics?
# ===================================================================
write("")
write("#" * 70)
write("# PART 9: FUN_008324e0 in CellTransitionHandler")
write("# Drains PPL task groups (audio) — does NOT stop AI physics")
write("#" * 70)

decompile_at(0x008324E0, "MusicStopStart (184 bytes)")

# ===================================================================
# PART 10: The AI thread's Havok access path
# What does the AI thread do with hkpSimulationIsland?
# ===================================================================
write("")
write("#" * 70)
write("# PART 10: AI thread Havok access — simulation islands")
write("# The crash was in hkpSimulationIsland processing")
write("# What accesses simulation islands on AI threads?")
write("#" * 70)

decompile_at(0x008C7F50, "AITask_FrameUpdate (346 bytes)")

# bhkWorldM — referenced on crash stack
# "Exception occurred while logging" suggests complex object
decompile_at(0x00856CA0, "bhkWorldM_StepPhysics? (1388 bytes, calls hkWorld_Lock)", 10000)

write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/cell_transition_havok_race.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
