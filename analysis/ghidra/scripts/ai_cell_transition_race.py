# @category Analysis
# @description Research the AI thread ↔ cell transition race condition.
# Goal: Find EXACTLY when AI threads are paused during cell transitions,
# what heightfield refs they hold, and where the race window is.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def decompile_at(addr_int, label, max_len=8000):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	output.append("")
	output.append("=" * 70)
	output.append("%s @ 0x%08x" % (label, addr_int))
	output.append("=" * 70)
	if func is None:
		output.append("  [function not found]")
		return
	output.append("  Function: %s, Size: %d bytes" % (func.getName(), func.getBody().getNumAddresses()))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		output.append(code[:max_len])
	else:
		output.append("  [decompilation failed]")

def find_xrefs_to(addr_int, label):
	addr = toAddr(addr_int)
	refs = getReferencesTo(addr)
	output.append("")
	output.append("--- XRefs to %s (0x%08x) ---" % (label, addr_int))
	count = 0
	for ref in refs:
		from_addr = ref.getFromAddress()
		func = fm.getFunctionContaining(from_addr)
		fname = func.getName() if func else "???"
		output.append("  %s @ 0x%s (in %s)" % (ref.getReferenceType(), from_addr, fname))
		count += 1
		if count > 30:
			output.append("  ... (truncated)")
			break
	output.append("  Total: %d refs" % count)

output.append("###############################################################")
output.append("# AI THREAD ↔ CELL TRANSITION RACE ANALYSIS")
output.append("# Goal: Find the exact synchronization (or lack thereof)")
output.append("# between AI threads and cell/PDD operations")
output.append("###############################################################")

# === Section 1: AI thread dispatch/wait in main loop ===
output.append("\n\n### SECTION 1: AI dispatch/wait around cell transitions")

# The key: CellTransitionHandler is called from FUN_0086f940 (line 273)
# which is BEFORE AI dispatch (line 431). So AI should be idle.
# BUT: post-render AI signal (line 497) runs AI concurrently.
# Does the game wait for post-render AI before cell transition?

decompile_at(0x0086F940, "PreAI_CellHandler (line 273, 595 bytes)", 10000)
decompile_at(0x0093BEA0, "CellTransition_Conditional (832 bytes)", 10000)

# === Section 2: AI dispatch flags ===
output.append("\n\n### SECTION 2: AI dispatch flags")
output.append("# DAT_011dfa18 = dispatch flag, DAT_011dfa19 = active flag")
output.append("# When are these set/cleared relative to cell transitions?")

find_xrefs_to(0x011DFA18, "AI_dispatch_flag")
find_xrefs_to(0x011DFA19, "AI_active_flag")

decompile_at(0x008C80E0, "AI_StartFrame (sets dispatch flag)")
decompile_at(0x008C78C0, "AI_ResetEvents (198 bytes)")
decompile_at(0x008C7990, "AI_PostRender (72 bytes)")

# === Section 3: Cell transition handler's AI synchronization ===
output.append("\n\n### SECTION 3: CellTransitionHandler AI sync")
output.append("# Does CellTransitionHandler pause/wait for AI threads?")

decompile_at(0x008774A0, "CellTransitionHandler (561 bytes)", 10000)

# FUN_00878160 — pre-destruction setup (called before PDD in normal gameplay)
decompile_at(0x00878160, "PreDestruction_Setup")
# Does it call Havok stop?
decompile_at(0x008324E0, "MusicStopStart (actually music, NOT Havok)")

# === Section 4: The ACTUAL Havok physics pause mechanism ===
output.append("\n\n### SECTION 4: Havok physics world lock/pause")
output.append("# Is there a Havok world lock that prevents AI raycasting?")

decompile_at(0x00C3E310, "hkWorld_Lock (called from PreDestruction)")
decompile_at(0x00C3E350, "hkWorld_Unlock")

# Find xrefs to the Havok world lock
find_xrefs_to(0x00C3E310, "hkWorld_Lock")
find_xrefs_to(0x00C3E350, "hkWorld_Unlock")

# === Section 5: What happens to hkBSHeightFieldShape during PDD ===
output.append("\n\n### SECTION 5: hkBSHeightFieldShape destruction path")
output.append("# PDD queue 0x20 calls FUN_00401970 (Havok_Release)")
output.append("# Trace: does it go through GameHeap::Free or CRT _free?")

decompile_at(0x00401970, "Havok_Release (PDD queue 0x20)")

# hkpShape destructor chain
decompile_at(0x00C40DC0, "bhkCollisionObject_dtor")
decompile_at(0x00C3E170, "hkDeallocate")
decompile_at(0x00C3E0D0, "hkAllocate")

# The Havok memory system — does it use GameHeap or its own allocator?
decompile_at(0x00C3DFC0, "hkMemorySystem_Alloc")
decompile_at(0x00C3E010, "hkMemorySystem_Free")

# === Section 6: AI raycasting heightfield access ===
output.append("\n\n### SECTION 6: AI raycasting — heightfield access")
output.append("# Where does AIProcess_Main read hkBSHeightFieldShape?")
output.append("# Is there a lock check before accessing?")

decompile_at(0x0096C330, "AIProcess_Main (991 bytes)", 12000)
decompile_at(0x0096CB50, "AIProcess_Secondary")

# === Section 7: Main loop AI lifecycle (full context) ===
output.append("\n\n### SECTION 7: Main loop frame — AI lifecycle")
output.append("# Show the full frame to understand AI start/stop timing")

# Lines around AI dispatch in main loop
decompile_at(0x0086E650, "MainLoop (2272 bytes)", 15000)

# === Write output ===
import os
out_path = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/ai_cell_transition_race.txt"

d = os.path.dirname(out_path)
if not os.path.exists(d):
	os.makedirs(d)

with open(out_path, "w") as f:
	f.write("\n".join(output))

print("Wrote %d lines to %s" % (len(output), out_path))
