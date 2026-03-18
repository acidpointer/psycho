# @category Analysis
# @description Find exactly WHERE in the frame the game calls ProcessDeferredDestruction

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def decompile_at(addr_int, label):
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
		if len(code) > 8000:
			output.append(code[:8000])
		else:
			output.append(code)
	output.append("")

output.append("FINDING SAFE POINT FOR ProcessDeferredDestruction")
output.append("=" * 70)

# =====================================================================
# PART 1: The AI coordinator functions that dispatch/wait for AI tasks
# These are the functions that KNOW when AI threads are idle
# =====================================================================
output.append("")
output.append("PART 1: AI COORDINATOR FUNCTIONS")
output.append("(These control when AI threads are active/idle)")

# FUN_008c7da0 - main coordinator, dispatches and waits
decompile_at(0x008c7da0, "AI_MainCoordinator (dispatch+wait)")

# FUN_008c7bd0 - another dispatcher
decompile_at(0x008c7bd0, "AI_Dispatcher2")

# Who calls these coordinators? That's where in the frame they run
output.append("")
output.append("--- Who calls AI_MainCoordinator (0x008c7da0)? ---")
refs = ref_mgr.getReferencesTo(toAddr(0x008c7da0))
for ref in refs:
	from_func = fm.getFunctionContaining(ref.getFromAddress())
	if from_func is not None:
		output.append("  0x%08x in %s (entry=0x%08x)" % (
			ref.getFromAddress().getOffset(),
			from_func.getName(),
			from_func.getEntryPoint().getOffset()
		))

output.append("")
output.append("--- Who calls AI_Dispatcher2 (0x008c7bd0)? ---")
refs = ref_mgr.getReferencesTo(toAddr(0x008c7bd0))
for ref in refs:
	from_func = fm.getFunctionContaining(ref.getFromAddress())
	if from_func is not None:
		output.append("  0x%08x in %s (entry=0x%08x)" % (
			ref.getFromAddress().getOffset(),
			from_func.getName(),
			from_func.getEntryPoint().getOffset()
		))

# =====================================================================
# PART 2: The main loop function - full decompilation
# We need to see the COMPLETE frame flow to find where AI tasks
# are dispatched, completed, and where cleanup happens
# =====================================================================
output.append("")
output.append("PART 2: MAIN LOOP (full frame flow)")
decompile_at(0x0086E650, "MainLoop (full decompilation)")

# =====================================================================
# PART 3: FUN_0086f890 - called from RenderUpdate
# This might be where AI tasks are dispatched
# =====================================================================
output.append("")
output.append("PART 3: RENDER/UPDATE INTERNALS")
decompile_at(0x0086f890, "RenderUpdate_Inner (FUN_0086f890)")
decompile_at(0x0086f640, "RenderUpdate_Pre (FUN_0086f640)")
decompile_at(0x0086f670, "RenderUpdate_Post (FUN_0086f670)")

# =====================================================================
# PART 4: FUN_0045dfe0 - one of the callers of ProcessDeferredDestruction
# This is a huge function (8357 bytes) that calls it.
# We need to know WHERE in the frame this runs
# =====================================================================
output.append("")
output.append("PART 4: FUN_0045dfe0 caller chain")
output.append("--- Who calls FUN_0045dfe0? ---")
refs = ref_mgr.getReferencesTo(toAddr(0x0045dfe0))
for ref in refs:
	from_func = fm.getFunctionContaining(ref.getFromAddress())
	if from_func is not None:
		output.append("  0x%08x in %s (entry=0x%08x)" % (
			ref.getFromAddress().getOffset(),
			from_func.getName(),
			from_func.getEntryPoint().getOffset()
		))

# FUN_00450770 calls FUN_0045dfe0
decompile_at(0x00450770, "CallerOf_0045dfe0")

output.append("")
output.append("--- Who calls FUN_00450770? ---")
refs = ref_mgr.getReferencesTo(toAddr(0x00450770))
for ref in refs:
	from_func = fm.getFunctionContaining(ref.getFromAddress())
	if from_func is not None:
		output.append("  0x%08x in %s (entry=0x%08x)" % (
			ref.getFromAddress().getOffset(),
			from_func.getName(),
			from_func.getEntryPoint().getOffset()
		))

# =====================================================================
# PART 5: FUN_00878250 - another caller of ProcessDeferredDestruction
# Small function (86 bytes), likely called from a specific frame point
# =====================================================================
output.append("")
output.append("PART 5: FUN_00878250 caller chain")
output.append("--- Who calls FUN_00878250? ---")
refs = ref_mgr.getReferencesTo(toAddr(0x00878250))
for ref in refs:
	from_func = fm.getFunctionContaining(ref.getFromAddress())
	if from_func is not None:
		output.append("  0x%08x in %s (entry=0x%08x)" % (
			ref.getFromAddress().getOffset(),
			from_func.getName(),
			from_func.getEntryPoint().getOffset()
		))

# =====================================================================
# PART 6: FUN_0093bea0 - another caller, related to cell transitions
# =====================================================================
output.append("")
output.append("PART 6: FUN_0093bea0 caller chain")
output.append("--- Who calls FUN_0093bea0? ---")
refs = ref_mgr.getReferencesTo(toAddr(0x0093bea0))
for ref in refs:
	from_func = fm.getFunctionContaining(ref.getFromAddress())
	if from_func is not None:
		output.append("  0x%08x in %s (entry=0x%08x)" % (
			ref.getFromAddress().getOffset(),
			from_func.getName(),
			from_func.getEntryPoint().getOffset()
		))

# =====================================================================
# PART 7: FUN_0084c5a0 - another caller (savegame/load related?)
# =====================================================================
output.append("")
output.append("PART 7: FUN_0084c5a0 caller chain")
output.append("--- Who calls FUN_0084c5a0? ---")
refs = ref_mgr.getReferencesTo(toAddr(0x0084c5a0))
for ref in refs:
	from_func = fm.getFunctionContaining(ref.getFromAddress())
	if from_func is not None:
		output.append("  0x%08x in %s (entry=0x%08x)" % (
			ref.getFromAddress().getOffset(),
			from_func.getName(),
			from_func.getEntryPoint().getOffset()
		))

# Write output
text = "\n".join(output)
outpath = "/tmp/find_deferred_safe_point.txt"
fout = open(outpath, "w")
fout.write(text)
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
