# @category Analysis
# @description Decompile AI thread sync primitives and cell transition handler

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
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
		if len(code) > 6000:
			output.append(code[:6000])
		else:
			output.append(code)
	output.append("")

output.append("AI THREAD SYNC PRIMITIVES + CELL TRANSITION HANDLER")
output.append("=" * 70)

# AI thread wait/signal functions
decompile_at(0x004424e0, "AI_WaitForWork (called in AI thread loop)")
decompile_at(0x00442550, "AI_SignalCompletion (called after task)")

# Cell transition handler's sync functions
decompile_at(0x004f1540, "CellTransition_SaveState (called before ProcessDeferredDestruction)")
decompile_at(0x004f15a0, "CellTransition_SetState (called before/after)")
decompile_at(0x007d6bd0, "CellTransition_PauseResume (saves/restores state around cleanup)")
decompile_at(0x008324e0, "CellTransition_Unknown (called before ProcessDeferredDestruction)")

# The cell transition handler itself (calls ProcessDeferredDestruction safely)
decompile_at(0x008774a0, "CellTransitionHandler (calls ProcessDeferredDestruction blocking)")

# FUN_00878250 - another caller of ProcessDeferredDestruction
decompile_at(0x00878250, "AnotherDeferredCaller")

# FUN_0045dfe0 - the big caller (main loop related?)
output.append("")
output.append("=" * 70)
output.append("FUN_0045dfe0 - who calls this?")
output.append("=" * 70)
ref_mgr = currentProgram.getReferenceManager()
refs = ref_mgr.getReferencesTo(toAddr(0x0045dfe0))
for ref in refs:
	from_addr = ref.getFromAddress()
	from_func = fm.getFunctionContaining(from_addr)
	if from_func is not None:
		output.append("  Called from 0x%08x in %s" % (from_addr.getOffset(), from_func.getName()))

# What does FUN_00877700 do? (called at start of cell transition)
decompile_at(0x00877700, "CellTransition_PreCleanup (called before everything)")

# The AI task dispatch function
decompile_at(0x008c79e0, "AI_DispatchTask")
decompile_at(0x008c7a70, "AI_DispatchTask2")

# Write
text = "\n".join(output)
outpath = "/tmp/ai_sync_primitives.txt"
fout = open(outpath, "w")
fout.write(text)
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
