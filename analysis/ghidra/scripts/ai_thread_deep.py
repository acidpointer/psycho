# @category Analysis
# @description Deep dive into AI thread synchronization - find the actual wait mechanism

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

def find_calls_from(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		return []
	called = []
	body = func.getBody()
	inst_iter = currentProgram.getListing().getInstructions(body, True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				called.append(ref.getToAddress().getOffset())
	return called

output.append("DEEP DIVE: AI THREAD SYNCHRONIZATION")
output.append("=" * 70)

# 1. FUN_00877700 - called by cell transition handler before cleanup
# This calls FUN_00ad8da0 with player+0x77c and timeout 1000
output.append("")
output.append("PART 1: FUN_00877700 and FUN_00ad8da0 (potential AI wait)")
decompile_at(0x00877700, "CellTransition_PreCleanup")
decompile_at(0x00ad8da0, "PotentialAIWait (called with timeout 1000)")

# 2. FUN_00ad8780 - called after FUN_00877700 in cell transition
decompile_at(0x00ad8780, "CellTransition_AfterPreCleanup")

# 3. The main loop function that contains our hook point
# We hook 0x0086ff70, which is called at 0x0086EDE8
# The render/update is at 0x008705d0 called at 0x0086EDF0
# We need to see what happens BETWEEN these calls
decompile_at(0x0086FF70, "OurHookTarget (pre-render maintenance)")
decompile_at(0x008705D0, "RenderUpdate (called right after our hook)")

# 4. The AI task execution function (FUN_008c7f50)
# This runs on AI threads - need to see what it dispatches
decompile_at(0x008c7f50, "AITaskExecution (runs on AI thread)")

# 5. FUN_0096c330 and FUN_0096cb50 - called from AI task execution
# These are the actual AI processing functions
decompile_at(0x0096c330, "AIProcess1 (from task execution)")
decompile_at(0x0096cb50, "AIProcess2 (from task execution)")

# 6. FUN_004f15a0 - sets a flag that might pause AI
# Called with (DAT_011dea0c, 0) before cleanup
decompile_at(0x004f15a0, "SetPauseFlag")

# 7. Who reads DAT_011dea0c + 4? (the flag set by FUN_004f15a0)
# This tells us if AI threads check this flag
output.append("")
output.append("=" * 70)
output.append("PART 2: Who reads the pause flag at DAT_011dea0c + 0x4?")
output.append("=" * 70)
refs = ref_mgr.getReferencesTo(toAddr(0x011DEA10))
output.append("References to DAT_011dea10 (nearby the flag):")
count = 0
for ref in refs:
	from_func = fm.getFunctionContaining(ref.getFromAddress())
	if from_func is not None:
		output.append("  0x%08x in %s" % (ref.getFromAddress().getOffset(), from_func.getName()))
	count = count + 1
	if count > 30:
		output.append("  ... (truncated, %d+ refs)" % count)
		break

# 8. The render/update function - does it wait for AI before rendering?
output.append("")
output.append("=" * 70)
output.append("PART 3: What does RenderUpdate call? (AI sync points)")
output.append("=" * 70)
calls = find_calls_from(0x008705D0)
unique = sorted(set(calls))
output.append("RenderUpdate (0x008705D0) calls %d unique functions:" % len(unique))
for t in unique:
	f = fm.getFunctionAt(toAddr(t))
	n = "???"
	if f is not None:
		n = f.getName()
	output.append("  -> 0x%08x %s" % (t, n))

# 9. FUN_008c79e0 callers - who dispatches AI tasks?
output.append("")
output.append("=" * 70)
output.append("PART 4: Who dispatches AI tasks (callers of FUN_008c79e0)?")
output.append("=" * 70)
refs = ref_mgr.getReferencesTo(toAddr(0x008c79e0))
for ref in refs:
	from_func = fm.getFunctionContaining(ref.getFromAddress())
	if from_func is not None:
		output.append("  0x%08x in %s (entry=0x%08x)" % (
			ref.getFromAddress().getOffset(),
			from_func.getName(),
			from_func.getEntryPoint().getOffset()
		))

# 10. FUN_008c7a70 callers - who waits for AI task completion?
output.append("")
output.append("=" * 70)
output.append("PART 5: Who waits for AI tasks (callers of FUN_008c7a70)?")
output.append("=" * 70)
refs = ref_mgr.getReferencesTo(toAddr(0x008c7a70))
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
outpath = "/tmp/ai_thread_deep.txt"
fout = open(outpath, "w")
fout.write(text)
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
