# @category Analysis
# @description Analyze AI thread Havok broadphase crash at 0x00CFFA08

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=10000):
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
	entry = func.getEntryPoint().getOffset()
	sz = func.getBody().getNumAddresses()
	write("  Function: %s, Size: %d bytes" % (func.getName(), sz))
	write("  Entry: 0x%08x" % entry)
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def disasm_range(start_int, count=30):
	listing = currentProgram.getListing()
	inst = listing.getInstructionAfter(toAddr(start_int - 1))
	for i in range(count):
		if inst is None:
			break
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()

def find_calls_from(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	listing = currentProgram.getListing()
	body = func.getBody()
	addr_iter = body.getAddresses(True)
	count = 0
	while addr_iter.hasNext():
		a = addr_iter.next()
		inst = listing.getInstructionAt(a)
		if inst is None:
			continue
		if not inst.getFlowType().isCall():
			continue
		refs_from = inst.getReferencesFrom()
		for r in refs_from:
			target = r.getToAddress().getOffset()
			target_func = fm.getFunctionAt(toAddr(target))
			target_name = target_func.getName() if target_func else "unknown_0x%08x" % target
			write("  CALL 0x%08x -> %s (from 0x%08x)" % (target, target_name, a.getOffset()))
			count += 1
	write("  Total: %d calls" % count)


write("=" * 70)
write("AI THREAD HAVOK CRASH at 0x00CFFA08")
write("Thread: AI Linear Task Thread 2")
write("EAX=0 (NULL), EDI=ahkpWorld, EBP=0")
write("Stack: 0x00C9507B, 0x008C0900")
write("=" * 70)

# SECTION 1: Crash point
write("")
write("#" * 70)
write("# SECTION 1: Crash point and containing function")
write("#" * 70)

decompile_at(0x00CFFA08, "CRASH_POINT")

write("")
write("Disasm around crash (0x00CFFA08):")
disasm_range(0x00CFF9E0, 30)

# SECTION 2: Callers from stack
write("")
write("#" * 70)
write("# SECTION 2: Stack return addresses")
write("#" * 70)

decompile_at(0x00C9507B, "STACK_CALLER_1")
write("")
write("Disasm around 0x00C9507B:")
disasm_range(0x00C95060, 15)

decompile_at(0x008C0900, "STACK_CALLER_2_AI_area")
write("")
write("Disasm around 0x008C0900:")
disasm_range(0x008C08E0, 15)

# SECTION 3: AI raycasting path — what leads to broadphase query?
write("")
write("#" * 70)
write("# SECTION 3: AI thread raycasting entry point")
write("#" * 70)

# FUN_0096c330 — AI raycasting (from heap_analysis)
decompile_at(0x0096C330, "AI_Raycast")
find_calls_from(0x0096C330, "AI_Raycast")

# SECTION 4: hkWorld_Lock internals — FUN_00c3e750 (the actual lock logic)
write("")
write("#" * 70)
write("# SECTION 4: hkWorld_Lock actual lock — FUN_00c3e750")
write("# What does it check? How does it block AI threads?")
write("#" * 70)

decompile_at(0x00C3E750, "hkWorld_ActualLock")
write("")
write("Disasm of hkWorld_ActualLock:")
disasm_range(0x00C3E750, 40)

# SECTION 5: What exactly is at 0x00CFFA08? Broadphase query?
write("")
write("#" * 70)
write("# SECTION 5: Broader context — functions near crash")
write("#" * 70)

# Look at the function containing the crash
decompile_at(0x00CFF9E0, "CrashFunction_area")

# SECTION 6: hkBroadPhase raycasting — hkp3AxisSweep
write("")
write("#" * 70)
write("# SECTION 6: Broadphase raycast functions near 0x00CFFA08")
write("#" * 70)

# The crash is in the 0x00CF* range which is Havok broadphase
decompile_at(0x00CFE880, "hkBroadPhase_area1")
decompile_at(0x00CFF740, "hkBroadPhase_area2")

# SECTION 7: AI dispatch — what data does AI thread receive?
write("")
write("#" * 70)
write("# SECTION 7: AI dispatch — FUN_008c80e0 + FUN_008c78c0")
write("#" * 70)

decompile_at(0x008C80E0, "AI_DispatchPrep")
decompile_at(0x008C78C0, "AI_Start")

# SECTION 8: Our hkWorld_Lock — verify we actually lock before PDD
# Check the PostDestructionRestore unlock
write("")
write("#" * 70)
write("# SECTION 8: PostDestructionRestore — when does hkWorld_Unlock?")
write("#" * 70)

decompile_at(0x00878200, "PostDestructionRestore")
write("")
write("Disasm:")
disasm_range(0x00878200, 25)

# hkWorld_Unlock
decompile_at(0x00C3E340, "hkWorld_Unlock")
write("")
write("Disasm:")
disasm_range(0x00C3E340, 20)

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/crash_00CFFA08_analysis.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
