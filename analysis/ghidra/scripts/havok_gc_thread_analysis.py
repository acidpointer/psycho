# @category Analysis
# @description Analyze Havok GC thread behavior, AI worker execution,
# broadphase modification paths. Crash at 0x00C94DA5 on AI thread.

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
	if faddr != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def find_and_print_calls_from(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found at 0x%08x]" % addr_int)
		return
	body = func.getBody()
	inst_iter = currentProgram.getListing().getInstructions(body, True)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
	write("  Total: %d calls" % count)

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
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
		if count > 40:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_callers_in_range(target_addr, range_start, range_end, label):
	write("")
	write("-" * 70)
	write("%s callers from 0x%08x-0x%08x" % (label, range_start, range_end))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(target_addr))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		src = ref.getFromAddress().getOffset()
		if range_start <= src <= range_end and ref.getReferenceType().isCall():
			func = fm.getFunctionContaining(ref.getFromAddress())
			name = func.getName() if func else "???"
			write("  0x%08x in %s" % (src, name))
			count += 1
	write("  Total: %d callers" % count)

write("=" * 70)
write("HAVOK GC + AI WORKER THREAD ANALYSIS")
write("Crash at 0x00C94DA5 on AI Linear Task Thread 2")
write("Classes: hkScaledMoppBvTreeShape, hkpSimulationIsland, ahkpWorld")
write("=" * 70)

# ===================================================================
write("")
write("#" * 70)
write("# PART 1: FUN_00c459d0 -- Havok GC / Async Flush")
write("#" * 70)

decompile_at(0x00c459d0, "HavokGC_AsyncFlush")
find_and_print_calls_from(0x00c459d0, "HavokGC")

# ===================================================================
write("")
write("#" * 70)
write("# PART 2: Crash site 0x00C94DA5 and callers")
write("#" * 70)

decompile_at(0x00c94da5, "CrashSite_00C94DA5", 12000)
decompile_at(0x00c90350, "CrashCaller_00C90350", 10000)

# ===================================================================
write("")
write("#" * 70)
write("# PART 3: AI worker thread execution path")
write("#" * 70)

decompile_at(0x008c78c0, "AI_START_Dispatch")
decompile_at(0x008c9fb0, "AI_WorkerBody")
decompile_at(0x008c7f50, "AITaskExecution")
find_and_print_calls_from(0x008c9fb0, "AI_WorkerBody")
find_and_print_calls_from(0x008c7f50, "AITaskExecution")

# ===================================================================
write("")
write("#" * 70)
write("# PART 4: GameHeap::Free/Alloc callers from Havok code")
write("#" * 70)

find_callers_in_range(0x00AA4060, 0x00C30000, 0x00D30000, "GameHeap::Free (0x00AA4060)")
find_callers_in_range(0x00AA3E40, 0x00C30000, 0x00D30000, "GameHeap::Allocate (0x00AA3E40)")

# ===================================================================
write("")
write("#" * 70)
write("# PART 5: hkpSimulationIsland -- who creates/destroys?")
write("#" * 70)

find_refs_to(0x010CCF28, "hkpSimulationIsland RTTI")

# ===================================================================
write("")
write("#" * 70)
write("# PART 6: OOM stage executor -- stages 3-4 detail")
write("#" * 70)

decompile_at(0x00866a90, "OOM_StageExecutor", 12000)

# ===================================================================
write("")
write("#" * 70)
write("# PART 7: hkWorld Lock/Unlock")
write("#" * 70)

find_refs_to(0x00c3e310, "hkWorld_Lock")
find_refs_to(0x00c3e340, "hkWorld_Unlock")
decompile_at(0x00c3e310, "hkWorld_Lock")
decompile_at(0x00c3e340, "hkWorld_Unlock")

# ===================================================================
write("")
write("#" * 70)
write("# PART 8: AI dispatch internals")
write("#" * 70)

decompile_at(0x008c7da0, "AI_Dispatch_Internal")

write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/havok_gc_thread_analysis.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
