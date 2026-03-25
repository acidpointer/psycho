# @category Analysis
# @description Map the EXACT event synchronization sequence between
# the main thread (FUN_008c7da0) and AI workers (FUN_008c7f50).
# Both functions call FUN_008c79e0 (signal) and FUN_008c7a70 (wait)
# with (thread_index, step_number) pairs.
# We need to build a timeline showing which steps overlap.
#
# Also trace FUN_008feb60 (process swap) and FUN_0096e870 (downgrade)
# to find exactly WHEN they free HighProcess memory.

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
		if count > 50:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

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

write("=" * 70)
write("AI EVENT SYNC SEQUENCE ANALYSIS")
write("Map exact overlap between main thread and AI worker steps")
write("=" * 70)

# ===================================================================
write("")
write("#" * 70)
write("# PART 1: Full decompilation of both dispatch functions")
write("# to map signal/wait sequence precisely")
write("#" * 70)

# Main thread dispatch (runs while AI workers execute)
decompile_at(0x008c7da0, "MainThread_Dispatch_FUN_008c7da0", 12000)

# AI worker execution (runs while main thread dispatch executes)
decompile_at(0x008c7f50, "AIWorker_Execution_FUN_008c7f50", 12000)

# ===================================================================
write("")
write("#" * 70)
write("# PART 2: FUN_008feb60 -- process swap (frees old process)")
write("# Called from FUN_00977130 at end of main thread step 5")
write("# Does it free HighProcess? What does it do?")
write("#" * 70)

decompile_at(0x008feb60, "ProcessSwap_008feb60", 10000)
find_and_print_calls_from(0x008feb60, "ProcessSwap")
find_refs_to(0x008feb60, "ProcessSwap")

# ===================================================================
write("")
write("#" * 70)
write("# PART 3: FUN_00565870 -- called by ProcessMgr_WithLock")
write("# (FUN_00978550) at Phase 5 with lock held.")
write("# Does it modify actor process?")
write("#" * 70)

decompile_at(0x00565870, "ProcessMgrLocked_00565870", 10000)
find_and_print_calls_from(0x00565870, "ProcessMgrLocked")

# ===================================================================
write("")
write("#" * 70)
write("# PART 4: FUN_008c8be0 -- calls FUN_008c8fd0 (ProcessChange)")
write("# What triggers process change? When?")
write("#" * 70)

decompile_at(0x008c8be0, "ProcessChangeTrigger_008c8be0", 10000)
find_refs_to(0x008c8be0, "ProcessChangeTrigger")

# ===================================================================
write("")
write("#" * 70)
write("# PART 5: FUN_008d98e0 and FUN_008d7510")
write("# HighProcess creation (RTTI refs). When are they called?")
write("#" * 70)

decompile_at(0x008d98e0, "HighProcess_Create1")
find_refs_to(0x008d98e0, "HighProcess_Create1")

decompile_at(0x008d7510, "HighProcess_Create2")
find_refs_to(0x008d7510, "HighProcess_Create2")

# ===================================================================
write("")
write("#" * 70)
write("# PART 6: FUN_0045cd60 -- called by HasProcess and downgrade")
write("# Returns process level? (0=high, 1=medium, 2=low?)")
write("#" * 70)

decompile_at(0x0045cd60, "GetProcessLevel_0045cd60")

# ===================================================================
write("")
write("#" * 70)
write("# PART 7: The actor vtable+0xD8 call in downgrade")
write("# (**(code **)(*param_1 + 0xd8))(1) -- what does this do?")
write("# For Character class, what is vtable+0xd8?")
write("#" * 70)

# Character vtable is large. vtable+0xD8 = offset 0xD8/4 = entry 54
# Let's find what function is at Character vtable + 0xD8
# Character RTTI is at 0x01086a6c. The vtable should be nearby.
# From crash data, Character vtable entries start around 0x01086xxx

# FUN_00933840 -- called from AIWorker_Process2, checks actor state
decompile_at(0x00933840, "ActorStateCheck_00933840")

# FUN_009334b0 -- called from ActorDowngrade
decompile_at(0x009334b0, "ProcessLevelCalc_009334b0")

# ===================================================================
write("")
write("#" * 70)
write("# PART 8: FUN_008c8bd0 -- called at START of main thread step 5")
write("# (FUN_0096bcd0). What does it initialize?")
write("#" * 70)

decompile_at(0x008c8bd0, "MainStep5Init_008c8bd0")

# ===================================================================
write("")
write("#" * 70)
write("# PART 9: FUN_008c8bb0 -- called at start of AI worker process1")
write("# Sets a byte at this+0x5f8. What is this flag?")
write("#" * 70)

decompile_at(0x008c8bb0, "AIWorkerInit_008c8bb0")

# ===================================================================
write("")
write("#" * 70)
write("# PART 10: The second AI dispatch function (FUN_008c7de0)")
write("# From the Ghidra analysis, FUN_008c7de0 is AI_WaitComplete")
write("# Used when multicore=false?")
write("#" * 70)

decompile_at(0x008c7de0, "AI_WaitComplete_008c7de0", 10000)

write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/ai_event_sync_sequence.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
