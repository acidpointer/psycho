# @category Analysis
# @description Trace what the main thread does IN PARALLEL with AI workers.
# FUN_008c7da0 runs on main thread while AI workers execute.
# Key question: does the main thread modify Havok world state while
# AI workers are reading/modifying it? This would explain the
# broadphase crash on AI thread.
#
# Also trace what AI workers call that touches Havok -- FUN_0096c330,
# FUN_0096cb50, FUN_008d0600, FUN_0096db30.

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

write("=" * 70)
write("AI + MAIN THREAD PARALLEL WORK ANALYSIS")
write("What does main thread do while AI workers run?")
write("What Havok functions do AI workers call?")
write("=" * 70)

# ===================================================================
write("")
write("#" * 70)
write("# PART 1: Main thread parallel work -- FUN_008c7da0")
write("# This runs on main thread WHILE AI workers execute.")
write("# It calls FUN_008c79e0 (signal) and FUN_008c7a70 (wait)")
write("# to synchronize with workers at each step.")
write("#" * 70)

# Functions called by main thread during AI execution:
# From the decompilation we already have, the key calls are:
decompile_at(0x0086fd70, "MainThread_DuringAI_Render")
decompile_at(0x00991500, "MainThread_DuringAI_FUN_00991500")
decompile_at(0x0096cca0, "MainThread_DuringAI_FUN_0096cca0")
decompile_at(0x0096cda0, "MainThread_DuringAI_FUN_0096cda0")
decompile_at(0x00455640, "MainThread_DuringAI_FUN_00455640")
decompile_at(0x009784c0, "MainThread_DuringAI_FUN_009784c0")

# ===================================================================
write("")
write("#" * 70)
write("# PART 2: AI worker Havok functions")
write("# FUN_0096c330 and FUN_0096cb50 are the main AI processing")
write("# Do they touch Havok world / broadphase?")
write("#" * 70)

decompile_at(0x0096c330, "AIWorker_Process1", 10000)
find_and_print_calls_from(0x0096c330, "AIWorker_Process1")

decompile_at(0x0096cb50, "AIWorker_Process2", 10000)
find_and_print_calls_from(0x0096cb50, "AIWorker_Process2")

# ===================================================================
write("")
write("#" * 70)
write("# PART 3: FUN_008d0600 -- called by AI worker between steps")
write("# What does it do? Does it modify Havok?")
write("#" * 70)

decompile_at(0x008d0600, "AIWorker_FUN_008d0600")
find_and_print_calls_from(0x008d0600, "AIWorker_FUN_008d0600")

# ===================================================================
write("")
write("#" * 70)
write("# PART 4: FUN_0096db30 -- called by AI worker")
write("#" * 70)

decompile_at(0x0096db30, "AIWorker_FUN_0096db30")
find_and_print_calls_from(0x0096db30, "AIWorker_FUN_0096db30")

# ===================================================================
write("")
write("#" * 70)
write("# PART 5: FUN_0096bcd0 -- called by main thread during AI")
write("# This is step 5 of the main thread parallel work")
write("#" * 70)

decompile_at(0x0096bcd0, "MainThread_DuringAI_FUN_0096bcd0", 10000)
find_and_print_calls_from(0x0096bcd0, "MainThread_DuringAI_FUN_0096bcd0")

# ===================================================================
write("")
write("#" * 70)
write("# PART 6: FUN_0096d520 -- called by main thread during AI")
write("# This is step 6 of the main thread parallel work")
write("#" * 70)

decompile_at(0x0096d520, "MainThread_DuringAI_FUN_0096d520")
find_and_print_calls_from(0x0096d520, "MainThread_DuringAI_FUN_0096d520")

# ===================================================================
write("")
write("#" * 70)
write("# PART 7: FUN_0096c7c0 -- called by main thread after waiting")
write("# for AI worker steps 1 and 3. What does it do?")
write("#" * 70)

decompile_at(0x0096c7c0, "MainThread_AfterWait_FUN_0096c7c0", 10000)
find_and_print_calls_from(0x0096c7c0, "MainThread_AfterWait_FUN_0096c7c0")

# ===================================================================
write("")
write("#" * 70)
write("# PART 8: Event sync primitives -- FUN_008c79e0 and FUN_008c7a70")
write("# These are the signal/wait used to coordinate main+workers")
write("#" * 70)

decompile_at(0x008c79e0, "AI_SignalEvent")
decompile_at(0x008c7a70, "AI_WaitForEvent")

# ===================================================================
write("")
write("#" * 70)
write("# PART 9: FUN_004772f0 -- called by AI worker")
write("# Between process steps. What does it do?")
write("#" * 70)

decompile_at(0x004772f0, "AIWorker_FUN_004772f0")

# ===================================================================
write("")
write("#" * 70)
write("# PART 10: FUN_00453550 -- called by AI worker (cell management?)")
write("# This touches DAT_011dea10 (game manager)")
write("#" * 70)

decompile_at(0x00453550, "AIWorker_CellMgmt_FUN_00453550")
decompile_at(0x00453850, "AIWorker_FUN_00453850")

# ===================================================================
write("")
write("#" * 70)
write("# PART 11: hkpWorld::addEntity crash path")
write("# FUN_00c94bd0 adds entities. Who calls it during AI?")
write("#" * 70)

find_refs_to(0x00c94bd0, "hkpWorld_addEntity (FUN_00c94bd0)")

# ===================================================================
write("")
write("#" * 70)
write("# PART 12: FUN_00c3e1b0 -- hkWorld step/simulate")
write("# Does this run during AI? Who calls it?")
write("#" * 70)

decompile_at(0x00c3e1b0, "hkWorld_StepSimulate", 10000)
find_refs_to(0x00c3e1b0, "hkWorld_StepSimulate")

write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/ai_main_thread_parallel_work.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
