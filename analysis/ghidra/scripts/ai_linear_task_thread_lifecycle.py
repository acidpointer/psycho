# @category Analysis
# @description Trace AI Linear Task Thread lifecycle and its relation to AI_ACTIVE flag (DAT_011DFA19). Validates whether is_ai_active() covers Linear Task Threads.

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
	write(
		"  Function: %s @ 0x%08x, Size: %d bytes"
		% (func.getName(), faddr, func.getBody().getNumAddresses())
	)
	if faddr != addr_int:
		write(
			"  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)"
			% (addr_int, func.getName(), faddr)
		)
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
		write(
			"  %s @ 0x%08x (in %s)"
			% (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname)
		)
		count += 1
		if count > 40:
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
				write(
					"  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name)
				)
				count += 1
	write("  Total: %d calls" % count)


def disasm_range(start_int, count=20):
	listing = currentProgram.getListing()
	inst = listing.getInstructionAfter(toAddr(start_int - 1))
	for i in range(count):
		if inst is None:
			break
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()


# ======================================================================
# MAIN ANALYSIS
# ======================================================================

write("AI LINEAR TASK THREAD LIFECYCLE ANALYSIS")
write("Goal: Does is_ai_active() (DAT_011DFA19) cover Linear Task Threads?")
write("Crash: 0x00C94DA5 on AI Linear Task Thread 2 after destruction_protocol")
write("=" * 70)

# SECTION 1: AI_ACTIVE flag — what reads/writes it?
write("")
write("#" * 70)
write("# SECTION 1: DAT_011DFA19 (AI_ACTIVE_FLAG) — all readers and writers")
write("# If Linear Task Threads never read this, is_ai_active() is useless")
write("#" * 70)

find_refs_to(0x011DFA19, "AI_ACTIVE_FLAG")

# SECTION 2: AILinearTaskThread class — RTTI and constructor
write("")
write("#" * 70)
write("# SECTION 2: AILinearTaskThread — find constructor/vtable")
write("#" * 70)

# The RTTI pointer from crash log: 0x01085688
find_refs_to(0x01085688, "AILinearTaskThread_RTTI")

# SECTION 3: AI_ThreadStart (Phase 8 hook target) — does it dispatch Linear Tasks?
write("")
write("#" * 70)
write("# SECTION 3: AI_ThreadStart (0x008C78C0) — does it create Linear Tasks?")
write("#" * 70)

decompile_at(0x008C78C0, "AI_ThreadStart")
find_and_print_calls_from(0x008C78C0, "AI_ThreadStart")

# SECTION 4: AI_ThreadJoin (Phase 9 hook target) — does it wait for Linear Tasks?
write("")
write("#" * 70)
write("# SECTION 4: AI_ThreadJoin (0x008C7990) — does it drain Linear Tasks?")
write("#" * 70)

decompile_at(0x008C7990, "AI_ThreadJoin")
find_and_print_calls_from(0x008C7990, "AI_ThreadJoin")

# SECTION 5: StopHavok_DrainAI — the vanilla mechanism
write("")
write("#" * 70)
write("# SECTION 5: StopHavok_DrainAI (FUN_008324e0) — vanilla sync")
write("# Does it properly drain Linear Task Threads?")
write("#" * 70)

decompile_at(0x008324E0, "StopHavok_DrainAI")
find_and_print_calls_from(0x008324E0, "StopHavok_DrainAI")

# SECTION 6: FUN_008325a0 — called by StopHavok_DrainAI, what does it do?
write("")
write("#" * 70)
write("# SECTION 6: FUN_008325a0 — called by StopHavok_DrainAI")
write("#" * 70)

decompile_at(0x008325A0, "StopHavok_SubFunc")

# SECTION 7: FUN_008300c0 — called with 1000ms timeout, what does it wait for?
write("")
write("#" * 70)
write("# SECTION 7: FUN_008300c0 — the actual wait function (timeout=1000ms)")
write("# Does this drain AI Linear Task Threads?")
write("#" * 70)

decompile_at(0x008300C0, "StopHavok_WaitFunc")

# SECTION 8: CellTransitionHandler — how the vanilla game calls StopHavok_DrainAI
write("")
write("#" * 70)
write("# SECTION 8: CellTransitionHandler — vanilla cell transition")
write("# How does it synchronize with AI threads before freeing cells?")
write("#" * 70)

decompile_at(0x008774A0, "CellTransitionHandler", 12000)

# SECTION 9: IOManager_Process Phase 3 — where Linear Task threads are dispatched
write("")
write("#" * 70)
write("# SECTION 9: IOManager_Process — where Linear Tasks get work")
write("#" * 70)

decompile_at(0x00C3DBF0, "IOManager_Process")
find_and_print_calls_from(0x00C3DBF0, "IOManager_Process")

# SECTION 10: What dispatches tasks to AILinearTaskThread?
write("")
write("#" * 70)
write("# SECTION 10: AILinearTaskThread dispatch chain")
write("# What function creates/queues work for Linear Task Threads?")
write("#" * 70)

# Find what references AILinearTaskThread RTTI
refs = ref_mgr.getReferencesTo(toAddr(0x01085688))
addr_list = []
while refs.hasNext():
	ref = refs.next()
	addr_list.append(ref.getFromAddress().getOffset())

for a in addr_list:
	func = fm.getFunctionContaining(toAddr(a))
	if func is not None:
		fname = func.getName()
		faddr = func.getEntryPoint().getOffset()
		write("  0x%08x in %s (0x%08x)" % (a, fname, faddr))

# SECTION 11: Does AI_WaitForWork (0x004424e0) apply to Linear Task Threads?
write("")
write("#" * 70)
write("# SECTION 11: AI_WaitForWork — is this for coordinator or workers?")
write("#" * 70)

decompile_at(0x004424E0, "AI_WaitForWork")
find_refs_to(0x004424E0, "AI_WaitForWork")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/ai_linear_task_thread_lifecycle.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
