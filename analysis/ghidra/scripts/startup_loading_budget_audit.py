# @category Analysis
# @description Audit ModelLoader wait loop, main-thread completion drain budget, and timing contracts

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=12000):
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
		if count > 80:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	write("")
	write("-" * 70)
	write("Calls FROM 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	addr_iter = func.getBody().getAddresses(True)
	count = 0
	while addr_iter.hasNext():
		a = addr_iter.next()
		inst = listing.getInstructionAt(a)
		if inst is None:
			continue
		if not inst.getFlowType().isCall():
			continue
		refs_from = inst.getReferencesFrom()
		for ref in refs_from:
			target = ref.getToAddress().getOffset()
			target_func = fm.getFunctionAt(toAddr(target))
			target_name = target_func.getName() if target_func else "unknown_0x%08x" % target
			write("  CALL 0x%08x -> %s (from 0x%08x)" % (target, target_name, a.getOffset()))
			count += 1
	write("  Total: %d calls" % count)

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionBefore(toAddr(center_int))
	count = 0
	while inst is not None and count < before_count:
		prev = inst.getPrevious()
		if prev is None:
			break
		inst = prev
		count += 1
	idx = 0
	limit = before_count + after_count + 1
	while inst is not None and idx < limit:
		marker = " << TARGET" if inst.getAddress().getOffset() == center_int else ""
		write("  0x%08x: %-38s%s" % (inst.getAddress().getOffset(), inst.toString(), marker))
		inst = inst.getNext()
		idx += 1

def scan_callers_to(addr_int, label):
	write("")
	write("=" * 70)
	write("CALLER SCAN: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_addr = ref.getFromAddress()
		from_func = fm.getFunctionContaining(from_addr)
		fname = from_func.getName() if from_func else "???"
		write("")
		write("Caller %d: %s @ 0x%08x in %s" % (count + 1, ref.getReferenceType(), from_addr.getOffset(), fname))
		disasm_window(from_addr.getOffset(), 10, 24, "caller of %s" % label)
		if from_func is not None:
			decompile_at(from_func.getEntryPoint().getOffset(), "Caller function %s" % fname, 6000)
		count += 1
		if count >= 40:
			write("  ... caller scan truncated")
			break
	write("Total callers printed: %d" % count)

def read_dword(addr_int, label):
	write("")
	write("-" * 70)
	write("DWORD %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	try:
		val = getInt(toAddr(addr_int)) & 0xffffffff
		write("  value: 0x%08x (%d)" % (val, val))
	except:
		write("  [read failed]")

def read_float(addr_int, label):
	write("")
	write("-" * 70)
	write("FLOAT %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	try:
		val = getFloat(toAddr(addr_int))
		write("  value: %f" % val)
	except:
		write("  [read failed]")

def analyze_wait_and_budget():
	write("")
	write("=" * 70)
	write("WAIT AND BUDGET PATCH SURFACES")
	write("=" * 70)
	disasm_window(0x00c3e105, 12, 24, "ModelLoader Sleep(50) poll wait")
	disasm_window(0x00c3dd0a, 18, 44, "main-thread completion drain budget setup")
	disasm_window(0x00c3dda5, 18, 40, "main-thread completion drain elapsed check")
	disasm_window(0x0086e897, 12, 20, "outer main-loop completion drain call")
	disasm_window(0x0086b3d3, 12, 20, "outer load loop Sleep(50) candidate A")
	disasm_window(0x0086b62e, 12, 20, "outer load loop Sleep(50) candidate B")

def analyze_core_functions():
	targets = [
		(0x00c3dbf0, "Main-thread completed task drain"),
		(0x00c3dfa0, "ModelLoader wait/drain loop"),
		(0x00c3e1b0, "ModelLoader batch enqueue/start"),
		(0x00c3e420, "Completed-task pop/dequeue helper"),
		(0x00c3e860, "Pending/expected task count helper"),
		(0x00aa4d80, "QPC tick/time helper"),
		(0x00ec62f6, "completion drain time-budget helper"),
		(0x0086e650, "main loop caller of IO drain"),
		(0x0086b380, "outer load wait loop candidate A"),
		(0x0086b5e0, "outer load wait loop candidate B")
	]
	for item in targets:
		decompile_at(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])

def analyze_refs():
	find_refs_to(0x00c3dbf0, "main-thread completed task drain")
	find_refs_to(0x00c3dfa0, "ModelLoader wait/drain loop")
	find_refs_to(0x00aa4d80, "QPC tick/time helper")
	find_refs_to(0x00ec62f6, "completion drain time-budget helper")
	find_refs_to(0x01202800, "completion drain budget/global milliseconds candidate")
	find_refs_to(0x011ac39c, "QPC ticks-per-millisecond scalar")
	find_refs_to(0x01202dd8, "main-thread drain reentrancy flag")
	find_refs_to(0x011af70c, "ModelLoader loading-complete flag")
	scan_callers_to(0x00ec62f6, "completion drain time-budget helper")

def main():
	write("=" * 70)
	write("STARTUP LOADING BUDGET AUDIT")
	write("=" * 70)
	write("Goal:")
	write("  Find whether the loader is slow because it sleeps while worker progress is pending,")
	write("  or because the main thread stops draining completed tasks after a tiny time budget.")
	write("")
	write("Interpretation rule:")
	write("  Worker-count changes alter queue topology and are rejected unless this audit disproves")
	write("  the completion-queue null crash contract, which current evidence does not.")
	analyze_wait_and_budget()
	analyze_core_functions()
	analyze_refs()
	read_dword(0x01202800, "completion drain budget/global milliseconds candidate")
	read_float(0x011ac39c, "QPC ticks-per-millisecond scalar")
	read_dword(0x01202dd8, "main-thread drain reentrancy flag initial value")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/startup_loading_budget_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
