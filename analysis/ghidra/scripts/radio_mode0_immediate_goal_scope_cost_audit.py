# @category Analysis
# @description Prove the mode-0 immediate-goal path and traversal-scope side effects for the radio scan fast path

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
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
		if len(code) > max_len:
			write("  [decompile truncated at %d chars, total %d]" % (max_len, len(code)))
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
		if count > 200:
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
	inst_iter = listing.getInstructions(func.getBody(), True)
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

def audit(addr_int, label, max_len=50000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def audit_targets(targets):
	for item in targets:
		audit(item[0], item[1], item[2])

def disasm_range(start_int, end_int, label):
	write("")
	write("-" * 70)
	write("Disassembly: %s (0x%08x - 0x%08x)" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	while inst is not None and inst.getAddress().getOffset() <= end_int:
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()

def print_data_refs(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("-" * 70)
	write("Direct data references: %s" % label)
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	seen = {}
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				continue
			target = ref.getToAddress().getOffset()
			if target < 0x01000000:
				continue
			key = (target, inst.getAddress().getOffset(), str(ref.getReferenceType()))
			if key in seen:
				continue
			seen[key] = True
			write("  0x%08x %s from 0x%08x" % (target, ref.getReferenceType(), inst.getAddress().getOffset()))
	write("  Total direct data refs: %d" % len(seen))

def main():
	write("RADIO MODE-0 IMMEDIATE-GOAL SCOPE COST AUDIT")
	write("")
	write("Runtime fact to explain:")
	write("  Each slow scan executes 12 query-mode-0 traversals, consuming about")
	write("  41 ms total, while FUN_006F36D0 neighbor expansion executes zero times.")
	write("  Prove whether the source node immediately satisfies FUN_006F3B00 and")
	write("  whether traversal setup/cleanup can be skipped without losing required")
	write("  lock, TLS, heap, task, or result-object side effects.")
	targets = [
		(0x006D4EB0, "mode-0 radio distance wrapper", 50000),
		(0x006D4D20, "generic path query wrapper", 90000),
		(0x006F34E0, "query setup source and goal descriptors", 90000),
		(0x006F3D00, "source seed insertion", 50000),
		(0x006F3D90, "goal search and result extraction owner", 60000),
		(0x006F3B00, "radio query goal predicate", 50000),
		(0x006F3FB0, "traversal with immediate-goal branch", 100000),
		(0x006F4230, "result-chain extraction", 70000),
		(0x006F45C0, "traversal scope setup", 60000),
		(0x006F4690, "traversal scope cleanup", 60000),
		(0x006F46F0, "priority queue pop", 60000),
		(0x006F4880, "scope base constructor", 60000),
		(0x006F4640, "scope base destructor", 60000),
		(0x006B3EB0, "scope setup terminal callee", 100000),
		(0x00AA42E0, "game TLS accessor", 60000),
		(0x008454F0, "task stack or scope cleanup helper", 80000),
		(0x006F3460, "path query destructor", 80000),
		(0x006F3C80, "path query search-state cleanup", 80000),
		(0x006F49C0, "mode-0 path result distance consumer", 80000),
	]
	audit_targets(targets)
	print_data_refs(0x006F45C0, "traversal scope setup")
	print_data_refs(0x006F4690, "traversal scope cleanup")
	print_data_refs(0x006B3EB0, "scope setup terminal callee")
	print_data_refs(0x008454F0, "task stack or scope cleanup helper")
	disasm_range(0x006F3D90, 0x006F4230, "goal owner, traversal, immediate goal, and result handoff")
	disasm_range(0x006F45C0, 0x006F48AF, "scope setup, cleanup, queue pop, and adjacent helpers")
	disasm_range(0x006B3EB0, 0x006B3F80, "scope terminal callee body and return ABI")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/radio_mode0_immediate_goal_scope_cost_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	decomp.dispose()

main()
