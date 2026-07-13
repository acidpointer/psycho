# @category Analysis
# @description Resolve the worker quiescence and lock ownership contract around FalloutNV save serialization

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
		if count > 120:
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
	inst_iter = listing.getInstructions(body, True)
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

def audit_function(addr_int, label, max_len=26000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def audit_targets():
	targets = [
		(0x00850BA0, "pre-save quiescence owner", 24000),
		(0x00850BF0, "post-save quiescence release owner", 20000),
		(0x006EBC70, "pre-save task or worker transition", 32000),
		(0x006EBC90, "pre-save task completion predicate", 30000),
		(0x006EBC50, "pre-save wait-loop progress function", 30000),
		(0x006EBCD0, "post-save task or worker transition", 26000),
		(0x006EB820, "task manager singleton constructor", 32000),
		(0x006EB3B0, "post-save worker resume implementation", 32000),
		(0x00C3E310, "global synchronization enter operation", 28000),
		(0x00C3E340, "global synchronization leave operation", 28000),
		(0x00C3E7D0, "related synchronization operation", 28000),
		(0x00844700, "changed-form map insertion", 26000),
		(0x00405430, "changed-form map removal", 26000),
		(0x008457B0, "save traversal map insertion owner", 30000),
		(0x00845A80, "save traversal map removal owner", 30000),
	]
	for item in targets:
		audit_function(item[0], item[1], item[2])

def audit_globals_and_callsites():
	find_refs_to(0x011C5290, "task manager singleton storage")
	find_refs_to(0x01202D98, "global save synchronization object")
	disasm_range(0x00850B80, 0x00850C20, "pre-save and post-save synchronization sequence")
	disasm_range(0x006EBC30, 0x006EBD20, "worker transition family")
	disasm_range(0x00C3E2D0, 0x00C3E390, "global synchronization enter and leave family")

def main():
	write("=" * 70)
	write("SAVE BARRIER SCOPE FOLLOW-UP")
	write("=" * 70)
	write("Questions: which worker families stop before serialization, what condition proves quiescence, and whether every changed-form map mutator participates in the same barrier or lock.")
	audit_targets()
	audit_globals_and_callsites()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/save_barrier_scope_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
