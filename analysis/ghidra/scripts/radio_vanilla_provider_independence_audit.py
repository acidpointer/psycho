# @category Analysis
# @description Prove the vanilla radio provider policy bypass and temporary-data cleanup contract

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
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
	write("  Total: %d calls" % count)

def audit(addr_int, label, max_len):
	decompile_at(addr_int, label, max_len)
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

def main():
	write("RADIO VANILLA PROVIDER INDEPENDENCE AUDIT")
	write("")
	write("Prove the exact vanilla provider, policy setup, accessibility,")
	write("and temporary lock-data cleanup contract needed when Stewie")
	write("does not own vtable slot 0x0106D900.")
	targets = [
		(0x006F36D0, "vanilla teleport-door provider", 90000),
		(0x00501D20, "vanilla teleport-door policy setup", 50000),
		(0x00501E50, "vanilla teleport-door policy cleanup", 20000),
		(0x00502450, "vanilla teleport-door accessibility predicate", 50000),
	]
	audit_targets(targets)
	disasm_range(0x006F36D0, 0x006F376A, "provider identity and disposition admission")
	disasm_range(0x006F3868, 0x006F3930, "setup, accessibility, disposition, and minimum-use branches")
	disasm_range(0x006F39C8, 0x006F39E1, "early policy cleanup")
	disasm_range(0x006F3ACC, 0x006F3AEC, "normal policy cleanup")
	disasm_range(0x00501E50, 0x00501E7A, "cleanup reads and frees only lock-data field plus 0x08")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/radio_vanilla_provider_independence_audit.txt"
	final_line_count = len(output) + 2
	write("")
	write("AUDIT COMPLETE - output written to %s (%d lines)" % (outpath, final_line_count))
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	decomp.dispose()

main()
