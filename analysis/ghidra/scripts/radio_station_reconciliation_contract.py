# @category Analysis
# @description Resolve radio station load reconciliation, invalid-form detection, and safe unlink ownership

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

def audit(addr_int, label, max_len=30000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def main():
	write("=" * 70)
	write("RADIO STATION RECONCILIATION CONTRACT")
	write("=" * 70)
	write("The load reconciliation at 0x00836AF0 removes a registered entry only when its wrapper is NULL or its first form pointer becomes NULL after 0x00836660. Determine why a missing/unloaded form can remain nonzero, and identify the exact load-boundary validation and unlink/destructor calls that are safe for that entry.")
	audit(0x00835F80, "deserialize found-radio entry", 40000)
	audit(0x00835FE0, "reconcile found-radio entry", 40000)
	audit(0x00836630, "deserialize registered-radio wrapper", 50000)
	audit(0x00836660, "resolve registered-radio wrapper form", 50000)
	audit(0x008366C0, "post-load registered-radio finalizer", 40000)
	audit(0x00832CB0, "registered-radio wrapper creator", 50000)
	audit(0x008327D0, "registered-radio wrapper constructor", 30000)
	audit(0x00833150, "serialized registered-radio constructor", 30000)
	audit(0x00832160, "registered-radio wrapper destructor", 40000)
	audit(0x00832190, "found-radio entry destructor", 40000)
	audit(0x008256D0, "list iterator end predicate", 12000)
	audit(0x006815C0, "list node payload accessor", 12000)
	audit(0x00726070, "list next-node accessor", 12000)
	audit(0x0063F7B0, "remove current or head list node", 30000)
	audit(0x00905330, "remove successor list node", 30000)
	audit(0x005AE3D0, "append list payload", 30000)
	audit(0x004702F0, "free list node", 20000)
	audit(0x0084BE40, "radio load read stage", 30000)
	audit(0x0084C030, "radio load reconcile stage", 30000)
	audit(0x0084C190, "radio load finalize stage", 30000)
	audit(0x0084C330, "radio load reset stage", 30000)
	disasm_range(0x00836B20, 0x00836C10, "registered list resolve and invalid-entry unlink")
	disasm_range(0x00836630, 0x008366C0, "registered wrapper deserialize and resolve")
	disasm_range(0x0084BFC0, 0x0084C240, "load-stage ordering around reconcile and finalize")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/radio_station_reconciliation_contract.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
