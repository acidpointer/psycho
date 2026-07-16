# @category Analysis
# @description Prove the vanilla teleport-door candidate enumeration, array ownership, and scan-local sharing boundary

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

def audit(addr_int, label, max_len=50000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def audit_targets(targets):
	for item in targets:
		audit(item[0], item[1], item[2])

def audit_direct_callees(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("=" * 70)
	write("DIRECT CALLEES: %s" % label)
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	seen = {}
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if not ref.getReferenceType().isCall():
				continue
			target = ref.getToAddress().getOffset()
			if target in seen:
				continue
			seen[target] = True
			target_func = fm.getFunctionAt(toAddr(target))
			name = target_func.getName() if target_func else "???"
			decompile_at(target, "direct callee %s from %s" % (name, label), 30000)

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
	write("RADIO TELEPORT-DOOR CANDIDATE BOUNDARY AUDIT")
	write("")
	write("Goal:")
	write("  Prove whether FUN_0054DB50 is a query-independent cell-to-door")
	write("  enumeration boundary whose pointer results can be memoized only for")
	write("  one synchronous FUN_004FF1A0 radio scan. Preserve every dynamic")
	write("  filter, cost, query-node, predecessor, and final-distance operation.")
	targets = [
		(0x0054DB50, "vanilla cell teleport-door candidate enumeration", 70000),
		(0x006F36D0, "vanilla TeleportDoorSearch neighbor expansion", 100000),
		(0x007CB2E0, "candidate array append helper", 50000),
		(0x008454F0, "candidate array clear or destroy helper", 50000),
		(0x0044DDC0, "candidate array count helper", 30000),
		(0x00877A30, "candidate array element accessor", 30000),
	]
	audit_targets(targets)
	disasm_range(0x0054DB50, 0x0054DBF6, "candidate enumeration and lock span")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/radio_teleport_door_candidate_boundary_audit.txt"
	final_line_count = len(output) + 2
	write("")
	write("AUDIT COMPLETE - output written to %s (%d lines)" % (outpath, final_line_count))
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	decomp.dispose()

main()
