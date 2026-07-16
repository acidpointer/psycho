# @category Analysis
# @description Prove whether radio path queries can be batched into one fresh one-to-many search per vanilla refresh

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

def func_for(addr_int):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	return func

def name_for_func(func):
	if func is None:
		return "???"
	return "%s @ 0x%08x" % (func.getName(), func.getEntryPoint().getOffset())

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

def collect_rdata_targets(addr_int):
	targets = {}
	func = func_for(addr_int)
	if func is None:
		return targets
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				continue
			target = ref.getToAddress().getOffset()
			if 0x01000000 <= target < 0x01100000:
				targets[target] = True
	return targets

def table_function_count(base, words):
	count = 0
	for index in range(words):
		value = getInt(toAddr(base + index * 4)) & 0xffffffff
		if fm.getFunctionAt(toAddr(value)) is not None:
			count += 1
	return count

def dump_pointer_table(base, words, label):
	write("")
	write("-" * 70)
	write("Pointer table: %s at 0x%08x" % (label, base))
	write("-" * 70)
	for index in range(words):
		address = base + index * 4
		value = getInt(toAddr(address)) & 0xffffffff
		func = fm.getFunctionAt(toAddr(value))
		write("  +0x%03x 0x%08x -> 0x%08x %s" % (index * 4, address, value, name_for_func(func)))

def audit_referenced_vtables(addr_int, label):
	write("")
	write("=" * 70)
	write("REFERENCED VTABLE CANDIDATES: %s" % label)
	write("=" * 70)
	targets = collect_rdata_targets(addr_int)
	seen_methods = {}
	for target in sorted(targets.keys()):
		function_count = table_function_count(target, 24)
		if function_count < 2:
			continue
		dump_pointer_table(target, 24, "candidate referenced by %s" % label)
		for index in range(24):
			value = getInt(toAddr(target + index * 4)) & 0xffffffff
			func = fm.getFunctionAt(toAddr(value))
			if func is None or value in seen_methods:
				continue
			seen_methods[value] = True
			decompile_at(value, "vtable method from %s slot +0x%X" % (label, index * 4), 40000)
			find_and_print_calls_from(value, "vtable method from %s" % label)
	write("  Unique vtable methods audited: %d" % len(seen_methods))

def main():
	write("RADIO ONE-TO-MANY PATH SEARCH CONTRACT AUDIT")
	write("")
	write("Goal:")
	write("  Avoid every cross-update cache and preserve vanilla radio cadence. Prove")
	write("  whether all player-to-station queries in one FUN_004FF1A0 invocation can")
	write("  share one fresh graph traversal or shortest-path tree, while retaining")
	write("  exact mode-0 distance and mode-2/3 path-domain filtering semantics.")
	query_targets = [
		(0x004FF1A0, "radio station scan and mode-specific result consumer", 110000),
		(0x006F33B0, "path query object constructor", 70000),
		(0x006F3460, "path query object destructor or reset", 70000),
		(0x006F34E0, "single-pair query setup and dispatch", 90000),
		(0x006F36D0, "sibling query setup path", 90000),
		(0x006F3D00, "source seed insertion", 50000),
		(0x006F3D90, "goal search and result production", 50000),
		(0x006F3E30, "search-node lookup or creation", 60000),
		(0x006F3FB0, "graph traversal loop", 100000),
		(0x006F4230, "result-chain extraction", 60000),
		(0x006F4340, "search-node allocation", 50000),
		(0x006F4390, "priority queue insertion", 50000),
		(0x006F4430, "search-node unlink or update", 50000),
		(0x006F45C0, "search traversal scope setup", 50000),
		(0x006F4690, "search traversal scope cleanup", 50000),
		(0x006F46F0, "priority queue pop", 50000),
		(0x006F4790, "priority bucket selection", 50000),
		(0x006B8490, "query neighbor expansion virtual-method candidate", 110000),
		(0x006B9130, "path node cost accessor", 30000),
		(0x006B9710, "path node priority accessor", 30000),
	]
	audit_targets(query_targets)
	audit_referenced_vtables(0x006F33B0, "path query constructor")
	audit_referenced_vtables(0x006B5C30, "path manager constructor")
	disasm_range(0x004FF430, 0x004FF690, "radio modes 2 and 3 query setup and final filtering")
	disasm_range(0x006F3F80, 0x006F4230, "graph traversal virtual goal and neighbor dispatch")
	find_refs_to(0x006B8490, "query neighbor expansion candidate including indirect gaps")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/radio_one_to_many_path_search_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	decomp.dispose()

main()
