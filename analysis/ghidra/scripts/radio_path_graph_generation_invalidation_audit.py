# @category Analysis
# @description Prove path graph identity, mutation, and generation contracts required for non-throttled radio optimization

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

def audit(addr_int, label, max_len=40000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def audit_targets(targets):
	for item in targets:
		audit(item[0], item[1], item[2])

def collect_direct_data_targets(targets):
	data_targets = {}
	for item in targets:
		func = func_for(item[0])
		if func is None:
			continue
		inst_iter = listing.getInstructions(func.getBody(), True)
		while inst_iter.hasNext():
			inst = inst_iter.next()
			refs = inst.getReferencesFrom()
			for ref in refs:
				if ref.getReferenceType().isCall():
					continue
				target = ref.getToAddress().getOffset()
				if 0x01000000 <= target < 0x01400000:
					data_targets[target] = True
	return sorted(data_targets.keys())

def print_data_targets_and_writers(targets):
	globals_found = collect_direct_data_targets(targets)
	write("")
	write("=" * 70)
	write("DIRECT GLOBALS READ OR WRITTEN BY PATH GRAPH TARGETS")
	write("=" * 70)
	for target in globals_found:
		write("")
		write("Global 0x%08x" % target)
		refs = ref_mgr.getReferencesTo(toAddr(target))
		count = 0
		write_count = 0
		while refs.hasNext():
			ref = refs.next()
			ref_type = str(ref.getReferenceType())
			from_func = fm.getFunctionContaining(ref.getFromAddress())
			if "WRITE" in ref_type:
				write("  WRITER %s @ 0x%08x in %s" % (ref_type, ref.getFromAddress().getOffset(), name_for_func(from_func)))
				write_count += 1
			count += 1
			if count >= 300:
				write("  ... references truncated at 300")
				break
		write("  writers=%d references_scanned=%d" % (write_count, count))
	write("  Total direct globals: %d" % len(globals_found))

def print_manager_accessor_callers():
	write("")
	write("=" * 70)
	write("PATH MANAGER ACCESSOR CALLERS")
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(0x0045AF00))
	seen = {}
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		if entry in seen:
			continue
		seen[entry] = True
		write("  caller %s" % name_for_func(func))
		find_and_print_calls_from(entry, "path manager accessor caller")

def main():
	write("RADIO PATH GRAPH GENERATION AND INVALIDATION AUDIT")
	write("")
	write("Goal:")
	write("  Preserve every vanilla radio update while proving whether modes 2/3 can")
	write("  reuse only their connectivity predicate. Identify canonical graph identity,")
	write("  every graph mutation boundary, and a monotonic generation or complete")
	write("  invalidation set. Do not cache station lists, strength, or mode-0 distance.")
	core_targets = [
		(0x0045AF00, "pathfinding manager accessor", 50000),
		(0x006B5C30, "pathfinding manager constructor", 70000),
		(0x006DCD70, "radio endpoint geometry construction", 70000),
		(0x006D6F40, "cell geometry identity lookup", 50000),
		(0x006D6F60, "worldspace-grid geometry identity lookup", 50000),
		(0x006B77E0, "cell geometry identity implementation", 50000),
		(0x006B7850, "worldspace-grid geometry identity implementation", 50000),
		(0x006D4D20, "radio path query wrapper", 60000),
		(0x006F34E0, "path query setup and dispatch", 90000),
		(0x006F3E30, "path search seed lookup", 70000),
		(0x006F3FB0, "path graph search", 100000),
		(0x006F4230, "path result extraction", 70000),
		(0x006F4390, "path search seed insertion", 60000),
		(0x006B51A0, "path manager lifecycle caller", 90000),
		(0x006B6C60, "worldspace-grid identity caller", 90000),
		(0x006B8490, "path manager graph operation", 90000),
		(0x006DF010, "path manager user", 70000),
		(0x008774A0, "cell transition destruction boundary", 70000),
		(0x00836AF0, "radio load reconciliation boundary", 70000),
	]
	audit_targets(core_targets)
	print_manager_accessor_callers()
	print_data_targets_and_writers(core_targets)
	find_refs_to(0x0102583C, "path geometry vtable")
	find_refs_to(0x011C8264, "radio scan list root")
	find_refs_to(0x011DD554, "registered radio list root")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/radio_path_graph_generation_invalidation_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
