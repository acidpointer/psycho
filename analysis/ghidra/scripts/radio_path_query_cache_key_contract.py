# @category Analysis
# @description Recover the exact radio path-query inputs, outputs, mutable engine state, and safe cache-key contract

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

def disassemble_range(start, end, label):
	write("")
	write("-" * 70)
	write("Disassembly: %s (0x%08x - 0x%08x)" % (label, start, end))
	write("-" * 70)
	listing = currentProgram.getListing()
	address = toAddr(start)
	while address.getOffset() < end:
		instruction = listing.getInstructionAt(address)
		if instruction is None:
			address = address.add(1)
			continue
		write("  0x%08x: %s" % (address.getOffset(), instruction))
		address = instruction.getNext().getAddress()

def audit(addr_int, label, max_len=50000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def main():
	write("RADIO PATH QUERY CACHE-KEY CONTRACT")
	write("Determine whether the expensive radio path query can be cached below the station scan without stale distance or signal results. Identify every position, cell, navmesh, mode, and global pathfinder value consumed by the query and every output observed by the caller.")
	audit(0x004FF1A0, "radio station scan and query result consumer", 70000)
	audit(0x006D4D20, "expensive path query wrapper", 50000)
	audit(0x006D4EB0, "radio distance helper", 50000)
	audit(0x006D4F70, "sibling path query wrapper", 50000)
	audit(0x006DCD70, "reference-to-path-geometry constructor", 50000)
	audit(0x006DD280, "path geometry field population", 50000)
	audit(0x006DCCE0, "pathfinder query input setup", 50000)
	audit(0x006DD4F0, "pathfinder world or navmesh accessor", 40000)
	audit(0x00441110, "alternate pathfinder world or navmesh accessor", 40000)
	audit(0x006F34E0, "pathfinder query implementation", 70000)
	audit(0x006F3D00, "path query state setup", 50000)
	audit(0x006F3D90, "path query solver and result production", 70000)
	audit(0x006CEE30, "pathfinder synchronization entry", 30000)
	audit(0x006CEEA0, "pathfinder synchronization exit", 30000)
	disassemble_range(0x004FF430, 0x004FF690, "radio modes 2 and 3 query argument setup and result use")
	disassemble_range(0x006D4D20, 0x006D4E84, "expensive wrapper stack objects and cleanup")
	disassemble_range(0x006F34E0, 0x006F36CD, "pathfinder input writes and solver call")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/radio_path_query_cache_key_contract.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
