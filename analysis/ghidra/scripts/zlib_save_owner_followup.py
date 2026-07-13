# @category Analysis
# @description Resolve the runtime owner and frequency contract of the save deflate path

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

def print_unique_callers(target_addr, label, max_len=12000):
	write("")
	write("=" * 70)
	write("UNIQUE CALLERS OF %s (0x%08x)" % (label, target_addr))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(target_addr))
	callers = []
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		if entry not in callers:
			callers.append(entry)
	write("  Unique caller functions: %d" % len(callers))
	for entry in callers:
		decompile_at(entry, "%s caller" % label, max_len)
		find_refs_to(entry, "%s caller" % label)
		find_and_print_calls_from(entry, "%s caller" % label)

def main():
	write("ZLIB SAVE OWNER FOLLOW-UP")
	write("=" * 70)
	decompile_at(0x00538110, "direct owner of record deflate", 20000)
	find_refs_to(0x00538110, "direct owner of record deflate")
	find_and_print_calls_from(0x00538110, "direct owner of record deflate")
	print_unique_callers(0x00538110, "direct owner of record deflate", 18000)
	find_refs_to(0x011C54CC, "record output buffer global")
	find_refs_to(0x011C54D0, "record output size global")
	find_refs_to(0x00483D70, "record deflate function")
	decompile_at(0x00483CF0, "record buffer setup neighborhood", 12000)
	decompile_at(0x00483FC0, "record deflate continuation neighborhood", 12000)
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/zlib_save_owner_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
