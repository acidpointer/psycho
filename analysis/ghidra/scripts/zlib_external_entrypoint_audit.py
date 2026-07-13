# @category Analysis
# @description Enumerate every FalloutNV.exe call entering the complete embedded zlib code range

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

def scan_external_zlib_calls(range_start, range_end):
	write("")
	write("=" * 70)
	write("EXTERNAL CALLS INTO ZLIB 0x%08x-0x%08x" % (range_start, range_end))
	write("=" * 70)
	function_iter = fm.getFunctions(True)
	entries = []
	targets = []
	count = 0
	while function_iter.hasNext():
		func = function_iter.next()
		source_entry = func.getEntryPoint().getOffset()
		if source_entry >= range_start and source_entry < range_end:
			continue
		inst_iter = listing.getInstructions(func.getBody(), True)
		while inst_iter.hasNext():
			inst = inst_iter.next()
			refs = inst.getReferencesFrom()
			for ref in refs:
				if not ref.getReferenceType().isCall():
					continue
				target = ref.getToAddress().getOffset()
				if target < range_start or target >= range_end:
					continue
				target_func = fm.getFunctionAt(toAddr(target))
				target_name = target_func.getName() if target_func else "???"
				write("  0x%08x %s -> 0x%08x %s" % (inst.getAddress().getOffset(), func.getName(), target, target_name))
				count += 1
				if source_entry not in entries:
					entries.append(source_entry)
				if target not in targets:
					targets.append(target)
	write("  Total external calls: %d" % count)
	write("  Unique source functions: %d" % len(entries))
	write("  Unique zlib entry targets: %d" % len(targets))
	for target in targets:
		find_refs_to(target, "external zlib entry")
		decompile_at(target, "external zlib entry", 10000)
	for entry in entries:
		decompile_at(entry, "external zlib caller", 12000)

def main():
	write("ZLIB EXTERNAL ENTRYPOINT AUDIT")
	write("=" * 70)
	scan_external_zlib_calls(0x00B43E00, 0x00B4E000)
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/zlib_external_entrypoint_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
