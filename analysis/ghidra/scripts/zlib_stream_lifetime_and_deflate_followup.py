# @category Analysis
# @description Resolve save deflate calls and CompressedArchiveFile stream/thread lifetime

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
	write("Disassembly %s: 0x%08x - 0x%08x" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	while inst is not None and inst.getAddress().getOffset() <= end_int:
		call_info = ""
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				call_info = " -> 0x%08x %s" % (tgt, name)
		write("  0x%08x: %s%s" % (inst.getAddress().getOffset(), inst, call_info))
		inst = inst.getNext()

def print_unique_callers(target_addr, label, max_len=9000):
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

def print_zlib_targets_from(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		return
	targets = []
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if not ref.getReferenceType().isCall():
				continue
			target = ref.getToAddress().getOffset()
			if target >= 0x00B40000 and target < 0x00B50000 and target not in targets:
				targets.append(target)
	write("")
	write("=" * 70)
	write("ZLIB TARGETS FROM %s" % label)
	write("=" * 70)
	for target in targets:
		target_func = fm.getFunctionAt(toAddr(target))
		name = target_func.getName() if target_func else "???"
		write("  0x%08x %s" % (target, name))
		find_refs_to(target, name)
		decompile_at(target, "zlib target %s" % name, 10000)

def main():
	write("ZLIB STREAM LIFETIME AND SAVE DEFLATE FOLLOW-UP")
	write("=" * 70)
	decompile_at(0x00483D70, "save serialization zlib deflate owner", 18000)
	disasm_range(0x00483D70, 0x00483F20, "save deflate construction and calls")
	find_refs_to(0x00483D70, "save serialization zlib deflate owner")
	find_and_print_calls_from(0x00483D70, "save serialization zlib deflate owner")
	print_zlib_targets_from(0x00483D70, "save serialization")
	decompile_at(0x00AFA550, "compressed archive constructor caller A", 14000)
	decompile_at(0x00AFA750, "compressed archive constructor caller B", 14000)
	decompile_at(0x00AFC660, "compressed archive virtual read adapter", 10000)
	decompile_at(0x00AFC6F0, "compressed archive deleting destructor adapter", 8000)
	find_refs_to(0x00AFA550, "compressed archive constructor caller A")
	find_refs_to(0x00AFA750, "compressed archive constructor caller B")
	find_refs_to(0x00AFC660, "compressed archive virtual read adapter")
	print_unique_callers(0x00AFA550, "compressed archive constructor caller A")
	print_unique_callers(0x00AFA750, "compressed archive constructor caller B")
	print_unique_callers(0x00AFC660, "compressed archive virtual read adapter")
	decompile_at(0x00AFB300, "ArchiveFile base constructor and input buffer policy", 16000)
	decompile_at(0x00AFB7A0, "ArchiveFile compressed-input refill", 14000)
	decompile_at(0x00AF43A0, "BSA buffer-cap writer A", 10000)
	decompile_at(0x00AF4540, "BSA buffer-cap writer B", 10000)
	find_refs_to(0x00AFB7A0, "ArchiveFile compressed-input refill")
	find_refs_to(0x00AF43A0, "BSA buffer-cap writer A")
	find_refs_to(0x00AF4540, "BSA buffer-cap writer B")
	find_and_print_calls_from(0x00AFA550, "compressed archive constructor caller A")
	find_and_print_calls_from(0x00AFA750, "compressed archive constructor caller B")
	find_and_print_calls_from(0x00AFC660, "compressed archive virtual read adapter")
	find_and_print_calls_from(0x00AFB7A0, "ArchiveFile compressed-input refill")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/zlib_stream_lifetime_and_deflate_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
