# @category Analysis
# @description Find a record-local malformed-load rejection boundary that preserves safety without per-field thread and global-state checks

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
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

def audit_function(addr_int, label, max_len=20000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def print_pointer_table(start_int, count, label):
	write("")
	write("-" * 70)
	write("Pointer table: %s @ 0x%08x" % (label, start_int))
	write("-" * 70)
	index = 0
	while index < count:
		entry_addr = start_int + index * 4
		try:
			value = memory.getInt(toAddr(entry_addr)) & 0xffffffff
			func = fm.getFunctionAt(toAddr(value))
			name = func.getName() if func else "???"
			write("  +0x%02x 0x%08x -> 0x%08x %s" % (index * 4, entry_addr, value, name))
		except:
			write("  +0x%02x 0x%08x [unreadable]" % (index * 4, entry_addr))
		index += 1

def audit_targets():
	targets = [
		(0x008643B0, "changed-record object constructor and embedded buffer", 18000),
		(0x00864450, "embedded record-buffer initialization", 14000),
		(0x008644B0, "changed-record disk header reader", 18000),
		(0x00864540, "record payload-consumption result", 14000),
		(0x00864580, "record payload skip owner", 14000),
		(0x008646B0, "record buffer base constructor", 14000),
		(0x00864740, "physical payload size transition", 16000),
		(0x00864790, "physical payload copy or cursor owner", 22000),
		(0x008647F0, "record buffer allocation and publication", 24000),
		(0x00864820, "unchecked in-memory field reader", 20000),
		(0x00864980, "fixed-size field reader", 14000),
		(0x008649A0, "length-prefixed string reader", 20000),
		(0x00864A60, "variable-width scalar reader", 20000),
		(0x00864E20, "record framing and payload acquisition", 24000),
		(0x00848D90, "record-local rejection flag writer", 14000),
		(0x00848DD0, "record-local rejection predicate", 14000),
		(0x00849D00, "record application owner consuming field readers", 36000),
		(0x00847DF0, "two-pass owner consuming record rejection", 46000),
	]
	for item in targets:
		audit_function(item[0], item[1], item[2])

def audit_exact_contract():
	print_pointer_table(0x01082028, 12, "changed-record vtable")
	print_pointer_table(0x01082048, 8, "record-buffer base vtable")
	disasm_range(0x008643B0, 0x008645C0, "record layout, header read, remaining length, and skip")
	disasm_range(0x008646B0, 0x008648A0, "buffer ownership, allocation, size, cursor, and unchecked copy")
	disasm_range(0x008648A0, 0x00864B10, "all direct in-memory reader wrappers")
	disasm_range(0x00848320, 0x00848620, "first-pass record rejection observation")
	disasm_range(0x008487A0, 0x00848A60, "second-pass record rejection and payload skip")

def main():
	write("=" * 70)
	write("SAVE LOAD HOT-PATH REJECTION-BOUNDARY AUDIT")
	write("=" * 70)
	write("Prove whether the record object itself owns the buffer, size, cursor, and rejection bit, and whether a checked reader can mark only that record without GetCurrentThreadId or global atomics on every valid field read.")
	audit_targets()
	audit_exact_contract()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/save_load_hotpath_rejection_boundary_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
