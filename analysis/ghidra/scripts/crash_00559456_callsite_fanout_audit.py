# @category Analysis
# @description Compact callsite fanout audit for FUN_00559450 around crash 0x00559456

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

def decompile_at(addr_int, label, max_len=12000):
	addr = toAddr(addr_int)
	func = func_for(addr_int)
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
			write("  [decompile truncated at %d chars]" % max_len)
	else:
		write("  [decompilation failed]")

def find_and_print_calls_from_func(func, label, limit=120):
	write("")
	write("-" * 70)
	write("Calls FROM %s" % label)
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionContaining(ref.getToAddress())
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name_for_func(tgt_func)))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def disasm_window(start_int, length, label, highlights, max_inst=100):
	end_int = start_int + length
	write("")
	write("-" * 70)
	write("Disassembly: %s 0x%08x..0x%08x" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	count = 0
	while inst is not None and inst.getAddress().getOffset() < end_int:
		off = inst.getAddress().getOffset()
		mark = "   "
		for item in highlights:
			if off == item:
				mark = "=> "
		write("%s0x%08x: %s" % (mark, off, inst.toString()))
		inst = inst.getNext()
		count += 1
		if count >= max_inst:
			write("  ... (truncated at %d instructions)" % max_inst)
			break
	write("  Instructions printed: %d" % count)

def in_relevant_range(addr_int):
	ranges = [
		(0x00440000, 0x00460000),
		(0x00540000, 0x00570000),
		(0x00868000, 0x00870000),
		(0x0094C000, 0x0094E000),
	]
	for item in ranges:
		if addr_int >= item[0] and addr_int < item[1]:
			return True
	return False

def add_unique_func(funcs, func):
	if func is None:
		return
	entry = func.getEntryPoint().getOffset()
	for item in funcs:
		if item.getEntryPoint().getOffset() == entry:
			return
	funcs.append(func)

def scan_function_for_text(func, label, needles, limit=120):
	write("")
	write("-" * 70)
	write("Instruction text scan: %s" % label)
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		matched = False
		for needle in needles:
			if needle.lower() in text:
				matched = True
		if matched:
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				break
	write("  Total matches: %d" % count)

def audit_fun_00559450_relevant_calls():
	write("")
	write("=" * 70)
	write("RELEVANT CALLS TO FUN_00559450")
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(0x00559450))
	funcs = []
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_addr = ref.getFromAddress().getOffset()
		if not in_relevant_range(from_addr):
			continue
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("  callsite 0x%08x in %s" % (from_addr, name_for_func(from_func)))
		disasm_window(max(0, from_addr - 0x24), 0x70, "FUN_00559450 relevant callsite", [from_addr], 80)
		add_unique_func(funcs, from_func)
		count += 1
	write("  Relevant callsites printed: %d" % count)
	audit_unique_funcs(funcs)

def audit_unique_funcs(funcs):
	write("")
	write("=" * 70)
	write("UNIQUE RELEVANT CALLER FUNCTIONS")
	write("=" * 70)
	for func in funcs:
		entry = func.getEntryPoint().getOffset()
		label = "caller of FUN_00559450 %s" % name_for_func(func)
		decompile_at(entry, label, 12000)
		find_and_print_calls_from_func(func, label, 160)
		scan_function_for_text(func, label, ["00559450", "00401000", "0x50", "+ 0x20", "+ 0x30", "+ 0x34", "[edx", "[ecx"], 120)

def audit_crash_chain_frames():
	items = [
		(0x0044C4FA, "ESP[0] return address"),
		(0x00449C90, "CrashLogger frame 1"),
		(0x00449C3F, "CrashLogger frame 2"),
		(0x00449A5F, "CrashLogger frame 3"),
		(0x00446C55, "CrashLogger frame 4"),
		(0x0094CFDB, "CrashLogger frame 5"),
		(0x0054835D, "CrashLogger frame 6"),
		(0x0086FB4D, "CrashLogger frame 7"),
		(0x0086E765, "CrashLogger frame 8"),
	]
	for item in items:
		func = func_for(item[0])
		disasm_window(max(0, item[0] - 0x30), 0xa0, item[1], [item[0]], 100)
		scan_function_for_text(func, item[1], ["00559450", "+ 0x20", "+ 0x30", "+ 0x34", "00401000", "0044cbf0", "006f74f0"], 120)

def main():
	write("=" * 70)
	write("CRASH 0x00559456 CALLSITE FANOUT AUDIT")
	write("=" * 70)
	write("")
	write("Purpose:")
	write("  Keep output smaller than a full global xref dump.")
	write("  Focus only on FUN_00559450 callsites in ranges present in the crash stack.")
	write("  Identify which caller can pass ECX=1 after reading a freed 80-byte LockFreeStringMap/QueuedReference cell.")
	audit_crash_chain_frames()
	audit_fun_00559450_relevant_calls()
	write("")
	write("=" * 70)
	write("END CRASH 0x00559456 CALLSITE FANOUT AUDIT")
	write("=" * 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_00559456_callsite_fanout_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
