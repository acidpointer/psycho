# @category Analysis
# @description Audit crash site 0x00559506 after allocator NULL/OOM in AI thread

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

def label_for(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is not None:
		return func.getName()
	func = fm.getFunctionContaining(toAddr(addr_int))
	if func is not None:
		return "%s+0x%x" % (func.getName(), addr_int - func.getEntryPoint().getOffset())
	return "unknown"

def decompile_at(addr_int, label, max_len=20000):
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
		if count > 80:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
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
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, label_for(tgt)))
				count += 1
	write("  Total: %d calls" % count)

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionBefore(toAddr(center_int))
	count = 0
	while inst is not None and count < before_count:
		prev = inst.getPrevious()
		if prev is None:
			break
		inst = prev
		count += 1
	idx = 0
	limit = before_count + after_count + 1
	while inst is not None and idx < limit:
		addr_int = inst.getAddress().getOffset()
		marker = " << CRASH_EIP" if addr_int == center_int else ""
		write("  0x%08x: %-44s%s" % (addr_int, inst.toString(), marker))
		inst = inst.getNext()
		idx += 1

def print_nearby_functions(center_int):
	write("")
	write("=" * 70)
	write("NEARBY FUNCTIONS")
	write("=" * 70)
	func = fm.getFunctionContaining(toAddr(center_int))
	if func is None:
		write("  [containing function not found]")
	else:
		write("  Containing: 0x%08x %-32s size=%d" % (func.getEntryPoint().getOffset(), func.getName(), func.getBody().getNumAddresses()))
	start_int = center_int - 0x1000
	if start_int < 0:
		start_int = 0
	end_int = center_int + 0x1000
	func_iter = fm.getFunctions(toAddr(start_int), True)
	count = 0
	while func_iter.hasNext():
		item = func_iter.next()
		entry = item.getEntryPoint().getOffset()
		if entry > end_int:
			break
		write("  0x%08x %-32s size=%d" % (entry, item.getName(), item.getBody().getNumAddresses()))
		count += 1
		if count > 40:
			write("  ... (truncated)")
			break

def main():
	crash = 0x00559506
	write("=" * 70)
	write("CRASH 0x00559506 OOM/NULL AUDIT")
	write("=" * 70)
	write("Runtime context: scrap_heap allocation returned NULL after VAS collapse; crash EIP reads 0x68.")
	decompile_at(crash, "Crash EIP containing function")
	disasm_window(crash, 24, 40, "crash EIP")
	find_and_print_calls_from(crash, "Crash EIP containing function")
	find_refs_to(crash, "exact crash EIP")
	print_nearby_functions(crash)
	decompile_at(0x00559450, "nearby NiPointer load helper")
	decompile_at(0x005595e0, "nearby scrap-backed array/vector constructor")
	find_refs_to(0x00aa54a0, "scrap_heap alloc function")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_00559506_oom_null_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))

def run():
	try:
		main()
	finally:
		decomp.dispose()

run()
