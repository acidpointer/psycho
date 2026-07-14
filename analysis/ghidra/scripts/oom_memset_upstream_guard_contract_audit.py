# @category Analysis
# @description Prove NULL allocation contracts at the two unchecked calloc-style callers before removing the global memset hook

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

def disasm_range(start_int, end_int, label):
	write("")
	write("-" * 70)
	write("Disassembly: %s (0x%08x - 0x%08x)" % (label, start_int, end_int))
	write("-" * 70)
	inst = currentProgram.getListing().getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = currentProgram.getListing().getInstructionAfter(toAddr(start_int))
	while inst is not None and inst.getAddress().getOffset() <= end_int:
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()

def dump_pointer_range(start_int, end_int, label):
	write("")
	write("-" * 70)
	write("Pointers: %s (0x%08x - 0x%08x)" % (label, start_int, end_int))
	write("-" * 70)
	addr_int = start_int
	while addr_int <= end_int:
		value = currentProgram.getMemory().getInt(toAddr(addr_int)) & 0xffffffff
		func = fm.getFunctionAt(toAddr(value))
		name = func.getName() if func else ""
		write("  0x%08x: 0x%08x %s" % (addr_int, value, name))
		addr_int += 4

def main():
	write("OOM MEMSET UPSTREAM GUARD CONTRACT")
	write("Recover exact function boundaries, arguments, return values, and caller ownership around 0x00AA2240 and 0x00AA23C0 so NULL is handled at allocation consumers instead of every memset call.")
	decompile_at(0x00AA2240, "first calloc-style allocation consumer", 50000)
	decompile_at(0x00AA2370, "second calloc-style allocation consumer", 50000)
	decompile_at(0x00AA2290, "first allocation call site", 50000)
	decompile_at(0x00AA23C0, "second allocation call site", 50000)
	decompile_at(0x00AA4030, "GameHeap allocation wrapper", 30000)
	find_refs_to(0x00AA2240, "first consumer entry")
	find_refs_to(0x00AA2370, "second consumer entry")
	find_refs_to(0x00AA2290, "first unchecked allocation call")
	find_refs_to(0x00AA23C0, "second unchecked allocation call")
	find_refs_to(0x00EC61C0, "global memset callers")
	find_and_print_calls_from(0x00AA2240, "first calloc-style consumer")
	find_and_print_calls_from(0x00AA23C0, "second calloc-style consumer")
	disasm_range(0x00AA2230, 0x00AA22E0, "first consumer including allocation and zeroing")
	disasm_range(0x00AA2370, 0x00AA2430, "second consumer including allocation and zeroing")
	disasm_range(0x00AA4030, 0x00AA4058, "allocation wrapper ABI and stack cleanup")
	dump_pointer_range(0x010A24E0, 0x010A25C0, "allocator vtable region containing first consumer")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/oom_memset_upstream_guard_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
