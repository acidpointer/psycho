# @category Analysis
# @description Audit Default/File vanilla heap live-allocation counters and reclaim safety

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

def func_at_or_containing(addr_int):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	return func

def func_name(func):
	if func is None:
		return "???"
	return "%s @ 0x%08x" % (func.getName(), func.getEntryPoint().getOffset())

def decompile_at(addr_int, label, max_len=22000):
	func = func_at_or_containing(addr_int)
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

def find_refs_to(addr_int, label, limit=100):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), func_name(from_func)))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def find_and_print_calls_from(addr_int, label, limit=220):
	func = func_at_or_containing(addr_int)
	write("")
	write("-" * 70)
	write("Calls FROM %s (0x%08x)" % (label, addr_int))
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
				tgt_func = func_at_or_containing(tgt)
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, func_name(tgt_func)))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def disasm_function(addr_int, label, max_inst=260):
	func = func_at_or_containing(addr_int)
	write("")
	write("-" * 70)
	write("Disassembly: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		count += 1
		if count >= max_inst:
			write("  ... (truncated at %d instructions)" % max_inst)
			break
	write("  Instructions printed: %d" % count)

def audit_function(addr_int, label, max_len=22000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)
	disasm_function(addr_int, label, 220)

def main():
	write("AUDIT: Default/File vanilla heap liveness and reclaim safety")
	write("=" * 70)
	write("")
	write("Goal: identify fields proving whether old Default/File heap reservations")
	write("can be released after gheap activation without breaking pre-hook pointers.")
	write("")
	write("Known constructor fields from prior audit:")
	write("  +0x14 reserve capacity, +0x18 initial commit size, +0x1c committed limit")
	write("  +0x24 bump/end offset, +0x28 high-water offset, +0x30 base pointer")
	write("Need to verify which counters track live allocations vs historical bytes.")
	write("")
	write("# Default/File vtable methods")
	audit_function(0x00AA7E20, "dtor_or_delete_00aa7e20")
	audit_function(0x00AA7E50, "release_or_cleanup_00aa7e50")
	audit_function(0x00AA7B20, "allocate_entry_00aa7b20")
	audit_function(0x00AA7B40, "free_entry_00aa7b40")
	audit_function(0x00AA7E70, "unknown_00aa7e70")
	audit_function(0x00AA9FB0, "unknown_00aa9fb0")
	audit_function(0x00AA7C60, "msize_or_find_00aa7c60")
	audit_function(0x00AA7CA0, "contains_or_validate_00aa7ca0")
	audit_function(0x00AA7D00, "unknown_00aa7d00")
	audit_function(0x00AA7BE0, "unknown_00aa7be0")
	audit_function(0x00AA7C00, "unknown_00aa7c00")
	audit_function(0x00AA9D10, "unknown_00aa9d10")
	write("")
	write("# Backing reserve/commit/decommit methods")
	audit_function(0x00AA79A0, "reserve_and_initial_commit_00aa79a0")
	audit_function(0x00AA7A30, "release_full_reservation_00aa7a30")
	audit_function(0x00AA7A50, "commit_more_00aa7a50")
	audit_function(0x00AA7AB0, "decommit_tail_00aa7ab0")
	audit_function(0x00AA7D60, "decommit_free_block_pages_00aa7d60")

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/memory/vanilla_large_heap_liveness_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
