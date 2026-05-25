# @category Analysis
# @description Audit vanilla large heap destructor and coalescing helpers for safe VAS reclaim

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

def decompile_at(addr_int, label, max_len=32000):
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

def find_refs_to(addr_int, label, limit=160):
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

def find_and_print_calls_from(addr_int, label, limit=260):
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

def disasm_function(addr_int, label, max_inst=520):
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

def audit_function(addr_int, label, max_len=32000, max_inst=520):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)
	disasm_function(addr_int, label, max_inst)

def main():
	write("AUDIT: vanilla large heap reclaim/destructor path")
	write("=" * 70)
	write("")
	write("Prior helper audit proved +0x2c is current live bytes.")
	write("This pass checks the cleanup path and coalescing helpers so gheap can")
	write("decide whether to call a vanilla method or manually release/reset")
	write("old Default/File heap reservations after +0x2c reaches zero.")
	write("")
	write("Questions:")
	write("  1. Does 00aa8ea0 call vtable+0x34 release_full_reservation?")
	write("  2. Which fields are cleared after release?")
	write("  3. Does 00aa9970 maintain +0x34 physical block count and +0x40 free count?")
	write("  4. Are bitmap/search helpers required after manual field reset?")
	targets = [
		(0x00AA8EA0, "large_heap_release_storage_00aa8ea0", 42000, 620),
		(0x00AA8DA0, "large_heap_base_dtor_00aa8da0", 26000, 360),
		(0x00AA9970, "coalesce_adjacent_free_blocks_00aa9970", 42000, 620),
		(0x00AA9A70, "rebuild_or_trim_free_lists_00aa9a70", 42000, 620),
		(0x00AA9EF0, "set_free_bitmap_00aa9ef0", 26000, 360),
		(0x00AA9F50, "clear_free_bitmap_00aa9f50", 26000, 360),
		(0x00AAA5E0, "unlink_free_links_helper_00aaa5e0", 26000, 360),
		(0x00AAA5B0, "base_virtual_dtor_00aaa5b0", 26000, 360),
		(0x00AAA650, "pure_or_stub_backing_00aaa650", 26000, 360),
		(0x00AAA660, "release_all_free_blocks_00aaa660", 42000, 620),
	]
	for item in targets:
		audit_function(item[0], item[1], item[2], item[3])

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/memory/vanilla_large_heap_reclaim_path_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
