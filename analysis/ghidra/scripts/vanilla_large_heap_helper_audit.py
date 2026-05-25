# @category Analysis
# @description Audit vanilla large heap helper functions and live-allocation accounting

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

def find_refs_to(addr_int, label, limit=120):
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

def disasm_function(addr_int, label, max_inst=420):
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

def audit_function(addr_int, label, max_len=30000, max_inst=420):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)
	disasm_function(addr_int, label, max_inst)

def print_focus():
	write("AUDIT: vanilla Default/File heap helper layer")
	write("=" * 70)
	write("")
	write("Goal: find a reliable live-allocation test before reclaiming old")
	write("Default/File heap reservations after gheap activation.")
	write("")
	write("Known object fields from earlier audits:")
	write("  +0x10 granularity")
	write("  +0x14 reserve capacity")
	write("  +0x18 initial commit size")
	write("  +0x1c committed limit")
	write("  +0x24 bump/end offset")
	write("  +0x28 high-water offset")
	write("  +0x2c suspected currently-allocated bytes; verify here")
	write("  +0x30 reservation base")
	write("  +0x3c first physical block/list head")
	write("  +0x44..+0x2043 free-list buckets")
	write("  +0x2048 large/free-list head")
	write("  +0x2058/+0x205c bitmap/search helpers")
	write("  +0x20d8 critical section")
	write("  +0x20f0 debug/alternate mode byte")
	write("")
	write("Block format suspected from allocator:")
	write("  block+0x00 previous physical block")
	write("  block+0x04 size low 28 bits, flags high nibble")
	write("  block+0x08 user payload for allocated blocks")
	write("  block+0x08/+0x0c free-list links for free blocks")
	write("")
	write("Questions to answer from this output:")
	write("  1. Does +0x2c decrement on free and increment on alloc?")
	write("  2. Does +0x24 return to 0 ever, or is it only bump/end?")
	write("  3. Is a fully free heap represented by one free block at +0x30?")
	write("  4. Does destructor 00aa7930 release backing storage and clear fields?")
	write("  5. Can we safely call vanilla release, or must we update fields manually?")

def audit_all():
	targets = [
		(0x00AA8CA0, "ctor_fields_00aa8ca0", 26000, 360),
		(0x00AA8DD0, "post_setup_reserve_00aa8dd0", 26000, 360),
		(0x00AA7930, "dtor_cleanup_00aa7930", 26000, 360),
		(0x00AA8F50, "allocate_helper_00aa8f50", 62000, 760),
		(0x00AA98F0, "free_helper_00aa98f0", 62000, 760),
		(0x00AAA0E0, "msize_or_find_helper_00aaa0e0", 62000, 760),
		(0x00AAA310, "validate_helper_00aaa310", 50000, 620),
		(0x00AAA430, "unknown_writer_helper_00aaa430", 50000, 620),
		(0x00AAA0D0, "visit_free_block_helper_00aaa0d0", 26000, 360),
		(0x00AA9BD0, "insert_free_block_by_size_00aa9bd0", 42000, 520),
		(0x00AA9CA0, "mark_allocated_block_00aa9ca0", 26000, 360),
		(0x00AA9D30, "insert_or_reinsert_free_block_00aa9d30", 42000, 520),
		(0x00AA9E50, "unlink_free_block_00aa9e50", 42000, 520),
		(0x00AAA6E0, "write_block_header_00aaa6e0", 26000, 360),
	]
	for item in targets:
		audit_function(item[0], item[1], item[2], item[3])

def main():
	print_focus()
	audit_all()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/memory/vanilla_large_heap_helper_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
