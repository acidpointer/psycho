# @category Analysis
# @description Dump vanilla heap vtables and backing-store virtual methods

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

def read_u32(addr_int):
	v = memory.getInt(toAddr(addr_int))
	if v < 0:
		v += 0x100000000
	return v

def decompile_at(addr_int, label, max_len=16000):
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

def find_refs_to(addr_int, label, limit=80):
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

def find_and_print_calls_from(addr_int, label, limit=180):
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

def dump_vtable(vtable_addr, label, entries):
	write("")
	write("=" * 70)
	write("VTABLE %s @ 0x%08x" % (label, vtable_addr))
	write("=" * 70)
	i = 0
	while i < entries:
		entry_addr = vtable_addr + i * 4
		target = read_u32(entry_addr)
		func = func_at_or_containing(target)
		write("  +0x%02x [0x%08x] -> 0x%08x %s" % (i * 4, entry_addr, target, func_name(func)))
		i += 1

def audit_function(addr_int, label, max_len=16000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def main():
	write("AUDIT: vanilla heap vtables and backing-store methods")
	write("=" * 70)
	write("")
	write("Focus: resolve virtual methods used by LargeHeap setup.")
	write("FUN_00aa8dd0 calls [vtable+0x30](heap_capacity, initial_commit_or_reserve).")
	write("FUN_00aa8f50 calls [vtable+0x38](base, old_limit, grow_bytes).")
	write("")
	dump_vtable(0x010A28FC, "Default/File final heap vtable", 18)
	dump_vtable(0x010A2BBC, "LargeHeap base vtable during construction", 18)
	dump_vtable(0x010A2884, "StaticHeap final vtable", 18)
	dump_vtable(0x010A28C8, "Common heap base vtable", 18)
	write("")
	write("# Backing-store methods with direct VirtualAlloc/VirtualFree")
	audit_function(0x00AA79A0, "heap_backing_method_00aa79a0", 22000)
	audit_function(0x00AA7A30, "heap_backing_method_00aa7a30", 14000)
	audit_function(0x00AA7A50, "heap_backing_method_00aa7a50", 14000)
	audit_function(0x00AA7AB0, "heap_backing_method_00aa7ab0", 18000)
	audit_function(0x00AA7B20, "heap_large_alloc_entry_00aa7b20", 12000)
	audit_function(0x00AA7D60, "heap_backing_method_00aa7d60", 16000)
	write("")
	write("# Scrap/SBM backing region cache methods")
	audit_function(0x00AA59B0, "sbm_cached_region_alloc_00aa59b0", 18000)
	audit_function(0x00AA5B70, "sbm_cached_region_release_00aa5b70", 16000)
	audit_function(0x00AA5D40, "sbm_cached_region_commit_or_reuse_00aa5d40", 16000)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/memory/vanilla_heap_vtable_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
