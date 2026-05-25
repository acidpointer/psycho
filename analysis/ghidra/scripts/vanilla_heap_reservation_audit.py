# @category Analysis
# @description Audit vanilla GameHeap/SBM reservations that may survive gheap activation

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

def decompile_at(addr_int, label, max_len=14000):
	addr = toAddr(addr_int)
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

def disasm_function(addr_int, label, max_inst=220):
	func = func_at_or_containing(addr_int)
	write("")
	write("-" * 70)
	write("Function disassembly: %s @ 0x%08x" % (label, addr_int))
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

def audit_function(addr_int, label, max_len=14000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def main():
	write("AUDIT: vanilla GameHeap/SBM reservations before gheap activation")
	write("=" * 70)
	write("")
	write("Questions:")
	write("  1. Which vanilla GameHeap/SBM constructors run before NVSE Load?")
	write("  2. Which functions reserve/commit backing memory for Default/File/Static heaps?")
	write("  3. Which release/purge paths are disabled by gheap patches, leaving old reservations alive?")
	write("")
	write("Current source context:")
	write("  gheap prepares trampolines in NVSEPlugin_Preload, enables hooks in NVSEPlugin_Load.")
	write("  apply_gheap_patches RET-patches GlobalCleanup, DeallocateAllArenas, PurgeUnusedArenas,")
	write("  DecrementArenaRef, and ReleaseArenaByPtr after hooks are active.")
	write("")
	write("# SECTION 1: startup/constructor order")
	audit_function(0x00AA3880, "HeapSingleton_constructor_FUN_00aa3880")
	audit_function(0x00AA39C0, "GameHeap_init_gate_FUN_00aa39c0")
	audit_function(0x00866E00, "SBM_related_heap_construction_FUN_00866e00")
	audit_function(0x00866690, "Early_SBM_init_caller_FUN_00866690")
	audit_function(0x00AA3050, "Late_SBM_init_gate_FUN_00aa3050")
	audit_function(0x00AA2020, "SBM_singleton_cell_init_FUN_00aa2020")
	write("")
	write("# SECTION 2: Default/File/Static heap backing-store constructors")
	audit_function(0x00AA78A0, "Default_File_heap_constructor_FUN_00aa78a0")
	audit_function(0x00AA7400, "Static_heap_constructor_FUN_00aa7400")
	audit_function(0x00AA8CA0, "Large_heap_base_setup_FUN_00aa8ca0", 22000)
	audit_function(0x00AA8DD0, "Large_heap_post_setup_FUN_00aa8dd0", 18000)
	audit_function(0x00AA8F50, "Large_heap_alloc_commit_growth_FUN_00aa8f50", 26000)
	write("")
	write("# SECTION 3: low-level VirtualAlloc/VirtualFree wrappers")
	audit_function(0x00AA5EC0, "SBM_reserve_8mb_then_commit_FUN_00aa5ec0")
	audit_function(0x00AA5E30, "SBM_commit_retry_FUN_00aa5e30")
	audit_function(0x00AA5F30, "SBM_release_FUN_00aa5f30")
	audit_function(0x00AA5E90, "SBM_decommit_FUN_00aa5e90")
	write("")
	write("# SECTION 4: small-block pool arena reservation")
	audit_function(0x00AA65B0, "SBM_pool_arena_reserve_FUN_00aa65b0")
	audit_function(0x00AA6610, "SBM_pool_page_commit_FUN_00aa6610")
	audit_function(0x00AA6AA0, "SBM_pool_alloc_FUN_00aa6aa0")
	audit_function(0x00AA6C70, "SBM_pool_free_FUN_00aa6c70")
	write("")
	write("# SECTION 5: release/purge paths gheap currently disables")
	audit_function(0x00AA5C80, "SBM_deallocate_all_arenas_FUN_00aa5c80")
	audit_function(0x00AA7030, "SBM_global_cleanup_FUN_00aa7030")
	audit_function(0x00AA6F90, "SBM_purge_unused_arenas_FUN_00aa6f90")
	audit_function(0x00AA7290, "SBM_decrement_arena_ref_FUN_00aa7290")
	audit_function(0x00AA7300, "SBM_release_arena_by_ptr_FUN_00aa7300")
	write("")
	write("# SECTION 6: disassembly for field-offset recovery")
	disasm_function(0x00AA8CA0, "Large_heap_base_setup_FUN_00aa8ca0", 260)
	disasm_function(0x00AA8DD0, "Large_heap_post_setup_FUN_00aa8dd0", 220)
	disasm_function(0x00AA65B0, "SBM_pool_arena_reserve_FUN_00aa65b0", 120)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/memory/vanilla_heap_reservation_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
