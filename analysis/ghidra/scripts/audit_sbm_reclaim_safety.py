# @category Analysis
# @description Audit old SBM heap/arena construction and release paths for gheap VAS reclamation safety

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=12000):
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
		faddr = from_func.getEntryPoint().getOffset() if from_func else 0
		write("  %s @ 0x%08x (in %s @ 0x%08x)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, faddr))
		count += 1
		if count > 80:
			write("  ... (truncated at 80)")
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

def audit_function(addr_int, label):
	decompile_at(addr_int, label)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def main():
	write("AUDIT: old SBM reclaim safety for gheap VAS pressure")
	write("=" * 70)
	write("")
	write("Goal: determine whether full gheap can safely reclaim old vanilla SBM")
	write("heap/arena reservations after hooks are active. Do not assume safety:")
	write("pre-hook allocations may still be freed through original GameHeap, and")
	write("unhooked internal SBM paths may still touch arena freelists.")
	write("")
	write("Known constructors from prior audit:")
	write("  FUN_00866e00 creates Default Heap via FUN_00aa78a0(..., 0x0c800000, 0x05500000, \"Default Heap\", 0)")
	write("  FUN_00866e00 creates Static Heap via FUN_00aa7400(..., 0x00183800, \"Static Heap\")")
	write("  FUN_00866e00 creates File Heap via FUN_00aa78a0(..., 0x04000000, 0x00200000, \"File Heap\", 0)")
	write("")
	write("# SECTION 1: heap constructors")
	audit_function(0x00866E00, "SBM_RelatedInit_heap_construction")
	audit_function(0x00AA78A0, "SBM_DefaultFileHeap_constructor_FUN_00aa78a0")
	audit_function(0x00AA7400, "SBM_StaticHeap_constructor_FUN_00aa7400")
	audit_function(0x00AA39C0, "GameHeap_init_gate_FUN_00aa39c0")
	write("")
	write("# SECTION 2: release and purge paths")
	audit_function(0x00AA5C80, "SBM_DeallocateAllArenas_FUN_00aa5c80")
	audit_function(0x00AA7030, "SBM_GlobalCleanup_FUN_00aa7030")
	audit_function(0x00AA6F90, "SBM_PurgeUnusedArenas_FUN_00aa6f90")
	audit_function(0x00AA7290, "SBM_DecrementArenaRef_FUN_00aa7290")
	audit_function(0x00AA7300, "SBM_ReleaseArenaByPtr_FUN_00aa7300")
	write("")
	write("# SECTION 3: low-level VirtualAlloc/VirtualFree wrappers")
	audit_function(0x00AA5EC0, "SBM_VirtualAlloc_ReserveAndCommit")
	audit_function(0x00AA5E30, "SBM_VirtualAlloc_CommitRetry")
	audit_function(0x00AA5F30, "SBM_VirtualFree_Release")
	audit_function(0x00AA5E90, "SBM_VirtualFree_Decommit")
	write("")
	write("# SECTION 4: old pool fast path and freelist paths")
	audit_function(0x00AA4960, "SBM_GetPool_by_size")
	audit_function(0x00AA6AA0, "SBM_ArenaAlloc")
	audit_function(0x00AA6C70, "SBM_ArenaFree")

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/memory/audit_sbm_reclaim_safety.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
