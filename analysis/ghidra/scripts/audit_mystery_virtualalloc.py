# @category Analysis
# @description Decompile non-SBM VirtualAlloc/VirtualFree callers and find what subsystem they belong to

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
	write("  Function: %s, Size: %d bytes" % (func.getName(), func.getBody().getNumAddresses()))
	if faddr != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

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
		if count > 60:
			write("  ... (truncated at 60)")
			break
	write("  Total: %d refs" % count)


# --- Main body ---

write("AUDIT: Non-SBM VirtualAlloc/VirtualFree callers")
write("=" * 70)
write("")
write("These functions call VirtualAlloc/VirtualFree directly, bypassing")
write("both the SBM and mimalloc. Memory from these is invisible to our")
write("hooks and cannot be tracked or reclaimed.")
write("")

# SECTION 1: FUN_009fcc60 - calls VirtualAlloc at 0x009fcd10
write("# SECTION 1: Mystery VirtualAlloc caller FUN_009fcc60")
decompile_at(0x009fcc60, "NonSBM_VirtualAlloc_009fcc60")
find_and_print_calls_from(0x009fcc60, "NonSBM_VirtualAlloc")
find_refs_to(0x009fcc60, "NonSBM_VirtualAlloc_callers")

# SECTION 2: FUN_009fb170 - calls VirtualFree at 0x009fb1a5
write("")
write("# SECTION 2: Mystery VirtualFree caller FUN_009fb170")
decompile_at(0x009fb170, "NonSBM_VirtualFree_009fb170")
find_and_print_calls_from(0x009fb170, "NonSBM_VirtualFree")
find_refs_to(0x009fb170, "NonSBM_VirtualFree_callers")

# SECTION 3: FUN_00401020 - GetHeapSingleton (used by HeapCompact)
write("")
write("# SECTION 3: FUN_00401020 - GetHeapSingleton")
decompile_at(0x00401020, "GetHeapSingleton")

# SECTION 4: FUN_00878110 - Read HeapCompact trigger
write("")
write("# SECTION 4: FUN_00878110 and FUN_00878130 - trigger read/reset")
decompile_at(0x00878110, "HeapCompact_ReadTrigger")
decompile_at(0x00878130, "HeapCompact_ResetTrigger")

# SECTION 5: FUN_00a5b460 - called by PostDestruction before GlobalCleanup
write("")
write("# SECTION 5: FUN_00a5b460 - PreGlobalCleanup (called by PostDestruction)")
write("# PostDestruction calls this BEFORE the ret-patched GlobalCleanup.")
write("# If this function does important cleanup, we need to preserve it.")
decompile_at(0x00a5b460, "PreGlobalCleanup_00a5b460")
find_and_print_calls_from(0x00a5b460, "PreGlobalCleanup")

# SECTION 6: SBM arena creation - how much memory per arena?
write("")
write("# SECTION 6: SBM arena creation details")
decompile_at(0x00AA65B0, "SBM_ArenaInit_00aa65b0")
decompile_at(0x00AA6610, "SBM_ArenaAlloc_00aa6610")
find_and_print_calls_from(0x00AA65B0, "SBM_ArenaInit")
find_refs_to(0x00AA65B0, "SBM_ArenaInit_callers")

# SECTION 7: NiMemoryAccumulator / NiAllocator
write("")
write("# SECTION 7: Ni memory system - alternative allocators?")
write("# NiNew/NiDelete may use separate allocators from GameHeap")
decompile_at(0x00A01000, "NiAlloc_related_00a01000")
find_and_print_calls_from(0x00A01000, "NiAlloc")

# SECTION 8: Havok allocator
write("")
write("# SECTION 8: Havok hkMemorySystem")
write("# Does Havok allocate through GameHeap or its own VirtualAlloc?")
decompile_at(0x00E1B190, "Havok_MemorySystem_00e1b190")
decompile_at(0x00C3DD10, "Havok_WorldCreate_or_related")
find_and_print_calls_from(0x00E1B190, "Havok_MemorySystem")

# SECTION 9: Track FUN_00aa8f50 - SBM function with 3 VirtualAlloc calls
write("")
write("# SECTION 9: FUN_00aa8f50 - SBM init with heavy VirtualAlloc")
write("# Has 3 VirtualAlloc calls. Likely creates large initial arenas.")
decompile_at(0x00AA8F50, "SBM_HeavyInit_00aa8f50")
find_refs_to(0x00AA8F50, "SBM_HeavyInit_callers")


# --- Output ---
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/audit_mystery_virtualalloc.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
