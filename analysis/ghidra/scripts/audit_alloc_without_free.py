# @category Analysis
# @description Find game subsystems that allocate via GameHeap but may free through
# other paths (VirtualFree, CRT free, or not at all). These are potential leaks.

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
		rtype = ref.getReferenceType()
		if rtype.isCall():
			write("  CALL @ 0x%08x in %s (0x%08x)" % (ref.getFromAddress().getOffset(), fname, faddr))
			count += 1
	write("  Total: %d call refs" % count)

def check_func_calls_free(addr_int, label):
	"""Check if a function calls any known free function."""
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		return
	body = func.getBody()
	inst_iter = currentProgram.getListing().getInstructions(body, True)
	free_targets = set([0x00401030, 0x00AA4060, 0x00AA42C0])
	alloc_targets = set([0x00401000, 0x00AA3E40, 0x00AA4290])
	calls_free = False
	calls_alloc = False
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				if tgt in free_targets:
					calls_free = True
				if tgt in alloc_targets:
					calls_alloc = True
	status = ""
	if calls_alloc and not calls_free:
		status = "ALLOC_ONLY (potential leak!)"
	elif calls_free and not calls_alloc:
		status = "FREE_ONLY"
	elif calls_alloc and calls_free:
		status = "ALLOC+FREE"
	else:
		status = "NEITHER"
	write("  %s: %s" % (label, status))


# --- Main body ---

write("AUDIT: Allocation without corresponding free paths")
write("=" * 70)
write("")
write("Looking for functions that allocate via GameHeap but never free,")
write("or free through non-hooked paths (VirtualFree, CRT free).")
write("")

# SECTION 1: SBM internal VirtualAlloc that we CANT free
write("# SECTION 1: SBM arena creation (VirtualAlloc calls)")
write("# These create SBM arenas that hold pre-hook allocations.")
write("# We ret-patched the cleanup, so these arenas NEVER get freed.")
write("# How much memory is in these arenas?")

# FUN_00aa6db0 creates new arena pages
decompile_at(0x00AA6DB0, "SBM_CreateArenaPage")
# FUN_00aa6610 allocates arena backing memory
decompile_at(0x00AA6610, "SBM_AllocArenaMemory")

# SECTION 2: Havok memory system
write("")
write("# SECTION 2: Havok memory system")
write("# Havok has its own allocator (hkMemorySystem). Does it use GameHeap")
write("# or its own VirtualAlloc? If its own, we cant track it.")

# hkMemorySystem allocate/free
decompile_at(0x00E1B190, "hkMemorySystem_or_related")
# Check what Havok world step allocates
decompile_at(0x00C3E310, "hkWorld_Lock")

# SECTION 3: BSA / file loading buffers
write("")
write("# SECTION 3: BSA file loading - buffer allocation")
write("# Large file reads (terrain, textures) need buffers.")
write("# Are these allocated via GameHeap or VirtualAlloc?")

# BSFile read functions
decompile_at(0x00AFF470, "BSFile_Read_or_related")
decompile_at(0x00AFE0B0, "BSFile_LoadBuffer")

# SECTION 4: Terrain / LOD data
write("")
write("# SECTION 4: Terrain and LOD data allocation")
write("# Terrain heightfields and LOD meshes are large allocations.")
write("# Do they go through GameHeap?")

# BGSTerrainChunkLoadTask
decompile_at(0x00793D20, "TerrainChunk_or_related")

# SECTION 5: NiStream / geometry loading
write("")
write("# SECTION 5: NiStream geometry loading")
write("# .nif file loading creates NiNode trees. How are they allocated?")
decompile_at(0x00A01000, "NiStream_related")

# SECTION 6: FastTravel and cell transition - complete decompile
write("")
write("# SECTION 6: FastTravel memory management")
write("# What does the fast travel handler do BESIDES calling GlobalCleanup?")
write("# Maybe it frees memory through paths we dont hook.")
decompile_at(0x0093CDF0, "FastTravel_CellTransition1")
decompile_at(0x0093D500, "FastTravel_CellTransition2")

# SECTION 7: The HeapCompact per-frame check - what does it ACTUALLY do?
write("")
write("# SECTION 7: HeapCompact per-frame check")
write("# FUN_00878080 checks HEAP_COMPACT_TRIGGER and calls stage executor.")
write("# BUT does it do anything ELSE that frees memory?")
decompile_at(0x00878080, "HeapCompact_PerFrame")
find_and_print_calls_from(0x00878080, "HeapCompact_PerFrame")

# Also check FUN_00878200 (PostDestruction/Shutdown)
decompile_at(0x00878200, "PostDestruction_Shutdown")
find_and_print_calls_from(0x00878200, "PostDestruction_Shutdown")

# SECTION 8: Count callers of key functions
write("")
write("# SECTION 8: Caller counts for key alloc/free functions")
find_refs_to(0x00AA3E40, "GameHeap_Allocate")
find_refs_to(0x00AA4060, "GameHeap_Free")
find_refs_to(0x00AA42C0, "CRT_free_fallback")
find_refs_to(0x00AA4290, "CRT_malloc_fallback")


# --- Output ---
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/audit_alloc_without_free.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
