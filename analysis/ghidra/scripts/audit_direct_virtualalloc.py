# @category Analysis
# @description Find ALL direct VirtualAlloc/VirtualFree callers to identify memory that bypasses mimalloc

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
		faddr = from_func.getEntryPoint().getOffset() if from_func else 0
		write("  %s @ 0x%08x (in %s @ 0x%08x)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, faddr))
		count += 1
		if count > 80:
			write("  ... (truncated at 80)")
			break
	write("  Total: %d refs" % count)

def find_ext_refs(name):
	write("")
	write("=" * 70)
	write("EXTERNAL FUNCTION: %s" % name)
	write("=" * 70)
	sym_table = currentProgram.getSymbolTable()
	syms = sym_table.getExternalSymbols(name)
	count = 0
	while syms.hasNext():
		sym = syms.next()
		write("  Symbol: %s at %s" % (sym.getName(), sym.getAddress()))
		refs = ref_mgr.getReferencesTo(sym.getAddress())
		while refs.hasNext():
			ref = refs.next()
			src = ref.getFromAddress().getOffset()
			from_func = fm.getFunctionContaining(ref.getFromAddress())
			fname = from_func.getName() if from_func else "???"
			faddr = from_func.getEntryPoint().getOffset() if from_func else 0
			# filter to game code only (0x00400000-0x00FF0000)
			if 0x00400000 <= src <= 0x00FF0000:
				write("    GAME CALL @ 0x%08x in %s (0x%08x)" % (src, fname, faddr))
				count += 1
			elif 0x00FF0000 < src:
				pass  # skip external DLLs
		write("  Game callers: %d" % count)
	return count

def classify_caller(addr_int):
	"""Classify a function by its address range."""
	if 0x00AA0000 <= addr_int <= 0x00AB0000:
		return "SBM_INTERNAL"
	elif 0x00860000 <= addr_int <= 0x008800000:
		return "MAIN_LOOP_HEAP"
	elif 0x00C40000 <= addr_int <= 0x00C50000:
		return "IO_MANAGER"
	elif 0x00E70000 <= addr_int <= 0x00F00000:
		return "RENDERER"
	else:
		return "GAME_CODE"


# --- Main body ---

write("AUDIT: Direct VirtualAlloc/VirtualFree callers in FalloutNV.exe")
write("=" * 70)
write("")
write("Purpose: Find memory allocations that bypass our mimalloc hooks.")
write("These are direct OS calls that we cannot track or reclaim.")
write("")

# 1. Find all VirtualAlloc callers
write("# SECTION 1: VirtualAlloc callers (memory that bypasses mimalloc)")
find_ext_refs("VirtualAlloc")

# 2. Find all VirtualFree callers
write("")
write("# SECTION 2: VirtualFree callers (memory returned to OS)")
find_ext_refs("VirtualFree")

# 3. Decompile key SBM functions that call VirtualAlloc
write("")
write("# SECTION 3: SBM VirtualAlloc wrappers")
write("# These are the SBM's own VirtualAlloc calls for arena management.")
write("# We ret-patched cleanup functions, so arenas from these calls")
write("# stay committed forever.")

decompile_at(0x00AA5E30, "SBM_VirtualAlloc_CommitRetry")
decompile_at(0x00AA5EC0, "SBM_VirtualAlloc_ReserveAndCommit")
decompile_at(0x00AA5F30, "SBM_VirtualFree_Release")
decompile_at(0x00AA5E90, "SBM_VirtualFree_Decommit")

# 4. Check the HeapCompact per-frame function
write("")
write("# SECTION 4: HeapCompact per-frame trigger check")
write("# FUN_00878080 is called every frame and checks HEAP_COMPACT_TRIGGER.")
write("# When trigger > 0, it calls FUN_00866a90 (stage executor).")
decompile_at(0x00878080, "HeapCompact_PerFrame_Check")

# 5. Decompile the OOM stage executor focusing on what each stage FREES
write("")
write("# SECTION 5: Key functions called by OOM stages that FREE memory")
write("# These are the functions that stages 0-5 call. If they free")
write("# memory through paths we dont hook, thats our leak.")

# Stage 0: texture cache flush
decompile_at(0x00452490, "Stage0_TextureCacheFlush")

# Stage 1: geometry cache teardown
decompile_at(0x00866D10, "Stage1_GetGeometryCache_PATCHED")

# Stage 3: async flush
decompile_at(0x00C459D0, "Stage3_AsyncFlush")

# Stage 5: cell unload components
decompile_at(0x00869190, "Stage5_PDD_SkipMask")
decompile_at(0x00453A80, "Stage5_FindCellToUnload_Check")
decompile_at(0x004539A0, "Stage5_FindCellToUnload")

# 6. Check D3D9 renderer memory allocation
write("")
write("# SECTION 6: D3D9 renderer VirtualAlloc usage")
write("# The renderer may allocate GPU-mapped system memory directly.")
find_ext_refs("CreateTexture")
find_ext_refs("CreateVertexBuffer")
find_ext_refs("CreateIndexBuffer")

# 7. Check HeapAlloc/HeapFree (Windows process heap, bypasses mimalloc)
write("")
write("# SECTION 7: HeapAlloc/HeapFree (Windows process heap)")
find_ext_refs("HeapAlloc")
find_ext_refs("HeapFree")

# --- Output ---
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/audit_direct_virtualalloc.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
