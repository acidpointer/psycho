# @category Analysis
# @description Research HeapCompact stage 5 (cell unload) — dispatcher, stage routing, locks

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
	entry = func.getEntryPoint().getOffset()
	sz = func.getBody().getNumAddresses()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), entry, sz))
	if entry != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), entry))
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
		if count > 60:
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

# ============================================================================
write("###############################################################")
write("# HEAPCOMPACT STAGE 5 (CELL UNLOAD) DEEP RESEARCH")
write("# Goal: How the game routes HeapCompact stages, what stage 5")
write("# does internally, what locks, what thread context.")
write("###############################################################")

# --- 1. HeapCompact trigger field readers/writers ---
write("\n\n### SECTION 1: HEAP_COMPACT_TRIGGER (0x011F636C) readers/writers")

find_refs_to(0x011F636C, "HEAP_COMPACT_TRIGGER")

# --- 2. OOM Stage Executor (routes to individual stages) ---
write("\n\n### SECTION 2: OOM_STAGE_EXEC (0x00866A90)")
write("# This function executes a single OOM/HeapCompact stage")
write("# Dispatches based on stage index to specific handlers")

decompile_at(0x00866A90, "OOM_STAGE_EXEC")
find_and_print_calls_from(0x00866A90, "OOM_STAGE_EXEC")

# --- 3. HeapCompact main dispatcher ---
write("\n\n### SECTION 3: HeapCompact dispatcher")
write("# The Phase 6 function that reads trigger and runs stages 0..N")

# Scan around known HeapCompact area
decompile_at(0x00866CC0, "HeapCompact_Entry_1")
find_and_print_calls_from(0x00866CC0, "HeapCompact_Entry_1")

decompile_at(0x00866D00, "HeapCompact_Entry_2")
find_and_print_calls_from(0x00866D00, "HeapCompact_Entry_2")

# --- 4. What function is called for stage 5? ---
write("\n\n### SECTION 4: Stage routing — which functions handle each stage")
write("# Stage 0: TextureCache, Stage 1: GeometryCache, Stage 2: MenuCleanup")
write("# Stage 3: HavokGC, Stage 4: PddPurge, Stage 5: CellUnload")

# Known stage handler functions
decompile_at(0x00866900, "HeapCompact_StageHandler_Candidate_1")
find_and_print_calls_from(0x00866900, "HeapCompact_StageHandler_Candidate_1")

decompile_at(0x00866800, "HeapCompact_StageHandler_Candidate_2")
find_and_print_calls_from(0x00866800, "HeapCompact_StageHandler_Candidate_2")

# --- 5. FindCellToUnload callers (who triggers cell unload?) ---
write("\n\n### SECTION 5: FindCellToUnload (0x00453A80) callers")

decompile_at(0x00453A80, "FindCellToUnload")
find_refs_to(0x00453A80, "FindCellToUnload")
find_and_print_calls_from(0x00453A80, "FindCellToUnload")

# --- 6. Heap singleton and primary heap ---
write("\n\n### SECTION 6: Heap singleton (0x011F6238)")
write("# The OOM stage executor uses heap_singleton + 0x110 (primary heap)")

find_refs_to(0x011F6238, "HEAP_SINGLETON")

# --- 7. Main loop Phase 6 context ---
write("\n\n### SECTION 7: Main loop around Phase 6")
write("# Where HeapCompact runs in the frame relative to AI")

decompile_at(0x0086B3E0, "MainLoop_Phase6_Region")
find_and_print_calls_from(0x0086B3E0, "MainLoop_Phase6_Region")

# --- Output ---
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/heapcompact_stage5_deep.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
