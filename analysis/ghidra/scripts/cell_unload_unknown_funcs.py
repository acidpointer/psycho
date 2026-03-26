# @category Analysis
# @description Follow-up: Decompile unknown functions from stage 5 cell unload path

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
write("# FOLLOW-UP: Unknown functions from Stage 5 cell unload path")
write("###############################################################")

# --- 1. FUN_00869190 — called with 0 before and 1 after FindCellToUnload ---
write("\n\n### SECTION 1: FUN_00869190 (cell unload lock/flag?)")
write("# Stage 5 calls FUN_00869190(0) BEFORE FindCellToUnload")
write("# and FUN_00869190(1) AFTER. What does it do?")

decompile_at(0x00869190, "FUN_00869190 (stage5 pre/post)")
find_refs_to(0x00869190, "FUN_00869190")
find_and_print_calls_from(0x00869190, "FUN_00869190")

# --- 2. FUN_004539a0 — grid compact (called when no cell to unload) ---
write("\n\n### SECTION 2: FUN_004539a0 (grid compact)")
write("# Called when FindCellToUnload returns 0 (no cells remain)")

decompile_at(0x004539A0, "FUN_004539a0 (grid compact)")
find_refs_to(0x004539A0, "FUN_004539a0")
find_and_print_calls_from(0x004539A0, "FUN_004539a0")

# --- 3. FUN_00452490 — flush cell arrays (called after FindCellToUnload) ---
write("\n\n### SECTION 3: FUN_00452490 (flush cell arrays)")
write("# Called after FindCellToUnload with (GAME_MANAGER, 0)")

decompile_at(0x00452490, "FUN_00452490 (flush cell arrays)")
find_refs_to(0x00452490, "FUN_00452490")
find_and_print_calls_from(0x00452490, "FUN_00452490")

# --- 4. FUN_00453940 — called from inside FindCellToUnload ---
write("\n\n### SECTION 4: FUN_00453940 (called from FindCellToUnload)")

decompile_at(0x00453940, "FUN_00453940 (from FindCellToUnload)")
find_refs_to(0x00453940, "FUN_00453940")
find_and_print_calls_from(0x00453940, "FUN_00453940")

# --- 5. FUN_00462290 — called after cell found in FindCellToUnload ---
write("\n\n### SECTION 5: FUN_00462290 (cell unload action)")
write("# Called when local_8 != NULL (cell found to unload)")

decompile_at(0x00462290, "FUN_00462290 (cell unload action)")
find_refs_to(0x00462290, "FUN_00462290")
find_and_print_calls_from(0x00462290, "FUN_00462290")

# --- 6. FUN_004511e0 — cell eligibility check ---
write("\n\n### SECTION 6: FUN_004511e0 (cell eligibility check)")
write("# Called to check if a cell can be unloaded")

decompile_at(0x004511E0, "FUN_004511e0 (cell eligible?)")
find_refs_to(0x004511E0, "FUN_004511e0")
find_and_print_calls_from(0x004511E0, "FUN_004511e0")

# --- 7. FUN_00557090 — second eligibility check ---
write("\n\n### SECTION 7: FUN_00557090 (second eligibility check)")

decompile_at(0x00557090, "FUN_00557090 (cell eligible 2?)")
find_refs_to(0x00557090, "FUN_00557090")
find_and_print_calls_from(0x00557090, "FUN_00557090")

# --- 8. FUN_0078d200 — InterlockedCompareExchange in stage 4 ---
write("\n\n### SECTION 8: FUN_0078d200 (stage 4 lock)")
write("# Stage 4 (PddPurge) uses this as a lock before PDD")

decompile_at(0x0078D200, "FUN_0078d200 (stage4 lock)")
find_and_print_calls_from(0x0078D200, "FUN_0078d200")

# --- 9. FUN_0040fba0 — stage 4 unlock ---
write("\n\n### SECTION 9: FUN_0040fba0 (stage 4 unlock)")

decompile_at(0x0040FBA0, "FUN_0040fba0 (stage4 unlock)")
find_and_print_calls_from(0x0040FBA0, "FUN_0040fba0")

# --- 10. FUN_005f36f0 — used at start of FindCellToUnload ---
write("\n\n### SECTION 10: FUN_005f36f0 (FindCellToUnload branch)")
write("# If this returns non-zero, FindCellToUnload takes different path")

decompile_at(0x005F36F0, "FUN_005f36f0 (FindCellToUnload branch)")
find_and_print_calls_from(0x005F36F0, "FUN_005f36f0")

# --- 11. FUN_00454fc0 — called between the two cell array searches ---
write("\n\n### SECTION 11: FUN_00454fc0 (between searches)")

decompile_at(0x00454FC0, "FUN_00454fc0 (between cell searches)")
find_and_print_calls_from(0x00454FC0, "FUN_00454fc0")

# --- Output ---
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/cell_unload_unknown_funcs.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
