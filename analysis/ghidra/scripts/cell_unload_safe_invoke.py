# @category Analysis
# @description Research: How the game safely invokes cell unloading — locks, queues, thread sync

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
write("CELL UNLOAD SAFE INVOCATION RESEARCH")
write("=" * 70)
write("")
write("Goal: Understand EXACTLY how the game safely unloads cells.")
write("What locks, what order, what threads must be quiesced.")
write("")

# --- 1. FindCellToUnload ---
write("")
write("###################################################################")
write("# SECTION 1: FindCellToUnload (0x00453A80)")
write("###################################################################")

decompile_at(0x00453A80, "FindCellToUnload")
find_refs_to(0x00453A80, "FindCellToUnload")
find_and_print_calls_from(0x00453A80, "FindCellToUnload")

# --- 2. Pre-destruction setup (Havok lock + scene graph invalidate) ---
write("")
write("###################################################################")
write("# SECTION 2: Pre-Destruction Setup (0x00878160)")
write("###################################################################")

decompile_at(0x00878160, "PreDestructionSetup")
find_and_print_calls_from(0x00878160, "PreDestructionSetup")

# --- 3. Post-destruction restore (Havok unlock) ---
write("")
write("###################################################################")
write("# SECTION 3: Post-Destruction Restore (0x00878200)")
write("###################################################################")

decompile_at(0x00878200, "PostDestructionRestore")
find_and_print_calls_from(0x00878200, "PostDestructionRestore")

# --- 4. Deferred cleanup small (PDD + async flush) ---
write("")
write("###################################################################")
write("# SECTION 4: Deferred Cleanup Small (0x00878250)")
write("###################################################################")

decompile_at(0x00878250, "DeferredCleanupSmall")
find_and_print_calls_from(0x00878250, "DeferredCleanupSmall")

# --- 5. The cell transition handler (0x008774A0) ---
write("")
write("###################################################################")
write("# SECTION 5: CellTransitionHandler (0x008774A0)")
write("# How the game orchestrates cell transitions internally")
write("###################################################################")

decompile_at(0x008774A0, "CellTransitionHandler")
find_and_print_calls_from(0x008774A0, "CellTransitionHandler")

# --- 6. IO wait mechanism (0x00877700) ---
write("")
write("###################################################################")
write("# SECTION 6: IO Wait (0x00877700)")
write("# Waits for BSTaskManagerThread to finish pending loads")
write("###################################################################")

decompile_at(0x00877700, "IOWait_FUN_00877700")
find_and_print_calls_from(0x00877700, "IOWait_FUN_00877700")

# --- 7. Havok stop simulation (0x008324E0) ---
write("")
write("###################################################################")
write("# SECTION 7: Havok Stop / AI Drain (0x008324E0)")
write("# Stops Havok simulation, drains AI task queues")
write("###################################################################")

decompile_at(0x008324E0, "HavokStop_AIDrain")
find_and_print_calls_from(0x008324E0, "HavokStop_AIDrain")

# --- 8. PDD blocking (0x00868D70) ---
write("")
write("###################################################################")
write("# SECTION 8: ProcessDeferredDestruction (0x00868D70)")
write("# Blocking PDD — runs after AI drained")
write("###################################################################")

decompile_at(0x00868D70, "PDD_Blocking")
find_and_print_calls_from(0x00868D70, "PDD_Blocking")

# --- 9. Async flush (0x00C459D0) ---
write("")
write("###################################################################")
write("# SECTION 9: Async Flush (0x00C459D0)")
write("###################################################################")

decompile_at(0x00C459D0, "AsyncFlush")
find_and_print_calls_from(0x00C459D0, "AsyncFlush")

# --- 10. Who calls FindCellToUnload? ---
write("")
write("###################################################################")
write("# SECTION 10: ALL callers of FindCellToUnload")
write("# Where in the game code is cell unloading triggered?")
write("###################################################################")

find_refs_to(0x00453A80, "FindCellToUnload - ALL callers")

# --- 11. Loading flag reads ---
write("")
write("###################################################################")
write("# SECTION 11: LOADING_FLAG (0x011DEA2B) readers")
write("# Who checks loading state before cell operations?")
write("###################################################################")

find_refs_to(0x011DEA2B, "LOADING_FLAG")

# --- Output ---
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/cell_unload_safe_invoke.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
