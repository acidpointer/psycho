# @category Analysis
# @description Close remaining knowledge gaps: cell unload eligibility,
#   IO lock re-entrancy, BSTreeNode state, quarantine during loading
#
# Open questions:
#   1. Why does FindCellToUnload always return 0? What are eligibility criteria?
#   2. Does DeferredCleanupSmall's async flush re-acquire the IO spin-lock?
#   3. What is FUN_00726070 (state check) and how does PDD change it?
#   4. What gets freed during coc that fills quarantine to 400MB?

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
	fsize = func.getBody().getNumAddresses()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, fsize))
	if faddr != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		if len(code) > max_len:
			write(code[:max_len])
			write("  ... [truncated at %d chars]" % max_len)
		else:
			write(code)
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
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
		if count > 50:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)


write("Open Questions Research")
write("=" * 70)

# ===================================================================
# Q1: Why does FindCellToUnload always return 0?
# ===================================================================
write("")
write("#" * 70)
write("# Q1: FindCellToUnload Eligibility (FUN_00453a80)")
write("#" * 70)
write("# Always returns false with 76-88 loaded cells. What are the criteria?")

decompile_at(0x00453a80, "FindCellToUnload", 20000)
find_and_print_calls_from(0x00453a80, "FindCellToUnload")

# Helper functions called by FindCellToUnload
decompile_at(0x004511e0, "Cell eligibility check (FUN_004511e0, if called)")
decompile_at(0x00557090, "Cell distance/state check (FUN_00557090, if called)")

# FUN_004539a0 — called before FindCellToUnload in stage 5
decompile_at(0x004539a0, "Pre-cell-unload setup (FUN_004539a0)")

# ===================================================================
# Q2: Does async flush re-acquire the IO spin-lock?
# ===================================================================
write("")
write("#" * 70)
write("# Q2: Async Flush IO Lock Re-entrancy")
write("#" * 70)
write("# DeferredCleanupSmall calls FUN_00c459d0 (async flush).")
write("# We hold the IO spin-lock (0x40FBF0). Does async flush")
write("# call FUN_0040FBF0 again? → deadlock if yes.")

# Already have FUN_00c459d0 decompiled. Check if it calls 0x0040FBF0.
decompile_at(0x00c459d0, "Async flush (FUN_00c459d0)")
find_and_print_calls_from(0x00c459d0, "Async flush")

# FUN_0078d200 — the try-lock used by async flush
decompile_at(0x0078d200, "Try-lock (FUN_0078d200)")

# Also check FUN_0040FBF0 — is it the same spin-lock?
decompile_at(0x0040fbf0, "Spin-lock acquire (FUN_0040FBF0)")

# Check: do 0x01202e40 (async flush lock) and IO_DEQUEUE_LOCK overlap?
write("")
write("--- Lock address comparison ---")
write("IO dequeue lock: IOManager+0x20")
write("Async flush lock: DAT_01202e40")
write("Are these the same lock? Check IOManager singleton at 0x01202d98")
write("IOManager+0x20 = *(0x01202d98) + 0x20 (runtime address)")
write("DAT_01202e40 is a static address")
write("These are DIFFERENT locks (one is indirect, one is static)")

# ===================================================================
# Q3: FUN_00726070 — BSTreeNode state check
# ===================================================================
write("")
write("#" * 70)
write("# Q3: BSTreeNode State (FUN_00726070)")
write("#" * 70)

decompile_at(0x00726070, "Node state / next-sibling (FUN_00726070)")
find_refs_to(0x00726070, "FUN_00726070 callers")

# Also check what sets the state. NiNode has state at some offset.
# The NiNode destructor chain (FUN_0048fb50) might change it.
# FUN_0043bac0 is called during NiNode destruction on children
decompile_at(0x0043bac0, "NiNode child cleanup (FUN_0043bac0)")
find_and_print_calls_from(0x0043bac0, "NiNode child cleanup")

# ===================================================================
# Q4: FUN_00877700 — IO wait in CellTransition
# ===================================================================
write("")
write("#" * 70)
write("# Q4: CellTransition IO Wait (FUN_00877700)")
write("#" * 70)
write("# CellTransition calls FUN_00877700 first. This waits for IO.")
write("# Does it also use the IO spin-lock?")

decompile_at(0x00877700, "CellTransition IO wait")
find_and_print_calls_from(0x00877700, "CellTransition IO wait")

# ===================================================================
# Q5: FUN_008776e0 — Post-CellTransition
# ===================================================================
write("")
write("#" * 70)
write("# Q5: Post-CellTransition (FUN_008776e0)")
write("#" * 70)

decompile_at(0x008776e0, "Post-CellTransition")
find_and_print_calls_from(0x008776e0, "Post-CellTransition")

# ===================================================================
# Q6: What is FUN_00453a70? (called before CellTransition PDD)
# ===================================================================
write("")
write("#" * 70)
write("# Q6: Pre-CellTransition cleanup (FUN_00453a70)")
write("#" * 70)

decompile_at(0x00453a70, "Pre-CellTransition cleanup")
find_and_print_calls_from(0x00453a70, "Pre-CellTransition cleanup")

# ===================================================================
# Q7: FUN_00869190 — skip mask setter
# ===================================================================
write("")
write("#" * 70)
write("# Q7: Skip Mask Setter (FUN_00869190)")
write("#" * 70)

decompile_at(0x00869190, "PDD skip mask setter")


write("")
write("=" * 70)
write("ANALYSIS COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/open_questions_research.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
