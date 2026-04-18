# @category Analysis
# @description Deep analysis of vanilla HeapCompact OOM recovery: full stage executor, main thread vs worker paths, memory manager integration, and what each stage actually frees.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []


def write(msg):
	output.append(msg)
	print(msg)


def decompile_at(addr_int, label, max_len=10000):
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
	write(
		"  Function: %s @ 0x%08x, Size: %d bytes"
		% (func.getName(), faddr, func.getBody().getNumAddresses())
	)
	if faddr != addr_int:
		write(
			"  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)"
			% (addr_int, func.getName(), faddr)
		)
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
				write(
					"  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name)
				)
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
		write(
			"  %s @ 0x%08x (in %s)"
			% (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname)
		)
		count += 1
		if count > 60:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)


# ======================================================================
write("VANILLA OOM RECOVERY DEEP ANALYSIS")
write("Goal: How does vanilla HeapCompact work? What does each stage do?")
write("      What is the main thread vs worker thread flow?")
write("      How does Stage 8 actually work?")
write("=" * 70)

# SECTION 1: The full HeapCompact entry point
write("")
write("#" * 70)
write("# SECTION 1: HeapCompact main entry (FUN_00866a90)")
write("# The full switch statement with ALL 9 stages")
write("#" * 70)
decompile_at(0x00866A90, "HeapCompact_Execute", 15000)
find_and_print_calls_from(0x00866A90, "HeapCompact_Execute")

# SECTION 2: What triggers HeapCompact? All callers.
write("")
write("#" * 70)
write("# SECTION 2: All callers of HeapCompact")
write("# Who calls this and why?")
write("#" * 70)
find_refs_to(0x00866A90, "HeapCompact_Execute")

# SECTION 3: The HeapCompactTrigger singleton
write("")
write("#" * 70)
write("# SECTION 3: HeapCompactTrigger (DAT_011de36c + offset 0x134)")
write("# How does the main thread detect and consume the trigger?")
write("#" * 70)
find_refs_to(0x011DE36C, "DAT_011de36c_HeapManager")

# SECTION 4: Stage 0 (TextureCache) — what does it actually purge?
write("")
write("#" * 70)
write("# SECTION 4: Stage 0 — TextureCache purge")
write("# FUN_00867d70 called by stage 0")
write("#" * 70)
decompile_at(0x00867D70, "TextureCachePurge", 5000)
find_and_print_calls_from(0x00867D70, "TextureCachePurge")

# SECTION 5: Stage 4 (PDD purge) — what does it drain?
write("")
write("#" * 70)
write("# SECTION 5: Stage 4 — PDD full drain")
write("# FUN_00868d70")
write("#" * 70)
decompile_at(0x00868D70, "PDD_Purge", 5000)
find_and_print_calls_from(0x00868D70, "PDD_Purge")

# SECTION 6: Stage 5 (CellUnload) — the FindCellToUnload flow
write("")
write("#" * 70)
write("# SECTION 6: Stage 5 — CellUnload")
write("# What determines 'cell eligible for unload'?")
write("#" * 70)
decompile_at(0x00866E70, "FindCellToUnload", 8000)
find_and_print_calls_from(0x00866E70, "FindCellToUnload")

# SECTION 7: Stage 8 — the actual vanilla sleep loop
write("")
write("#" * 70)
write("# SECTION 7: Stage 8 — vanilla sleep/retry loop")
write("# What happens here exactly?")
write("#" * 70)
# Read stage 8 from within HeapCompact
decompile_at(0x00866A90, "HeapCompact_Stage8Section")
# Also check the release_bstask function
decompile_at(0x00866CE0, "ReleaseBSTaskSems", 3000)

# SECTION 8: How does the main thread process the trigger?
write("")
write("#" * 70)
write("# SECTION 8: Main loop trigger processing")
write("# How does the game check and consume HeapCompact trigger?")
write("#" * 70)
decompile_at(0x008774A0, "CellTransitionHandler", 12000)

# SECTION 9: DeferredCleanupSmall — how it interacts with stages
write("")
write("#" * 70)
write("# SECTION 9: DeferredCleanupSmall")
write("#" * 70)
decompile_at(0x00878250, "DeferredCleanupSmall", 3000)
find_and_print_calls_from(0x00878250, "DeferredCleanupSmall")

# SECTION 10: What memory does SBM GlobalCleanup (Stage 6) actually reclaim?
write("")
write("#" * 70)
write("# SECTION 10: Stage 6 — SBM GlobalCleanup")
write("# gheap skips this because it 'allocates'. What does it do?")
write("#" * 70)
decompile_at(0x00866DC0, "Stage6_SBMCleanup", 5000)

# SECTION 11: How does vanilla handle the case where stages 3-5 free nothing?
write("")
write("#" * 70)
write("# SECTION 11: Vanilla death spiral handling")
write("# What happens when stages 0-5 all return done=1?")
write("#" * 70)
# Look at the loop around HeapCompact caller
decompile_at(0x00C40A20, "GameHeap_Alloc_or_OOM", 15000)

# SECTION 12: The memory manager integration
write("")
write("#" * 70)
write("# SECTION 12: Memory manager — how does it handle OOM?")
write("#" * 70)
decompile_at(0x00AA54A0, "SBM_Alloc_Original", 8000)
find_and_print_calls_from(0x00AA54A0, "SBM_Alloc_Original")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/vanilla_oom_recovery_deep.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
