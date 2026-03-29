# @category Analysis
# @description Compare HeapCompact stage 4 (PDD purge) vs stage 3 (HavokGC)
#   and their effect on BSTreeManager cleanup
#
# Hypothesis: HeapCompact stage 4 triggers PDD purge which cleans BSTreeManager
# map entries. Without stage 4 (only stage 3), BSTreeManager entries accumulate
# and become dangling pointers when quarantine frees the memory.
#
# Key functions to trace:
#   FUN_006652e0 — SpeedTree update called AFTER Phase 7 in main loop
#   FUN_00868850 — per-frame PDD drain (Phase 7)
#   FUN_00868d70 — full PDD drain (called by stage 4 and DeferredCleanupSmall)
#   FUN_00878080 — HeapCompact frame check (Phase 6)
#   FUN_00866a90 — HeapCompact/OOM stage executor
#   FUN_00c458f0 — completed IO task processor (runs in FUN_0086ff70)

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


write("HeapCompact Stage 4 vs Stage 3: BSTreeManager Cleanup")
write("=" * 70)

# ===================================================================
# PART 1: FUN_006652e0 — the SpeedTree function called after Phase 7
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: FUN_006652e0 (SpeedTree update, called after PDD drain)")
write("#" * 70)

decompile_at(0x006652e0, "SpeedTree update (called from main loop after PDD)")
find_and_print_calls_from(0x006652e0, "SpeedTree update")
find_refs_to(0x006652e0, "SpeedTree update callers")

# ===================================================================
# PART 2: Per-frame PDD drain vs full PDD drain — what's different?
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: Per-frame PDD drain (FUN_00868850) vs Full PDD (FUN_00868d70)")
write("#" * 70)
write("# Does per-frame drain process NiNode/BSTreeNode queue?")
write("# Does full PDD process MORE than per-frame?")

decompile_at(0x00868850, "Per-frame PDD drain (Phase 7)")
find_and_print_calls_from(0x00868850, "Per-frame PDD drain")

decompile_at(0x00868d70, "Full PDD drain (used by stage 4 and DeferredCleanupSmall)")
find_and_print_calls_from(0x00868d70, "Full PDD drain")

# Also the second PDD-related function called from main loop
decompile_at(0x00868d10, "PDD-related (called after per-frame drain in main loop)")
find_and_print_calls_from(0x00868d10, "PDD-related")

# ===================================================================
# PART 3: HeapCompact stage executor — which stages call what
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: HeapCompact Stage Executor")
write("#" * 70)

decompile_at(0x00878080, "HeapCompact frame check (Phase 6)")
find_and_print_calls_from(0x00878080, "HeapCompact frame check")

# The OOM stage executor that handles stages 0-8
decompile_at(0x00866a90, "OOM/HeapCompact stage executor")
find_and_print_calls_from(0x00866a90, "OOM/HeapCompact stage executor")

# ===================================================================
# PART 4: FUN_00c458f0 — completed IO task processor
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: Completed IO Task Processor")
write("#" * 70)
write("# This processes completed IO tasks in FUN_0086ff70 (pre-hook)")
write("# Calls vtable[1] on completed tasks — if task refs freed BSTreeNode...")

decompile_at(0x00c458f0, "IO task processor (completed tasks)")
find_and_print_calls_from(0x00c458f0, "IO task processor")

decompile_at(0x00c45e50, "IO task dequeue (called by processor)")

# ===================================================================
# PART 5: FUN_00878860 — called right before IO task processor
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: FUN_00878860 (called before IO processor in FUN_0086ff70)")
write("#" * 70)

decompile_at(0x00878860, "Pre-IO-processor function")
find_and_print_calls_from(0x00878860, "Pre-IO-processor")

# ===================================================================
# PART 6: ProcessPendingCleanup (FUN_00452490) — called by DeferredCleanupSmall
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: ProcessPendingCleanup")
write("#" * 70)

decompile_at(0x00452490, "ProcessPendingCleanup")
find_and_print_calls_from(0x00452490, "ProcessPendingCleanup")

# ===================================================================
# PART 7: BSTreeManager cleanup function FUN_00664cd0 (from lifecycle analysis)
# ===================================================================
write("")
write("#" * 70)
write("# PART 7: BSTreeManager cleanup caller chain")
write("#" * 70)

find_refs_to(0x00664cd0, "BSTreeManager cleanup (FUN_00664cd0)")
find_refs_to(0x006652e0, "SpeedTree update (FUN_006652e0)")

# Who calls FUN_00664840 (BSTreeManager getter)?
find_refs_to(0x00664840, "BSTreeManager getter (FUN_00664840)")


write("")
write("=" * 70)
write("ANALYSIS COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/bstree_stage4_vs_stage3.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
