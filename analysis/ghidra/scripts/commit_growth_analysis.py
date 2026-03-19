# @category Analysis
# @description Analyze what drives commit growth beyond NiNode queue
#
# Even with boosted NiNode drain (FUN_00868850 x20), commit still climbs
# from ~1.0GB to ~1.7GB during stress. We need to understand:
#   1. What objects go into each PDD queue and how fast
#   2. What memory is allocated by cell loading that ISN'T in any queue
#   3. Whether there are other cleanup paths we're missing
#   4. What the original HeapCompact does that we don't replicate
#
# Output: analysis/ghidra/output/memory/commit_growth_analysis.txt

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label):
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
	size = func.getBody().getNumAddresses()
	write("  Function: %s, Size: %d bytes, Convention: %s" % (
		func.getName(), size,
		func.getCallingConventionName() or "unknown"))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		if len(code) > 15000:
			write(code[:15000])
			write("  ... [truncated at 15000 chars]")
		else:
			write(code)
	else:
		write("  [decompilation failed]")
	write("")

def find_calls_from(addr_int, label):
	write("")
	write("-" * 70)
	write("Calls FROM 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found]")
		return []
	called = []
	body = func.getBody()
	inst_iter = currentProgram.getListing().getInstructions(body, True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				called.append(ref.getToAddress().getOffset())
	unique = sorted(set(called))
	write("  Calls %d unique functions:" % len(unique))
	for t in unique:
		f = fm.getFunctionAt(toAddr(t))
		n = f.getName() if f is not None else "???"
		sz = f.getBody().getNumAddresses() if f is not None else 0
		write("    -> 0x%08x  %s  (%d bytes)" % (t, n, sz))
	return unique

def find_refs_to(addr_int, label):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	funcs = set()
	count = 0
	for ref in refs:
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		if from_func is not None:
			funcs.add(from_func)
		count += 1
	write("  %d references from %d functions:" % (count, len(funcs)))
	for func in sorted(funcs, key=lambda f: f.getEntryPoint().getOffset()):
		entry = func.getEntryPoint()
		write("    0x%08x  %s  (%d bytes)" % (
			entry.getOffset(),
			func.getName(),
			func.getBody().getNumAddresses()))
	return funcs


write("COMMIT GROWTH + ALTERNATIVE CLEANUP ANALYSIS")
write("=" * 70)

# ===================================================================
# PART 1: HeapCompact stages we DON'T replicate
# Stage 2: cell/resource cleanup
# Stage 3: async queue flush
# Stage 6: GlobalCleanup (SBM, we RET-patched this)
# Are stages 2 and 3 contributing to cleanup we're missing?
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: HeapCompact Stages We Don't Replicate")
write("#" * 70)

# Stage 2 calls FUN_00652110 -> FUN_00529ea0 -> FUN_00650a30
# These are cell/resource cleanup
decompile_at(0x00652110, "FUN_00652110 (exterior cell manager get)")
decompile_at(0x00529ea0, "FUN_00529ea0 (cell check in Stage 2)")
decompile_at(0x00650a30, "FUN_00650a30 (resource cleanup, 355 bytes)")
find_calls_from(0x00650a30, "FUN_00650a30")

# FUN_00652190 — called in HeapCompact Stage 2
decompile_at(0x00652190, "FUN_00652190 (Stage 2 end)")

# Stage 3: FUN_00c459d0 — async queue flush
# We call this in DeferredCleanup_Small but not from our hook
decompile_at(0x00c459d0, "FUN_00c459d0 (async queue flush, 172 bytes)")
find_calls_from(0x00c459d0, "FUN_00c459d0")

# ===================================================================
# PART 2: FUN_00a61cd0 — the main cleanup dispatcher
# Called from ProcessPendingCleanup when flush is needed.
# Also called unconditionally in MainLoop at line ~800.
# What does it clean up? This might be a big memory reclaimation path.
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: Main Cleanup Dispatcher (FUN_00a61cd0)")
write("#" * 70)

decompile_at(0x00a61cd0, "FUN_00a61cd0 (main cleanup dispatcher, 390 bytes)")
find_calls_from(0x00a61cd0, "FUN_00a61cd0")
find_refs_to(0x00a61cd0, "FUN_00a61cd0")

# ===================================================================
# PART 3: What does FUN_0048fb50 actually free?
# This is the NiNode destructor (923 bytes, called by queue 0x08).
# Understanding what it frees tells us how much memory per NiNode.
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: NiNode Destructor Deep Dive (what gets freed)")
write("#" * 70)

decompile_at(0x0048fb50, "FUN_0048fb50 (NiNode destructor, 923 bytes)")
find_calls_from(0x0048fb50, "FUN_0048fb50")

# ===================================================================
# PART 4: Cell loading path — what gets allocated?
# When a cell loads, many objects are created. Understanding this
# tells us the "incoming rate" during stress.
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: Cell Loading Allocations")
write("#" * 70)

# FUN_00452580 — called by cell transition to load cells
# This is the function that creates new cell data
decompile_at(0x00452580, "FUN_00452580 (cell load/move, 2105 bytes)")

# FUN_00457d70 — also called during cell transitions
decompile_at(0x00457d70, "FUN_00457d70 (cell management, 550 bytes)")

# ===================================================================
# PART 5: IOManager async texture loading
# Queue 0x04 (textures) might be a significant contributor.
# What is the async IO queue and how does it interact with cleanup?
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: Async IO / Texture Queue")
write("#" * 70)

# FUN_00c459d0 was already decompiled above (async queue flush)
# Let's look at the texture enqueue path
# FUN_00418e00 is the texture destructor (queue 0x04)
decompile_at(0x00418e00, "FUN_00418e00 (texture release, queue 0x04)")
find_calls_from(0x00418e00, "FUN_00418e00")

# What fills queue 0x04?
find_refs_to(0x011de910, "DAT_011de910 (texture PDD queue)")

# ===================================================================
# PART 6: Havok queue 0x20 — what fills it and how fast?
# FUN_00401970 is the Havok release for queue 0x20
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: Havok Queue Analysis")
write("#" * 70)

decompile_at(0x00401970, "FUN_00401970 (Havok release, queue 0x20)")
find_calls_from(0x00401970, "FUN_00401970")

# What fills queue 0x20?
find_refs_to(0x011de924, "DAT_011de924 (Havok PDD queue)")

# ===================================================================
# PART 7: Animation queue 0x02 — FUN_00868ce0
# This is listed as "just clears bit 0x40000000, no destruction"
# Verify this is truly lightweight
# ===================================================================
write("")
write("#" * 70)
write("# PART 7: Animation Queue (0x02)")
write("#" * 70)

decompile_at(0x00868ce0, "FUN_00868ce0 (animation handler, queue 0x02)")

# ===================================================================
# PART 8: Generic queue 0x01 — what objects go here?
# ===================================================================
write("")
write("#" * 70)
write("# PART 8: Generic Ref-Counted Queue (0x01)")
write("#" * 70)

find_refs_to(0x011de874, "DAT_011de874 (generic queue 0x01)")

# ===================================================================
# PART 9: FUN_00b5fd60 / FUN_00b5ac90 — called in cleanup paths
# These might be memory reclamation we're missing
# ===================================================================
write("")
write("#" * 70)
write("# PART 9: Additional Cleanup Functions")
write("#" * 70)

decompile_at(0x00b5fd60, "FUN_00b5fd60 (cleanup in DeferredCleanup_Small)")
find_calls_from(0x00b5fd60, "FUN_00b5fd60")

decompile_at(0x00b5ac90, "FUN_00b5ac90 (called in MainLoop pre-render area)")
find_calls_from(0x00b5ac90, "FUN_00b5ac90")

# ===================================================================
# PART 10: DAT_011ddf38 checks — this global gates many operations
# It's checked before almost every cleanup path. What is it?
# ===================================================================
write("")
write("#" * 70)
write("# PART 10: DAT_011ddf38 (cleanup gate flag)")
write("#" * 70)

decompile_at(0x0042ce10, "FUN_0042ce10 (checks DAT_011ddf38, 26 bytes)")
find_refs_to(0x011ddf38, "DAT_011ddf38 (cleanup gate)")

# ===================================================================
# PART 11: FUN_0086ef70 — gates FUN_004556d0 call in MainLoop
# Understanding this gate tells us when the game's own cleanup fires
# ===================================================================
write("")
write("#" * 70)
write("# PART 11: MainLoop Cleanup Gates")
write("#" * 70)

decompile_at(0x0086ef70, "FUN_0086ef70 (gates FUN_004556d0)")
decompile_at(0x00451530, "FUN_00451530 (first gate for FUN_004556d0)")

# FUN_00424940 — gates FUN_008782b0 (the early PDD caller)
# Returns renderer state; PDD only fires when state==3
decompile_at(0x00424940, "FUN_00424940 (renderer state check, gates PDD)")


write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

# Write output
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/commit_growth_analysis.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
