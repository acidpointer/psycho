# @category Analysis
# @description Find the exact mechanism to trigger HeapCompact from FUN_00878080
#
# FUN_00878080 at MainLoop line ~797 calls:
#   heap = FUN_00401020()  // get heap singleton
#   stage = FUN_00878110(heap)  // get pending compact stage
#   if (stage != 0) { run HeapCompact stages 0..stage }
#   FUN_00878130(heap)  // reset
#
# HeapCompact Stage 8 writes: *(heap + 0x134) = 6
# This is a non-main thread requesting cleanup.
#
# HYPOTHESIS: FUN_00878110 reads heap+0x134 (the compact request).
# If we write a value there, HeapCompact fires at its NATIVE safe position.
#
# This would solve everything:
# - Runs before AI dispatch (line ~855) — safe for Havok
# - Runs before render (line ~904) — safe for SpeedTree draw lists
# - Uses TLS=0 for immediate destruction — BSTreeNodes removed from
#   BSTreeManager maps during destruction, before draw lists are built
# - Full PDD — all queues processed safely
# - The game's own synchronization handles everything
#
# Output: analysis/ghidra/output/memory/heapcompact_trigger.txt

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
		write(code)
	else:
		write("  [decompilation failed]")
	write("")

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


write("HEAPCOMPACT TRIGGER MECHANISM")
write("=" * 70)

# ===================================================================
# PART 1: The key functions — what offset do they read/write?
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: HeapCompact trigger check and reset")
write("#" * 70)

# FUN_00878110 — checks if HeapCompact is needed (20 bytes)
# Called by FUN_00878080 to decide whether to run stages
decompile_at(0x00878110, "FUN_00878110 (HeapCompact trigger check, 20 bytes)")

# FUN_00878130 — resets after HeapCompact completes (33 bytes)
decompile_at(0x00878130, "FUN_00878130 (HeapCompact reset, 33 bytes)")

# FUN_00401020 — gets the heap singleton (10 bytes)
decompile_at(0x00401020, "FUN_00401020 (get heap singleton)")

# ===================================================================
# PART 2: Who writes to the trigger? Find all paths that request compact
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: Who triggers HeapCompact?")
write("#" * 70)

# HeapCompact Stage 8 writes *(this + 0x134) = 6
# Are there other writers?
find_refs_to(0x00878110, "FUN_00878110 (trigger check)")
find_refs_to(0x00878130, "FUN_00878130 (trigger reset)")

# ===================================================================
# PART 3: FUN_00878080 full context — verify the loop logic
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: HeapCompact main loop caller (full)")
write("#" * 70)

decompile_at(0x00878080, "FUN_00878080 (MainLoop HeapCompact caller)")

# ===================================================================
# PART 4: What does FUN_00401020 return? The heap singleton.
# We need to know the heap singleton pointer to write the trigger.
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: Heap singleton access")
write("#" * 70)

decompile_at(0x00401020, "FUN_00401020 (heap singleton getter)")

# Also check: is DAT_011F6238 the heap singleton directly,
# or a pointer to it?
find_refs_to(0x011f6238, "DAT_011F6238 (heap singleton global)")

# ===================================================================
# PART 5: Verify Stage 5 behavior with TLS=0
# Specifically: does immediate BSTreeNode destruction call
# TreeMgr_RemoveOnState? If so, the node is removed from
# BSTreeManager before render builds draw lists.
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: SetTlsCleanupFlag implementation")
write("#" * 70)

decompile_at(0x00869190, "SetTlsCleanupFlag (29 bytes)")

# ===================================================================
# PART 6: FUN_0044b130 — the critical section check at the start
# of FUN_00878080. What lock is this? Could it prevent our trigger?
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: FUN_00878080 entry lock")
write("#" * 70)

decompile_at(0x0044b130, "FUN_0044b130 (TryEnterCriticalSection wrapper?)")
decompile_at(0x0082f1f0, "FUN_0082f1f0 (LeaveCriticalSection wrapper?)")

# ===================================================================
# PART 7: Does FUN_00868330 (NiNode enqueue) check TLS flag?
# This tells us if TLS=0 bypasses the queue entirely
# ===================================================================
write("")
write("#" * 70)
write("# PART 7: NiNode enqueue TLS check (already have but verify)")
write("#" * 70)

# From earlier research, FUN_00868330 has:
# if (TLS[0x298] == 0 || (DAT_011ddf38 && FUN_0042ce10(DAT_011ddf38)))
#   → immediate destruction (FUN_00418d20)
# else
#   → enqueue to DAT_011de808 (FUN_008693c0)
# This confirms TLS=0 causes immediate destruction

# ===================================================================
# PART 8: FUN_00866a90 Stage 5 — verify it only unloads 1 cell
# ===================================================================
write("")
write("#" * 70)
write("# PART 8: HeapCompact Stage 5 cell count (already have)")
write("#" * 70)

write("From earlier decompilation of HeapCompact Stage 5:")
write("  case 5:")
write("    if (!bVar5) break;  // main thread only")
write("    FUN_00869190(0);  // TLS = 0 (immediate)")
write("    uVar4 = FUN_00453a80(DAT_011dea10);  // FindCellToUnload")
write("    if ((uVar4 & 0xff) == 0) {")
write("        FUN_004539a0(DAT_011dea10, 1, 0);  // ForceUnloadCell")
write("    } else {")
write("        param_2 = param_2 - 1;  // retry Stage 5 next time")
write("    }")
write("    FUN_00452490(DAT_011dea10, 0);  // ProcessPendingCleanup")
write("    FUN_00869190(1);  // TLS = 1 (deferred)")
write("    FUN_00868d70(1);  // PDD (try_lock)")
write("")
write("KEY: If FindCellToUnload succeeds, param_2 is decremented")
write("(param_2 - 1 = 4), so HeapCompact returns 5 (param_2+1=5)")
write("and the FUN_00878080 loop calls Stage 5 AGAIN.")
write("This means Stage 5 loops until no more cells can be unloaded.")
write("")
write("But it returns to the FUN_00878080 loop between iterations,")
write("allowing the stage counter check (uVar4 < local_c).")


write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

# Write output
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/heapcompact_trigger.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
