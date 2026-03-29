# @category Analysis
# @description Investigate why HeapCompact stage 4 (PDD purge) causes game freeze
#
# The freeze pattern:
#   - HeapCompact stage 4 signaled from pressure relief every 2 seconds
#   - Game freezes during Phase 6 (HeapCompact runs stages 0-4)
#   - Main thread AND watchdog both stop (process-wide hang)
#   - Commit ~1.6-1.7GB, Gen queue had 761 entries before freeze
#
# HeapCompact frame check (FUN_00878080) calls FUN_00866a90 for each stage.
# Stage 4 presumably calls full PDD drain or similar.
# Need to find: what does FUN_00866a90 do at stage=4?
#
# Also: HeapCompact acquires a critical section (line 738 of frame check).
# Does PDD also acquire locks? Is there a lock ordering issue?
#
# Key addresses:
#   FUN_00866a90 — OOM/HeapCompact stage executor
#   FUN_00878080 — HeapCompact frame check (Phase 6)
#   FUN_00868d70 — Full PDD drain
#   FUN_00452490 — ProcessPendingCleanup (BSTreeManager cleanup)
#   DAT_011de804 — PDD skip mask
#   DAT_011de958 — PDD reentrancy guard
#   Gen queue: 0x11de874 (had 761 entries before freeze)

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


write("HeapCompact Stage 4 PDD Freeze Investigation")
write("=" * 70)

# ===================================================================
# PART 1: OOM/HeapCompact stage executor — what does each stage do?
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: OOM/HeapCompact Stage Executor (FUN_00866a90)")
write("#" * 70)
write("# Called from HeapCompact frame check with stage 0,1,2,3,4")
write("# Need to see what stage 4 specifically does")

decompile_at(0x00866a90, "OOM/HeapCompact stage executor (THE KEY FUNCTION)", 20000)
find_and_print_calls_from(0x00866a90, "Stage executor")

# ===================================================================
# PART 2: What locks does HeapCompact hold?
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: HeapCompact Locking")
write("#" * 70)
write("# FUN_00878080 acquires critical section at param_1+0x14")
write("# FUN_0044b130 = TryEnterCriticalSection wrapper?")

decompile_at(0x0044b130, "TryEnterCriticalSection wrapper")
decompile_at(0x0082f1f0, "LeaveCriticalSection wrapper (release)")

# ===================================================================
# PART 3: Full PDD reentrancy guard and locks
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: Full PDD Locking (FUN_00868d70)")
write("#" * 70)
write("# DAT_011de958 is reentrancy guard (set to 1 during PDD)")
write("# FUN_00867f50/FUN_00867f70 = PDD lock acquire")
write("# FUN_00867f80 = PDD lock release")

decompile_at(0x00867f50, "PDD lock acquire (blocking)")
decompile_at(0x00867f70, "PDD lock acquire (try)")
decompile_at(0x00867f80, "PDD lock release")

# ===================================================================
# PART 4: ProcessPendingCleanup — what locks does it take?
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: ProcessPendingCleanup (FUN_00452490)")
write("#" * 70)

decompile_at(0x00452490, "ProcessPendingCleanup")
find_and_print_calls_from(0x00452490, "ProcessPendingCleanup")

# ===================================================================
# PART 5: Generic queue processing — what does processing 761 entries do?
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: Generic Queue (0x11de874) Processing")
write("#" * 70)
write("# Gen queue had 761 entries before freeze.")
write("# Full PDD processes Generic with: while count != 0, call vtable[4]")
write("# Per-frame processes with: cVar1 = FUN_00868250, rate limited")

# FUN_00868250 — the PDD processing gate
decompile_at(0x00868250, "PDD processing gate (FUN_00868250)")

# What are Generic queue entries? They have vtable calls at +0x10
# Look at what the vtable[4] call does for generic entries
# From full PDD: (**(code **)(*(int *)*piVar7 + 0x10))(1);

# ===================================================================
# PART 6: FUN_004aaf10 — called after generic queue processing
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: FUN_004aaf10 (post-queue-drain cleanup)")
write("#" * 70)

decompile_at(0x004aaf10, "Post-queue-drain cleanup")

# ===================================================================
# PART 7: DAT_011de804 (PDD skip mask) — who writes it?
# ===================================================================
write("")
write("#" * 70)
write("# PART 7: PDD Skip Mask (DAT_011de804)")
write("#" * 70)

find_refs_to(0x011de804, "PDD skip mask (DAT_011de804)")

# ===================================================================
# PART 8: FUN_00452530 — called by full PDD (stage 0x10 check)
# ===================================================================
write("")
write("#" * 70)
write("# PART 8: FUN_00452530 (called by full PDD after stage 0x10)")
write("#" * 70)

decompile_at(0x00452530, "Full PDD stage 0x10 handler")
find_and_print_calls_from(0x00452530, "Full PDD stage 0x10")

# ===================================================================
# PART 9: The critical section at heap+0x14 — who else acquires it?
# ===================================================================
write("")
write("#" * 70)
write("# PART 9: Heap Critical Section (heap_singleton + 0x14 = 0x011F624C)")
write("#" * 70)
write("# HeapCompact acquires this. If PDD or our code also acquires it...")

find_refs_to(0x011F624C, "Heap critical section (heap+0x14)")

# ===================================================================
# PART 10: What happens when stage executor hits stage 4?
# ===================================================================
write("")
write("#" * 70)
write("# PART 10: Stage 4 specific path in executor")
write("#" * 70)
write("# Need to trace what FUN_00866a90 does when stage=4")
write("# It probably calls different functions for different stages")

# The stage executor likely has a switch/if chain
# Already decompiled in PART 1, but let's also check what it calls
# that we haven't seen yet

# FUN_00878310 — might be a stage-specific function
decompile_at(0x00878310, "Possible stage handler (near HeapCompact)")
decompile_at(0x00878130, "HeapCompact trigger reset (FUN_00878130)")

# FUN_0078d1f0 — called by full PDD (IO-related check?)
decompile_at(0x0078d1f0, "IO check in full PDD (FUN_0078d1f0)")


write("")
write("=" * 70)
write("ANALYSIS COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/stage4_pdd_freeze.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
