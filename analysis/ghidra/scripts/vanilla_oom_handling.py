# @category Analysis
# @description Research how vanilla game handles OOM - the original allocator's retry loop
#
# The original FUN_00aa3e40 has a do-while retry loop with FUN_00866a90.
# This is the game's OWN OOM handler. We replaced it with mimalloc.
# Need to understand EXACTLY what the vanilla OOM handler does:
# 1. What does FUN_00866a90 do per stage?
# 2. How many stages are there?
# 3. Does Stage 5 (which we skip) actually fix the OOM?
# 4. What does the game do differently from us?
# 5. Does the original allocator call D3D9 to release resources?

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)
listing = currentProgram.getListing()

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=6000):
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
	write("  Function: %s, Size: %d bytes" % (func.getName(), sz))
	write("  Entry: 0x%08x" % entry)
	result = decomp.decompileFunction(func, 60, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def find_calls_from(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	body = func.getBody()
	addr_iter = body.getAddresses(True)
	count = 0
	while addr_iter.hasNext():
		a = addr_iter.next()
		inst = listing.getInstructionAt(a)
		if inst is None:
			continue
		if not inst.getFlowType().isCall():
			continue
		refs_from = inst.getReferencesFrom()
		for r in refs_from:
			target = r.getToAddress().getOffset()
			target_func = fm.getFunctionAt(toAddr(target))
			target_name = target_func.getName() if target_func else "unknown_0x%08x" % target
			write("  CALL 0x%08x -> %s (from 0x%08x)" % (target, target_name, a.getOffset()))
			count += 1
	write("  Total: %d calls" % count)

def find_xrefs_to(addr_int, label, limit=10):
	addr = toAddr(addr_int)
	refs = getReferencesTo(addr)
	write("")
	write("--- XRefs to %s (0x%08x) ---" % (label, addr_int))
	count = 0
	for ref in refs:
		from_addr = ref.getFromAddress()
		func = fm.getFunctionContaining(from_addr)
		fname = func.getName() if func else "???"
		write("  %s @ 0x%s (in %s)" % (ref.getReferenceType(), from_addr, fname))
		count += 1
		if count >= limit:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)


write("=" * 70)
write("VANILLA OOM HANDLING - ORIGINAL ALLOCATOR RETRY LOOP")
write("=" * 70)

# SECTION 1: FUN_00866a90 - THE key function. Called per HeapCompact stage
# AND from the allocator's OOM retry loop. What does each stage do?
write("")
write("# SECTION 1: FUN_00866a90 - HeapCompact stage executor (OOM handler)")
decompile_at(0x00866A90, "OOM_StageExec")
find_calls_from(0x00866A90, "OOM_StageExec")

# SECTION 2: The stages call different cleanup functions.
# We need to trace what each stage number dispatches to.
# Stage 0 = ProcessPendingCleanup
# Stage 1 = SBM cleanup
# Stage 2 = BSA/texture cleanup
# Stage 3+ = ???
# Look at how the stage number maps to function calls
write("")
write("# SECTION 2: What does FUN_00866a90 do with stage=0?")
write("# And stage=1, 2, 3, 4, 5?")
write("# The function uses the stage number to dispatch different cleanup")

# SECTION 3: FUN_00aa4290 - CRT malloc fallback in allocator
write("")
write("# SECTION 3: FUN_00aa4290 - CRT fallback allocator")
decompile_at(0x00AA4290, "CRT_Fallback")

# SECTION 4: FUN_00aa4960 - called from allocator when size < 0x3fd
write("")
write("# SECTION 4: FUN_00aa4960 - small alloc optimization?")
decompile_at(0x00AA4960, "SmallAlloc")

# SECTION 5: How does the original allocator's retry loop work?
# FUN_00aa3e40 do-while loop calls FUN_00866a90 repeatedly
# The local_d flag controls when to stop
write("")
write("# SECTION 5: FUN_00aa3e40 retry loop - full re-read")
decompile_at(0x00AA3E40, "Allocator_RetryLoop")

# SECTION 6: Who else calls FUN_00866a90?
write("")
write("# SECTION 6: All callers of FUN_00866a90")
find_xrefs_to(0x00866A90, "StageExec_callers")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/vanilla_oom_handling.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
