# @category Analysis
# @description Research IO thread quiescing: how game drains BSTaskManagerThread before cell unloads

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
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
	entry = func.getEntryPoint().getOffset()
	sz = func.getBody().getNumAddresses()
	write("  Function: %s, Size: %d bytes" % (func.getName(), sz))
	write("  Entry: 0x%08x" % entry)
	result = decomp.decompileFunction(func, 120, monitor)
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
	listing = currentProgram.getListing()
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

def find_xrefs_to(addr_int, label, limit=30):
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
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total: %d refs" % count)


write("=" * 70)
write("IO THREAD QUIESCE MECHANISM — DEEP RESEARCH")
write("How does the game ensure BSTaskManagerThread is idle before PDD?")
write("=" * 70)

# SECTION 1: IO flush chain — the three flush-related functions
write("")
write("#" * 70)
write("# SECTION 1: IO flush chain (FUN_00c45830, FUN_00c458f0, FUN_00c459d0)")
write("# These all reference IO_FlushLock/Counter/QueueBase")
write("#" * 70)

decompile_at(0x00C45830, "IO_FlushRequest")
find_calls_from(0x00C45830, "IO_FlushRequest")

decompile_at(0x00C458F0, "IO_DeferredTaskBudget")
find_calls_from(0x00C458F0, "IO_DeferredTaskBudget")

# Who calls these?
find_xrefs_to(0x00C45830, "IO_FlushRequest")
find_xrefs_to(0x00C458F0, "IO_DeferredTaskBudget")

# SECTION 2: PreCellUnload_cleanup internals
# FUN_004539a0 is called by CellTransitionHandler BEFORE cell unloads
write("")
write("#" * 70)
write("# SECTION 2: PreCellUnload_cleanup inner functions")
write("#" * 70)

# FUN_00455200 — unload preparation (called from 004539a0)
decompile_at(0x00455200, "UnloadPrep")
find_calls_from(0x00455200, "UnloadPrep")

# FUN_008d7dc0 — called when params (0,0) → likely LOD cleanup
decompile_at(0x008D7DC0, "LOD_Cleanup_maybe")
find_calls_from(0x008D7DC0, "LOD_Cleanup_maybe")

# FUN_00453940 — cleanup called from PreCellUnload
decompile_at(0x00453940, "PreUnload_Inner")
find_calls_from(0x00453940, "PreUnload_Inner")

# FUN_00454D50 — called at end of PreCellUnload
decompile_at(0x00454D50, "PostUnload_Cleanup")
find_calls_from(0x00454D50, "PostUnload_Cleanup")

# SECTION 3: FUN_007037c0 and FUN_0061cc40 — force unload cells
# Called by CellTransitionHandler with 0x7fffffff
write("")
write("#" * 70)
write("# SECTION 3: Force unload functions from CellTransitionHandler")
write("#" * 70)

decompile_at(0x007037C0, "ForceUnloadCells")
find_calls_from(0x007037C0, "ForceUnloadCells")

decompile_at(0x0061CC40, "ForceUnloadCells2")
find_calls_from(0x0061CC40, "ForceUnloadCells2")

# SECTION 4: IO queue count and pending state
# FUN_00c45ae0 references IO_QueueBase and IO_QueueCount
write("")
write("#" * 70)
write("# SECTION 4: IO queue pending count queries")
write("#" * 70)

decompile_at(0x00C45AE0, "IO_GetPendingCount")

# SECTION 5: BSTaskManagerThread object — find the singleton pointer
# We need to know how to access BSTaskManagerThread's handles
write("")
write("#" * 70)
write("# SECTION 5: BSTaskManagerThread singleton access")
write("#" * 70)

# FUN_00c3ee70 references BSTaskManagerThread RTTI
decompile_at(0x00C3EE70, "BSTaskManagerThread_GetSingleton_maybe")
find_xrefs_to(0x00C3EE70, "BSTaskManagerThread_GetSingleton")

# FUN_00c3da50 references IOManager RTTI
decompile_at(0x00C3DA50, "IOManager_Create_maybe")

# SECTION 6: lpCriticalSection_011f4380 — who enters it and why?
# The key functions that hold this CS
write("")
write("#" * 70)
write("# SECTION 6: Functions that enter lpCriticalSection_011f4380")
write("# These are the ones that block AsyncFlush TryEnter")
write("#" * 70)

# Main holders (from xref analysis):
decompile_at(0x00A5B990, "CS_Holder_1")
decompile_at(0x00A5BA40, "CS_Holder_2")
decompile_at(0x00A5BBA0, "CS_Holder_3")
decompile_at(0x0078D080, "CS_Holder_4")
decompile_at(0x00C5F680, "CS_Holder_5_IOArea")

# SECTION 7: FUN_00adc560 — the actual WaitForSingleObject wrapper
# Used by FUN_00ad8da0 to wait for TES+0x77c
write("")
write("#" * 70)
write("# SECTION 7: Wait mechanism — FUN_00adc560")
write("#" * 70)

decompile_at(0x00ADC560, "WaitForObject_WithTimeout")
find_calls_from(0x00ADC560, "WaitForObject_WithTimeout")

# Who calls FUN_00adc560? Other waiters we might use
find_xrefs_to(0x00ADC560, "WaitForObject_WithTimeout")

# SECTION 8: FUN_00ad8780 — called by CellTransitionHandler right after IO wait
# This might be part of the quiescing
write("")
write("#" * 70)
write("# SECTION 8: FUN_00ad8780 — post-IO-wait quiescing?")
write("#" * 70)

decompile_at(0x00AD8780, "PostIOWait_Quiesce")
find_calls_from(0x00AD8780, "PostIOWait_Quiesce")

# SECTION 9: The IOManager queue submission path
# How are texture tasks submitted? Can we block new submissions?
write("")
write("#" * 70)
write("# SECTION 9: Task submission to BSTaskManagerThread")
write("#" * 70)

# FUN_00c41610 — called from IOManager_GetQueue (creates TLS queue)
decompile_at(0x00C41610, "IOQueue_CreateTLS")

# FUN_00c416a0 — called from IO_ProcessTask_Variant2
decompile_at(0x00C416A0, "IOQueue_ProcessNext")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/io_thread_quiesce_mechanism.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
