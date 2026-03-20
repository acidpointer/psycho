# @category Analysis
# @description Research BSTaskManagerThread wait/sync mechanisms for proper cell unload sync

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=8000):
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


write("=" * 70)
write("BSTaskManagerThread SYNCHRONIZATION MECHANISM RESEARCH")
write("Goal: Find how the game properly waits for IO thread to be idle")
write("=" * 70)

# SECTION 1: How CellTransitionHandler waits for BSTaskManagerThread
write("")
write("#" * 70)
write("# SECTION 1: CellTransitionHandler IO wait mechanism")
write("# FUN_008774a0 calls FUN_00877700 to wait for BSTaskManagerThread")
write("#" * 70)

decompile_at(0x008774A0, "CellTransitionHandler")
find_calls_from(0x008774A0, "CellTransitionHandler")

decompile_at(0x00877700, "IO_Wait_Wrapper")
find_calls_from(0x00877700, "IO_Wait_Wrapper")

decompile_at(0x00AD8DA0, "WaitForHandle_1000ms")
find_calls_from(0x00AD8DA0, "WaitForHandle_1000ms")

# SECTION 2: Who else waits for BSTaskManagerThread?
write("")
write("#" * 70)
write("# SECTION 2: All callers of FUN_00877700 (IO wait)")
write("#" * 70)

find_xrefs_to(0x00877700, "IO_Wait_Wrapper")

# SECTION 3: The TES+0x77c handle — how is it set/cleared?
write("")
write("#" * 70)
write("# SECTION 3: TES+0x77c handle lifecycle")
write("# Who sets it to track IO tasks? Who clears it?")
write("#" * 70)

# TES singleton is at DAT_011dea3c, offset 0x77c
# Look for writes to TES+0x77c
find_xrefs_to(0x011DEA3C, "TES_singleton_ptr", 15)

# SECTION 4: IOManager task queue management
# How are tasks submitted and how does the game know all tasks completed?
write("")
write("#" * 70)
write("# SECTION 4: IOManager task submission and completion")
write("#" * 70)

# FUN_00c3f750 — gets IOManager queue? (called from BSTaskManagerThread loop)
decompile_at(0x00C3F750, "IOManager_GetQueue")

# FUN_00c40e70 — dequeue task (called from BSTaskManagerThread loop)
decompile_at(0x00C40E70, "IO_DequeueTask", 12000)

# FUN_00c42060 — signal completion
decompile_at(0x00C42060, "IO_SignalCompletion")

# SECTION 5: IOManager struct layout and locking
write("")
write("#" * 70)
write("# SECTION 5: IOManager singleton and its locking mechanism")
write("#" * 70)

# The IOManager RTTI
find_xrefs_to(0x010C1604, "IOManager_RTTI", 15)
find_xrefs_to(0x010C1740, "BSTaskManagerThread_RTTI", 15)

# IOManager singleton pointer?
# FUN_00c3dba0 — likely GetIOManager
decompile_at(0x00C3DBA0, "GetIOManager_maybe")

# SECTION 6: FUN_00c3fc94 — the actual task dispatch/processing on IO thread
# This is in the crash callstack for ExteriorCellLoaderTask
write("")
write("#" * 70)
write("# SECTION 6: IO task dispatch — vtable+0x4c and vtable+0x50")
write("#" * 70)

decompile_at(0x00C3FC94, "IO_TaskDispatch_area")

# SECTION 7: How does the game CANCEL pending IO tasks during cell unload?
write("")
write("#" * 70)
write("# SECTION 7: DestroyCell internals — does it cancel IO tasks?")
write("#" * 70)

decompile_at(0x00462290, "DestroyCell", 12000)
find_calls_from(0x00462290, "DestroyCell")

# SECTION 8: FUN_004539a0 — pre-cleanup before cell unload
# CellTransitionHandler calls this before PDD
write("")
write("#" * 70)
write("# SECTION 8: Pre-unload cleanup functions")
write("#" * 70)

decompile_at(0x004539A0, "PreCellUnload_cleanup")
decompile_at(0x00453A70, "PreCellUnload_prep")

# SECTION 9: The blocking async flush — FUN_00c459d0 internals
# Specifically: what does it actually drain? Task queue or completion queue?
write("")
write("#" * 70)
write("# SECTION 9: AsyncFlush inner queue — what exactly gets drained?")
write("#" * 70)

decompile_at(0x00C46270, "AsyncFlush_DequeueItem")
decompile_at(0x00C45B20, "AsyncFlush_DrainBatch")

# SECTION 10: BSTaskManagerThread object layout
# param_1 offsets: +0x10 event, +0x0c count, +0x1c semaphore, +0x18 sem_count, +0x30 queue_mgr
write("")
write("#" * 70)
write("# SECTION 10: BSTaskManagerThread constructor (object layout)")
write("#" * 70)

# Look for constructor that sets up the events/semaphores
find_xrefs_to(0x010C1664, "BSTaskThread_vtable1_ptr", 10)
find_xrefs_to(0x010C1670, "BSTaskThread_vtable2_ptr", 10)

# FUN_00c42dc5 — likely BSTaskManagerThread constructor
decompile_at(0x00C42DC5, "BSTaskManagerThread_ctor_area")

# SECTION 11: IOManager task count and idle detection
write("")
write("#" * 70)
write("# SECTION 11: Is there a 'pending task count' in IOManager?")
write("#" * 70)

# DAT_01202e20 is referenced by AsyncFlush as the queue base
find_xrefs_to(0x01202E20, "IO_QueueBase", 20)
find_xrefs_to(0x01202E2A, "IO_QueueCount_ushort", 20)
find_xrefs_to(0x01202E40, "IO_FlushLock", 20)
find_xrefs_to(0x01202E44, "IO_FlushCounter", 20)

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/io_thread_wait_mechanism.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
