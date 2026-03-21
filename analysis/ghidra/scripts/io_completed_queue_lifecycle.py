# @category Analysis
# @description Research IOManager completed task queue lifecycle
#
# Crash: main thread in FUN_0044dd60 releasing completed QueuedTexture
# The completed queue holds tasks AFTER BSTaskManagerThread processes them.
# Main thread dequeues them in Phase 3 (FUN_00c3dbf0) with a time budget.
# If tasks sit in the queue > 30 frames, quarantine frees their memory.
#
# Need to understand:
# 1. How does BSTaskManagerThread put completed tasks back?
# 2. Where is the completed queue? Is it the same as the dequeue queue?
# 3. How does FUN_00c3dbf0 dequeue completed tasks?
# 4. What is the time budget? How deep can the queue get?
# 5. Does FUN_00448620 (task cancellation) handle completed tasks?
# 6. What holds the ref on completed tasks in the queue?

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
write("IO COMPLETED TASK QUEUE LIFECYCLE")
write("=" * 70)

# SECTION 1: FUN_00c3dbf0 - main thread IO processing
# How does it dequeue completed tasks? What is the time budget?
write("")
write("# SECTION 1: FUN_00c3dbf0 - main thread IO processing (full)")
decompile_at(0x00C3DBF0, "IO_MainThreadProcess")

# SECTION 2: FUN_00c3e420 - queue dequeue (called by main thread)
# This dequeues completed tasks. What queue does it read from?
write("")
write("# SECTION 2: FUN_00c3e420 - completed task dequeue")
decompile_at(0x00C3E420, "CompletedQueue_Dequeue")

# SECTION 3: How does BSTaskManagerThread put tasks into completed queue?
# After process+complete, the task is released. But is it also queued?
# Look at IOManager vtable+0x48 (called at end of task body FUN_0043c050)
write("")
write("# SECTION 3: IOManager vtable+0x48 - task completion notification")
write("# Called at end of QueuedTexture task body: (*DAT_01202d98->vtable+0x48)(this)")
# Read IOManager vtable
io_mgr_vtable_addr = 0x010C1604  # IOManager RTTI suggests vtable nearby
# Actually, the task body calls *(*(DAT_01202d98) + 0x48)
# DAT_01202d98 is IOManager singleton. *(DAT_01202d98) = vtable.
# vtable+0x48 is the completion callback.
# Let's find what function is at IOManager_vtable+0x48
# We need the IOManager vtable address first.
find_xrefs_to(0x010C1604, "IOManager_RTTI")

# SECTION 4: FUN_0044dd60 - task release. WHO calls it on completed tasks?
write("")
write("# SECTION 4: FUN_0044dd60 callers - who releases tasks?")
find_xrefs_to(0x0044DD60, "TaskRelease_callers")

# SECTION 5: FUN_00c42b80 - the cleanup function in BSTaskManagerThread
# From earlier analysis this was called from BSTaskManagerThread.
# Does it process completed tasks?
write("")
write("# SECTION 5: FUN_00c42b80 - BSTaskManagerThread cleanup")
decompile_at(0x00C42B80, "BSTask_Cleanup")

# SECTION 6: FUN_00448620 - task cancellation
# Does it handle completed tasks in the queue?
write("")
write("# SECTION 6: FUN_00448620 - task cancellation internals")
decompile_at(0x00448620, "TaskCancel")
find_calls_from(0x00448620, "TaskCancel")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/io_completed_queue_lifecycle.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
