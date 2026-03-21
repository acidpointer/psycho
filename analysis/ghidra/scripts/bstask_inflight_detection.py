# @category Analysis
# @description Deep research: how to reliably detect BSTaskManagerThread in-flight state
#
# Problem: after acquiring IO lock, BSTaskManagerThread is in one of:
# a) Blocked on our lock at dequeue (no task, safe)
# b) Mid-task processing (has task, unsafe to flush quarantine)
# Both show semaphore count=0, iter_count stable for variable time.
# Any timeout is a guess. Need a RELIABLE detection mechanism.
#
# Questions:
# 1. What thread state can we read to detect "blocked in spin-lock"?
# 2. Does BSTaskManagerThread write any flag BEFORE processing that we can read?
# 3. Is there a task pointer we can check (local_38 equivalent in memory)?
# 4. Can we check BSTaskManagerThread's instruction pointer / stack?
# 5. What does FUN_00c42060(local_30, 0) do - does it set a state?
# 6. Is there a "currently processing task" field anywhere?

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

def disasm_range(start_int, count=30):
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int - 1))
	for i in range(count):
		if inst is None:
			break
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()

def find_xrefs_to(addr_int, label, limit=15):
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


write("=" * 70)
write("BSTaskManagerThread IN-FLIGHT DETECTION RESEARCH")
write("=" * 70)

# SECTION 1: FUN_00c42060(local_30, param) - what state does it set?
# Called at multiple points in the inner loop. What does it write?
write("")
write("# SECTION 1: FUN_00c42060 - state setter in BSTaskManagerThread loop")
decompile_at(0x00C42060, "BSTask_SetState")

# SECTION 2: local_30 layout - what IS the state object?
# local_30[0] is set to PTR_FUN_010c1664 at start, PTR_FUN_010c1670 at end
# These are vtable pointers. What classes are they?
def dump_vtables():
	write("")
	write("# SECTION 2: State vtables - PTR_FUN_010c1664 and PTR_FUN_010c1670")
	for i in range(4):
		addr = toAddr(0x010C1664 + i * 4)
		raw = getInt(addr) & 0xFFFFFFFF
		target_func = fm.getFunctionAt(toAddr(raw))
		fname = target_func.getName() if target_func else "unknown"
		write("  010c1664[%d]: 0x%08x -> %s" % (i, raw, fname))
	write("")
	for i in range(4):
		addr = toAddr(0x010C1670 + i * 4)
		raw = getInt(addr) & 0xFFFFFFFF
		target_func = fm.getFunctionAt(toAddr(raw))
		fname = target_func.getName() if target_func else "unknown"
		write("  010c1670[%d]: 0x%08x -> %s" % (i, raw, fname))

dump_vtables()

# SECTION 3: BSTaskManagerThread object layout
# param_1 is the BSTaskManagerThread object
# +0x0c: pending count (InterlockedDecrement after work sem)
# +0x10: work semaphore HANDLE
# +0x18: iter count (InterlockedIncrement)
# +0x1c: iter semaphore HANDLE
# +0x30: pointer to IOManager dispatch table
# What else is in the object? Is there a "current task" field?
write("")
write("# SECTION 3: BSTaskManagerThread constructor - object layout")
decompile_at(0x00C42DD0, "BSTaskThread_init")
find_calls_from(0x00C42DD0, "BSTaskThread_init")

# SECTION 4: The process/complete dispatch
# (**(code **)(**(int **)(param_1 + 0x30) + 0x4c))(local_38)
# (**(code **)(**(int **)(param_1 + 0x30) + 0x50))(local_38)
# Does the dispatch table at *(param_1+0x30) have a "current task" field?
write("")
write("# SECTION 4: IOManager dispatch table layout")
write("# *(param_1+0x30) points to IOManager. Check fields near +0x4c/+0x50")

# SECTION 5: FUN_00c40e70 (IO_DequeueTask) - full flow including lock
# Does it write the dequeued task somewhere in the BSTaskManagerThread object?
write("")
write("# SECTION 5: IO_DequeueTask - where does dequeued task go?")
write("# param_2 receives the task. Is it also stored in the thread object?")
disasm_range(0x00C40E70, 30)

# SECTION 6: FUN_00c3f750 - what does this return? (called in dequeue)
write("")
write("# SECTION 6: FUN_00c3f750 - helper in dequeue path")
decompile_at(0x00C3F750, "Dequeue_Helper")

# SECTION 7: The spin-lock itself - what field stores the holder threadID?
# Can we check if BSTaskManagerThread is spinning on it?
write("")
write("# SECTION 7: Spin-lock internals (FUN_0040fbf0)")
write("# +0x00 = lock (threadID of holder, 0 = free)")
write("# +0x04 = reentrance counter")
write("# What threadID does BSTaskManagerThread have?")
disasm_range(0x0040FBF0, 30)

# SECTION 8: Can we read BSTaskManagerThread's thread HANDLE/ID?
# BSTaskThread_init creates the thread. Where is the handle stored?
write("")
write("# SECTION 8: BSTaskManagerThread thread handle / ID")
write("# Need to find where the thread handle is stored in the object")
write("# to use GetThreadId or check against lock holder")
find_xrefs_to(0x00C410B0, "BSTask_LoopFunc_callers")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/bstask_inflight_detection.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
