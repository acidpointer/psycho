# @category Analysis
# @description Analyze what the IO dequeue lock actually protects vs what it doesn't
#
# The IO lock at IOManager+0x20 blocks IO_DequeueTask (new task pickup).
# But BSTaskManagerThread may already have a task in-flight when we acquire.
# Need to understand: what happens between dequeue and task completion?

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

def disasm_range(start_int, count=25):
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int - 1))
	for i in range(count):
		if inst is None:
			break
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()

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
write("IO LOCK PROTECTION SCOPE ANALYSIS")
write("=" * 70)

# SECTION 1: IO_DequeueTask - where exactly is the lock acquired?
write("")
write("# SECTION 1: FUN_00c40e70 - IO_DequeueTask (called by BSTaskManagerThread)")
write("# This is where the IO lock at +0x20 is acquired")
decompile_at(0x00C40E70, "IO_DequeueTask")
find_calls_from(0x00C40E70, "IO_DequeueTask")

# SECTION 2: BSTaskManagerThread loop - full context of dequeue vs process
write("")
write("# SECTION 2: BSTaskManagerThread inner loop (FUN_00c410b0)")
write("# Where dequeue happens relative to task processing")
write("# Key: dequeue at FUN_00c40e70, process at vtable+0x4c, complete at vtable+0x50")
decompile_at(0x00C410B0, "BSTask_FullLoop")

# SECTION 3: The inter-iteration semaphore lifecycle
write("")
write("# SECTION 3: Semaphore at +0x1c lifecycle in the loop")
write("# WaitForSingleObject(+0x1c, 0) probes idle state")
write("# ReleaseSemaphore(+0x1c, 1, NULL) signals iteration done")
write("# Our io_lock_acquire uses this to detect mid-task")
disasm_range(0x00C41150, 40)

# SECTION 4: What objects does BSTaskManagerThread hold during processing?
write("")
write("# SECTION 4: FUN_0043C090 - QueuedTexture task body")
write("# What refs does it hold? What can be freed under it?")
decompile_at(0x0043C090, "QueuedTexture_TaskBody")
find_calls_from(0x0043C090, "QueuedTexture_TaskBody")

# SECTION 5: FUN_0044dd60 - task release after processing
write("")
write("# SECTION 5: FUN_0044dd60 - task ref release")
decompile_at(0x0044DD60, "TaskRelease")

# SECTION 6: LockFreeQueue dequeue - is there a window between
# dequeue and the IO lock check?
write("")
write("# SECTION 6: FUN_00c3e420 - LockFreeQueue dequeue?")
decompile_at(0x00C3E420, "Queue_Dequeue")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/io_lock_protection_scope.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
