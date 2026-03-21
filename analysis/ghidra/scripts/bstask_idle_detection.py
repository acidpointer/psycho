# @category Analysis
# @description Research BSTaskManagerThread idle detection — proper mechanism instead of timeout

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

def disasm_range(start_int, count=30):
	listing = currentProgram.getListing()
	inst = listing.getInstructionAfter(toAddr(start_int - 1))
	for i in range(count):
		if inst is None:
			break
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()


write("=" * 70)
write("BSTaskManagerThread IDLE DETECTION RESEARCH")
write("Goal: Distinguish 'idle' from 'busy processing' without timeout")
write("=" * 70)

# SECTION 1: BSTaskManagerThread_Loop detailed analysis
# Focus on the state transitions: idle → processing → dequeue → idle
write("")
write("#" * 70)
write("# SECTION 1: BSTaskManagerThread_Loop — state transitions")
write("# Identify flags/counters that indicate 'idle' vs 'processing'")
write("#" * 70)

decompile_at(0x00C410B0, "BSTaskManagerThread_Loop", 15000)

# SECTION 2: The pending event count at BSTaskManagerThread+0x0c
# When BSTaskManagerThread wakes, it decrements this.
# When a task is submitted, this is incremented (via SetEvent/ReleaseSemaphore).
# If +0x0c == 0, no pending wakeups = thread is either idle or processing last task.
write("")
write("#" * 70)
write("# SECTION 2: Who increments BSTaskManagerThread+0x0c?")
write("# (pending event count — InterlockedIncrement when task submitted)")
write("#" * 70)

# BSTaskThread_init: *(+0x0c) = 0 initially
# BSTaskManagerThread_Loop: InterlockedDecrement(+0x0c) on wakeup
# Who does InterlockedIncrement(+0x0c)?
# Search for the semaphore at +0x10 — who signals it?

# FUN_00c42f50 — starts the BSTaskManagerThread (called from BSTaskManager_ctor)
decompile_at(0x00C42F50, "BSTaskThread_Start")

# SECTION 3: How are tasks submitted to BSTaskManagerThread?
# Find the function that submits IO tasks and signals the semaphore
write("")
write("#" * 70)
write("# SECTION 3: Task submission — who signals BSTaskManagerThread?")
write("#" * 70)

# FUN_00c3f860 — likely task submit function (called from various places)
decompile_at(0x00C3F860, "IOTask_Submit_maybe")

# FUN_00c40990 — another task-related function (references vtable2)
decompile_at(0x00C40990, "IOTask_Related1")

# FUN_00c40b40 — another task-related function (references vtable2)
decompile_at(0x00C40B40, "IOTask_Related2")

# SECTION 4: The inner loop exit condition
# (local_18 & 2) == 0 → continue processing
# (local_18 & 2) != 0 → queue exhausted, exit inner loop
# Where is bit 2 set? This is the "queue empty" flag
write("")
write("#" * 70)
write("# SECTION 4: Queue exhausted flag (bit 2 of local_18)")
write("# When set, BSTaskManagerThread exits inner loop → goes to WaitForSingleObject")
write("#" * 70)

# The flag is at the BSTaskManagerThread's local state, not a global.
# But IO_DequeueTask sets it when no more tasks:
# *(byte*)(param_1 + 0x18) |= 2  (queue exhausted)
# Look at how it's cleared and set

# SECTION 5: BSTaskManagerThread_Loop semaphore usage
# +0x10 is the wake semaphore (WaitForSingleObject)
# +0x1c is the inter-iteration semaphore
# +0x0c is the pending count
# +0x18 is the iteration count
write("")
write("#" * 70)
write("# SECTION 5: Semaphore handle at +0x10 — can we WaitForSingleObject on it?")
write("# If we wait on the same semaphore with 0 timeout, we can detect if")
write("# there are pending tasks (wait succeeds) or not (WAIT_TIMEOUT)")
write("#" * 70)

# The wake semaphore at +0x10:
# - Initial count: *(+0x0c) = 0
# - Max count: *(+0x14) = 0x7FFFFFFF
# - BSTaskManagerThread does WaitForSingleObject(+0x10, INFINITE) to block
# - When a task is submitted, someone does ReleaseSemaphore(+0x10, 1, ...) to wake it
# - BSTaskManagerThread does InterlockedDecrement(+0x0c) after waking

# Can we check the semaphore count directly? No — Windows doesn't expose it.
# Can we check +0x0c (pending count)? If 0, no tasks are pending.
# But the thread might still be processing the LAST task (decremented +0x0c already)

# SECTION 6: Alternative — SuspendThread/ResumeThread
# We could suspend BSTaskManagerThread, check its EIP (GetThreadContext),
# determine if it's in WaitForSingleObject (idle) or in task code (busy)
write("")
write("#" * 70)
write("# SECTION 6: BSTaskManagerThread thread handle location")
write("# BSTaskThread_init creates the thread — handle at +0x04?")
write("#" * 70)

decompile_at(0x00C42DD0, "BSTaskThread_init")

# The thread handle is at +0x04 (from CreateThread return value)
# We can use: SuspendThread(handle) → GetThreadContext → check EIP → ResumeThread

# SECTION 7: Alternative — use the inter-iteration semaphore +0x1c
# BSTaskManagerThread does ReleaseSemaphore(+0x1c, 1, 0) after EACH iteration
# and WaitForSingleObject(+0x1c, 0) at the START of each iteration.
# If we do WaitForSingleObject(+0x1c, INFINITE), we'd wait for one iteration to complete.
# But this CONSUMES the signal — BSTaskManagerThread might deadlock.
write("")
write("#" * 70)
write("# SECTION 7: Can we safely wait on the +0x1c semaphore?")
write("#" * 70)

# Disasm the semaphore wait/release pattern in the loop
write("BSTaskManagerThread_Loop semaphore usage:")
disasm_range(0x00C41100, 30)

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/bstask_idle_detection.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
