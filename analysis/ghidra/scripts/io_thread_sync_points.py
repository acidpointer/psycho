# @category Analysis
# @description Find IO thread synchronization points.
# Goal: Can we check if IO queue is empty? Can we pause the IO thread?
# The async flush (FUN_00c459d0) blocks until IO completes — trace it.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
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
	write("  Function: %s, Size: %d bytes" % (func.getName(), func.getBody().getNumAddresses()))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

write("=" * 70)
write("IO THREAD SYNCHRONIZATION POINTS")
write("=" * 70)

# Part 1: AsyncQueueFlush — the blocking flush
write("")
write("#" * 70)
write("# PART 1: AsyncQueueFlush (FUN_00c459d0) — blocking mode")
write("# param=0 blocks. What does it wait on? How does it drain?")
write("#" * 70)

decompile_at(0x00C459D0, "AsyncQueueFlush (172 bytes)")

# Part 2: The IO task completion mechanism
write("")
write("#" * 70)
write("# PART 2: How does the IO thread signal task completion?")
write("#" * 70)

decompile_at(0x00C40E70, "IO_DequeueTask (FUN_00c40e70)")
decompile_at(0x00C42060, "IO_SignalCompletion (FUN_00c42060)")

# Part 3: IOManager structure — find queue count field
write("")
write("#" * 70)
write("# PART 3: IOManager fields — is there a pending task count?")
write("#" * 70)

decompile_at(0x00449150, "IOTask_Enqueue (FUN_00449150)")
decompile_at(0x0044DD60, "IOTask_DecRef (FUN_0044dd60)")
decompile_at(0x0044DDC0, "GetQueueCount (FUN_0044ddc0)")

# Part 4: BSTaskManagerThread — its Event/Semaphore
write("")
write("#" * 70)
write("# PART 4: BSTaskManagerThread sync primitives")
write("#" * 70)

decompile_at(0x00C42DA0, "BSTaskManager_ThreadEntry (37 bytes)")
decompile_at(0x00C410B0, "BSTaskManager_MainLoop (633 bytes)", 10000)

# Part 5: What FUN_00b5fd60 does (called by DeferredCleanupSmall)
write("")
write("#" * 70)
write("# PART 5: FUN_00b5fd60 — called between PDD and AsyncFlush")
write("#" * 70)

decompile_at(0x00B5FD60, "DCS_Middle (FUN_00b5fd60)")

write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/io_thread_sync_points.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
