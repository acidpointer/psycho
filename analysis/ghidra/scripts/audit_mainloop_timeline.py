# @category Analysis
# @description AUDIT: Main loop timeline — exact execution order.
# Need to know PRECISELY when AI threads are active/idle,
# when BSTaskManager processes tasks, when render runs,
# and where our hooks fire relative to all of this.
# This is THE critical document for understanding thread safety.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=15000):
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
write("AUDIT: MAIN LOOP EXECUTION TIMELINE")
write("=" * 70)
write("")
write("Goal: Map the exact order of operations in one frame.")
write("Where are AI threads signaled/joined?")
write("Where does BSTaskManager get work?")
write("Where is our hook (0x008705D0)?")
write("Where is HeapCompact (0x00878080)?")
write("Where is per-frame queue drain (0x00868850)?")

# Section 1: The main loop function (huge, but essential)
write("")
write("#" * 70)
write("# SECTION 1: Main loop (FUN_0086a850) — THE critical function")
write("# This is ~5000+ bytes. Need full decompile to map timeline.")
write("#" * 70)

decompile_at(0x0086A850, "MainLoop_Full", 30000)

# Section 2: AI thread signal/wait functions
write("")
write("#" * 70)
write("# SECTION 2: AI thread signal and wait points")
write("#" * 70)

# AI dispatch (signals AI threads to start)
decompile_at(0x008C7E30, "AI_Dispatch_FUN_008c7e30")

# AI wait/join (blocks until AI threads finish)
decompile_at(0x008C7DE0, "AI_WaitComplete_FUN_008c7de0")

# The AI thread semaphore/event
decompile_at(0x008C71A0, "AI_ThreadEntry_008c71a0")

# Section 3: BSTaskManager signal points
write("")
write("#" * 70)
write("# SECTION 3: BSTaskManager — when does it get/complete work?")
write("#" * 70)

decompile_at(0x00C42DA0, "BSTaskManager_ThreadEntry")
decompile_at(0x00C42060, "BSTaskManager_SignalComplete")

# Section 4: Render begin/end markers
write("")
write("#" * 70)
write("# SECTION 4: Render markers")
write("#" * 70)

decompile_at(0x008705D0, "OurHook_PostRender (FUN_008705d0)")
decompile_at(0x00868850, "PerFrameQueueDrain (FUN_00868850)")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/audit_mainloop_timeline.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
