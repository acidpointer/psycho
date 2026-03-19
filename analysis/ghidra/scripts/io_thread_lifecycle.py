# @category Analysis
# @description Research the IO thread (BSTaskManagerThread) lifecycle.
# Goal: Find how to check if IO queue is empty, what synchronization
# exists, and whether we can safely hook the IO completion path.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def decompile_at(addr_int, label, max_len=8000):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	output.append("")
	output.append("=" * 70)
	output.append("%s @ 0x%08x" % (label, addr_int))
	output.append("=" * 70)
	if func is None:
		output.append("  [function not found]")
		return
	output.append("  Function: %s, Size: %d bytes" % (func.getName(), func.getBody().getNumAddresses()))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		output.append(code[:max_len])
	else:
		output.append("  [decompilation failed]")

def find_xrefs_to(addr_int, label):
	"""Find all references TO an address (callers)."""
	addr = toAddr(addr_int)
	refs = getReferencesTo(addr)
	output.append("")
	output.append("--- XRefs to %s (0x%08x) ---" % (label, addr_int))
	count = 0
	for ref in refs:
		from_addr = ref.getFromAddress()
		func = fm.getFunctionContaining(from_addr)
		fname = func.getName() if func else "???"
		output.append("  %s @ 0x%s (in %s)" % (ref.getReferenceType(), from_addr, fname))
		count += 1
	output.append("  Total: %d refs" % count)

output.append("###############################################################")
output.append("# IO THREAD LIFECYCLE ANALYSIS")
output.append("# Goal: Understand BSTaskManagerThread, IOManager, LockFreeQueue")
output.append("# Find: queue count/empty check, sync points, completion hooks")
output.append("###############################################################")

# === Section 1: IOManager singleton and structure ===
output.append("\n\n### SECTION 1: IOManager structure")
output.append("# IOManager RTTI at 0x010C1604")
output.append("# LockFreeQueue<IOTask> RTTI at 0x010C1760")
output.append("# LockFreePriorityQueue<IOTask> RTTI at 0x010C16DC")

# IOManager constructor / init — find its vtable and structure
decompile_at(0x00C42DA0, "BSTaskManagerThread_Main (IO thread entry)")
decompile_at(0x00C41200, "BSTaskManagerThread_Loop (task processing)")
decompile_at(0x00C3FC00, "IOManager_ProcessTask")
decompile_at(0x00C3DD00, "IOManager_Inner")

# === Section 2: QueuedTexture processing ===
output.append("\n\n### SECTION 2: QueuedTexture virtual calls")
output.append("# QueuedTexture vtable at 0x01016788")
output.append("# Crash at 0x0043BFC1 (return addr from virtual call)")

decompile_at(0x0043BF00, "QueuedTexture_Process (crash area)")
decompile_at(0x0043BD00, "QueuedTexture_Caller")
decompile_at(0x0043C400, "QueuedTexture_Outer")

# === Section 3: LockFreeQueue operations ===
output.append("\n\n### SECTION 3: LockFreeQueue<IOTask> operations")
output.append("# How are tasks enqueued/dequeued? Is there a count/empty check?")

# Find vtable entries for LockFreeQueue
# Look for push/pop/count methods
decompile_at(0x0043C1B0, "LockFreeQueue_Op1")
decompile_at(0x0043C4D0, "LockFreeQueue_Op2")

# === Section 4: Async queue flush (Stage 3) ===
output.append("\n\n### SECTION 4: Async queue flush")
output.append("# FUN_00c459d0 — what exactly does it flush?")
decompile_at(0x00C459D0, "AsyncQueueFlush (172 bytes)")

# === Section 5: QueuedTexture destructor / release ===
output.append("\n\n### SECTION 5: QueuedTexture release")
output.append("# When PDD queue 0x04 frees a texture, what happens?")
output.append("# Does it invalidate the IO queue entry?")

# QueuedTexture vtable entries (vtable at 0x01016788)
# Read vtable to find destructor
listing = currentProgram.getListing()
vtable_addr = toAddr(0x01016788)
output.append("\nQueuedTexture vtable entries:")
for i in range(8):
	addr = toAddr(0x01016788 + i * 4)
	data = listing.getDataAt(addr)
	if data:
		output.append("  [%d] +0x%02x: %s" % (i, i*4, data.getValue()))
	else:
		# Read raw bytes
		mem = currentProgram.getMemory()
		buf = bytearray(4)
		mem.getBytes(addr, buf)
		val = (buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | buf[0]
		output.append("  [%d] +0x%02x: 0x%08x" % (i, i*4, val))
		if val > 0x00400000 and val < 0x01000000:
			decompile_at(val, "QueuedTexture_vtable[%d]" % i, 3000)

# === Section 6: Cell transition → IO interaction ===
output.append("\n\n### SECTION 6: Does CellTransitionHandler wait for IO?")
decompile_at(0x008774A0, "CellTransitionHandler (561 bytes)", 10000)

# Does it signal/wait on the IO thread?
decompile_at(0x00877700, "CellTransition_PreCleanup (wait)")
decompile_at(0x00453A70, "Pre-cleanup generic")

# === Section 7: Find IOManager singleton address ===
output.append("\n\n### SECTION 7: IOManager singleton")
output.append("# Need to find the global pointer to IOManager to read queue state")

# The IOManager appears at various stack offsets in crash logs
# Look for the constructor or accessor
find_xrefs_to(0x010C1604, "IOManager_vtable")

# === Write output ===
import os
out_path = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/io_thread_lifecycle.txt"

d = os.path.dirname(out_path)
if not os.path.exists(d):
	os.makedirs(d)

with open(out_path, "w") as f:
	f.write("\n".join(output))

print("Wrote %d lines to %s" % (len(output), out_path))
