# @category Analysis
# @description Analyze BSTaskManagerThread crash at 0x00A61A74 during QueuedTexture processing

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

def find_xrefs_to(addr_int, label, limit=20):
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
			break
	write("  Total: %d refs" % count)


write("=" * 70)
write("BSTaskManagerThread CRASH at 0x00A61A74")
write("Thread: BSTaskManagerThread")
write("QueuedTexture bodymods texture, EAX=0x200, EDI=0")
write("Callchain: A61A74 -> 43C4E0 -> 43C1BB -> C3FC94 -> C41257 -> C42DBF")
write("=" * 70)

# SECTION 1: Crash point
write("")
write("#" * 70)
write("# SECTION 1: Crash point 0x00A61A74")
write("#" * 70)

decompile_at(0x00A61A74, "CRASH_POINT")
write("")
write("Disasm around crash:")
disasm_range(0x00A61A50, 20)

# SECTION 2: Full call chain on BSTaskManagerThread
write("")
write("#" * 70)
write("# SECTION 2: BSTaskManagerThread call chain")
write("#" * 70)

decompile_at(0x0043C4E0, "CALLER_1_0043C4E0")
find_calls_from(0x0043C4E0, "CALLER_1")

decompile_at(0x0043C1BB, "CALLER_2_0043C1BB")

decompile_at(0x00C3FC94, "IO_TaskDispatch_0x00C3FC94")

# 0x00C41257 is inside BSTaskManagerThread_Loop
write("")
write("Disasm around 0x00C41257 (inside BSTaskManagerThread_Loop):")
disasm_range(0x00C41240, 15)

# SECTION 3: What is at 0x0043C51C (stack[01] = return address)?
write("")
write("#" * 70)
write("# SECTION 3: 0x0043C51C — return address from crash function")
write("#" * 70)

decompile_at(0x0043C51C, "RETURN_ADDR_0043C51C")
write("")
write("Disasm around 0x0043C51C:")
disasm_range(0x0043C500, 15)

# SECTION 4: QueuedTexture vtable — what functions does BSTaskManagerThread call?
write("")
write("#" * 70)
write("# SECTION 4: QueuedTexture class — vtable and processing")
write("#" * 70)

find_xrefs_to(0x01016788, "QueuedTexture_RTTI", 10)

# The QueuedTexture vtable — what's at vtable+4 (process)?
# Look for QueuedTexture constructor to find vtable address
# QueuedTexture RTTI is at 0x01016788
# The vtable pointer is typically before the RTTI reference

# SECTION 5: FUN_00448620 — does it cancel QueuedTexture tasks specifically?
# Or only certain task types?
write("")
write("#" * 70)
write("# SECTION 5: FUN_00448620 internals — what tasks does it cancel?")
write("#" * 70)

decompile_at(0x00448620, "CancelStaleTasks", 15000)

# SECTION 6: Is the crash DURING or AFTER CellTransitionHandler?
# The crash is on BSTaskManagerThread. If our IO lock is held,
# BSTaskManagerThread should be blocked on IO_DequeueTask.
# But the crash is in task PROCESSING, which means either:
# a) The task was dequeued BEFORE the lock was acquired
# b) The lock wasn't acquired at all
# c) The crash happens OUTSIDE CellTransitionHandler (between transitions)
write("")
write("#" * 70)
write("# SECTION 6: When does BSTaskManagerThread process QueuedTexture?")
write("# Is it during CellTransitionHandler or between transitions?")
write("#" * 70)

# QueuedTexture processing — vtable+0x4c and vtable+0x50
# The BSTaskManagerThread_Loop calls:
#   (**(code**)(**(int**)(param_1+0x30) + 0x4c))(task)  // process
#   (**(code**)(**(int**)(param_1+0x30) + 0x50))(task)  // complete

# 0x00C3FC94 is IO_TaskDispatch — let's see what vtable call it makes
decompile_at(0x00C3FC80, "IO_TaskDispatch")

# SECTION 7: What exactly does the QueuedTexture task DO when processed?
# The task's vtable+4 (called by IO_TaskDispatch) does the actual work
write("")
write("#" * 70)
write("# SECTION 7: QueuedTexture task processing path")
write("#" * 70)

# FUN_0043C1BB is in the call chain — what function contains it?
decompile_at(0x0043C1B0, "QueuedTexture_Process_area")
find_calls_from(0x0043C1B0, "QueuedTexture_Process_area")

# FUN_0043C4E0 calls into FUN_0043C1BB area
decompile_at(0x0043C4B0, "QueuedTexture_Process_outer")
find_calls_from(0x0043C4B0, "QueuedTexture_Process_outer")

# SECTION 8: hkFreeListAllocator on stack — is Havok involved?
write("")
write("#" * 70)
write("# SECTION 8: hkFreeListAllocator presence on stack")
write("#" * 70)

find_xrefs_to(0x010D1464, "hkFreeListAllocator_RTTI", 5)

# SECTION 9: Is QueuedTexture submitted during CellTransitionHandler?
# Or is it queued before the transition and processed after?
write("")
write("#" * 70)
write("# SECTION 9: Who creates/submits QueuedTexture tasks?")
write("#" * 70)

# QueuedTexture constructor — search for RTTI assignment
find_xrefs_to(0x01016788, "QueuedTexture_vtable_assign", 15)

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/crash_00A61A74_bstask.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
