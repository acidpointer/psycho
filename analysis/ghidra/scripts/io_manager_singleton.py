# @category Analysis
# @description Find IOManager singleton pointer and dequeue lock for BSTaskManagerThread sync

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
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total: %d refs" % count)

def read_mem_u32(addr_int):
	mem = currentProgram.getMemory()
	buf = bytearray(4)
	try:
		mem.getBytes(toAddr(addr_int), buf)
		return (buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | buf[0]
	except:
		return None


write("=" * 70)
write("IOManager SINGLETON + DEQUEUE LOCK RESEARCH")
write("Goal: Find the global pointer chain to queue_mgr+0x20 (dequeue lock)")
write("=" * 70)

# SECTION 1: FUN_00c3dbf0 — IOManager task processing (called from main loop)
# Main loop calls this at 0x0086e897
write("")
write("#" * 70)
write("# SECTION 1: Main loop IOManager call — how does it get the singleton?")
write("#" * 70)

decompile_at(0x00C3DBF0, "MainLoop_IOProcess")
find_calls_from(0x00C3DBF0, "MainLoop_IOProcess")

# Look at the main loop around 0x0086e897 to see what param is passed
decompile_at(0x0086E897, "MainLoop_IOCall_context")

# SECTION 2: FUN_00c3e4f0 — BSTaskManager base constructor
# Creates IOManager internals including BSTaskManagerThread
write("")
write("#" * 70)
write("# SECTION 2: BSTaskManager base constructor — creates threads")
write("#" * 70)

decompile_at(0x00C3E4F0, "BSTaskManager_ctor", 12000)
find_calls_from(0x00C3E4F0, "BSTaskManager_ctor")

# SECTION 3: DAT_011c3b3c — referenced by DeferredCleanupSmall
# Could be IOManager/BSTaskManager singleton
write("")
write("#" * 70)
write("# SECTION 3: DAT_011c3b3c — potential BSTaskManager singleton")
write("#" * 70)

find_xrefs_to(0x011C3B3C, "DAT_011c3b3c")

# SECTION 4: FUN_00450b80 — called from DeferredCleanupSmall to get manager
write("")
write("#" * 70)
write("# SECTION 4: FUN_00450b80 — manager getter in DeferredCleanupSmall")
write("#" * 70)

decompile_at(0x00450B80, "GetManager_DCS")

# SECTION 5: FUN_00448620 — called with DAT_011c3b3c in DeferredCleanupSmall
write("")
write("#" * 70)
write("# SECTION 5: FUN_00448620 — what does it do with DAT_011c3b3c?")
write("#" * 70)

decompile_at(0x00448620, "UsesDAT011c3b3c")
find_calls_from(0x00448620, "UsesDAT011c3b3c")

# SECTION 6: Find BSTaskManagerThread singleton by tracing from creation
# FUN_00c3e4f0 creates BSTaskManagerThread via FUN_00c3ee70
# Where does it store the result?
write("")
write("#" * 70)
write("# SECTION 6: BSTaskManagerThread creation and storage")
write("#" * 70)

decompile_at(0x00C3EE70, "BSTaskManagerThread_ctor")
find_calls_from(0x00C3EE70, "BSTaskManagerThread_ctor")

# FUN_00c42dd0 — called from BSTaskManagerThread_ctor
decompile_at(0x00C42DD0, "BSTaskThread_init")

# SECTION 7: FUN_0040fbf0 — the spin-lock acquire used by IO_DequeueTask
# What is the expected value format? Can we safely acquire it?
write("")
write("#" * 70)
write("# SECTION 7: Spin-lock mechanism (FUN_0040fbf0)")
write("# This is the lock at queue_mgr+0x20 we need to hold")
write("#" * 70)

decompile_at(0x0040FBF0, "SpinLock_Acquire")
decompile_at(0x0040FCA0, "SpinLock_Sleep")
decompile_at(0x0040FC90, "SpinLock_GetThreadId")
decompile_at(0x0043B460, "SpinLock_CAS")
decompile_at(0x0040FBE0, "SpinLock_PostAcquire")

# FUN_0078d200 — try-lock variant (for reference)
# Already decompiled — uses same primitives

# SECTION 8: FUN_0040fbe0 — post-lock callback
# Called after successful acquire. What does it do?
write("")
write("#" * 70)
write("# SECTION 8: Lock release mechanism")
write("#" * 70)

# What is the release function? Look at IO_DequeueTask end:
# this+0x24 decrement, when 0 → this+0x20 = 0 (release)
# So the release is just writing 0 to the lock address
write("# Lock release in IO_DequeueTask:")
write("# *(this+0x24) -= 1;")
write("# if (*(this+0x24) == 0) { *(this+0x20) = 0; } // release")
write("# So it's a reentrant spin-lock: threadID-based CAS + counter at +0x24")

# SECTION 9: Trace queue_mgr from main loop
# The main loop at 0x0086e897 calls FUN_00c3dbf0
# FUN_00c3dbf0 likely uses a global IOManager pointer
# Let's see what FUN_00c3dbf0 receives
write("")
write("#" * 70)
write("# SECTION 9: IOManager global pointer candidates")
write("#" * 70)

# Look for globals near IOManager vtable that might be singleton pointers
for addr in [0x011C3B3C, 0x011C3B40, 0x011C3B44, 0x011F4AA0]:
	val = read_mem_u32(addr)
	if val is not None:
		write("  0x%08x = 0x%08x" % (addr, val))
	else:
		write("  0x%08x = [unreadable]" % addr)

# SECTION 10: How does the main loop get the IOManager?
# Disasm around the call at 0x0086e897
write("")
write("#" * 70)
write("# SECTION 10: Main loop disasm around IOManager call")
write("#" * 70)

listing = currentProgram.getListing()
addr = toAddr(0x0086e880)
for i in range(20):
	inst = listing.getInstructionAt(addr)
	if inst is not None:
		write("  0x%08x: %s" % (addr.getOffset(), inst.toString()))
		addr = inst.getNext().getAddress()
	else:
		write("  0x%08x: [no inst]" % addr.getOffset())
		break

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/io_manager_singleton.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
