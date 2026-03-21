# @category Analysis
# @description Find hook points for IOTask dead set - fix double-release crash
#
# The crash: FUN_0044dd60 calls DecRef on a freed IOTask.
# Fix: dead set tracks destroyed IOTasks. FUN_0044dd60 hook checks dead set.
#
# Need to find:
# 1. IOTask destructor chain - where to insert into dead set
# 2. FUN_0044dd60 - exact size, can we inline hook it?
# 3. FUN_00c3c590 - NiRefObject base (where refcount lives)
# 4. All IOTask vtable[0] entries (destructors to hook)
# 5. Where tasks are freed after destructor (GameHeap::Free call site)
# 6. Can we hook FUN_0044dd60 directly as the single intercept point?

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
write("IOTask DEAD SET HOOK POINTS")
write("=" * 70)

# SECTION 1: FUN_0044dd60 - the release function (HOOK TARGET)
# This is where we intercept. If task is in dead set, skip DecRef.
write("")
write("# SECTION 1: FUN_0044dd60 - full disasm (need size for inline hook)")
disasm_range(0x0044DD60, 30)
decompile_at(0x0044DD60, "TaskRelease")

# SECTION 2: FUN_00c3c590 - NiRefObject base constructor
# Where is refcount initialized?
write("")
write("# SECTION 2: FUN_00c3c590 - NiRefObject base ctor")
decompile_at(0x00C3C590, "NiRefObject_BaseCtor")

# SECTION 3: IOTask base vtable (PTR_FUN_010c1554)
# What destructor does it have?
write("")
write("# SECTION 3: IOTask base vtable at 0x010c1554")
decompile_at(0x0044CBF0, "IOTask_BaseDtor_area")

# SECTION 4: QueuedTexture destructor chain
# vtable[0] = 0x0043be30 -> FUN_0043bf80 -> ~cancellation_token_source + FUN_00c3cea0
write("")
write("# SECTION 4: FUN_00c3cea0 - IOTask base destructor")
decompile_at(0x00C3CEA0, "IOTask_BaseDtor")
find_calls_from(0x00C3CEA0, "IOTask_BaseDtor")

# SECTION 5: Where is the task freed after destruction?
# QueuedTexture vtable[0] = FUN_0043be30 which does:
#   FUN_0043bf80(this)  // destructor
#   if (param_1 & 1) FUN_00401030(this)  // conditional free
write("")
write("# SECTION 5: FUN_00401030 - GameHeap free after destructor")
decompile_at(0x00401030, "GameHeap_Free_wrapper")

# SECTION 6: Can we hook FUN_0044dd60 as single point?
# It's 81 bytes. Is it big enough for inline hook?
# Check first 5 bytes for hook feasibility
write("")
write("# SECTION 6: FUN_0044dd60 first bytes (hook feasibility)")
disasm_range(0x0044DD60, 8)

# SECTION 7: Alternative - hook FUN_004019a0 (DecRef itself)
# Only 15 bytes. Too small for inline hook.
write("")
write("# SECTION 7: FUN_004019a0 - DecRef (15 bytes)")
disasm_range(0x004019A0, 8)

# SECTION 8: FUN_00443190 / FUN_004431b0 - task state checks in cancellation
# FUN_00448620 calls these to check if task is alive
write("")
write("# SECTION 8: FUN_00443190 - task alive check")
decompile_at(0x00443190, "TaskAliveCheck1")

write("")
write("# SECTION 8b: FUN_004431b0 - task alive check 2")
decompile_at(0x004431B0, "TaskAliveCheck2")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/iotask_deadset_hookpoints.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
