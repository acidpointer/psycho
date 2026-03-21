# @category Analysis
# @description Research BSTaskManagerThread lifecycle during startup/loading - PART 2
#
# Goal: When is BSTaskManagerThread created? Who submits QueuedTexture tasks
# during loading? Is there an IO pause mechanism?

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
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


write("=" * 70)
write("BSTaskManagerThread LIFECYCLE - PART 2: CREATION + IO SUBMISSION")
write("=" * 70)

# SECTION 1: IOManager singleton writers
write("")
write("# SECTION 1: Who writes IOManager singleton 0x01202D98?")
find_xrefs_to(0x01202D98, "IOManager_singleton_ptr")

# SECTION 2: IO processing - task submission path
write("")
write("# SECTION 2: FUN_00c3dbf0 - IO processing (main loop)")
decompile_at(0x00C3DBF0, "IO_Processing")
find_calls_from(0x00C3DBF0, "IO_Processing")

# SECTION 3: BSTaskManager init area
write("")
write("# SECTION 3: BSTaskManager init / thread creation area")
decompile_at(0x00C42060, "BSTaskManager_init_area")

# SECTION 4: QueuedTexture submission during cell load
write("")
write("# SECTION 4: FUN_00877700 - wait for pending cell loads")
decompile_at(0x00877700, "WaitForPendingCellLoad")
find_xrefs_to(0x00877700, "WaitForPendingCellLoad_callers")

# SECTION 5: NiSourceTexture creation - vtable assignment
write("")
write("# SECTION 5: Who creates NiSourceTexture?")
find_xrefs_to(0x0109B9EC, "NiSourceTexture_vtable_assign")

# SECTION 6: Task dispatch in BSTaskManagerThread
write("")
write("# SECTION 6: FUN_00c41240 - task dispatch within BSTaskManagerThread")
decompile_at(0x00C41240, "BSTask_Dispatch")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/bstask_startup_lifecycle_p2.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
