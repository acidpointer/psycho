# @category Analysis
# @description Trace QueuedTexture refcount lifecycle: who AddRef/DecRef?
#
# The crash is DecRef on recycled memory. Need to know:
# 1. When is the QueuedTexture created? What is initial refcount?
# 2. Who AddRef's it? (queue insertion, BSTaskManagerThread dequeue)
# 3. Who DecRef's it? (BSTaskManagerThread release, main thread release)
# 4. Can refcount reach 0 while task is still in completed queue?
# 5. What does FUN_004019a0 do? (called by FUN_0044dd60 for DecRef)
# 6. What does FUN_00c3ce60 do? (QueuedTexture base class init)

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
write("QueuedTexture REFCOUNT LIFECYCLE TRACE")
write("=" * 70)

# SECTION 1: FUN_004019a0 - the DecRef function
write("")
write("# SECTION 1: FUN_004019a0 - DecRef (called by FUN_0044dd60)")
decompile_at(0x004019A0, "DecRef")

# SECTION 2: FUN_00c3ce60 - QueuedTexture base class init
# Sets initial refcount and fields
write("")
write("# SECTION 2: FUN_00c3ce60 - IOTask base class constructor")
decompile_at(0x00C3CE60, "IOTask_BaseCtor")
find_calls_from(0x00C3CE60, "IOTask_BaseCtor")

# SECTION 3: FUN_00449150 - task submission (called from QueuedTexture init)
# This is where the task enters the IO system
write("")
write("# SECTION 3: FUN_00449150 - task submission to IO system")
decompile_at(0x00449150, "TaskSubmit")
find_calls_from(0x00449150, "TaskSubmit")

# SECTION 4: Who calls FUN_004019a0 (DecRef)?
write("")
write("# SECTION 4: All callers of FUN_004019a0 (DecRef)")
find_xrefs_to(0x004019A0, "DecRef_callers")

# SECTION 5: FUN_00c3cff0 - called from QueuedTexture vtable[1] processing
# Gets a BSFile handle. Does it AddRef the task?
write("")
write("# SECTION 5: FUN_00c3cff0 - get file handle during processing")
decompile_at(0x00C3CFF0, "GetFileHandle")

# SECTION 6: The AddRef counterpart
write("")
write("# SECTION 6: FUN_00401980 - AddRef?")
decompile_at(0x00401980, "AddRef")
find_xrefs_to(0x00401980, "AddRef_callers")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/queuedtexture_refcount_trace.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
