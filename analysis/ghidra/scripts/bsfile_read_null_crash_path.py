# @category Analysis
# @description Trace the exact crash path from BSTaskManagerThread to memcpy(NULL)
#
# Crash: 0x00ED2C9E MOVDQA [EDI],XMM0 with EDI=0
# Stack: 0x00AA22A2 -> 0x00EC61C0 (memcpy) -> 0x00ED2C9E
# NiDDSReader on stack, CompressedArchiveFile "test15.dds"
#
# Need to trace: QueuedTexture task -> DDS read -> NiPixelData buffer -> memcpy

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

def find_xrefs_to(addr_int, label, limit=10):
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


write("=" * 70)
write("BSFile::Read NULL CRASH PATH TRACE")
write("=" * 70)

# SECTION 1: Function containing 0x00AA22A2
write("")
write("# SECTION 1: Function at 0x00AA22A2 - the BSFile::Read caller")
decompile_at(0x00AA22A2, "BSFile_Read_Caller")
find_calls_from(0x00AA22A2, "BSFile_Read_Caller")

# SECTION 2: Disasm around the crash call
write("")
write("# SECTION 2: Disasm around 0x00AA2290 (the memcpy call)")
disasm_range(0x00AA2270, 25)

# SECTION 3: Who calls this function? (to trace from QueuedTexture)
write("")
write("# SECTION 3: Who calls the function containing 0x00AA22A2?")
find_xrefs_to(0x00AA22A2, "ReturnAddr_callers")
# The function entry is what we need
func = fm.getFunctionContaining(toAddr(0x00AA22A2))
if func is not None:
	entry = func.getEntryPoint().getOffset()
	write("  Function entry: 0x%08x (%s)" % (entry, func.getName()))
	find_xrefs_to(entry, "FuncEntry_callers")

# SECTION 4: FUN_00ec61c0 - the memcpy that crashes
write("")
write("# SECTION 4: FUN_00ec61c0 - memcpy function")
disasm_range(0x00EC61C0, 20)

# SECTION 5: What passes the NULL pointer?
# EDI=0 at crash. What sets EDI before the memcpy?
write("")
write("# SECTION 5: What sets EDI (destination) before memcpy?")
write("# Trace back from 0x00AA229D to find where dest ptr comes from")
disasm_range(0x00AA2260, 30)

# SECTION 6: NiDDSReader - how does it get the NiPixelData buffer?
write("")
write("# SECTION 6: NiDDSReader vtable 0x0109F48C")
write("# What virtual functions does it have?")
dtor_addr = getInt(toAddr(0x0109F48C + 4)) & 0xFFFFFFFF
write("  NiDDSReader vtable[1] = 0x%08x" % dtor_addr)
# Look for the Read function (vtable offset that takes buffer pointer)
read_fn = getInt(toAddr(0x0109F48C + 8)) & 0xFFFFFFFF
write("  NiDDSReader vtable[2] = 0x%08x" % read_fn)
decompile_at(read_fn, "NiDDSReader_vtable2")

# SECTION 7: How does QueuedTexture get the NiPixelData buffer pointer?
# FUN_0043c4b0 / FUN_0043c4f0 are texture lookup functions
write("")
write("# SECTION 7: FUN_0043c4b0 - texture cache lookup wrapper")
decompile_at(0x0043C4B0, "TextureCacheLookup")

# SECTION 8: FUN_0043c1b0 area - QueuedTexture process internals
write("")
write("# SECTION 8: FUN_0043c150 - QueuedTexture vtable[1] (process?)")
decompile_at(0x0043C150, "QueuedTexture_vtable1")
find_calls_from(0x0043C150, "QueuedTexture_vtable1")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/bsfile_read_null_crash_path.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
