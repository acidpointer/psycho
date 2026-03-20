# @category Analysis
# @description Verify IOManager singleton pointer by tracing exact assembly

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
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

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

def disasm_range(start_int, count=30):
	listing = currentProgram.getListing()
	inst = listing.getInstructionAfter(toAddr(start_int - 1))
	for i in range(count):
		if inst is None:
			break
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()


write("=" * 70)
write("VERIFY IOManager SINGLETON POINTER")
write("Is DAT_01202D98 the IOManager or the Havok world?")
write("=" * 70)

# SECTION 1: Disassemble main loop around FUN_00c3dbf0 call
# The call should be around 0x0086e897 based on the xrefs
write("")
write("#" * 70)
write("# SECTION 1: Main loop disasm around FUN_00c3dbf0 call")
write("# Looking for what gets loaded into ECX before the CALL")
write("#" * 70)

# Find the exact CALL to FUN_00c3dbf0 in the main loop
listing = currentProgram.getListing()
func = fm.getFunctionContaining(toAddr(0x0086e650))
if func is not None:
	body = func.getBody()
	addr_iter = body.getAddresses(True)
	while addr_iter.hasNext():
		a = addr_iter.next()
		inst = listing.getInstructionAt(a)
		if inst is not None and inst.getFlowType().isCall():
			refs = inst.getReferencesFrom()
			for r in refs:
				if r.getToAddress().getOffset() == 0x00c3dbf0:
					call_addr = a.getOffset()
					write("")
					write("Found CALL to FUN_00c3dbf0 at 0x%08x" % call_addr)
					write("Disasm before and after:")
					disasm_range(call_addr - 30, 20)

# SECTION 2: Disassemble around hkWorld_Lock call in PreDestructionSetup
# to see what global it reads for the Havok world pointer
write("")
write("#" * 70)
write("# SECTION 2: PreDestructionSetup — what global is the Havok world?")
write("#" * 70)

decompile_at(0x00878160, "PreDestructionSetup")

write("")
write("PreDestructionSetup disasm:")
disasm_range(0x00878160, 40)

# SECTION 3: Disassemble hkWorld_Lock to see what offsets it accesses
write("")
write("#" * 70)
write("# SECTION 3: hkWorld_Lock — what offsets does it use?")
write("#" * 70)

decompile_at(0x00C3E310, "hkWorld_Lock")

write("")
write("hkWorld_Lock disasm:")
disasm_range(0x00C3E310, 20)

# SECTION 4: IO_DequeueTask — disasm around lock acquire to verify offset
write("")
write("#" * 70)
write("# SECTION 4: IO_DequeueTask disasm — verify lock offset")
write("#" * 70)

write("")
write("IO_DequeueTask first 20 instructions:")
disasm_range(0x00C40E70, 20)

# SECTION 5: Who calls IOManager_Create (FUN_00c3da50)?
# Where is the result stored?
write("")
write("#" * 70)
write("# SECTION 5: IOManager_Create callers — where is singleton stored?")
write("#" * 70)

find_xrefs_to(0x00C3DA50, "IOManager_Create")

# Also check FUN_00c3e4f0 (BSTaskManager_ctor) callers
find_xrefs_to(0x00C3E4F0, "BSTaskManager_ctor")

# SECTION 6: FUN_00c3ec80 base constructor — what does it init at +0x20?
write("")
write("#" * 70)
write("# SECTION 6: BSTaskManager base ctor (FUN_00c3ec80)")
write("# What does it initialize at offset +0x20?")
write("#" * 70)

decompile_at(0x00C3EC80, "BSTaskManagerBase_ctor")

# SECTION 7: Check all globals in 0x01202D90-0x01202DA0 range
write("")
write("#" * 70)
write("# SECTION 7: Globals near 0x01202D98")
write("#" * 70)

mem = currentProgram.getMemory()
for offset in range(0x01202D80, 0x01202DA8, 4):
	buf = bytearray(4)
	try:
		mem.getBytes(toAddr(offset), buf)
		val = (buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | buf[0]
		# Check xrefs
		refs = getReferencesTo(toAddr(offset))
		ref_count = 0
		for r in refs:
			ref_count += 1
		write("  0x%08x = 0x%08x (%d xrefs)" % (offset, val, ref_count))
	except:
		write("  0x%08x = [unreadable]" % offset)

# SECTION 8: DAT_01202d98 xrefs — who reads/writes it?
write("")
write("#" * 70)
write("# SECTION 8: All xrefs to DAT_01202D98")
write("#" * 70)

find_xrefs_to(0x01202D98, "DAT_01202d98")

# SECTION 9: FUN_00c3e420 — called from FUN_00c3dbf0 with param_1+0x64
# What object type does it expect?
write("")
write("#" * 70)
write("# SECTION 9: FUN_00c3e420 — IOManager task dequeue")
write("#" * 70)

decompile_at(0x00C3E420, "IOManager_TaskDequeue")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/verify_io_manager_ptr.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
