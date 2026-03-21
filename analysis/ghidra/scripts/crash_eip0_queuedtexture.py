# @category Analysis
# @description Analyze EIP=0 crash via QueuedTexture vtable on BSTaskManagerThread
#
# EIP=0, EDX=0x01016788 (QueuedTexture vtable), return addr 0x0043BFC1
# BSTaskManagerThread called virtual function on freed QueuedTexture
# IO lock only blocks dequeue, not in-flight task processing

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
write("EIP=0 CRASH - QueuedTexture vtable NULL dispatch")
write("BSTaskManagerThread processing path")
write("=" * 70)

# SECTION 1: Crash return address 0x0043BFC1
write("")
write("# SECTION 1: 0x0043BFC1 - crash return address")
write("# Disasm around the call that jumped to EIP=0")
disasm_range(0x0043BF90, 25)

# SECTION 2: Decompile function containing 0x0043BFC1
write("")
write("# SECTION 2: Function containing crash point")
decompile_at(0x0043BFC1, "CrashPoint")
find_calls_from(0x0043BFC1, "CrashPoint")

# SECTION 3: 0x0043BE3F on stack - caller in chain
write("")
write("# SECTION 3: 0x0043BE3F - caller in chain")
disasm_range(0x0043BE20, 20)
decompile_at(0x0043BE3F, "Caller_0043BE3F")

# SECTION 4: 0x0044DDA1 on stack - outer caller
write("")
write("# SECTION 4: 0x0044DDA1 - outer caller (task release?)")
disasm_range(0x0044DD80, 20)
decompile_at(0x0044DDA1, "Caller_0044DDA1")

# SECTION 5: QueuedTexture vtable at 0x01016788
write("")
write("# SECTION 5: QueuedTexture vtable (0x01016788)")
write("# EDX held this value at crash time")
for i in range(16):
	addr = toAddr(0x01016788 + i * 4)
	raw = getInt(addr) & 0xFFFFFFFF
	target_func = fm.getFunctionAt(toAddr(raw))
	fname = target_func.getName() if target_func else "unknown"
	write("  [%d] +0x%02x: 0x%08x -> %s" % (i, i * 4, raw, fname))

# SECTION 6: QueuedTexture process function (vtable+0x4c and +0x50)
write("")
write("# SECTION 6: QueuedTexture process/complete (vtable+0x4c, +0x50)")
process_addr = getInt(toAddr(0x01016788 + 0x4c)) & 0xFFFFFFFF
complete_addr = getInt(toAddr(0x01016788 + 0x50)) & 0xFFFFFFFF
write("  vtable+0x4c (process): 0x%08x" % process_addr)
write("  vtable+0x50 (complete): 0x%08x" % complete_addr)
decompile_at(process_addr, "QueuedTexture_Process")
decompile_at(complete_addr, "QueuedTexture_Complete")

# SECTION 7: What does QueuedTexture access on the NiSourceTexture?
write("")
write("# SECTION 7: QueuedTexture constructor - what refs does it hold?")
find_xrefs_to(0x01016788, "QueuedTexture_vtable_assign")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/crash_eip0_queuedtexture.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
