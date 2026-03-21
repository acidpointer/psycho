# @category Analysis
# @description Research BSTaskManagerThread lifecycle during startup/loading - PART 1
#
# Goal: Is BSTaskManagerThread active when DAT_011dea2b (loading flag) is set?
# The quarantine bypass assumes IO idle during loading - startup crash disproves this.

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

def disasm_range(start_int, count=20):
	listing = currentProgram.getListing()
	inst = listing.getInstructionAfter(toAddr(start_int - 1))
	for i in range(count):
		if inst is None:
			break
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()

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
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)


write("=" * 70)
write("BSTaskManagerThread LIFECYCLE - PART 1: LOADING FLAG")
write("=" * 70)

# SECTION 1: Who writes DAT_011dea2b?
write("")
write("# SECTION 1: DAT_011dea2b writers")
find_xrefs_to(0x011DEA2B, "DAT_011dea2b_loading_flag")

# SECTION 2: BSTaskManagerThread main loop
write("")
write("# SECTION 2: BSTaskManagerThread loop - does it check loading flag?")
decompile_at(0x00C42CA0, "BSTaskManagerThread_Loop")

# SECTION 3: Crash point context
write("")
write("# SECTION 3: Crash point 0x00ED2C9E and 0x00AA22A2")
disasm_range(0x00ED2C80, 15)
write("")
write("Return addr 0x00AA22A2:")
disasm_range(0x00AA2280, 15)

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/bstask_startup_lifecycle.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
