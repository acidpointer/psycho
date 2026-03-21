# @category Analysis
# @description Research DAT_011f6238 allocator and function containing 0x00AA22A2
#
# The crash at 0x00ED2C9E is memset(NULL, 0, size) where the allocation
# at FUN_00aa4030(DAT_011f6238) returned NULL. Need to understand:
# 1. What is DAT_011f6238? Is it GameHeap (our mimalloc) or separate?
# 2. What function contains 0x00AA22A2? (Ghidra didn't find boundary)
# 3. What is EDI pointing to? Is it NiPixelData or file data?
# 4. Who calls this function from BSTaskManagerThread?

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
write("DAT_011f6238 ALLOCATOR + CRASH FUNCTION RESEARCH")
write("=" * 70)

# SECTION 1: FUN_00aa4030 - the allocation function that returned NULL
write("")
write("# SECTION 1: FUN_00aa4030 - allocator that returned NULL")
decompile_at(0x00AA4030, "Allocator_aa4030")

# SECTION 2: FUN_00aa3e40 - related allocator (used in BSTaskManagerThread)
write("")
write("# SECTION 2: FUN_00aa3e40 - related allocator")
decompile_at(0x00AA3E40, "Allocator_aa3e40")

# SECTION 3: DAT_011f6238 xrefs - what is this singleton?
write("")
write("# SECTION 3: DAT_011f6238 - allocator singleton xrefs")
find_xrefs_to(0x011F6238, "DAT_011f6238_allocator")

# SECTION 4: Find the function boundary around 0x00AA22A2
# Ghidra didn't find it. Search backwards for a PUSH EBP / function prologue
write("")
write("# SECTION 4: Search for function containing 0x00AA22A2")
write("# Disasm backwards from 0x00AA2200")
disasm_range(0x00AA2170, 25)

write("")
write("# More context:")
disasm_range(0x00AA21C0, 25)

# SECTION 5: Who calls FUN_00aa4030 from BSTaskManagerThread path?
write("")
write("# SECTION 5: Callers of FUN_00aa4030")
find_xrefs_to(0x00AA4030, "Allocator_callers")

# SECTION 6: FUN_00aa4060 - the free function (counterpart)
write("")
write("# SECTION 6: FUN_00aa4060 - free function")
decompile_at(0x00AA4060, "Free_aa4060")

# SECTION 7: Is DAT_011f6238 the same as GameHeap?
# Check if FUN_00401000 (GameHeap::Alloc) references 011f6238
write("")
write("# SECTION 7: Does GameHeap reference DAT_011f6238?")
find_calls_from(0x00401000, "GameHeap_Alloc")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/crash_aa22a2_allocator.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
