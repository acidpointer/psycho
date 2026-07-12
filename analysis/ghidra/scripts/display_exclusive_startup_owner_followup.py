# @category Analysis
# @description Prove exclusive-fullscreen bootstrap window ownership and the safe pre-visible placement boundary

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
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
	faddr = func.getEntryPoint().getOffset()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, func.getBody().getNumAddresses()))
	if faddr != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def find_refs_to(addr_int, label):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
		if count > 80:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found at 0x%08x]" % addr_int)
		return
	body = func.getBody()
	inst_iter = currentProgram.getListing().getInstructions(body, True)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
	write("  Total: %d calls" % count)

def disasm_range(start_int, end_int, label):
	write("")
	write("-" * 70)
	write("%s 0x%08x-0x%08x" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	while inst is not None and inst.getAddress().getOffset() <= end_int:
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()

write("DISPLAY EXCLUSIVE STARTUP OWNER FOLLOW-UP")
write("Goal: prove why exclusive fullscreen retains the bootstrap position and identify a safe placement boundary before the window becomes visible or presents frames.")

decompile_at(0x0086A850, "WinMain bootstrap window and renderer sequencing", 50000)
disasm_range(0x0086AEE0, 0x0086B0C0, "bootstrap CreateWindowExA through renderer initialization")
find_and_print_calls_from(0x0086A850, "WinMain")

decompile_at(0x0086D500, "renderer initialization wrapper", 16000)
disasm_range(0x0086D500, 0x0086D580, "renderer wrapper call and return")
find_refs_to(0x0086D500, "renderer initialization wrapper")

decompile_at(0x004DA670, "renderer creation full function", 80000)
disasm_range(0x004DA810, 0x004DAA80, "device success and fullscreen/windowed HWND branch")
disasm_range(0x004DBE80, 0x004DC000, "renderer creation tail and return")
find_and_print_calls_from(0x004DA670, "renderer creation owner")

decompile_at(0x004DC710, "renderer/device initialization before HWND branch", 30000)
find_and_print_calls_from(0x004DC710, "renderer/device initialization before HWND branch")

decompile_at(0x00446E10, "bFull Screen predicate")
decompile_at(0x00454AF0, "boolean setting accessor")
find_refs_to(0x011C77B4, "bFull Screen setting object")
find_refs_to(0x011C6FC0, "top-level game HWND")
find_refs_to(0x011C6FBC, "renderer child/target HWND")

find_refs_to(0x00FDF2B8, "CreateWindowExA IAT slot")
find_refs_to(0x00FDF2A4, "SetWindowPos IAT slot")
find_refs_to(0x00FDF288, "ShowWindow IAT slot")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/display_exclusive_startup_owner_followup.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
