# @category Analysis
# @description Prove initial game-window placement ownership, SetWindowPos arguments, and ordering before the first focus transition

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
		if count > 40:
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

write("DISPLAY STARTUP POSITION FOLLOW-UP")
write("Goal: identify the exact call that establishes the initial corner position and whether the audited lifecycle call can run before Psycho installs.")

decompile_at(0x0086A850, "WinMain and initial window/renderer sequencing", 30000)
disasm_range(0x0086AEC0, 0x0086AF70, "WinMain initial CreateWindowExA region")
find_and_print_calls_from(0x0086A850, "WinMain and initial window/renderer sequencing")

decompile_at(0x004DA670, "renderer window creation and parent placement owner", 30000)
disasm_range(0x004DA880, 0x004DA980, "renderer creation SetWindowPos construction")
find_refs_to(0x004DA670, "renderer window creation owner")

decompile_at(0x004D75B0, "window procedure and show/position owner", 16000)
disasm_range(0x004D77F0, 0x004D78A0, "window procedure SetWindowPos and ShowWindow path")
find_refs_to(0x004D75B0, "window procedure")

decompile_at(0x004DC360, "D3D lifecycle reset and window placement owner", 20000)
disasm_range(0x004DC430, 0x004DC500, "D3D lifecycle SetWindowPos construction")
find_refs_to(0x004DC360, "D3D lifecycle reset owner")

decompile_at(0x00872570, "registered renderer lifecycle callback", 16000)
disasm_range(0x00872680, 0x00872740, "registered renderer callback SetWindowPos construction")
find_refs_to(0x00872570, "registered renderer lifecycle callback")

decompile_at(0x004503F0, "startup window coordinate helper")
find_refs_to(0x004503F0, "startup window coordinate helper")
decompile_at(0x004DC1F0, "configured render width accessor")
decompile_at(0x004DC200, "configured render height accessor")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/display_startup_position_followup.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
