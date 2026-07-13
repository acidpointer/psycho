# @category Analysis
# @description Resolve the ExtraPrimitive lazy-build missing-property crash on BackgroundCloneThread and its safe recovery boundary

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
		if count > 160:
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
	inst_iter = listing.getInstructions(body, True)
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
	write("Disassembly: %s (0x%08x - 0x%08x)" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	while inst is not None and inst.getAddress().getOffset() <= end_int:
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()

def audit_function(addr_int, label, max_len=24000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def audit_targets():
	targets = [
		(0x004A72D0, "ExtraPrimitive lazy geometry builder and fault owner", 36000),
		(0x00441130, "NiProperty flag mutation fault function", 18000),
		(0x00A59D30, "NiAVObject property lookup by type", 18000),
		(0x00439410, "primitive geometry property attachment candidate", 20000),
		(0x004391C0, "primitive alpha property constructor candidate", 18000),
		(0x0049ED90, "primitive alpha configuration", 18000),
		(0x004A51B0, "ExtraPrimitive cached geometry accessor", 18000),
		(0x004A78E0, "ExtraPrimitive cached geometry consumer", 22000),
		(0x004A7800, "primitive vertex constructor", 16000),
		(0x0056B2D0, "reference model and primitive setup owner", 42000),
		(0x00440A90, "queued model execution virtual-call owner", 24000),
		(0x00442350, "BackgroundCloneThread work loop", 26000),
		(0x00C410B0, "BSTask background worker loop", 26000),
		(0x00C42DA0, "BackgroundCloneThread entry", 14000),
	]
	for item in targets:
		audit_function(item[0], item[1], item[2])

def audit_fault_chain():
	disasm_range(0x004A72D0, 0x004A7340, "lazy cache test and construction entry")
	disasm_range(0x004A75A0, 0x004A7710, "geometry creation, alpha attachment, failed lookup, and continuation")
	disasm_range(0x00441130, 0x004411D0, "property flag setter null dereference")
	disasm_range(0x0056B430, 0x0056B4F5, "reference setup dispatch into ExtraPrimitive builder")
	disasm_range(0x00440B10, 0x00440B75, "queued model virtual execution")
	disasm_range(0x004423D0, 0x00442455, "background queue task execution")
	find_refs_to(0x010151B4, "ExtraPrimitive vtable")
	find_refs_to(0x010162DC, "NiAlphaProperty vtable")

def main():
	write("=" * 70)
	write("BACKGROUND CLONE MISSING PROPERTY CRASH AUDIT")
	write("=" * 70)
	write("Questions: why ExtraPrimitive can lose its just-created type-3 property, whether construction is shared across threads, and which failure boundary can preserve queue and object lifetime safely.")
	audit_targets()
	audit_fault_chain()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_20260713_background_clone_missing_property_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
