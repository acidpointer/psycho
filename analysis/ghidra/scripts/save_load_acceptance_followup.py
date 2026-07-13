# @category Analysis
# @description Resolve FalloutNV save header completeness, changed-record bounds, malformed-data propagation, and load abort behavior

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
		if count > 120:
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

def audit_function(addr_int, label, max_len=22000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def audit_targets():
	targets = [
		(0x0084D4B0, "save header and physical body writer", 34000),
		(0x0084D8C0, "save header validator A", 30000),
		(0x0084DAB0, "save header validator B", 30000),
		(0x00847660, "master-file and initial save acceptance", 30000),
		(0x00860E20, "save metadata header reader", 26000),
		(0x00861130, "save metadata header writer", 30000),
		(0x00845D20, "load stream initialization", 22000),
		(0x00846B60, "load chapter table constructor", 24000),
		(0x00846E70, "load chapter table reader", 24000),
		(0x008643B0, "changed-form record constructor", 22000),
		(0x008644B0, "changed-form record header reader", 26000),
		(0x008665B0, "changed-form saved type or version reader", 18000),
		(0x00849D00, "changed-form payload load and decompression owner", 32000),
		(0x00864580, "changed-form record release or skip", 22000),
		(0x00848CF0, "global load-error predicate", 18000),
		(0x00848DD0, "changed-form rejection predicate", 18000),
		(0x00848D50, "changed-form load finalization", 22000),
		(0x00864820, "changed-form buffer checked read", 24000),
		(0x00846080, "variable-sized value reader", 24000),
		(0x00845FC0, "variable-sized value writer", 22000),
		(0x00865F60, "variable-sized value writer alternate path", 22000),
		(0x00866140, "save buffer backpatch or shift", 22000),
		(0x00483D70, "changed-record deflate error handling", 26000),
	]
	for item in targets:
		audit_function(item[0], item[1], item[2])

def audit_callsites():
	disasm_range(0x0084D4B0, 0x0084D860, "save header fields, body sizes, and final markers")
	disasm_range(0x0084D8C0, 0x0084DC00, "header validation and truncated-file handling")
	disasm_range(0x00847EE0, 0x00848040, "LoadGame acceptance gate")
	disasm_range(0x008482D0, 0x00848980, "changed-form loop error and skip decisions")
	disasm_range(0x00864820, 0x008648A0, "changed-record buffer read bounds")
	disasm_range(0x00483E10, 0x00483FC0, "deflate allocation and return-code handling")

def main():
	write("=" * 70)
	write("SAVE LOAD ACCEPTANCE FOLLOW-UP")
	write("=" * 70)
	write("Questions: whether the format has a complete-body invariant, which malformed lengths are fatal, and whether load errors abort before state is committed.")
	audit_targets()
	audit_callsites()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/save_load_acceptance_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
