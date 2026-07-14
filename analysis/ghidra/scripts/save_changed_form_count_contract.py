# @category Analysis
# @description Resolve changed-form list count ownership and safe rejection boundaries for missing-content saves

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

def audit(addr_int, label, max_len=20000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def main():
	write("=" * 70)
	write("CHANGED-FORM COUNT AND REJECTION CONTRACT")
	write("=" * 70)
	write("Resolve the object written at EBP-0x298..EBP-0x290 in FUN_00847DF0. Its count at EBP-0x290 bounds both changed-record passes and is passed to FUN_0084B5C0 and FUN_0084BC20. Identify the file field that supplies it, allocation ownership, maximum valid count, and the earliest safe record-local rejection path for unresolved embedded FormIDs.")
	audit(0x00846300, "raw save-file read wrapper mistyped as ShowToolBar", 40000)
	audit(0x00462D80, "raw save-file read used for the 0x6E-byte load header", 30000)
	audit(0x00846400, "save-file cursor or position query", 24000)
	audit(0x00846440, "save-file cursor restore or section close", 24000)
	audit(0x00846490, "save-file section completion", 24000)
	audit(0x00845D20, "save-load record table setup", 30000)
	audit(0x00846E70, "save-load table reader called for owner fields", 30000)
	audit(0x0084B5C0, "changed-form list pre-pass using record count", 30000)
	audit(0x0084BC20, "changed-form list completion using record count", 30000)
	audit(0x0042FC00, "container reserve helper receiving header count", 30000)
	audit(0x0072BA80, "container shrink helper receiving header count", 24000)
	audit(0x008646B0, "per-record section reader in count-driven completion pass", 24000)
	audit(0x008646F0, "per-record section completion in count-driven pass", 24000)
	audit(0x00864740, "per-record fixed header reader", 30000)
	audit(0x0084BE40, "per-record completion or validation helper", 30000)
	audit(0x008456E0, "changed-form lookup or remap helper", 24000)
	audit(0x00841120, "saved identity construction helper", 24000)
	audit(0x0084A3A0, "record identity compatibility check", 24000)
	disasm_range(0x00848010, 0x00848310, "list construction, count publication, and first-pass entry")
	disasm_range(0x00848330, 0x00848485, "record header, embedded identity remap, and reconstruction call")
	disasm_range(0x00848750, 0x00848870, "second-pass count use and rejected-record removal")
	disasm_range(0x00848BC0, 0x00848C10, "count handoff to completion")
	disasm_range(0x00462D80, 0x00462E80, "raw save-file read implementation and short-read behavior")
	disasm_range(0x0084B5C0, 0x0084B630, "count-driven container resize arithmetic")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/save_changed_form_count_contract.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
