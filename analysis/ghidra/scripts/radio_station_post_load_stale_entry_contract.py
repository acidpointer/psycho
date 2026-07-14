# @category Analysis
# @description Resolve ownership and safe removal of the stale radio station entry observed after save load

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
	write("POST-LOAD STALE RADIO ENTRY CONTRACT")
	write("=" * 70)
	write("Crash evidence: FUN_00834260 receives a non-NULL station wrapper whose first pointer is stale, then FUN_00440DA0 faults reading form+8. Identify the wrapper allocation, list ownership, form reference policy, save-load reset path, destructor/free path, and earliest record-local or list-local removal that preserves valid radio stations.")
	audit(0x00833D00, "phase-10 radio list producer and iteration owner", 50000)
	audit(0x00834260, "per-station update containing the unchecked first-pointer read", 50000)
	audit(0x00440DA0, "unchecked TESForm flag reader at the crash EIP", 12000)
	audit(0x006815C0, "radio iteration node payload accessor", 20000)
	audit(0x00726070, "radio iteration next-node helper", 20000)
	audit(0x00470440, "list-node allocation helper", 22000)
	audit(0x00470470, "list destruction helper called after radio iteration", 22000)
	audit(0x004037D0, "radio temporary-list RemoveAll helper", 22000)
	audit(0x00832010, "registered/found radio list owner", 40000)
	audit(0x00832830, "registered radio list reader or mutator", 40000)
	audit(0x008329A0, "registered radio list reader or mutator 2", 40000)
	audit(0x00835BE0, "registered radio entry mutation path", 30000)
	audit(0x008366E0, "found radio station list mutation path", 40000)
	audit(0x008368B0, "radio global-data save/load or reset owner", 40000)
	audit(0x00836AF0, "registered/found station reconciliation owner", 50000)
	audit(0x00836E20, "registered radio list cleanup owner", 40000)
	audit(0x00836EF0, "radio list final cleanup owner", 40000)
	find_refs_to(0x011DD554, "global registered radio entry list")
	find_refs_to(0x011DD59C, "global found radio station list")
	find_refs_to(0x011DD42C, "current radio entry")
	disasm_range(0x00833D80, 0x008341C5, "station list construction, iteration, and call to FUN_00834260")
	disasm_range(0x00834260, 0x00834340, "station wrapper validation and crash read")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/radio_station_post_load_stale_entry_contract.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
