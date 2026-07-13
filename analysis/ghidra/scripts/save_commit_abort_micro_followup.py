# @category Analysis
# @description Resolve the exact save close/flush contract and malformed-load abort checkpoints

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

def audit_close_contract():
	targets = [
		(0x00AFF240, "BSFile destructor and close owner"),
		(0x00AFF490, "BSFile open-state and status initializer"),
		(0x00AFF9D0, "BSFile unbuffered read callback"),
		(0x00AFF9F0, "BSFile unbuffered write callback"),
		(0x00AFFA10, "BSFile buffered read callback"),
		(0x00AFFA60, "BSFile buffered write callback"),
		(0x00AA8660, "CRT physical transfer helper"),
		(0x008462C0, "BGSSaveLoadFile destruction dispatch"),
	]
	for item in targets:
		audit_function(item[0], item[1], 30000)

def audit_barrier_primitives():
	audit_function(0x00446F70, "worker gate acquisition primitive", 26000)
	audit_function(0x00446FF0, "worker gate release primitive", 26000)

def audit_abort_contract():
	audit_function(0x007CBAF0, "top-level game load owner", 48000)
	audit_function(0x00847DF0, "changed-form two-pass load owner", 52000)
	disasm_range(0x007CC550, 0x007CC6D0, "top-level load error publication and handling")
	disasm_range(0x008489D0, 0x00848B70, "changed-form global error checkpoints")
	disasm_range(0x008505B0, 0x00850670, "save failure decision, barrier release, and promotion")

def main():
	write("=" * 70)
	write("SAVE COMMIT AND ABORT MICRO FOLLOW-UP")
	write("=" * 70)
	write("Questions: what close actually guarantees, what the save barrier actually gates, and where a malformed record can abort before further live-state mutation.")
	audit_close_contract()
	audit_barrier_primitives()
	audit_abort_contract()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/save_commit_abort_micro_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
