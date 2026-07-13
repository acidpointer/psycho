# @category Analysis
# @description Resolve FalloutNV changed-record payload framing, decompression, bounds, rejection, and load-error propagation contracts

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

def audit_function(addr_int, label, max_len=30000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def audit_targets():
	targets = [
		(0x00864E20, "changed-record payload acquisition owner", 40000),
		(0x00864450, "changed-record constructor payload setup", 24000),
		(0x00864520, "changed-record encoded payload length reader", 18000),
		(0x00845E50, "changed-record physical payload reader", 30000),
		(0x008646B0, "changed-record payload buffer constructor", 24000),
		(0x008646F0, "changed-record payload buffer cleanup", 22000),
		(0x00864740, "changed-record payload state transition", 24000),
		(0x00864820, "unchecked changed-record buffer read", 22000),
		(0x00864980, "changed-record scalar buffer reader", 22000),
		(0x008649A0, "changed-record compound buffer reader", 26000),
		(0x00864A60, "changed-record variable buffer reader", 28000),
		(0x00848CF0, "global load-error predicate", 20000),
		(0x00848D90, "per-record rejection setter", 24000),
		(0x00848E70, "changed-record preload or validation path", 40000),
		(0x008495D0, "alternate changed-record load path", 40000),
		(0x004740A0, "TES zlib inflate owner used by engine records", 40000),
		(0x00483D70, "changed-record deflate producer", 36000),
	]
	for item in targets:
		audit_function(item[0], item[1], item[2])

def audit_zlib_and_load_error_refs():
	find_refs_to(0x00B43FE0, "zlib inflateInit entrypoint")
	find_refs_to(0x00B44000, "zlib inflate entrypoint")
	find_refs_to(0x00B45DB0, "zlib inflateEnd entrypoint")
	find_refs_to(0x011DE9A0, "BGSSaveLoadGame singleton if mapped at expected address")
	disasm_range(0x00864E20, 0x00865040, "changed-record framing and payload acquisition")
	disasm_range(0x00864820, 0x00864B10, "changed-record in-memory readers and spacer handling")
	disasm_range(0x00848C80, 0x00848E20, "global and per-record load-error flags")
	disasm_range(0x00483E00, 0x00483FB0, "deflate return handling and compressed-record publication")

def main():
	write("=" * 70)
	write("SAVE CHANGED-RECORD INFLATE AND BOUNDS FOLLOW-UP")
	write("=" * 70)
	write("Questions: which lengths are trusted, how compressed payloads are validated, and whether malformed records are rejected before any unchecked buffer read or live-state mutation.")
	audit_targets()
	audit_zlib_and_load_error_refs()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/save_changed_record_inflate_bounds_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
