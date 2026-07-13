# @category Analysis
# @description Resolve missing-master FormID expansion, changed-record publication, and primitive-cache ownership after the reproducible old-save crash

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

def print_data_refs_from(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("--- Data references FROM %s (0x%08x) ---" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if not ref.getReferenceType().isCall() and ref.getToAddress().isMemoryAddress():
				write("  0x%08x %s -> 0x%08x" % (inst.getAddress().getOffset(), ref.getReferenceType(), ref.getToAddress().getOffset()))
				count += 1
	write("  Total: %d data refs" % count)

def audit_function(addr_int, label, max_len=20000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def audit_targets():
	targets = [
		(0x00846D20, "saved FormID to runtime FormID translation", 20000),
		(0x008645B0, "changed-record live-form virtual resolver", 22000),
		(0x00864610, "changed-record adjacent virtual method", 16000),
		(0x0044EDB0, "changed-record runtime FormID accessor", 16000),
		(0x008644B0, "changed-record payload binding", 22000),
		(0x00848D90, "changed-record rejection marker", 18000),
		(0x00848DD0, "changed-record rejection predicate", 16000),
		(0x008492B0, "load global synchronization release", 22000),
		(0x004416C0, "queued model task execute wrapper", 22000),
		(0x00441780, "reference model task publication", 24000),
		(0x00442650, "background clone global synchronization participant", 26000),
		(0x004A72D0, "shared primitive lazy-cache builder", 36000),
	]
	for item in targets:
		audit_function(item[0], item[1], item[2])

def audit_exact_dataflow():
	disasm_range(0x00846D20, 0x00846DB0, "saved plugin-index expansion including 0xFF")
	disasm_range(0x008645B0, 0x00864670, "changed-record live-form resolution methods")
	disasm_range(0x00848340, 0x00848470, "first-pass identity, map publication, and live-form resolution")
	disasm_range(0x00848470, 0x008486A0, "first-pass rejection and cleanup after live-form resolution")
	disasm_range(0x00848780, 0x008488B0, "second-pass rejected-record skip and live-form lookup")
	disasm_range(0x004A72D0, 0x004A77F0, "primitive cache check, construction, and publication")
	print_data_refs_from(0x004A72D0, "shared primitive lazy-cache builder")
	disasm_range(0x004416C0, 0x00441820, "model task execution and publication")
	disasm_range(0x00442650, 0x00442B00, "background clone synchronization and queue ownership")

def main():
	write("=" * 70)
	write("SAVE MISSING-CONTENT PUBLICATION MICRO FOLLOW-UP")
	write("=" * 70)
	write("Prove how a missing master's 0xFF index reaches changed-record live-form lookup, which first-pass structures are retained for an unresolved form, when the load barrier releases background model work, and whether the primitive failure comes from shared lazy-cache publication rather than the saved object itself.")
	audit_targets()
	audit_exact_dataflow()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/save_missing_content_publication_micro_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
