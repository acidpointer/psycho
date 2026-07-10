# @category Analysis
# @description Trace high-risk shared ScrapHeap identities from worker and main-thread entry paths

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


def decompile_at(addr_int, label, max_len=12000):
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
	write(
		"  Function: %s @ 0x%08x, Size: %d bytes"
		% (func.getName(), faddr, func.getBody().getNumAddresses())
	)
	if faddr != addr_int:
		write(
			"  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)"
			% (addr_int, func.getName(), faddr)
		)
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		write(result.getDecompiledFunction().getC()[:max_len])
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
		write(
			"  %s @ 0x%08x (in %s)"
			% (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname)
		)
		count += 1
	write("  Total: %d refs" % count)


def find_and_print_calls_from(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				write(
					"  0x%08x -> 0x%08x %s"
					% (inst.getAddress().getOffset(), tgt, name)
				)
				count += 1
	write("  Total: %d calls" % count)


def main():
	write("SCRAP HEAP SHARED-IDENTITY WORKER AUDIT")
	write("=" * 70)
	write("Goal: determine whether direct ScrapHeap identities can reach worker threads.")
	write("Do not remove Heap::state locking unless every identity is thread-confined.")
	decompile_at(0x0086A850, "Main loop entry")
	decompile_at(0x00C410B0, "BSTaskManager worker entry")
	decompile_at(0x008C7764, "AI worker entry")
	decompile_at(0x00B5DAC0, "Global ScrapHeap allocation user")
	decompile_at(0x00C49850, "Global ScrapHeap allocation user")
	decompile_at(0x0068CB60, "TLS-backed multi-buffer allocation user")
	decompile_at(0x005595E0, "Embedded ScrapHeap allocation user")
	find_and_print_calls_from(0x0086A850, "Main loop entry")
	find_and_print_calls_from(0x00C410B0, "BSTaskManager worker entry")
	find_and_print_calls_from(0x008C7764, "AI worker entry")
	find_refs_to(0x00B5DAC0, "Global ScrapHeap allocation user")
	find_refs_to(0x00C49850, "Global ScrapHeap allocation user")
	find_refs_to(0x0068CB60, "TLS-backed multi-buffer allocation user")
	find_refs_to(0x005595E0, "Embedded ScrapHeap allocation user")
	find_refs_to(0x011F6238, "Global ScrapHeap identity")


main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/memory/scrap_heap_shared_identity_worker_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
