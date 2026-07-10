# @category Analysis
# @description Audit ScrapHeap identity and thread ownership before changing its locking model

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

SHEAP_GET_TLS = 0x00AA42E0
SHEAP_ALLOC = 0x00AA54A0
SHEAP_FREE = 0x00AA5610
SHEAP_PURGE = 0x00AA5460


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


def print_call_context(call_addr, before_count=12):
	inst = listing.getInstructionAt(toAddr(call_addr))
	if inst is None:
		write("  [instruction missing at 0x%08x]" % call_addr)
		return
	steps = 0
	while inst.getPrevious() is not None and steps < before_count:
		inst = inst.getPrevious()
		steps += 1
	printed = 0
	while inst is not None and printed <= before_count:
		write("    0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()
		printed += 1


def audit_callers(target, label, decompile_limit):
	write("")
	write("=" * 70)
	write("%s call-site identity provenance" % label)
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(target))
	seen = {}
	unique = []
	count = 0
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		call_addr = ref.getFromAddress().getOffset()
		func = fm.getFunctionContaining(ref.getFromAddress())
		entry = func.getEntryPoint().getOffset() if func else 0
		name = func.getName() if func else "???"
		write("  CALL 0x%08x in 0x%08x %s" % (call_addr, entry, name))
		print_call_context(call_addr)
		if entry != 0 and entry not in seen:
			seen[entry] = 1
			unique.append(entry)
		count += 1
	write("  Total call sites: %d, unique callers: %d" % (count, len(unique)))
	index = 0
	while index < len(unique) and index < decompile_limit:
		entry = unique[index]
		decompile_at(entry, "%s caller %d" % (label, index + 1), 12000)
		index += 1
	if len(unique) > decompile_limit:
		write("  Caller decompilation capped at %d of %d" % (decompile_limit, len(unique)))


def main():
	write("SCRAP HEAP IDENTITY AND THREAD-OWNERSHIP CONTRACT")
	write("=" * 70)
	write("Goal: determine whether a ScrapHeap identity can be shared by threads.")
	write("A lock-free Runtime fast path is unsafe until this is proven.")
	decompile_at(SHEAP_GET_TLS, "ScrapHeap_GetThreadLocal original")
	decompile_at(SHEAP_ALLOC, "ScrapHeap_Allocate original")
	decompile_at(SHEAP_FREE, "ScrapHeap_Free original")
	decompile_at(SHEAP_PURGE, "ScrapHeap_Purge original")
	find_and_print_calls_from(SHEAP_GET_TLS, "ScrapHeap_GetThreadLocal original")
	find_and_print_calls_from(SHEAP_ALLOC, "ScrapHeap_Allocate original")
	find_and_print_calls_from(SHEAP_FREE, "ScrapHeap_Free original")
	find_and_print_calls_from(SHEAP_PURGE, "ScrapHeap_Purge original")
	audit_callers(SHEAP_GET_TLS, "ScrapHeap_GetThreadLocal", 24)
	audit_callers(SHEAP_ALLOC, "ScrapHeap_Allocate", 48)
	audit_callers(SHEAP_FREE, "ScrapHeap_Free", 40)
	audit_callers(SHEAP_PURGE, "ScrapHeap_Purge", 16)
	find_refs_to(SHEAP_GET_TLS, "ScrapHeap_GetThreadLocal")
	find_refs_to(SHEAP_ALLOC, "ScrapHeap_Allocate")
	find_refs_to(SHEAP_FREE, "ScrapHeap_Free")
	find_refs_to(SHEAP_PURGE, "ScrapHeap_Purge")


main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/memory/scrap_heap_identity_thread_contract.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
