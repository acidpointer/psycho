# @category Analysis
# @description Resolve the save-load C0000417 origin and prove complete LOD multi-worker lifetime coverage

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []
decompiled = {}

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

def decompile_once(addr_int, label, max_len=16000):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		decompile_at(addr_int, label, max_len)
		return
	entry = func.getEntryPoint().getOffset()
	if entry in decompiled:
		write("  [already decompiled 0x%08x as %s]" % (entry, decompiled[entry]))
		return
	decompiled[entry] = label
	decompile_at(addr_int, label, max_len)

def audit_function(addr_int, label, max_len=16000):
	decompile_once(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def audit_addresses(items):
	for item in items:
		audit_function(item[0], item[1], item[2])

def print_instruction_window(addr_int, label, before=20, after=48):
	write("")
	write("=" * 70)
	write("Instruction window %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	inst = listing.getInstructionContaining(toAddr(addr_int))
	if inst is None:
		write("  [instruction not found]")
		return
	start = inst
	count = 0
	while start.getPrevious() is not None and count < before:
		start = start.getPrevious()
		count += 1
	cur = start
	count = 0
	while cur is not None and count < before + after + 1:
		marker = "  "
		if cur.getAddress() == inst.getAddress():
			marker = ">>"
		write("%s 0x%08x  %s" % (marker, cur.getAddress().getOffset(), cur))
		cur = cur.getNext()
		count += 1

def print_reference_windows(addr_int, label, limit=80, before=16, after=28):
	write("")
	write("=" * 70)
	write("Code-reference windows to %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext() and count < limit:
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		from_addr = ref.getFromAddress()
		inst = listing.getInstructionContaining(from_addr)
		if inst is None:
			continue
		owner = fm.getFunctionContaining(from_addr)
		owner_name = owner.getName() if owner else "???"
		write("")
		write("-" * 70)
		write("Reference 0x%08x in %s" % (from_addr.getOffset(), owner_name))
		start = inst
		back_count = 0
		while start.getPrevious() is not None and back_count < before:
			start = start.getPrevious()
			back_count += 1
		cur = start
		window_count = 0
		while cur is not None and window_count < before + after + 1:
			marker = "  "
			if cur.getAddress() == inst.getAddress():
				marker = ">>"
			write("%s 0x%08x  %s" % (marker, cur.getAddress().getOffset(), cur))
			cur = cur.getNext()
			window_count += 1
		count += 1
	if refs.hasNext():
		write("  [truncated after %d code references]" % limit)

def collect_call_referrers(addr_int):
	entries = {}
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		if entry not in entries:
			entries[entry] = [func.getName(), []]
		entries[entry][1].append(ref.getFromAddress().getOffset())
	return entries

def print_call_referrer_inventory(addr_int, label):
	write("")
	write("=" * 70)
	write("Complete direct caller inventory for %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	entries = collect_call_referrers(addr_int)
	keys = entries.keys()
	keys.sort()
	for entry in keys:
		item = entries[entry]
		callsites = item[1]
		callsites.sort()
		formatted = []
		for callsite in callsites:
			formatted.append("0x%08x" % callsite)
		write("  0x%08x %-32s calls=%s" % (entry, item[0], ",".join(formatted)))
	write("  Unique direct caller functions: %d" % len(keys))

def decompile_callers_in_range(addr_int, label, start, end, max_len=20000):
	write("")
	write("=" * 70)
	write("Direct callers of %s in 0x%08x-0x%08x" % (label, start, end))
	write("=" * 70)
	entries = collect_call_referrers(addr_int)
	keys = entries.keys()
	keys.sort()
	count = 0
	for entry in keys:
		if entry < start or entry >= end:
			continue
		decompile_once(entry, "%s caller %s" % (label, entries[entry][0]), max_len)
		find_and_print_calls_from(entry, "%s caller %s" % (label, entries[entry][0]))
		count += 1
	write("  Decompiled caller functions in range: %d" % count)

def print_functions_referencing(addr_int, label, start, end):
	write("")
	write("-" * 70)
	write("Functions referencing 0x%08x (%s) in 0x%08x-0x%08x" % (addr_int, label, start, end))
	write("-" * 70)
	seen = {}
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		if entry >= start and entry < end:
			seen[entry] = func.getName()
	keys = seen.keys()
	keys.sort()
	for entry in keys:
		write("  0x%08x %s" % (entry, seen[entry]))
	write("  Unique functions: %d" % len(keys))

write("LOD SAVE-LOAD C0000417 ORIGIN AND COVERAGE AUDIT")
write("Program: %s" % currentProgram.getName())
write("Image base: %s" % currentProgram.getImageBase())
write("")
write("Observed current evidence:")
write("  C0000417 during save load; current CrashLogger lost the call trace.")
write("  Historical main-thread signature: 0x00ec7c62 -> 0x00b03e48 SpeedTree erase.")
write("  Historical worker signature: 0x00ecb144 -> 0x00ecb387 -> 0x00ecb3c0 -> IO path.")
write("")
write("Contract questions:")
write("  1. Which game functions can directly enter each invalid-parameter family?")
write("  2. Can any save-load, LOD, IO, or SpeedTree path reach those entries?")
write("  3. Does every SpeedTree owner-vector mutation pass the hooked constructor or scalar destructor?")
write("  4. Does the second worker expose a separate secure-path or task-container contract failure?")

invalid_parameter_core = [
	(0x00EC7C56, "checked-container invalid-parameter wrapper", 12000),
	(0x00EC7C62, "historical checked-container failure instruction", 12000),
	(0x00ECB144, "historical worker invalid-parameter failure instruction", 16000),
	(0x00ECB387, "historical worker invalid-parameter caller A", 18000),
	(0x00ECB3C0, "historical worker invalid-parameter caller B", 18000)
]

worker_chain = [
	(0x00AA1588, "worker invalid chain allocator or string caller", 20000),
	(0x00AFF477, "worker invalid chain path helper", 24000),
	(0x00AFE0B4, "worker invalid chain file lookup", 28000),
	(0x00C3D075, "IOTask path request caller", 22000),
	(0x0043C261, "IOTask execution caller", 22000),
	(0x00C3FC94, "IO queue worker caller", 24000),
	(0x00C41257, "BSTask worker dispatch caller", 24000),
	(0x00C42DBF, "BSTaskManagerThread outer worker", 24000)
]

speedtree_contract = [
	(0x00B036D0, "SpeedTree clone constructor hook target", 26000),
	(0x00B05210, "SpeedTree clone allocation wrapper", 18000),
	(0x00B0DDC0, "SpeedTree owner-vector insertion", 22000),
	(0x00B03B30, "SpeedTree core destructor", 32000),
	(0x00666910, "SpeedTree scalar destructor hook target", 14000),
	(0x00B0DF00, "SpeedTree owner-vector erase", 18000),
	(0x00B10430, "SpeedTree checked iterator constructor", 14000),
	(0x00B0ECA0, "SpeedTree checked iterator comparison", 14000),
	(0x00B02EF0, "SpeedTree base constructor and registry insertion", 32000),
	(0x00B08EC0, "SpeedTree global registry traversal", 26000),
	(0x0066A650, "BSTreeModel load and clone creation", 32000),
	(0x0066AC40, "BSTreeModel reload or replacement", 32000),
	(0x00666800, "BSTreeModel destructor", 22000),
	(0x006667D0, "BSTreeModel scalar destructor", 14000)
]

io_contract = [
	(0x00C3C590, "BSTask base constructor and TLS capture", 18000),
	(0x00C3CE60, "IOTask base constructor", 14000),
	(0x00C3CEE0, "IOTask secure path copy", 18000),
	(0x00C3CF60, "IOTask file request publication", 22000),
	(0x00C3D090, "IOTask path request builder", 18000),
	(0x00AFD270, "file request secure path split", 24000),
	(0x00C3D980, "IOManager destruction or reset candidate", 26000),
	(0x00C3DA50, "IOManager constructor and worker count", 26000),
	(0x00C3DBF0, "IOManager processing and release", 28000),
	(0x00C3E4F0, "BSTaskManager TLS-slot constructor", 26000),
	(0x0044C040, "LockFreeMap constructor family A hook target", 22000),
	(0x0044C270, "LockFreeMap constructor family B hook target", 22000),
	(0x0044CB70, "LockFreeMap destructor", 18000),
	(0x0044E3A0, "LockFreeMap TLS registration capacity gate", 22000)
]

write("")
write("# INVALID-PARAMETER ENTRY FAMILIES")
audit_addresses(invalid_parameter_core)
print_call_referrer_inventory(0x00EC7C56, "checked-container invalid-parameter wrapper")
print_reference_windows(0x00EC7C56, "checked-container invalid-parameter wrapper", 120, 14, 24)
decompile_callers_in_range(0x00EC7C56, "checked-container invalid-parameter wrapper", 0x00660000, 0x00710000, 24000)
decompile_callers_in_range(0x00EC7C56, "checked-container invalid-parameter wrapper", 0x00AF0000, 0x00B20000, 26000)
decompile_callers_in_range(0x00EC7C56, "checked-container invalid-parameter wrapper", 0x00C30000, 0x00C50000, 26000)

write("")
write("# HISTORICAL WORKER INVALID-PARAMETER CHAIN")
audit_addresses(worker_chain)
print_call_referrer_inventory(0x00ECB144, "historical worker invalid-parameter failure")

write("")
write("# SPEEDTREE OWNER AND DESTRUCTION COVERAGE")
audit_addresses(speedtree_contract)
print_functions_referencing(0x011F8BDC, "SpeedTree global registry begin", 0x00B00000, 0x00B20000)
print_functions_referencing(0x011F8BC4, "SpeedTree registry critical section", 0x00B00000, 0x00B20000)
print_instruction_window(0x00B038D7, "clone owner-vector insertion call", 28, 36)
print_instruction_window(0x00B03E43, "clone owner-vector erase call", 36, 32)
print_instruction_window(0x00666910, "scalar destructor hook boundary", 12, 24)

write("")
write("# TWO-WORKER IO AND SECURE-PATH COVERAGE")
audit_addresses(io_contract)
print_instruction_window(0x00C3DA7A, "IOManager worker-count immediate", 24, 44)
print_instruction_window(0x00C3D075, "historical worker path failure caller", 28, 44)
print_reference_windows(0x00C3CEE0, "IOTask secure path copy", 40, 16, 28)
print_reference_windows(0x0044E3A0, "LockFreeMap TLS registration capacity gate", 60, 18, 32)

write("")
write("END LOD SAVE-LOAD C0000417 ORIGIN AND COVERAGE AUDIT")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/lod_save_load_c0000417_origin_and_coverage_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
