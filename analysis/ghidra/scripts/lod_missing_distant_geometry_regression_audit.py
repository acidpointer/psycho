# @category Analysis
# @description Prove why terrain, object, and tree distant geometry stop publishing after the LOD scheduler fixes

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

def decompile_once(addr_int, label, max_len=18000):
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
	decompile_at(entry, label, max_len)

def audit_function(addr_int, label, max_len=18000):
	decompile_once(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def decompile_callers(addr_int, label, limit=80):
	write("")
	write("=" * 70)
	write("Decompiled callers of %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = set()
	count = 0
	while refs.hasNext() and count < limit:
		ref = refs.next()
		if ref.getReferenceType().isCall():
			func = fm.getFunctionContaining(ref.getFromAddress())
			if func is not None:
				entry = func.getEntryPoint().getOffset()
				if entry not in seen:
					seen.add(entry)
					decompile_once(entry, "%s caller" % label, 22000)
					find_and_print_calls_from(entry, "%s caller" % label)
					count += 1
	write("  Total unique callers: %d" % count)

def print_function_instructions(addr_int, label, limit=900):
	write("")
	write("=" * 70)
	write("Full instructions for %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext() and count < limit:
		inst = inst_iter.next()
		write("  0x%08x  %s" % (inst.getAddress().getOffset(), inst))
		count += 1
	if inst_iter.hasNext():
		write("  [truncated after %d instructions]" % limit)
	write("  Total printed: %d" % count)

def print_reference_windows(addr_int, label, limit=80, before=18, after=45):
	write("")
	write("=" * 70)
	write("Code-reference windows to %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext() and count < limit:
		ref = refs.next()
		from_addr = ref.getFromAddress()
		inst = listing.getInstructionContaining(from_addr)
		if inst is not None:
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
	write("  Total code references: %d" % count)

write("LOD MISSING DISTANT GEOMETRY REGRESSION AUDIT")
write("Program: %s" % currentProgram.getName())
write("Image base: %s" % currentProgram.getImageBase())
write("")
write("Symptom: close geometry remains, but distant terrain, objects, and trees never appear")
write("Goal: distinguish demand failure, priority starvation, file-read failure, and completion-publication failure")

write("")
write("# PRIORITY KEY ORDERING AND WORKER DEQUEUE")
audit_function(0x0043CCA0, "BSTask packed priority getter", 12000)
audit_function(0x0043CC60, "BSTask packed-key comparator wrapper", 16000)
audit_function(0x0043D6B0, "Priority consumer or queue comparator A", 22000)
audit_function(0x0043FED0, "Priority consumer or queue comparator B", 22000)
audit_function(0x00C3D440, "IOTask packed queue-key construction", 20000)
audit_function(0x006FC440, "Native LOD task priority provider", 14000)
audit_function(0x00C3CAE0, "IOTask dependency priority propagation", 18000)
audit_function(0x00C3DF40, "BSTaskManager priority-field replacement", 16000)
audit_function(0x00C3E690, "BSTaskManager remove and requeue", 22000)
audit_function(0x00C40E70, "Worker queue selection and pop", 26000)
audit_function(0x00C410B0, "BSTaskManagerThread worker loop", 28000)
print_function_instructions(0x0043CC60, "BSTask packed-key comparator wrapper", 180)
print_function_instructions(0x0043D6B0, "Priority consumer or queue comparator A", 420)
print_function_instructions(0x0043FED0, "Priority consumer or queue comparator B", 420)
print_function_instructions(0x00C40E70, "Worker queue selection and pop", 900)

write("")
write("# BSFILE OPEN, CACHE, DIRECT-READ, AND FAILURE CONTRACT")
audit_function(0x00AFF490, "BSFile open-state and optional-cache initializer", 26000)
audit_function(0x00AFF2A0, "BSFile attach-existing-stream caller", 16000)
audit_function(0x00AFF300, "BSFile physical-file open caller", 24000)
audit_function(0x00B004E0, "Concrete BSFile size virtual", 18000)
audit_function(0x00AA3E40, "GameHeap allocate used by BSFile cache", 26000)
audit_function(0x00AA1570, "BSFile preload raw-read wrapper", 14000)
audit_function(0x00AA15A0, "BSFile cache and stream cursor synchronizer", 18000)
audit_function(0x00AA1750, "BSFile buffered or direct read", 24000)
audit_function(0x00AFF240, "BSFile destruction and cache release", 18000)
decompile_callers(0x00AFF490, "BSFile open-state and optional-cache initializer", 20)
decompile_callers(0x00AA1750, "BSFile buffered or direct read", 60)
print_function_instructions(0x00AFF490, "BSFile open-state and optional-cache initializer", 420)
print_function_instructions(0x00AA1750, "BSFile buffered or direct read", 420)
print_reference_windows(0x00AA1750, "BSFile buffered or direct read", 60, 18, 45)

write("")
write("# RESOURCE LOOKUP AND LOAD-RESULT PROPAGATION")
audit_function(0x00AFDF20, "Resource lookup choosing archive or BSFile", 26000)
audit_function(0x00C3CFF0, "IOTask path resource request", 22000)
audit_function(0x00AF6340, "Archive resource lookup path", 24000)
decompile_callers(0x00C3CFF0, "IOTask path resource request", 80)
decompile_callers(0x00AFDF20, "Resource lookup choosing archive or BSFile", 80)

write("")
write("# THREE LOD DEMAND PRODUCERS")
audit_function(0x006FE550, "Terrain LOD demand predicate", 16000)
audit_function(0x006FE620, "Object LOD demand predicate", 16000)
audit_function(0x006FE780, "Tree LOD demand predicate", 16000)
audit_function(0x006FDAA0, "Terrain LOD request and retirement owner", 28000)
audit_function(0x006FDFC0, "Object LOD request and retirement owner", 28000)
audit_function(0x006FE330, "Tree LOD request and retirement owner", 28000)
audit_function(0x006FCA90, "Worldspace LOD update owner", 28000)

write("")
write("# WORKER LOAD AND MAIN-THREAD PUBLICATION FOR ALL LOD TYPES")
audit_function(0x006F71E0, "Object LOD worker load", 28000)
audit_function(0x006F73D0, "Object LOD main-thread completion", 22000)
audit_function(0x006F7070, "Object LOD result cleanup", 18000)
audit_function(0x006F9570, "Tree LOD worker load", 22000)
audit_function(0x006F9610, "Tree LOD main-thread completion", 16000)
audit_function(0x006F94C0, "Tree LOD result cleanup", 14000)
audit_function(0x006FBD00, "Terrain LOD worker load", 30000)
audit_function(0x006FC020, "Terrain LOD main-thread completion", 32000)
audit_function(0x006FBBD0, "Terrain LOD result cleanup", 22000)
audit_function(0x00C3DBF0, "Main-thread completed-task drain", 28000)
audit_function(0x00C3DFA0, "Blocking save-load completed-task drain", 28000)
audit_function(0x006FCDB0, "Distant LOD post-update owner", 26000)
audit_function(0x006FEA70, "Terrain morph and publication phase", 28000)

write("")
write("# CROSS-SUBSYSTEM CALLER COVERAGE")
find_refs_to(0x006F71E0, "Object LOD worker load")
find_refs_to(0x006F9570, "Tree LOD worker load")
find_refs_to(0x006FBD00, "Terrain LOD worker load")
find_refs_to(0x00C3DBF0, "Main-thread completed-task drain")
find_refs_to(0x00C3DFA0, "Blocking save-load completed-task drain")

write("")
write("END OF AUDIT")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/lod_missing_distant_geometry_regression_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
