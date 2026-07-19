# @category Analysis
# @description Close FNV LOD streaming issuance, dependency-priority, IO worker-capacity, queue-ordering, and completion-budget performance gaps

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
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

def read_u32(addr_int):
	try:
		return memory.getInt(toAddr(addr_int)) & 0xffffffff
	except:
		return None

def decompile_once(addr_int, label, max_len):
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

def collect_callers(addr_int):
	callers = {}
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	while refs.hasNext():
		ref = refs.next()
		if ref.getReferenceType().isCall():
			func = fm.getFunctionContaining(ref.getFromAddress())
			if func is not None:
				callers[func.getEntryPoint().getOffset()] = True
	return sorted(callers.keys())

def decompile_callers(addr_int, label, limit, max_len):
	callers = collect_callers(addr_int)
	idx = 0
	while idx < len(callers) and idx < limit:
		entry = callers[idx]
		decompile_once(entry, "%s caller %d" % (label, idx + 1), max_len)
		find_and_print_calls_from(entry, "%s caller %d" % (label, idx + 1))
		idx += 1
	write("  Caller functions considered: %d of %d" % (idx, len(callers)))

def collect_callees(addr_int):
	callees = {}
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		return []
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				target_func = fm.getFunctionAt(toAddr(target))
				if target_func is None:
					target_func = fm.getFunctionContaining(toAddr(target))
				if target_func is not None:
					entry = target_func.getEntryPoint().getOffset()
					if 0x00400000 <= entry < 0x01000000:
						callees[entry] = True
	return sorted(callees.keys())

def decompile_callees(addr_int, label, limit, max_len):
	callees = collect_callees(addr_int)
	idx = 0
	while idx < len(callees) and idx < limit:
		entry = callees[idx]
		decompile_once(entry, "%s callee %d" % (label, idx + 1), max_len)
		find_and_print_calls_from(entry, "%s callee %d" % (label, idx + 1))
		idx += 1
	write("  Direct callees considered: %d of %d" % (idx, len(callees)))

def collect_reference_owners(addr_int):
	owners = {}
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is not None:
			owners[func.getEntryPoint().getOffset()] = True
	return sorted(owners.keys())

def decompile_reference_owners(addr_int, label, limit, max_len, include_callees):
	owners = collect_reference_owners(addr_int)
	write("")
	write("#" * 70)
	write("REFERENCE OWNERS: %s @ 0x%08x" % (label, addr_int))
	write("#" * 70)
	idx = 0
	while idx < len(owners) and idx < limit:
		entry = owners[idx]
		owner_label = "%s owner %d" % (label, idx + 1)
		decompile_once(entry, owner_label, max_len)
		find_and_print_calls_from(entry, owner_label)
		if include_callees:
			decompile_callees(entry, owner_label, 24, max_len)
		idx += 1
	write("  Reference owners considered: %d of %d" % (idx, len(owners)))

def audit_known_function(addr_int, label, max_len, caller_limit):
	decompile_once(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)
	if caller_limit > 0:
		decompile_callers(addr_int, label, caller_limit, max_len)

def audit_with_callees(addr_int, label, max_len, callee_limit):
	audit_known_function(addr_int, label, max_len, 0)
	decompile_callees(addr_int, label, callee_limit, max_len)

def print_instruction_window(addr_int, label, before_count, after_count):
	write("")
	write("-" * 70)
	write("INSTRUCTION WINDOW: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	inst = listing.getInstructionContaining(toAddr(addr_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(addr_int - 1))
	back = 0
	while inst is not None and back < before_count:
		prev = inst.getPrevious()
		if prev is None:
			break
		inst = prev
		back += 1
	count = 0
	total = before_count + after_count + 1
	while inst is not None and count < total:
		marker = " =>" if inst.getAddress().getOffset() == addr_int else "   "
		write("%s 0x%08x: %s" % (marker, inst.getAddress().getOffset(), inst.toString()))
		refs = inst.getReferencesFrom()
		for ref in refs:
			write("      %s -> 0x%08x" % (ref.getReferenceType(), ref.getToAddress().getOffset()))
		inst = inst.getNext()
		count += 1
	write("  Instructions printed: %d" % count)

def print_vtable(vtable, label, max_slots):
	write("")
	write("-" * 70)
	write("%s vtable @ 0x%08x" % (label, vtable))
	write("-" * 70)
	idx = 0
	while idx < max_slots:
		target = read_u32(vtable + idx * 4)
		if target is None:
			write("  [%02d] unreadable" % idx)
			break
		func = fm.getFunctionAt(toAddr(target))
		if func is None:
			func = fm.getFunctionContaining(toAddr(target))
		name = func.getName() if func is not None else "???"
		write("  [%02d] +0x%02x -> 0x%08x %s" % (idx, idx * 4, target, name))
		if not (0x00400000 <= target < 0x01000000) and idx >= 5:
			break
		idx += 1

write("FNV LOD STREAMING PERFORMANCE BOTTLENECK AUDIT")
write("")
write("This audit closes the performance contract left intentionally unchanged by the correctness fix:")
write("1. Per-frame terrain, object, and tree request issuance cadence and any native throttles.")
write("2. Parent-to-dependency priority inheritance for LOD model and texture work.")
write("3. Exact IO priority key, comparison, enqueue, reprioritization, and fairness behavior.")
write("4. IOManager construction, worker count/capacity, wakeup, and shutdown ownership.")
write("5. Worker versus main-thread phase ownership and the completed-task time budget.")

write("")
write("######################################################################")
write("REQUEST ISSUANCE AND PRODUCER CADENCE")
write("######################################################################")
audit_known_function(0x006FCA90, "camera/worldspace distant-manager update owner", 100000, 4)
audit_with_callees(0x006FDAA0, "terrain per-frame update and request issuance", 100000, 36)
audit_with_callees(0x006FDFC0, "distant-object per-frame update and request issuance", 100000, 36)
audit_with_callees(0x006FE330, "distant-tree per-frame update and request issuance", 100000, 36)
audit_known_function(0x006F5160, "distant-object block task producer", 80000, 6)
audit_known_function(0x006F7540, "distant-tree block task producer", 80000, 6)
audit_known_function(0x006FA210, "terrain chunk task producer", 100000, 6)

write("")
write("######################################################################")
write("LOD DEPENDENCY CREATION AND PRIORITY INHERITANCE")
write("######################################################################")
audit_known_function(0x006F7070, "object LOD slot 8 dependency creation", 70000, 4)
audit_known_function(0x006F94C0, "tree LOD slot 8 dependency creation", 70000, 4)
audit_known_function(0x006FBBD0, "terrain LOD slot 8 dependency creation", 70000, 4)
audit_with_callees(0x004436C0, "model and texture dependency lookup/create/attach", 120000, 48)
audit_with_callees(0x0043CC60, "parent task priority exported to dependencies", 70000, 24)
audit_known_function(0x0043BD10, "new dependency task constructor path A", 70000, 8)
audit_known_function(0x0043BE60, "new dependency task constructor path B", 70000, 8)
audit_known_function(0x0043BEF0, "cached dependency task constructor path", 70000, 8)
print_instruction_window(0x006F70B8, "object dependency priority argument handoff", 10, 18)
print_instruction_window(0x006FBC2A, "terrain dependency priority argument handoff", 10, 18)

write("")
write("######################################################################")
write("IO PRIORITY KEY, QUEUE ORDERING, AND REPRIORITIZATION")
write("######################################################################")
audit_with_callees(0x00C3CE60, "IOTask base construction and initial scheduling fields", 90000, 32)
audit_with_callees(0x00C3D440, "IOTask packed priority key construction", 90000, 32)
audit_with_callees(0x006FC440, "LOD task priority-class selector", 70000, 20)
audit_with_callees(0x0043C030, "LOD dynamic priority contribution", 70000, 24)
audit_with_callees(0x00C3DE80, "IOManager task submission and key publication", 90000, 32)
audit_with_callees(0x00C3FB50, "IOManager pending priority-queue insertion", 100000, 40)
audit_with_callees(0x00C3DF40, "IOTask priority-change request", 70000, 24)
audit_with_callees(0x00C3E690, "IOManager queued-task reprioritization", 100000, 40)
audit_known_function(0x00C3F6B0, "IOManager 64-bit priority-key comparator", 50000, 8)
print_instruction_window(0x00C3D440, "packed key construction prologue", 0, 70)
print_instruction_window(0x00C3DEA0, "submission key update and queue insertion", 12, 48)

write("")
write("######################################################################")
write("IOMANAGER WORKER CAPACITY AND THREAD OWNERSHIP")
write("######################################################################")
find_refs_to(0x010C1604, "IOManager vtable")
decompile_reference_owners(0x010C1604, "IOManager vtable", 12, 120000, True)
find_refs_to(0x01202D98, "IOManager singleton")
decompile_reference_owners(0x01202D98, "IOManager singleton", 24, 120000, False)
audit_with_callees(0x00C3FE00, "IOManager worker object construction", 100000, 40)
audit_with_callees(0x00C3DB60, "IOManager shutdown and worker teardown", 120000, 40)
audit_with_callees(0x00C3FCE0, "IOManager worker dispatch or completion publication", 100000, 40)
audit_with_callees(0x00C3EA10, "IOManager queue wakeup or shutdown transition", 80000, 32)
print_vtable(0x010C1604, "IOManager", 28)
print_vtable(0x010C1664, "IO priority queue/container", 24)

write("")
write("######################################################################")
write("WORKER EXECUTION, LOD PHASE COST, AND MAIN-THREAD DRAIN")
write("######################################################################")
audit_with_callees(0x00C3FC80, "worker phase 1 virtual dispatch", 70000, 20)
audit_with_callees(0x00C3FCA0, "worker phase 2 virtual dispatch and completion", 70000, 20)
audit_with_callees(0x006F71E0, "object LOD worker phase 1", 100000, 32)
audit_with_callees(0x006F73D0, "object LOD worker phase 2 publication", 100000, 32)
audit_with_callees(0x006F9570, "tree LOD worker phase 1 parse", 100000, 32)
audit_with_callees(0x006F9610, "tree LOD worker phase 2 publication", 70000, 20)
audit_with_callees(0x006FBD00, "terrain LOD worker phase 1", 120000, 40)
audit_with_callees(0x006FC020, "terrain LOD worker phase 2 publication", 120000, 40)
audit_with_callees(0x00C3DBF0, "main-thread completed-task budget drain", 100000, 32)
audit_known_function(0x00AA4D80, "completed-drain high-resolution clock", 50000, 12)
audit_known_function(0x00EC62F6, "completed-drain budget source", 50000, 12)
print_instruction_window(0x00C3DCD8, "completed-drain clock and budget setup", 12, 42)
print_instruction_window(0x00C3DD90, "completed-drain budget comparison", 16, 42)

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/lod_streaming_performance_bottleneck_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
