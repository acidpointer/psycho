# @category Analysis
# @description Close FNV LockFreeMap TLS-capacity and packed-priority contracts required for faster LOD streaming

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

def read_u32(addr_int):
	try:
		return memory.getInt(toAddr(addr_int)) & 0xffffffff
	except:
		return None

def decompile_once(addr_int, label, max_len=10000):
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

def audit_function(addr_int, label):
	decompile_once(addr_int, label, 14000)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def print_instruction_window(addr_int, label, before=16, after=36):
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

def print_reference_windows(addr_int, label, limit=64, before=14, after=30):
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

def decompile_callers(addr_int, label, limit=64):
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
					decompile_once(entry, "%s caller" % label, 14000)
					find_and_print_calls_from(entry, "%s caller" % label)
					count += 1

def decompile_direct_callees(addr_int, label, limit=40):
	write("")
	write("=" * 70)
	write("Direct callees of %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found]")
		return
	seen = set()
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext() and count < limit:
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				if target not in seen and fm.getFunctionAt(toAddr(target)) is not None:
					seen.add(target)
					decompile_once(target, "%s direct callee" % label, 12000)
					count += 1

def print_data_ref_neighborhoods(addr_int, label, before_slots=16, after_slots=10):
	write("")
	write("=" * 70)
	write("Data-reference neighborhoods to %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_addr = ref.getFromAddress()
		if listing.getInstructionContaining(from_addr) is None:
			write("")
			write("-" * 70)
			write("Data reference at 0x%08x" % from_addr.getOffset())
			index = -before_slots
			while index <= after_slots:
				slot_addr = from_addr.getOffset() + index * 4
				value = read_u32(slot_addr)
				marker = "  "
				if index == 0:
					marker = ">>"
				if value is None:
					write("%s 0x%08x: [unreadable]" % (marker, slot_addr))
				else:
					func = fm.getFunctionAt(toAddr(value))
					name = func.getName() if func else "???"
					write("%s 0x%08x: 0x%08x %s" % (marker, slot_addr, value, name))
				index += 1
			count += 1
	write("  Total data references: %d" % count)

write("LOD STREAMING MULTI-WORKER TLS CAPACITY FINAL AUDIT")
write("Program: %s" % currentProgram.getName())
write("Image base: %s" % currentProgram.getImageBase())
write("")
write("# EXACT PACKED PRIORITY ABI")

audit_function(0x0043CC60, "BSTask packed priority read")
audit_function(0x0043CC80, "BSTask packed priority byte wrapper")
audit_function(0x0043CCA0, "BSTask packed priority shift helper")
audit_function(0x00440660, "IOTask public priority update wrapper")
audit_function(0x00C3D440, "BSTask packed queue key builder")
audit_function(0x00C3DE80, "IOManager task submission")
audit_function(0x00C3DF40, "IOManager queued task priority update")
audit_function(0x00C3CAE0, "IOTask dependency priority propagation")
print_instruction_window(0x0043CC60, "BSTask packed priority read", 12, 30)
print_instruction_window(0x0043CC80, "BSTask packed priority byte wrapper", 12, 30)
print_instruction_window(0x0043CCA0, "BSTask packed priority shift helper", 12, 30)
print_instruction_window(0x00C3D440, "BSTask packed queue key builder", 18, 90)
print_instruction_window(0x00C3DF40, "IOManager queued task priority update", 12, 50)

audit_function(0x006F6D10, "Object LOD task producer")
audit_function(0x006F6FE0, "Object LOD task constructor")
audit_function(0x006F9360, "Tree LOD task producer")
audit_function(0x006F94A0, "Tree LOD task constructor")
audit_function(0x006FB980, "Terrain LOD task producer")
audit_function(0x006FBB10, "Terrain LOD task constructor")
audit_function(0x0043BD10, "Dependency task constructor A")
audit_function(0x0043BE60, "Dependency task constructor B")
audit_function(0x0043BEF0, "Cached dependency task constructor")
audit_function(0x00C3CE60, "IOTask base constructor with inherited key")

write("")
write("# GENERIC LOCK-FREE MAP TLS CAPACITY")

audit_function(0x00449090, "LockFreeMap base constructor candidate")
audit_function(0x0044C270, "LockFreeMap constructor")
audit_function(0x0044CB70, "LockFreeMap destructor")
audit_function(0x0044CD00, "LockFreeMap TLS value constructor")
audit_function(0x0044D5B0, "LockFreeMap current thread TLS lookup")
audit_function(0x0044D5C0, "LockFreeMap TLS lookup with allocation")
audit_function(0x0044E340, "LockFreeMap TLS registration")
audit_function(0x0044E3A0, "LockFreeMap TLS slot allocation and capacity gate")
decompile_direct_callees(0x0044C270, "LockFreeMap constructor", 40)
decompile_callers(0x0044C270, "LockFreeMap constructor", 80)
decompile_callers(0x00449090, "LockFreeMap base constructor candidate", 80)
print_reference_windows(0x0044C270, "LockFreeMap constructor", 80, 18, 42)
print_reference_windows(0x0044E3A0, "LockFreeMap TLS capacity gate", 16, 18, 50)

write("")
write("# IO MANAGER SPECIALIZATION AND FAILED CALLER FAMILIES")

audit_function(0x00C3EC80, "IOManager LockFreeMap constructor specialization")
audit_function(0x00C3E4F0, "BSTaskManager constructor deriving TLS slots from worker count")
audit_function(0x00C3DA50, "IOManager constructor worker count")
decompile_direct_callees(0x00C3EC80, "IOManager LockFreeMap constructor specialization", 40)
print_reference_windows(0x00C3EC80, "IOManager LockFreeMap constructor specialization", 20, 18, 50)

audit_function(0x00449F80, "LockFreeMap public TLS getter")
decompile_callers(0x00449F80, "LockFreeMap public TLS getter", 80)
print_data_ref_neighborhoods(0x00449530, "Known crashing LockFreeMap consumer method", 18, 12)
print_data_ref_neighborhoods(0x00449580, "Adjacent LockFreeMap consumer method", 18, 12)
print_data_ref_neighborhoods(0x004495D0, "Adjacent LockFreeMap consumer method", 18, 12)
print_data_ref_neighborhoods(0x004498B0, "Second known null consumer wrapper", 18, 12)

write("")
write("END OF AUDIT")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/lod_streaming_multiworker_tls_capacity_final_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
