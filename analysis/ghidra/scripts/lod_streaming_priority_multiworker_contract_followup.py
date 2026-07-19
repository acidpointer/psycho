# @category Analysis
# @description Audit FNV LOD task priority ABI and the completion/TLS contract blocking safe multi-worker streaming

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

def decompile_once(addr_int, label, max_len=8000):
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

def print_instruction_window(addr_int, label, before=12, after=20):
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

def print_reference_windows(addr_int, label, limit=40, before=10, after=18):
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

def print_vtable(base_int, label, slots=24):
	write("")
	write("=" * 70)
	write("Vtable %s @ 0x%08x" % (label, base_int))
	write("=" * 70)
	index = 0
	while index < slots:
		value = read_u32(base_int + index * 4)
		if value is None:
			write("  slot %02d +0x%02x: [unreadable]" % (index, index * 4))
		else:
			func = fm.getFunctionAt(toAddr(value))
			name = func.getName() if func else "???"
			write("  slot %02d +0x%02x -> 0x%08x %s" % (index, index * 4, value, name))
		index += 1

def audit_task_vtables_from_slot6(slot6_target, limit=80):
	write("")
	write("=" * 70)
	write("Task vtables whose slot 6 targets 0x%08x" % slot6_target)
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(slot6_target))
	bases = []
	priorities = []
	count = 0
	while refs.hasNext() and count < limit:
		ref = refs.next()
		from_addr = ref.getFromAddress()
		if listing.getInstructionContaining(from_addr) is None:
			base_int = from_addr.getOffset() - 0x18
			priority = read_u32(base_int + 0x2c)
			write("  slot6 ref 0x%08x -> vtable 0x%08x, slot11=%s" % (from_addr.getOffset(), base_int, str(priority)))
			bases.append(base_int)
			if priority is not None:
				priorities.append(priority)
			count += 1
	index = 0
	while index < len(bases):
		print_vtable(bases[index], "BSTask-derived candidate", 16)
		index += 1
	index = 0
	while index < len(priorities):
		decompile_once(priorities[index], "task slot11 priority", 8000)
		index += 1

def audit_function(addr_int, label):
	decompile_once(addr_int, label, 12000)
	find_and_print_calls_from(addr_int, label)
	find_refs_to(addr_int, label)

write("LOD STREAMING PRIORITY AND MULTI-WORKER CONTRACT FOLLOW-UP")
write("Program: %s" % currentProgram.getName())
write("Image base: %s" % currentProgram.getImageBase())
write("")
write("# PRIORITY ABI AND CLASS RANGE")

audit_function(0x0043CCA0, "BSTask priority getter")
audit_function(0x0043CC80, "BSTask priority getter wrapper")
audit_function(0x00440540, "Task priority related helper")
audit_function(0x0043DB70, "Task submit or priority init")
audit_function(0x0043DBB0, "Task priority init helper 1")
audit_function(0x0043DC10, "Task priority init helper 2")
audit_function(0x0043DC30, "Task priority init helper 3")
audit_function(0x00C3D440, "BSTask build packed queue key")
audit_function(0x00C3DF40, "BSTaskManager change priority")
audit_function(0x00C3CAE0, "Priority change known caller")
audit_function(0x00C3E690, "BSTaskManager remove and requeue")
print_instruction_window(0x00C3DF40, "BSTaskManager change priority entry", 8, 40)
print_reference_windows(0x00C3DF40, "BSTaskManager change priority", 32, 10, 24)
audit_task_vtables_from_slot6(0x00C3D440, 80)
print_vtable(0x01016788, "Dependency task candidate", 20)
print_vtable(0x0106DC3C, "Object LOD block task", 20)
print_vtable(0x0106DED0, "Tree LOD block task", 20)
print_vtable(0x0106E1DC, "Terrain LOD block task", 20)

write("")
write("# MULTI-WORKER CREATION, TLS, COMPLETION, AND NULLABILITY")

audit_function(0x00C3DA50, "IOManager constructor with one worker")
audit_function(0x00C3E4F0, "BSTaskManager constructor worker count")
audit_function(0x00C3EE70, "BSTaskManagerThread constructor")
audit_function(0x00C42DD0, "BSThread start")
audit_function(0x00C42DA0, "BSThread entry")
audit_function(0x00C410B0, "BSTaskManagerThread worker loop")
audit_function(0x00C3E3A0, "Task manager thread index or hash")
audit_function(0x00C3F750, "Task TLS accessor")
audit_function(0x00C3F7A0, "Task TLS queue accessor")
audit_function(0x00C3F530, "Completion queue handle acquire")
audit_function(0x00C3E8B0, "Completion pool constructor")
audit_function(0x00C3EEB0, "Completion pool entry constructor")
audit_function(0x00449F80, "Completion queue public getter")
audit_function(0x0044D5C0, "Completion queue lookup")
audit_function(0x0044D5B0, "Completion queue adjacent lookup")
audit_function(0x0044E3A0, "Completion queue or TLS owner")
audit_function(0x00449530, "Known crash wrapper")
audit_function(0x006EC830, "Known null consumer")
audit_function(0x006EC9B0, "Known null consumer adjacent")
print_reference_windows(0x00449F80, "Completion queue public getter", 80, 14, 30)
print_reference_windows(0x0044D5C0, "Completion queue lookup", 80, 14, 30)
print_reference_windows(0x006EC830, "Known null consumer", 80, 14, 30)
print_vtable(0x010C167C, "BSTaskManager", 28)
print_vtable(0x010C1740, "BSTaskManagerThread", 20)
print_vtable(0x010C16DC, "Completion pool candidate", 20)

write("")
write("END OF AUDIT")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/lod_streaming_priority_multiworker_contract_followup.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
