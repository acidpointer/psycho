# @category Analysis
# @description Proves the native IO task priority key range, shard mapping, insertion order, and worker dequeue boundary for the missing distant LOD regression.

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

def print_instructions(addr_int, label, max_count=300):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("=" * 70)
	write("Full instructions for %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext() and count < max_count:
		inst = inst_iter.next()
		write("  0x%08x  %s" % (inst.getAddress().getOffset(), inst.toString()))
		count += 1
	write("  Total printed: %d" % count)

def print_pointer_table(addr_int, count, label):
	write("")
	write("=" * 70)
	write("Pointer table %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	index = 0
	while index < count:
		entry_addr = toAddr(addr_int + index * 4)
		data = listing.getDataAt(entry_addr)
		value = None
		if data is not None:
			value = data.getValue()
		if value is not None and hasattr(value, "getOffset"):
			target = value.getOffset()
		else:
			mem = currentProgram.getMemory()
			try:
				target = mem.getInt(entry_addr) & 0xffffffff
			except:
				target = 0
		func = fm.getFunctionAt(toAddr(target))
		name = func.getName() if func else "???"
		write("  [%02d] +0x%02x -> 0x%08x %s" % (index, index * 4, target, name))
		index += 1

def audit_function(addr_int, label, max_len=8000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

write("LOD PRIORITY QUEUE BOUNDARY FINAL AUDIT")
write("Program: %s" % currentProgram.getName())
write("Image base: %s" % currentProgram.getImageBase())
write("")
write("Goal: prove whether priority 255 is a valid high-priority value or an out-of-range queue key that cannot service distant LOD")

write("")
write("# PACKED KEY CONSTRUCTION AND LEGAL PRIORITY DOMAIN")
audit_function(0x0043CCA0, "Packed priority-byte getter")
audit_function(0x0043C030, "Dynamic archive priority contribution")
audit_function(0x0043DB70, "Native task key initializer")
audit_function(0x0043DBB0, "Packed task key writer")
audit_function(0x00C3D440, "IO task packed key constructor")
audit_function(0x00C3DE80, "IO task submission and state clamp")
audit_function(0x00C3DF40, "Runtime priority field replacement")
audit_function(0x00C3E690, "Runtime remove and requeue")
print_instructions(0x0043DBB0, "Packed task key writer")
print_instructions(0x00C3D440, "IO task packed key constructor")
print_instructions(0x00C3DE80, "IO task submission and state clamp")
print_instructions(0x00C3DF40, "Runtime priority field replacement")

write("")
write("# MANAGER VTABLE AND PRIORITY SHARD MAPPING")
print_pointer_table(0x010C167C, 28, "BSTaskManager vtable")
audit_function(0x00C3EC80, "Task queue base constructor", 12000)
audit_function(0x00C3E4F0, "Task manager constructor", 12000)
audit_function(0x00C3F650, "Packed key to queue shard mapping")
audit_function(0x00C3F670, "Packed key helper A")
audit_function(0x00C3F690, "Packed key helper B")
audit_function(0x00C3F6B0, "Packed key helper C")
audit_function(0x008D0560, "Accepted task queue value mapping")
audit_function(0x00C3E860, "Pending count below load-state boundary", 12000)
audit_function(0x00C3E1B0, "Blocking-load queue boundary owner", 12000)

write("")
write("# INSERTION, ORDERING, AND WORKER DEQUEUE")
audit_function(0x00C3FB50, "Accepted task insertion owner", 12000)
audit_function(0x00C3F1F0, "Pending ordered queue insertion")
audit_function(0x00C3FFB0, "Pending ordered queue insertion core", 12000)
audit_function(0x00C3F750, "Worker TLS queue accessor")
audit_function(0x00C40E70, "Worker shard traversal and pop", 16000)
audit_function(0x00C42380, "First task pop from shard", 14000)
audit_function(0x00C42560, "Subsequent ordered task pop", 18000)
audit_function(0x00C416A0, "Ordered task iterator comparison", 16000)
print_instructions(0x00C3F650, "Packed key to queue shard mapping")
print_instructions(0x00C3F1F0, "Pending ordered queue insertion")
print_instructions(0x00C3FFB0, "Pending ordered queue insertion core")
print_instructions(0x00C416A0, "Ordered task iterator comparison")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/lod_priority_queue_boundary_final_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
