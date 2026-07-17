# @category Analysis
# @description Resolve IO task state transitions, mode-counter decrements, completion publication, and cancellation balance

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()
memory = currentProgram.getMemory()
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
		if len(code) > max_len:
			write("  [decompile truncated at %d chars, total %d]" % (max_len, len(code)))
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
		if count > 240:
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
	inst_iter = listing.getInstructions(func.getBody(), True)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				target_func = fm.getFunctionAt(toAddr(target))
				name = target_func.getName() if target_func else "???"
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), target, name))
				count += 1
	write("  Total: %d calls" % count)

def audit(addr_int, label, max_len=100000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def dump_pointer_table(addr_int, count, label):
	write("")
	write("=" * 70)
	write("POINTER TABLE: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	index = 0
	while index < count:
		slot = addr_int + index * 4
		try:
			value = memory.getInt(toAddr(slot)) & 0xffffffff
		except:
			write("  [%02d] +0x%02x [unreadable]" % (index, index * 4))
			index += 1
			continue
		func = fm.getFunctionAt(toAddr(value))
		name = func.getName() if func else "???"
		write("  [%02d] +0x%02x -> 0x%08x %s" % (index, index * 4, value, name))
		index += 1

write("IO TASK COUNTER BALANCE AUDIT")
write("")
write("Goal:")
write("  Prove one accepted-task increment has exactly one balancing decrement")
write("  across processing, completion, cancellation, mode transition, and destruction.")

audit(0x00C3FB50, "accepted task enqueue and mode-counter increment", 120000)
audit(0x00C3DE80, "IOManager completion accounting override", 140000)
audit(0x00C3FC80, "worker processing dispatch", 60000)
audit(0x00C3FCA0, "worker finalization dispatch", 60000)
audit(0x00C410B0, "BSTaskManagerThread worker loop", 160000)
audit(0x00C3FCE0, "synchronous task drain or cancellation owner", 160000)
audit(0x00C3D4F0, "IO task queue ownership helper", 120000)
audit(0x00C3D5E0, "IO task queue cancellation helper", 120000)

audit(0x00441800, "QueuedCharacter worker process", 80000)
audit(0x00441820, "QueuedCharacter completion or finalizer", 120000)
audit(0x00441C30, "QueuedPlayer worker process", 120000)
audit(0x00441E40, "queued-file worker process", 120000)
audit(0x0043DAA0, "queued-file completion method", 100000)
audit(0x00441E10, "queued-file completion publication", 60000)
audit(0x00C3CB70, "generic IO task completion method", 140000)
audit(0x00C3D440, "generic IO task mode method", 100000)
audit(0x00C3CAE0, "generic IO task queue method", 100000)
audit(0x00C3C930, "generic IO task fallback publication", 140000)

audit(0x00C3C620, "IO task base constructor", 100000)
audit(0x00C3C700, "IO task base copy or cancellation", 100000)
audit(0x00C3C7E0, "IO task base state owner", 100000)
audit(0x00C3EA60, "manager queue transition and release", 140000)

dump_pointer_table(0x010C1604, 28, "IOManager vtable")
dump_pointer_table(0x010C167C, 28, "BSTaskManager vtable")
dump_pointer_table(0x01016CEC, 12, "QueuedCharacter vtable")
dump_pointer_table(0x01016D7C, 12, "QueuedPlayer vtable")
dump_pointer_table(0x01016DC4, 12, "queued-file vtable A")
dump_pointer_table(0x01016E1C, 12, "queued-file vtable B")

find_refs_to(0x00C3FB50, "accepted-task enqueue")
find_refs_to(0x00C3DE80, "completion accounting override")
find_refs_to(0x00C3FC80, "worker process dispatch")
find_refs_to(0x00C3FCA0, "worker finalization dispatch")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/io_task_counter_balance_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
