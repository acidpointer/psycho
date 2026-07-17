# @category Analysis
# @description Resolve ModelLoader manager callbacks, pending-slot writers, queued-model vtables, and failure-path counter ownership

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

def audit(addr_int, label, max_len=80000):
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

def decompile_singleton_users(addr_int, label):
	write("")
	write("=" * 70)
	write("SINGLETON USERS: %s" % label)
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = {}
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		if entry in seen:
			continue
		seen[entry] = True
		decompile_at(entry, "singleton user %s" % func.getName(), 70000)
		find_and_print_calls_from(entry, "singleton user %s" % func.getName())
	write("  Unique singleton users: %d" % len(seen))

write("MODELLOADER PENDING OWNERSHIP AUDIT")
write("")
write("Goal:")
write("  Resolve the exact producer/decrement contract for the three pending")
write("  sources that hold FUN_00C3DFA0 mode 5, without assuming a timeout is safe.")

audit(0x0044FB20, "ModelLoader singleton construction or publication", 140000)
audit(0x00450770, "ModelLoader singleton replacement or teardown", 140000)
audit(0x00442650, "ModelLoader manager field user", 140000)
audit(0x00448420, "ModelLoader global lock and drain owner", 140000)
audit(0x00445570, "ModelLoader queue wrapper A", 100000)
audit(0x004454D0, "ModelLoader queue wrapper B", 100000)
audit(0x00445430, "ModelLoader queue wrapper C", 100000)

audit(0x00440A90, "queued model task execution core", 180000)
audit(0x00441780, "queued model task success continuation A", 100000)
audit(0x004418B0, "queued model task success continuation B", 100000)
audit(0x004417C0, "queued model task success continuation C", 100000)
audit(0x00449C30, "model task destructor body", 100000)
audit(0x00C3E420, "completed-task dequeue", 100000)
audit(0x00C40E70, "worker task dequeue and mode selection", 180000)
audit(0x00C42060, "mode queue range setup", 100000)
audit(0x00C3E7D0, "manager unlock predicate", 70000)

dump_pointer_table(0x01016D24, 40, "queued model task vtable A")
dump_pointer_table(0x01016DB4, 40, "queued model task vtable B")
dump_pointer_table(0x01017154, 40, "model task vtable")
find_refs_to(0x01016D24, "queued model task vtable A")
find_refs_to(0x01016DB4, "queued model task vtable B")
find_refs_to(0x01017154, "model task vtable")

decompile_singleton_users(0x01202D98, "ModelLoader manager")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/model_loader_pending_ownership_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
