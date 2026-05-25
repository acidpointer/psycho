# @category Analysis
# @description Deep audit of FNV startup/save loading pipeline, IO queues, and completion contracts

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
		if count > 80:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	write("")
	write("-" * 70)
	write("Calls FROM 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	addr_iter = func.getBody().getAddresses(True)
	count = 0
	while addr_iter.hasNext():
		a = addr_iter.next()
		inst = listing.getInstructionAt(a)
		if inst is None:
			continue
		if not inst.getFlowType().isCall():
			continue
		refs_from = inst.getReferencesFrom()
		for ref in refs_from:
			target = ref.getToAddress().getOffset()
			target_func = fm.getFunctionAt(toAddr(target))
			target_name = target_func.getName() if target_func else "unknown_0x%08x" % target
			write("  CALL 0x%08x -> %s (from 0x%08x)" % (target, target_name, a.getOffset()))
			count += 1
	write("  Total: %d calls" % count)

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionBefore(toAddr(center_int))
	count = 0
	while inst is not None and count < before_count:
		prev = inst.getPrevious()
		if prev is None:
			break
		inst = prev
		count += 1
	idx = 0
	limit = before_count + after_count + 1
	while inst is not None and idx < limit:
		marker = " << TARGET" if inst.getAddress().getOffset() == center_int else ""
		write("  0x%08x: %-38s%s" % (inst.getAddress().getOffset(), inst.toString(), marker))
		inst = inst.getNext()
		idx += 1

def read_vtable(addr_int, label, count):
	write("")
	write("-" * 70)
	write("VTable/dispatch table %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	for idx in range(count):
		slot_addr = addr_int + idx * 4
		try:
			target = getInt(toAddr(slot_addr)) & 0xffffffff
		except:
			write("  [%02d] +0x%02x: <read failed>" % (idx, idx * 4))
			continue
		target_func = fm.getFunctionAt(toAddr(target))
		name = target_func.getName() if target_func else "unknown"
		write("  [%02d] +0x%02x: 0x%08x -> %s" % (idx, idx * 4, target, name))

def scan_callers_to(addr_int, label):
	write("")
	write("=" * 70)
	write("CALLER SCAN: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_addr = ref.getFromAddress()
		from_func = fm.getFunctionContaining(from_addr)
		fname = from_func.getName() if from_func else "???"
		write("")
		write("Caller %d: %s @ 0x%08x in %s" % (count + 1, ref.getReferenceType(), from_addr.getOffset(), fname))
		disasm_window(from_addr.getOffset(), 8, 16, "caller of %s" % label)
		if from_func is not None:
			decompile_at(from_func.getEntryPoint().getOffset(), "Caller function %s" % fname, 5000)
		count += 1
		if count >= 30:
			write("  ... caller scan truncated")
			break
	write("Total callers printed: %d" % count)

def print_patch_bytes():
	write("")
	write("=" * 70)
	write("KNOWN PATCH CANDIDATES AND RISK")
	write("=" * 70)
	disasm_window(0x00c3da7a, 5, 8, "IOManager worker count immediate")
	write("  Worker count patch 1->2 is unsafe from crash evidence: completion queue returned NULL.")
	disasm_window(0x00c3e105, 8, 16, "ModelLoader Sleep(50)")
	write("  Sleep patch only changes wait polling. Still needs isolated validation.")
	disasm_window(0x00c3dd0a, 8, 24, "Main-thread drain time budget source")
	write("  Main drain budget may be a safer target than worker count if it preserves single-worker ordering.")

def analyze_core_targets():
	targets = [
		(0x00c3da50, "IOManager constructor wrapper"),
		(0x00c3e4f0, "BSTaskManager constructor"),
		(0x00c3ee70, "BSTaskManagerThread constructor"),
		(0x00c42dd0, "BSTaskThread base constructor / CreateThread suspended"),
		(0x00c42f50, "BSTaskThread resume"),
		(0x00c410b0, "BSTaskManagerThread worker loop"),
		(0x00c40e70, "Worker dequeue/select task"),
		(0x00c3dbf0, "Main-thread completed task drain"),
		(0x00c3dfa0, "ModelLoader wait/drain loop"),
		(0x00c3e1b0, "ModelLoader batch enqueue/start"),
		(0x00c3e420, "Completed-task pop/dequeue helper"),
		(0x00c3e860, "Pending/expected task count helper"),
		(0x00c3ec80, "Task queue container constructor"),
		(0x00c3f7a0, "IOTask submit/TLS queue helper"),
		(0x00449f80, "IOManager get completion queue"),
		(0x0044d5c0, "Completion queue dequeue/get"),
		(0x00c3ea60, "Lock-free completion queue pop"),
		(0x00c3f090, "Completion node recycle/free"),
		(0x00449280, "Completion wrapper 1"),
		(0x00449530, "Completion wrapper 2 / crash caller"),
		(0x00449580, "Completion wrapper 3"),
		(0x004495d0, "Completion wrapper 4"),
		(0x006ec830, "Crash callee requiring non-null queue object"),
		(0x00664f50, "BSTreeManager load/find tree"),
		(0x0050f810, "Tree load caller")
	]
	for item in targets:
		decompile_at(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])

def analyze_dispatch_tables():
	read_vtable(0x010c1604, "IOManager vtable", 28)
	read_vtable(0x010c167c, "BSTaskManager vtable", 28)
	read_vtable(0x010c1740, "BSTaskManagerThread vtable", 24)
	read_vtable(0x010c1844, "BSTaskThread base vtable", 16)
	read_vtable(0x010c1664, "Worker task iterator state A", 12)
	read_vtable(0x010c1670, "Worker task iterator state B", 12)
	read_vtable(0x01016788, "QueuedTexture vtable", 24)

def analyze_globals_and_refs():
	find_refs_to(0x01202dd8, "main-thread drain reentrancy flag")
	find_refs_to(0x011af70c, "ModelLoader loading-complete flag")
	find_refs_to(0x01202d98, "IOManager singleton")
	find_refs_to(0x011d5c48, "BSTreeManager singleton")
	find_refs_to(0x00449f80, "IOManager get completion queue")
	find_refs_to(0x00c3dbf0, "main-thread completed task drain")
	find_refs_to(0x00c3dfa0, "ModelLoader wait/drain loop")
	find_refs_to(0x00c410b0, "BSTaskManagerThread loop")

def analyze_completion_contract():
	scan_callers_to(0x00449f80, "IOManager get completion queue")
	scan_callers_to(0x00c3e420, "completed-task pop/dequeue helper")
	scan_callers_to(0x0044d5c0, "completion queue dequeue/get")

def main():
	write("=" * 70)
	write("STARTUP LOADING PIPELINE DEEP AUDIT")
	write("=" * 70)
	write("Crash lesson:")
	write("  More IO workers can make IOManager_GetCompletionQueue return NULL where callers assume non-null.")
	write("  This audit maps which waits are idle and which waits are ordering/synchronization contracts.")
	print_patch_bytes()
	analyze_core_targets()
	analyze_dispatch_tables()
	analyze_globals_and_refs()
	analyze_completion_contract()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/startup_loading_pipeline_deep_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
