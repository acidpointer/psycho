# @category Analysis
# @description Audit FalloutNV save snapshot ownership, task barriers, change-map mutation, and save/load phase synchronization

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
		if count > 140:
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

def scan_function_for_sync(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("-" * 70)
	write("Synchronization instructions in %s" % label)
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		lower = text.lower()
		if "lock" not in lower and "cmpxchg" not in lower and "xchg" not in lower and "critical" not in lower:
			continue
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), text))
		count += 1
	write("  Total synchronization-looking instructions: %d" % count)

def audit_function(addr_int, label, max_len=20000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)
	scan_function_for_sync(addr_int, label)

def audit_targets():
	targets = [
		(0x008503B0, "SaveGameManager save orchestration", 28000),
		(0x00847850, "BGSSaveLoadGame SaveGame snapshot traversal", 34000),
		(0x00847D00, "saving-state publication", 16000),
		(0x0084AB20, "CleanupExpiredData before save", 36000),
		(0x00850BF0, "save-side task/model barrier", 16000),
		(0x0084EB80, "changed form save dispatch setup", 18000),
		(0x008457B0, "change-map mutation during save", 18000),
		(0x00845A80, "change-map lookup/filter during save", 18000),
		(0x006B7F20, "change-map iterator", 18000),
		(0x004B9BA0, "change-map iteration begin", 14000),
		(0x00847DF0, "BGSSaveLoadGame LoadGame phase owner", 36000),
		(0x0086E650, "main-loop loading state owner", 36000),
	]
	for item in targets:
		audit_function(item[0], item[1], item[2])

def audit_globals():
	find_refs_to(0x011DDF38, "BGSSaveLoadGame singleton")
	find_refs_to(0x011DE134, "SaveGameManager singleton")
	find_refs_to(0x011DEA2B, "engine loading flag")
	find_refs_to(0x011C54CC, "shared save record buffer")
	find_refs_to(0x011C54D0, "shared save record size")

def main():
	write("=" * 70)
	write("SAVE SNAPSHOT AND THREAD CONTRACT AUDIT")
	write("=" * 70)
	write("Questions: what is stopped before serialization, which maps remain mutable, and can worker-owned objects change mid-save?")
	audit_targets()
	audit_globals()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/save_snapshot_thread_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
