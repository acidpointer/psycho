# @category Analysis
# @description Resolve FalloutNV save-time task quiescence, change-map locking, saving-flag consumers, and mutable object ownership

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
		if count > 160:
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
		lower = inst.toString().lower()
		if "lock" not in lower and "cmpxchg" not in lower and "xchg" not in lower:
			continue
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		count += 1
	write("  Total synchronization-looking instructions: %d" % count)

def disasm_range(start_int, end_int, label):
	write("")
	write("-" * 70)
	write("Disassembly: %s (0x%08x - 0x%08x)" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	while inst is not None and inst.getAddress().getOffset() <= end_int:
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()

def audit_function(addr_int, label, max_len=20000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)
	scan_function_for_sync(addr_int, label)

def audit_targets():
	targets = [
		(0x00850BA0, "pre-save phase transition", 18000),
		(0x00850BF0, "post-save phase transition", 18000),
		(0x00C3E340, "post-save task call A", 22000),
		(0x0047D0B0, "post-save task call B", 22000),
		(0x006EBCD0, "post-save task call C", 22000),
		(0x004623F0, "CleanupExpiredData save-scope state toggle", 18000),
		(0x00438AF0, "CleanupExpiredData final queue or lock action", 20000),
		(0x0084B4E0, "CleanupExpiredData setup", 20000),
		(0x00845880, "SafeRWList constructor used by change map", 22000),
		(0x00844700, "change-map list insertion", 26000),
		(0x00841100, "change-map state mutation", 24000),
		(0x009A4250, "change-map lookup", 22000),
		(0x00559450, "change-map traversal state accessor", 18000),
		(0x00562210, "change-map traversal state mutation", 18000),
		(0x00845690, "change-map removal or flag mutation", 22000),
		(0x00405430, "change-map element cleanup", 22000),
		(0x00562140, "saving-state query consumer A", 18000),
		(0x00875FD0, "saving-state query consumer B", 26000),
	]
	for item in targets:
		audit_function(item[0], item[1], item[2])

def audit_callsites():
	disasm_range(0x008504D0, 0x008505C8, "pre-save cleanup through serializer entry")
	disasm_range(0x00847870, 0x00847BB0, "save traversal map ownership and virtual dispatch")
	disasm_range(0x008457B0, 0x00845880, "change-map mutation and SafeRWList allocation")
	disasm_range(0x00850B80, 0x00850C20, "pre-save and post-save phase helpers")

def main():
	write("=" * 70)
	write("SAVE SNAPSHOT LOCK OWNERSHIP FOLLOW-UP")
	write("=" * 70)
	write("Questions: whether workers are quiesced before traversal, whether the change map is locked, and which subsystems honor the saving flag.")
	audit_targets()
	audit_callsites()
	find_refs_to(0x011DDF38, "BGSSaveLoadGame singleton")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/save_snapshot_lock_ownership_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
