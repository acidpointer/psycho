# @category Analysis
# @description Audit AI-thread Havok call path for world-lock/loading-state synchronization

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

HKWORLD_LOCK = 0x00C3E310
HKWORLD_UNLOCK = 0x00C3E340
LOADING_STATE_COUNTER = 0x01202D6C

def write(msg):
	output.append(msg)
	print(msg)

def func_for(addr_int):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	return func

def name_for_func(func):
	if func is None:
		return "???"
	return "%s @ 0x%08x" % (func.getName(), func.getEntryPoint().getOffset())

def decompile_at(addr_int, label, max_len=16000):
	addr = toAddr(addr_int)
	func = func_for(addr_int)
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
			write("  [decompile truncated at %d chars]" % max_len)
	else:
		write("  [decompilation failed]")

def find_refs_to(addr_int, label, limit=180):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		faddr = from_func.getEntryPoint().getOffset() if from_func else 0
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s @ 0x%08x)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, faddr))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def find_refs_into_function(addr_int, label, limit=180):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("References INTO function containing 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	body = func.getBody()
	addr_iter = body.getAddresses(True)
	count = 0
	while addr_iter.hasNext():
		addr = addr_iter.next()
		refs = ref_mgr.getReferencesTo(addr)
		while refs.hasNext():
			ref = refs.next()
			from_func = fm.getFunctionContaining(ref.getFromAddress())
			if from_func is not None and from_func.getEntryPoint() == func.getEntryPoint():
				continue
			write("  target=0x%08x %s from 0x%08x in %s" % (addr.getOffset(), ref.getReferenceType(), ref.getFromAddress().getOffset(), name_for_func(from_func)))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				write("  Total printed: %d" % count)
				return
	write("  Total printed: %d" % count)

def find_and_print_calls_from(addr_int, label, limit=220):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Calls FROM %s (0x%08x)" % (label, addr_int))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				if tgt_func is None:
					tgt_func = fm.getFunctionContaining(toAddr(tgt))
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name_for_func(tgt_func)))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def scan_function_for_targets(addr_int, label, targets):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Target scan: %s" % label)
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			tgt = ref.getToAddress().getOffset()
			idx = 0
			while idx < len(targets):
				item = targets[idx]
				if tgt == item[0]:
					write("  0x%08x -> 0x%08x %s via %s" % (inst.getAddress().getOffset(), tgt, item[1], ref.getReferenceType()))
					count += 1
				idx += 1
	write("  Total target refs in function: %d" % count)

def scan_function_for_text(addr_int, label, needles, limit=180):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Instruction text scan: %s" % label)
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		matched = False
		for needle in needles:
			if needle.lower() in text:
				matched = True
		if matched:
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				break
	write("  Total matches: %d" % count)

def audit_function(addr_int, label, max_len=16000):
	decompile_at(addr_int, label, max_len)
	find_refs_into_function(addr_int, label)
	find_and_print_calls_from(addr_int, label)
	scan_function_for_targets(addr_int, label, [(HKWORLD_LOCK, "hkWorld_Lock"), (HKWORLD_UNLOCK, "hkWorld_Unlock"), (LOADING_STATE_COUNTER, "LOADING_STATE_COUNTER")])
	scan_function_for_text(addr_int, "%s synchronization-like instructions" % label, ["lock", "unlock", "01202d6c", "1202d6c", "c3e310", "c3e340"])

def audit_calltrace():
	addrs = [
		(0x00C6757A, "Crash EIP / Havok object consumer"),
		(0x00C6AECF, "AI-thread Havok caller 1"),
		(0x004BA9B5, "AI-thread caller 2"),
		(0x00453624, "AI-thread caller 3"),
		(0x008C8042, "AI-thread task runner 1"),
		(0x008C71A8, "AI-thread task runner 2"),
		(0x008C7764, "AI-thread task runner 3"),
		(0x00AA64E0, "thread entry wrapper"),
	]
	idx = 0
	while idx < len(addrs):
		item = addrs[idx]
		audit_function(item[0], item[1], 18000)
		idx += 1

def main():
	write("=" * 70)
	write("HAVOK AI THREAD SYNCHRONIZATION AUDIT")
	write("=" * 70)
	write("")
	write("Question:")
	write("  The stress crash happened on AI Linear Task Thread 2 inside Havok.")
	write("  This script checks whether that call path has direct world-lock or")
	write("  loading-state gating, and identifies where such gating could be added")
	write("  if the path is unsynchronized.")
	write("")
	write("# SECTION 1: known synchronization anchors")
	find_refs_to(HKWORLD_LOCK, "hkWorld_Lock")
	find_refs_to(HKWORLD_UNLOCK, "hkWorld_Unlock")
	find_refs_to(LOADING_STATE_COUNTER, "LOADING_STATE_COUNTER")
	write("")
	write("# SECTION 2: full crash calltrace audit")
	audit_calltrace()
	write("")
	write("# SECTION 3: known Havok sparse-result guard targets for comparison")
	audit_function(0x00C94BD0, "FUN_00C94BD0 addEntityBatch", 26000)
	audit_function(0x00CFFA00, "FUN_00CFFA00 entity post-add callback", 16000)
	audit_function(0x00CF7080, "FUN_00CF7080 narrowphase add-agent dispatcher", 22000)
	write("")
	write("=" * 70)
	write("END HAVOK AI THREAD SYNCHRONIZATION AUDIT")
	write("=" * 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/havok_ai_thread_sync_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
