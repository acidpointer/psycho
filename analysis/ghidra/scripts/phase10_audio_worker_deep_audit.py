# @category Analysis
# @description Deep audit of Phase 10 audio/focus worker responsible for recurring stutter

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

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

def decompile_at(addr_int, label, max_len=22000):
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
			write("  [decompile truncated at %d chars, total %d]" % (max_len, len(code)))
	else:
		write("  [decompilation failed]")

def find_refs_to(addr_int, label, limit=220):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), name_for_func(from_func)))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def find_and_print_calls_from(addr_int, label, limit=260):
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
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name_for_func(func_for(tgt))))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def collect_call_targets(addr_int, limit=260):
	func = func_for(addr_int)
	targets = {}
	if func is None:
		return targets
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				targets[tgt] = func_for(tgt)
				count += 1
				if count >= limit:
					return targets
	return targets

def decompile_call_targets(addr_int, label, max_funcs=80):
	write("")
	write("=" * 70)
	write("Immediate call target decompile: %s" % label)
	write("=" * 70)
	targets = collect_call_targets(addr_int, 260)
	keys = sorted(targets.keys())
	printed = 0
	for key in keys:
		decompile_at(key, "callee from %s" % label, 14000)
		find_and_print_calls_from(key, "callee from %s" % label, 120)
		printed += 1
		if printed >= max_funcs:
			write("  [callee decompile truncated at %d functions]" % max_funcs)
			break
	write("  Unique callees printed: %d" % printed)

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly: %s around 0x%08x" % (label, center_int))
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
		off = inst.getAddress().getOffset()
		marker = " << target" if off == center_int else ""
		write("  0x%08x: %-58s%s" % (off, inst.toString(), marker))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (tgt, name_for_func(func_for(tgt))))
		inst = inst.getNext()
		idx += 1

def scan_function_text(addr_int, terms, label, limit=260):
	func = func_for(addr_int)
	write("")
	write("=" * 70)
	write("Instruction text scan: %s" % label)
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		hit = None
		for term in terms:
			if term in text:
				hit = term
				break
		if hit is not None:
			write("  hit=%-12s 0x%08x %s" % (hit, inst.getAddress().getOffset(), inst.toString()))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				break
	write("  Total printed: %d" % count)

def audit_known_targets():
	targets = [
		(0x00832ad0, "Phase 10 audio gate FUN_00832ad0"),
		(0x00833d00, "Phase 10 audio/focus worker FUN_00833d00"),
		(0x008324e0, "Havok stop/start FUN_008324e0"),
		(0x00453a70, "Focus manager accessor FUN_00453a70"),
		(0x008329a0, "Audio/focus side-effect helper FUN_008329a0"),
	]
	for item in targets:
		decompile_at(item[0], item[1], 42000)
		find_and_print_calls_from(item[0], item[1], 260)
		find_refs_to(item[0], item[1], 260)

def audit_worker_hot_points():
	disasm_window(0x00833e37, 18, 24, "FUN_00833d00 focus accessor call A")
	disasm_window(0x00834112, 18, 24, "FUN_00833d00 focus accessor call B")
	disasm_window(0x00834176, 18, 24, "FUN_00833d00 HavokStopStart call")
	disasm_window(0x008341d7, 18, 24, "FUN_00833d00 linked-list helper call")
	terms = ["011dd", "011de", "011f", "120", "amlradio", "sleep", "wait", "lock", "critical", "semaphore"]
	scan_function_text(0x00833d00, terms, "FUN_00833d00 globals/wait/lock scan", 320)
	decompile_call_targets(0x00833d00, "FUN_00833d00", 80)

def main():
	write("Phase 10 audio worker deep audit")
	write("")
	write("Goal:")
	write("  Explain the Capital Wasteland recurring stutter narrowed by runtime logs:")
	write("  10pre -> pre32/FUN_00832ad0 -> pre33/FUN_00833d00.")
	write("  Runtime hSS stayed zero in gameplay, so this script maps what else")
	write("  inside FUN_00833d00 can take ~47-51 ms without guessing.")
	audit_known_targets()
	audit_worker_hot_points()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/phase10_audio_worker_deep_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
