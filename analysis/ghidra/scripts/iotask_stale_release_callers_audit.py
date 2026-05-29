# @category Analysis
# @description Audit IOTask release, smart-pointer wrappers, and callers that can retain stale 80-byte task pointers

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

def label_for_addr(addr_int):
	func = func_for(addr_int)
	if func is None:
		return "0x%08x ???" % addr_int
	return "0x%08x %s" % (addr_int, name_for_func(func))

def decompile_at(addr_int, label, max_len=9000):
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

def find_refs_to(addr_int, label, limit=100):
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

def find_and_print_calls_from(addr_int, label, limit=160):
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
				write("  0x%08x -> %s" % (inst.getAddress().getOffset(), label_for_addr(tgt)))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def disasm_window(start_int, length, label, highlights, max_inst=120):
	end_int = start_int + length
	write("")
	write("-" * 70)
	write("Disassembly: %s 0x%08x..0x%08x" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	count = 0
	while inst is not None and inst.getAddress().getOffset() < end_int:
		off = inst.getAddress().getOffset()
		mark = "   "
		for item in highlights:
			if off == item:
				mark = "=> "
		write("%s0x%08x: %s" % (mark, off, inst.toString()))
		inst = inst.getNext()
		count += 1
		if count >= max_inst:
			write("  ... (truncated at %d instructions)" % max_inst)
			break
	write("  Instructions printed: %d" % count)

def print_refs_with_context(addr_int, label, before=0x35, after=0x75, limit=35):
	write("")
	write("-" * 70)
	write("References with compact context TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	highlights = [addr_int, 0x0044dd60, 0x0044cbf0, 0x006f74f0, 0x00559450, 0x00528cb0, 0x00444957, 0x00444961]
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		from_addr = ref.getFromAddress().getOffset()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("")
		write("  REF %d: %s from 0x%08x in %s" % (count + 1, ref.getReferenceType(), from_addr, name_for_func(from_func)))
		disasm_window(from_addr - before, before + after, "xref context for 0x%08x" % from_addr, highlights, 100)
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Context refs printed: %d" % count)

def scan_function_for_text(addr_int, label, needles, limit=120):
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

def audit_function(item):
	addr = item[0]
	label = item[1]
	max_len = item[2]
	decompile_at(addr, label, max_len)
	find_and_print_calls_from(addr, label, 180)
	scan_function_for_text(addr, label, ["0044dd60", "0044cbf0", "006f74f0", "00559450", "00528cb0", "0x8", "0x1c", "0x20", "0x24", "0x40", "0x48", "0x50"], 130)

def audit_functions(items):
	for item in items:
		audit_function(item)

def main():
	functions = [
		(0x00444850, "CreateQueuedCharacter: crash owner and local task holder", 22000),
		(0x0044cbf0, "task holder release wrapper, releases *holder via IOTask_Release", 8000),
		(0x0044dd60, "IOTask_Release: decrement +8 then vtable[0](1)", 8000),
		(0x006f74f0, "task holder assignment helper", 11000),
		(0x00559450, "task holder get helper", 8000),
		(0x00528cb0, "task holder init helper", 8000),
		(0x00c3dbf0, "IOManager_Process: releases queued tasks", 13000),
		(0x00c3e1b0, "IO task queue helper with release calls", 12000),
		(0x00c3ea60, "IO task queue helper with release calls", 12000),
		(0x00c42b80, "BSTaskManagerThread cleanup", 13000),
		(0x00c42560, "task manager release-heavy helper", 12000)
	]
	write("=" * 70)
	write("IOTASK STALE RELEASE CALLERS AUDIT")
	write("=" * 70)
	write("")
	write("Goal:")
	write("  The release guard prevented final-destructor UAF, but the same 80-byte free cell later crashed in CreateQueuedCharacter.")
	write("  This audits release/set/get wrappers and caller contexts to find where stale task pointers are retained.")
	find_refs_to(0x0044dd60, "IOTask_Release", 160)
	find_refs_to(0x0044cbf0, "task holder release wrapper", 120)
	find_refs_to(0x006f74f0, "task holder assignment helper", 120)
	find_refs_to(0x00559450, "task holder get helper", 120)
	print_refs_with_context(0x0044dd60, "IOTask_Release callers", 0x45, 0x85, 50)
	print_refs_with_context(0x0044cbf0, "task holder release wrapper callers", 0x45, 0x85, 45)
	print_refs_with_context(0x006f74f0, "task holder assignment helper callers", 0x45, 0x85, 45)
	disasm_window(0x00444920, 0x90, "exact CreateQueuedCharacter crash and cleanup window", [0x00444957, 0x00444961, 0x0044cbf0], 140)
	audit_functions(functions)
	write("")
	write("=" * 70)
	write("END IOTASK STALE RELEASE CALLERS AUDIT")
	write("=" * 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/iotask_stale_release_callers_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
