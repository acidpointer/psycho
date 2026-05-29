# @category Analysis
# @description Audit LockFree map field contract around this+0x14 for crash 0x00559456

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

def decompile_at(addr_int, label, max_len=14000):
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
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), name_for_func(from_func)))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def find_and_print_calls_from(addr_int, label, limit=200):
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

def disasm_window(start_int, length, label, highlights, max_inst=160):
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

def scan_function_for_fields(addr_int, label, needles, limit=160):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Field/disasm scan: %s" % label)
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

def audit_function(addr_int, label):
	decompile_at(addr_int, label, 16000)
	find_and_print_calls_from(addr_int, label, 220)
	scan_function_for_fields(addr_int, label, ["+ 0x14", "+ 0x18", "+ 0x20", "[ecx + 0x14", "[eax + 0x14", "[edx + 0x14", "0044c480", "00559450", "00401030"], 180)

def audit_callers_to_clear():
	write("")
	write("=" * 70)
	write("CALLERS TO LOCKFREE MAP CLEAR 0x0044C480")
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(0x0044c480))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("  0x%08x -> 0x0044c480 from %s" % (ref.getFromAddress().getOffset(), name_for_func(from_func)))
		count += 1
	write("  Total callers printed: %d" % count)

def main():
	write("=" * 70)
	write("CRASH 0x00559456 LOCKFREE MAP FIELD CONTRACT AUDIT")
	write("=" * 70)
	write("")
	write("Crash mechanism:")
	write("  FUN_0044C480 tests this+0x14 for nonzero, then passes *(this+0x14) to FUN_00559450.")
	write("  In the crash, this is the freed 80-byte cell 0x34E798F0 and this+0x14 contains 1.")
	write("  The goal is to learn who initializes, clears, releases, and rebuilds this field.")
	disasm_window(0x0044c480, 0x1c0, "full map clear/reset body", [0x0044c4c8, 0x0044c4f2, 0x0044c4f5, 0x0044c52b, 0x0044c604], 180)
	audit_function(0x0044c480, "LockFree map clear/reset")
	audit_function(0x0044c040, "LockFree map constructor/init")
	audit_function(0x0044c1e0, "LockFree map destructor/finalize")
	audit_function(0x0044c270, "LockFree map constructor/init variant")
	audit_function(0x0044c3f0, "LockFree map clear/rebuild variant")
	audit_function(0x0044cae0, "LockFree map clear caller variant")
	audit_function(0x0044d7f0, "QueuedReference map constructor helper")
	audit_function(0x0044d8f0, "QueuedReference map destructor")
	audit_function(0x00528e40, "QueuedReference map clear helper")
	audit_function(0x0044ddc0, "LockFree map bucket/count helper")
	audit_function(0x0044dec0, "LockFree map node read helper")
	audit_function(0x0044dde0, "LockFree map node free helper")
	audit_function(0x006c73b0, "replacement holder allocator from clear/reset")
	audit_callers_to_clear()
	find_refs_to(0x0044c480, "LockFree map clear/reset", 120)
	write("")
	write("=" * 70)
	write("END CRASH 0x00559456 LOCKFREE MAP FIELD CONTRACT AUDIT")
	write("=" * 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_00559456_lockfree_map_field_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
