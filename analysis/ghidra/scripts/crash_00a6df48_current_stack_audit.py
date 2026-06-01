# @category Analysis
# @description Audit current 0x00A6DF48 ragdoll null-bone crash stack from cell attach path

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

def decompile_at(addr_int, label, max_len=24000):
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

def is_highlight(addr_int, highlights):
	for item in highlights:
		if addr_int == item:
			return True
	return False

def disasm_window(center_int, before_count, after_count, label, highlights):
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
		prefix = "=> " if is_highlight(off, highlights) else "   "
		write("%s0x%08x: %-58s" % (prefix, off, inst.toString()))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (tgt, name_for_func(func_for(tgt))))
		inst = inst.getNext()
		idx += 1

def audit_stack_function(addr_int, label):
	decompile_at(addr_int, label, 26000)
	disasm_window(addr_int, 28, 90, label, [addr_int])
	find_and_print_calls_from(addr_int, label, 260)

def audit_current_stack():
	write("Current 0x00A6DF48 ragdoll null-bone stack audit")
	write("")
	write("CrashLogger facts to verify against disassembly:")
	write("  EIP=0x00A6DF48, ESI=0x00000034, thread=main.")
	write("  Stack object: bhkRagdollController 0xFCC61D10.")
	write("  Actor: Gun Runner Guard, FormID 2D033EE2, cell Wilderness, state Attaching.")
	write("  Memory pressure was low: virtual usage about 1.08 GiB / 4 GiB.")
	write("")
	write("Current calltrace:")
	write("  00A6DF48 <- 00C796F7 <- 00C7D866 <- 00931443 <- 0056F8D4")
	write("  <- 0054BC5B <- 0054BD6A <- 004533B3 <- 00452D22")
	write("  <- 0086FC22 <- 0086EB24 <- 0086B3E8")
	write("")
	targets = [
		(0x00a6df48, "Crash site quaternion/matrix helper"),
		(0x00c796f7, "Ragdoll skeleton update crash instruction context"),
		(0x00c79680, "Ragdoll skeleton update entry"),
		(0x00c7d866, "Ragdoll bone transform update caller context"),
		(0x00c7d810, "Ragdoll bone transform update entry"),
		(0x00931443, "Actor process update current frame"),
		(0x0056f8d4, "Reference processing current frame"),
		(0x0054bc5b, "Current mid frame A"),
		(0x0054bd6a, "Current mid frame B"),
		(0x004533b3, "Current cell/package frame"),
		(0x00452d22, "Current cell attach/update frame"),
		(0x0086fc22, "Outer frame A"),
		(0x0086eb24, "Outer frame B"),
		(0x0086b3e8, "Main loop frame"),
	]
	for item in targets:
		audit_stack_function(item[0], item[1])

def audit_key_refs():
	find_refs_to(0x00c79680, "Ragdoll skeleton update", 260)
	find_refs_to(0x00c7d810, "Ragdoll bone transform update", 260)
	find_refs_to(0x00930c70, "Actor process update entry", 120)
	find_refs_to(0x0056f700, "Reference processing entry", 120)
	find_refs_to(0x0054bcf0, "Current mid frame function", 120)
	find_refs_to(0x00452580, "Cell attach/update function", 120)

def main():
	audit_current_stack()
	audit_key_refs()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_00a6df48_current_stack_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
