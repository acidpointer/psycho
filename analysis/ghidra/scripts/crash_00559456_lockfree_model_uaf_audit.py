# @category Analysis
# @description Audit stress-test crash at 0x00559456 through stale LockFreeStringMap/QueuedReference state

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()
mem = currentProgram.getMemory()
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
				write("  0x%08x -> %s" % (inst.getAddress().getOffset(), label_for_addr(tgt)))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def disasm_window(start_int, length, label, highlights, max_inst=180):
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

def disasm_function(addr_int, label, highlights, max_inst=260):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Function disassembly: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		off = inst.getAddress().getOffset()
		mark = "   "
		for item in highlights:
			if off == item:
				mark = "=> "
		write("%s0x%08x: %s" % (mark, off, inst.toString()))
		count += 1
		if count >= max_inst:
			write("  ... (truncated at %d instructions)" % max_inst)
			break
	write("  Instructions printed: %d" % count)

def scan_function_for_text(addr_int, label, needles, limit=160):
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

def print_refs_with_context(addr_int, label, before=0x30, after=0x80, limit=80):
	write("")
	write("-" * 70)
	write("References with disasm context TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_addr = ref.getFromAddress().getOffset()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("")
		write("REF %d: %s from 0x%08x in %s" % (count + 1, ref.getReferenceType(), from_addr, name_for_func(from_func)))
		disasm_window(max(0, from_addr - before), before + after, "xref context for 0x%08x" % from_addr, [from_addr], 80)
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def print_runtime_facts():
	write("=" * 70)
	write("CRASH 0x00559456 LOCKFREE MODEL / QUEUEDREFERENCE UAF AUDIT")
	write("=" * 70)
	write("")
	write("Runtime facts from psycho + CrashLogger:")
	write("  EIP=0x00559456 inside FUN_00559450, a 16-byte helper that returns *ECX.")
	write("  Registers: ECX=0x00000001, EAX=0x00000001, EDX=0x34E79910.")
	write("  Fault address: read 0x00000001, so the immediate bad pointer is ECX=1.")
	write("  crash_diag: EDX=0x34E79910 is pool#16 item=80 cell_start=0x34E798F0 off=0x20, free=true.")
	write("  Psycho log: [POOL] Double-free ignored for cell=0x34E798F0 about 143 ms before AV.")
	write("  Crash stack shows 0x34E798F0 as LockFreeStringMap<Model*> and a TESObjectREFR for HooverDam scaffolding.")
	write("  This is not OOM and not the previous Havok 0x00C6757A path; it is a stale 80-byte map/reference object.")

def audit_call_chain():
	items = [
		(0x00559456, "faulting pointer get helper"),
		(0x0044C4FA, "ESP[0] return address / likely direct caller"),
		(0x00449C90, "CrashLogger frame 1"),
		(0x00449C3F, "CrashLogger frame 2"),
		(0x00449A5F, "CrashLogger frame 3"),
		(0x00446C55, "CrashLogger frame 4"),
		(0x0094CFDB, "CrashLogger frame 5"),
		(0x0054835D, "CrashLogger frame 6"),
		(0x0086FB4D, "CrashLogger frame 7"),
		(0x0086E765, "CrashLogger frame 8"),
		(0x0086B3E8, "outer loop / NVSE hook frame"),
	]
	for item in items:
		decompile_at(item[0], item[1], 18000)
		find_and_print_calls_from(item[0], item[1], 220)
		scan_function_for_text(item[0], item[1], ["00559450", "+ 0x20", "[edx", "[ecx", "[eax", "0x50", "0x34"], 120)

def main():
	print_runtime_facts()
	disasm_function(0x00559456, "FUN_00559450 faulting helper", [0x00559456], 40)
	disasm_window(0x0044C480, 0x120, "window around ESP[0]=0x0044C4FA", [0x0044C4FA, 0x00559456], 180)
	disasm_window(0x00449BC0, 0x120, "window around CrashLogger frame 0x00449C90", [0x00449C90, 0x00449C3F], 180)
	audit_call_chain()
	decompile_at(0x00528CB0, "NiPointer/ref holder init-addref helper", 8000)
	decompile_at(0x006F74F0, "NiPointer/ref holder assignment helper", 10000)
	decompile_at(0x0044CBF0, "Queued task/ref holder release helper", 10000)
	decompile_at(0x0092C870, "Refcount increment helper called by 0x00528CB0", 9000)
	find_refs_to(0x00559450, "pointer get helper", 200)
	print_refs_with_context(0x00559450, "pointer get helper", 0x24, 0x50, 60)
	find_refs_into_function(0x0044C4FA, "likely direct caller containing ESP[0]", 180)
	write("")
	write("=" * 70)
	write("END CRASH 0x00559456 LOCKFREE MODEL / QUEUEDREFERENCE UAF AUDIT")
	write("=" * 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_00559456_lockfree_model_uaf_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
