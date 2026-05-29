# @category Analysis
# @description Audit stress-test crash at 0x00C94DA5 in Havok add-entities / MOPP path

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

def decompile_at(addr_int, label, max_len=18000):
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
		faddr = from_func.getEntryPoint().getOffset() if from_func else 0
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s @ 0x%08x)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, faddr))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def find_refs_into_function(addr_int, label, limit=260):
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

def find_and_print_calls_from(addr_int, label, limit=320):
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

def disasm_window(start_int, length, label, highlights, max_inst=520):
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

def print_instruction(addr_int, label):
	inst = listing.getInstructionAt(toAddr(addr_int))
	write("")
	write("-" * 70)
	write("Instruction: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	if inst is None:
		write("  [instruction not found]")
		return
	write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
	write("  Flow: %s" % inst.getFlowType())
	write("  Length: %d" % inst.getLength())

def scan_function_for_text(addr_int, label, needles, limit=260):
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

def print_refs_with_context(addr_int, label, before=0x50, after=0xa0, limit=80):
	write("")
	write("-" * 70)
	write("References with disasm context TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	highlights = [addr_int, 0x00c94da5, 0x00c67551]
	while refs.hasNext():
		ref = refs.next()
		from_addr = ref.getFromAddress().getOffset()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("")
		write("  REF %d: %s from 0x%08x in %s" % (count + 1, ref.getReferenceType(), from_addr, name_for_func(from_func)))
		disasm_window(from_addr - before, before + after, "xref context for 0x%08x" % from_addr, highlights, 140)
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Context refs printed: %d" % count)

def audit_function(addr_int, label, max_len):
	decompile_at(addr_int, label, max_len)
	find_refs_into_function(addr_int, label)
	find_and_print_calls_from(addr_int, label)
	scan_function_for_text(addr_int, label, ["0xd4", "0x94", "0x104", "0xc8", "0xcc", "0xf0", "0x100", "esi", "ecx", "call", "test"], 260)

def audit_function_list(items):
	for item in items:
		audit_function(item[0], item[1], item[2])

def print_windows(items):
	for item in items:
		disasm_window(item[0], item[1], item[2], item[3], item[4])

def main():
	highlights = [
		0x00c94bd0, 0x00c94d90, 0x00c94da3, 0x00c94da5, 0x00c94dab,
		0x00c674d0, 0x00c67551, 0x00c6757a, 0x00c6769d,
		0x00c90350, 0x00c90510, 0x00c905b0, 0x00c91160, 0x00c91620,
		0x00c9c040, 0x00d07420, 0x00d07830
	]
	functions = [
		(0x00c94bd0, "crash function: Havok world add entities / LtAddEntities", 26000),
		(0x00c674d0, "pending add flush caller that previously crashed at 0x00c6757a", 24000),
		(0x00c6b540, "known caller of pending add flush", 22000),
		(0x00c68a40, "known caller of pending add flush", 22000),
		(0x00c6b0a0, "known caller of pending add flush", 24000),
		(0x00c6b3c0, "known caller of pending add flush", 22000),
		(0x00c90350, "CrashLogger second falloutnv frame", 18000),
		(0x00c90510, "entity pre-add helper after [entity+0xd4] write", 18000),
		(0x00c905b0, "entity post-loop helper in pending add path", 18000),
		(0x00c91160, "recursive/deferred add-entities path when world already adding", 22000),
		(0x00c91620, "pending add fallback helper from 0x00c674d0", 18000),
		(0x00c9c040, "collision agent helper called with entity shape/agent", 20000),
		(0x00d07420, "island/collection insert helper", 20000),
		(0x00d07830, "temporary collection constructor helper", 18000)
	]
	windows = [
		(0x00c94d70, 0x190, "exact null-entity write window at 0x00c94da5", highlights, 260),
		(0x00c94bd0, 0x330, "function prologue through failing add loop", highlights, 420),
		(0x00c674d0, 0x230, "pending-add caller and memset tail", highlights, 360),
		(0x00c90320, 0x120, "CrashLogger frame near 0x00c90350", highlights, 220)
	]
	write("=" * 70)
	write("CRASH 0x00C94DA5 HAVOK MOPP ADD-ENTITIES AUDIT")
	write("=" * 70)
	write("")
	write("Runtime facts from latest crash:")
	write("  Thread: [FNV] AI Linear Task Thread 2")
	write("  EIP=0x00C94DA5, fault W 0x000000D4, ECX/ESI=0")
	write("  EBP points to hkScaledMoppBvTreeShape; EBX hkpSimulationIsland; EDI ahkpWorld")
	write("  Psycho log saw repeated pool double-free for pool=18 cell=0xb8f8d8e0 ~300 ms before AV")
	write("")
	print_instruction(0x00c94da5, "faulting store")
	find_refs_to(0x00c94bd0, "Havok add entities entry")
	find_refs_to(0x00c674d0, "pending add flush entry")
	print_refs_with_context(0x00c94bd0, "callers into add entities", 0x70, 0xb0, 120)
	print_refs_with_context(0x00c674d0, "callers into pending add flush", 0x70, 0xb0, 120)
	audit_function_list(functions)
	print_windows(windows)
	write("")
	write("=" * 70)
	write("END CRASH 0x00C94DA5 HAVOK MOPP ADD-ENTITIES AUDIT")
	write("=" * 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_00c94da5_mopp_add_entities_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
