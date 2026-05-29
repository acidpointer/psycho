# @category Analysis
# @description Audit navmesh/path name helper contract and invalid small-pointer handling

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

def audit_function(addr_int, label, max_len):
	decompile_at(addr_int, label, max_len)
	find_refs_into_function(addr_int, label)
	find_and_print_calls_from(addr_int, label)
	scan_function_for_text(addr_int, label, ["0x4", "0x1c", "0x20", "0x54", "eax", "ecx", "ret", "call", "cmp", "test", "jz", "jnz"], 260)

def audit_function_list(items):
	for item in items:
		audit_function(item[0], item[1], item[2])

def print_windows(items):
	for item in items:
		disasm_window(item[0], item[1], item[2], item[3], item[4])

def main():
	highlights = [
		0x0069083a, 0x00690830, 0x00690800, 0x00690816, 0x0069081b,
		0x006b8ccf, 0x006b8cd4, 0x006b8cdb, 0x006b8ce5,
		0x006c95c1, 0x006c95c8, 0x006c95e1, 0x006c95e8, 0x006c95fb, 0x006c9600,
		0x006b77c6, 0x006937de, 0x006b6cd5
	]
	functions = [
		(0x00690830, "crashing navmesh/path name helper, raw object pointer in ECX", 14000),
		(0x00690800, "wrapper that normalizes helper result through 0x00ec43fb", 14000),
		(0x006b8c50, "crash caller: compares two endpoint helper identities", 18000),
		(0x006c94c0, "producer path: builds query endpoints and calls 0x006b8c50", 22000),
		(0x005c3420, "producer helper: returns value passed as endpoint object", 22000),
		(0x0048d150, "producer helper used before second 0x005c3420", 22000),
		(0x006a9540, "producer helper used before first 0x005c3420", 22000),
		(0x004839c0, "fallback name/string resolver used when +0x1c is null", 18000),
		(0x00ec43fb, "wrapper normalization/hash/string helper", 18000),
		(0x006b77b0, "direct caller of 0x00690830", 18000),
		(0x00692950, "direct caller of 0x00690830", 22000),
		(0x006b6c60, "direct caller of 0x00690830", 24000),
		(0x006d4f70, "additional wrapper caller seen in references", 22000),
		(0x0068f6d0, "additional wrapper caller seen in references", 22000)
	]
	windows = [
		(0x00690800, 0x60, "helper/wrapper exact crash window", highlights, 120),
		(0x006b8c40, 0x160, "0x006b8c50 arg use: [EBP+0x10] and [EBP+0x18] into wrapper", highlights, 220),
		(0x006c95a0, 0x80, "0x006c94c0 callsite: producer return values pushed to 0x006b8c50", highlights, 160),
		(0x005c33a0, 0x120, "0x005c3420 local disassembly", highlights, 200),
		(0x0048d0c0, 0x160, "0x0048d150 local disassembly", highlights, 220),
		(0x006a94b0, 0x160, "0x006a9540 local disassembly", highlights, 220)
	]
	write("=" * 70)
	write("NAVMESH NAME HELPER CONTRACT AUDIT")
	write("=" * 70)
	write("")
	write("Goal:")
	write("  Validate whether a central guard on 0x00690830 or 0x00690800 can safely turn invalid small endpoint pointers into a null identity.")
	write("  Runtime crash had ECX/EAX=0x00000004 and faulted on [ECX+0x1c], so this script focuses on helper callers and endpoint producers.")
	find_refs_to(0x00690830, "direct entry refs to helper")
	find_refs_to(0x00690800, "direct entry refs to wrapper")
	find_refs_to(0x005c3420, "producer helper refs")
	find_refs_to(0x0048d150, "producer helper refs")
	find_refs_to(0x006a9540, "producer helper refs")
	audit_function_list(functions)
	print_windows(windows)
	write("")
	write("=" * 70)
	write("END NAVMESH NAME HELPER CONTRACT AUDIT")
	write("=" * 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/navmesh_name_helper_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
