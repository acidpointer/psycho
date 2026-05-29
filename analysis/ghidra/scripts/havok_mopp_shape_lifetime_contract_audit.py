# @category Analysis
# @description Audit hkScaledMopp/Bethesda Havok shape lifetime, vtable refs, and AI-thread ownership

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

def find_refs_to(addr_int, label, limit=240):
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

def find_refs_into_function(addr_int, label, limit=220):
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

def scan_function_for_text(addr_int, label, needles, limit=240):
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

def print_refs_with_context(addr_int, label, before=0x50, after=0xb0, limit=120):
	write("")
	write("-" * 70)
	write("References with disasm context TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	highlights = [addr_int, 0x00c94da5, 0x00c459d0, 0x00aa4060, 0x00401030]
	while refs.hasNext():
		ref = refs.next()
		from_addr = ref.getFromAddress().getOffset()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("")
		write("  REF %d: %s from 0x%08x in %s" % (count + 1, ref.getReferenceType(), from_addr, name_for_func(from_func)))
		disasm_window(from_addr - before, before + after, "xref context for 0x%08x" % from_addr, highlights, 160)
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Context refs printed: %d" % count)

def decompile_ref_functions(addr_int, label, limit=18, max_len=12000):
	write("")
	write("-" * 70)
	write("Unique ref functions for 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = {}
	count = 0
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		if entry in seen:
			continue
		seen[entry] = True
		decompile_at(entry, "%s ref function %d" % (label, count + 1), max_len)
		find_and_print_calls_from(entry, "%s ref function %d" % (label, count + 1), 120)
		scan_function_for_text(entry, "%s ref function %d" % (label, count + 1), ["0x4", "0x8", "0xc", "0x10", "0x14", "0x18", "0x1c", "0xd4", "0x100", "delete", "call"], 120)
		count += 1
		if count >= limit:
			write("  ... (truncated at %d unique functions)" % limit)
			break
	write("  Unique functions printed: %d" % count)

def audit_function(addr_int, label, max_len):
	decompile_at(addr_int, label, max_len)
	find_refs_into_function(addr_int, label)
	find_and_print_calls_from(addr_int, label)
	scan_function_for_text(addr_int, label, ["0x4", "0x8", "0xc", "0x10", "0x14", "0x18", "0x1c", "0x24", "0xd4", "0x100", "call", "test"], 220)

def audit_function_list(items):
	for item in items:
		audit_function(item[0], item[1], item[2])

def audit_vtables(items):
	for item in items:
		find_refs_to(item[0], item[1], item[2])
		print_refs_with_context(item[0], item[1], 0x40, 0xb0, item[3])
		decompile_ref_functions(item[0], item[1], item[4], item[5])

def print_windows(items):
	for item in items:
		disasm_window(item[0], item[1], item[2], item[3], item[4])

def main():
	highlights = [
		0x010ca330, 0x0103093c, 0x010c69f4, 0x010c3bc4, 0x010ccf28,
		0x00c94da5, 0x00c94bd0, 0x00c459d0, 0x00aa4060, 0x00401030
	]
	vtables = [
		(0x010ca330, "hkScaledMoppBvTreeShape vtable from crash EBP", 220, 120, 24, 14000),
		(0x0103093c, "bhkBoxShape vtable from crash stack", 180, 80, 14, 12000),
		(0x010c69f4, "bhkWorldM vtable from crash stack", 180, 80, 14, 12000),
		(0x010c3bc4, "ahkpWorld vtable from crash EDI", 180, 80, 14, 12000),
		(0x010ccf28, "hkpSimulationIsland vtable from crash EBX", 180, 80, 14, 12000),
		(0x01085688, "AILinearTaskThread vtable from crash stack", 120, 60, 10, 12000)
	]
	functions = [
		(0x00c459d0, "Havok GC / async flush that previously reproduced 0x00c94da5", 18000),
		(0x00c46080, "Havok GC subpath from 0x00c459d0", 18000),
		(0x00c45a80, "Havok GC subpath from 0x00c459d0", 18000),
		(0x008324e0, "AI Linear Task stop/start dispatcher used as drain", 20000),
		(0x008c78c0, "AI Linear Task Thread entry", 18000),
		(0x008c7990, "AI Linear Task join/wait", 18000),
		(0x00c94bd0, "Havok add entities crash function", 22000),
		(0x00c674d0, "pending add flush caller", 22000),
		(0x00c3e310, "hkWorld lock", 10000),
		(0x00c3e340, "hkWorld unlock", 10000)
	]
	windows = [
		(0x00c459d0, 0xd0, "Havok GC lock/flush/unlock window", highlights, 180),
		(0x008324e0, 0x160, "AI task stop/start drain window", highlights, 240),
		(0x008c78c0, 0x100, "AI Linear Task Thread entry window", highlights, 200),
		(0x00c94d70, 0x190, "current fault in add entities", highlights, 260)
	]
	write("=" * 70)
	write("HAVOK MOPP SHAPE LIFETIME CONTRACT AUDIT")
	write("=" * 70)
	write("")
	write("Goal:")
	write("  Find who owns/destroys hkScaledMoppBvTreeShape and related Bethesda Havok objects")
	write("  and whether the 0x00C94DA5 path can observe destroyed or null entity entries on AI threads.")
	write("")
	audit_vtables(vtables)
	find_refs_to(0x00c3e310, "hkWorld_Lock")
	find_refs_to(0x00c3e340, "hkWorld_Unlock")
	find_refs_to(0x00c459d0, "Havok GC / async flush")
	find_refs_to(0x008324e0, "AI Linear Task stop/start drain")
	audit_function_list(functions)
	print_windows(windows)
	write("")
	write("=" * 70)
	write("END HAVOK MOPP SHAPE LIFETIME CONTRACT AUDIT")
	write("=" * 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/havok_mopp_shape_lifetime_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
