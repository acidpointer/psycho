# @category Analysis
# @description Audit navmesh/tasklet allocation and OOM contracts behind 0x0069083A

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

def find_and_print_calls_from(addr_int, label, limit=300):
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

def disasm_window(start_int, length, label, highlights, max_inst=460):
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

def print_call_context(from_addr, label):
	write("")
	write("Call context: 0x%08x (%s)" % (from_addr, label))
	disasm_window(from_addr - 0x50, 0xF0, "call context", [from_addr], 120)

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

def scan_range_for_text(start_int, end_int, label, needles, limit=360):
	write("")
	write("-" * 70)
	write("Instruction text scan: %s 0x%08x..0x%08x" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	count = 0
	while inst is not None and inst.getAddress().getOffset() < end_int:
		text = inst.toString().lower()
		matched = False
		for needle in needles:
			if needle.lower() in text:
				matched = True
		if matched:
			from_func = fm.getFunctionContaining(inst.getAddress())
			write("  0x%08x: %-44s in %s" % (inst.getAddress().getOffset(), inst.toString(), name_for_func(from_func)))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				break
		inst = inst.getNext()
	write("  Total matches: %d" % count)

def alloc_targets():
	return [
		(0x00AA3E40, "GameHeap_Allocate"),
		(0x00AA2240, "aligned calloc / memset path"),
		(0x00AA4290, "SBM CRT malloc fallback"),
		(0x00401000, "FormHeap_Allocate wrapper"),
		(0x00ECD1C7, "CRT malloc #1"),
		(0x00ED0CDF, "CRT malloc #2"),
		(0x00EDDD7D, "CRT calloc #1"),
		(0x00ED0D24, "CRT calloc #2"),
		(0x00ECCF5D, "CRT realloc #1"),
		(0x00ED0D70, "CRT realloc #2")
	]

def calltrace_targets():
	return [
		(0x0069083A, "crash function"),
		(0x006B8CD4, "navmesh caller"),
		(0x006C9600, "navmesh caller"),
		(0x006C8FB4, "navmesh caller"),
		(0x006C8EE0, "navmesh caller"),
		(0x006D0B54, "navmesh caller"),
		(0x006D0970, "navmesh caller"),
		(0x006EA0B6, "pathfinding outer"),
		(0x00B0258A, "tasklet worker dispatch"),
		(0x00B02403, "tasklet thread loop")
	]

def print_direct_alloc_calls_in_function(addr_int, label):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Direct allocator calls in %s" % label)
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	targets = alloc_targets()
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if not ref.getReferenceType().isCall():
				continue
			tgt = ref.getToAddress().getOffset()
			for item in targets:
				if tgt == item[0]:
					write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), item[0], item[1]))
					print_call_context(inst.getAddress().getOffset(), item[1])
					count += 1
	if count == 0:
		write("  No direct allocator calls in this function.")
	else:
		write("  Total direct allocator calls: %d" % count)

def print_callers_to_target_in_range(target_addr, target_label, start_int, end_int, limit=180):
	write("")
	write("-" * 70)
	write("Callers of %s in 0x%08x..0x%08x" % (target_label, start_int, end_int))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(target_addr))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		src = ref.getFromAddress().getOffset()
		if src < start_int or src >= end_int:
			continue
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("  0x%08x in %s" % (src, name_for_func(from_func)))
		if count < 18:
			print_call_context(src, target_label)
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def audit_allocator_target_refs():
	targets = alloc_targets()
	for item in targets:
		find_refs_to(item[0], item[1], 80)
		print_callers_to_target_in_range(item[0], item[1], 0x00680000, 0x006F2000, 80)
		print_callers_to_target_in_range(item[0], item[1], 0x00B00000, 0x00B04000, 80)

def audit_calltrace_alloc_contracts():
	items = calltrace_targets()
	for item in items:
		addr_int = item[0]
		label = item[1]
		decompile_at(addr_int, label, 24000)
		find_refs_into_function(addr_int, label, 180)
		find_and_print_calls_from(addr_int, label, 260)
		print_direct_alloc_calls_in_function(addr_int, label)
		scan_function_for_text(addr_int, label, ["00aa3e40", "00aa2240", "00aa4290", "00401000", "ecd1c7", "ed0cdf", "eddd7d", "ed0d24", "call", "test", "cmp", "jz", "jnz", "+ 0x20", "+0x20", "+ 0x1c", "+0x1c", "400", "0x400"], 220)

def find_strings_matching(patterns, limit=140):
	write("")
	write("-" * 70)
	write("Defined string scan for pathing/navmesh names")
	write("-" * 70)
	data_iter = listing.getDefinedData(True)
	count = 0
	while data_iter.hasNext():
		data = data_iter.next()
		try:
			if not data.hasStringValue():
				continue
			value = data.getValue()
		except:
			continue
		if value is None:
			continue
		text = str(value)
		lower = text.lower()
		matched = None
		for pattern in patterns:
			if pattern.lower() in lower:
				matched = pattern
				break
		if matched is None:
			continue
		addr_int = data.getAddress().getOffset()
		write("  0x%08x: %s" % (addr_int, text))
		refs = ref_mgr.getReferencesTo(toAddr(addr_int))
		ref_count = 0
		while refs.hasNext():
			ref = refs.next()
			from_func = fm.getFunctionContaining(ref.getFromAddress())
			write("    %s @ 0x%08x in %s" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), name_for_func(from_func)))
			if ref_count < 4:
				print_call_context(ref.getFromAddress().getOffset(), "string %s" % matched)
			ref_count += 1
			if ref_count >= 16:
				write("    ... refs truncated")
				break
		count += 1
		if count >= limit:
			write("  ... strings truncated at %d" % limit)
			break
	write("  Total matching strings printed: %d" % count)

def main():
	highlights = [0x0069083A, 0x0069081B, 0x006B8CD4, 0x006C9600, 0x006C8FB4, 0x006C8EE0, 0x006D0B54, 0x006D0970, 0x006EA0B6, 0x00B0258A, 0x00B02403]
	write("=" * 70)
	write("NAVMESH TASKLET PRESSURE CONTRACT AUDIT")
	write("=" * 70)
	write("")
	write("Question this script tries to answer:")
	write("  Did the pathfinding/navmesh tasklet path allocate or consume optional arrays")
	write("  while gheap was returning NULL under pool/VAS pressure, then dereference a")
	write("  small sentinel or unchecked NULL-derived pointer at 0x0069083A?")
	write("")
	write("Runtime reason for this direction:")
	write("  Psycho log showed repeated pool exhaustion before the crash and AV read at 0x20.")
	write("  Registers at crash had EAX=ECX=4 and EDX=NavMeshInfoSearch.")
	write("")
	write("# SECTION 1: allocator implementations and vanilla OOM contract")
	decompile_at(0x00AA3E40, "GameHeap_Allocate vanilla retry/OOM contract", 28000)
	find_and_print_calls_from(0x00AA3E40, "GameHeap_Allocate vanilla retry/OOM contract", 180)
	decompile_at(0x00AA2240, "aligned calloc / memset path", 22000)
	find_and_print_calls_from(0x00AA2240, "aligned calloc / memset path", 180)
	decompile_at(0x00AA4290, "SBM CRT malloc fallback", 14000)
	find_and_print_calls_from(0x00AA4290, "SBM CRT malloc fallback", 120)
	decompile_at(0x00401000, "FormHeap_Allocate wrapper", 14000)
	find_and_print_calls_from(0x00401000, "FormHeap_Allocate wrapper", 120)
	write("")
	write("# SECTION 2: pathfinding/navmesh calltrace contract")
	audit_calltrace_alloc_contracts()
	write("")
	write("# SECTION 3: allocator callers inside pathfinding/tasklet regions")
	audit_allocator_target_refs()
	write("")
	write("# SECTION 4: high-signal instruction scans in related address ranges")
	scan_range_for_text(0x00680000, 0x006F2000, "pathfinding/navmesh region allocator/null/array scan", ["00aa3e40", "00aa2240", "00aa4290", "00401000", "ecd1c7", "ed0cdf", "eddd7d", "ed0d24", "call", "test", "cmp", "jz", "jnz", "+ 0x20", "+0x20", "+ 0x1c", "+0x1c", "0x400", "400"])
	scan_range_for_text(0x00B00000, 0x00B04000, "BSWin32TaskletManager dispatch scan", ["call", "test", "cmp", "jz", "jnz", "+ 0x20", "+0x20", "+ 0x1c", "+0x1c"])
	write("")
	write("# SECTION 5: focused windows for manual follow-up")
	disasm_window(0x006907C0, 0x180, "faulting function", highlights, 420)
	disasm_window(0x006B8B80, 0x280, "0x006B8CD4 caller", highlights, 420)
	disasm_window(0x006C8E00, 0xA00, "0x006C8EE0..0x006C9600 caller region", highlights, 760)
	disasm_window(0x006D0800, 0x4A0, "0x006D0970..0x006D0B54 caller region", highlights, 560)
	disasm_window(0x006E9F00, 0x320, "0x006EA0B6 pathfinding outer", highlights, 480)
	disasm_window(0x00B02380, 0x2C0, "tasklet manager worker loop", highlights, 420)
	write("")
	write("# SECTION 6: pathing/navmesh strings and source-file anchors")
	find_strings_matching(["NavMeshInfoSearch", "NavMesh", "PathManager", "Pathfinding", "BSScrapArray", "Tasklet"], 120)
	write("")
	write("=" * 70)
	write("END NAVMESH TASKLET PRESSURE CONTRACT AUDIT")
	write("=" * 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/navmesh_tasklet_pressure_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
