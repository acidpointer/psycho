# @category Analysis
# @description Audit bhkRagdollController +0xA0/+0xA4/+0xA8 table array helper contract

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

def read_u32(addr_int):
	try:
		return getInt(toAddr(addr_int)) & 0xffffffff
	except:
		return None

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

def find_refs_to(addr_int, label, limit=160):
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

def find_and_print_calls_from(addr_int, label, limit=240):
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
		write("  0x%08x: %-62s%s" % (off, inst.toString(), marker))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (tgt, name_for_func(func_for(tgt))))
		inst = inst.getNext()
		idx += 1

def inspect_function_offsets(addr_int, label, terms):
	func = func_for(addr_int)
	write("")
	write("=" * 70)
	write("Table-offset instruction scan in %s (0x%08x)" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		for term in terms:
			if term in text:
				write("  0x%08x %-70s hit=%s" % (inst.getAddress().getOffset(), inst.toString(), term))
				count += 1
				break
	write("  Total hits: %d" % count)

def print_calls_near_table_offsets(addr_int, label, terms, window):
	func = func_for(addr_int)
	write("")
	write("=" * 70)
	write("Calls with nearby +0xA0/+0xA4/+0xA8/+0xAC terms in %s (0x%08x)" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	insts = []
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		insts.append(inst_iter.next())
	count = 0
	for idx in range(0, len(insts)):
		inst = insts[idx]
		refs = inst.getReferencesFrom()
		is_call = False
		for ref in refs:
			if ref.getReferenceType().isCall():
				is_call = True
				break
		if not is_call:
			continue
		start = idx - window
		if start < 0:
			start = 0
		end = idx + 1
		hit = False
		for j in range(start, end):
			text = insts[j].toString().lower()
			for term in terms:
				if term in text:
					hit = True
					break
			if hit:
				break
		if hit:
			write("  call @ 0x%08x %s" % (inst.getAddress().getOffset(), inst.toString()))
			for j in range(start, end):
				write("    0x%08x: %s" % (insts[j].getAddress().getOffset(), insts[j].toString()))
			count += 1
	write("  Total call windows: %d" % count)

def inspect_array_vtable(vtable_addr, label, count):
	write("")
	write("=" * 70)
	write("Array helper vtable %s @ 0x%08x" % (label, vtable_addr))
	write("=" * 70)
	for i in range(0, count):
		slot = vtable_addr + i * 4
		ptr = read_u32(slot)
		if ptr is None:
			write("  [%02d] 0x%08x -> [unreadable]" % (i, slot))
		else:
			write("  [%02d] 0x%08x -> 0x%08x %s" % (i, slot, ptr, name_for_func(func_for(ptr))))
	for i in range(0, count):
		ptr = read_u32(vtable_addr + i * 4)
		if ptr is not None:
			decompile_at(ptr, "%s vtable slot %02d target" % (label, i), 12000)
			find_refs_to(ptr, "%s vtable slot %02d target" % (label, i), 80)

def inspect_targets():
	targets = [
		(0x00c7f060, "bhkRagdollController constructor"),
		(0x00c7d900, "bhkRagdollController destructor"),
		(0x00c7bcb0, "temporary bone list builder"),
		(0x00c7d3b0, "constructor pre-init helper"),
		(0x00c75c00, "constructor post-init helper"),
		(0x00c7e9a0, "controller data init"),
		(0x00c741e0, "outer CreateRagdollController constructor"),
		(0x00c78090, "triplet reader using +0xA8 count"),
		(0x00c79680, "skeleton update reader"),
		(0x00c75b40, "save/load writeback"),
		(0x00c79a50, "runtime writeback"),
	]
	terms = ["+ 0xa0", "+ 0xa4", "+ 0xa8", "+ 0xac", "+0xa0", "+0xa4", "+0xa8", "+0xac"]
	for item in targets:
		decompile_at(item[0], item[1], 26000)
		find_and_print_calls_from(item[0], item[1], 260)
		inspect_function_offsets(item[0], item[1], terms)
		print_calls_near_table_offsets(item[0], item[1], terms, 10)

def inspect_references():
	find_refs_to(0x01071aec, "bhkRagdollController +0xA0 array vtable")
	find_refs_to(0x01071af4, "array vtable slot near destructor/free")
	find_refs_to(0x00c75b40, "save/load writeback")
	find_refs_to(0x00c79a50, "runtime writeback")
	find_refs_to(0x00c7d900, "controller destructor")
	find_refs_to(0x00c7de30, "controller cleanup caller")
	find_refs_to(0x0087e130, "actor/NiNode attach path")

def main():
	write("Ragdoll live +0xA4 table array helper contract audit")
	write("")
	write("Goal:")
	write("  Prove how bhkRagdollController +0xA4/+0xA8/+0xAC is populated/freed.")
	write("  Identify whether a safe repair can repopulate the table directly or must rebuild through actor attach.")
	inspect_array_vtable(0x01071aec, "PTR_FUN_01071aec", 8)
	inspect_targets()
	inspect_references()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/ragdoll_table_array_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
