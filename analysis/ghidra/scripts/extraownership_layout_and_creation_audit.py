# @category Analysis
# @description Prove ExtraOwnership layout, creation paths, vtable/type writes, and owner-field offsets

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()
mem = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

EXTRA_OWNERSHIP_VTABLE = 0x010158B4
EXTRA_OWNERSHIP_RTTI = 0x0118476C
EXTRA_OWNERSHIP_TYPE = 0x21

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
		return mem.getInt(toAddr(addr_int)) & 0xffffffff
	except:
		return None

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

def find_refs_to(addr_int, label, limit=120):
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

def find_and_print_calls_from(addr_int, label, limit=180):
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
				tgt_func = func_for(tgt)
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name_for_func(tgt_func)))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
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
		marker = ""
		if off == center_int:
			marker = " << ref"
		write("  0x%08x: %-42s%s" % (off, inst.toString(), marker))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (tgt, name_for_func(func_for(tgt))))
		inst = inst.getNext()
		idx += 1

def print_vtable(vtable_addr, label, slots):
	write("")
	write("=" * 70)
	write("%s vtable @ 0x%08x" % (label, vtable_addr))
	write("=" * 70)
	idx = 0
	while idx < slots:
		entry_addr = vtable_addr + idx * 4
		target = read_u32(entry_addr)
		if target is None:
			write("  [%02d] 0x%08x: [unreadable]" % (idx, entry_addr))
		else:
			write("  [%02d] 0x%08x -> 0x%08x %s" % (idx, entry_addr, target, name_for_func(func_for(target))))
		idx += 1

def decompile_ref_functions(addr_int, label, limit=24):
	write("")
	write("=" * 70)
	write("Functions referencing %s 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = {}
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		if from_func is not None:
			entry = from_func.getEntryPoint().getOffset()
			if entry not in seen:
				seen[entry] = True
				disasm_window(ref.getFromAddress().getOffset(), 10, 18, "ref to %s" % label)
				decompile_at(entry, "ref function for %s" % label, 14000)
				find_and_print_calls_from(entry, "ref function for %s" % label, 80)
				count += 1
				if count >= limit:
					write("  ... (ref function decompile truncated at %d)" % limit)
					return
	write("  Total unique functions printed: %d" % count)

def scan_instruction_text(patterns, title, limit=220):
	write("")
	write("=" * 70)
	write(title)
	write("=" * 70)
	inst_iter = listing.getInstructions(True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		match = False
		idx = 0
		while idx < len(patterns):
			if patterns[idx] in text:
				match = True
				break
			idx += 1
		if match:
			func = fm.getFunctionContaining(inst.getAddress())
			write("  0x%08x: %-48s in %s" % (inst.getAddress().getOffset(), inst.toString(), name_for_func(func)))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				break
	write("  Total printed: %d" % count)

def main():
	write("=" * 70)
	write("EXTRAOWNERSHIP LAYOUT AND CREATION AUDIT")
	write("=" * 70)
	write("Known xNVSE source model to prove against Ghidra:")
	write("  BSExtraData: vtbl +0, type +4, next +8")
	write("  ExtraOwnership: owner +0x0C")
	write("  ExtraOwnership vtable: 0x010158B4, type: 0x21")
	print_vtable(EXTRA_OWNERSHIP_VTABLE, "ExtraOwnership", 24)
	find_refs_to(EXTRA_OWNERSHIP_VTABLE, "ExtraOwnership vtable", 160)
	find_refs_to(EXTRA_OWNERSHIP_RTTI, "ExtraOwnership RTTI", 80)
	decompile_ref_functions(EXTRA_OWNERSHIP_VTABLE, "ExtraOwnership vtable", 20)
	decompile_ref_functions(EXTRA_OWNERSHIP_RTTI, "ExtraOwnership RTTI", 10)
	decompile_at(0x0042C5E0, "Known/likely ExtraOwnership create/constructor ref target", 22000)
	find_refs_to(0x0042C5E0, "0x0042C5E0 create/constructor candidate", 120)
	find_and_print_calls_from(0x0042C5E0, "0x0042C5E0 create/constructor candidate", 120)
	scan_instruction_text(["+ 0xc", "+0xc", "+ 0x0c", "+0x0c"], "All instruction text hits for displacement +0x0C (candidate owner field)", 260)
	scan_instruction_text(["0x21"], "All instruction text hits for literal 0x21 (candidate ExtraOwnership type)", 180)
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/extraownership_layout_and_creation_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
