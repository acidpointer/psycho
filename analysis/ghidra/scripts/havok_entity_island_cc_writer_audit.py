# @category Analysis
# @description Find Havok entity +0xCC island-pointer readers and writers

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
		write("  0x%08x: %-58s%s" % (off, inst.toString(), marker))
		inst = inst.getNext()
		idx += 1

def operand_text(inst, idx):
	try:
		return inst.getDefaultOperandRepresentation(idx)
	except:
		return ""

def is_cc_instruction(inst):
	text = inst.toString().lower()
	return "+ 0xcc" in text or "+0xcc" in text or "0xcc]" in text

def is_probable_write(inst):
	if inst.getMnemonicString().upper() != "MOV":
		return False
	op0 = operand_text(inst, 0).lower()
	return "+ 0xcc" in op0 or "+0xcc" in op0 or "0xcc]" in op0

def scan_cc_accesses():
	write("")
	write("=" * 70)
	write("Scan Havok-range instructions touching +0xCC")
	write("=" * 70)
	write("Range: 0x00C60000..0x00D20000. Writers are the most important lines.")
	funcs = fm.getFunctions(True)
	total = 0
	writes = 0
	seen_writers = {}
	while funcs.hasNext():
		func = funcs.next()
		entry = func.getEntryPoint().getOffset()
		if entry < 0x00c60000 or entry > 0x00d20000:
			continue
		inst_iter = listing.getInstructions(func.getBody(), True)
		while inst_iter.hasNext():
			inst = inst_iter.next()
			if not is_cc_instruction(inst):
				continue
			off = inst.getAddress().getOffset()
			write_mark = "WRITE" if is_probable_write(inst) else "read "
			write("  %-5s 0x%08x in %-30s %s" % (write_mark, off, name_for_func(func), inst.toString()))
			total += 1
			if is_probable_write(inst):
				writes += 1
				seen_writers[entry] = 1
				disasm_window(off, 8, 14, "writer context")
			if total >= 260:
				write("  ... (truncated instruction scan at 260)")
				write("  Printed accesses: %d, writers: %d" % (total, writes))
				print_writer_decompiles(seen_writers)
				return
	write("  Printed accesses: %d, writers: %d" % (total, writes))
	print_writer_decompiles(seen_writers)

def print_writer_decompiles(writer_map):
	write("")
	write("=" * 70)
	write("Unique +0xCC writer function decompiles")
	write("=" * 70)
	keys = writer_map.keys()
	keys.sort()
	for entry in keys:
		decompile_at(entry, "+0xCC writer", 18000)
		find_and_print_calls_from(entry, "+0xCC writer", 160)

def audit_known_island_helpers():
	decompile_at(0x00d07420, "Known writer: set entity+0xCC to island", 12000)
	find_refs_to(0x00d07420, "set entity+0xCC helper", 120)
	decompile_at(0x00d0d3f0, "Crash worker using entity+0xCC before/after StAddAgt", 30000)
	decompile_at(0x00cf7080, "StAddAgt dispatcher that runs between safe read and crash read", 22000)

def main():
	write("HAVOK ENTITY +0xCC ISLAND POINTER WRITER AUDIT")
	write("")
	write("Crash model to validate:")
	write("  0x00D0D7D8 reads [EDX+0xCC] after EDX was loaded from the exported broadphase object array.")
	write("  EDX is zero in the fresh crash, while the same array slot was used earlier for C911D0.")
	write("  We need to know which Havok paths write/clear entity+0xCC and whether StAddAgt can change it.")
	audit_known_island_helpers()
	scan_cc_accesses()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/havok_entity_island_cc_writer_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
