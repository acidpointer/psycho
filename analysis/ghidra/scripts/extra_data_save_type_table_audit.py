# @category Analysis
# @description Locate extra-data save dispatch table and prove how handler 0x004BED60 is selected

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()
mem = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

SAVE_HANDLER = 0x004BED60

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
				tgt_func = func_for(tgt)
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name_for_func(tgt_func)))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def scan_data_for_pointer(ptr, start_int, end_int, limit=80):
	write("")
	write("=" * 70)
	write("Data scan for pointer 0x%08x in 0x%08x..0x%08x" % (ptr, start_int, end_int))
	write("=" * 70)
	matches = []
	addr = start_int
	while addr < end_int:
		value = read_u32(addr)
		if value == ptr:
			sym = getSymbolAt(toAddr(addr))
			sname = sym.getName(True) if sym else ""
			write("  match @ 0x%08x %s" % (addr, sname))
			matches.append(addr)
			if len(matches) >= limit:
				write("  ... (truncated at %d matches)" % limit)
				break
		addr += 4
	return matches

def print_dword_window(center_int, before_dwords, after_dwords, label):
	write("")
	write("-" * 70)
	write("Dword window %s around 0x%08x" % (label, center_int))
	write("-" * 70)
	start = center_int - before_dwords * 4
	end = center_int + after_dwords * 4
	addr = start
	while addr <= end:
		value = read_u32(addr)
		marker = ""
		if addr == center_int:
			marker = " << handler"
		if value is None:
			write("  0x%08x: [unreadable]%s" % (addr, marker))
		else:
			func = func_for(value)
			write("  0x%08x: 0x%08x %-38s%s" % (addr, value, name_for_func(func), marker))
		addr += 4

def decompile_table_neighbors(center_int, before_dwords, after_dwords, limit=14):
	write("")
	write("-" * 70)
	write("Decompile callable table neighbors near 0x%08x" % center_int)
	write("-" * 70)
	addr = center_int - before_dwords * 4
	end = center_int + after_dwords * 4
	count = 0
	seen = {}
	while addr <= end:
		value = read_u32(addr)
		if value is not None:
			func = func_for(value)
			if func is not None:
				entry = func.getEntryPoint().getOffset()
				if entry not in seen:
					seen[entry] = True
					decompile_at(value, "table neighbor from 0x%08x" % addr, 10000)
					count += 1
					if count >= limit:
						write("  ... (neighbor decompile truncated at %d)" % limit)
						return
		addr += 4

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
			marker = " << target"
		write("  0x%08x: %-42s%s" % (off, inst.toString(), marker))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (tgt, name_for_func(func_for(tgt))))
		inst = inst.getNext()
		idx += 1

def analyze_matches(matches, limit=4):
	idx = 0
	while idx < len(matches) and idx < limit:
		match = matches[idx]
		print_dword_window(match, 24, 40, "possible save dispatch table")
		decompile_table_neighbors(match, 12, 18, 12)
		idx += 1
	if len(matches) > limit:
		write("")
		write("Only first %d table matches were expanded to keep output readable." % limit)

def main():
	write("=" * 70)
	write("EXTRA-DATA SAVE TYPE TABLE AUDIT")
	write("=" * 70)
	write("Goal: prove whether 0x004BED60 is a type-dispatched save handler and identify the table/index contract.")
	find_refs_to(SAVE_HANDLER, "0x004BED60 save handler", 180)
	decompile_at(SAVE_HANDLER, "0x004BED60 save handler", 22000)
	find_and_print_calls_from(SAVE_HANDLER, "0x004BED60 save handler", 180)
	decompile_at(0x004D4090, "0x004D4090 probable extra-list save dispatcher", 22000)
	disasm_window(0x004D4112, 60, 70, "runtime caller inside 0x004D4090")
	find_and_print_calls_from(0x004D4090, "0x004D4090 probable dispatcher", 220)
	matches = scan_data_for_pointer(SAVE_HANDLER, 0x01000000, 0x01280000, 120)
	analyze_matches(matches, 4)
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/extra_data_save_type_table_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
