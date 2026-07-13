# @category Analysis
# @description Audit every game zlib caller, BSA stream lifetime, and Psycho patch contract

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=8000):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
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
	else:
		write("  [decompilation failed]")

def find_refs_to(addr_int, label):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
		if count > 40:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found at 0x%08x]" % addr_int)
		return
	body = func.getBody()
	inst_iter = listing.getInstructions(body, True)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
	write("  Total: %d calls" % count)

def disasm_range(start_int, end_int, label):
	write("")
	write("-" * 70)
	write("Disassembly %s: 0x%08x - 0x%08x" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	while inst is not None and inst.getAddress().getOffset() <= end_int:
		call_info = ""
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				call_info = " -> 0x%08x %s" % (tgt, name)
		write("  0x%08x: %s%s" % (inst.getAddress().getOffset(), inst, call_info))
		inst = inst.getNext()

def print_unique_callers(target_addr, label, max_len=7000):
	write("")
	write("=" * 70)
	write("UNIQUE CALLERS OF %s (0x%08x)" % (label, target_addr))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(target_addr))
	callers = []
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		if entry not in callers:
			callers.append(entry)
	write("  Unique caller functions: %d" % len(callers))
	for entry in callers:
		decompile_at(entry, "%s caller" % label, max_len)

def print_callsite_contracts():
	sites = [
		(0x004742AC, 0x004742C0, "TES inflateInit_"),
		(0x0047434F, 0x00474363, "TES inflate"),
		(0x004742CA, 0x004742D5, "TES inflateEnd init failure"),
		(0x00474388, 0x00474393, "TES inflateEnd inflate failure"),
		(0x004743D5, 0x004743E0, "TES inflateEnd no stream end"),
		(0x00474419, 0x00474424, "TES inflateEnd success"),
		(0x00AFC537, 0x00AFC54B, "BSA inflateInit_"),
		(0x00AFC1F4, 0x00AFC208, "BSA inflate"),
		(0x00AFC00E, 0x00AFC019, "BSA inflateEnd destructor"),
		(0x00AFC21B, 0x00AFC226, "BSA inflateEnd read failure"),
		(0x00AFC552, 0x00AFC55D, "BSA inflateEnd init failure"),
		(0x00AFC49D, 0x00AFC4A6, "BSA stream allocation immediate"),
		(0x00AFC583, 0x00AFC5B7, "BSA output buffer cap"),
	]
	for item in sites:
		disasm_range(item[0], item[1], item[2])

def print_vtable(start_addr, count, label):
	write("")
	write("=" * 70)
	write("%s @ 0x%08x" % (label, start_addr))
	write("=" * 70)
	index = 0
	while index < count:
		addr = start_addr + index * 4
		try:
			value = memory.getInt(toAddr(addr)) & 0xffffffff
			func = fm.getFunctionAt(toAddr(value))
			name = func.getName() if func else "???"
			write("  [%02d] 0x%08x -> 0x%08x %s" % (index, addr, value, name))
		except:
			write("  [%02d] 0x%08x [unreadable]" % (index, addr))
		index += 1

def print_string_matches(patterns, limit):
	write("")
	write("=" * 70)
	write("ZLIB STRING ANCHORS")
	write("=" * 70)
	data_iter = listing.getDefinedData(True)
	count = 0
	while data_iter.hasNext() and count < limit:
		data = data_iter.next()
		if not data.hasStringValue():
			continue
		value = data.getValue()
		if value is None:
			continue
		text = str(value)
		matched = False
		for pattern in patterns:
			if pattern.lower() in text.lower():
				matched = True
				break
		if not matched:
			continue
		write("  0x%08x %s" % (data.getAddress().getOffset(), text[:180]))
		refs = ref_mgr.getReferencesTo(data.getAddress())
		while refs.hasNext():
			ref = refs.next()
			func = fm.getFunctionContaining(ref.getFromAddress())
			fname = func.getName() if func else "???"
			faddr = func.getEntryPoint().getOffset() if func else 0
			write("    0x%08x in %s @ 0x%08x" % (ref.getFromAddress().getOffset(), fname, faddr))
		count += 1

def main():
	write("FALLOUTNV ZLIB FULL CONTRACT AUDIT")
	write("=" * 70)
	write("Questions: all consumers, exact patch bytes, stream lifetime, buffer ownership, and thread-visible object paths.")
	find_refs_to(0x00B43FE0, "inflateInit_")
	find_refs_to(0x00B44000, "inflate")
	find_refs_to(0x00B45DB0, "inflateEnd")
	print_unique_callers(0x00B43FE0, "inflateInit_")
	print_unique_callers(0x00B44000, "inflate")
	print_unique_callers(0x00B45DB0, "inflateEnd", 10000)
	print_callsite_contracts()
	decompile_at(0x00AFC430, "CompressedArchiveFile constructor", 14000)
	decompile_at(0x00AFC0E0, "CompressedArchiveFile read/decompress", 18000)
	decompile_at(0x00AFBFE0, "CompressedArchiveFile destructor area", 10000)
	find_refs_to(0x00AFC430, "CompressedArchiveFile constructor")
	find_refs_to(0x00AFC0E0, "CompressedArchiveFile read/decompress")
	find_refs_to(0x00AFBFE0, "CompressedArchiveFile destructor area")
	find_refs_to(0x011F8164, "BSA decompression buffer cap global")
	print_vtable(0x010A464C, 20, "CompressedArchiveFile vtable")
	find_refs_to(0x010A464C, "CompressedArchiveFile vtable")
	find_and_print_calls_from(0x00AFC430, "CompressedArchiveFile constructor")
	find_and_print_calls_from(0x00AFC0E0, "CompressedArchiveFile read/decompress")
	find_and_print_calls_from(0x004740A0, "TESFile compressed record load")
	print_string_matches(["1.2.1", "zlib", "inflate", "deflate", "compressed"], 120)
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/zlib_full_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
