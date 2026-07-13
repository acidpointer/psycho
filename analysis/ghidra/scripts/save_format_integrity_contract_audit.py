# @category Analysis
# @description Audit FalloutNV save format framing, compression, read bounds, count validation, and malformed-file rejection

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
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
		if count > 100:
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

def audit_function(addr_int, label, max_len=18000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def audit_targets():
	targets = [
		(0x00860E20, "save header read and signature/version validation", 26000),
		(0x00857B50, "raw save header writer", 14000),
		(0x00857BA0, "raw save header reader", 14000),
		(0x00846330, "BGSSaveLoadFile raw write", 18000),
		(0x00846570, "BGSSaveLoadFile raw read candidate", 18000),
		(0x00847590, "save file header and chapter serialization", 28000),
		(0x00847DF0, "BGSSaveLoadGame LoadGame", 32000),
		(0x00846E00, "save chapter writer", 22000),
		(0x00865A30, "changed-form buffer finalization", 16000),
		(0x00865AD0, "changed-form header construction", 16000),
		(0x00865570, "save buffer merge/write primitive", 18000),
		(0x00865F20, "variable-sized block begin", 12000),
		(0x00865FF0, "variable-sized block end and length patch", 16000),
		(0x00483D70, "changed-record zlib deflate", 24000),
		(0x00864980, "load buffer raw read", 16000),
		(0x008648A0, "load encoded ref ID", 16000),
		(0x008579E0, "load-game typed read", 14000),
		(0x00862110, "load block-framing predicate", 12000),
		(0x00825C00, "load buffer position query", 12000),
	]
	for item in targets:
		audit_function(item[0], item[1], item[2])

def find_strings_matching():
	patterns = ["fo3savegame", "saveload:", "savegame", "save game", "buffer overrun", "buffer underrun", "block header", "error deflating", "error initializing zlib", "corrupt", "out of disk", "save failed", ".fos", ".tmp"]
	write("")
	write("=" * 70)
	write("SAVE FORMAT AND ERROR STRING ANCHORS")
	write("=" * 70)
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
		matched = False
		for pattern in patterns:
			if pattern in lower:
				matched = True
				break
		if not matched:
			continue
		addr_int = data.getAddress().getOffset()
		write("  0x%08x: %s" % (addr_int, text[:260]))
		refs = ref_mgr.getReferencesTo(data.getAddress())
		ref_count = 0
		while refs.hasNext():
			ref = refs.next()
			from_func = fm.getFunctionContaining(ref.getFromAddress())
			fname = from_func.getName() if from_func else "???"
			faddr = from_func.getEntryPoint().getOffset() if from_func else 0
			write("    %s @ 0x%08x in %s @ 0x%08x" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, faddr))
			ref_count += 1
			if ref_count >= 24:
				write("    ... refs truncated")
				break
		count += 1
		if count >= 240:
			write("  ... strings truncated")
			break
	write("  Total matching strings: %d" % count)

def main():
	write("=" * 70)
	write("SAVE FORMAT INTEGRITY CONTRACT AUDIT")
	write("=" * 70)
	write("Questions: which sizes and counts are trusted, where bounds are checked, and what malformed data is accepted?")
	audit_targets()
	find_strings_matching()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/save_format_integrity_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
