# @category Analysis
# @description Audit save/load form-reference resolver chain used by EntryData.type

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
		write("  0x%08x: %-46s%s" % (off, inst.toString(), marker))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (tgt, name_for_func(func_for(tgt))))
		inst = inst.getNext()
		idx += 1

def print_ref_windows(addr_int, label, before_count, after_count, limit):
	write("")
	write("=" * 70)
	write("Reference windows for %s 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("")
		write("Reference %d: 0x%08x in %s" % (count + 1, ref.getFromAddress().getOffset(), name_for_func(from_func)))
		disasm_window(ref.getFromAddress().getOffset(), before_count, after_count, label)
		count += 1
		if count >= limit:
			write("  ... (window expansion truncated at %d)" % limit)
			break
	write("  Total windows printed: %d" % count)

def analyze_core_functions():
	targets = [
		(0x00865DF0, "save TESForm/form-ref writer"),
		(0x008648A0, "load form-ref reader"),
		(0x004839C0, "form lookup / conversion helper"),
		(0x00EC43FB, "RTTI/cast/helper after form lookup"),
		(0x0084EAF0, "save form remap helper"),
		(0x00853570, "save form id encode helper"),
		(0x00865570, "raw save writer"),
		(0x00864980, "raw load field reader"),
		(0x00864A60, "load variable count reader"),
		(0x004BED60, "EntryData save"),
		(0x004BEE00, "EntryData load")
	]
	idx = 0
	while idx < len(targets):
		item = targets[idx]
		decompile_at(item[0], item[1], 20000)
		find_and_print_calls_from(item[0], item[1], 260)
		idx += 1

def analyze_call_windows():
	write("")
	write("=" * 70)
	write("Focused save/load chain windows")
	write("=" * 70)
	disasm_window(0x004BED75, 20, 34, "EntryData save calls form writer")
	disasm_window(0x004BEE37, 16, 38, "EntryData load reads form ref")
	disasm_window(0x004BEE3D, 16, 38, "EntryData load form lookup helper")
	disasm_window(0x004BEE48, 16, 38, "EntryData load cast/helper")
	disasm_window(0x004BEE53, 16, 30, "EntryData load writes resolved type")
	disasm_window(0x004BEA4E, 18, 50, "older EntryData load raw form ref")
	disasm_window(0x004BEA77, 18, 42, "older EntryData load form lookup helper")
	disasm_window(0x004BEA82, 18, 42, "older EntryData load cast/helper")
	disasm_window(0x004BEA8D, 18, 30, "older EntryData load writes resolved type")

def analyze_refs():
	targets = [
		(0x008648A0, "load form-ref reader"),
		(0x004839C0, "form lookup / conversion helper"),
		(0x00EC43FB, "RTTI/cast/helper after lookup"),
		(0x00865DF0, "save TESForm/form-ref writer")
	]
	idx = 0
	while idx < len(targets):
		item = targets[idx]
		find_refs_to(item[0], item[1], 220)
		idx += 1
	print_ref_windows(0x008648A0, "load form-ref reader", 10, 18, 40)
	print_ref_windows(0x00EC43FB, "RTTI/cast/helper after lookup", 10, 18, 40)

def main():
	write("=" * 70)
	write("ENTRYDATA FORMREF RESOLVER CONTRACT AUDIT")
	write("=" * 70)
	write("Goal: prove the contract of the form-reference load chain used to fill")
	write("EntryData.type, and whether it can return non-null invalid values.")
	write("")
	write("EntryData load chain under audit:")
	write("  0x004BEE00 -> 0x008648A0 -> 0x004839C0 -> 0x00EC43FB -> [entry+0x08]")
	write("EntryData save chain under audit:")
	write("  [entry+0x08] -> 0x00865DF0 -> raw save writer")
	analyze_core_functions()
	analyze_call_windows()
	analyze_refs()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/entrydata_formref_resolver_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
