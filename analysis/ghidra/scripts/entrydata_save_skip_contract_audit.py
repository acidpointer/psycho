# @category Analysis
# @description Audit EntryData save loop counter/block contract and safe invalid-entry skip boundary

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

def analyze_save_loop():
	write("=" * 70)
	write("ENTRYDATA SAVE SKIP CONTRACT AUDIT")
	write("=" * 70)
	write("Question: if EntryData.type is invalid, can we skip only that entry without corrupting save block counts?")
	decompile_at(0x004D4090, "EntryData list save dispatcher 0x004D4090", 22000)
	disasm_window(0x004D410D, 70, 62, "call to EntryData save and post-call count increment")
	find_and_print_calls_from(0x004D4090, "EntryData list save dispatcher", 220)
	find_refs_to(0x004D4090, "EntryData list save dispatcher", 160)
	decompile_at(0x004BED60, "EntryData save function 0x004BED60", 22000)
	disasm_window(0x004BED75, 28, 40, "EntryData.type form write")
	disasm_window(0x004BEDC7, 40, 40, "ExtendDataList nested ExtraDataList save")
	find_and_print_calls_from(0x004BED60, "EntryData save function", 180)
	find_refs_to(0x004BED60, "EntryData save function", 160)

def analyze_save_count_helpers():
	targets = [
		(0x00865F20, "save count begin marker"),
		(0x00865FF0, "save count patch/end marker"),
		(0x00865570, "raw save writer"),
		(0x00865DF0, "TESForm/form-ref save writer"),
		(0x00865E50, "raw field save writer"),
		(0x00428110, "change flag reader/helper"),
		(0x00428130, "change flag scope/end helper"),
		(0x0050F9C0, "save buffer state helper")
	]
	idx = 0
	while idx < len(targets):
		item = targets[idx]
		decompile_at(item[0], item[1], 16000)
		find_and_print_calls_from(item[0], item[1], 140)
		idx += 1

def analyze_neighbor_functions():
	targets = [
		(0x004D4000, "neighbor before save dispatcher"),
		(0x004D4160, "neighbor after save dispatcher"),
		(0x009590F0, "caller family 0x009590F0"),
		(0x009C4FF0, "caller family 0x009C4FF0")
	]
	idx = 0
	while idx < len(targets):
		item = targets[idx]
		decompile_at(item[0], item[1], 20000)
		find_and_print_calls_from(item[0], item[1], 220)
		idx += 1

def main():
	analyze_save_loop()
	analyze_save_count_helpers()
	analyze_neighbor_functions()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/entrydata_save_skip_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
