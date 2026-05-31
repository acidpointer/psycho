# @category Analysis
# @description Audit ExtraContainerChanges::EntryData load contract and invalid-type rejection path

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

def find_refs_to(addr_int, label, limit=140):
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

def decompile_callers(addr_int, label, limit=8, max_len=12000):
	write("")
	write("=" * 70)
	write("Caller functions for %s 0x%08x" % (label, addr_int))
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
				disasm_window(ref.getFromAddress().getOffset(), 18, 30, "call/ref to %s" % label)
				decompile_at(entry, "caller for %s" % label, max_len)
				count += 1
				if count >= limit:
					write("  ... (caller expansion truncated at %d)" % limit)
					return
	write("  Total unique callers printed: %d" % count)

def scan_entrydata_type_access(addr_int, label):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Candidate EntryData +0x08 accesses inside %s" % label)
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		if "+ 0x8" in text or "+0x8" in text:
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
			count += 1
	write("  Total candidate accesses printed: %d" % count)

def analyze_load_functions():
	targets = [
		(0x004D4160, "EntryData list load dispatcher"),
		(0x004BEE00, "EntryData body load"),
		(0x004D3CC0, "EntryData older/block load path"),
		(0x004BE930, "EntryData older body load"),
		(0x004BC780, "EntryData reject/destroy helper"),
		(0x0076B630, "EntryData zero/default constructor"),
		(0x0044DDC0, "EntryData type accessor"),
		(0x005AE3D0, "list append/adopt helper"),
		(0x004459E0, "EntryData release/destructor call")
	]
	idx = 0
	while idx < len(targets):
		item = targets[idx]
		decompile_at(item[0], item[1], 18000)
		find_and_print_calls_from(item[0], item[1], 220)
		scan_entrydata_type_access(item[0], item[1])
		idx += 1

def analyze_load_windows():
	write("")
	write("=" * 70)
	write("Focused load-path windows")
	write("=" * 70)
	disasm_window(0x004D41EA, 26, 42, "EntryData count read in load dispatcher")
	disasm_window(0x004D4258, 30, 56, "EntryData body load then validation")
	disasm_window(0x004D4260, 20, 46, "EntryData type validation after body load")
	disasm_window(0x004D426C, 20, 46, "invalid EntryData destroy branch")
	disasm_window(0x004BEE00, 10, 80, "EntryData body load entry")
	disasm_window(0x004BE930, 10, 80, "older EntryData body load entry")
	disasm_window(0x004D3E46, 28, 58, "older body load then type validation")

def analyze_refs():
	targets = [
		(0x004D4160, "EntryData list load dispatcher"),
		(0x004BEE00, "EntryData body load"),
		(0x004D3CC0, "EntryData older/block load path"),
		(0x004BE930, "EntryData older body load"),
		(0x004BC780, "EntryData reject/destroy helper"),
		(0x0076B630, "EntryData zero/default constructor"),
		(0x0044DDC0, "EntryData type accessor")
	]
	idx = 0
	while idx < len(targets):
		item = targets[idx]
		find_refs_to(item[0], item[1], 180)
		idx += 1
	decompile_callers(0x004D4160, "EntryData list load dispatcher", 10, 14000)
	decompile_callers(0x004BEE00, "EntryData body load", 10, 10000)

def main():
	write("=" * 70)
	write("ENTRYDATA LOAD CONTRACT DEEP AUDIT")
	write("=" * 70)
	write("Goal: prove whether invalid EntryData.type can enter through vanilla load,")
	write("and identify the exact reject/add ordering for loaded EntryData objects.")
	write("")
	write("Known layout:")
	write("  EntryData +0x00 ExtendDataList*")
	write("  EntryData +0x04 countDelta")
	write("  EntryData +0x08 TESForm* type")
	analyze_load_functions()
	analyze_load_windows()
	analyze_refs()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/entrydata_load_contract_deep_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
