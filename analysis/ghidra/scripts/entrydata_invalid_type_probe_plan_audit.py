# @category Analysis
# @description Identify precise probe points for EntryData.type corruption without patching behavior

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

def decompile_at(addr_int, label, max_len=14000):
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

def print_ref_windows(addr_int, label, before_count, after_count, limit):
	write("")
	write("=" * 70)
	write("Call/reference windows for %s 0x%08x" % (label, addr_int))
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

def gather_unique_callers(addr_int, limit):
	result = []
	seen = {}
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		if from_func is not None:
			entry = from_func.getEntryPoint().getOffset()
			if entry not in seen:
				seen[entry] = True
				result.append(entry)
				if len(result) >= limit:
					break
	return result

def scan_plus8_accesses(func_addr, label):
	func = func_for(func_addr)
	write("")
	write("-" * 70)
	write("EntryData-like +0x08 accesses in %s" % label)
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
	write("  Total printed: %d" % count)

def scan_caller_sets():
	write("")
	write("=" * 70)
	write("Focused +0x08 scan in constructor/copy/load callers")
	write("=" * 70)
	callers = []
	callers.extend(gather_unique_callers(0x004BC550, 48))
	callers.extend(gather_unique_callers(0x004BC650, 16))
	callers.extend(gather_unique_callers(0x004BEE00, 16))
	callers.extend(gather_unique_callers(0x004BE930, 16))
	seen = {}
	idx = 0
	while idx < len(callers):
		entry = callers[idx]
		if entry not in seen:
			seen[entry] = True
			scan_plus8_accesses(entry, name_for_func(func_for(entry)))
		idx += 1

def analyze_core_probe_points():
	write("")
	write("=" * 70)
	write("Core probe points and call contracts")
	write("=" * 70)
	decompile_at(0x004BC550, "EntryData constructor: writes type from param_2")
	decompile_at(0x004BC650, "EntryData copy: copies source type")
	decompile_at(0x004BEE00, "EntryData body load: loads type/count/list")
	decompile_at(0x004D4160, "EntryData list load dispatcher: reject/add ordering")
	decompile_at(0x004D4090, "EntryData list save dispatcher: safe skip boundary")
	decompile_at(0x004BED60, "EntryData save: unsafe global hook boundary")
	disasm_window(0x004BC550, 4, 46, "constructor entry")
	disasm_window(0x004BC650, 4, 72, "copy entry")
	disasm_window(0x004BEE00, 8, 92, "body load entry")
	disasm_window(0x004D410D, 26, 38, "save dispatcher call/count")
	disasm_window(0x004D4258, 28, 64, "load dispatcher body-load/validate/add")

def analyze_callsite_windows():
	find_refs_to(0x004BC550, "EntryData constructor", 180)
	find_refs_to(0x004BC650, "EntryData copy", 80)
	find_refs_to(0x004BEE00, "EntryData body load", 80)
	find_refs_to(0x004BE930, "older EntryData body load", 80)
	find_refs_to(0x004BED60, "EntryData save", 40)
	print_ref_windows(0x004BC550, "EntryData constructor", 10, 16, 60)
	print_ref_windows(0x004BC650, "EntryData copy", 10, 16, 24)
	print_ref_windows(0x004BEE00, "EntryData body load", 16, 20, 24)
	print_ref_windows(0x004BE930, "older EntryData body load", 16, 20, 24)

def main():
	write("=" * 70)
	write("ENTRYDATA INVALID TYPE PROBE PLAN AUDIT")
	write("=" * 70)
	write("Goal: no behavior change. Identify where to log EntryData.type creation,")
	write("copy, load, validation, save, and rejection so the producer of 0x00000007")
	write("can be proven instead of guessed.")
	write("")
	write("Known crash fact:")
	write("  EntryData.type was 0x00000007 at 0x004BED75 -> 0x00865DF0.")
	write("  Hooking 0x004BED60 is unsafe because callers may already count the entry.")
	analyze_core_probe_points()
	analyze_callsite_windows()
	scan_caller_sets()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/entrydata_invalid_type_probe_plan_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
