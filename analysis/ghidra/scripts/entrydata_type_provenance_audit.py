# @category Analysis
# @description Trace ExtraContainerChanges::EntryData::type construction, copy, load, and writer paths

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

def decompile_at(addr_int, label, max_len=20000):
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

def decompile_callers(addr_int, label, limit=10):
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
				disasm_window(ref.getFromAddress().getOffset(), 18, 26, "call/ref to %s" % label)
				decompile_at(entry, "caller for %s" % label, 14000)
				count += 1
				if count >= limit:
					write("  ... (caller expansion truncated at %d)" % limit)
					return
	write("  Total unique callers printed: %d" % count)

def scan_type_writes_in_function(addr_int, label):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Candidate EntryData.type writes inside %s" % label)
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		mnemonic = inst.getMnemonicString().lower()
		if mnemonic == "mov" and ("+ 0x8" in text or "+0x8" in text):
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
			count += 1
	write("  Total candidate writes/reads printed: %d" % count)

def analyze_known_entrydata_functions():
	targets = [
		(0x004BC550, "EntryData constructor"),
		(0x004BC5F0, "EntryData destructor"),
		(0x004BC650, "EntryData copy"),
		(0x004CA200, "InventoryChanges iterator create"),
		(0x004CA330, "InventoryChanges iterator NextEntry"),
		(0x004C8C10, "Data::GetEntryDataEquippedItem"),
		(0x004BF220, "TESObjectREFR::GetInventoryChangesData"),
		(0x004BEFB0, "InventoryChanges data/create helper"),
		(0x00418520, "inventory changes getter helper"),
		(0x0040FF60, "tList/Add helper used for BSExtraData/EntryData lists")
	]
	idx = 0
	while idx < len(targets):
		item = targets[idx]
		decompile_at(item[0], item[1], 18000)
		find_and_print_calls_from(item[0], item[1], 180)
		scan_type_writes_in_function(item[0], item[1])
		idx += 1

def analyze_deserializer_windows():
	write("")
	write("=" * 70)
	write("Focused windows inside 0x00428150 large load/deserialization function")
	write("=" * 70)
	disasm_window(0x00428638, 42, 58, "EntryData type 0x21 create/load path")
	disasm_window(0x0042A3CC, 36, 48, "literal 0x21 path inside load/deserialization")
	disasm_window(0x0042B97D, 36, 48, "vtable slot +0x218 path inside load/deserialization")
	decompile_at(0x00428150, "0x00428150 large load/deserialization function", 26000)
	scan_type_writes_in_function(0x00428150, "0x00428150 large load/deserialization function")

def analyze_refs():
	targets = [
		(0x004BC550, "EntryData constructor"),
		(0x004BC650, "EntryData copy"),
		(0x004CA330, "InventoryChanges iterator NextEntry"),
		(0x004BF220, "TESObjectREFR::GetInventoryChangesData"),
		(0x004BEFB0, "InventoryChanges create helper"),
		(0x004D4090, "EntryData list save dispatcher"),
		(0x004BED60, "EntryData save function")
	]
	idx = 0
	while idx < len(targets):
		item = targets[idx]
		find_refs_to(item[0], item[1], 180)
		decompile_callers(item[0], item[1], 8)
		idx += 1

def main():
	write("=" * 70)
	write("ENTRYDATA TYPE PROVENANCE AUDIT")
	write("=" * 70)
	write("Known source layout:")
	write("  ExtraContainerChanges::EntryData size 0x0C")
	write("  +0x00 ExtendDataList* extendData")
	write("  +0x04 SInt32 countDelta")
	write("  +0x08 TESForm* type")
	write("")
	write("Crash fact to explain: EntryData.type was 0x00000007 when 0x004BED60 saved it.")
	analyze_known_entrydata_functions()
	analyze_deserializer_windows()
	analyze_refs()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/entrydata_type_provenance_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
