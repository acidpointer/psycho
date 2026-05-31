# @category Analysis
# @description Audit ExtraLinkedRefChildren type 0x52 GetByType callers and NULL-safety contract

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

def decompile_at(addr_int, label, max_len=16000):
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
		marker = ""
		if off == center_int:
			marker = " << target"
		write("  0x%08x: %-56s%s" % (off, inst.toString(), marker))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (tgt, name_for_func(func_for(tgt))))
		inst = inst.getNext()
		idx += 1

def instruction_window_has_type52(call_inst, scan_back):
	inst = call_inst
	count = 0
	while inst is not None and count < scan_back:
		text = str(inst.toString()).lower()
		if "0x52" in text or ",52h" in text or " 52h" in text or ",0x52" in text:
			return True
		inst = inst.getPrevious()
		count += 1
	return False

def print_getbytype_type52_callers():
	write("")
	write("=" * 70)
	write("Direct BaseExtraList::GetByType callers that appear to request type 0x52")
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(0x00410220))
	printed = 0
	seen = {}
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		call_addr = ref.getFromAddress().getOffset()
		inst = listing.getInstructionAt(ref.getFromAddress())
		if inst is None:
			continue
		if not instruction_window_has_type52(inst, 10):
			continue
		func = fm.getFunctionContaining(ref.getFromAddress())
		key = func.getEntryPoint().getOffset() if func else call_addr
		if key in seen:
			continue
		seen[key] = True
		printed += 1
		disasm_window(call_addr, 14, 42, "type 0x52 GetByType callsite")
		decompile_at(call_addr, "type 0x52 GetByType caller", 22000)
		find_and_print_calls_from(call_addr, "type 0x52 GetByType caller", 120)
		if printed >= 30:
			write("  ... truncated type 0x52 caller scan at 30 unique functions")
			break
	write("Type 0x52 direct caller functions printed: %d" % printed)

def print_crash_related_functions():
	write("")
	write("=" * 70)
	write("Crash-related type 0x52 stack focus")
	write("=" * 70)
	disasm_window(0x0041e619, 32, 70, "crash caller after GetByType")
	decompile_at(0x0041e619, "crash caller after GetByType", 26000)
	disasm_window(0x0055a976, 24, 54, "stack parent")
	decompile_at(0x0055a976, "stack parent", 22000)
	disasm_window(0x0055a3df, 24, 54, "stack parent")
	decompile_at(0x0055a3df, "stack parent", 22000)
	disasm_window(0x0086816a, 24, 54, "stack parent")
	decompile_at(0x0086816a, "stack parent", 22000)

def main():
	write("ExtraLinkedRefChildren type 0x52 contract audit")
	write("")
	write("xNVSE enum says type 0x52 is ExtraLinkedRefChildren. Crash register EBX=0x52 shows GetByType was looking for that extra.")
	write("Goal: identify every direct type-0x52 GetByType caller, especially 0x0041E619, and prove whether a NULL result is checked before dereference.")
	print_crash_related_functions()
	print_getbytype_type52_callers()
	find_refs_to(0x00410220, "BaseExtraList::GetByType", 220)
	find_refs_to(0x010143E8, "ExtraDataList vtable from CrashLogger stack", 80)
	find_refs_to(0x0102F55C, "TESObjectREFR vtable from CrashLogger stack", 80)
	find_refs_to(0x0102E9B4, "TESObjectCELL vtable from CrashLogger stack", 80)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/extralinkedrefchildren_type52_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
