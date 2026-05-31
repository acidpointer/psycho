# @category Analysis
# @description Audit central ExtraOwnership access boundaries for invalid owner scrubbing

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

def find_refs_to(addr_int, label, limit=220):
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

def find_and_print_calls_from(addr_int, label, limit=260):
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

def print_getbytype_ownership_refs():
	write("")
	write("=" * 70)
	write("Ownership type constant and access helper focus")
	write("=" * 70)
	write("Known ExtraOwnership type is 0x21; owner field is +0x0C.")
	disasm_window(0x00418660, 8, 36, "small ownership getter candidate")
	disasm_window(0x00567770, 8, 28, "TESObjectREFR direct ownership resolver")
	disasm_window(0x00410220, 8, 50, "BaseExtraList::GetByType candidate")
	disasm_window(0x00410140, 8, 70, "BaseExtraList::RemoveByType candidate")

def main():
	write("ExtraOwnership access boundary audit")
	write("")
	write("Goal: identify the central point where invalid ExtraOwnership.owner can be scrubbed once.")
	write("Fresh crash proves xNVSE GetOwner read owner=0x00000007 from ExtraOwnership after the AI guard already skipped it.")
	print_getbytype_ownership_refs()
	decompile_at(0x00418660, "small ownership getter candidate", 10000)
	decompile_at(0x00567770, "TESObjectREFR direct ownership resolver", 10000)
	decompile_at(0x00567790, "TESObjectREFR ownership resolver with fallback", 18000)
	decompile_at(0x00410220, "BaseExtraList::GetByType candidate", 14000)
	decompile_at(0x00410140, "BaseExtraList::RemoveByType candidate", 14000)
	decompile_at(0x0040ff60, "BaseExtraList::Add candidate", 12000)
	find_and_print_calls_from(0x00418660, "small ownership getter candidate", 120)
	find_and_print_calls_from(0x00567770, "TESObjectREFR direct ownership resolver", 120)
	find_and_print_calls_from(0x00410220, "BaseExtraList::GetByType candidate", 120)
	find_refs_to(0x00418660, "small ownership getter candidate")
	find_refs_to(0x00567770, "TESObjectREFR direct ownership resolver")
	find_refs_to(0x00410220, "BaseExtraList::GetByType candidate")
	find_refs_to(0x00410140, "BaseExtraList::RemoveByType candidate")

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/extraownership_access_boundary_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
