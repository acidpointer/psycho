# @category Analysis
# @description Audit ExtraOwnership load contract and exact owner write path

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

def print_range(start_int, end_int, label):
	write("")
	write("-" * 70)
	write("Instruction range: %s 0x%08x..0x%08x" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	while inst is not None:
		off = inst.getAddress().getOffset()
		if off > end_int:
			break
		write("  0x%08x: %s" % (off, inst.toString()))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (tgt, name_for_func(func_for(tgt))))
		inst = inst.getNext()

def print_owner_writes_near_load():
	write("")
	write("=" * 70)
	write("Candidate owner field writes in ExtraOwnership load window")
	write("=" * 70)
	inst = listing.getInstructionAt(toAddr(0x004285e0))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(0x004285e0))
	while inst is not None:
		off = inst.getAddress().getOffset()
		if off > 0x004286d0:
			break
		text = inst.toString()
		if "+ 0xc" in text or "+0xc" in text or "0xc]" in text:
			write("  0x%08x: %s" % (off, text))
		inst = inst.getNext()

def main():
	write("ExtraOwnership load contract deep audit")
	write("")
	write("Goal: prove how type 0x21 load creates ExtraOwnership and fills owner +0x0C.")
	write("This answers whether the correct fix belongs at load-time owner resolution, access-time ownership lookup, or both.")
	print_range(0x004285e0, 0x004286d0, "ExtraOwnership case in ExtraDataList::LoadGame")
	disasm_window(0x00428638, 28, 38, "ExtraOwnership default constructor during load")
	disasm_window(0x00428689, 26, 46, "Owner form-ref reader call")
	disasm_window(0x0042868f, 26, 58, "Owner form lookup/conversion call")
	print_owner_writes_near_load()
	decompile_at(0x00428150, "ExtraDataList::LoadGame candidate", 22000)
	decompile_at(0x0042c5e0, "ExtraOwnership default constructor", 6000)
	decompile_at(0x00431a40, "ExtraOwnership owner constructor", 6000)
	decompile_at(0x008648a0, "save/load form-ref reader", 8000)
	decompile_at(0x004839c0, "form lookup/conversion helper", 8000)
	find_and_print_calls_from(0x00428150, "ExtraDataList::LoadGame candidate", 360)
	find_refs_to(0x0042c5e0, "ExtraOwnership default constructor")
	find_refs_to(0x00431a40, "ExtraOwnership owner constructor")
	find_refs_to(0x008648a0, "save/load form-ref reader")
	find_refs_to(0x004839c0, "form lookup/conversion helper")

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/extraownership_load_contract_deep_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
