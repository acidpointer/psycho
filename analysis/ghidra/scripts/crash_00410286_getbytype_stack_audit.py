# @category Analysis
# @description Audit crash at BaseExtraList::GetByType+0x66 from save-to-save load path

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

def print_stack_chain():
	write("")
	write("=" * 70)
	write("Crash stack function chain")
	write("=" * 70)
	addrs = [
		(0x00410286, "crash EIP inside BaseExtraList::GetByType"),
		(0x0041e619, "return after GetByType caller"),
		(0x0055a976, "stack caller"),
		(0x0055a3df, "stack caller"),
		(0x0086816a, "stack caller"),
		(0x00550ac2, "stack caller"),
		(0x0046230d, "stack caller"),
		(0x00454def, "stack caller"),
		(0x00452b83, "stack caller"),
		(0x0045470b, "stack caller"),
		(0x0093c500, "stack caller"),
	]
	for item in addrs:
		disasm_window(item[0], 14, 34, item[1])
		decompile_at(item[0], item[1], 18000)
		find_and_print_calls_from(item[0], item[1], 120)

def print_core_extra_functions():
	write("")
	write("=" * 70)
	write("BaseExtraList traversal helpers")
	write("=" * 70)
	disasm_window(0x00410220, 8, 80, "BaseExtraList::GetByType")
	disasm_window(0x00410286, 20, 24, "crashing deref in GetByType")
	disasm_window(0x0040f9e0, 12, 34, "BaseExtraList cached lookup helper")
	disasm_window(0x0040fa40, 12, 34, "BaseExtraList cache store helper")
	disasm_window(0x0044ddc0, 10, 28, "BSExtraData next helper")
	disasm_window(0x004f1540, 10, 28, "BSExtraData type helper")
	decompile_at(0x00410220, "BaseExtraList::GetByType", 16000)
	decompile_at(0x0040f9e0, "BaseExtraList cached lookup helper", 12000)
	decompile_at(0x0040fa40, "BaseExtraList cache store helper", 12000)
	decompile_at(0x0044ddc0, "BSExtraData next helper", 12000)
	decompile_at(0x004f1540, "BSExtraData type helper", 12000)

def main():
	write("Crash 0x00410286 GetByType stack audit")
	write("")
	write("Crash facts from log: EIP=0x00410286, EBX/requested type=0x52 (ExtraLinkedRefChildren), ECX/EDX=0x2E646C72, ESI=0x06007B07.")
	write("Goal: prove the exact caller path and whether the caller can tolerate GetByType returning NULL for type 0x52.")
	print_core_extra_functions()
	print_stack_chain()
	find_refs_to(0x00410220, "BaseExtraList::GetByType", 180)
	find_refs_to(0x0041e619, "specific return/callsite address")
	find_refs_to(0x004f1540, "BSExtraData type helper", 160)
	find_refs_to(0x0044ddc0, "BSExtraData next helper", 160)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_00410286_getbytype_stack_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
