# @category Analysis
# @description Audit whether BaseExtraList traversal can be made safe without changing valid semantics

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

def find_refs_to(addr_int, label, limit=180):
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

def print_traversal_family():
	write("")
	write("=" * 70)
	write("BaseExtraList and BSExtraData traversal family")
	write("=" * 70)
	targets = [
		(0x0040f7d0, "BaseExtraList clear type/cache bit"),
		(0x0040f9e0, "BaseExtraList cached lookup helper"),
		(0x0040fa40, "BaseExtraList cache store helper"),
		(0x0040fe80, "BaseExtraList has type bit helper"),
		(0x0040fee0, "BaseExtraList mark type bit helper"),
		(0x0040ff60, "BaseExtraList add extra"),
		(0x00410140, "BaseExtraList remove by type"),
		(0x00410220, "BaseExtraList get by type"),
		(0x004102d0, "BaseExtraList get count/by index style neighbor"),
		(0x0044ddc0, "BSExtraData next helper"),
		(0x004f1540, "BSExtraData type helper"),
		(0x0041b090, "ExtraDataList duplicate for container"),
	]
	for item in targets:
		disasm_window(item[0], 12, 58, item[1])
		decompile_at(item[0], item[1], 18000)
		find_and_print_calls_from(item[0], item[1], 140)

def print_known_bad_shape():
	write("")
	write("=" * 70)
	write("Crash shape to evaluate against traversal contract")
	write("=" * 70)
	write("CrashLogger stack says BaseExtraList pointer=0xF9763934, owning ref=0xF97638F0, ref is deleted Terminal 36007C07, cell 360076E4 is unloading.")
	write("At crash: GetByType local node in ECX is 0x2E646C72, requested type is 0x52, and vanilla is about to call BSExtraData::GetType on that node.")
	write("Questions this script output must answer:")
	write("  1. Is +0x04 always BaseExtraList head pointer?")
	write("  2. Does cache lookup avoid list walk for valid cached extras?")
	write("  3. Is returning NULL from GetByType valid for missing type 0x52?")
	write("  4. Which functions mutate list head or next pointers during cell unload/save-load?")

def main():
	write("BaseExtraList safe traversal contract audit")
	write("")
	write("Goal: gather enough concrete data before deciding between global safe traversal, type-0x52 guard, or callsite-specific guard.")
	print_known_bad_shape()
	print_traversal_family()
	find_refs_to(0x0040ff60, "BaseExtraList add extra", 180)
	find_refs_to(0x00410140, "BaseExtraList remove by type", 180)
	find_refs_to(0x00410220, "BaseExtraList get by type", 240)
	find_refs_to(0x0044ddc0, "BSExtraData next helper", 220)
	find_refs_to(0x004f1540, "BSExtraData type helper", 220)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/baseextralist_safe_traversal_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
