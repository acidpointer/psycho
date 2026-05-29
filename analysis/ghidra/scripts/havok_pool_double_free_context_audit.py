# @category Analysis
# @description Compact audit for Havok pool double-free context before 0x00C94DA5 crash

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

def label_for_addr(addr_int):
	func = func_for(addr_int)
	if func is None:
		return "0x%08x ???" % addr_int
	return "0x%08x %s" % (addr_int, name_for_func(func))

def decompile_at(addr_int, label, max_len=9000):
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

def find_refs_to(addr_int, label, limit=80):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		faddr = from_func.getEntryPoint().getOffset() if from_func else 0
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s @ 0x%08x)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, faddr))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def find_and_print_calls_from(addr_int, label, limit=120):
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
				write("  0x%08x -> %s" % (inst.getAddress().getOffset(), label_for_addr(tgt)))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def disasm_window(start_int, length, label, highlights, max_inst=120):
	end_int = start_int + length
	write("")
	write("-" * 70)
	write("Disassembly: %s 0x%08x..0x%08x" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	count = 0
	while inst is not None and inst.getAddress().getOffset() < end_int:
		off = inst.getAddress().getOffset()
		mark = "   "
		for item in highlights:
			if off == item:
				mark = "=> "
		write("%s0x%08x: %s" % (mark, off, inst.toString()))
		inst = inst.getNext()
		count += 1
		if count >= max_inst:
			write("  ... (truncated at %d instructions)" % max_inst)
			break
	write("  Instructions printed: %d" % count)

def scan_function_for_text(addr_int, label, needles, limit=80):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Instruction text scan: %s" % label)
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		matched = False
		for needle in needles:
			if needle.lower() in text:
				matched = True
		if matched:
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				break
	write("  Total matches: %d" % count)

def print_refs_with_context(addr_int, label, before=0x40, after=0x80, limit=20):
	write("")
	write("-" * 70)
	write("References with compact context TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	highlights = [addr_int, 0x00c94bd0, 0x00c94da5, 0x00c674d0, 0x00aa3e40, 0x00aa4060, 0x00401030]
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		from_addr = ref.getFromAddress().getOffset()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("")
		write("  REF %d: %s from 0x%08x in %s" % (count + 1, ref.getReferenceType(), from_addr, name_for_func(from_func)))
		disasm_window(from_addr - before, before + after, "xref context for 0x%08x" % from_addr, highlights, 110)
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Context refs printed: %d" % count)

def print_interesting_calls_in_function(addr_int, label, targets):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Allocator/free-like calls inside %s" % label)
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
			if not ref.getReferenceType().isCall():
				continue
			tgt = ref.getToAddress().getOffset()
			for target in targets:
				if tgt == target[0]:
					write("  0x%08x -> %s (%s)" % (inst.getAddress().getOffset(), label_for_addr(tgt), target[1]))
					count += 1
	write("  Total interesting calls: %d" % count)

def audit_function(addr_int, label, max_len, targets):
	decompile_at(addr_int, label, max_len)
	find_and_print_calls_from(addr_int, label, 100)
	print_interesting_calls_in_function(addr_int, label, targets)
	scan_function_for_text(addr_int, label, ["0x50", "0x6c", "0x80", "0xd4", "0xcc", "0x100", "0x104", "0xbb8", "test", "jz", "jnz"], 90)

def audit_function_list(items, targets):
	for item in items:
		audit_function(item[0], item[1], item[2], targets)

def print_contexts(items):
	for item in items:
		print_refs_with_context(item[0], item[1], item[2], item[3], item[4])

def print_pool_note():
	write("")
	write("-" * 70)
	write("Runtime pool note")
	write("-" * 70)
	write("  Latest log: pool=18 was subpool #18 of class #11 80B, range 0xb8800000..0xb9000000.")
	write("  Double-free cell 0xb8f8d8e0 is offset 0x78d8e0, cell index 98998, aligned to 80 bytes.")
	write("  This script does not scan the whole Havok image; it only audits functions that can feed 0x00C94BD0.")

def main():
	targets = [
		(0x00aa3e40, "GameHeap allocate"),
		(0x00aa4060, "GameHeap free"),
		(0x00aa4150, "GameHeap realloc1"),
		(0x00aa4200, "GameHeap realloc2"),
		(0x00aa44c0, "GameHeap msize"),
		(0x00401030, "operator delete"),
		(0x00c85750, "Havok allocator router"),
		(0x00c908c0, "Havok array reserve/realloc"),
		(0x00c90510, "Havok ref/inc helper"),
		(0x00c905b0, "Havok ref/dec helper")
	]
	functions = [
		(0x00c94bd0, "central addEntityBatch crash target", 11000),
		(0x00c674d0, "pending-add flush caller", 10000),
		(0x00cf7c10, "direct addEntityBatch caller #2", 9000),
		(0x00ce1680, "direct addEntityBatch caller #3", 8000),
		(0x00c97f80, "direct addEntityBatch caller #4 with sparse fallback", 9000),
		(0x00c6b540, "pending flush producer #1", 7000),
		(0x00c68a40, "pending flush producer #2", 7000),
		(0x00c6b0a0, "pending flush producer #3/#4", 9000),
		(0x00c6b3c0, "pending flush producer #5", 9000)
	]
	contexts = [
		(0x00c94bd0, "central addEntityBatch callers", 0x50, 0x90, 8),
		(0x00c674d0, "pending add flush callers", 0x50, 0x90, 10),
		(0x00aa4060, "direct GameHeap free refs, limited", 0x35, 0x60, 10),
		(0x00401030, "operator delete refs, limited", 0x35, 0x60, 10),
		(0x00c908c0, "Havok array reserve/realloc refs, limited", 0x35, 0x60, 10)
	]
	write("=" * 70)
	write("HAVOK POOL DOUBLE-FREE CONTEXT AUDIT - COMPACT")
	write("=" * 70)
	write("")
	write("Goal:")
	write("  Correlate the pool #18 80B double-free with the addEntityBatch null-slot crash without producing a huge whole-image dump.")
	print_pool_note()
	find_refs_to(0x00c94bd0, "central addEntityBatch")
	find_refs_to(0x00c674d0, "pending add flush")
	find_refs_to(0x00aa4060, "GameHeap free", 40)
	find_refs_to(0x00401030, "operator delete", 40)
	print_contexts(contexts)
	audit_function_list(functions, targets)
	write("")
	write("=" * 70)
	write("END HAVOK POOL DOUBLE-FREE CONTEXT AUDIT - COMPACT")
	write("=" * 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/havok_pool_double_free_context_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
