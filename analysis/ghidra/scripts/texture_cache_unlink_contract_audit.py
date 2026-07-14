# @category Analysis
# @description Prove texture cache bucket ownership, unlink operations, and lock order for stale-root removal

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=8000):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
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
	else:
		write("  [decompilation failed]")

def find_refs_to(addr_int, label):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
		if count > 40:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found at 0x%08x]" % addr_int)
		return
	body = func.getBody()
	inst_iter = currentProgram.getListing().getInstructions(body, True)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
	write("  Total: %d calls" % count)

def disasm_range(start_int, end_int, label):
	write("")
	write("-" * 70)
	write("Disassembly: %s (0x%08x - 0x%08x)" % (label, start_int, end_int))
	write("-" * 70)
	inst = currentProgram.getListing().getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = currentProgram.getListing().getInstructionAfter(toAddr(start_int))
	while inst is not None and inst.getAddress().getOffset() <= end_int:
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()

def audit(addr_int, label, max_len=30000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def main():
	write("TEXTURE CACHE STALE-ROOT UNLINK CONTRACT")
	write("Identify the exact bucket link layout, insertion/removal functions, engine lock ownership, and destructor ordering needed to unlink a dying texture once without a lookup pre-walk or per-frame dead set.")
	audit(0x00A615C0, "texture hash-table destructor", 50000)
	audit(0x00A61610, "texture hash-node insertion", 50000)
	audit(0x00A61670, "texture hash-node payload release", 50000)
	audit(0x00A616E0, "texture hash iterator begin", 40000)
	audit(0x00A61750, "texture hash helper", 40000)
	audit(0x00A617C0, "texture hash-node allocator or lookup", 50000)
	audit(0x00A61890, "texture hash-node unlink", 50000)
	audit(0x00A61920, "texture hash lookup helper", 50000)
	audit(0x00A619B0, "texture cache lookup family entry", 50000)
	audit(0x00A61A60, "hooked texture cache find", 50000)
	audit(0x00A61AD0, "texture cache insertion or replacement", 50000)
	audit(0x00A61B90, "texture cache table operation", 50000)
	audit(0x00A61C50, "texture cache table operation", 50000)
	audit(0x00A61CD0, "texture cache cleanup operation", 50000)
	audit(0x00A61F30, "texture cache table operation", 40000)
	audit(0x00A61FB0, "texture cache table operation", 40000)
	audit(0x00A62030, "texture cache full reset", 40000)
	audit(0x00A61E60, "texture cache targeted operation", 50000)
	audit(0x00A61EC0, "texture cache table teardown", 50000)
	audit(0x00A5FCA0, "NiSourceTexture destructor", 50000)
	audit(0x00A60160, "NiSourceTexture scalar destructor caller", 40000)
	audit(0x00A61250, "NiSourceTexture release caller", 40000)
	audit(0x0043C4F0, "texture cache find caller and lock context", 50000)
	audit(0x0040FBF0, "engine lock acquisition", 30000)
	audit(0x0040FBA0, "engine lock release", 30000)
	find_refs_to(0x011F4480, "engine texture/cache lock global")
	disasm_range(0x00A619A0, 0x00A620A0, "texture cache operation family")
	disasm_range(0x00A5FC80, 0x00A5FE20, "texture destructor ordering")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/memory/texture_cache_unlink_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
