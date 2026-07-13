# @category Analysis
# @description Prove the Sphere primitive cache layout, child identity, and NiTriStrips virtual-slot contract after the second old-save crash

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
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
		if count > 160:
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
	inst_iter = listing.getInstructions(body, True)
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
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	while inst is not None and inst.getAddress().getOffset() <= end_int:
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()

def audit_function(addr_int, label, max_len=24000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def ascii_dword(value):
	chars = []
	index = 0
	while index < 4:
		byte = (value >> (index * 8)) & 0xff
		chars.append(chr(byte) if byte >= 0x20 and byte < 0x7f else ".")
		index += 1
	return "".join(chars)

def print_pointer_table(start_int, count, label):
	write("")
	write("-" * 70)
	write("Pointer table: %s @ 0x%08x" % (label, start_int))
	write("-" * 70)
	index = 0
	while index < count:
		entry_addr = start_int + index * 4
		try:
			value = memory.getInt(toAddr(entry_addr)) & 0xffffffff
			func = fm.getFunctionAt(toAddr(value))
			name = func.getName() if func else "???"
			write("  +0x%02x 0x%08x -> 0x%08x %-24s '%s'" % (index * 4, entry_addr, value, name, ascii_dword(value)))
		except:
			write("  +0x%02x 0x%08x [unreadable]" % (index * 4, entry_addr))
		index += 1

def audit_primitive_lifetime():
	targets = [
		(0x004A7150, "BGSPrimitiveSphere constructor and field initialization", 26000),
		(0x004A71F0, "BGSPrimitiveSphere destructor", 26000),
		(0x004A7830, "BGSPrimitiveSphere cached-node getter", 20000),
		(0x004A7240, "BGSPrimitiveSphere vtable method before builder", 22000),
		(0x004A7AA0, "BGSPrimitiveSphere vtable method after builder", 24000),
		(0x0056C7F0, "reference caller primitive result getter", 22000),
		(0x00B6FC90, "generated primitive geometry constructor", 28000),
		(0x00A71C40, "generated primitive geometry-data constructor", 30000),
		(0x00A5DB60, "BSFadeNode child virtual plus B0 dispatcher", 22000),
	]
	for item in targets:
		audit_function(item[0], item[1], item[2])

def audit_child_vtable():
	find_refs_to(0x0109CD44, "NiTriStrips vtable observed in crash")
	print_pointer_table(0x0109CD44, 56, "NiTriStrips runtime vtable and following data")
	print_pointer_table(0x010A8F90, 48, "BSFadeNode vtable through child-dispatch slot")
	disasm_range(0x004A7150, 0x004A72D0, "Sphere constructor, destructor, and adjacent virtual methods")
	disasm_range(0x00B6FC90, 0x00B6FD90, "generated primitive geometry vtable initialization")
	disasm_range(0x00A5DB60, 0x00A5DBE0, "child plus-B0 virtual dispatch")

def main():
	write("=" * 70)
	write("BGSPrimitiveSphere CHILD IDENTITY MICRO FOLLOW-UP")
	write("=" * 70)
	write("Prove whether CigarettePack:0 can satisfy the child virtual contract used by the Sphere builder, what class the builder creates locally, and whether stale object lifetime or concurrent cache publication can replace fields +0x24 and +0x2C.")
	audit_primitive_lifetime()
	audit_child_vtable()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_20260713_primitive_child_identity_micro_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
