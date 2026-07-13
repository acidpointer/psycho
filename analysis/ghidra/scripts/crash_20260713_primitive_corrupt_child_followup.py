# @category Analysis
# @description Resolve the second BGSPrimitiveSphere crash after the missing-property guard and identify the safe construction boundary

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
			write("  +0x%02x 0x%08x -> 0x%08x %s" % (index * 4, entry_addr, value, name))
		except:
			write("  +0x%02x 0x%08x [unreadable]" % (index * 4, entry_addr))
		index += 1

def audit_crash_path():
	targets = [
		(0x004A72D0, "BGSPrimitiveSphere lazy geometry and node builder", 48000),
		(0x004A71D0, "BGSPrimitiveSphere adjacent lifetime or dispatch owner", 24000),
		(0x004A5100, "primitive base construction or cached field owner", 26000),
		(0x0041FAE0, "BGSPrimitiveSphere construction reference owner", 26000),
		(0x0041FB50, "adjacent primitive construction reference owner", 26000),
		(0x004A78E0, "BGSPrimitiveSphere cached result consumer", 26000),
		(0x0056B2D0, "reference primitive setup caller", 42000),
		(0x00559450, "NiPointer value accessor", 12000),
		(0x00633C90, "NiPointer retaining assignment", 16000),
		(0x0066B0D0, "NiPointer replacing assignment", 18000),
		(0x00B4E150, "Sphere BSFadeNode construction", 30000),
		(0x00A5A040, "post-attach scene graph operation reached before crash", 42000),
		(0x00A5DBAF, "invalid virtual dispatch owner after scene graph operation", 42000),
		(0x00A59C60, "scene graph pointer release helper", 22000),
	]
	for item in targets:
		audit_function(item[0], item[1], item[2])

def audit_exact_instructions():
	disasm_range(0x004A74D0, 0x004A75C0, "geometry allocation, configuration, and cache publication")
	disasm_range(0x004A7630, 0x004A77C0, "property lookup failure through the second crash return site")
	disasm_range(0x00A5A040, 0x00A5A140, "first post-attach scene graph operation")
	disasm_range(0x00A5DB40, 0x00A5DC30, "callee containing the invalid virtual dispatch")
	disasm_range(0x00B4E150, 0x00B4E280, "Sphere BSFadeNode initialization")

def audit_ownership_and_dispatch():
	find_refs_to(0x0101EA64, "BGSPrimitiveSphere vtable base")
	find_refs_to(0x0101EA68, "BGSPrimitiveSphere lazy builder vtable slot")
	find_refs_to(0x010A8F90, "BSFadeNode vtable seen in crash object graph")
	print_pointer_table(0x0101EA64, 20, "BGSPrimitiveSphere vtable")
	print_pointer_table(0x010A8F90, 64, "BSFadeNode vtable")

def main():
	write("=" * 70)
	write("BGSPrimitiveSphere CORRUPT CHILD FOLLOW-UP")
	write("=" * 70)
	write("The missing-property guard executed, but the same builder later exposed a Sphere node with CigarettePack-named geometry and reached an invalid virtual target. Determine whether this is concurrent lazy publication, stale cache ownership, or a failed local construction, and identify a safe whole-builder serialization or abort boundary.")
	audit_crash_path()
	audit_exact_instructions()
	audit_ownership_and_dispatch()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_20260713_primitive_corrupt_child_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
