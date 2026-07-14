# @category Analysis
# @description Resolve radio path-geometry identity fields and whether they prove coordinate-independent connectivity caching

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

def dump_pointers(start, end, label):
	write("")
	write("-" * 70)
	write("Pointers: %s (0x%08x - 0x%08x)" % (label, start, end))
	write("-" * 70)
	address = start
	while address <= end:
		value = getInt(toAddr(address)) & 0xffffffff
		func = fm.getFunctionAt(toAddr(value))
		name = func.getName() if func else ""
		write("  0x%08x: 0x%08x %s" % (address, value, name))
		address += 4

def audit(addr_int, label, max_len=50000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def main():
	write("RADIO PATH GEOMETRY IDENTITY FOLLOW-UP")
	write("Prove whether geometry fields +0x10, +0x14, +0x18, +0x1C, and +0x20 identify a connected navmesh component strongly enough for radio modes 2/3 to cache connectivity without endpoint coordinates. Also identify graph mutation or generation state required for invalidation.")
	dump_pointers(0x0102583C, 0x01025880, "path geometry vtable")
	audit(0x005C3420, "path geometry coordinate accessor", 40000)
	audit(0x006D6F40, "geometry identity lookup from cell", 60000)
	audit(0x006D6F60, "geometry identity lookup from worldspace and grid", 60000)
	audit(0x00587410, "geometry field 0x20 conversion", 50000)
	audit(0x00587440, "worldspace grid lookup from coordinates", 50000)
	audit(0x006DCFE0, "single-connection state selector", 50000)
	audit(0x006F3E30, "path search seed lookup", 70000)
	audit(0x006F3FB0, "path search execution", 90000)
	audit(0x006F4230, "path result extraction", 70000)
	audit(0x006F4390, "path search seed insertion", 50000)
	audit(0x006F48B0, "path result object constructor", 40000)
	audit(0x006F49C0, "path result distance consumer", 50000)
	find_refs_to(0x011C8264, "radio scan list root")
	find_refs_to(0x011DD554, "registered radio list root")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/radio_path_geometry_identity_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
