# @category Analysis
# @description Audit FNV startup fullscreen/borderless setting and D3D device creation contract

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00C44280: "INISettingCollection::ReadSetting",
	0x00446E10: "fullscreen predicate",
	0x00408D60: "setting value pointer helper",
	0x011C77B4: "bFull Screen:Display setting object",
	0x011C77B8: "bFull Screen:Display setting value",
	0x0086AF04: "startup CreateWindow style immediate",
	0x0086AF2F: "startup CreateWindow visible style immediate",
	0x00E731FF: "NiDX9Renderer CreateDevice vtable call",
	0x00E73204: "NiDX9Renderer CreateDevice return",
}

def write(msg):
	output.append(msg)
	print(msg)

def label_for(addr_int):
	label = KNOWN.get(addr_int)
	if label is not None:
		return label
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is not None:
		return func.getName()
	func = fm.getFunctionContaining(toAddr(addr_int))
	if func is not None:
		return "%s+0x%x" % (func.getName(), addr_int - func.getEntryPoint().getOffset())
	return "unknown"

def decompile_at(addr_int, label, max_len=12000):
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
		if count > 80:
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
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, label_for(tgt)))
				count += 1
	write("  Total: %d calls" % count)

def disasm_range(start, end, label):
	write("")
	write("-" * 70)
	write("%s 0x%08x-0x%08x" % (label, start, end))
	write("-" * 70)
	addr = toAddr(start)
	while addr.getOffset() <= end:
		inst = listing.getInstructionAt(addr)
		if inst is None:
			addr = addr.add(1)
			continue
		marker = ""
		if KNOWN.get(inst.getAddress().getOffset()) is not None:
			marker = " ; " + KNOWN.get(inst.getAddress().getOffset())
		write("  0x%08x: %-48s%s" % (inst.getAddress().getOffset(), inst.toString(), marker))
		addr = inst.getAddress().add(inst.getLength())

def print_setting_contract():
	decompile_at(0x00C44280, "INISettingCollection::ReadSetting")
	decompile_at(0x00446E10, "fullscreen predicate")
	decompile_at(0x00408D60, "setting value pointer helper")
	find_and_print_calls_from(0x00446E10, "fullscreen predicate")
	find_refs_to(0x011C77B4, "bFull Screen:Display setting object")
	find_refs_to(0x011C77B8, "bFull Screen:Display setting value")

def print_startup_patch_sites():
	disasm_range(0x0086AEE0, 0x0086AF50, "startup window creation style setup")
	disasm_range(0x00E731D8, 0x00E73208, "D3D9 CreateDevice callsite")
	decompile_at(0x00E72E60, "NiDX9Renderer device initialization", 16000)

def main():
	write("DISPLAY BORDERLESS STARTUP AUDIT")
	write("Goal: verify whether forcing bFull Screen false plus popup window styles prevents exclusive fullscreen startup.")
	print_setting_contract()
	print_startup_patch_sites()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/display_borderless_startup_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
