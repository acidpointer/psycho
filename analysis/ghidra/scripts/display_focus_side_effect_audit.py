# @category Analysis
# @description Audit focus active/inactive helper side effects for plugin-owned alt-tab handling

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
sym_tab = currentProgram.getSymbolTable()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00871C90: "OSGlobals focus active/inactive",
	0x00408D60: "fullscreen/force-active predicate used by focus state",
	0x007FDF30: "focus subsystem singleton/accessor",
	0x00A237B0: "focus side effect A",
	0x00A23010: "focus side effect B",
	0x00A253D0: "focus side effect C",
	0x00AA5040: "focus active side effect",
	0x00AA50A0: "focus inactive side effect",
	0x00877720: "WndProc active/cursor helper",
	0x00A23C00: "WndProc activate side effect",
	0x00871D10: "mouse move helper",
	0x0086BDF0: "main loop inactive gate",
	0x0078CFC0: "main loop inactive transition",
	0x0078D020: "main loop active transition",
	0x00453A70: "focus manager accessor",
	0x00AD8740: "regain begin",
	0x00AD8700: "lose begin",
	0x00830660: "regain refresh",
	0x00830640: "lose refresh",
	0x00832AD0: "focus update",
	0x00AD7740: "focus end",
}

TARGETS = [
	0x00871C90,
	0x00408D60,
	0x007FDF30,
	0x00A237B0,
	0x00A23010,
	0x00A253D0,
	0x00AA5040,
	0x00AA50A0,
	0x00877720,
	0x00A23C00,
	0x00871D10,
	0x0086BDF0,
	0x0078CFC0,
	0x0078D020,
	0x00453A70,
	0x00AD8740,
	0x00AD8700,
	0x00830660,
	0x00830640,
	0x00832AD0,
	0x00AD7740,
]

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
	sym = sym_tab.getPrimarySymbol(toAddr(addr_int))
	if sym is not None:
		return sym.getName()
	return "unknown"

def decompile_at(addr_int, label, max_len=16000):
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
		if count > 120:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
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
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, label_for(tgt)))
				count += 1
	write("  Total: %d calls" % count)

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
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
		addr_int = inst.getAddress().getOffset()
		marker = " << TARGET" if addr_int == center_int else ""
		write("  0x%08x: %-52s%s" % (addr_int, inst.toString(), marker))
		inst = inst.getNext()
		idx += 1

def print_targets():
	for addr_int in TARGETS:
		label = label_for(addr_int)
		decompile_at(addr_int, label)
		find_and_print_calls_from(addr_int, label)
		find_refs_to(addr_int, label)

def print_callsite_windows():
	windows = [
		(0x0086A1AB, "WndProc focus active call"),
		(0x0086A25B, "WndProc focus inactive call"),
		(0x0086B08D, "startup focus active call"),
		(0x0086B548, "main loop regain sequence"),
		(0x0086B5C9, "main loop lose sequence")
	]
	for item in windows:
		disasm_window(item[0], 32, 52, item[1])

def main():
	write("DISPLAY FOCUS SIDE EFFECT AUDIT")
	write("Goal: identify which vanilla focus side effects must be preserved before replacing window/focus ownership.")
	print_targets()
	print_callsite_windows()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/display_focus_side_effect_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
