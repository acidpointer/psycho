# @category Analysis
# @description Audit vanilla window helper functions and SetWindowPos callers for plugin-owned fullscreen/borderless state

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
sym_tab = currentProgram.getSymbolTable()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x004DA670: "SetWindowPos caller/window helper A",
	0x004DC360: "SetWindowPos caller/window helper B",
	0x00872570: "SetWindowPos caller/window helper C",
	0x004D75B0: "SetWindowPos caller/window helper D",
	0x004DC1E0: "HWND/render window accessor",
	0x004DC1F0: "render width accessor",
	0x004DC200: "render height accessor",
	0x004DC6E0: "render size update helper",
	0x0086A0A0: "FNV WndProc",
	0x0086AE60: "startup/window creation driver",
	0x0086AF42: "startup CreateWindowExA callsite",
	0x0086B4BF: "main loop regain SetWindowPos",
	0x0086B628: "main loop lose SetWindowPos",
}

TARGETS = [
	0x004DA670,
	0x004DC360,
	0x00872570,
	0x004D75B0,
	0x004DC1E0,
	0x004DC1F0,
	0x004DC200,
	0x004DC6E0,
	0x0086A0A0,
	0x0086AE60,
]

IMPORTS = [
	"CreateWindowExA",
	"AdjustWindowRect",
	"AdjustWindowRectEx",
	"SetWindowPos",
	"MoveWindow",
	"ShowWindow",
	"SetWindowLongA",
	"GetWindowLongA",
	"GetClientRect",
	"GetWindowRect",
	"MonitorFromWindow",
	"GetMonitorInfoA",
	"ChangeDisplaySettingsA",
	"ChangeDisplaySettingsExA",
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

def decompile_at(addr_int, label, max_len=18000):
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
		if count > 140:
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

def print_import_refs(name, limit):
	write("")
	write("-" * 70)
	write("Import/symbol refs: %s" % name)
	write("-" * 70)
	symbols = sym_tab.getSymbols(name)
	total = 0
	while symbols.hasNext():
		sym = symbols.next()
		write("  Symbol %s @ %s" % (sym.getName(), sym.getAddress()))
		refs = ref_mgr.getReferencesTo(sym.getAddress())
		count = 0
		while refs.hasNext():
			ref = refs.next()
			from_func = fm.getFunctionContaining(ref.getFromAddress())
			fname = from_func.getName() if from_func else "???"
			write("    %s @ 0x%08x in %s" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
			count += 1
			total += 1
			if count >= limit:
				write("    ... refs for this symbol truncated")
				break
	write("  Total refs printed: %d" % total)

def print_targets():
	for addr_int in TARGETS:
		label = label_for(addr_int)
		decompile_at(addr_int, label)
		find_and_print_calls_from(addr_int, label)
		find_refs_to(addr_int, label)

def print_imports():
	for name in IMPORTS:
		print_import_refs(name, 80)

def print_patch_windows():
	windows = [
		(0x0086AF42, "startup CreateWindowExA"),
		(0x0086B4BF, "main loop regain SetWindowPos"),
		(0x0086B628, "main loop lose SetWindowPos"),
		(0x004DA670, "window helper A"),
		(0x004DC360, "window helper B"),
		(0x00872570, "window helper C"),
		(0x004D75B0, "window helper D")
	]
	for item in windows:
		disasm_window(item[0], 42, 76, item[1])

def main():
	write("DISPLAY WINDOW HELPER CONTRACT AUDIT")
	write("Goal: find whether vanilla helpers can be reused or must be bypassed for plugin-owned fullscreen/borderless.")
	print_imports()
	print_targets()
	print_patch_windows()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/display_window_helper_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
