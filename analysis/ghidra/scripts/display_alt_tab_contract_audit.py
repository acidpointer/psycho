# @category Analysis
# @description Audit FNV display, fullscreen, window, and alt-tab contracts

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
sym_tab = currentProgram.getSymbolTable()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0086A850: "WinMain / startup driver",
	0x0086A0A0: "FNV WndProc",
	0x0086C160: "OSGlobals constructor candidate",
	0x00871C90: "OSGlobals active/focus state handler",
	0x0086BDF0: "startup focus helper",
	0x0044DDC0: "OSGlobals window getter candidate",
	0x00446E10: "fullscreen predicate",
	0x004DC1F0: "configured width getter",
	0x004DC200: "configured height getter",
	0x011DEA0C: "OSGlobals singleton",
	0x011C73B4: "NiDX9Renderer singleton pointer",
	0x0086B421: "SetWindowPos path: regain focus",
	0x0086B58A: "SetWindowPos path: lose focus",
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
	sym = sym_tab.getPrimarySymbol(toAddr(addr_int))
	if sym is not None:
		return sym.getName()
	return "unknown"

def decompile_at(addr_int, label, max_len=14000):
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
		write("  0x%08x: %-44s%s" % (addr_int, inst.toString(), marker))
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

def print_import_overview():
	names = [
		"FindWindowA",
		"CreateWindowExA",
		"GetActiveWindow",
		"GetForegroundWindow",
		"GetWindowRect",
		"GetWindowLongA",
		"SetWindowLongA",
		"AdjustWindowRect",
		"AdjustWindowRectEx",
		"SetWindowPos",
		"ShowWindow",
		"ChangeDisplaySettingsA",
		"Direct3DCreate9",
		"Direct3DCreate9Ex"
	]
	for name in names:
		print_import_refs(name, 80)

def decompile_targets():
	targets = [
		(0x0086A850, "WinMain / startup driver"),
		(0x0086A0A0, "FNV WndProc"),
		(0x0086C160, "OSGlobals constructor candidate"),
		(0x0044DDC0, "OSGlobals window getter candidate"),
		(0x00446E10, "fullscreen predicate"),
		(0x004DC1F0, "configured width getter"),
		(0x004DC200, "configured height getter"),
		(0x00871C90, "OSGlobals active/focus state handler"),
		(0x0086BDF0, "startup focus helper")
	]
	for item in targets:
		decompile_at(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])

def print_focus_windows():
	windows = [
		(0x0086B2F2, "OSGlobals window getter call before idle loop"),
		(0x0086B421, "fullscreen restore after regain focus"),
		(0x0086B445, "width getter in regain-focus window path"),
		(0x0086B450, "height getter in regain-focus window path"),
		(0x0086B58A, "fullscreen resize after losing focus"),
		(0x0086B5AE, "width getter in lose-focus window path"),
		(0x0086B5B9, "height getter in lose-focus window path"),
		(0x0086A1AB, "WndProc active/focus callsite used by Stewie"),
		(0x0086A99F, "FindWindowA duplicate-instance check")
	]
	for item in windows:
		disasm_window(item[0], 18, 28, item[1])

def print_global_refs():
	find_refs_to(0x011DEA0C, "OSGlobals singleton")
	find_refs_to(0x011C73B4, "NiDX9Renderer singleton pointer")

def main():
	write("DISPLAY ALT-TAB CONTRACT AUDIT")
	write("Goal: verify current display_tweaks assumptions against vanilla window/fullscreen behavior.")
	print_import_overview()
	decompile_targets()
	print_focus_windows()
	print_global_refs()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/display_alt_tab_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
