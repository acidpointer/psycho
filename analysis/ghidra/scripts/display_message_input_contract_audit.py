# @category Analysis
# @description Audit window messages, focus transitions, and input cursor ownership for alt-tab-safe display takeover

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
sym_tab = currentProgram.getSymbolTable()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0086A0A0: "FNV WndProc",
	0x00871C90: "OSGlobals focus active/inactive",
	0x0086A1AB: "WndProc -> focus state callsite",
	0x0086A850: "WinMain/startup driver",
	0x0086BDF0: "startup focus helper",
	0x011DEA0C: "OSGlobals singleton pointer",
}

WINDOW_MESSAGES = {
	0x0001: "WM_CREATE",
	0x0002: "WM_DESTROY",
	0x0003: "WM_MOVE",
	0x0005: "WM_SIZE",
	0x0006: "WM_ACTIVATE",
	0x0007: "WM_SETFOCUS",
	0x0008: "WM_KILLFOCUS",
	0x000F: "WM_PAINT",
	0x0010: "WM_CLOSE",
	0x0018: "WM_SHOWWINDOW",
	0x001C: "WM_ACTIVATEAPP",
	0x0024: "WM_GETMINMAXINFO",
	0x0047: "WM_WINDOWPOSCHANGED",
	0x0086: "WM_NCACTIVATE",
	0x0112: "WM_SYSCOMMAND",
	0x0116: "WM_INITMENU",
	0x0200: "WM_MOUSEMOVE",
	0x0201: "WM_LBUTTONDOWN",
	0x0202: "WM_LBUTTONUP",
	0x020A: "WM_MOUSEWHEEL",
	0x0100: "WM_KEYDOWN",
	0x0101: "WM_KEYUP",
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
		write("  0x%08x: %-48s%s" % (addr_int, inst.toString(), marker))
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

def scan_wndproc_for_message_constants():
	func = fm.getFunctionAt(toAddr(0x0086A0A0))
	if func is None:
		func = fm.getFunctionContaining(toAddr(0x0086A0A0))
	write("")
	write("-" * 70)
	write("WndProc message immediate candidates")
	write("-" * 70)
	if func is None:
		write("  [WndProc not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		for key in WINDOW_MESSAGES.keys():
			needle = "0x%x" % key
			if needle in text:
				write("  0x%08x: %-44s ; %s" % (inst.getAddress().getOffset(), inst.toString(), WINDOW_MESSAGES.get(key)))
				count += 1
				break
	write("  Total candidates: %d" % count)

def print_message_windows():
	targets = [
		(0x0086A1AB, "focus state call from WndProc"),
		(0x0086B08D, "startup focus state call"),
		(0x0086B421, "main loop regain-focus fullscreen branch"),
		(0x0086B58A, "main loop lose-focus fullscreen branch")
	]
	for item in targets:
		disasm_window(item[0], 32, 44, item[1])

def print_input_imports():
	names = [
		"DirectInput8Create",
		"GetCursorPos",
		"SetCursorPos",
		"ClipCursor",
		"ShowCursor",
		"SetCapture",
		"ReleaseCapture",
		"GetCapture",
		"GetActiveWindow",
		"GetForegroundWindow",
		"SetForegroundWindow",
		"DefWindowProcA"
	]
	for name in names:
		print_import_refs(name, 80)

def main():
	write("DISPLAY MESSAGE INPUT CONTRACT AUDIT")
	write("Goal: understand focus/window message and cursor/input ownership before replacing vanilla alt-tab behavior.")
	print_input_imports()
	decompile_at(0x0086A0A0, "FNV WndProc", 22000)
	find_and_print_calls_from(0x0086A0A0, "FNV WndProc")
	decompile_at(0x00871C90, "OSGlobals focus active/inactive", 16000)
	find_and_print_calls_from(0x00871C90, "OSGlobals focus active/inactive")
	scan_wndproc_for_message_constants()
	print_message_windows()
	find_refs_to(0x011DEA0C, "OSGlobals singleton pointer")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/display_message_input_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
