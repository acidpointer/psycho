# @category Analysis
# @description Audit vanilla SetWindowPos argument order in fullscreen focus paths

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
sym_tab = currentProgram.getSymbolTable()
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
				write("  0x%08x -> 0x%08x" % (inst.getAddress().getOffset(), tgt))
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

def print_setwindowpos_refs():
	write("")
	write("=" * 70)
	write("SetWindowPos import refs")
	write("=" * 70)
	symbols = sym_tab.getSymbols("SetWindowPos")
	total = 0
	while symbols.hasNext():
		sym = symbols.next()
		write("Symbol %s @ %s" % (sym.getName(), sym.getAddress()))
		refs = ref_mgr.getReferencesTo(sym.getAddress())
		while refs.hasNext():
			ref = refs.next()
			from_addr = ref.getFromAddress().getOffset()
			from_func = fm.getFunctionContaining(ref.getFromAddress())
			fname = from_func.getName() if from_func else "???"
			write("  %s @ 0x%08x in %s" % (ref.getReferenceType(), from_addr, fname))
			disasm_window(from_addr, 14, 5, "SetWindowPos call")
			total += 1
	write("Total SetWindowPos refs: %d" % total)

def print_known_focus_windows():
	windows = [
		(0x0086B421, "regain-focus fullscreen SetWindowPos path"),
		(0x0086B58A, "lose-focus fullscreen SetWindowPos path")
	]
	for item in windows:
		disasm_window(item[0], 24, 34, item[1])

def main():
	write("DISPLAY SETWINDOWPOS ARGUMENT AUDIT")
	write("Goal: verify x/y/cx/cy/flags pushed by vanilla fullscreen focus paths.")
	decompile_at(0x0086A850, "WinMain / startup driver", 12000)
	find_and_print_calls_from(0x0086A850, "WinMain / startup driver")
	print_setwindowpos_refs()
	print_known_focus_windows()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/display_setwindowpos_arg_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
