# @category Analysis
# @description Audit D3D9 device creation/reset/present lifecycle for robust alt-tab handling

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
sym_tab = currentProgram.getSymbolTable()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00E72E60: "NiDX9Renderer device initialization",
	0x00E6BF50: "D3DPRESENT_PARAMETERS builder",
	0x00E6C240: "D3D post-create/backbuffer validation",
	0x00E731FF: "IDirect3D9/CreateDevice callsite",
	0x00E73204: "CreateDevice return",
	0x0126F0D8: "Direct3D9 interface/global candidate",
	0x0126F0D0: "Direct3D9Ex mode flag candidate",
	0x011C73B4: "NiDX9Renderer singleton pointer",
	0x00A62030: "Texture cache pre-reset",
	0x00A62090: "Texture cache reset",
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

def scan_function_for_vtable_offsets(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("-" * 70)
	write("Vtable-call candidates in %s (0x%08x)" % (label, addr_int))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	offsets = ["+ 0xc", "+ 0x10", "+ 0x14", "+ 0x34", "+ 0x40", "+ 0x44", "+ 0x48", "+ 0x50"]
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		found = False
		for off in offsets:
			if off in text:
				found = True
		if found:
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
			count += 1
			if count > 160:
				write("  ... (truncated)")
				break
	write("  Total candidates: %d" % count)

def print_d3d_imports():
	names = [
		"Direct3DCreate9",
		"Direct3DCreate9Ex",
		"D3DPERF_BeginEvent",
		"D3DPERF_EndEvent"
	]
	for name in names:
		print_import_refs(name, 80)

def print_d3d_core():
	targets = [
		(0x00E72E60, "NiDX9Renderer device initialization"),
		(0x00E6BF50, "D3DPRESENT_PARAMETERS builder"),
		(0x00E6C240, "D3D post-create/backbuffer validation"),
		(0x00A62030, "Texture cache pre-reset"),
		(0x00A62090, "Texture cache reset")
	]
	for item in targets:
		decompile_at(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])
		scan_function_for_vtable_offsets(item[0], item[1])

def print_device_windows():
	windows = [
		(0x00E731FF, "IDirect3D9 CreateDevice callsite"),
		(0x00E73204, "CreateDevice return and HRESULT handling")
	]
	for item in windows:
		disasm_window(item[0], 36, 48, item[1])

def print_globals():
	find_refs_to(0x0126F0D8, "Direct3D9 interface/global candidate")
	find_refs_to(0x0126F0D0, "Direct3D9Ex mode flag candidate")
	find_refs_to(0x011C73B4, "NiDX9Renderer singleton pointer")

def main():
	write("DISPLAY D3D DEVICE LIFECYCLE AUDIT")
	write("Goal: identify the safe plugin-owned layer for device lost/reset and fullscreen/windowed present params.")
	print_d3d_imports()
	print_d3d_core()
	print_device_windows()
	print_globals()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/display_d3d_device_lifecycle_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
