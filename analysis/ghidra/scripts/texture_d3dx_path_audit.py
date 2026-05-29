# @category Analysis
# @description Audit D3DX texture import thunks and texture creation call paths

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

def label_for(addr_int):
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
		if count > 100:
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

def print_thunk(addr_int, label):
	write("")
	write("=" * 70)
	write("IMPORT THUNK: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	disasm_window(addr_int, 2, 4, label)
	find_refs_to(addr_int, label)

def print_callsite(addr_int, label):
	write("")
	write("=" * 70)
	write("D3DX CALLSITE: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	inst = listing.getInstructionAt(toAddr(addr_int))
	if inst is None:
		write("  [instruction not found]")
		return
	write("  Instruction: %s" % inst.toString())
	refs = inst.getReferencesFrom()
	for ref in refs:
		if ref.getReferenceType().isCall():
			target = ref.getToAddress().getOffset()
			write("  CALL target: 0x%08x %s" % (target, label_for(target)))
	disasm_window(addr_int, 10, 18, label)

def print_d3dx_overview():
	imports = [
		"D3DXGetImageInfoFromFileInMemory",
		"D3DXCreateTextureFromFileInMemory",
		"D3DXCreateTextureFromFileInMemoryEx",
		"D3DXCreateCubeTextureFromFileInMemory",
		"D3DXCreateVolumeTextureFromFileInMemory",
		"D3DXCreateTextureFromFileA",
		"D3DXCreateCubeTextureFromFileA",
		"D3DXCreateVolumeTextureFromFileA"
	]
	for name in imports:
		print_import_refs(name, 30)

def print_thunks_and_callsites():
	thunks = [
		(0x00ee6e22, "D3DXGetImageInfoFromFileInMemory"),
		(0x00ee6e1c, "D3DXCreateTextureFromFileInMemory"),
		(0x00ee6e16, "D3DXCreateCubeTextureFromFileInMemory"),
		(0x00ee6e10, "D3DXCreateVolumeTextureFromFileInMemory")
	]
	callsites = [
		(0x00e68bcd, "image info"),
		(0x00e68dcd, "2D texture create"),
		(0x00e68df3, "cube texture create"),
		(0x00e68e18, "volume texture create")
	]
	for item in thunks:
		print_thunk(item[0], item[1])
	for item in callsites:
		print_callsite(item[0], item[1])

def print_stewie_related():
	write("")
	write("=" * 70)
	write("STEWIE-COMPATIBLE PATCH SURFACES")
	write("=" * 70)
	write("Stewie source patches 0x00E68DCD for bDontMirrorTexturesInRAM and 0x00E68BA9 for zeroing.")
	disasm_window(0x00e68ba9, 8, 14, "texture zeroing callsite")
	disasm_window(0x00e68dcd, 8, 14, "texture create callsite")
	disasm_window(0x00e68df3, 8, 14, "cube create callsite")
	disasm_window(0x00e68e18, 8, 14, "volume create callsite")

def main():
	write("=" * 70)
	write("D3DX TEXTURE PATH AUDIT")
	write("=" * 70)
	write("Goal: explain why runtime create probes may not count while image-info does.")
	decompile_at(0x00e68a80, "NiDX9SourceTextureData texture load")
	find_and_print_calls_from(0x00e68a80, "NiDX9SourceTextureData texture load")
	print_d3dx_overview()
	print_thunks_and_callsites()
	print_stewie_related()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/texture_d3dx_path_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
