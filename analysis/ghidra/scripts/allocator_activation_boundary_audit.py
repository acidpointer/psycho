# @category Analysis
# @description Establish engine startup, heap construction, thread creation, and allocator activation boundaries

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

def print_program_identity():
	write("# PROGRAM IDENTITY")
	write("Name: %s" % currentProgram.getName())
	write("Executable path: %s" % currentProgram.getExecutablePath())
	write("Executable format: %s" % currentProgram.getExecutableFormat())
	write("Image base: %s" % currentProgram.getImageBase())
	write("Minimum address: %s" % currentProgram.getMinAddress())
	write("Maximum address: %s" % currentProgram.getMaxAddress())
	write("Language: %s" % currentProgram.getLanguageID())
	write("Compiler: %s" % currentProgram.getCompilerSpec().getCompilerSpecID())

def print_external_entry_points():
	write("")
	write("# PE EXTERNAL ENTRY POINTS")
	entries = sym_tab.getExternalEntryPointIterator()
	count = 0
	while entries.hasNext():
		addr = entries.next()
		func = fm.getFunctionAt(addr)
		name = func.getName() if func else "???"
		write("  %s %s" % (addr, name))
		count += 1
	write("  Total: %d" % count)

def print_named_symbol_refs(name, limit=160):
	write("")
	write("-" * 70)
	write("SYMBOL REFERENCES: %s" % name)
	write("-" * 70)
	symbols = sym_tab.getSymbols(name)
	symbol_count = 0
	ref_count = 0
	while symbols.hasNext():
		symbol = symbols.next()
		symbol_count += 1
		write("  Symbol %s @ %s, type=%s" % (symbol.getName(), symbol.getAddress(), symbol.getSymbolType()))
		refs = ref_mgr.getReferencesTo(symbol.getAddress())
		while refs.hasNext():
			ref = refs.next()
			owner = fm.getFunctionContaining(ref.getFromAddress())
			owner_name = owner.getName() if owner else "???"
			write("    %s @ %s in %s" % (ref.getReferenceType(), ref.getFromAddress(), owner_name))
			ref_count += 1
			if ref_count >= limit:
				write("    ... references truncated at %d" % limit)
				write("  Symbols: %d, refs printed: %d" % (symbol_count, ref_count))
				return
	write("  Symbols: %d, refs printed: %d" % (symbol_count, ref_count))

def print_symbol_family(names):
	for name in names:
		print_named_symbol_refs(name)

def print_disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("DISASSEMBLY WINDOW: %s @ 0x%08x" % (label, center_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionContaining(toAddr(center_int))
	if inst is None:
		write("  [instruction not found]")
		return
	back = 0
	while back < before_count:
		previous = inst.getPrevious()
		if previous is None:
			break
		inst = previous
		back += 1
	count = 0
	limit = before_count + after_count + 1
	while inst is not None and count < limit:
		addr_int = inst.getAddress().getOffset()
		marker = " << TARGET" if addr_int == center_int else ""
		write("  0x%08x: %-48s%s" % (addr_int, inst.toString(), marker))
		inst = inst.getNext()
		count += 1

def audit_function(addr_int, label, max_len=18000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def audit_functions(items):
	for item in items:
		audit_function(item[0], item[1], item[2])

def main():
	write("ALLOCATOR ACTIVATION BOUNDARY AUDIT")
	write("=" * 70)
	write("Questions:")
	write("  1. Does HeapSingleton construction precede WinMain and normal engine startup?")
	write("  2. Which engine-owned worker threads can allocate before the main loop?")
	write("  3. Is DirectInput initialization a usable post-loader-lock synchronization boundary?")
	write("  4. Which boundaries are observation points only and which can safely own activation?")
	write("  Note: xNVSE and proxy DLL ordering is external to the vanilla executable and")
	write("  must be combined with source/runtime evidence; this script proves engine order only.")
	write("")
	print_program_identity()
	print_external_entry_points()
	write("")
	write("# PE ENTRY AND CRT INITIALIZER DISPATCH")
	entry_functions = [
		(0x00FDE590, "PE entry point", 24000),
		(0x00ECC46B, "CRT startup containing the WinMain call", 30000),
		(0x00ECCD6B, "CRT initialization containing the initterm call", 22000),
		(0x00ECCCD3, "CRT initializer table dispatcher __initterm", 16000)
	]
	audit_functions(entry_functions)
	find_refs_to(0x00FDF4C4, "CRT initializer table slot containing HeapSingleton wrapper")
	print_disasm_window(0x00ECC46B, 24, 16, "CRT transition into WinMain")
	print_disasm_window(0x00ECCD6B, 24, 16, "CRT global initializer table dispatch")
	write("")
	write("# CRT AND GLOBAL INITIALIZER CHAIN")
	crt_functions = [
		(0x00FB66A0, "HeapSingleton CRT global initializer wrapper", 10000),
		(0x00AA3880, "HeapSingleton constructor", 24000),
		(0x00AA39C0, "HeapSingleton initialization gate", 14000),
		(0x00866E00, "Default File and Static heap construction", 24000),
		(0x00866690, "early SBM singleton initializer", 18000),
		(0x00AA2020, "SBM singleton cell allocation", 14000)
	]
	audit_functions(crt_functions)
	write("")
	write("# WINMAIN AND FIRST ENGINE SUBSYSTEMS")
	startup_functions = [
		(0x0086A850, "WinMain startup driver", 50000),
		(0x00A22660, "DirectInput owner and input subsystem construction", 30000),
		(0x008705D0, "post-render main-loop maintenance", 22000),
		(0x00868850, "per-frame queue drain", 26000)
	]
	audit_functions(startup_functions)
	print_disasm_window(0x0086A850, 0, 80, "WinMain entry and earliest direct calls")
	print_disasm_window(0x00A22784, 12, 22, "DirectInput creation call family A")
	print_disasm_window(0x00A229AB, 12, 22, "DirectInput creation call family B")
	write("")
	write("# THREAD CREATION OWNERS")
	thread_functions = [
		(0x00C42DD0, "BSTaskThread constructor and suspended CreateThread", 24000),
		(0x00C3E4F0, "BSTaskManager constructor", 30000),
		(0x00C3EE70, "BSTaskManagerThread constructor", 14000),
		(0x00EC16D0, "MoviePlayer thread constructor", 18000),
		(0x009FE780, "CreateThread owner 009FE780", 20000),
		(0x00EC1940, "CreateThread owner 00EC1940", 20000),
		(0x00B01D50, "CreateThread owner 00B01D50", 26000),
		(0x00D87940, "CreateThread owner 00D87940", 20000),
		(0x00AA6430, "CreateThread owner 00AA6430", 24000),
		(0x00C410B0, "BSTaskManagerThread worker loop", 26000),
		(0x00C42DA0, "BSTaskThread start procedure", 14000),
		(0x00EC16B0, "MoviePlayer start procedure", 14000)
	]
	audit_functions(thread_functions)
	write("")
	write("# IMPORT AND CRT STARTUP SYMBOL EVIDENCE")
	print_symbol_family([
		"WinMain",
		"WinMainCRTStartup",
		"mainCRTStartup",
		"_initterm",
		"__initterm",
		"CreateThread",
		"_beginthreadex",
		"beginthreadex",
		"ResumeThread",
		"DirectInput8Create"
	])
	write("")
	write("# KEY OWNERSHIP REFERENCES")
	find_refs_to(0x00FB66A0, "HeapSingleton CRT initializer wrapper")
	find_refs_to(0x00AA3880, "HeapSingleton constructor")
	find_refs_to(0x0086A850, "WinMain startup driver")
	find_refs_to(0x00A22660, "DirectInput owner")
	find_refs_to(0x00C42DD0, "BSTaskThread constructor")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/memory/allocator_activation_boundary_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
