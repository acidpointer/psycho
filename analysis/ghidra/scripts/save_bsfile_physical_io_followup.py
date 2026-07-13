# @category Analysis
# @description Resolve FalloutNV save-file open, read, write, close, flush, short-count, and OS error propagation contracts

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
symbol_table = currentProgram.getSymbolTable()
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
		if count > 120:
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
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
	write("  Total: %d calls" % count)

def disasm_range(start_int, end_int, label):
	write("")
	write("-" * 70)
	write("Disassembly: %s (0x%08x - 0x%08x)" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	while inst is not None and inst.getAddress().getOffset() <= end_int:
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()

def audit_function(addr_int, label, max_len=24000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def print_data_refs_from(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("-" * 70)
	write("Data references FROM %s (0x%08x)" % (label, addr_int))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isData():
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), ref.getToAddress().getOffset(), ref.getReferenceType()))
				count += 1
	write("  Total: %d data refs" % count)

def find_named_api_refs():
	names = [
		"CreateFileA",
		"ReadFile",
		"WriteFile",
		"FlushFileBuffers",
		"SetEndOfFile",
		"CloseHandle",
		"GetLastError",
		"MoveFileA",
		"DeleteFileA",
	]
	for name in names:
		write("")
		write("-" * 70)
		write("Symbols and references for %s" % name)
		write("-" * 70)
		symbols = symbol_table.getSymbols(name)
		count = 0
		for symbol in symbols:
			addr = symbol.getAddress()
			write("  Symbol %s @ %s" % (symbol.getName(True), addr))
			refs = ref_mgr.getReferencesTo(addr)
			while refs.hasNext():
				ref = refs.next()
				from_func = fm.getFunctionContaining(ref.getFromAddress())
				fname = from_func.getName() if from_func else "???"
				write("    %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
				count += 1
		write("  Total references: %d" % count)

def audit_targets():
	targets = [
		(0x0044E120, "underlying physical write primitive", 32000),
		(0x00462DC0, "underlying physical read primitive", 32000),
		(0x00B00260, "BSFile constructor and OS handle open", 36000),
		(0x00846330, "BGSSaveLoadFile write wrapper", 18000),
		(0x00846300, "BGSSaveLoadFile read wrapper", 18000),
		(0x008462C0, "BGSSaveLoadFile destruction and close dispatch", 18000),
		(0x008463C0, "BGSSaveLoadFile open-status dispatch", 18000),
		(0x00845E50, "changed-record payload physical read and count", 26000),
		(0x00473180, "save staging-buffer append to physical writer", 22000),
		(0x00850100, "save close and promotion owner", 30000),
	]
	for item in targets:
		audit_function(item[0], item[1], item[2])

def audit_contract_disassembly():
	disasm_range(0x0044E120, 0x0044E2A0, "physical write count and failure branches")
	disasm_range(0x00462DC0, 0x00462E90, "physical read count and failure branches")
	disasm_range(0x00B00260, 0x00B00580, "BSFile construction, vtable, and handle state")
	disasm_range(0x008462C0, 0x008463F0, "BGSSaveLoadFile close, read, write, and status wrappers")
	print_data_refs_from(0x00B00260, "BSFile constructor")
	print_data_refs_from(0x0044E120, "physical write primitive")

def main():
	write("=" * 70)
	write("SAVE PHYSICAL FILE I/O FOLLOW-UP")
	write("=" * 70)
	write("Questions: can short writes, flush/close errors, and OS failures reach the save transaction owner, and which concrete BSFile methods own that state?")
	audit_targets()
	audit_contract_disassembly()
	find_named_api_refs()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/save_bsfile_physical_io_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
