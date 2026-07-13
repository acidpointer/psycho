# @category Analysis
# @description Follow FalloutNV save bytes from staging buffers through file I/O, close, backup rotation, and temporary-file promotion

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
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

def audit_function(addr_int, label, max_len=20000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def audit_targets():
	targets = [
		(0x0084D4B0, "FO3SAVEGAME file activation and initial write", 32000),
		(0x0084D8C0, "FO3SAVEGAME physical-file validation path A", 26000),
		(0x0084DAB0, "FO3SAVEGAME physical-file validation path B", 26000),
		(0x008461E0, "BGSSaveLoadFile constructor and underlying file open", 24000),
		(0x008462C0, "BGSSaveLoadFile destructor and underlying file close", 20000),
		(0x008463C0, "BGSSaveLoadFile post-construction result", 14000),
		(0x008464F0, "BGSSaveLoadFile path or manager transfer", 16000),
		(0x00845D00, "save stream write entry", 18000),
		(0x00845D80, "save stream changed-record write", 24000),
		(0x00865C80, "changed-record physical write owner", 22000),
		(0x00473180, "shared save staging-buffer append", 20000),
		(0x00424940, "BGSSaveLoadFile write sizing-mode predicate", 14000),
		(0x0047C850, "save header sizing-mode predicate", 14000),
		(0x00462D80, "raw save file read primitive", 20000),
		(0x00857BD0, "typed load read accounting", 18000),
		(0x00864820, "changed-record load buffer read", 22000),
		(0x00850030, "temporary save file factory", 22000),
		(0x00850100, "close, backup rotation, and temporary promotion", 30000),
		(0x00850330, "BGSSaveLoadFile destroy wrapper", 14000),
		(0x00EC862C, "CRT rename implementation used by save promotion", 22000),
		(0x00456A20, "save file existence or accessibility query", 18000),
	]
	for item in targets:
		audit_function(item[0], item[1], item[2])

def audit_callsites():
	disasm_range(0x0084D4C0, 0x0084D860, "initial save header writes and result handling")
	disasm_range(0x008461E0, 0x00846330, "BGSSaveLoadFile open and close ownership")
	disasm_range(0x00845D70, 0x00845E00, "changed-record write result handling")
	disasm_range(0x00850070, 0x008500F0, "temporary file deletion and open result")
	disasm_range(0x00850140, 0x00850320, "close, backup rotation, and promotion result handling")

def main():
	write("=" * 70)
	write("SAVE I/O AND COMMIT ERROR FOLLOW-UP")
	write("=" * 70)
	write("Questions: which byte counts are checked, whether close can fail, and whether any failed rename can still be reported as a successful save.")
	audit_targets()
	audit_callsites()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/save_io_commit_error_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
