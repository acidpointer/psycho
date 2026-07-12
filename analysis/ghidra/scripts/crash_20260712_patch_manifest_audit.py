# @category Analysis
# @description Emit exact FalloutNV 1.4.0.525 bytes and call targets required by the 2026-07-12 engine-fix patch manifest

from ghidra.app.decompiler import DecompInterface
from jarray import zeros

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()
memory = currentProgram.getMemory()
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

def byte_text(addr_int, size):
	data = zeros(size, "b")
	read = memory.getBytes(toAddr(addr_int), data)
	if read != size:
		return "[read %d of %d bytes]" % (read, size)
	parts = []
	for value in data:
		parts.append("%02X" % (value & 0xFF))
	return " ".join(parts)

def print_range(addr_int, size, label):
	write("")
	write("%s" % label)
	write("  range: 0x%08X..0x%08X (%d bytes)" % (addr_int, addr_int + size, size))
	write("  bytes: %s" % byte_text(addr_int, size))

def print_instruction_span(start_addr, end_addr, label):
	write("")
	write("%s instructions" % label)
	inst = listing.getInstructionAt(toAddr(start_addr))
	while inst is not None and inst.getAddress().getOffset() < end_addr:
		off = inst.getAddress().getOffset()
		length = inst.getLength()
		write("  0x%08X: %-32s ; %s" % (off, byte_text(off, length), inst.toString()))
		inst = inst.getNext()

def print_pointer(addr_int, label):
	value = memory.getInt(toAddr(addr_int)) & 0xFFFFFFFF
	write("  0x%08X %-38s -> 0x%08X" % (addr_int, label, value))

def print_manifest():
	write("=" * 70)
	write("2026-07-12 ENGINE-FIX PATCH MANIFEST AUDIT")
	write("=" * 70)
	write("Program: %s" % currentProgram.getName())
	write("Language: %s" % currentProgram.getLanguageID())
	write("Compiler: %s" % currentProgram.getCompilerSpec().getCompilerSpecID())
	print_range(0x009105BF, 5, "LowProcess genericLocationsList AppendRefID call")
	print_instruction_span(0x009105B6, 0x009105CD, "LowProcess save-call context")
	print_range(0x0094CFD6, 5, "Main-loop task-drain call")
	print_instruction_span(0x0094CFCE, 0x0094CFE5, "Main-loop late-boundary context")
	print_range(0x00446C48, 13, "Queued-task virtual dispatch replacement block")
	print_instruction_span(0x00446C41, 0x00446C61, "Queued-task dispatch context")
	print_range(0x0044DD60, 24, "General task-release prologue")
	print_range(0x0090CC10, 64, "Vanilla LowProcess Func011F signature prefix")
	write("")
	write("LowProcess vanilla vtable pointers")
	print_pointer(0x01087CE0, "LowProcess")
	print_pointer(0x01088B60, "MiddleLowProcess")
	print_pointer(0x010894C8, "MiddleHighProcess")
	print_pointer(0x0108A048, "HighProcess")
	decompile_at(0x00910450, "LowProcess serializer", 12000)
	find_and_print_calls_from(0x00910450, "LowProcess serializer")
	decompile_at(0x00446B50, "Main-thread task consumer", 14000)
	find_and_print_calls_from(0x00446B50, "Main-thread task consumer")
	decompile_at(0x0044DD60, "General task release", 10000)
	find_and_print_calls_from(0x0044DD60, "General task release")
	find_refs_to(0x0090CC10, "vanilla LowProcess Func011F")

def main():
	print_manifest()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_20260712_patch_manifest_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
