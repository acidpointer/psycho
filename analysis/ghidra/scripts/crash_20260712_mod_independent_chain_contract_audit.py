# @category Analysis
# @description Audit chain-compatible LowProcess vtable wrapping and queued-task holder-release call interception

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
		if count > 80:
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

def print_instruction_range(start_addr, end_addr, label):
	write("")
	write("-" * 70)
	write("%s 0x%08X..0x%08X" % (label, start_addr, end_addr))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_addr))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_addr))
	while inst is not None and inst.getAddress().getOffset() < end_addr:
		off = inst.getAddress().getOffset()
		write("  0x%08X: %-32s ; %s" % (off, byte_text(off, inst.getLength()), inst.toString()))
		inst = inst.getNext()

def print_pointer(addr_int, label):
	value = memory.getInt(toAddr(addr_int)) & 0xFFFFFFFF
	write("  0x%08X %-28s -> 0x%08X" % (addr_int, label, value))

def print_vtable_contract():
	write("")
	write("LowProcess-family vtable slot 0x11F mapping")
	write("  slot byte offset: 0x47C")
	print_pointer(0x01087CE0, "HighProcess + 0x47C")
	print_pointer(0x01088B60, "LowProcess + 0x47C")
	print_pointer(0x010894C8, "MiddleHighProcess + 0x47C")
	print_pointer(0x0108A048, "MiddleLowProcess + 0x47C")
	print_pointer(0x01087864, "HighProcess vtable base")
	print_pointer(0x010886E4, "LowProcess vtable base")
	print_pointer(0x0108904C, "MiddleHigh vtable base")
	print_pointer(0x01089BCC, "MiddleLow vtable base")

def audit_function(addr_int, label, max_len=12000):
	decompile_at(addr_int, label, max_len)
	find_and_print_calls_from(addr_int, label)

def main():
	write("=" * 70)
	write("2026-07-12 MOD-INDEPENDENT CHAIN CONTRACT AUDIT")
	write("=" * 70)
	write("Program: %s" % currentProgram.getName())
	write("Goal: wrap arbitrary partial LowProcess vtable replacements and chain the current queued-task release target.")
	print_vtable_contract()
	print_instruction_range(0x0090CD50, 0x0090CDC0, "Vanilla genericLocationsList removal branch")
	audit_function(0x0090CC10, "Vanilla LowProcess Func011F", 18000)
	audit_function(0x0063F7B0, "List head removal helper", 12000)
	audit_function(0x00905330, "List node removal helper", 12000)
	audit_function(0x006815C0, "tList node data helper", 10000)
	audit_function(0x00726070, "tList next-node helper", 10000)
	print_instruction_range(0x0044CBF0, 0x0044CC10, "Local holder release wrapper")
	audit_function(0x0044CBF0, "Local holder release wrapper", 10000)
	print_instruction_range(0x00446C41, 0x00446C61, "Main consumer dispatch and holder release")
	find_refs_to(0x0044DD60, "General task release")
	find_refs_to(0x0044CBF0, "Local holder release wrapper")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_20260712_mod_independent_chain_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
