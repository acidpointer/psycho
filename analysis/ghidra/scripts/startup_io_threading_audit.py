# @category Analysis
# @description Audit startup IO/model loader threading and worker-count patch sites

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
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

def disasm_window(addr_int, label, before=32, after=80):
	start = addr_int - before
	end = addr_int + after
	write("")
	write("-" * 70)
	write("Disassembly %s: 0x%08x - 0x%08x" % (label, start, end))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start))
	while inst is not None and inst.getAddress().getOffset() <= end:
		a = inst.getAddress().getOffset()
		marker = ""
		if a == addr_int:
			marker = " << TARGET"
		call_info = ""
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				call_info = " -> %s" % name
		write("  0x%08x: %s%s%s" % (a, inst, call_info, marker))
		inst = inst.getNext()

def byte_dump(addr_int, count, label):
	write("")
	write("-" * 70)
	write("Bytes %s @ 0x%08x (%d bytes)" % (label, addr_int, count))
	write("-" * 70)
	idx = 0
	line = []
	while idx < count:
		b = memory.getByte(toAddr(addr_int + idx)) & 0xff
		line.append("%02X" % b)
		if len(line) == 16:
			write("  0x%08x: %s" % (addr_int + idx - 15, " ".join(line)))
			line = []
		idx += 1
	if len(line) > 0:
		write("  0x%08x: %s" % (addr_int + count - len(line), " ".join(line)))

def print_sites():
	sites = [
		(0x00C3DA50, "IOManager constructor wrapper"),
		(0x00C3E4F0, "BSTaskManager constructor creates worker threads"),
		(0x00C3EE70, "BSTaskManagerThread constructor"),
		(0x00C42DD0, "BSTaskThread init creates suspended thread"),
		(0x00C42F50, "BSTaskThread start/resume"),
		(0x00C410B0, "BSTaskManagerThread loop"),
		(0x00C3F7A0, "IOTask submit/TLS queue helper"),
		(0x00C40E70, "IO dequeue under queue lock"),
		(0x00C3DBF0, "Main-thread completed task processing"),
		(0x00C3DFA0, "ModelLoader/IO drain wait loop")
	]
	for item in sites:
		decompile_at(item[0], item[1], 10000)
		disasm_window(item[0], item[1])
		find_refs_to(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])

def print_patch_focus():
	write("")
	write("=" * 70)
	write("PATCH FOCUS")
	write("=" * 70)
	write("Known decompile target: IOManager_Create calls BSTaskManager_ctor(this, 10, 1, 0x78).")
	write("The third argument is the worker thread count used by BSTaskManager_ctor.")
	write("Confirm exact push/immediate below before changing 1 -> 2.")
	byte_dump(0x00C3DA50, 160, "IOManager_Create")
	disasm_window(0x00C3DA50, "IOManager_Create", 0, 160)

def main():
	write("=" * 70)
	write("STARTUP IO THREADING AUDIT")
	write("=" * 70)
	print_patch_focus()
	print_sites()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/startup_io_threading_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
