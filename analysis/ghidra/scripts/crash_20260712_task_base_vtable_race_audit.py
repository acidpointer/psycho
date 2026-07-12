# @category Analysis
# @description Audit the 2026-07-12 main-thread queued-task dispatch through a zero-refcount base NiRefObject vtable

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()
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

def disasm_around(addr_int, label, before_count=34, after_count=42):
	write("")
	write("-" * 70)
	write("Disassembly around %s 0x%08x" % (label, addr_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(addr_int))
	if inst is None:
		inst = listing.getInstructionBefore(toAddr(addr_int))
	count = 0
	while inst is not None and count < before_count:
		prev = inst.getPrevious()
		if prev is None:
			break
		inst = prev
		count += 1
	printed = 0
	limit = before_count + after_count + 1
	while inst is not None and printed < limit:
		off = inst.getAddress().getOffset()
		marker = "=>" if off == addr_int else "  "
		write("%s 0x%08x: %s" % (marker, off, inst.toString()))
		inst = inst.getNext()
		printed += 1

def audit_function(addr_int, label, max_len=16000):
	decompile_at(addr_int, label, max_len)
	find_and_print_calls_from(addr_int, label)

def main():
	write("=" * 70)
	write("2026-07-12 TASK BASE-VTABLE RACE AUDIT")
	write("=" * 70)
	write("Crash: EIP=0x64492067 from CALL [task->vtable+0x1C] at 0x00446C53.")
	write("Task=0xBB7CF740, vtable=0x0101DCE4 (NiRefObject), refcount=0.")
	write("The bad target is ASCII at base-vtable+0x1C, not executable code.")
	write("Questions: which queue owns the reference, where is its increment paired, and can pop race final release?")
	disasm_around(0x00446C53, "main-thread indirect task dispatch")
	disasm_around(0x0094CFD6, "main-loop caller")
	audit_function(0x00446B50, "queue consumer and virtual dispatcher", 20000)
	audit_function(0x00906570, "TaskStack queue pop helper", 20000)
	audit_function(0x0044CC10, "TaskStack constructor", 12000)
	audit_function(0x0044CBF0, "local holder release wrapper", 12000)
	audit_function(0x0044DD60, "task refcount release", 14000)
	audit_function(0x0092C820, "task refcount increment helper", 12000)
	audit_function(0x00528CB0, "local holder initialization", 10000)
	audit_function(0x006F74F0, "holder assignment and retain", 14000)
	audit_function(0x00449090, "derived task constructor", 14000)
	audit_function(0x004490E0, "derived task constructor variant", 14000)
	audit_function(0x00C3C620, "IO task base/derived lifecycle helper", 18000)
	find_refs_to(0x00906570, "TaskStack pop helper")
	find_refs_to(0x0101DCE4, "base NiRefObject vtable")
	find_refs_to(0x01017138, "expected queued model task vtable")
	find_refs_to(0x0044DD60, "task release")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_20260712_task_base_vtable_race_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
