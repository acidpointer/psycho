# @category Analysis
# @description Audit stress-test crash EIP=0x64492067 from CreateQueuedCharacter indirect call

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()
mem = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def func_for(addr_int):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	return func

def name_for_func(func):
	if func is None:
		return "???"
	return "%s @ 0x%08x" % (func.getName(), func.getEntryPoint().getOffset())

def label_for_addr(addr_int):
	func = func_for(addr_int)
	if func is None:
		return "0x%08x ???" % addr_int
	return "0x%08x %s" % (addr_int, name_for_func(func))

def decompile_at(addr_int, label, max_len=10000):
	addr = toAddr(addr_int)
	func = func_for(addr_int)
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
		if len(code) > max_len:
			write("  [decompile truncated at %d chars]" % max_len)
	else:
		write("  [decompilation failed]")

def find_refs_to(addr_int, label, limit=80):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		faddr = from_func.getEntryPoint().getOffset() if from_func else 0
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s @ 0x%08x)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, faddr))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def find_and_print_calls_from(addr_int, label, limit=180):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Calls FROM %s (0x%08x)" % (label, addr_int))
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
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("  0x%08x -> %s" % (inst.getAddress().getOffset(), label_for_addr(tgt)))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def disasm_window(start_int, length, label, highlights, max_inst=160):
	end_int = start_int + length
	write("")
	write("-" * 70)
	write("Disassembly: %s 0x%08x..0x%08x" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	count = 0
	while inst is not None and inst.getAddress().getOffset() < end_int:
		off = inst.getAddress().getOffset()
		mark = "   "
		for item in highlights:
			if off == item:
				mark = "=> "
		write("%s0x%08x: %s" % (mark, off, inst.toString()))
		inst = inst.getNext()
		count += 1
		if count >= max_inst:
			write("  ... (truncated at %d instructions)" % max_inst)
			break
	write("  Instructions printed: %d" % count)

def print_instruction_at_or_before(addr_int, label):
	write("")
	write("-" * 70)
	write("Instruction at/before %s 0x%08x" % (label, addr_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(addr_int))
	if inst is None:
		inst = listing.getInstructionBefore(toAddr(addr_int))
	if inst is None:
		write("  [instruction not found]")
		return
	write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
	write("  Flow: %s" % inst.getFlowType())
	write("  Length: %d" % inst.getLength())

def safe_u32(addr_int):
	try:
		addr = toAddr(addr_int)
		if not mem.contains(addr):
			return None
		return getInt(addr) & 0xffffffff
	except:
		return None

def print_memory_membership(addr_int, label):
	write("")
	write("-" * 70)
	write("Memory membership: %s 0x%08x" % (label, addr_int))
	write("-" * 70)
	addr = toAddr(addr_int)
	if mem.contains(addr):
		block = mem.getBlock(addr)
		bname = block.getName() if block else "???"
		write("  In currentProgram memory block: %s" % bname)
	else:
		write("  Not in currentProgram memory. Treat as wild/module-external address.")

def print_vtable(base, label, slots=20):
	write("")
	write("-" * 70)
	write("VTable/dword table %s @ 0x%08x" % (label, base))
	write("-" * 70)
	for i in range(slots):
		slot = base + i * 4
		value = safe_u32(slot)
		if value is None:
			write("  [%02d] +0x%02x: <unreadable>" % (i, i * 4))
			continue
		write("  [%02d] +0x%02x: 0x%08x -> %s" % (i, i * 4, value, label_for_addr(value)))

def print_runtime_facts():
	write("=" * 70)
	write("CRASH 0x64492067 CREATEQUEUEDCHARACTER TASK UAF AUDIT")
	write("=" * 70)
	write("")
	write("Runtime facts from latest stress-test crash:")
	write("  CrashLogger only captured EXCEPTION_ACCESS_VIOLATION on [FNV] AI Linear Task Thread 1.")
	write("  Psycho AV: EIP=EAX=0x64492067, ECX=0x1f7c5f10, EDX=0x0101dce4, ESP[0]=0x00444957.")
	write("  ECX is pool #15 class #11 80B and was already free at crash time.")
	write("  Same cell had two double-free reports, then TASK_RELEASE non-positive refcount guards.")
	write("  This script checks whether 0x00444957 is an indirect task virtual call and identifies vtable/class context.")

def main():
	print_runtime_facts()
	print_memory_membership(0x64492067, "faulting EIP/EAX")
	print_memory_membership(0x0101dce4, "EDX at crash, known NiRefObject vtable")
	print_memory_membership(0x01097314, "vtable observed by TASK_RELEASE before crash")
	print_instruction_at_or_before(0x00444957, "return address on stack")
	disasm_window(0x00444920, 0xa0, "CreateQueuedCharacter crash window", [0x00444957, 0x00444961, 0x00444850], 180)
	decompile_at(0x00444850, "CreateQueuedCharacter / task submit path", 22000)
	find_and_print_calls_from(0x00444850, "CreateQueuedCharacter", 220)
	print_vtable(0x01097314, "TASK_RELEASE observed vtable", 24)
	find_refs_to(0x01097314, "TASK_RELEASE observed vtable", 120)
	print_vtable(0x0101dce4, "NiRefObject vtable / crash EDX", 24)
	find_refs_to(0x0101dce4, "NiRefObject vtable", 80)
	decompile_at(0x0044cbf0, "IOTask/NiPointer release wrapper used after task call", 7000)
	decompile_at(0x0044dd60, "IOTask_Release, refcount at +8, vtable[0] final release", 7000)
	decompile_at(0x006f74f0, "Pointer assignment helper used by CreateQueuedCharacter", 9000)
	decompile_at(0x00559450, "Pointer get helper used before indirect task calls", 7000)
	decompile_at(0x00528cb0, "Pointer init helper for local task holder", 7000)
	write("")
	write("=" * 70)
	write("END CRASH 0x64492067 CREATEQUEUEDCHARACTER TASK UAF AUDIT")
	write("=" * 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_64492067_createqueuedcharacter_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
