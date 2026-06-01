# @category Analysis
# @description Re-audit current 0x00D0D7D8 Havok remove/add-agent crash contract

from ghidra.app.decompiler import DecompInterface

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

def decompile_at(addr_int, label, max_len=24000):
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
			write("  [decompile truncated at %d chars, total %d]" % (max_len, len(code)))
	else:
		write("  [decompilation failed]")

def find_refs_to(addr_int, label, limit=160):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), name_for_func(from_func)))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def find_and_print_calls_from(addr_int, label, limit=220):
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
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name_for_func(func_for(tgt))))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def byte_at(addr_int):
	b = memory.getByte(toAddr(addr_int))
	if b < 0:
		b += 256
	return b

def print_bytes(start_int, length, label):
	write("")
	write("-" * 70)
	write("Bytes: %s @ 0x%08x len=0x%x" % (label, start_int, length))
	write("-" * 70)
	pos = 0
	while pos < length:
		line_addr = start_int + pos
		parts = []
		i = 0
		while i < 16 and pos + i < length:
			try:
				parts.append("%02x" % byte_at(line_addr + i))
			except:
				parts.append("??")
			i += 1
		write("  0x%08x: %s" % (line_addr, " ".join(parts)))
		pos += 16

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly: %s around 0x%08x" % (label, center_int))
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
		off = inst.getAddress().getOffset()
		marker = " << target" if off == center_int else ""
		write("  0x%08x: %-58s%s" % (off, inst.toString(), marker))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (tgt, name_for_func(func_for(tgt))))
		inst = inst.getNext()
		idx += 1

def print_call_contexts(target_int, label, limit=80):
	write("")
	write("-" * 70)
	write("Call contexts TO 0x%08x (%s)" % (target_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(target_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		off = ref.getFromAddress().getOffset()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("")
		write("CALL %d: 0x%08x in %s" % (count + 1, off, name_for_func(from_func)))
		disasm_window(off, 18, 28, "xref context")
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total call contexts printed: %d" % count)

def print_crash_notes():
	write("CURRENT 0x00D0D7D8 HAVOK REMOVE/ADD-AGENT AUDIT")
	write("")
	write("Fresh CrashLogger:")
	write("  Thread: AI Linear Task Thread 2")
	write("  EIP: 0x00D0D7D8")
	write("  ECX=0 EDX=0")
	write("  Stack includes hkpRigidBody CrateLidC, hkpContinuousSimulation, ahkpWorld")
	write("")
	write("Known immediate fault:")
	write("  0x00D0D7D8: MOV EAX, dword ptr [EDX + 0xCC]")
	write("  In the crashing path, EDX comes from *local_10 / *piVar9.")
	write("  The begin lock call used (*local_10)->+0xCC before FUN_00CF7080.")
	write("  The end unlock call rereads (*local_10)->+0xCC after FUN_00CF7080.")
	write("")
	write("This script checks whether current data supports a safe fix or only the symptom.")

def audit_core():
	print_bytes(0x00d0d730, 0xc0, "FUN_00D0D3F0 remove/add-agent crash area")
	disasm_window(0x00d0d7d8, 46, 58, "crash instruction in StRemoveAgt/StAddAgt")
	decompile_at(0x00d0d3f0, "FUN_00D0D3F0 broadphase remove/add-agent worker", 36000)
	find_and_print_calls_from(0x00d0d3f0, "FUN_00D0D3F0", 260)
	decompile_at(0x00cf7080, "FUN_00CF7080 StAddAgt narrowphase dispatcher", 22000)
	decompile_at(0x00c911d0, "FUN_00C911D0 enter island critical section", 8000)
	decompile_at(0x00c91210, "FUN_00C91210 leave island critical section", 8000)

def audit_callers():
	find_refs_to(0x00d0d3f0, "FUN_00D0D3F0 broadphase worker", 120)
	find_refs_to(0x00cf7080, "FUN_00CF7080 StAddAgt", 160)
	find_refs_to(0x00c911d0, "FUN_00C911D0 enter island critical section", 120)
	find_refs_to(0x00c91210, "FUN_00C91210 leave island critical section", 120)
	print_call_contexts(0x00c911d0, "enter island critical section", 20)
	print_call_contexts(0x00c91210, "leave island critical section", 20)
	print_call_contexts(0x00cf7080, "StAddAgt", 20)

def main():
	print_crash_notes()
	audit_core()
	audit_callers()
	write("")
	write("Questions to answer from this output:")
	write("  1. Does FUN_00CF7080 legally remove/null the first exported collision object slot?")
	write("  2. Is C911D0/C91210 strictly an Enter/Leave pair for one island critical section?")
	write("  3. Can we preserve the island pointer read before StAddAgt and use it for C91210?")
	write("  4. Do sibling workers use the same unsafe reread pattern?")

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_00d0d7d8_current_remove_agent_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
