# @category Analysis
# @description Audit stress-test crash at 0x00C6757A on AI Linear Task Thread 2

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

def decompile_at(addr_int, label, max_len=16000):
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

def find_refs_to(addr_int, label, limit=140):
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

def find_refs_into_function(addr_int, label, limit=180):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("References INTO function containing 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	body = func.getBody()
	addr_iter = body.getAddresses(True)
	count = 0
	while addr_iter.hasNext():
		addr = addr_iter.next()
		refs = ref_mgr.getReferencesTo(addr)
		while refs.hasNext():
			ref = refs.next()
			from_func = fm.getFunctionContaining(ref.getFromAddress())
			if from_func is not None and from_func.getEntryPoint() == func.getEntryPoint():
				continue
			write("  target=0x%08x %s from 0x%08x in %s" % (addr.getOffset(), ref.getReferenceType(), ref.getFromAddress().getOffset(), name_for_func(from_func)))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				write("  Total printed: %d" % count)
				return
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
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				if tgt_func is None:
					tgt_func = fm.getFunctionContaining(toAddr(tgt))
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name_for_func(tgt_func)))
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

def print_instruction(addr_int, label):
	inst = listing.getInstructionAt(toAddr(addr_int))
	write("")
	write("-" * 70)
	write("Instruction: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	if inst is None:
		write("  [instruction not found]")
		return
	write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
	write("  Flow: %s" % inst.getFlowType())
	write("  Length: %d" % inst.getLength())

def disasm_window(start_int, length, label, max_inst=260):
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
		mark = "   "
		off = inst.getAddress().getOffset()
		if off == 0x00C6757A:
			mark = "=> "
		write("%s0x%08x: %s" % (mark, off, inst.toString()))
		inst = inst.getNext()
		count += 1
		if count >= max_inst:
			write("  ... (truncated at %d instructions)" % max_inst)
			break
	write("  Instructions printed: %d" % count)

def disasm_function(addr_int, label, max_inst=260):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Function disassembly: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		mark = "   "
		off = inst.getAddress().getOffset()
		if off == 0x00C6757A:
			mark = "=> "
		write("%s0x%08x: %s" % (mark, off, inst.toString()))
		count += 1
		if count >= max_inst:
			write("  ... (truncated at %d instructions)" % max_inst)
			break
	write("  Instructions printed: %d" % count)

def scan_function_for_text(addr_int, label, needles, limit=180):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Instruction text scan: %s" % label)
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		matched = False
		for needle in needles:
			if needle.lower() in text:
				matched = True
		if matched:
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				break
	write("  Total matches: %d" % count)

def print_refs_with_context(addr_int, label, before=0x40, after=0x90, limit=100):
	write("")
	write("-" * 70)
	write("References with disasm context TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_addr = ref.getFromAddress().getOffset()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("")
		write("  REF %d: %s from 0x%08x in %s" % (count + 1, ref.getReferenceType(), from_addr, name_for_func(from_func)))
		disasm_window(from_addr - before, before + after, "xref context for 0x%08x" % from_addr, 120)
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Context refs printed: %d" % count)

def audit_function(addr_int, label, max_len=18000):
	decompile_at(addr_int, label, max_len)
	disasm_function(addr_int, label)
	find_refs_into_function(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def audit_calltrace():
	addrs = [
		(0x00C6757A, "Crash EIP"),
		(0x00C6AECF, "CrashLogger caller 1"),
		(0x004BA9B5, "CrashLogger caller 2"),
		(0x00453624, "CrashLogger caller 3"),
		(0x008C8042, "CrashLogger caller 4"),
		(0x008C71A8, "CrashLogger caller 5"),
		(0x008C7764, "CrashLogger caller 6"),
		(0x00AA64E0, "CrashLogger thread entry"),
	]
	idx = 0
	while idx < len(addrs):
		item = addrs[idx]
		audit_function(item[0], item[1], 14000)
		idx += 1

def main():
	write("=" * 70)
	write("STRESS CRASH 0x00C6757A HAVOK AUDIT")
	write("=" * 70)
	write("")
	write("Runtime facts from logs:")
	write("  Thread: [FNV] AI Linear Task Thread 2")
	write("  Exception: read AV at 0x00000028, EIP=0x00C6757A")
	write("  Registers: EAX=0x0000000B EBX=0 EDX=0 ECX=0x01205DE4 ESI=0x1A49E034 EDI=0x168756F0")
	write("  Stack contains bhkWorldM at ESP+0x08 and ahkpWorld at ESP+0x14.")
	write("  Psycho log emitted many FUN_00CFFA00 NULL entity skips 22 ms before the crash.")
	write("  VAS was not critical: free about 345MB, largest hole about 155MB before crash.")
	write("")
	write("# SECTION 1: exact crash instruction")
	print_instruction(0x00C6757A, "faulting instruction")
	print_bytes(0x00C674D0, 0x230, "function bytes around FUN_00C674D0")
	disasm_window(0x00C67530, 0xB0, "tight window around 0x00C6757A")
	scan_function_for_text(0x00C6757A, "member accesses in crash function", ["+ 0x28", "+ 0x2c", "+ 0xcc", "+ 0x1b0", "[eax", "[edx", "[ebx", "[esi", "[edi"])
	write("")
	write("# SECTION 2: crash function contract")
	audit_function(0x00C6757A, "FUN_00C674D0 crash function", 26000)
	write("")
	write("# SECTION 3: direct callees used by the crash function")
	audit_function(0x00C94BD0, "FUN_00C94BD0 addEntityBatch candidate", 32000)
	audit_function(0x00C91620, "FUN_00C91620 fallback from NULL child branch", 22000)
	audit_function(0x00CB6E70, "FUN_00CB6E70 pvVar1 handler", 22000)
	audit_function(0x00C92A80, "FUN_00C92A80 optional pvVar1 handler", 16000)
	write("")
	write("# SECTION 4: calltrace functions")
	audit_calltrace()
	write("")
	write("# SECTION 5: known sparse broadphase hooks")
	find_refs_to(0x00C674D0, "FUN_00C674D0 entry")
	print_refs_with_context(0x00C674D0, "FUN_00C674D0 entry")
	find_refs_to(0x00CFFA00, "FUN_00CFFA00 NULL entity shim target")
	find_refs_to(0x00CF7080, "FUN_00CF7080 narrowphase shim target")
	write("")
	write("=" * 70)
	write("END STRESS CRASH 0x00C6757A HAVOK AUDIT")
	write("=" * 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_00c6757a_stress_havok_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
