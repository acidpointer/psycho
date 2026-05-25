# @category Analysis
# @description Analyze recurring AI/Havok crash at 0x00D0D7D8 with CrateLidC rigid body on AI Linear Task Thread

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

def decompile_at(addr_int, label, max_len=20000):
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

def instruction_at_or_before(addr_int):
	addr = toAddr(addr_int)
	inst = listing.getInstructionAt(addr)
	if inst is not None:
		return inst
	inst = listing.getInstructionBefore(addr)
	if inst is not None:
		end = inst.getAddress().getOffset() + inst.getLength()
		if addr_int < end:
			return inst
	return None

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

def print_instruction_details(addr_int, label):
	write("")
	write("-" * 70)
	write("Instruction details: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	inst = instruction_at_or_before(addr_int)
	if inst is None:
		write("  [instruction not found]")
		return
	iaddr = inst.getAddress().getOffset()
	write("  Instruction @ 0x%08x len=%d: %s" % (iaddr, inst.getLength(), inst.toString()))
	write("  Mnemonic: %s" % inst.getMnemonicString())
	write("  Flow: %s" % inst.getFlowType())
	op_count = inst.getNumOperands()
	i = 0
	while i < op_count:
		try:
			write("  Operand %d: %s" % (i, inst.getDefaultOperandRepresentation(i)))
		except:
			write("  Operand %d: [unavailable]" % i)
		i += 1
	refs = inst.getReferencesFrom()
	count = 0
	for ref in refs:
		write("  RefFrom: %s -> 0x%08x" % (ref.getReferenceType(), ref.getToAddress().getOffset()))
		count += 1
	write("  References from instruction: %d" % count)
	refs_to = ref_mgr.getReferencesTo(inst.getAddress())
	count_to = 0
	while refs_to.hasNext():
		ref = refs_to.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("  RefToInst: %s @ 0x%08x in %s" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), name_for_func(from_func)))
		count_to += 1
		if count_to > 40:
			write("  ... (truncated)")
			break
	write("  References to instruction: %d" % count_to)

def disasm_window(center_int, before, after, label):
	start_int = center_int - before
	end_int = center_int + after
	write("")
	write("-" * 70)
	write("Disassembly window: %s 0x%08x..0x%08x" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	count = 0
	while inst is not None and inst.getAddress().getOffset() < end_int:
		marker = "=> " if inst.getAddress().getOffset() == center_int else "   "
		write("%s0x%08x: %s" % (marker, inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()
		count += 1
		if count > 240:
			write("  ... (truncated)")
			break

def disasm_function(addr_int, label, max_inst=360):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Function disassembly: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	write("  Function: %s" % name_for_func(func))
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		count += 1
		if count >= max_inst:
			write("  ... (truncated at %d instructions)" % max_inst)
			break
	write("  Instructions printed: %d" % count)

def find_refs_to(addr_int, label, limit=100):
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

def find_refs_into_function(addr_int, label, limit=160):
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

def scan_function_for_text(addr_int, label, needles, limit=200):
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
		text = inst.toString()
		lower = text.lower()
		matched = False
		for needle in needles:
			if needle.lower() in lower:
				matched = True
		if matched:
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), text))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				break
	write("  Total matches: %d" % count)

def list_functions_in_range(start_int, end_int, label):
	write("")
	write("-" * 70)
	write("Functions in range: %s 0x%08x..0x%08x" % (label, start_int, end_int))
	write("-" * 70)
	func_iter = fm.getFunctions(toAddr(start_int), True)
	count = 0
	while func_iter.hasNext():
		func = func_iter.next()
		entry = func.getEntryPoint().getOffset()
		if entry >= end_int:
			break
		write("  0x%08x size=%d %s" % (entry, func.getBody().getNumAddresses(), func.getName()))
		count += 1
		if count > 160:
			write("  ... (truncated)")
			break
	write("  Total printed: %d" % count)

def audit_function(addr_int, label, max_len=16000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_refs_into_function(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def main():
	write("=" * 70)
	write("CRASH 0x00D0D7D8 HAVOK / AI CONTEXT")
	write("=" * 70)
	write("")
	write("Observed crash logs:")
	write("  2026-05-25: AI Linear Task Thread 2, EIP=0x00D0D7D8, read AV 0x000000CC")
	write("  2026-05-20 and 2026-05-09: same EIP and CrateLidC hkpRigidBody")
	write("  Stack includes ahkpWorld, hkpContinuousSimulation, hkpDefaultWorldMaintenanceMgr, bhkWorldM")
	write("  Current psycho diag: ESI points inside a live gheap 40B pool cell, not a freed cell")
	write("")
	write("Goal:")
	write("  Identify exact crash instruction, containing Havok function, caller path,")
	write("  and whether a small guard/engine fix can safely avoid the null/invalid access.")
	write("")
	write("# SECTION 1: exact crash instruction")
	print_instruction_details(0x00D0D7D8, "crash EIP")
	print_bytes(0x00D0D7B0, 0x90, "bytes around crash")
	disasm_window(0x00D0D7D8, 0x90, 0x110, "crash basic-block neighborhood")
	decompile_at(0x00D0D7D8, "Crash function containing EIP 0x00D0D7D8", 30000)
	disasm_function(0x00D0D7D8, "Crash function full disasm")
	find_refs_into_function(0x00D0D7D8, "Crash function")
	find_and_print_calls_from(0x00D0D7D8, "Crash function")
	scan_function_for_text(0x00D0D7D8, "Crash function offset/register clues", ["+ 0xcc", "+0xcc", "0xcc", "EDX", "EAX", "ECX", "ESI"])
	write("")
	write("# SECTION 2: nearby Havok function family")
	list_functions_in_range(0x00D0C000, 0x00D0F800, "near 0x00D0D7D8")
	write("")
	write("# SECTION 3: crash calltrace functions")
	audit_function(0x00C90350, "Calltrace lower frame: FUN_00C90350 / hkpContinuousSimulation area", 22000)
	audit_function(0x00C66510, "Calltrace lower frame: FUN_00C66510", 18000)
	write("")
	write("# SECTION 4: Havok simulation island / world maintenance candidates")
	audit_function(0x00D07420, "SimIsland_AddEntity_or_related_FUN_00D07420", 18000)
	audit_function(0x00D07830, "SimIsland_Create_or_related_FUN_00D07830", 18000)
	audit_function(0x00C90510, "Havok_AddEntity_PerEntityInit_FUN_00C90510", 16000)
	audit_function(0x00C9C040, "Havok_AddEntity_PostBroadphase_FUN_00C9C040", 16000)
	write("")
	write("# SECTION 5: add/remove/lifecycle functions that may leave stale Havok state")
	audit_function(0x00C94BD0, "hkpWorld_addEntity_FUN_00C94BD0", 22000)
	audit_function(0x00C420D0, "Havok_RemoveFromWorld_FUN_00C420D0", 18000)
	audit_function(0x00C41FE0, "Havok_FreeEntry_FUN_00C41FE0", 18000)
	audit_function(0x00C40B70, "bhkCollisionObject_dtor_FUN_00C40B70", 22000)
	audit_function(0x00401970, "PDD_queue_0x20_HavokRelease_FUN_00401970", 12000)
	write("")
	write("# SECTION 6: thread/stop/drain/GC synchronization")
	audit_function(0x008324E0, "StopHavok_DrainAI_FUN_008324E0", 18000)
	audit_function(0x008300C0, "StopHavok_WaitFunc_FUN_008300C0", 16000)
	audit_function(0x00877700, "PreStopHavok_AIDrain_FUN_00877700", 16000)
	audit_function(0x00C459D0, "HavokGC_AsyncFlush_FUN_00C459D0", 18000)
	audit_function(0x00C3E1B0, "HavokLockUnlock_or_allocator_pair_FUN_00C3E1B0", 16000)
	write("")
	write("# SECTION 7: RTTI/static refs from crash stack")
	find_refs_to(0x010C3BC4, "ahkpWorld RTTI")
	find_refs_to(0x010CD45C, "hkpContinuousSimulation RTTI")
	find_refs_to(0x010CD34C, "hkpDefaultWorldMaintenanceMgr RTTI")
	find_refs_to(0x010C7888, "hkpRigidBody RTTI")
	find_refs_to(0x010C69F4, "bhkWorldM RTTI")
	find_refs_to(0x01085688, "AILinearTaskThread RTTI")
	write("")
	write("# SECTION 8: broadphase/sweep refs for stale entry hypothesis")
	find_refs_to(0x010CD5CC, "hkp3AxisSweep RTTI candidate")
	find_refs_to(0x010C3C14, "hkp3AxisSweep alternate RTTI candidate")
	write("")
	write("=" * 70)
	write("END CRASH 0x00D0D7D8 HAVOK / AI CONTEXT")
	write("=" * 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_00d0d7d8_havok_context.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
