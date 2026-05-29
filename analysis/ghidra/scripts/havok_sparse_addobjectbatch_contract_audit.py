# @category Analysis
# @description Audit sparse hkp3AxisSweep::addObjectBatch result contract and consumers

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

def decompile_at(addr_int, label, max_len=18000):
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

def find_refs_to(addr_int, label, limit=180):
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

def find_refs_into_function(addr_int, label, limit=240):
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

def find_and_print_calls_from(addr_int, label, limit=260):
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
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()
		count += 1
		if count >= max_inst:
			write("  ... (truncated at %d instructions)" % max_inst)
			break
	write("  Instructions printed: %d" % count)

def scan_function_for_text(addr_int, label, needles, limit=220):
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

def print_refs_with_context(addr_int, label, before=0x50, after=0xB0, limit=120):
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
		disasm_window(from_addr - before, before + after, "xref context for 0x%08x" % from_addr, 150)
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Context refs printed: %d" % count)

def audit_function(addr_int, label, max_len=22000):
	decompile_at(addr_int, label, max_len)
	find_refs_into_function(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def find_callers_in_range(target_addr, range_start, range_end, label, limit=160):
	write("")
	write("-" * 70)
	write("%s callers from 0x%08x-0x%08x" % (label, range_start, range_end))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(target_addr))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_off = ref.getFromAddress().getOffset()
		if from_off >= range_start and from_off <= range_end:
			from_func = fm.getFunctionContaining(ref.getFromAddress())
			write("  %s @ 0x%08x in %s" % (ref.getReferenceType(), from_off, name_for_func(from_func)))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				break
	write("  Total printed: %d" % count)

def main():
	write("=" * 70)
	write("HAVOK SPARSE ADDOBJECTBATCH CONTRACT AUDIT")
	write("=" * 70)
	write("")
	write("Reason:")
	write("  Stress crash emitted power-of-two FUN_00CFFA00 NULL entity skips, then")
	write("  crashed at 0x00C6757A in another Havok path on AI Linear Task Thread 2.")
	write("  This script checks whether the addObjectBatch sparse result is consumed")
	write("  by more than one unchecked loop.")
	write("")
	write("# SECTION 1: known add/broadphase consumers")
	audit_function(0x00C94BD0, "FUN_00C94BD0 addEntityBatch / broadphase result producer", 36000)
	audit_function(0x00CFFA00, "FUN_00CFFA00 per-entity AddedToWorld callback", 20000)
	audit_function(0x00CF7080, "FUN_00CF7080 narrowphase add-agent dispatcher", 26000)
	audit_function(0x00C674D0, "FUN_00C674D0 crash function consuming world/entity data", 30000)
	write("")
	write("# SECTION 2: compaction and null-slot handling candidates")
	audit_function(0x00D00370, "FUN_00D00370 null-slot compactor", 26000)
	audit_function(0x00C91620, "FUN_00C91620 fallback called by crash function", 22000)
	write("")
	write("# SECTION 3: caller and xref context")
	find_refs_to(0x00C94BD0, "FUN_00C94BD0 addEntityBatch")
	print_refs_with_context(0x00C94BD0, "FUN_00C94BD0 addEntityBatch")
	find_refs_to(0x00C674D0, "FUN_00C674D0 crash function")
	print_refs_with_context(0x00C674D0, "FUN_00C674D0 crash function")
	find_callers_in_range(0x00C94BD0, 0x00C00000, 0x00DFFFFF, "Havok-range addEntityBatch")
	find_callers_in_range(0x00C674D0, 0x00C00000, 0x00DFFFFF, "Havok-range crash-function")
	write("")
	write("# SECTION 4: instruction scans for unchecked slot/object access")
	scan_function_for_text(0x00C94BD0, "addEntityBatch slot/object access", ["+ 0x214", "+ 0xcc", "+ 0x58", "+ 0x64", "[eax", "[edx", "[esi", "[edi", "call"])
	scan_function_for_text(0x00C674D0, "crash function object/member access", ["+ 0x28", "+ 0x2c", "+ 0xcc", "+ 0x1b0", "[eax", "[edx", "[ebx", "[esi", "[edi", "call"])
	scan_function_for_text(0x00D00370, "compactor null checks", ["test", "jz", "jnz", "mov", "cmp"])
	write("")
	write("# SECTION 5: hkp3AxisSweep RTTI/vtable anchors")
	find_refs_to(0x010CD5CC, "hkp3AxisSweep RTTI candidate")
	find_refs_to(0x010C3C14, "hkp3AxisSweep alternate RTTI candidate")
	write("")
	write("=" * 70)
	write("END HAVOK SPARSE ADDOBJECTBATCH CONTRACT AUDIT")
	write("=" * 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/havok_sparse_addobjectbatch_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
