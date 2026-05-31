# @category Analysis
# @description Audit 0x00401170 GetTypeID crash contract and low-pointer call paths

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

def find_refs_to(addr_int, label, limit=120):
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
				tgt_func = func_for(tgt)
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name_for_func(tgt_func)))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def disasm_window(start_int, length, label, highlights, max_inst=220):
	end_int = start_int + length
	write("")
	write("-" * 70)
	write("Disassembly: %s 0x%08x..0x%08x" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	count = 0
	while inst is not None and inst.getAddress().getOffset() < end_int and count < max_inst:
		off = inst.getAddress().getOffset()
		prefix = "=> " if off in highlights else "   "
		write("%s0x%08x: %s" % (prefix, off, inst.toString()))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (tgt, name_for_func(func_for(tgt))))
		inst = inst.getNext()
		count += 1
	if count >= max_inst:
		write("  ... (truncated at %d instructions)" % max_inst)

def print_gettypeid_calls(addr_int, label):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("GetTypeID calls inside %s" % label)
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
			if ref.getReferenceType().isCall() and ref.getToAddress().getOffset() == 0x00401170:
				write("  call at 0x%08x returns to 0x%08x" % (inst.getAddress().getOffset(), inst.getAddress().getOffset() + inst.getLength()))
				count += 1
	write("  Total: %d" % count)

def main():
	write("Crash 0x00401170 GetTypeID contract audit")
	write("")
	write("Runtime note from Stewie source:")
	write("  0x00401170 is patched to TESForm::GetTypeID: movzx eax, byte ptr [ecx+4]; ret")
	write("  0x007AF430 is patched to TESObjectREFR::baseForm: mov eax, [ecx+0x20]; ret")
	write("")
	write("CrashLogger ECX=0x7 means a caller passed a low/sentinel form pointer into GetTypeID.")
	decompile_at(0x00401170, "TESForm::GetTypeID original")
	disasm_window(0x00401160, 0x40, "TESForm::GetTypeID vicinity", [0x00401170])
	decompile_at(0x007af430, "TESObjectREFR::GetBaseForm runtime patch target")
	disasm_window(0x007af420, 0x40, "GetBaseForm vicinity", [0x007af430])
	decompile_at(0x005785e0, "Callback helper FUN_005785E0", 22000)
	print_gettypeid_calls(0x005785e0, "FUN_005785E0")
	find_and_print_calls_from(0x005785e0, "FUN_005785E0")
	decompile_at(0x009f5070, "Cell enum callback FUN_009F5070", 22000)
	disasm_window(0x009f5130, 0x50, "Direct baseForm/GetTypeID branch", [0x009f5152, 0x009f5159])
	disasm_window(0x009f5430, 0x30, "Helper branch returning to crash frame", [0x009f5449, 0x009f544e])
	print_gettypeid_calls(0x009f5070, "FUN_009F5070")
	find_refs_to(0x005785e0, "Callback helper FUN_005785E0")
	find_refs_to(0x00401170, "TESForm::GetTypeID", 80)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_00401170_typeid_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
