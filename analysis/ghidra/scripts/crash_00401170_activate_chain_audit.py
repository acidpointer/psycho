# @category Analysis
# @description Audit current 0x00401170 crash through activation and Stewie no-activate-sound path

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

def is_highlight(addr_int, highlights):
	for item in highlights:
		if addr_int == item:
			return True
	return False

def disasm_window(center_int, before_count, after_count, label, highlights):
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
		prefix = "=> " if is_highlight(off, highlights) else "   "
		write("%s0x%08x: %-58s" % (prefix, off, inst.toString()))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (tgt, name_for_func(func_for(tgt))))
		inst = inst.getNext()
		idx += 1

def print_crash_facts():
	write("Crash 0x00401170 activation chain audit")
	write("")
	write("Crash facts from CrashLogger:")
	write("  EIP=0x00401170, TESForm::GetTypeID inline reads byte [ECX+4].")
	write("  ECX=EAX=0xFFFFFDA5, so the caller supplied an invalid TESForm pointer.")
	write("  EDX=0xFC4B0460 dereferences as ExtraLinkedRef; xNVSE says ExtraLinkedRef is type 0x51.")
	write("  Stack object is TESObjectREFR 36007C03 DefaultUnlockTermWALL in cell 360076E4 AWOPSunnySetWaterProcessing.")
	write("  Stewie frame is MenuFixes::OnActivateRefShouldSkipNoActivateSound+0x36, which calls ref->Activate().")
	write("  Psycho memory log does not show OOM/VAS pressure before the crash.")
	write("")
	write("Goal:")
	write("  Identify the exact game function that turns an ExtraLinkedRef or linked target into ECX=0xFFFFFDA5.")
	write("  Do not infer from the old ExtraLinkedRefChildren type 0x52 crash; this crash is type 0x51 shaped.")

def audit_stack_functions():
	targets = [
		(0x00401170, "TESForm::GetTypeID inline"),
		(0x0056869f, "Stack slot 00 / possible immediate caller context"),
		(0x005012e9, "Crash frame 1"),
		(0x00501485, "Crash frame 2"),
		(0x00573733, "Crash frame 3"),
		(0x0086fa31, "Parent frame after Stewie hook"),
		(0x0086e765, "Parent frame"),
		(0x0086b3e8, "Parent frame"),
		(0x0094328e, "Stewie WriteRelCall game callsite for no-activate-sound tweak"),
	]
	for item in targets:
		decompile_at(item[0], item[1], 22000)
		disasm_window(item[0], 24, 70, item[1], [item[0]])
		find_and_print_calls_from(item[0], item[1], 180)

def audit_key_references():
	find_refs_to(0x00401170, "TESForm::GetTypeID inline", 260)
	find_refs_to(0x005012e9, "Crash frame 1 address", 80)
	find_refs_to(0x00501485, "Crash frame 2 address", 80)
	find_refs_to(0x00573733, "Crash frame 3 address", 80)
	find_refs_to(0x0094328e, "Stewie no-activate-sound patched callsite", 80)
	find_refs_to(0x00410220, "BaseExtraList::GetByType", 260)

def main():
	print_crash_facts()
	audit_stack_functions()
	audit_key_references()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_00401170_activate_chain_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
