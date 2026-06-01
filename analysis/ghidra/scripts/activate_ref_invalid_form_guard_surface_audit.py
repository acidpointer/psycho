# @category Analysis
# @description Find safe guard surfaces for invalid linked-ref form pointers during activation

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

def calls_target(inst, target_int):
	refs = inst.getReferencesFrom()
	for ref in refs:
		if ref.getReferenceType().isCall() and ref.getToAddress().getOffset() == target_int:
			return True
	return False

def print_calls_to_target_inside(addr_int, label, target_int, target_label):
	func = func_for(addr_int)
	write("")
	write("=" * 70)
	write("Calls to %s inside %s" % (target_label, label))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		if calls_target(inst, target_int):
			count += 1
			disasm_window(inst.getAddress().getOffset(), 18, 36, "call to %s in %s" % (target_label, name_for_func(func)))
	write("  Calls found: %d" % count)

def print_candidate_surfaces():
	write("")
	write("=" * 70)
	write("Patch-surface questions")
	write("=" * 70)
	write("A good fix should not hide a bad ECX after GetTypeID. It should stop the invalid pointer before the virtual/type dispatch.")
	write("Check these from the script output:")
	write("  1. Which frame reads ExtraLinkedRef type 0x51 from BaseExtraList?")
	write("  2. Which field from ExtraLinkedRef becomes ECX=0xFFFFFDA5?")
	write("  3. Is NULL accepted by the caller, or does NULL propagate to another crash?")
	write("  4. Is there a local return-false path for activation checks before any side effects?")
	write("  5. Is the Stewie callsite only exposing vanilla Activate behavior? If yes, fix belongs in psycho-engine-fixes, not helper.")

def audit_candidate_functions():
	targets = [
		(0x005012e9, "Crash frame 1"),
		(0x00501485, "Crash frame 2"),
		(0x00573733, "Crash frame 3"),
		(0x0056869f, "Stack slot 00 context"),
		(0x0094328e, "No-activate-sound callsite patched by Stewie"),
		(0x00410220, "BaseExtraList::GetByType"),
		(0x00401170, "TESForm::GetTypeID"),
	]
	for item in targets:
		decompile_at(item[0], item[1], 22000)
		disasm_window(item[0], 26, 90, item[1])
		find_and_print_calls_from(item[0], item[1], 200)
		print_calls_to_target_inside(item[0], item[1], 0x00401170, "TESForm::GetTypeID")
		print_calls_to_target_inside(item[0], item[1], 0x00410220, "BaseExtraList::GetByType")

def audit_reference_fanout():
	find_refs_to(0x00401170, "TESForm::GetTypeID", 320)
	find_refs_to(0x00410220, "BaseExtraList::GetByType", 320)
	find_refs_to(0x005012e9, "Crash frame 1 address", 120)
	find_refs_to(0x00501485, "Crash frame 2 address", 120)
	find_refs_to(0x00573733, "Crash frame 3 address", 120)
	find_refs_to(0x0094328e, "Stewie patched callsite", 120)

def main():
	write("Activation invalid TESForm guard-surface audit")
	write("")
	write("Crash shape: ExtraLinkedRef is present, then TESForm::GetTypeID receives ECX=0xFFFFFDA5.")
	write("This script is for choosing a non-propagating guard point after the contract scripts identify the bad field.")
	print_candidate_surfaces()
	audit_candidate_functions()
	audit_reference_fanout()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/activate_ref_invalid_form_guard_surface_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
