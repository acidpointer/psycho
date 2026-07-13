# @category Analysis
# @description Resolve the menu approval, missing-master detection, and late missing-content prompt contract during save loading

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
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
		if count > 120:
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

def disasm_range(start_int, end_int, label):
	write("")
	write("-" * 70)
	write("Disassembly: %s (0x%08x - 0x%08x)" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	while inst is not None and inst.getAddress().getOffset() <= end_int:
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()

def audit_function(addr_int, label, max_len=24000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def audit_targets():
	targets = [
		(0x007CE9B0, "StartMenu save-selection input owner", 32000),
		(0x007D3470, "selected-save load request owner", 30000),
		(0x007D40A0, "vanilla load confirmation owner", 30000),
		(0x00850760, "top-level save load and missing-content prompt owner", 32000),
		(0x00847DF0, "changed-form load owner", 36000),
		(0x00847660, "saved-master matching predicate", 30000),
		(0x00845CC0, "save-load diagnostic reporter", 18000),
		(0x00F778E0, "Xbox missing-content game-setting accessor", 12000),
		(0x00F77940, "missing-content game-setting accessor", 12000),
		(0x00703E80, "message-menu creation entry", 24000),
		(0x00704010, "synchronous message result owner", 24000),
	]
	for item in targets:
		audit_function(item[0], item[1], item[2])

def audit_prompt_state():
	find_refs_to(0x011D2100, "sSaveGameContentIsMissing setting object")
	find_refs_to(0x010612C0, "default missing-content message text")
	disasm_range(0x007CED70, 0x007CEF20, "StartMenu selected-save branch and confirmation handoff")
	disasm_range(0x007D33F0, 0x007D35D0, "selected-save request, missing-content decision, and MenuButton Back calls")
	disasm_range(0x00850760, 0x008509A0, "top-level load, missing-content prompt, approval mode, and cleanup")
	disasm_range(0x00847EE0, 0x00847F90, "master matching result and allow-missing mode gate")

def main():
	write("=" * 70)
	write("SAVE MISSING-CONTENT PROMPT CONTRACT FOLLOW-UP")
	write("=" * 70)
	write("Questions: where missing-master evidence is computed, where the menu asks once, how approval reaches the real load, and why a prompt can be shown after the loading transition begins.")
	audit_targets()
	audit_prompt_state()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/save_missing_content_prompt_contract_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
