# @category Analysis
# @description Deep audit of save crash 0x00865DFB stack contract and caller argument setup

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

def entry_for(addr_int):
	func = func_for(addr_int)
	if func is None:
		return None
	return func.getEntryPoint().getOffset()

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

def disasm_function(addr_int, label, max_inst=260):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Function disassembly: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	write("  Function: %s entry=0x%08x size=%d" % (func.getName(), func.getEntryPoint().getOffset(), func.getBody().getNumAddresses()))
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		off = inst.getAddress().getOffset()
		write("  0x%08x: %-42s" % (off, inst.toString()))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (tgt, name_for_func(func_for(tgt))))
		count += 1
		if count >= max_inst:
			write("  ... (truncated at %d instructions)" % max_inst)
			return

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
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
		marker = ""
		if off == center_int:
			marker = " << target"
		write("  0x%08x: %-42s%s" % (off, inst.toString(), marker))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (tgt, name_for_func(func_for(tgt))))
		inst = inst.getNext()
		idx += 1

def print_crash_facts():
	write("=" * 70)
	write("CRASH 0x00865DFB STACK CONTRACT DEEP AUDIT")
	write("=" * 70)
	write("Runtime facts from latest CrashLogger:")
	write("  EIP=0x00865DFB, EAX=0x00000007")
	write("  ECX/ESI/EDI=0x0170F4F8 -> BGSSaveFormBuffer")
	write("  EDX=0xC4B30200 -> ExtraOwnership")
	write("  Stack includes Famine Box / PWBFamineBoxREF / Famine.esp")
	write("  Calltrace: 0x00865DFB <- 0x004BEDCC <- psycho_engine_fixes <- 0x004D4112 <- 0x00562305")
	write("")
	write("Questions this script must answer:")
	write("  1. What exact pointer is passed from 0x004BED60 into 0x00865DF0?")
	write("  2. Is that pointer ExtraOwnership.owner, BSExtraData.next, or another save-list field?")
	write("  3. Which function owns the failing dereference, and where is the safe boundary?")

def analyze_targets():
	disasm_function(0x004BED60, "0x004BED60 full caller", 260)
	disasm_window(0x004BEDCC, 36, 42, "runtime return site 0x004BEDCC")
	disasm_window(0x004BED7E, 28, 34, "first save-field call setup in 0x004BED60")
	disasm_window(0x004BED88, 28, 34, "second save-field call setup in 0x004BED60")
	decompile_at(0x004BED60, "0x004BED60 full decompile", 22000)
	find_and_print_calls_from(0x004BED60, "0x004BED60")
	disasm_function(0x00865DF0, "0x00865DF0 fault helper", 180)
	disasm_window(0x00865DFB, 24, 42, "fault instruction")
	decompile_at(0x00865DF0, "0x00865DF0 fault helper", 22000)
	find_and_print_calls_from(0x00865DF0, "0x00865DF0")
	decompile_at(0x0084E3A0, "0x0084E3A0 callee reached with ECX=0x7", 22000)
	disasm_function(0x0084E3A0, "0x0084E3A0", 220)
	find_and_print_calls_from(0x0084E3A0, "0x0084E3A0")
	decompile_at(0x004D4090, "0x004D4090 containing runtime caller 0x004D4112", 22000)
	disasm_window(0x004D4112, 40, 48, "runtime caller 0x004D4112")
	find_and_print_calls_from(0x004D4090, "0x004D4090")
	decompile_at(0x00562230, "0x00562230 containing runtime caller 0x00562305", 22000)
	disasm_window(0x00562305, 48, 56, "runtime caller 0x00562305")
	find_and_print_calls_from(0x00562230, "0x00562230")

def analyze_refs():
	targets = [
		(0x004BED60, "0x004BED60 entry"),
		(0x00865DF0, "0x00865DF0 fault helper"),
		(0x0084E3A0, "0x0084E3A0 type/id helper"),
		(0x004D4090, "0x004D4090 caller entry"),
		(0x00562230, "0x00562230 caller entry")
	]
	idx = 0
	while idx < len(targets):
		item = targets[idx]
		entry = entry_for(item[0])
		if entry is not None:
			find_refs_to(entry, item[1], 160)
		idx += 1

def main():
	print_crash_facts()
	analyze_targets()
	analyze_refs()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_00865dfb_stack_contract_deep_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
