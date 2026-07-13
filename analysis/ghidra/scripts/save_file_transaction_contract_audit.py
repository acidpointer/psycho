# @category Analysis
# @description Audit FalloutNV save file creation, error propagation, close, temporary-file promotion, and backup handling

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
		if count > 80:
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

def disasm_around(addr_int, label, before_count=28, after_count=44):
	write("")
	write("-" * 70)
	write("Disassembly around %s 0x%08x" % (label, addr_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(addr_int))
	if inst is None:
		inst = listing.getInstructionBefore(toAddr(addr_int))
	count = 0
	while inst is not None and count < before_count:
		previous = inst.getPrevious()
		if previous is None:
			break
		inst = previous
		count += 1
	printed = 0
	limit = before_count + after_count + 1
	while inst is not None and printed < limit:
		offset = inst.getAddress().getOffset()
		marker = "=>" if offset == addr_int else "  "
		write("%s 0x%08x: %s" % (marker, offset, inst.toString()))
		inst = inst.getNext()
		printed += 1

def audit_function(addr_int, label, max_len=16000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def audit_targets():
	targets = [
		(0x008503B0, "SaveGameManager save orchestration", 26000),
		(0x00850030, "BGSSaveLoadFile factory", 18000),
		(0x00850100, "BGSSaveLoadFile manager release", 12000),
		(0x00850330, "BGSSaveLoadFile destroy", 12000),
		(0x00847850, "BGSSaveLoadGame SaveGame", 30000),
		(0x00847D00, "global saving-state transition", 12000),
		(0x00847590, "save header and chapter setup", 24000),
		(0x00847D50, "save phase setup helper", 12000),
		(0x00847D70, "save chapter begin helper", 12000),
		(0x00847D90, "save chapter end helper", 12000),
		(0x00846330, "BGSSaveLoadFile write boundary", 16000),
		(0x00846E00, "save chapter flush helper", 18000),
		(0x005621D0, "post-save failure predicate", 12000),
		(0x00850BF0, "save task barrier helper", 12000),
		(0x00850EA0, "save file activation helper", 12000),
		(0x00851250, "save history finalization", 18000),
		(0x00851680, "save list insertion", 18000),
		(0x0084FF30, "save directory builder", 12000),
		(0x0084FF90, "save filename builder", 16000),
		(0x0085762B, "temporary save rename callsite owner", 26000),
		(0x00860E20, "save header reader and initial validator", 22000),
	]
	for item in targets:
		audit_function(item[0], item[1], item[2])

def audit_critical_callsites():
	sites = [
		(0x00850545, "file creation result"),
		(0x008505BB, "engine SaveGame return boundary"),
		(0x008505C6, "post-save failure decision"),
		(0x0085063E, "temporary BGSSaveLoadFile release"),
		(0x0085762B, "temporary-to-final rename"),
	]
	for item in sites:
		disasm_around(item[0], item[1], 36, 56)

def audit_named_file_functions():
	patterns = ["rename", "movefile", "replacefile", "deletefile", "copyfile", "flushfilebuffers", "writefile", "closehandle", "fclose"]
	write("")
	write("=" * 70)
	write("NAMED FILE API AND CRT FUNCTIONS")
	write("=" * 70)
	functions = fm.getFunctions(True)
	count = 0
	while functions.hasNext():
		func = functions.next()
		name = func.getName()
		lower = name.lower()
		matched = False
		for pattern in patterns:
			if pattern in lower:
				matched = True
				break
		if not matched:
			continue
		entry = func.getEntryPoint().getOffset()
		write("  0x%08x %s" % (entry, name))
		find_refs_to(entry, name)
		count += 1
		if count >= 80:
			write("  ... named function scan truncated")
			break
	write("  Total named functions: %d" % count)

def main():
	write("=" * 70)
	write("SAVE FILE TRANSACTION CONTRACT AUDIT")
	write("=" * 70)
	write("Questions: when is the old save replaced, which failures propagate, and can a partial .tmp file be promoted?")
	audit_targets()
	audit_critical_callsites()
	audit_named_file_functions()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/save_file_transaction_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
