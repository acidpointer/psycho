# @category Analysis
# @description Resolve final FalloutNV save transaction, barrier, record-buffer, and failure-flag intervention contracts

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
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

def audit_function(addr_int, label, max_len=30000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def dump_and_decompile_vtable(addr_int, count, label):
	write("")
	write("=" * 70)
	write("%s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	targets = []
	for index in range(count):
		entry_addr = addr_int + index * 4
		target = memory.getInt(toAddr(entry_addr)) & 0xffffffff
		func = fm.getFunctionAt(toAddr(target))
		name = func.getName() if func else "???"
		write("  [%02d] +0x%02x -> 0x%08x %s" % (index, index * 4, target, name))
		if func is not None and target not in targets:
			targets.append(target)
	for index in range(len(targets)):
		decompile_at(targets[index], "%s virtual method" % label, 26000)
		find_and_print_calls_from(targets[index], "%s virtual method" % label)

def audit_physical_file_contract():
	targets = [
		(0x00AFEAC0, "BSFile OS handle creation", 36000),
		(0x00AFECD0, "BSFile ReadFile implementation", 32000),
		(0x00AFEDE0, "BSFile WriteFile implementation", 32000),
		(0x00AFEEF0, "BSFile seek or position implementation", 26000),
		(0x00AFF060, "BSFile FlushFileBuffers implementation", 24000),
		(0x00AFF090, "BSFile CloseHandle implementation", 26000),
		(0x00AFF300, "BSFile write-mode open owner", 36000),
		(0x00AFF990, "BSFile reset or base initialization", 26000),
		(0x00AFFC60, "BSFile read-mode open owner", 36000),
		(0x00AA15A0, "BSFile buffered-write finalization candidate", 32000),
		(0x00B00650, "BSFile exact-count read wrapper", 26000),
	]
	for item in targets:
		audit_function(item[0], item[1], item[2])
	dump_and_decompile_vtable(0x010A4764, 12, "BSFile vtable")

def audit_barrier_contract():
	targets = [
		(0x006EB310, "PathManager pause transition", 32000),
		(0x006EB390, "PathManager paused predicate", 32000),
		(0x006EAE40, "PathManager wait-loop progress", 36000),
		(0x006EB420, "related PathManager transition", 30000),
		(0x006EB440, "related PathManager transition predicate", 30000),
		(0x00C3E750, "global worker barrier enter implementation", 36000),
		(0x0044FB20, "global worker barrier construction or publication", 40000),
		(0x00448420, "representative global worker barrier owner", 40000),
		(0x008503B0, "save transaction orchestration and barrier lifetime", 44000),
	]
	for item in targets:
		audit_function(item[0], item[1], item[2])

def audit_changed_record_contract():
	targets = [
		(0x008643B0, "changed-record object constructor", 24000),
		(0x008644B0, "changed-record disk header reader", 26000),
		(0x00864540, "changed-record payload remaining calculation", 22000),
		(0x00864580, "changed-record payload skip owner", 26000),
		(0x00864790, "record-buffer physical read and allocation", 32000),
		(0x008647F0, "record-buffer ownership adoption", 30000),
		(0x00864820, "record-buffer unchecked read primitive", 22000),
		(0x00864A60, "record-buffer unchecked variable-length peek", 24000),
		(0x0084F330, "form deserializer record-buffer binding", 36000),
		(0x00849D00, "changed-form live-state application owner", 48000),
		(0x007CC680, "BGSSaveLoadGame load-error flag 0x80 setter", 24000),
		(0x00538110, "owner of disputed zlib deflate path", 44000),
	]
	for item in targets:
		audit_function(item[0], item[1], item[2])
	find_refs_to(0x011C54CC, "disputed compressed-record buffer global")
	find_refs_to(0x011C54D0, "disputed compressed-record length global")
	disasm_range(0x00864740, 0x008648A0, "record payload read, buffer setup, and unchecked consumption")
	disasm_range(0x008644B0, 0x00864620, "changed-record header, length, remaining, and skip operations")

def main():
	write("=" * 70)
	write("SAVE FINAL INTERVENTION CONTRACT AUDIT")
	write("=" * 70)
	write("Questions: exact physical failure semantics, full save-barrier scope, record-buffer length ownership, and the engine flag used to abort a malformed load before further live-state mutation.")
	audit_physical_file_contract()
	audit_barrier_contract()
	audit_changed_record_contract()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/save_final_intervention_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
