# @category Analysis
# @description Trace missing-master FormID translation through changed-record loading and background model publication after the reproducible old-save crash

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
		if count > 40:
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

def audit_function(addr_int, label, max_len=20000):
	decompile_at(addr_int, label, max_len)
	find_refs_to(addr_int, label)
	find_and_print_calls_from(addr_int, label)

def print_pointer_table(start_int, count, label):
	write("")
	write("-" * 70)
	write("Pointer table: %s @ 0x%08x" % (label, start_int))
	write("-" * 70)
	index = 0
	while index < count:
		entry_addr = start_int + index * 4
		try:
			value = memory.getInt(toAddr(entry_addr)) & 0xffffffff
			func = fm.getFunctionAt(toAddr(value))
			name = func.getName() if func else "???"
			write("  +0x%02x 0x%08x -> 0x%08x %s" % (index * 4, entry_addr, value, name))
		except:
			write("  +0x%02x 0x%08x [unreadable]" % (index * 4, entry_addr))
		index += 1

def audit_targets():
	targets = [
		(0x00850760, "top-level load and missing-content approval owner", 30000),
		(0x00847660, "saved-master name matching and index-map writer", 22000),
		(0x00847DF0, "two-pass changed-form load owner", 52000),
		(0x00849D00, "single changed-record live-state application", 36000),
		(0x008643B0, "changed-record object constructor", 16000),
		(0x008665B0, "changed-record saved identity accessor", 12000),
		(0x00853640, "saved identity field reader", 16000),
		(0x00853500, "record FormID field reader", 16000),
		(0x008648A0, "generic changed-record form-reference reader", 16000),
		(0x004839C0, "generic loaded FormID to TESForm resolver", 18000),
		(0x00853130, "global FormID map lookup used by the resolver", 22000),
		(0x00846C90, "runtime FormID to saved identity mapping", 18000),
		(0x008456E0, "change-map lookup used before record application", 18000),
		(0x008458B0, "change-map insertion after first-pass work", 18000),
		(0x00845960, "change-map insertion for unresolved live forms", 18000),
		(0x0084A3A0, "record compatibility predicate", 18000),
		(0x0084A880, "record rejection or replacement owner", 22000),
		(0x00843630, "live-form removal after first-pass mismatch", 18000),
		(0x0056B2D0, "reference model setup reached by background clone", 42000),
		(0x00440A90, "queued model execution owner", 22000),
		(0x00442350, "BackgroundCloneThread work loop", 26000),
	]
	for item in targets:
		audit_function(item[0], item[1], item[2])

def audit_exact_dataflow():
	print_pointer_table(0x01082028, 12, "changed-record derived vtable")
	disasm_range(0x00847EE0, 0x00847FA0, "missing-master result and allow-missing gate")
	disasm_range(0x008482E0, 0x00848630, "first changed-record pass identity resolution and rejection")
	disasm_range(0x00848780, 0x00848C80, "second changed-record pass lookup, application, and skip")
	disasm_range(0x00849D00, 0x0084A370, "per-record live-state application and all rejection branches")
	disasm_range(0x0056B430, 0x0056B510, "reference ExtraPrimitive selection and publication")
	disasm_range(0x00440A90, 0x00440B90, "background task reference virtual dispatch")
	disasm_range(0x004423D0, 0x00442470, "background queue task execution and completion")

def main():
	write("=" * 70)
	write("SAVE MISSING-CONTENT ROOT-CAUSE AUDIT")
	write("=" * 70)
	write("Determine exactly how a saved plugin index mapped to 0xFF affects top-level and embedded FormIDs, whether either changed-record pass can still publish partial live state, and whether an aborted or accepted missing-content load can leave a background model task consuming that state.")
	audit_targets()
	audit_exact_dataflow()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/save_missing_content_root_cause_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
