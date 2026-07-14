# @category Analysis
# @description Trace missing-content payload references, non-terminating changed-form load passes, and runaway reconstruction allocation

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

def audit_load_owners():
	audit_function(0x00850760, "top-level load, approval, and completion owner", 30000)
	audit_function(0x00847DF0, "changed-form multi-pass load owner", 60000)
	audit_function(0x00849D00, "first-pass changed-form reconstruction owner", 50000)
	audit_function(0x00848CA0, "changed-form load cleanup or completion owner", 24000)
	audit_function(0x00850B40, "post changed-form load completion", 24000)
	audit_function(0x00850D60, "successful top-level load publication", 24000)

def audit_record_identity_and_payload():
	audit_function(0x008644B0, "changed-record header and owning FormID reader", 18000)
	audit_function(0x008645B0, "changed-record live-form resolver", 18000)
	audit_function(0x00864580, "changed-record remaining-payload skip", 16000)
	audit_function(0x00848D90, "changed-record rejection marker", 12000)
	audit_function(0x00848DD0, "changed-record rejection predicate", 12000)
	audit_function(0x00846D20, "saved FormID remapping including unavailable masters", 20000)
	audit_function(0x00853500, "record-buffer FormID reader and remapper", 18000)
	audit_function(0x0084F330, "live-form deserializer record-buffer binding", 30000)
	audit_function(0x0084F8E0, "created-reference reconstruction and bound-object validation", 40000)

def audit_application_helpers():
	audit_function(0x0084E730, "changed-record type discriminator", 16000)
	audit_function(0x0084E850, "changed-record reconstruction metadata reader", 18000)
	audit_function(0x0084E3A0, "changed-record runtime identity helper", 18000)
	audit_function(0x0084E610, "changed-record flags reader", 18000)
	audit_function(0x0084E6A0, "changed-record payload reference reader", 22000)
	audit_function(0x0084E930, "created-reference publication helper", 24000)
	audit_function(0x00845760, "changed-form map lookup", 22000)
	audit_function(0x00559450, "runtime FormID lookup used by reconstruction", 22000)

def audit_exact_control_flow():
	disasm_range(0x00850800, 0x00850870, "top-level changed-form call and success decision")
	disasm_range(0x00847DF0, 0x008482D0, "load setup and initial data")
	disasm_range(0x008482D0, 0x00848780, "first changed-record pass and loop exit")
	disasm_range(0x00848780, 0x00848C80, "rejected-record pass, live publication, and completion")
	disasm_range(0x00849D00, 0x0084A360, "reconstruction branches and payload-reference handling")
	disasm_range(0x0084F8E0, 0x0084FBB0, "created-reference allocation and missing bound-object branches")

def main():
	write("=" * 70)
	write("SAVE MISSING-CONTENT RUNAWAY LOAD FOLLOW-UP")
	write("=" * 70)
	write("Resolve why a missing-content save enters the visible world without returning from the changed-form load owner, keeps allocating medium blocks, and never reports an owning FormID-zero rejection. Distinguish missing record owners from unresolved FormIDs embedded in surviving records and identify the earliest record-local rejection boundary before reconstruction or publication.")
	audit_load_owners()
	audit_record_identity_and_payload()
	audit_application_helpers()
	audit_exact_control_flow()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/save_missing_content_runaway_load_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
