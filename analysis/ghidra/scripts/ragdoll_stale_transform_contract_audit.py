# @category Analysis
# @description Audit ragdoll stale-but-non-null transform state after save-load

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.address import AddressSet

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

def decompile_at(addr_int, label, max_len=24000):
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
			write("  [decompile truncated at %d chars, total %d]" % (max_len, len(code)))
	else:
		write("  [decompilation failed]")

def find_refs_to(addr_int, label, limit=260):
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

def scan_calls_to_targets(start_int, end_int, targets, label, limit=420):
	write("")
	write("=" * 70)
	write("Calls to target set in 0x%08x-0x%08x (%s)" % (start_int, end_int, label))
	write("=" * 70)
	aset = AddressSet(toAddr(start_int), toAddr(end_int))
	inst_iter = listing.getInstructions(aset, True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				if tgt in targets:
					func = fm.getFunctionContaining(inst.getAddress())
					write("  %-24s 0x%08x -> 0x%08x in %s" % (targets[tgt], inst.getAddress().getOffset(), tgt, name_for_func(func)))
					count += 1
					if count >= limit:
						write("  ... (truncated at %d)" % limit)
						write("  Total printed: %d" % count)
						return
	write("  Total printed: %d" % count)

def scan_text_mentions(start_int, end_int, terms, label, limit=420):
	write("")
	write("=" * 70)
	write("Instruction text scan in 0x%08x-0x%08x (%s)" % (start_int, end_int, label))
	write("=" * 70)
	aset = AddressSet(toAddr(start_int), toAddr(end_int))
	inst_iter = listing.getInstructions(aset, True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		hit = None
		for term in terms:
			if term in text:
				hit = term
				break
		if hit is not None:
			func = fm.getFunctionContaining(inst.getAddress())
			write("  hit=%-12s 0x%08x %-56s in %s" % (hit, inst.getAddress().getOffset(), inst.toString(), name_for_func(func)))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				break
	write("  Total printed: %d" % count)

def audit_ragdoll_paths():
	targets = [
		(0x00c79680, "Ragdoll skeleton update reader of bone_table[i] + 0x34"),
		(0x00c796f7, "Ragdoll skeleton update crash-context instruction"),
		(0x00c7d810, "Bone transform update guarded target"),
		(0x00c7d630, "Alternate ragdoll update guarded target"),
		(0x00c7d900, "bhkRagdollController cleanup/destructor"),
		(0x00c7f060, "bhkRagdollController constructor"),
		(0x00c7e9a0, "Ragdoll controller data init helper"),
		(0x00c75c00, "Ragdoll constructor follow-up helper"),
		(0x00c85750, "Havok allocator/context accessor"),
		(0x00931443, "Actor process frame calling ragdoll update"),
		(0x0056f8d4, "Reference/queued character processing frame"),
		(0x00452d22, "Cell attach/update frame"),
	]
	for item in targets:
		decompile_at(item[0], item[1], 26000)
		find_and_print_calls_from(item[0], item[1], 260)
		disasm_window(item[0], 22, 90, item[1])

def audit_refs():
	find_refs_to(0x00c79680, "Ragdoll skeleton update", 260)
	find_refs_to(0x00c7d810, "Bone transform update", 260)
	find_refs_to(0x00c7d630, "Alternate ragdoll update", 260)
	find_refs_to(0x00c7d900, "Ragdoll cleanup/destructor", 260)
	find_refs_to(0x00c7f060, "Ragdoll constructor", 260)
	find_refs_to(0x010c4ddc, "bhkRagdollController vtable", 260)

def audit_allocator_and_pdd_overlap():
	targets = {
		0x00aa3e40: "GameHeap::Allocate",
		0x00aa4060: "GameHeap::Free",
		0x00aa4150: "GameHeap::Realloc1",
		0x00aa4200: "GameHeap::Realloc2",
		0x00868d70: "PDD full drain",
		0x00868850: "Per-frame PDD drain",
		0x00867f90: "PDD generic router",
		0x00868330: "PDD NiNode enqueue",
		0x00868560: "PDD texture/anim enqueue",
		0x00c459d0: "Async flush",
		0x00c3e310: "hkWorld lock",
		0x00c3e340: "hkWorld unlock",
	}
	scan_calls_to_targets(0x00c70000, 0x00c82000, targets, "ragdoll/controller range", 520)
	scan_calls_to_targets(0x00900000, 0x00990000, targets, "actor process/high-process range", 520)
	scan_calls_to_targets(0x00450000, 0x00580000, targets, "cell/ref attach range", 520)

def audit_field_mentions():
	terms = ["0xa4", "0x2a4", "0x34", "0x8c", "0x90", "0x94", "0x98", "0x9c", "0x100", "0x104"]
	scan_text_mentions(0x00c70000, 0x00c82000, terms, "ragdoll fields and transform offsets", 700)
	scan_text_mentions(0x00900000, 0x00990000, ["0x2b", "0x34", "0xa4", "0x2a4"], "actor process ragdoll pointer use", 420)

def main():
	write("Ragdoll stale transform contract audit")
	write("")
	write("Goal:")
	write("  Existing guard covers NULL bone entries. The reported bug is stale-but-valid state:")
	write("  head/neck transform rotates around the wrong axis after save-load.")
	write("  This script maps writers/readers/destructors for ragdoll bone tables and transform fields")
	write("  so we can distinguish incomplete init, stale PDD object reuse, and block-tier buffer reuse.")
	audit_ragdoll_paths()
	audit_refs()
	audit_allocator_and_pdd_overlap()
	audit_field_mentions()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/ragdoll_stale_transform_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
