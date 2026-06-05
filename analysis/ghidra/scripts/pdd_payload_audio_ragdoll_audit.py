# @category Analysis
# @description Audit PDD queue payload producers and whether audio/ragdoll objects enter deferred destruction

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

def decompile_at(addr_int, label, max_len=22000):
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

def collect_ref_functions(addr_int, limit):
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = {}
	count = 0
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is not None:
			seen[func.getEntryPoint().getOffset()] = func
		count += 1
		if count >= limit:
			break
	return seen

def decompile_ref_functions(addr_int, label, limit=260, max_funcs=80):
	write("")
	write("=" * 70)
	write("Functions referencing 0x%08x (%s)" % (addr_int, label))
	write("=" * 70)
	seen = collect_ref_functions(addr_int, limit)
	keys = sorted(seen.keys())
	printed = 0
	for key in keys:
		decompile_at(key, "ref-user: %s" % label, 18000)
		find_and_print_calls_from(key, "ref-user: %s" % label, 160)
		printed += 1
		if printed >= max_funcs:
			write("  [ref-user decompile truncated at %d functions]" % max_funcs)
			break
	write("  Unique ref functions printed: %d" % printed)

def scan_calls_to_targets(start_int, end_int, targets, label, limit=520):
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

def audit_pdd_core():
	write("")
	write("=" * 70)
	write("PDD core queue functions")
	write("=" * 70)
	targets = [
		(0x00868d70, "Full PDD drain"),
		(0x00868850, "Vanilla per-frame PDD drain"),
		(0x00867f90, "PDD generic queue router"),
		(0x00868270, "PDD queue helper mentioned by Generic refs"),
		(0x00868330, "PDD NiNode enqueue/cleanup path"),
		(0x00868490, "PDD Form enqueue path"),
		(0x00868560, "PDD texture/anim enqueue path"),
		(0x00868d10, "PDD form/small queue helper"),
		(0x008693c0, "PDD vector enqueue helper"),
		(0x008694c0, "PDD queue move helper"),
		(0x00869420, "PDD queue move helper 2"),
		(0x00869510, "PDD Havok queue move helper"),
	]
	for item in targets:
		decompile_at(item[0], item[1], 22000)
		find_and_print_calls_from(item[0], item[1], 220)

def audit_queue_refs():
	queue_items = [
		(0x011de808, "PDD NiNode queue"),
		(0x011de828, "PDD form queue"),
		(0x011de874, "PDD generic queue"),
		(0x011de888, "PDD anim/form queue"),
		(0x011de910, "PDD texture queue"),
		(0x011de924, "PDD Havok/NiRef queue"),
		(0x011de958, "PDD reentrancy guard"),
		(0x011de804, "PDD skip mask"),
	]
	for item in queue_items:
		find_refs_to(item[0], item[1], 320)
		decompile_ref_functions(item[0], item[1], 420, 60)

def audit_producer_overlap():
	targets = {
		0x00867f90: "generic router",
		0x00868330: "NiNode enqueue",
		0x00868490: "Form enqueue",
		0x00868560: "texture/anim enqueue",
		0x00868d10: "form/small helper",
		0x008693c0: "queue push helper",
		0x00868d70: "full PDD",
		0x00868850: "per-frame PDD",
		0x00aa3e40: "GameHeap::Allocate",
		0x00aa4060: "GameHeap::Free",
		0x00aa4150: "GameHeap::Realloc1",
		0x00aa4200: "GameHeap::Realloc2",
		0x00c459d0: "Async flush",
	}
	scan_calls_to_targets(0x00ad8000, 0x00aeb800, targets, "audio subsystem range", 520)
	scan_calls_to_targets(0x00c70000, 0x00c82000, targets, "ragdoll/controller range", 520)
	scan_calls_to_targets(0x00900000, 0x00990000, targets, "actor process/ragdoll high-process range", 520)
	scan_calls_to_targets(0x00450000, 0x00580000, targets, "cell/ref processing range", 520)

def audit_payload_type_hints():
	terms = ["0x10", "0x100", "0xc4", "0x224", "0x228", "0x434", "0xa4", "0x2a4", "0xf4"]
	scan_text_mentions(0x00867000, 0x00869600, terms, "PDD vtable slots and queue fields", 520)
	scan_text_mentions(0x00ad8000, 0x00aeb800, terms, "audio fields near possible PDD producers", 360)
	scan_text_mentions(0x00c70000, 0x00c82000, terms, "ragdoll fields near possible PDD producers", 360)

def main():
	write("PDD payload audio/ragdoll audit")
	write("")
	write("Goal:")
	write("  Identify which game systems enqueue objects into PDD queues.")
	write("  Specifically verify whether audio voice/playback objects or ragdoll/bone objects")
	write("  can be freed under the gheap PDD freeze guard.")
	write("  This is required before treating the 5s PDD thaw delay as the direct root cause.")
	audit_pdd_core()
	audit_queue_refs()
	audit_producer_overlap()
	audit_payload_type_hints()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/memory/pdd_payload_audio_ragdoll_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
