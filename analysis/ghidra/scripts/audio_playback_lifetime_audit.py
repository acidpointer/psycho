# @category Analysis
# @description Audit audio playback lifetime, locks, allocator use, and async/PDD overlap

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

def scan_text_mentions(start_int, end_int, terms, label, limit=320):
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

def audit_audio_roots():
	write("")
	write("=" * 70)
	write("Audio roots and known lock/wait functions")
	write("=" * 70)
	targets = [
		(0x00aea020, "BSAudioManager singleton write/init"),
		(0x00aea100, "Audio manager lock/helper used before TryEnter sites"),
		(0x00addc00, "Audio TryEnterCriticalSection per-frame/update user"),
		(0x00adddd0, "Audio update callee from TryEnter path"),
		(0x00add1e0, "Audio singleton heavy user A"),
		(0x00adbb30, "Audio singleton heavy user B"),
		(0x00adf080, "Audio singleton heavy user C"),
		(0x00ada1d0, "Audio singleton repeated-field user"),
		(0x00add6f0, "Audio singleton repeated-field user 2"),
		(0x00ae5a50, "Audio singleton repeated-field user 3"),
		(0x00ae9460, "Audio singleton repeated-field user 4"),
		(0x00ad9870, "Audio singleton user near thread/wait range"),
		(0x00c459d0, "Async flush used by cell transitions and OOM stage 3"),
		(0x00c46080, "Async flush inner batch"),
		(0x00c45a80, "Async flush inner queue"),
	]
	for item in targets:
		decompile_at(item[0], item[1], 22000)
		find_and_print_calls_from(item[0], item[1], 220)
		disasm_window(item[0], 18, 80, item[1])

def audit_refs():
	find_refs_to(0x011f6d98, "BSAudioManager_Singleton", 320)
	decompile_ref_functions(0x011f6d98, "BSAudioManager_Singleton", 420, 90)
	find_refs_to(0x00aea100, "Audio lock/helper", 160)
	find_refs_to(0x00c459d0, "Async flush", 120)

def audit_allocator_and_pdd_overlap():
	targets = {
		0x00aa3e40: "GameHeap::Allocate",
		0x00aa4060: "GameHeap::Free",
		0x00aa4150: "GameHeap::Realloc1",
		0x00aa4200: "GameHeap::Realloc2",
		0x00aa44c0: "GameHeap::Msize",
		0x00ecd1c7: "CRT malloc1",
		0x00ed0cdf: "CRT malloc2",
		0x00eddd7d: "CRT calloc1",
		0x00ed0d24: "CRT calloc2",
		0x00eccf5d: "CRT realloc1",
		0x00ed0d70: "CRT realloc2",
		0x00ecd291: "CRT free",
		0x00868d70: "PDD full drain",
		0x00868850: "Per-frame PDD drain",
		0x00867f90: "PDD generic router",
		0x00868330: "PDD NiNode enqueue",
		0x00868560: "PDD texture/anim enqueue",
		0x00c459d0: "Async flush",
		0x0040fbf0: "spin-lock acquire",
		0x0078d200: "try-lock acquire",
		0x00ad8da0: "wait/dequeue",
	}
	scan_calls_to_targets(0x00ad8000, 0x00aeb800, targets, "audio subsystem range", 520)
	scan_calls_to_targets(0x00450000, 0x00460000, targets, "cell attach/audio call range", 220)

def audit_field_mentions():
	terms = ["0x14", "0xf4", "0x100", "0x104", "0x108", "0x10c", "0x110", "0x114"]
	scan_text_mentions(0x00ad8000, 0x00aeb800, terms, "audio singleton/list/lock fields", 420)

def main():
	write("Audio playback lifetime audit")
	write("")
	write("Goal:")
	write("  Explain NPC voice stutter/wrong speed without guessing.")
	write("  Map BSAudioManager users, locks, allocator calls, and overlap with PDD/async flush.")
	write("  This should answer whether gheap PDD freeze can retain/reuse audio objects,")
	write("  or whether audio symptoms are more likely from async flush/lock contention/VAS pressure.")
	audit_audio_roots()
	audit_refs()
	audit_allocator_and_pdd_overlap()
	audit_field_mentions()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/memory/audio_playback_lifetime_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
