# @category Analysis
# @description Track bhkRagdollController +0xA4 population, save-load reuse, and safe owner clear path

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

def decompile_at(addr_int, label, max_len=30000):
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

def find_and_print_calls_from(addr_int, label, limit=300):
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
		write("  0x%08x: %-62s%s" % (off, inst.toString(), marker))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (tgt, name_for_func(func_for(tgt))))
		inst = inst.getNext()
		idx += 1

def classify_offset_access(inst, term):
	text = inst.toString().lower()
	if term not in text:
		return None
	mn = inst.getMnemonicString().lower()
	if "," in text:
		left = text.split(",", 1)[0]
		if "[" in left and term in left:
			if mn.startswith("mov") or mn.startswith("fst") or mn.startswith("xchg") or mn.startswith("cmpxchg"):
				return "WRITE_DST"
			return "WRITE_LIKE_DST"
	if "[" in text:
		return "READ_OR_ADDR"
	return "STACK_OR_IMM"

def is_nonstack_dst_offset_write(inst, term):
	kind = classify_offset_access(inst, term)
	if kind != "WRITE_DST":
		return False
	text = inst.toString().lower()
	if "," not in text:
		return False
	left = text.split(",", 1)[0]
	if "esp" in left or "ebp" in left:
		return False
	return True

def add_seen(seen, func):
	if func is None:
		return
	key = func.getEntryPoint().getOffset()
	if key not in seen:
		seen[key] = func

def inspect_function_offsets(addr_int, label, terms):
	func = func_for(addr_int)
	write("")
	write("=" * 70)
	write("Targeted offset accesses in %s (0x%08x)" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
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
			kind = classify_offset_access(inst, hit)
			if kind is None:
				kind = "MENTION"
			write("  %-14s hit=%-8s 0x%08x %s" % (kind, hit, inst.getAddress().getOffset(), inst.toString()))
			count += 1
	write("  Total hits: %d" % count)

def inspect_target(addr_int, label, max_len=30000):
	decompile_at(addr_int, label, max_len)
	find_and_print_calls_from(addr_int, label, 360)
	inspect_function_offsets(addr_int, label, ["0xa4", "0xa8", "0x9c", "0x94", "0x98", "0x88", "0x48", "0x58", "0x2a4", "0x2a0", "0x2b", "0x594", "0x598", "0x28c", "0x68"])

def scan_offset_accesses(start_int, end_int, term, label, limit=500, owner_limit=80):
	write("")
	write("=" * 70)
	write("Offset access scan for %s in 0x%08x-0x%08x (%s)" % (term, start_int, end_int, label))
	write("=" * 70)
	aset = AddressSet(toAddr(start_int), toAddr(end_int))
	inst_iter = listing.getInstructions(aset, True)
	seen = {}
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		kind = classify_offset_access(inst, term)
		if kind is not None:
			func = fm.getFunctionContaining(inst.getAddress())
			add_seen(seen, func)
			write("  %-14s 0x%08x %-60s in %s" % (kind, inst.getAddress().getOffset(), inst.toString(), name_for_func(func)))
			count += 1
			if count >= limit:
				write("  ... (scan truncated at %d)" % limit)
				break
	write("  Total printed: %d" % count)
	write("")
	write("-" * 70)
	write("Owner functions for %s" % term)
	write("-" * 70)
	keys = sorted(seen.keys())
	printed = 0
	for key in keys:
		write("  0x%08x %s" % (key, name_for_func(seen[key])))
		printed += 1
		if printed >= owner_limit:
			write("  ... (owner list truncated at %d)" % owner_limit)
			break

def scan_nonstack_writes(start_int, end_int, term, label, limit=260):
	write("")
	write("=" * 70)
	write("Non-stack destination writes to %s in 0x%08x-0x%08x (%s)" % (term, start_int, end_int, label))
	write("=" * 70)
	aset = AddressSet(toAddr(start_int), toAddr(end_int))
	inst_iter = listing.getInstructions(aset, True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		if is_nonstack_dst_offset_write(inst, term):
			func = fm.getFunctionContaining(inst.getAddress())
			write("  0x%08x %-62s in %s" % (inst.getAddress().getOffset(), inst.toString(), name_for_func(func)))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				break
	write("  Total printed: %d" % count)

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
					write("  %-34s 0x%08x -> 0x%08x in %s" % (targets[tgt], inst.getAddress().getOffset(), tgt, name_for_func(func)))
					count += 1
					if count >= limit:
						write("  ... (truncated at %d)" % limit)
						write("  Total printed: %d" % count)
						return
	write("  Total printed: %d" % count)

def inspect_list(targets):
	for item in targets:
		inspect_target(item[0], item[1], item[2])

def inspect_population_candidates():
	targets = [
		(0x00c7f060, "bhkRagdollController constructor, live +0xA4 zero point", 36000),
		(0x00c7d3b0, "Constructor pre-init helper, calls 00C7BCB0", 24000),
		(0x00c7bcb0, "Temporary bone list builder called by 00C7D3B0", 36000),
		(0x00c75c00, "Constructor post-init helper consuming temporary bone list", 24000),
		(0x00c7e9a0, "Controller data init, builds +0x48/+0x58/+0x2A4", 42000),
		(0x00c7e3b0, "Skeleton group builder, builds +0x88/+0x94/+0x98", 42000),
		(0x00c78090, "Ragdoll helper reads live +0xA4/+0xA8 triplets", 30000),
		(0x00c79340, "Ragdoll readiness/state helper used before fallback rebuild", 32000),
		(0x00c817d0, "Nearby class function reading +0xA4", 24000),
		(0x00c81890, "Nearby class function reading +0xA4", 24000),
		(0x00ca9580, "Outer subobject initializer fed setup +0xA4/+0x9C", 32000),
		(0x00cac300, "Late init helper called after setup +0x48 write", 30000),
	]
	inspect_list(targets)

def inspect_update_and_writeback():
	targets = [
		(0x00c79680, "Skeleton update reads live +0xA4 and copies to +0x94", 36000),
		(0x00c75b40, "Save/load style writeback writes +0x94 into live +0xA4 bone entries", 24000),
		(0x00c79a50, "Runtime writeback writes +0x94 into live +0xA4 bone entries", 36000),
		(0x00c7c150, "State reset touches live +0xA4 bone entries", 24000),
		(0x00c7d630, "Alternate update wrapper", 30000),
		(0x00c7d810, "Bone transform update wrapper", 24000),
		(0x00c7d900, "bhkRagdollController destructor/cleanup", 30000),
		(0x00c7de60, "Runtime skeleton fallback/rebuild helper", 36000),
	]
	inspect_list(targets)

def inspect_owner_reuse_clear_path():
	targets = [
		(0x009306d0, "Existing ragdoll getter through actor process vtable +0x28C", 16000),
		(0x00930c70, "Actor process creates/reuses ragdoll and handles NiNode changes", 52000),
		(0x0087e130, "Actor/NiNode attach path creating bhkRagdollController", 52000),
		(0x0087e9d0, "Attach helper near ragdoll owner flag write", 20000),
		(0x0087e980, "Attach helper used after getter returns non-null", 20000),
		(0x0087ea80, "Attach helper fed existing ragdoll data", 20000),
		(0x0087ea20, "Attach success predicate after controller construction", 20000),
		(0x00931510, "Actor process ragdoll create helper", 24000),
		(0x00931530, "Actor process ragdoll update helper", 24000),
		(0x00931560, "Actor process ragdoll post-create helper", 24000),
		(0x00931580, "Actor process ragdoll conditional helper", 24000),
		(0x009315a0, "Player-specific ragdoll helper", 24000),
		(0x00930640, "Neighbor of ragdoll getter", 20000),
		(0x00930700, "Neighbor of ragdoll getter", 20000),
		(0x009307d0, "Neighbor of ragdoll getter", 20000),
		(0x009308f0, "Neighbor of ragdoll getter", 24000),
		(0x00931ed0, "Existing ragdoll query/owner helper", 30000),
		(0x00931fb0, "Existing ragdoll query/owner helper", 24000),
		(0x00810640, "Ragdoll owner character backlink setter", 16000),
		(0x00c6e050, "Owner/backlink writer called by 00810640", 20000),
		(0x00c6d7a0, "Ragdoll NiNode change handler", 16000),
		(0x00c85c10, "Ragdoll owned object retarget helper", 20000),
	]
	inspect_list(targets)

def inspect_refs_and_windows():
	find_refs_to(0x00c7f060, "bhkRagdollController constructor", 260)
	find_refs_to(0x00c79680, "Skeleton update reader", 260)
	find_refs_to(0x00c75b40, "Save/load style writeback", 260)
	find_refs_to(0x00c79a50, "Runtime writeback", 260)
	find_refs_to(0x00c7d900, "Controller destructor", 260)
	find_refs_to(0x010c4ddc, "Final bhkRagdollController vtable", 260)
	find_refs_to(0x010c49c4, "Outer CreateRagdollController vtable", 260)
	find_refs_to(0x009306d0, "Existing ragdoll getter", 320)
	disasm_window(0x00c7f42b, 40, 80, "Constructor call to 00C7D3B0")
	disasm_window(0x00c7f454, 40, 80, "Constructor call to 00C75C00")
	disasm_window(0x0087e357, 55, 95, "Attach path call to 00C7F060")
	disasm_window(0x00930f42, 45, 115, "Actor process getter and create branch")
	disasm_window(0x00931265, 45, 115, "Actor process NiNode change retarget path")
	disasm_window(0x00931384, 45, 95, "Actor process forced attach path")

def scan_global_candidates():
	scan_offset_accesses(0x00c70000, 0x00c82000, "0xa4", "focused ragdoll/controller code", 700, 100)
	scan_offset_accesses(0x00c70000, 0x00c82000, "0xa8", "focused ragdoll/controller code", 700, 100)
	scan_nonstack_writes(0x00c00000, 0x00cf0000, "0xa4", "Havok/controller region, exact population candidates", 360)
	scan_nonstack_writes(0x00c00000, 0x00cf0000, "0xa8", "Havok/controller region, exact count/capacity candidates", 360)
	targets = {
		0x00c7f060: "bhkRagdollController constructor",
		0x00c7d3b0: "constructor pre-init helper",
		0x00c7bcb0: "temporary bone list builder",
		0x00c75c00: "constructor post-init helper",
		0x00c7e9a0: "controller data init",
		0x00c7e3b0: "skeleton group builder",
		0x00c7de60: "runtime fallback/rebuild",
		0x00c79680: "skeleton update reader",
		0x00c75b40: "writeback helper",
		0x00c79a50: "runtime writeback",
		0x00c7d900: "controller cleanup",
	}
	scan_calls_to_targets(0x00c00000, 0x00cf0000, targets, "Havok/controller region calls into ragdoll functions", 620)
	scan_calls_to_targets(0x00800000, 0x00990000, targets, "actor/process region calls into ragdoll functions", 620)

def main():
	write("Ragdoll +0xA4 population and save-load owner dataflow audit")
	write("")
	write("Goal:")
	write("  Prove the writer/owner of live bhkRagdollController +0xA4 and +0xA8.")
	write("  Distinguish live controller fields from setup-object fields with the same offsets.")
	write("  Prove a safe intervention path: validate/skip, rebuild live controller, or clear owner pointer.")
	write("")
	inspect_population_candidates()
	inspect_update_and_writeback()
	inspect_owner_reuse_clear_path()
	inspect_refs_and_windows()
	scan_global_candidates()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/ragdoll_a4_population_dataflow_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
