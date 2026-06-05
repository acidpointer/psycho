# @category Analysis
# @description Deep audit of ragdoll save-load stale transform ownership and +0xA4 population contract

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

def add_seen(seen, func):
	if func is None:
		return
	key = func.getEntryPoint().getOffset()
	if key not in seen:
		seen[key] = func

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

def scan_offset_accesses(start_int, end_int, term, label, limit=500, owner_limit=60):
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
	inspect_function_offsets(addr_int, label, ["0xa4", "0xa8", "0x9c", "0x94", "0x98", "0x88", "0x48", "0x58", "0x2a4", "0x22c", "0x230", "0x594", "0x598", "0x28c", "0x68", "0x80"])

def inspect_ragdoll_contract_functions():
	targets = [
		(0x00c73ed0, "CreateRagdollController late init helper, likely hidden +0xA4 contract"),
		(0x00c741e0, "CreateRagdollController main constructor"),
		(0x00c72410, "Nearby large ragdoll/character init helper before 00C73ED0"),
		(0x00c73170, "Nearby large ragdoll/character update owner before 00C73ED0"),
		(0x00c74570, "Ragdoll constructor post-helper neighbor"),
		(0x00c7f060, "bhkRagdollController constructor, zeroes +0xA4/+0x2A4"),
		(0x00c7e9a0, "bhkRagdollController data init helper, sets +0x48/+0x58/+0x2A4"),
		(0x00c7e3b0, "Builds ragdoll skeleton groups from +0x58 into +0x2A4"),
		(0x00c7de60, "Runtime ragdoll skeleton fallback/rebuild helper"),
		(0x00c7d900, "bhkRagdollController cleanup/destructor"),
		(0x00c79680, "Skeleton update, reads +0xA4 bone entries and writes +0x94"),
		(0x00c75b40, "Writes +0x94 transforms back into bone entries"),
		(0x00c79a50, "Runtime update writes into bone entries"),
		(0x00c7c150, "State reset touches bone entries and readiness flags"),
		(0x00c79e20, "Alignment assertion/sanity checker using +0x48/+0x2A4"),
		(0x00c7d630, "Alternate update wrapper"),
		(0x00c7d810, "Bone transform update wrapper"),
	]
	for item in targets:
		inspect_target(item[0], item[1], 32000)

def inspect_owner_and_save_load_path():
	targets = [
		(0x009306d0, "Existing ragdoll getter through actor process +0x68 vtable+0x28C"),
		(0x00930c70, "Actor process creates/reuses ragdoll and handles NiNode change"),
		(0x0087e130, "Actor/NiNode attach path that calls bhkRagdollController constructor"),
		(0x0043fcd0, "Get current NiNode from character"),
		(0x00c6d7a0, "Ragdoll NiNode change handler using +0x594/+0x598"),
		(0x00c85c10, "Ragdoll owned object retarget helper called by NiNode change"),
		(0x00810640, "Ragdoll owner character backlink setter"),
		(0x00c6e050, "Owner/backlink writer called by 00810640"),
		(0x008e5700, "Death/ragdoll note existence check"),
		(0x008e4e50, "Death processing reads existing ragdoll through vtable+0x28C"),
		(0x0048fb50, "NiNode PDD inner destructor, possible old tree teardown"),
		(0x0086f940, "Cell transition/load-adjacent actor processing context"),
	]
	for item in targets:
		inspect_target(item[0], item[1], 26000)

def inspect_refs():
	find_refs_to(0x00c73ed0, "CreateRagdollController late init helper", 260)
	find_refs_to(0x00c741e0, "CreateRagdollController main", 260)
	find_refs_to(0x00c7f060, "bhkRagdollController constructor", 260)
	find_refs_to(0x00c7d900, "bhkRagdollController cleanup", 260)
	find_refs_to(0x00c79680, "Skeleton update reader", 260)
	find_refs_to(0x00c75b40, "Bone-entry writeback helper", 260)
	find_refs_to(0x00c79a50, "Runtime bone-entry writeback helper", 260)
	find_refs_to(0x00c7e3b0, "Skeleton group builder", 260)
	find_refs_to(0x00c7de60, "Skeleton fallback/rebuild helper", 260)
	find_refs_to(0x00c79e20, "Alignment assertion/sanity checker", 260)
	find_refs_to(0x009306d0, "Existing ragdoll getter", 260)
	find_refs_to(0x010c4ddc, "Final bhkRagdollController vtable", 260)
	find_refs_to(0x010c49c4, "Initial CreateRagdollController vtable", 260)

def inspect_disasm_hotspots():
	hotspots = [
		(0x00c74016, "Call from 00C73ED0 to allocator/context accessor"),
		(0x00c7422b, "CreateRagdollController reads setup +0xA4"),
		(0x00c74512, "CreateRagdollController calls 00C73ED0"),
		(0x00c7f0da, "Constructor zeroes exact +0xA4"),
		(0x00c796e0, "Skeleton update reads exact +0xA4"),
		(0x00c79ab9, "Runtime update reads exact +0xA4"),
		(0x00c75b8a, "Writeback helper reads exact +0xA4"),
		(0x00c7c1e0, "State reset reads exact +0xA4"),
		(0x00931074, "Actor process constructs ragdoll controller"),
		(0x00931230, "Actor process gets current ragdoll NiNode owner"),
		(0x00931265, "Actor process retargets ragdoll to new NiNode"),
	]
	for item in hotspots:
		disasm_window(item[0], 28, 90, item[1])

def inspect_global_offset_scans():
	scan_offset_accesses(0x00c70000, 0x00c82000, "0xa4", "focused ragdoll/controller code", 800, 80)
	scan_offset_accesses(0x00c70000, 0x00c82000, "0x2a4", "focused ragdoll/controller code", 500, 80)
	scan_offset_accesses(0x00c70000, 0x00c82000, "0x48", "focused ragdoll scene root field", 500, 80)
	scan_offset_accesses(0x00c70000, 0x00c82000, "0x58", "focused ragdoll transform root field", 500, 80)
	scan_offset_accesses(0x00800000, 0x00990000, "0x28c", "actor/high-process ragdoll virtual getter", 400, 80)
	scan_offset_accesses(0x00800000, 0x00990000, "0x68", "actor process pointer and HighProcess owner", 500, 80)

def main():
	write("Ragdoll save-load stale transform contract deep audit")
	write("")
	write("Goal:")
	write("  Prove where bhkRagdollController +0xA4 is populated, not only read.")
	write("  Prove whether save/load reuses a controller whose +0x48/+0x58/+0x2A4/+0xA4 belong to different generations.")
	write("  Identify the safe intervention point: skip update, rebuild controller, or clear owner ragdoll pointer.")
	write("")
	write("Known before this script:")
	write("  Current Rust guard validates readability/nullness only. That catches NULL entries but not stale readable transforms.")
	write("  FUN_00C79680 reads bone_table[i]+0x34; FUN_00C75B40 and FUN_00C79A50 write transforms back into bone entries.")
	write("")
	inspect_ragdoll_contract_functions()
	inspect_owner_and_save_load_path()
	inspect_refs()
	inspect_disasm_hotspots()
	inspect_global_offset_scans()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/ragdoll_save_load_contract_deep_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
