# @category Analysis
# @description Trace FNV PBR PPLighting pass-entry resource argument provenance before E7EA00 texture binding

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00BA8C50: "pass-entry reused-entry array setter",
	0x00BA8EC0: "pass-entry constructor",
	0x00BA9EE0: "pass-entry append/reuse helper",
	0x00B7DD50: "B7 dispatcher current-pass entry apply",
	0x00BD9540: "PPLighting pass-entry helper 00BD9540",
	0x00BD9770: "PPLighting pass-entry helper 00BD9770",
	0x00BD9840: "PPLighting pass-entry helper 00BD9840",
	0x00BD99C0: "PPLighting pass-entry helper 00BD99C0",
	0x00BD9AC0: "PPLighting pass-entry helper 00BD9AC0",
	0x00BD9BC0: "PPLighting pass-entry helper 00BD9BC0",
	0x00BD9D00: "PPLighting pass-entry helper 00BD9D00",
	0x00BD9DA0: "PPLighting pass-entry helper 00BD9DA0",
	0x00BD9E60: "PPLighting pass-entry helper 00BD9E60",
	0x00BD9F00: "PPLighting pass-entry helper 00BD9F00",
	0x00BD9F90: "PPLighting pass-entry helper 00BD9F90",
	0x00BDA030: "PPLighting pass-entry helper 00BDA030",
	0x00BDA060: "PPLighting pass-entry helper 00BDA060",
	0x00BDA0A0: "PPLighting pass-entry helper 00BDA0A0",
	0x00BDAC00: "PPLighting pass-entry helper 00BDAC00",
	0x00BDAF10: "PPLighting pass-entry helper 00BDAF10",
	0x00BDB380: "PPLighting pass-entry helper 00BDB380",
	0x00BDBF60: "PPLighting pass-entry helper 00BDBF60",
	0x00BDC030: "PPLighting pass-entry helper 00BDC030",
	0x00BDC0D0: "PPLighting pass-entry helper 00BDC0D0",
	0x00BDC530: "PPLighting pass-entry helper 00BDC530",
	0x00BDCA60: "PPLighting pass-entry helper 00BDCA60",
	0x00BDD050: "PPLighting pass-entry helper 00BDD050",
	0x00BDD520: "PPLighting pass-entry helper 00BDD520",
	0x00BDDA20: "PPLighting pass-entry helper 00BDDA20",
	0x00BDDBC0: "PPLighting pass-entry helper 00BDDBC0",
	0x00BDDD80: "PPLighting pass-entry helper 00BDDD80",
	0x00BDDE10: "PPLighting pass-entry helper 00BDDE10",
	0x00BDDFB0: "PPLighting pass-entry helper 00BDDFB0",
	0x00BDE1D0: "PPLighting pass-entry helper 00BDE1D0",
	0x00BDE9B0: "PPLighting pass-entry helper 00BDE9B0",
	0x00BDEF40: "PPLighting pass-entry helper 00BDEF40",
	0x00BDF3E0: "PPLighting pass-entry helper 00BDF3E0",
	0x00BDF650: "PPLighting pass-entry helper 00BDF650",
	0x00BDF6C0: "PPLighting pass-entry helper 00BDF6C0",
	0x00BDF790: "PPLighting pass-entry helper 00BDF790",
	0x00C03230: "active object resource/state getter used before E7EB00",
	0x00E7EA00: "pass-entry downstream texture/state apply helper",
	0x00E7EB00: "pass-entry cache/apply helper",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x011F91E0: "current geometry/proxy global",
	0x011F951C: "global fallback resource used by B7E150 branch",
	0x0126F680: "pass-entry +8 cache table keyed by entry +4",
	0x0126F6C4: "renderer global used for resource resolver",
	0x0126F6C8: "renderer +0x8B8 render-state global",
	0x0126F74C: "current NiD3DPass global",
}

PASS_ENTRY_SCAN_FUNCTIONS = [
	(0x00BD9540, "PPLighting pass-entry helper 00BD9540"),
	(0x00BD9770, "PPLighting pass-entry helper 00BD9770"),
	(0x00BD9840, "PPLighting pass-entry helper 00BD9840"),
	(0x00BD99C0, "PPLighting pass-entry helper 00BD99C0"),
	(0x00BD9AC0, "PPLighting pass-entry helper 00BD9AC0"),
	(0x00BD9BC0, "PPLighting pass-entry helper 00BD9BC0"),
	(0x00BD9D00, "PPLighting pass-entry helper 00BD9D00"),
	(0x00BD9DA0, "PPLighting pass-entry helper 00BD9DA0"),
	(0x00BD9E60, "PPLighting pass-entry helper 00BD9E60"),
	(0x00BD9F00, "PPLighting pass-entry helper 00BD9F00"),
	(0x00BD9F90, "PPLighting pass-entry helper 00BD9F90"),
	(0x00BDA030, "PPLighting pass-entry helper 00BDA030"),
	(0x00BDA060, "PPLighting pass-entry helper 00BDA060"),
	(0x00BDA0A0, "PPLighting pass-entry helper 00BDA0A0"),
	(0x00BDAC00, "PPLighting pass-entry helper 00BDAC00"),
	(0x00BDAF10, "PPLighting pass-entry helper 00BDAF10"),
	(0x00BDB380, "PPLighting pass-entry helper 00BDB380"),
	(0x00BDBF60, "PPLighting pass-entry helper 00BDBF60"),
	(0x00BDC030, "PPLighting pass-entry helper 00BDC030"),
	(0x00BDC0D0, "PPLighting pass-entry helper 00BDC0D0"),
	(0x00BDC530, "PPLighting pass-entry helper 00BDC530"),
	(0x00BDCA60, "PPLighting pass-entry helper 00BDCA60"),
	(0x00BDD050, "PPLighting pass-entry helper 00BDD050"),
	(0x00BDD520, "PPLighting pass-entry helper 00BDD520"),
	(0x00BDDA20, "PPLighting pass-entry helper 00BDDA20"),
	(0x00BDDBC0, "PPLighting pass-entry helper 00BDDBC0"),
	(0x00BDDD80, "PPLighting pass-entry helper 00BDDD80"),
	(0x00BDDE10, "PPLighting pass-entry helper 00BDDE10"),
	(0x00BDDFB0, "PPLighting pass-entry helper 00BDDFB0"),
	(0x00BDE1D0, "PPLighting pass-entry helper 00BDE1D0"),
	(0x00BDE9B0, "PPLighting pass-entry helper 00BDE9B0"),
	(0x00BDEF40, "PPLighting pass-entry helper 00BDEF40"),
	(0x00BDF3E0, "PPLighting pass-entry helper 00BDF3E0"),
	(0x00BDF650, "PPLighting pass-entry helper 00BDF650"),
	(0x00BDF6C0, "PPLighting pass-entry helper 00BDF6C0"),
	(0x00BDF790, "PPLighting pass-entry helper 00BDF790"),
]

DYNAMIC_FOCUS_FUNCTIONS = [
	(0x00BD9540, "PPLighting pass-entry helper 00BD9540"),
	(0x00BDA0A0, "PPLighting pass-entry helper 00BDA0A0"),
	(0x00BDAF10, "PPLighting pass-entry helper 00BDAF10"),
	(0x00BDC0D0, "PPLighting pass-entry helper 00BDC0D0"),
	(0x00BDC530, "PPLighting pass-entry helper 00BDC530"),
	(0x00BDCA60, "PPLighting pass-entry helper 00BDCA60"),
	(0x00BDD050, "PPLighting pass-entry helper 00BDD050"),
	(0x00BDD520, "PPLighting pass-entry helper 00BDD520"),
	(0x00BDDA20, "PPLighting pass-entry helper 00BDDA20"),
	(0x00BDDBC0, "PPLighting pass-entry helper 00BDDBC0"),
	(0x00BDDE10, "PPLighting pass-entry helper 00BDDE10"),
	(0x00BDDFB0, "PPLighting pass-entry helper 00BDDFB0"),
	(0x00BDEF40, "PPLighting pass-entry helper 00BDEF40"),
	(0x00BDF3E0, "PPLighting pass-entry helper 00BDF3E0"),
	(0x00BDF650, "PPLighting pass-entry helper 00BDF650"),
	(0x00BDF790, "PPLighting pass-entry helper 00BDF790"),
]

ARG_NAMES = [
	"entry+0 type_or_mode",
	"entry+4 stage_key",
	"entry+7 byte",
	"entry+9 array_count",
	"resource0 entry+0x0c[0]",
	"resource1 entry+0x0c[1]",
	"resource2 entry+0x0c[2]",
	"resource3 entry+0x0c[3]",
]

REGISTERS = [
	"EAX",
	"EBX",
	"ECX",
	"EDX",
	"ESI",
	"EDI",
	"EBP",
]

SOURCE_PATTERNS = [
	"+ 0xac",
	"+0xac",
	"+ 0xb0",
	"+0xb0",
	"+ 0xb4",
	"+0xb4",
	"+ 0xb8",
	"+0xb8",
	"+ 0xbc",
	"+0xbc",
	"+ 0xc0",
	"+0xc0",
	"+ 0xc4",
	"+0xc4",
	"+ 0xcc",
	"+0xcc",
	"+ 0xdc",
	"+0xdc",
	"+ 0xec",
	"+0xec",
	"+ 0xf4",
	"+0xf4",
	"+ 0xe0",
	"+0xe0",
	"+ 0x90",
	"+0x90",
	"011f91e0",
	"011f951c",
	"0126f74c",
	"c03230",
	"ba9ee0",
	"e7eb00",
	"texture",
	"resource",
	"stage",
]

def write(msg):
	output.append(msg)
	print(msg)

def label_for(addr_int):
	if addr_int is None:
		return "unreadable"
	label = KNOWN.get(addr_int)
	if label is not None:
		return label
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is not None:
		return func.getName()
	func = fm.getFunctionContaining(toAddr(addr_int))
	if func is not None:
		return "%s+0x%x" % (func.getName(), addr_int - func.getEntryPoint().getOffset())
	return "unknown"

def operand_text(inst, index):
	try:
		return inst.getDefaultOperandRepresentation(index)
	except:
		return "?"

def decompile_text(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		return None
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		return result.getDecompiledFunction().getC()
	return None

def decompile_at(addr_int, label, max_len=18000):
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
	code = decompile_text(addr_int)
	if code is None:
		write("  [decompilation failed]")
		return
	write(code[:max_len])

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
		write("  %s/%s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getOperandIndex(), ref.getFromAddress().getOffset(), fname))
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
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, label_for(tgt)))
				count += 1
	write("  Total: %d calls" % count)

def collect_pushes_before(inst, max_pushes, max_steps):
	pushes = []
	cur = listing.getInstructionBefore(inst.getAddress())
	steps = 0
	while cur is not None and steps < max_steps and len(pushes) < max_pushes:
		mnemonic = cur.getMnemonicString()
		if mnemonic == "PUSH":
			pushes.append((cur.getAddress().getOffset(), operand_text(cur, 0), cur.toString()))
		elif mnemonic.startswith("CALL") or mnemonic.startswith("RET"):
			break
		cur = listing.getInstructionBefore(cur.getAddress())
		steps += 1
	return pushes

def instruction_before_steps(inst, steps):
	cur = inst
	count = 0
	while count < steps and cur is not None:
		cur = listing.getInstructionBefore(cur.getAddress())
		count += 1
	return cur

def print_short_window(center_inst, before_count, after_count):
	start = instruction_before_steps(center_inst, before_count)
	if start is None:
		start = center_inst
	cur = start
	count = 0
	limit = before_count + after_count + 1
	while cur is not None and count < limit:
		marker = "=>" if cur.getAddress().getOffset() == center_inst.getAddress().getOffset() else "  "
		write("    %s 0x%08x: %s" % (marker, cur.getAddress().getOffset(), cur.toString()))
		cur = listing.getInstructionAfter(cur.getAddress())
		count += 1

def is_register_text(text):
	upper = text.upper()
	for reg in REGISTERS:
		if upper == reg:
			return True
	return False

def is_constant_zero(text):
	lower = text.lower()
	return lower == "0x0" or lower == "0"

def get_push_arg(pushes, index):
	if index < len(pushes):
		return pushes[index][1]
	return "?"

def get_push_inst(pushes, index):
	if index < len(pushes):
		return listing.getInstructionAt(toAddr(pushes[index][0]))
	return None

def call_target_for_instruction(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		if ref.getReferenceType().isCall():
			return ref.getToAddress().getOffset()
	return None

def instruction_writes_register(inst, reg):
	mnemonic = inst.getMnemonicString()
	dst = operand_text(inst, 0).upper()
	if dst == reg:
		return True
	if mnemonic == "POP" and dst == reg:
		return True
	if mnemonic.startswith("CALL") and reg == "EAX":
		return True
	return False

def print_refs_from_instruction(inst, indent):
	refs = inst.getReferencesFrom()
	for ref in refs:
		write("%sref %s -> 0x%08x %s" % (indent, ref.getReferenceType(), ref.getToAddress().getOffset(), label_for(ref.getToAddress().getOffset())))

def print_register_defs_before(inst, reg, max_steps, max_hits, indent):
	cur = listing.getInstructionBefore(inst.getAddress())
	steps = 0
	hits = 0
	while cur is not None and steps < max_steps and hits < max_hits:
		if instruction_writes_register(cur, reg):
			write("%sdef %s @ 0x%08x: %s" % (indent, reg, cur.getAddress().getOffset(), cur.toString()))
			print_refs_from_instruction(cur, indent + "  ")
			hits += 1
			if hits == 1:
				print_source_reg_defs(cur, reg, indent + "  ")
		mnemonic = cur.getMnemonicString()
		if mnemonic.startswith("RET"):
			break
		cur = listing.getInstructionBefore(cur.getAddress())
		steps += 1
	if hits == 0:
		write("%sdef %s: [no local write found in %d instructions]" % (indent, reg, max_steps))

def print_source_reg_defs(inst, written_reg, indent):
	src = operand_text(inst, 1).upper()
	if src == written_reg:
		return
	if is_register_text(src):
		write("%sfollow source register %s before 0x%08x:" % (indent, src, inst.getAddress().getOffset()))
		print_register_defs_before(inst, src, 36, 2, indent + "  ")

def row_has_interesting_resources(pushes):
	array_count = get_push_arg(pushes, 3)
	if array_count == "?":
		return True
	if not is_constant_zero(array_count):
		return True
	index = 0
	while index < len(pushes):
		if get_push_arg(pushes, index) == "?":
			return True
		index += 1
	return False

def print_arg_provenance(pushes, index):
	arg = get_push_arg(pushes, index)
	arg_inst = get_push_inst(pushes, index)
	if arg_inst is None:
		write("    %-28s = %-10s ; [push instruction not found]" % (ARG_NAMES[index], arg))
		return
	write("    %-28s = %-10s ; push @ 0x%08x" % (ARG_NAMES[index], arg, arg_inst.getAddress().getOffset()))
	if is_register_text(arg):
		print_register_defs_before(arg_inst, arg.upper(), 42, 4, "      ")
	elif arg == "?":
		write("      unresolved by push collector; local call window follows")

def print_ba9ee0_resource_provenance():
	write("")
	write("=" * 70)
	write("BA9EE0 RESOURCE ARGUMENT PROVENANCE")
	write("=" * 70)
	write("Rows are printed when the vararg array count is nonzero, unresolved, or the push collector saw unknown fields.")
	total = 0
	printed = 0
	for item in PASS_ENTRY_SCAN_FUNCTIONS:
		func = fm.getFunctionAt(toAddr(item[0]))
		if func is None:
			func = fm.getFunctionContaining(toAddr(item[0]))
		if func is None:
			continue
		inst_iter = listing.getInstructions(func.getBody(), True)
		while inst_iter.hasNext():
			inst = inst_iter.next()
			target = call_target_for_instruction(inst)
			if target == 0x00BA9EE0:
				total += 1
				pushes = collect_pushes_before(inst, 8, 54)
				if row_has_interesting_resources(pushes):
					printed += 1
					write("")
					write("  call 0x%08x in %s" % (inst.getAddress().getOffset(), item[1]))
					write("  row: entry+0=%s entry+4=%s entry+7=%s count=%s array0=%s array1=%s array2=%s array3=%s" % (get_push_arg(pushes, 0), get_push_arg(pushes, 1), get_push_arg(pushes, 2), get_push_arg(pushes, 3), get_push_arg(pushes, 4), get_push_arg(pushes, 5), get_push_arg(pushes, 6), get_push_arg(pushes, 7)))
					print_arg_provenance(pushes, 0)
					print_arg_provenance(pushes, 1)
					print_arg_provenance(pushes, 2)
					print_arg_provenance(pushes, 3)
					print_arg_provenance(pushes, 4)
					print_arg_provenance(pushes, 5)
					print_arg_provenance(pushes, 6)
					print_arg_provenance(pushes, 7)
					write("    local call window:")
					print_short_window(inst, 12, 5)
	write("")
	write("  Total BA9EE0 calls scanned: %d" % total)
	write("  Printed resource-bearing/unresolved rows: %d" % printed)

def scan_source_patterns(addr_int, label):
	write("")
	write("=" * 70)
	write("SOURCE/RESOURCE PATTERN LINES: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	code = decompile_text(addr_int)
	if code is None:
		write("  [decompilation failed]")
		return
	lines = code.splitlines()
	line_no = 0
	for line in lines:
		line_no += 1
		lower = line.lower()
		for pattern in SOURCE_PATTERNS:
			if pattern.lower() in lower:
				write("  L%-4d %s" % (line_no, line))
				break

def print_focus_function_patterns():
	for item in DYNAMIC_FOCUS_FUNCTIONS:
		scan_source_patterns(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])

def print_key_refs():
	find_refs_to(0x00BA9EE0, "pass-entry append/reuse helper")
	find_refs_to(0x00E7EB00, "pass-entry cache/apply helper")
	find_refs_to(0x00E7EA00, "pass-entry downstream texture/state apply helper")
	find_refs_to(0x00C03230, "active object resource/state getter used before E7EB00")
	find_refs_to(0x011F91E0, "current geometry/proxy global")
	find_refs_to(0x011F951C, "global fallback resource used by B7E150 branch")
	find_refs_to(0x0126F680, "pass-entry +8 cache table keyed by entry +4")

def main():
	write("FNV PBR PPLIGHTING PASS RESOURCE PROVENANCE FOLLOW-UP AUDIT")
	write("")
	write("Purpose:")
	write("1. Resolve where BA9EE0 entry +0x0C resource-array values come from at callsites.")
	write("2. Separate true texture/resource pointers from dynamic mode/type registers before assigning PBR map semantics.")
	write("3. Keep visible PBR replacement blocked unless the resource path to E7EA00/SetTexture is concrete.")
	print_key_refs()
	print_ba9ee0_resource_provenance()
	print_focus_function_patterns()
	decompile_at(0x00E7EB00, "pass-entry cache/apply helper", 12000)
	decompile_at(0x00E7EA00, "pass-entry downstream texture/state apply helper", 14000)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_pass_resource_provenance_followup_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
