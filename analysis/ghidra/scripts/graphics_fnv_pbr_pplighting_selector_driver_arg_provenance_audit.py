# @category Analysis
# @description Trace FNV PBR PPLighting selector driver helper-call arguments back to material/resource sources

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00439090: "small utility called by BDF790",
	0x004390C0: "small utility called by BDF790",
	0x004A2020: "repeated utility/assert-like helper called by BDF790",
	0x00653290: "geometry/property helper called by BDF790",
	0x00A59D30: "material/property helper called by BDAF10/BDF790",
	0x00B4F5C0: "material branch/helper called by BDF790",
	0x00B70590: "PPLighting resource helper 00B70590",
	0x00B70600: "PPLighting resource helper 00B70600",
	0x00B70680: "PPLighting resource helper 00B70680",
	0x00B70700: "PPLighting resource helper 00B70700",
	0x00B707D0: "PPLighting resource helper 00B707D0",
	0x00BA9EE0: "pass-entry append/reuse helper",
	0x00BD9540: "PPLighting pass-entry helper 00BD9540",
	0x00BD9840: "PPLighting pass-entry helper 00BD9840",
	0x00BD9BC0: "PPLighting pass-entry helper 00BD9BC0",
	0x00BD9DA0: "PPLighting pass-entry helper 00BD9DA0",
	0x00BD9E60: "PPLighting pass-entry helper 00BD9E60",
	0x00BD9F00: "PPLighting pass-entry helper 00BD9F00",
	0x00BD9F90: "PPLighting pass-entry helper 00BD9F90",
	0x00BDA030: "PPLighting pass-entry helper 00BDA030",
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
	0x00BDF790: "PPLighting selector/pass-entry driver 00BDF790",
	0x00E7EA00: "pass-entry downstream texture/state apply helper",
	0x00E7EB00: "pass-entry cache/apply helper",
}

DRIVER_FUNCTION = 0x00BDF790

HELPER_TARGETS = [
	0x00BD9540,
	0x00BD9840,
	0x00BD9BC0,
	0x00BD9DA0,
	0x00BD9E60,
	0x00BD9F00,
	0x00BD9F90,
	0x00BDA030,
	0x00BDAF10,
	0x00BDB380,
	0x00BDBF60,
	0x00BDC030,
	0x00BDC0D0,
	0x00BDC530,
	0x00BDCA60,
	0x00BDD050,
	0x00BDD520,
	0x00BDDA20,
	0x00BDDBC0,
	0x00BDDD80,
	0x00BDDE10,
	0x00BDDFB0,
	0x00BDE1D0,
	0x00BDE9B0,
	0x00BDEF40,
	0x00BDF3E0,
	0x00BDF650,
	0x00BA9EE0,
]

RESOURCE_HELPERS = [
	0x00B4F5C0,
	0x00653290,
	0x00A59D30,
	0x00B70590,
	0x00B70600,
	0x00B70680,
	0x00B70700,
	0x00B707D0,
	0x00439090,
	0x004390C0,
	0x004A2020,
]

DECOMPILE_TARGETS = [
	(0x00BDF790, "PPLighting selector/pass-entry driver 00BDF790", 70000),
	(0x00B70590, "PPLighting resource helper 00B70590", 14000),
	(0x00B70600, "PPLighting resource helper 00B70600", 14000),
	(0x00B70680, "PPLighting resource helper 00B70680", 14000),
	(0x00B70700, "PPLighting resource helper 00B70700", 14000),
	(0x00B707D0, "PPLighting resource helper 00B707D0", 14000),
	(0x00B4F5C0, "material branch/helper called by BDF790", 12000),
	(0x00653290, "geometry/property helper called by BDF790", 12000),
	(0x00A59D30, "material/property helper called by BDAF10/BDF790", 12000),
]

PATTERNS = [
	"ba9ee0",
	"bd9540",
	"bd9840",
	"bda030",
	"bdaf10",
	"bdc0d0",
	"bdc530",
	"bdca60",
	"bdd050",
	"bdd520",
	"bdda20",
	"bddbc0",
	"bddd80",
	"bdde10",
	"bddfb0",
	"bde1d0",
	"bde9b0",
	"bdef40",
	"bdf3e0",
	"bdf650",
	"b70590",
	"b70600",
	"b70680",
	"b70700",
	"b707d0",
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
	"+ 0xdc",
	"+0xdc",
	"+ 0xe0",
	"+0xe0",
	"+ 0xec",
	"+0xec",
	"+ 0xf4",
	"+0xf4",
	"+ 0x194",
	"+0x194",
	"texture",
	"resource",
	"stage",
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
		if count > 100:
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

def is_register_text(text):
	upper = text.upper()
	for reg in REGISTERS:
		if upper == reg:
			return True
	return False

def call_target_for_instruction(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		if ref.getReferenceType().isCall():
			return ref.getToAddress().getOffset()
	return None

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

def print_source_reg_defs(inst, written_reg, indent):
	src = operand_text(inst, 1).upper()
	if src == written_reg:
		return
	if is_register_text(src):
		write("%sfollow source register %s before 0x%08x:" % (indent, src, inst.getAddress().getOffset()))
		print_register_defs_before(inst, src, 36, 2, indent + "  ")

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

def get_push_arg(pushes, index):
	if index < len(pushes):
		return pushes[index][1]
	return "?"

def get_push_inst(pushes, index):
	if index < len(pushes):
		return listing.getInstructionAt(toAddr(pushes[index][0]))
	return None

def print_arg_argprovenance(pushes, index, name):
	arg = get_push_arg(pushes, index)
	arg_inst = get_push_inst(pushes, index)
	if arg_inst is None:
		write("    %-18s = %-28s ; [push instruction not found]" % (name, arg))
		return
	write("    %-18s = %-28s ; push @ 0x%08x" % (name, arg, arg_inst.getAddress().getOffset()))
	if is_register_text(arg):
		print_register_defs_before(arg_inst, arg.upper(), 56, 6, "      ")

def target_in_list(target, values):
	for value in values:
		if value == target:
			return True
	return False

def scan_decompile_patterns(addr_int, label):
	write("")
	write("=" * 70)
	write("DECOMPILE PATTERN LINES: %s @ 0x%08x" % (label, addr_int))
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
		for pattern in PATTERNS:
			if pattern.lower() in lower:
				write("  L%-4d %s" % (line_no, line))
				break

def print_driver_call_arg_table():
	func = fm.getFunctionAt(toAddr(DRIVER_FUNCTION))
	if func is None:
		func = fm.getFunctionContaining(toAddr(DRIVER_FUNCTION))
	write("")
	write("=" * 70)
	write("BDF790 HELPER CALL ARGUMENT PROVENANCE")
	write("=" * 70)
	if func is None:
		write("  [BDF790 function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	total = 0
	printed = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		target = call_target_for_instruction(inst)
		if target is None:
			continue
		if not target_in_list(target, HELPER_TARGETS) and not target_in_list(target, RESOURCE_HELPERS):
			continue
		total += 1
		printed += 1
		write("")
		write("  call 0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), target, label_for(target)))
		pushes = collect_pushes_before(inst, 10, 72)
		write("    ECX before call:")
		print_register_defs_before(inst, "ECX", 48, 5, "      ")
		index = 0
		while index < 10:
			print_arg_argprovenance(pushes, index, "stack_arg%d" % index)
			index += 1
		write("    local call window:")
		print_short_window(inst, 18, 8)
	write("")
	write("  Interesting direct calls scanned: %d" % total)
	write("  Printed direct calls: %d" % printed)

def print_resource_helper_calls():
	for addr in RESOURCE_HELPERS:
		find_refs_to(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))

def print_core_decompiles():
	for item in DECOMPILE_TARGETS:
		decompile_at(item[0], item[1], item[2])

def print_pattern_sections():
	scan_decompile_patterns(0x00BDF790, "PPLighting selector/pass-entry driver 00BDF790")
	scan_decompile_patterns(0x00BDAF10, "PPLighting helper with source texture array tests 00BDAF10")
	scan_decompile_patterns(0x00BDF3E0, "PPLighting helper with dynamic stage/resource calls 00BDF3E0")

def print_key_refs():
	find_refs_to(0x00BDF790, "PPLighting selector/pass-entry driver 00BDF790")
	find_refs_to(0x00BA9EE0, "pass-entry append/reuse helper")
	find_refs_to(0x00E7EB00, "pass-entry cache/apply helper")
	find_refs_to(0x00E7EA00, "pass-entry downstream texture/state apply helper")

def main():
	write("FNV PBR PPLIGHTING SELECTOR DRIVER ARGUMENT PROVENANCE AUDIT")
	write("")
	write("Purpose:")
	write("1. Normalize direct helper-call arguments from BDF790, the PPLighting selector/pass-entry driver.")
	write("2. Trace BDF790 resource-helper return values and stack arguments before they are forwarded into BA9EE0 helper families.")
	write("3. Keep visible PBR replacement blocked until helper params map back to concrete material fields/getters and final E7EA00 stages.")
	print_key_refs()
	print_driver_call_arg_table()
	print_pattern_sections()
	print_resource_helper_calls()
	print_core_decompiles()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_selector_driver_arg_provenance_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
