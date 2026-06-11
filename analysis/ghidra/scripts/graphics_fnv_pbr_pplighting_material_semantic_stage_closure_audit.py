# @category Analysis
# @description Close FNV PPLighting material array semantics against pass-entry stage rows

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00A59D30: "NiAVObject property lookup by type",
	0x00B68660: "PPLighting six texture-array writer",
	0x00B690D0: "PPLighting material texture/effect serializer",
	0x00B69FF0: "PPLighting height predicate selector",
	0x00BB41E0: "PPLighting env predicate selector",
	0x00BB4740: "PPLighting long selector variant A",
	0x00BC3E40: "PPLighting active-object/env selector",
	0x00BDB4A0: "PPLighting setup variant before BDF790",
	0x00BDF790: "PPLighting selector/pass-entry driver",
	0x00C058F0: "PPLighting long selector variant B",
	0x00BA9EE0: "PPLighting pass-entry append/reuse helper",
	0x00E7EA00: "final pass-entry resource resolver and SetTexture caller",
	0x00E88A20: "NiDX9RenderState::SetTexture",
}

MATERIAL_ARRAY_OFFSETS = [
	(0xAC, "diffuse/base texture array"),
	(0xB0, "normal/normal-map texture array"),
	(0xB4, "glow/skin/hair layer texture array"),
	(0xB8, "heightmap texture array"),
	(0xBC, "envmap texture array"),
	(0xC0, "envmap-mask texture array"),
	(0xC4, "per-index material flag bytes"),
	(0xCC, "per-index normal/spec flag bytes"),
]

FOCUS_FUNCTIONS = [
	(0x00B68660, "array writer and normal flag source"),
	(0x00B690D0, "serializer only, no draw BA9EE0"),
	(0x00B69FF0, "height predicate selector"),
	(0x00BB41E0, "env predicate selector"),
	(0x00BB4740, "long selector variant A"),
	(0x00BC3E40, "active-object/env selector"),
	(0x00BDB4A0, "setup variant before BDF790"),
	(0x00BDF790, "main selector/pass-entry driver"),
	(0x00C058F0, "long selector variant B"),
]

HELPER_FUNCTIONS = [
	(0x00BD9540, "helper resource family 0x58..0x60"),
	(0x00BD9770, "helper resource family 0x7C..0x7E"),
	(0x00BD9840, "helper resource family 0x12D..0x131"),
	(0x00BD99C0, "helper resource family 0x154..0x157"),
	(0x00BD9AC0, "helper zero-resource family 0x244..0x247"),
	(0x00BD9BC0, "helper zero-resource family 0x252..0x256"),
	(0x00BD9D00, "helper zero-resource family 0x24E..0x24F"),
	(0x00BD9DA0, "helper zero-resource family 0x1E2..0x1E4"),
	(0x00BD9E60, "helper zero-resource family 0x1E5..0x1E6"),
	(0x00BD9F00, "helper zero-resource family 0x01..0x03"),
	(0x00BD9F90, "helper zero-resource family 0x04..0x05"),
	(0x00BDA0A0, "large helper resource family 0x64..0x92"),
	(0x00BDAC00, "helper zero/resource family 0x14A..0x152"),
	(0x00BDB380, "post-material helper"),
	(0x00BDBF60, "selector subhelper BDBF60"),
	(0x00BDC030, "selector subhelper BDC030"),
	(0x00BDC0D0, "selector subhelper BDC0D0"),
	(0x00BDC530, "selector subhelper BDC530"),
	(0x00BDCA60, "selector subhelper BDCA60"),
	(0x00BDD050, "selector subhelper BDD050"),
	(0x00BDD520, "selector subhelper BDD520"),
	(0x00BDDA20, "selector subhelper BDDA20"),
	(0x00BDDBC0, "selector subhelper BDDBC0"),
	(0x00BDDD80, "selector subhelper BDDD80"),
	(0x00BDDE10, "selector subhelper BDDE10"),
	(0x00BDDFB0, "selector subhelper BDDFB0"),
	(0x00BDE170, "selector subhelper BDE170"),
	(0x00BDE1D0, "selector subhelper BDE1D0"),
	(0x00BDE9B0, "selector subhelper BDE9B0"),
	(0x00BDEF40, "selector subhelper BDEF40"),
	(0x00BDF3E0, "selector subhelper BDF3E0"),
	(0x00BDF650, "helper 00BDF650"),
	(0x00BDF6C0, "helper 00BDF6C0"),
	(0x00BDA030, "late helper BDA030"),
	(0x00BDAF10, "diffuse/glow material helper"),
]

HELPER_TARGETS = [
	0x00BD9540,
	0x00BD9770,
	0x00BD9840,
	0x00BD99C0,
	0x00BD9AC0,
	0x00BD9BC0,
	0x00BD9D00,
	0x00BD9DA0,
	0x00BD9E60,
	0x00BD9F00,
	0x00BD9F90,
	0x00BDA0A0,
	0x00BDAC00,
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
	0x00BDE170,
	0x00BDE1D0,
	0x00BDE9B0,
	0x00BDEF40,
	0x00BDF3E0,
	0x00BDF650,
	0x00BDF6C0,
	0x00BDA030,
	0x00BDAF10,
]

SCAN_PATTERNS = [
	"FUN_00ba9ee0",
	"FUN_00b68660",
	"FUN_00b70590",
	"FUN_00b70600",
	"FUN_00b70680",
	"FUN_00b70700",
	"FUN_00b707d0",
	"FUN_00bd9540",
	"FUN_00bd9840",
	"FUN_00bdca60",
	"FUN_00bdd050",
	"FUN_00bdd520",
	"FUN_00bde1d0",
	"FUN_00bde9b0",
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

def read_byte(addr_int):
	try:
		value = memory.getByte(toAddr(addr_int))
		if value < 0:
			value += 0x100
		return value
	except:
		return None

def read_c_string(addr_int, limit):
	chars = []
	index = 0
	while index < limit:
		value = read_byte(addr_int + index)
		if value is None:
			return None
		if value == 0:
			break
		if value < 0x20 or value > 0x7e:
			return None
		chars.append(chr(value))
		index += 1
	if len(chars) < 3:
		return None
	return "".join(chars)

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
	text = read_c_string(addr_int, 96)
	if text is not None:
		return "\"%s\"" % text
	return "unknown"

def get_function(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	return func

def decompile_text_for_func(func):
	if func is None:
		return None
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		return result.getDecompiledFunction().getC()
	return None

def decompile_at(addr_int, label, max_len=12000):
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
		inst = listing.getInstructionContaining(ref.getFromAddress())
		inst_text = inst.toString() if inst is not None else ""
		write("  %s @ 0x%08x (in %s) %s" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, inst_text))
		count += 1
		if count > 140:
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
	inst_iter = currentProgram.getListing().getInstructions(body, True)
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
				name = tgt_func.getName() if tgt_func else label_for(tgt)
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
	write("  Total: %d calls" % count)

def instruction_before_steps(inst, steps):
	cur = inst
	count = 0
	while count < steps and cur is not None:
		cur = listing.getInstructionBefore(cur.getAddress())
		count += 1
	return cur

def print_refs_from_instruction(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		target = ref.getToAddress()
		taddr = target.getOffset()
		write("      ref %s -> 0x%08x %s" % (ref.getReferenceType(), taddr, label_for(taddr)))

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("=" * 70)
	write("Raw disassembly %s around 0x%08x" % (label, center_int))
	write("=" * 70)
	inst = listing.getInstructionContaining(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionAt(toAddr(center_int))
	if inst is None:
		write("  [instruction not found]")
		return
	cur = instruction_before_steps(inst, before_count)
	if cur is None:
		cur = inst
	count = 0
	limit = before_count + after_count + 1
	while cur is not None and count < limit:
		addr_int = cur.getAddress().getOffset()
		marker = "=> " if addr_int == inst.getAddress().getOffset() else "   "
		write("%s0x%08x: %-58s %s" % (marker, addr_int, cur.toString(), label_for(addr_int)))
		print_refs_from_instruction(cur)
		cur = listing.getInstructionAfter(cur.getAddress())
		count += 1

def normalized_text(text):
	return text.lower().replace(" ", "")

def scan_patterns_in_code(code, patterns, limit):
	if code is None:
		write("  [decompilation failed]")
		return
	lines = code.splitlines()
	line_no = 0
	matched = 0
	for line in lines:
		line_no += 1
		lower = line.lower()
		for pattern in patterns:
			if pattern.lower() in lower:
				write("  L%-4d %s" % (line_no, line))
				matched += 1
				break
		if matched >= limit:
			write("  ... (truncated)")
			break
	write("  Total matched lines: %d" % matched)

def print_matched_decompile_lines(func, label, limit):
	write("")
	write("=" * 70)
	write("MATCHED DECOMPILE LINES: %s @ 0x%08x" % (label, func.getEntryPoint().getOffset()))
	write("=" * 70)
	code = decompile_text_for_func(func)
	scan_patterns_in_code(code, SCAN_PATTERNS, limit)

def is_instruction_call_to(inst, target_int):
	refs = inst.getReferencesFrom()
	for ref in refs:
		if ref.getReferenceType().isCall() and ref.getToAddress().getOffset() == target_int:
			return True
	return False

def call_target(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		if ref.getReferenceType().isCall():
			return ref.getToAddress().getOffset()
	return None

def operand_text(inst, index):
	try:
		return inst.getDefaultOperandRepresentation(index)
	except:
		return "?"

def collect_push_args_before_call(call_inst, max_args, max_steps):
	args = []
	inst = listing.getInstructionBefore(call_inst.getAddress())
	steps = 0
	while inst is not None and steps < max_steps and len(args) < max_args:
		mnemonic = inst.getMnemonicString().upper()
		if mnemonic == "PUSH":
			args.append((operand_text(inst, 0), inst.getAddress().getOffset()))
		elif mnemonic.startswith("RET"):
			break
		inst = listing.getInstructionBefore(inst.getAddress())
		steps += 1
	return args

def print_recent_register_def(start_addr, reg, max_steps):
	inst = listing.getInstructionBefore(toAddr(start_addr))
	steps = 0
	while inst is not None and steps < max_steps:
		text = inst.toString().upper()
		if text.startswith("MOV %s," % reg) or text.startswith("LEA %s," % reg) or text.startswith("XOR %s," % reg):
			write("      def %s @ 0x%08x: %s" % (reg, inst.getAddress().getOffset(), inst.toString()))
			print_refs_from_instruction(inst)
			return
		if inst.getMnemonicString().upper().startswith("CALL"):
			break
		inst = listing.getInstructionBefore(inst.getAddress())
		steps += 1
	write("      def %s: [not found in local window]" % reg)

def print_stack_args_for_call(call_inst, max_args):
	args = collect_push_args_before_call(call_inst, max_args, 84)
	index = 0
	for item in args:
		op = item[0]
		push_addr = item[1]
		ntext = op.strip().upper()
		write("    stack_arg%d = %-14s ; push @ 0x%08x" % (index, op, push_addr))
		if index == 0:
			write("      BA9EE0 field: entry +0 seed/owner")
		elif index == 1:
			write("      BA9EE0 field: entry +4 final stage/key")
		elif index == 2:
			write("      BA9EE0 field: entry +7 selector byte")
		elif index == 3:
			write("      BA9EE0 field: entry +9 resource count")
		elif index >= 4:
			write("      BA9EE0 field: entry +0x0C resource slot %d" % (index - 4))
		if ntext in REGISTERS:
			print_recent_register_def(push_addr, ntext, 42)
		index += 1
	if len(args) == 0:
		write("    [no local PUSH args found]")

def material_label_for_text(text):
	lower = normalized_text(text)
	for item in MATERIAL_ARRAY_OFFSETS:
		if "+0x%x" % item[0] in lower:
			return item[1]
	return None

def is_stack_offset_text(text):
	lower = normalized_text(text)
	return "[esp+" in lower or "[esp-" in lower

def print_material_access_windows(func, label, stack_mode, limit):
	write("")
	write("=" * 70)
	mode = "STACK/OFFSET FALSE-POSITIVE" if stack_mode else "DIRECT MATERIAL-OBJECT"
	write("%s MATERIAL OFFSET WINDOWS: %s @ 0x%08x" % (mode, label, func.getEntryPoint().getOffset()))
	write("=" * 70)
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		offset_label = material_label_for_text(text)
		if offset_label is None:
			continue
		is_stack = is_stack_offset_text(text)
		if stack_mode != is_stack:
			continue
		addr_int = inst.getAddress().getOffset()
		write("")
		write("  %s reference at 0x%08x: %s" % (offset_label, addr_int, text))
		disasm_window(addr_int, 8, 10, "%s %s reference in %s" % (mode, offset_label, label))
		count += 1
		if count >= limit:
			write("  ... (truncated)")
			break
	write("  Total %s material-offset windows printed: %d" % (mode.lower(), count))

def print_ba9ee0_rows(func, label, limit):
	write("")
	write("=" * 70)
	write("INTERPRETED BA9EE0 ROWS: %s @ 0x%08x" % (label, func.getEntryPoint().getOffset()))
	write("=" * 70)
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		if not is_instruction_call_to(inst, 0x00BA9EE0):
			continue
		call_addr = inst.getAddress().getOffset()
		write("")
		write("  BA9EE0 call %d at 0x%08x" % (count + 1, call_addr))
		print_stack_args_for_call(inst, 8)
		disasm_window(call_addr, 12, 10, "BA9EE0 row in %s" % label)
		count += 1
		if count >= limit:
			write("  ... (truncated)")
			break
	write("  Total BA9EE0 rows printed: %d" % count)

def print_helper_calls_from_func(func, label, limit):
	write("")
	write("=" * 70)
	write("SELECTOR HELPER CALLS FROM %s @ 0x%08x" % (label, func.getEntryPoint().getOffset()))
	write("=" * 70)
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		tgt = call_target(inst)
		if tgt is None or tgt not in HELPER_TARGETS:
			continue
		call_addr = inst.getAddress().getOffset()
		write("")
		write("  helper call %d at 0x%08x -> 0x%08x %s" % (count + 1, call_addr, tgt, label_for(tgt)))
		print_stack_args_for_call(inst, 16)
		disasm_window(call_addr, 12, 12, "helper call from %s" % label)
		count += 1
		if count >= limit:
			write("  ... (truncated)")
			break
	write("  Total helper calls printed: %d" % count)

def print_focus_function(addr_int, label, max_decompile, ba9_limit, helper_limit):
	func = get_function(addr_int)
	if func is None:
		write("")
		write("Missing function 0x%08x %s" % (addr_int, label))
		return
	title = "%s: %s" % (label_for(func.getEntryPoint().getOffset()), label)
	decompile_at(addr_int, title, max_decompile)
	find_and_print_calls_from(addr_int, title)
	print_matched_decompile_lines(func, title, 140)
	print_material_access_windows(func, title, False, 32)
	print_material_access_windows(func, title, True, 18)
	if ba9_limit > 0:
		print_ba9ee0_rows(func, title, ba9_limit)
	if helper_limit > 0:
		print_helper_calls_from_func(func, title, helper_limit)

def print_function_list(items, max_decompile, ba9_limit, helper_limit):
	for item in items:
		print_focus_function(item[0], item[1], max_decompile, ba9_limit, helper_limit)

def main():
	write("FNV PBR PPLIGHTING MATERIAL SEMANTIC STAGE CLOSURE AUDIT")
	write("")
	write("Questions:")
	write("1. Which +0xAC..+0xC0 references are real material-object fields versus ESP stack offsets?")
	write("2. Which real remaining-array reads choose pass-entry stage keys, resource counts, or only flags?")
	write("3. Which helper families receive selector-driver arguments and emit final BA9EE0 rows?")
	write("4. Is any normal/height/env/env-mask row proven from material array to final SetTexture stage?")
	write("")
	write("Compatibility rule:")
	write("Do not enable visible PBR replacement until material array, pass index, stage key, resource count, and fallback behavior are all proven.")
	find_refs_to(0x00B68660, "PPLighting six texture-array writer")
	find_refs_to(0x00B690D0, "PPLighting material serializer")
	find_refs_to(0x00BDF790, "main selector/pass-entry driver")
	find_refs_to(0x00C058F0, "alternate long selector variant")
	find_refs_to(0x00BB4740, "long selector variant")
	print_function_list(FOCUS_FUNCTIONS, 30000, 28, 44)
	print_function_list(HELPER_FUNCTIONS, 16000, 24, 0)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_material_semantic_stage_closure_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
