# @category Analysis
# @description Audit remaining FNV PPLighting material array consumers for native PBR

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
	0x00BA9EE0: "PPLighting pass-entry append/reuse helper",
	0x00BD9540: "PPLighting pass helper 00BD9540",
	0x00BD9770: "PPLighting pass helper 00BD9770",
	0x00BD9840: "PPLighting pass helper 00BD9840",
	0x00BD99C0: "PPLighting pass helper 00BD99C0",
	0x00BD9AC0: "PPLighting pass helper 00BD9AC0",
	0x00BD9BC0: "PPLighting pass helper 00BD9BC0",
	0x00BD9D00: "PPLighting pass helper 00BD9D00",
	0x00BD9DA0: "PPLighting pass helper 00BD9DA0",
	0x00BD9E60: "PPLighting pass helper 00BD9E60",
	0x00BD9F00: "PPLighting pass helper 00BD9F00",
	0x00BD9F90: "PPLighting pass helper 00BD9F90",
	0x00BDA0A0: "PPLighting pass helper 00BDA0A0",
	0x00BDAC00: "PPLighting pass helper 00BDAC00",
	0x00BDAF10: "PPLighting material/property array helper",
	0x00BDB380: "PPLighting post-material helper",
	0x00BDB4A0: "PPLighting setup variant before BDF790",
	0x00BDF650: "PPLighting helper 00BDF650",
	0x00BDF6C0: "PPLighting helper 00BDF6C0",
	0x00BDF790: "PPLighting selector/pass-entry driver",
	0x00E7EA00: "final pass-entry resource resolver and SetTexture caller",
	0x00E7EB00: "final pass-entry texture cache compare/apply helper",
	0x00E88A20: "NiDX9RenderState::SetTexture",
}

BASELINE_FUNCTIONS = [
	(0x00BDAF10, "known diffuse/glow predicate helper"),
	(0x00BDB4A0, "caller/setup for material helper"),
	(0x00BDF790, "selector/pass-entry driver"),
	(0x00B68660, "material array writer and normal flag source"),
	(0x00B690D0, "serializer that is not draw-time binding"),
]

PASS_HELPER_FUNCTIONS = [
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
	0x00BDAF10,
	0x00BDB380,
	0x00BDB4A0,
	0x00BDF650,
	0x00BDF6C0,
	0x00BDF790,
]

REMAINING_ARRAY_OFFSETS = [
	(0xB0, "normal/normal-map texture array"),
	(0xB8, "heightmap texture array"),
	(0xBC, "envmap texture array"),
	(0xC0, "envmap-mask texture array"),
]

ALL_MATERIAL_ARRAY_OFFSETS = [
	(0xAC, "diffuse/base texture array"),
	(0xB0, "normal/normal-map texture array"),
	(0xB4, "glow/skin/hair layer texture array"),
	(0xB8, "heightmap texture array"),
	(0xBC, "envmap texture array"),
	(0xC0, "envmap-mask texture array"),
	(0xC4, "material byte flags"),
	(0xCC, "material byte flags"),
]

SCAN_PATTERNS = [
	"FUN_00ba9ee0",
	"FUN_00a59d30",
	"FUN_00e7ea00",
	"SetTexture",
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
	"0x93",
	"0x94",
	"0x1ef",
	"0x1f1",
	"0x1f2",
	"0x1f3",
	"0x1f4",
	"0x1f5",
	"0xd7",
	"0xe9",
	"0x95",
	"0xab",
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

def decompile_text(addr_int):
	func = get_function(addr_int)
	return decompile_text_for_func(func)

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
		inst = listing.getInstructionContaining(ref.getFromAddress())
		inst_text = inst.toString() if inst is not None else ""
		write("  %s @ 0x%08x (in %s) %s" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, inst_text))
		count += 1
		if count > 120:
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

def offset_labels_in_text(text, offsets):
	labels = []
	lower = normalized_text(text)
	for item in offsets:
		needle = "+0x%x" % item[0]
		if needle in lower:
			labels.append(item[1])
	return labels

def function_has_call_to(func, target_int):
	if func is None:
		return False
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall() and ref.getToAddress().getOffset() == target_int:
				return True
	return False

def function_call_count_to(func, target_int):
	if func is None:
		return 0
	count = 0
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall() and ref.getToAddress().getOffset() == target_int:
				count += 1
	return count

def collect_ba9ee0_callers(entries):
	refs = ref_mgr.getReferencesTo(toAddr(0x00BA9EE0))
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		entries[entry] = func

def add_baseline_entries(entries):
	for item in BASELINE_FUNCTIONS:
		func = get_function(item[0])
		if func is not None:
			entries[func.getEntryPoint().getOffset()] = func
	for addr_int in PASS_HELPER_FUNCTIONS:
		func = get_function(addr_int)
		if func is not None:
			entries[func.getEntryPoint().getOffset()] = func

def should_print_function(func, code, is_baseline):
	if code is None:
		return is_baseline
	remaining = offset_labels_in_text(code, REMAINING_ARRAY_OFFSETS)
	if len(remaining) > 0:
		return True
	if is_baseline:
		return True
	return False

def format_labels(labels):
	if len(labels) == 0:
		return "none"
	return ", ".join(labels)

def scan_patterns_in_code(code, label, patterns):
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
		if matched >= 220:
			write("  ... (truncated)")
			break
	write("  Total matched lines: %d" % matched)

def print_matched_decompile_lines(func, label):
	write("")
	write("=" * 70)
	write("MATCHED DECOMPILE LINES: %s @ 0x%08x" % (label, func.getEntryPoint().getOffset()))
	write("=" * 70)
	code = decompile_text_for_func(func)
	scan_patterns_in_code(code, label, SCAN_PATTERNS)

def is_instruction_call_to(inst, target_int):
	refs = inst.getReferencesFrom()
	for ref in refs:
		if ref.getReferenceType().isCall() and ref.getToAddress().getOffset() == target_int:
			return True
	return False

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
	args = collect_push_args_before_call(call_inst, max_args, 72)
	index = 0
	for item in args:
		op = item[0]
		push_addr = item[1]
		ntext = op.strip().upper()
		write("    stack_arg%d = %-14s ; push @ 0x%08x" % (index, op, push_addr))
		if ntext in REGISTERS:
			print_recent_register_def(push_addr, ntext, 36)
		index += 1
	if len(args) == 0:
		write("    [no local PUSH args found]")

def print_ba9ee0_windows(func, label, limit):
	write("")
	write("=" * 70)
	write("BA9EE0 CALL WINDOWS: %s @ 0x%08x" % (label, func.getEntryPoint().getOffset()))
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
		disasm_window(call_addr, 14, 10, "BA9EE0 call in %s" % label)
		count += 1
		if count >= limit:
			write("  ... (truncated)")
			break
	write("  Total BA9EE0 calls printed: %d" % count)

def material_offset_label_for_instruction(inst):
	text = normalized_text(inst.toString())
	for item in ALL_MATERIAL_ARRAY_OFFSETS:
		needle = "+0x%x" % item[0]
		if needle in text:
			return item[1]
	return None

def print_material_offset_windows(func, label, limit):
	write("")
	write("=" * 70)
	write("MATERIAL OFFSET WINDOWS: %s @ 0x%08x" % (label, func.getEntryPoint().getOffset()))
	write("=" * 70)
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		offset_label = material_offset_label_for_instruction(inst)
		if offset_label is None:
			continue
		addr_int = inst.getAddress().getOffset()
		write("")
		write("  %s reference at 0x%08x: %s" % (offset_label, addr_int, inst.toString()))
		disasm_window(addr_int, 8, 10, "%s reference in %s" % (offset_label, label))
		count += 1
		if count >= limit:
			write("  ... (truncated)")
			break
	write("  Total material-offset windows printed: %d" % count)

def print_candidate_summary(entries):
	write("")
	write("=" * 70)
	write("CANDIDATE FUNCTION SUMMARY")
	write("=" * 70)
	keys = entries.keys()
	keys.sort()
	printed = 0
	for entry in keys:
		func = entries[entry]
		code = decompile_text_for_func(func)
		is_baseline = entry in [item[0] for item in BASELINE_FUNCTIONS] or entry in PASS_HELPER_FUNCTIONS
		if not should_print_function(func, code, is_baseline):
			continue
		remaining = offset_labels_in_text(code if code is not None else "", REMAINING_ARRAY_OFFSETS)
		all_offsets = offset_labels_in_text(code if code is not None else "", ALL_MATERIAL_ARRAY_OFFSETS)
		ba9_count = function_call_count_to(func, 0x00BA9EE0)
		write("  0x%08x %-36s BA9EE0=%d remaining=[%s] all=[%s]" % (entry, label_for(entry), ba9_count, format_labels(remaining), format_labels(all_offsets)))
		printed += 1
	write("  Total candidate functions printed: %d" % printed)

def print_focused_candidates(entries):
	keys = entries.keys()
	keys.sort()
	printed = 0
	for entry in keys:
		func = entries[entry]
		code = decompile_text_for_func(func)
		is_baseline = entry in [item[0] for item in BASELINE_FUNCTIONS] or entry in PASS_HELPER_FUNCTIONS
		if not should_print_function(func, code, is_baseline):
			continue
		label = label_for(entry)
		decompile_at(entry, label, 26000)
		find_and_print_calls_from(entry, label)
		print_matched_decompile_lines(func, label)
		print_material_offset_windows(func, label, 36)
		if function_has_call_to(func, 0x00BA9EE0):
			print_ba9ee0_windows(func, label, 36)
		printed += 1
		if printed >= 32:
			write("  ... focused candidate print truncated")
			break

def main():
	write("FNV PBR PPLIGHTING REMAINING MATERIAL ARRAY CONSUMER FOLLOW-UP AUDIT")
	write("")
	write("Questions:")
	write("1. Which BA9EE0 draw-stage helpers read +0xB0/+0xB8/+0xBC/+0xC0?")
	write("2. Are those reads real type-3 material arrays, or unrelated stack/object offsets?")
	write("3. Do remaining-array reads feed BA9EE0 resources, only branch predicates, or only serialization?")
	write("4. Is there any safe vanilla draw-stage path for normal/height/env/env-mask before visible PBR replacement?")
	write("")
	write("Compatibility rule:")
	write("Visible replacement remains blocked unless every texture stage used by the replacement is proven from source array to final SetTexture.")
	find_refs_to(0x00BA9EE0, "PPLighting pass-entry append/reuse helper")
	find_refs_to(0x00BDAF10, "known diffuse/glow predicate helper")
	entries = {}
	collect_ba9ee0_callers(entries)
	add_baseline_entries(entries)
	print_candidate_summary(entries)
	print_focused_candidates(entries)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_remaining_array_consumer_followup_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
