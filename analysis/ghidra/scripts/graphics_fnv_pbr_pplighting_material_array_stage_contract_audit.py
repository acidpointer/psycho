# @category Analysis
# @description Audit FNV PPLighting material texture arrays to pass-entry stage keys for native PBR

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
	0x00B4F5C0: "renderer singleton getter used by BDF790",
	0x00B70600: "active-object iterator helper A",
	0x00B70700: "active-object iterator helper B",
	0x00BA9EE0: "PPLighting pass-entry append/reuse helper",
	0x00BDAF10: "PPLighting material/property array helper",
	0x00BDB4A0: "PPLighting setup variant before BDF790",
	0x00BDF790: "PPLighting selector/pass-entry driver",
	0x00E7EA00: "final pass-entry resource resolver and SetTexture caller",
	0x00E7EB00: "final pass-entry texture cache compare/apply helper",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x00B68660: "PPLighting six texture-array writer",
	0x00B690D0: "PPLighting material texture/effect serializer",
}

FOCUS_FUNCTIONS = [
	(0x00BDAF10, "PPLighting material/property array helper", 52000),
	(0x00BDF790, "PPLighting selector/pass-entry driver", 42000),
	(0x00BDB4A0, "PPLighting setup variant before BDF790", 36000),
	(0x00BA9EE0, "PPLighting pass-entry append/reuse helper", 26000),
	(0x00E7EB00, "final pass-entry texture cache compare/apply helper", 26000),
	(0x00E7EA00, "final pass-entry resource resolver and SetTexture caller", 26000),
]

REF_TARGETS = [
	(0x00BDAF10, "PPLighting material/property array helper"),
	(0x00BA9EE0, "PPLighting pass-entry append/reuse helper"),
	(0x00A59D30, "NiAVObject property lookup by type"),
	(0x00B68660, "PPLighting six texture-array writer"),
	(0x00E7EA00, "final pass-entry resource resolver"),
	(0x00E7EB00, "final pass-entry apply helper"),
	(0x00E88A20, "NiDX9RenderState::SetTexture"),
]

MATERIAL_ARRAY_OFFSETS = [
	(0xAC, "diffuse/base texture array"),
	(0xB0, "normal/normal-map texture array"),
	(0xB4, "glow/skin/hair layer texture array"),
	(0xB8, "heightmap texture array"),
	(0xBC, "envmap texture array"),
	(0xC0, "envmap-mask texture array"),
	(0xC4, "per-index material byte flags"),
	(0xCC, "per-index material byte flags"),
]

BDAF10_STAGE_KEYS = [
	0x93,
	0x94,
	0x1EF,
	0x1F1,
	0x1F2,
	0x1F3,
	0x1F4,
	0x1F5,
]

SCAN_PATTERNS = [
	"FUN_00ba9ee0",
	"FUN_00a59d30",
	"FUN_00b70600",
	"FUN_00b70700",
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
	"499",
	"500",
	"0x1f5",
	"param_3",
	"param_6",
	"param_7",
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

def read_u32(addr_int):
	try:
		value = memory.getInt(toAddr(addr_int))
		if value < 0:
			value += 0x100000000
		return value
	except:
		return None

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

def decompile_text(addr_int):
	func = get_function(addr_int)
	if func is None:
		return None
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		return result.getDecompiledFunction().getC()
	return None

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

def operand_text(inst, index):
	try:
		return inst.getDefaultOperandRepresentation(index)
	except:
		return "?"

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

def normalized_instruction_text(inst):
	return inst.toString().lower().replace(" ", "")

def material_offset_label_from_text(text):
	for item in MATERIAL_ARRAY_OFFSETS:
		needle = "+0x%x" % item[0]
		needle_alt = "+0x%02x" % item[0]
		if needle in text or needle_alt in text:
			return item[1]
	return None

def stage_key_label_from_text(text):
	for key in BDAF10_STAGE_KEYS:
		needle = "0x%x" % key
		if needle in text:
			return "BDAF10 material-stage key 0x%x" % key
	if "push499" in text or ",499," in text:
		return "BDAF10 material-stage key 0x1f3 (499)"
	if "push500" in text or ",500," in text:
		return "BDAF10 material-stage key 0x1f4 (500)"
	return None

def scan_patterns(addr_int, label, patterns):
	write("")
	write("=" * 70)
	write("MATCHED DECOMPILE LINES: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	code = decompile_text(addr_int)
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
		if matched >= 280:
			write("  ... (truncated)")
			break
	write("  Total matched lines: %d" % matched)

def is_call_to(inst, target_int):
	refs = inst.getReferencesFrom()
	for ref in refs:
		if ref.getReferenceType().isCall() and ref.getToAddress().getOffset() == target_int:
			return True
	return False

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

def print_stack_args_for_call(call_inst, max_args):
	args = collect_push_args_before_call(call_inst, max_args, 64)
	index = 0
	for item in args:
		op = item[0]
		push_addr = item[1]
		ntext = op.strip().upper()
		write("    stack_arg%d = %-14s ; push @ 0x%08x" % (index, op, push_addr))
		if ntext in REGISTERS:
			print_recent_register_def(push_addr, ntext, 32)
		index += 1
	if len(args) == 0:
		write("    [no local PUSH args found]")

def print_material_offset_windows(addr_int, label):
	write("")
	write("=" * 70)
	write("MATERIAL ARRAY OFFSET WINDOWS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = get_function(addr_int)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	last_printed = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		addr_int = inst.getAddress().getOffset()
		text = normalized_instruction_text(inst)
		offset_label = material_offset_label_from_text(text)
		if offset_label is None:
			continue
		if count > 0 and addr_int - last_printed < 8:
			continue
		write("")
		write("  %s referenced at 0x%08x: %s" % (offset_label, addr_int, inst.toString()))
		disasm_window(addr_int, 8, 10, "%s material array reference" % offset_label)
		last_printed = addr_int
		count += 1
		if count >= 60:
			write("  ... (truncated)")
			break
	write("  Total material array references printed: %d" % count)

def print_ba9ee0_call_windows(addr_int, label):
	write("")
	write("=" * 70)
	write("BA9EE0 CALL WINDOWS WITH STACK ARGS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = get_function(addr_int)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		if not is_call_to(inst, 0x00BA9EE0):
			continue
		call_addr = inst.getAddress().getOffset()
		write("")
		write("  CALL %d to BA9EE0 at 0x%08x" % (count + 1, call_addr))
		print_stack_args_for_call(inst, 8)
		disasm_window(call_addr, 18, 12, "BA9EE0 call in %s" % label)
		count += 1
		if count >= 48:
			write("  ... (truncated)")
			break
	write("  Total BA9EE0 call windows printed: %d" % count)

def print_stage_key_windows(addr_int, label):
	write("")
	write("=" * 70)
	write("BDAF10 MATERIAL STAGE KEY WINDOWS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = get_function(addr_int)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = normalized_instruction_text(inst)
		key_label = stage_key_label_from_text(text)
		if key_label is None:
			continue
		write("")
		write("  %s at 0x%08x: %s" % (key_label, inst.getAddress().getOffset(), inst.toString()))
		disasm_window(inst.getAddress().getOffset(), 8, 8, key_label)
		count += 1
		if count >= 48:
			write("  ... (truncated)")
			break
	write("  Total stage-key windows printed: %d" % count)

def print_focus_decompiles():
	for item in FOCUS_FUNCTIONS:
		decompile_at(item[0], item[1], item[2])
		find_and_print_calls_from(item[0], item[1])
		scan_patterns(item[0], item[1], SCAN_PATTERNS)

def print_refs():
	for item in REF_TARGETS:
		find_refs_to(item[0], item[1])

def main():
	write("FNV PBR PPLIGHTING MATERIAL ARRAY STAGE CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. Which BDAF10 branches read the proven type-3 material arrays +0xAC..+0xC0?")
	write("2. Which exact BA9EE0 entry +4 stage keys are emitted from those branches?")
	write("3. Are normal/height/env/env-mask arrays consumed by this material helper, or only diffuse/glow?")
	write("4. What material-stage map is still missing before a visible native PBR replacement shader can bind safely?")
	write("")
	write("Compatibility rule:")
	write("Do not replace a material shader until source arrays, final pass stages, constants, and sampler policy are all proven for one family.")
	print_refs()
	print_focus_decompiles()
	print_material_offset_windows(0x00BDAF10, "PPLighting material/property array helper")
	print_stage_key_windows(0x00BDAF10, "PPLighting material/property array helper")
	print_ba9ee0_call_windows(0x00BDAF10, "PPLighting material/property array helper")

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_material_array_stage_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
