# @category Analysis
# @description Audit PPLighting close-terrain discriminator versus shader-slot-only land replacement

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00539960: "terrain texture writer callsite A",
	0x0053A090: "terrain texture writer callsite B",
	0x00B66640: "PPLighting texture-array flag initializer",
	0x00B68660: "PPLighting six texture-array writer",
	0x00BA9EE0: "PPLighting pass-entry append/reuse helper",
	0x00BD9540: "PPLighting material helper BD9540",
	0x00BD9840: "PPLighting material helper BD9840",
	0x00BD99C0: "PPLighting material helper BD99C0",
	0x00BD9AC0: "PPLighting material helper BD9AC0",
	0x00BD9BC0: "PPLighting material helper BD9BC0",
	0x00BDAC00: "PPLighting land/specular helper BDAC00",
	0x00BDAF10: "PPLighting diffuse/glow material helper",
	0x00BDB4A0: "PPLighting setup variant before main",
	0x00BDF3E0: "PPLighting LandO/alternate land helper",
	0x00BDF790: "PPLighting main selector/pass-entry driver",
}

LAND_STRINGS = [
	(0x010AEAB8, "lighting\\2x\\v\\land.v.hlsl"),
	(0x010AEA94, "lighting\\2x\\v\\landlighting.v.hlsl"),
	(0x010AE914, "lighting\\2x\\v\\LandO.v.hlsl"),
	(0x010AEC2C, "lighting\\1x\\v\\land.v.hlsl"),
	(0x010AEC20, "LANDALPHA define"),
	(0x010AEBA0, "PROJ_SHADOW define"),
	(0x010AEB98, "LIGHTS define"),
	(0x010AEB8C, "SPECULAR define"),
	(0x010AEAFC, "NUM_PT_LIGHTS define"),
]

FOCUS_FUNCTIONS = [
	(0x00539960, "terrain texture writer callsite A"),
	(0x0053A090, "terrain texture writer callsite B"),
	(0x00B66640, "texture-array flag initializer"),
	(0x00B68660, "six texture-array writer"),
	(0x00BDB4A0, "setup variant before main"),
	(0x00BDF790, "main selector/pass-entry driver"),
	(0x00BDAC00, "land/specular helper"),
	(0x00BDAF10, "diffuse/glow material helper"),
	(0x00BDF3E0, "LandO/alternate land helper"),
]

HELPER_TARGETS = [
	0x00BA9EE0,
	0x00BD9540,
	0x00BD9840,
	0x00BD99C0,
	0x00BD9AC0,
	0x00BD9BC0,
	0x00BDAC00,
	0x00BDAF10,
	0x00BDF3E0,
]

SCAN_PATTERNS = [
	"FUN_00ba9ee0",
	"FUN_00bdac00",
	"FUN_00bdaf10",
	"FUN_00bdf3e0",
	"FUN_00b68660",
	"FUN_00b66640",
	"param_1[8]",
	"param_1[9]",
	"+ 0x20",
	"+0x20",
	"+ 0x24",
	"+0x24",
	"+ 0x34",
	"+0x34",
	"+ 0x9c",
	"+0x9c",
	"+ 0xb8",
	"+0xb8",
	"+ 0xbc",
	"+0xbc",
	"+ 0xc0",
	"+0xc0",
	"+ 0xac",
	"+0xac",
	"+ 0xb0",
	"+0xb0",
	"landscape texturing",
	"landscape textures",
]

INSTRUCTION_PATTERNS = [
	"TEST",
	"CMP",
	"MOV",
	"CALL",
	"0x20",
	"0x24",
	"0x34",
	"0x9c",
	"0xb8",
	"0xbc",
	"0xc0",
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

def decompile_at(addr_int, label, max_len):
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
		return None
	faddr = func.getEntryPoint().getOffset()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, func.getBody().getNumAddresses()))
	if faddr != addr_int:
		write("  NOTE: requested address is inside function entry 0x%08x" % faddr)
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
		return code
	write("  [decompilation failed]")
	return None

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
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
		if count > 80:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def print_refs_from_instruction(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		target = ref.getToAddress()
		taddr = target.getOffset()
		write("      ref %s -> 0x%08x %s" % (ref.getReferenceType(), taddr, label_for(taddr)))

def instruction_before_steps(inst, steps):
	cur = inst
	count = 0
	while count < steps and cur is not None:
		cur = listing.getInstructionBefore(cur.getAddress())
		count += 1
	return cur

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

def print_matched_decompile_lines(func, code, label, limit):
	write("")
	write("=" * 70)
	write("MATCHED DECOMPILE LINES: %s @ 0x%08x" % (label, func.getEntryPoint().getOffset()))
	write("=" * 70)
	scan_patterns_in_code(code, SCAN_PATTERNS, limit)

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
	args = collect_push_args_before_call(call_inst, max_args, 96)
	index = 0
	for item in args:
		op = item[0]
		push_addr = item[1]
		ntext = op.strip().upper()
		write("    stack_arg%d = %-14s ; push @ 0x%08x" % (index, op, push_addr))
		if index == 0:
			write("      entry +0 seed/owner")
		elif index == 1:
			write("      entry +4 final stage/key")
		elif index == 2:
			write("      entry +7 selector byte")
		elif index == 3:
			write("      entry +9 resource count")
		elif index >= 4:
			write("      entry +0x0C resource slot %d" % (index - 4))
		if ntext in REGISTERS:
			print_recent_register_def(push_addr, ntext, 48)
		index += 1
	if len(args) == 0:
		write("    [no local PUSH args found]")

def print_helper_calls(func, label, limit):
	write("")
	write("=" * 70)
	write("HELPER CALLS FROM %s @ 0x%08x" % (label, func.getEntryPoint().getOffset()))
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
		write("  call %d at 0x%08x -> 0x%08x %s" % (count + 1, call_addr, tgt, label_for(tgt)))
		print_stack_args_for_call(inst, 16)
		disasm_window(call_addr, 10, 10, "helper call in %s" % label)
		count += 1
		if count >= limit:
			write("  ... (truncated)")
			break
	write("  Total helper calls printed: %d" % count)

def interesting_instruction(text):
	upper = text.upper()
	if "TEST" in upper or "CMP" in upper:
		return True
	if "0X20" in upper or "0X24" in upper or "0X34" in upper or "0X9C" in upper:
		return True
	if "0XB8" in upper or "0XBC" in upper or "0XC0" in upper:
		return True
	return False

def print_interesting_instructions(func, label, limit):
	write("")
	write("=" * 70)
	write("FLAG/GEOMETRY INSTRUCTION LINES: %s @ 0x%08x" % (label, func.getEntryPoint().getOffset()))
	write("=" * 70)
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		if not interesting_instruction(text):
			continue
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), text))
		print_refs_from_instruction(inst)
		count += 1
		if count >= limit:
			write("  ... (truncated)")
			break
	write("  Total interesting instructions printed: %d" % count)

def print_function(addr_int, label):
	func = get_function(addr_int)
	if func is None:
		write("")
		write("Missing function 0x%08x %s" % (addr_int, label))
		return
	code = decompile_at(addr_int, label, 26000)
	print_matched_decompile_lines(func, code, label, 120)
	print_interesting_instructions(func, label, 160)
	print_helper_calls(func, label, 36)

def print_function_list(items):
	for item in items:
		print_function(item[0], item[1])

def print_land_string_refs():
	write("")
	write("=" * 70)
	write("LAND SHADER/DEFINE STRING REFERENCES")
	write("=" * 70)
	for item in LAND_STRINGS:
		addr_int = item[0]
		label = item[1]
		find_refs_to(addr_int, label)

def main():
	write("FNV PBR CLOSE TERRAIN TRUE-LAND DISCRIMINATOR AUDIT")
	write("")
	write("Questions:")
	write("1. Which engine branches prove a draw is real close landscape, not merely a land shader slot?")
	write("2. Which selector/geometry flags and material arrays differ for landscape versus interior/static draws?")
	write("3. Which land helper pass entries carry real texture resources, projected shadow rows, and point-light rows?")
	write("4. What should OMV require before replacing close terrain shaders?")
	print_land_string_refs()
	print_function_list(FOCUS_FUNCTIONS)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_true_land_discriminator_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
