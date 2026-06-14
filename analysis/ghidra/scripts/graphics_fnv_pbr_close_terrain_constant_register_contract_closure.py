# @category Analysis
# @description Close FNV PBR close-terrain constant register ownership contract

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00B71BF0: "PPLighting vertex descriptor constructor",
	0x00B74210: "PPLighting pixel descriptor constructor",
	0x00B7E430: "PPLighting shader constant/interface setup",
	0x00B994F0: "current draw dispatcher",
	0x00BD4BA0: "current pass shader-interface apply",
	0x00BDB4A0: "selector setup +0xF0 variant",
	0x00BDF790: "selector setup +0xF4 main",
	0x00BE1F90: "BSShader::SetShaders",
	0x00E826D0: "shader-interface record apply",
	0x010AF4B0: "FogParams string",
	0x010AF54C: "Light Direction string",
	0x010AF55C: "LightColors string",
	0x010AF568: "Ambient Color string",
	0x010AF5E4: "FogColor string",
	0x010AF62C: "LightData string",
}

REGISTER_TARGETS = [
	(1, "AmbientColor c1"),
	(3, "SunColor c3"),
	(18, "SunDir c18"),
	(32, "LandSpec c32"),
	(33, "LandSpec c33"),
	(34, "LandHeight c34"),
	(35, "LandHeight c35"),
	(36, "FogParam c36"),
	(37, "FogColor c37"),
	(39, "PointLightColor c39"),
	(63, "PointLightPosition c63"),
	(88, "PointLightCount c88"),
	(89, "TESR_TerrainData c89"),
	(90, "TESR_TerrainExtraData c90"),
]

VANILLA_CONSTANT_STRINGS = [
	(0x010AF4B0, "FogParams"),
	(0x010AF50C, "Light Position3"),
	(0x010AF51C, "Light Position2"),
	(0x010AF52C, "Light Position1"),
	(0x010AF53C, "Light Position0"),
	(0x010AF54C, "Light Direction"),
	(0x010AF55C, "LightColors"),
	(0x010AF568, "Ambient Color"),
	(0x010AF5E4, "FogColor / ShadowVolumeExtrudeDistance"),
	(0x010AF62C, "LightData"),
]

FOCUS_FUNCTIONS = [
	(0x00B71BF0, "PPLighting vertex descriptor constructor", 30000),
	(0x00B74210, "PPLighting pixel descriptor constructor", 30000),
	(0x00B7E430, "PPLighting shader constant/interface setup", 30000),
	(0x00B994F0, "current draw dispatcher", 18000),
	(0x00BD4BA0, "current pass shader-interface apply", 22000),
	(0x00BDB4A0, "selector setup +0xF0 variant", 30000),
	(0x00BDF790, "selector setup +0xF4 main", 30000),
	(0x00BE1F90, "BSShader::SetShaders", 22000),
	(0x00E826D0, "shader-interface record apply", 22000),
]

MATCH_PATTERNS = [
	"FogParams",
	"Light Direction",
	"LightColors",
	"Ambient Color",
	"FogColor",
	"LightData",
	"0x20",
	"0x21",
	"0x22",
	"0x23",
	"0x24",
	"0x25",
	"0x27",
	"0x3f",
	"0x58",
	"0x59",
	"0x5a",
	"FUN_00e826d0",
	"FUN_00bd4ba0",
	"DAT_0126f74c",
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

def get_function(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	return func

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

def decompile_text_for_func(func):
	if func is None:
		return None
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		return result.getDecompiledFunction().getC()
	return None

def decompile_at(addr_int, label, max_len=12000):
	func = get_function(addr_int)
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
		write("  NOTE: requested 0x%08x is inside entry 0x%08x" % (addr_int, faddr))
	code = decompile_text_for_func(func)
	if code is None:
		write("  [decompilation failed]")
		return None
	write(code[:max_len])
	return code

def matched_lines(code, label):
	write("")
	write("=" * 70)
	write("MATCHED CONSTANT/REGISTER LINES: %s" % label)
	write("=" * 70)
	if code is None:
		write("  [no code]")
		return
	lines = code.splitlines()
	count = 0
	for index in range(len(lines)):
		lower = lines[index].lower()
		for pattern in MATCH_PATTERNS:
			if pattern.lower() in lower:
				write("  L%-4d %s" % (index + 1, lines[index]))
				count += 1
				break
	write("  Total matched lines: %d" % count)

def find_refs_to(addr_int, label, limit):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_addr = ref.getFromAddress()
		from_func = fm.getFunctionContaining(from_addr)
		fname = from_func.getName() if from_func else "???"
		inst = listing.getInstructionContaining(from_addr)
		text = inst.toString() if inst is not None else ""
		write("  %s @ 0x%08x (in %s) %s" % (ref.getReferenceType(), from_addr.getOffset(), fname, text))
		count += 1
		if count >= limit:
			write("  ... (truncated)")
			break
	write("  Total printed: %d refs" % count)

def instruction_before_steps(inst, steps):
	cur = inst
	index = 0
	while cur is not None and index < steps:
		prev = listing.getInstructionBefore(cur.getAddress())
		if prev is None:
			break
		cur = prev
		index += 1
	return cur

def print_refs_from_instruction(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		target = ref.getToAddress()
		if target is None:
			continue
		write("      ref %-18s -> 0x%08x %s" % (str(ref.getReferenceType()), target.getOffset(), label_for(target.getOffset())))

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("=" * 70)
	write("DISASM: %s around 0x%08x" % (label, center_int))
	write("=" * 70)
	inst = listing.getInstructionContaining(toAddr(center_int))
	if inst is None:
		write("  [instruction not found]")
		return
	cur = instruction_before_steps(inst, before_count)
	count = 0
	while cur is not None and count <= before_count + after_count:
		prefix = "=> " if cur.getAddress().getOffset() == inst.getAddress().getOffset() else "   "
		func = fm.getFunctionContaining(cur.getAddress())
		fname = func.getName() if func else "???"
		write("%s0x%08x: %-58s %s" % (prefix, cur.getAddress().getOffset(), cur.toString(), fname))
		print_refs_from_instruction(cur)
		cur = listing.getInstructionAfter(cur.getAddress())
		count += 1

def scalar_value(inst, operand_index):
	try:
		scalar = inst.getScalar(operand_index)
		if scalar is None:
			return None
		value = scalar.getValue()
		if value < 0:
			value += 0x100000000
		return value
	except:
		return None

def instruction_has_scalar(inst, target):
	count = inst.getNumOperands()
	index = 0
	while index < count:
		value = scalar_value(inst, index)
		if value == target:
			return True
		index += 1
	return False

def scan_register_immediates_in_function(addr_int, label):
	func = get_function(addr_int)
	write("")
	write("=" * 70)
	write("REGISTER IMMEDIATE SCAN: %s" % label)
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	hits = 0
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		for item in REGISTER_TARGETS:
			if instruction_has_scalar(inst, item[0]):
				write("  hit %-32s at 0x%08x: %s" % (item[1], inst.getAddress().getOffset(), inst.toString()))
				print_refs_from_instruction(inst)
				hits += 1
				if hits <= 80:
					disasm_window(inst.getAddress().getOffset(), 8, 12, "%s / %s" % (label, item[1]))
				break
	write("  Total register-immediate hits: %d" % hits)

def print_constant_string_refs():
	for item in VANILLA_CONSTANT_STRINGS:
		find_refs_to(item[0], item[1], 80)

def decompile_focus_functions():
	for item in FOCUS_FUNCTIONS:
		code = decompile_at(item[0], item[1], item[2])
		matched_lines(code, item[1])

def scan_register_immediates():
	for item in FOCUS_FUNCTIONS:
		scan_register_immediates_in_function(item[0], item[1])

def main():
	write("FNV PBR CLOSE TERRAIN CONSTANT REGISTER CONTRACT CLOSURE")
	write("")
	write("Goal:")
	write("- Prove whether vanilla terrain rows provide NVR-required c32/c34/c36/c37/c39/c63/c88 constants.")
	write("- Distinguish vanilla constants from Psycho-owned c89/c90 terrain controls.")
	write("- Keep point-light and parallax/height terrain variants blocked until their register payload is proven.")
	print_constant_string_refs()
	decompile_focus_functions()
	scan_register_immediates()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_constant_register_contract_closure.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
