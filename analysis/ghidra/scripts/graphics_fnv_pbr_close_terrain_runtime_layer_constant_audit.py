# @category Analysis
# @description Audit close-terrain runtime layer, define, and constant contract for native PBR

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
	0x00B66640: "terrain layer flag initializer",
	0x00B68660: "six material array writer",
	0x00B71BF0: "PPLighting vertex descriptor constructor",
	0x00B74210: "PPLighting pixel descriptor constructor candidate",
	0x00B874F0: "TEX define user / shader descriptor family",
	0x00BA9EE0: "PPLighting pass-entry append/reuse helper",
	0x00BC5C40: "TEX define user / shader descriptor family",
	0x00BD4BA0: "current pass shader-interface apply",
	0x00BDAC00: "land/specular helper",
	0x00BDAF10: "diffuse/glow material helper",
	0x00BDB4A0: "PPLighting selector setup +0xF0 variant",
	0x00BDF3E0: "LandO/light-resource helper",
	0x00BDF790: "PPLighting selector setup +0xF4 main",
	0x00BE1F90: "BSShader::SetShaders",
	0x01011584: "empty define string",
	0x010AE9CC: "LANDLO define",
	0x010AEAB8: "lighting\\2x\\v\\land.v.hlsl",
	0x010AEAF0: "NUM_PT_LIGHTS candidate",
	0x010AEAFC: "NUM_PT_LIGHTS candidate lower",
	0x010AEB0C: "POINT define",
	0x010AEB8C: "SPECULAR define",
	0x010AEB98: "LIGHTS define",
	0x010AEBA0: "PROJ_SHADOW define",
	0x010AEC18: "PTLIGHT define",
	0x010AEC20: "LANDALPHA define",
	0x010AEC48: "SI define",
	0x010AECAC: "TEX define",
	0x010AECE0: "FOG define",
	0x010AF030: "lighting\\2x\\p\\land.p.hlsl",
}

DEFINE_STRINGS = [
	(0x010AEAB8, "lighting\\2x\\v\\land.v.hlsl"),
	(0x010AF030, "lighting\\2x\\p\\land.p.hlsl"),
	(0x010AECAC, "TEX define"),
	(0x010AEC20, "LANDALPHA define"),
	(0x010AEBA0, "PROJ_SHADOW define"),
	(0x010AEC18, "PTLIGHT define"),
	(0x010AEC48, "SI define"),
	(0x010AE9CC, "LANDLO define"),
	(0x010AECE0, "FOG define"),
	(0x010AEAFC, "NUM_PT_LIGHTS candidate lower"),
	(0x010AEB0C, "POINT define"),
]

VANILLA_CONSTANT_STRINGS = [
	(0x010AF4B0, "FogParams candidate"),
	(0x010AF50C, "Light Position3 candidate"),
	(0x010AF51C, "Light Position2 candidate"),
	(0x010AF52C, "Light Position1 candidate"),
	(0x010AF53C, "Light Position0 candidate"),
	(0x010AF54C, "Light Direction candidate"),
	(0x010AF55C, "LightColors candidate"),
	(0x010AF568, "Ambient Color candidate"),
	(0x010AF5E4, "FogColor / ShadowVolumeExtrudeDistance candidate"),
	(0x010AF62C, "LightData candidate"),
	(0x010A91D4, "land/specular compare global candidate"),
]

FOCUS_FUNCTIONS = [
	(0x00539960, "terrain texture writer callsite A", 18000),
	(0x0053A090, "terrain texture writer callsite B", 18000),
	(0x00B66640, "terrain layer flag initializer", 18000),
	(0x00B68660, "six material array writer", 20000),
	(0x00B71BF0, "PPLighting vertex descriptor constructor", 30000),
	(0x00B74210, "PPLighting pixel descriptor constructor candidate", 30000),
	(0x00BDB4A0, "PPLighting selector setup +0xF0 variant", 28000),
	(0x00BDF790, "PPLighting selector setup +0xF4 main", 28000),
	(0x00BDAC00, "land/specular helper", 18000),
	(0x00BDF3E0, "LandO/light-resource helper", 18000),
	(0x00BD4BA0, "current pass shader-interface apply", 18000),
]

SCAN_PATTERNS = [
	"0xa8",
	"0xac",
	"0xb0",
	"0xb4",
	"0xb8",
	"0xbc",
	"0xc0",
	"0xc4",
	"0xcc",
	"0x20",
	"0x24",
	"0x34",
	"0x36",
	"0x37",
	"0x39",
	"0x63",
	"0x88",
	"0x89",
	"FUN_00ba9ee0",
	"FUN_00b66640",
	"FUN_00b68660",
	"FUN_00bdac00",
	"FUN_00bdaf10",
	"FUN_00bdf3e0",
	"Land",
	"land",
	"TEX",
	"texture",
	"constant",
	"Fog",
	"Light",
]

PASS_ENTRY_HELPERS = [
	0x00BDB4A0,
	0x00BDF790,
	0x00BDAC00,
	0x00BDF3E0,
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

def read_u32(addr_int):
	try:
		value = memory.getInt(toAddr(addr_int))
		if value < 0:
			value += 0x100000000
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
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	code = decompile_text_for_func(func)
	if code is None:
		write("  [decompilation failed]")
		return None
	write(code[:max_len])
	return code

def find_refs_to(addr_int, label):
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
		if count > 140:
			write("  ... (truncated)")
			break
	write("  Total printed: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	func = get_function(addr_int)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	count = 0
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target_int = ref.getToAddress().getOffset()
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), target_int, label_for(target_int)))
				count += 1
	write("  Total: %d calls" % count)

def scan_decompile_lines(addr_int, label, patterns):
	write("")
	write("=" * 70)
	write("Matched decompile lines: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = get_function(addr_int)
	if func is None:
		write("  [function not found]")
		return
	code = decompile_text_for_func(func)
	if code is None:
		write("  [decompilation failed]")
		return
	lines = code.splitlines()
	count = 0
	line_no = 1
	for line in lines:
		lower = line.lower()
		matched = False
		for pattern in patterns:
			if pattern.lower() in lower:
				matched = True
		if matched:
			write("  L%-4d %s" % (line_no, line))
			count += 1
		line_no += 1
	write("  Total matched lines: %d" % count)

def operand_text(inst, index):
	try:
		return inst.getDefaultOperandRepresentation(index)
	except:
		return "?"

def full_inst_text(inst):
	if inst is None:
		return "[missing instruction]"
	parts = []
	index = 0
	while index < inst.getNumOperands():
		parts.append(operand_text(inst, index))
		index += 1
	if len(parts) == 0:
		return inst.getMnemonicString()
	return "%s %s" % (inst.getMnemonicString(), ",".join(parts))

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
		rtype = ref.getReferenceType()
		if rtype.isCall() or rtype.isJump() or rtype.isData() or rtype.isRead() or rtype.isWrite():
			write("      ref %-18s -> 0x%08x %s" % (str(rtype), target.getOffset(), label_for(target.getOffset())))

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("=" * 70)
	write("DISASM: %s around 0x%08x" % (label, center_int))
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
		marker = "=> " if cur.getAddress().getOffset() == inst.getAddress().getOffset() else "   "
		write("%s0x%08x: %-58s %s" % (marker, cur.getAddress().getOffset(), full_inst_text(cur), label_for(cur.getAddress().getOffset())))
		print_refs_from_instruction(cur)
		cur = listing.getInstructionAfter(cur.getAddress())
		count += 1

def ref_in_interesting_range(addr_int):
	if addr_int >= 0x00B71BF0 and addr_int <= 0x00B78940:
		return True
	if addr_int >= 0x00BDB4A0 and addr_int <= 0x00BE08A0:
		return True
	if addr_int >= 0x00BDAC00 and addr_int <= 0x00BDF700:
		return True
	if addr_int >= 0x00BC5C40 and addr_int <= 0x00BC6600:
		return True
	if addr_int >= 0x00B874F0 and addr_int <= 0x00B87D40:
		return True
	return False

def print_ref_windows(addr_int, label, max_windows):
	find_refs_to(addr_int, label)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_int = ref.getFromAddress().getOffset()
		if not ref_in_interesting_range(from_int):
			continue
		disasm_window(from_int, 10, 22, "%s ref" % label)
		count += 1
		if count >= max_windows:
			write("  [ref window limit reached for %s]" % label)
			break

def print_all_define_refs():
	write("")
	write("=" * 70)
	write("SHADER DEFINE / LAND VARIANT STRING REFERENCES")
	write("=" * 70)
	for item in DEFINE_STRINGS:
		print_ref_windows(item[0], item[1], 18)

def print_all_constant_refs():
	write("")
	write("=" * 70)
	write("VANILLA CONSTANT STRING / GLOBAL REFERENCES")
	write("=" * 70)
	for item in VANILLA_CONSTANT_STRINGS:
		print_ref_windows(item[0], item[1], 10)

def print_focus_functions():
	for item in FOCUS_FUNCTIONS:
		find_refs_to(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])
		decompile_at(item[0], item[1], item[2])
		scan_decompile_lines(item[0], item[1], SCAN_PATTERNS)

def print_calls_to_ba9ee0_from(addr_int, label):
	func = get_function(addr_int)
	write("")
	write("=" * 70)
	write("PASS ENTRY CALL WINDOWS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	count = 0
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall() and ref.getToAddress().getOffset() == 0x00BA9EE0:
				disasm_window(inst.getAddress().getOffset(), 18, 18, "%s -> BA9EE0" % label)
				count += 1
	write("  Total BA9EE0 calls: %d" % count)

def print_pass_entry_windows():
	for addr_int in PASS_ENTRY_HELPERS:
		print_calls_to_ba9ee0_from(addr_int, label_for(addr_int))

def print_expected_contract():
	write("")
	write("=" * 70)
	write("NVR CLOSE TERRAIN ABI TO PROVE AGAINST VANILLA")
	write("=" * 70)
	write("Textures: BaseMap[7] at s0..s6, NormalMap[7] at s7..s13.")
	write("Layer count: TEX_COUNT macro must match active layer count; do not assume 7 for every row.")
	write("Blend inputs: blend_0.xyzw plus blend_1.xyz feed seven layer weights.")
	write("Pixel constants: AmbientColor c1, SunColor c3, SunDir c18, LandSpec c32/c33, LandHeight c34/c35, FogParam c36, FogColor c37.")
	write("Point light variants additionally need PointLightColor c39, PointLightPosition c63, PointLightCount c88.")
	write("PBR controls: TESR_TerrainData c89 and TESR_TerrainExtraData c90 are NVR-owned extras, not vanilla constants.")
	write("Replacement is valid only if the active runtime row owns these textures/constants or has a proven fallback.")

def main():
	write("FNV PBR CLOSE TERRAIN RUNTIME LAYER/CONSTANT CONTRACT AUDIT")
	write("")
	write("Goal:")
	write("- Prove close-terrain TEX_COUNT/layer ownership instead of assuming seven layers.")
	write("- Prove which land-ish variants own diffuse/normal arrays and which are projected-shadow, SI, LandO, landlo-fog, or point-light rows.")
	write("- Check whether vanilla supplies the constants NVR close-terrain shaders expect, and which constants must be uploaded by Psycho.")
	print_expected_contract()
	print_all_define_refs()
	print_all_constant_refs()
	print_focus_functions()
	print_pass_entry_windows()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_runtime_layer_constant_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
