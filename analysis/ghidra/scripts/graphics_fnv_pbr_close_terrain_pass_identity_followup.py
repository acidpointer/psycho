# @category Analysis
# @description Follow up close-terrain PBR pass identity and exclusion contract

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

PPLIGHTING_VERTEX_GROUP_C_ADDR = 0x011FDE5C
PPLIGHTING_PIXEL_GROUP_B_ADDR = 0x011FDB08

TARGET_SHADER_SLOTS = [
	("landlod", PPLIGHTING_VERTEX_GROUP_C_ADDR, 2, PPLIGHTING_PIXEL_GROUP_B_ADDR, 3),
	("landlod_projected_shadow", PPLIGHTING_VERTEX_GROUP_C_ADDR, 5, PPLIGHTING_PIXEL_GROUP_B_ADDR, 6),
	("close_land_projected_shadow", PPLIGHTING_VERTEX_GROUP_C_ADDR, 53, PPLIGHTING_PIXEL_GROUP_B_ADDR, 60),
	("close_land_alpha_projected_shadow", PPLIGHTING_VERTEX_GROUP_C_ADDR, 54, PPLIGHTING_PIXEL_GROUP_B_ADDR, 61),
	("close_land_base", PPLIGHTING_VERTEX_GROUP_C_ADDR, 78, PPLIGHTING_PIXEL_GROUP_B_ADDR, 80),
	("close_land_alpha", PPLIGHTING_VERTEX_GROUP_C_ADDR, 79, PPLIGHTING_PIXEL_GROUP_B_ADDR, 81),
	("close_land_landlo_fog", PPLIGHTING_VERTEX_GROUP_C_ADDR, 80, PPLIGHTING_PIXEL_GROUP_B_ADDR, 82),
	("close_land_si", PPLIGHTING_VERTEX_GROUP_C_ADDR, 78, PPLIGHTING_PIXEL_GROUP_B_ADDR, 83),
	("close_land_alpha_si", PPLIGHTING_VERTEX_GROUP_C_ADDR, 81, PPLIGHTING_PIXEL_GROUP_B_ADDR, 84),
	("close_land_point", PPLIGHTING_VERTEX_GROUP_C_ADDR, 82, PPLIGHTING_PIXEL_GROUP_B_ADDR, 85),
	("close_land_alpha_point", PPLIGHTING_VERTEX_GROUP_C_ADDR, 83, PPLIGHTING_PIXEL_GROUP_B_ADDR, 86),
]

KEY_FUNCTIONS = [
	(0x00B55520, "light/environment selector helper before shader-interface apply"),
	(0x00B55560, "shader-interface object selector"),
	(0x00B66640, "terrain texture-array flag initializer"),
	(0x00B68660, "six texture-array writer"),
	(0x00BA9EE0, "pass-entry append/reuse helper"),
	(0x00BD4BA0, "current pass shader-interface apply"),
	(0x00BDAC00, "zero-resource land/specular helper"),
	(0x00BDB4A0, "PPLighting selector setup variant"),
	(0x00BDF3E0, "LandO/light-resource helper"),
	(0x00BDF790, "PPLighting selector/pass-entry driver"),
	(0x00BE1F90, "BSShader::SetShaders"),
]

PASS_HELPERS = [
	(0x00BD9540, "PPLighting pass-entry helper BD9540"),
	(0x00BD9840, "PPLighting pass-entry helper BD9840"),
	(0x00BD99C0, "PPLighting pass-entry helper BD99C0"),
	(0x00BD9AC0, "PPLighting pass-entry helper BD9AC0"),
	(0x00BD9BC0, "PPLighting pass-entry helper BD9BC0"),
	(0x00BDAC00, "PPLighting land/specular helper BDAC00"),
	(0x00BDAF10, "PPLighting diffuse/glow material helper BDAF10"),
	(0x00BDB380, "PPLighting pass-entry helper BDB380"),
	(0x00BDF3E0, "PPLighting LandO/light-resource helper BDF3E0"),
	(0x00BDF650, "PPLighting pass-entry helper BDF650"),
	(0x00BDF6C0, "PPLighting pass-entry helper BDF6C0"),
	(0x00BDF790, "PPLighting selector/pass-entry driver BDF790"),
]

REF_TARGETS = [
	(0x00B55520, "light/environment selector helper"),
	(0x00B55560, "shader-interface object selector"),
	(0x00B66640, "terrain texture-array flag initializer"),
	(0x00B68660, "six texture-array writer"),
	(0x00BA9EE0, "pass-entry append/reuse helper"),
	(0x00BD4BA0, "current pass shader-interface apply"),
	(0x00BDAC00, "zero-resource land/specular helper"),
	(0x00BDAF10, "diffuse/glow material helper"),
	(0x00BDB4A0, "PPLighting selector setup variant"),
	(0x00BDF3E0, "LandO/light-resource helper"),
	(0x00BDF790, "PPLighting selector/pass-entry driver"),
	(0x00BE1F90, "BSShader::SetShaders"),
	(0x011F91E0, "current geometry slot"),
	(0x011F9548, "shader interface selector array"),
	(0x0126F74C, "current pass global"),
]

DECOMPILE_PATTERNS = [
	"0xa8",
	"0xc4",
	"0xac",
	"0xb0",
	"0xb4",
	"0xb8",
	"0xbc",
	"0xc0",
	"param_1[0x2a]",
	"param_1[0x31]",
	"param_1[0x3c]",
	"FUN_00ba9ee0",
	"FUN_00bdac00",
	"FUN_00bdaf10",
	"FUN_00bdf3e0",
	"FUN_00b68660",
	"FUN_00b66640",
	"land",
	"Land",
	"terrain",
	"Terrain",
]

LAND_STRINGS = [
	(0x010AEAB8, "lighting\\2x\\v\\land.v.hlsl"),
	(0x010AF030, "lighting\\2x\\p\\land.p.hlsl"),
	(0x010AE914, "lighting\\2x\\v\\LandO.v.hlsl"),
	(0x010AEBA0, "PROJ_SHADOW"),
	(0x010AEC48, "SI"),
	(0x010AEAF0, "NUM_PT_LIGHTS"),
	(0x010AEB0C, "POINT"),
	(0x010AECAC, "TEX"),
]

def write(msg):
	output.append(msg)
	print(msg)

def read_dword(addr_int):
	try:
		return memory.getInt(toAddr(addr_int)) & 0xffffffff
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
	if len(chars) < 2:
		return None
	return "".join(chars)

def get_function(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	return func

def label_for_addr(addr_int):
	if addr_int is None:
		return "unreadable"
	text = read_c_string(addr_int, 96)
	if text is not None:
		return "\"%s\"" % text
	func = get_function(addr_int)
	if func is not None:
		entry = func.getEntryPoint().getOffset()
		if entry == addr_int:
			return func.getName()
		return "%s+0x%x" % (func.getName(), addr_int - entry)
	return "unknown"

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

def find_and_print_calls_from(addr_int, label):
	func = get_function(addr_int)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	body = func.getBody()
	inst_iter = listing.getInstructions(body, True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, label_for_addr(tgt)))
				count += 1
	write("  Total: %d calls" % count)

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
		write("      ref %-18s -> 0x%08x %s" % (str(ref.getReferenceType()), target.getOffset(), label_for_addr(target.getOffset())))

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
	limit = before_count + after_count + 1
	count = 0
	while cur is not None and count < limit:
		marker = "=> " if cur.getAddress().getOffset() == inst.getAddress().getOffset() else "   "
		write("%s0x%08x: %s" % (marker, cur.getAddress().getOffset(), cur.toString()))
		print_refs_from_instruction(cur)
		cur = listing.getInstructionAfter(cur.getAddress())
		count += 1

def print_decompile_matches(addr_int, label):
	code = decompile_at(addr_int, label, 22000)
	if code is None:
		return
	write("")
	write("MATCHED DECOMPILE LINES: %s" % label)
	lines = code.splitlines()
	for line_index in range(0, len(lines)):
		line = lines[line_index]
		lower = line.lower()
		for pattern in DECOMPILE_PATTERNS:
			if pattern.lower() in lower:
				start = max(0, line_index - 2)
				end = min(len(lines), line_index + 3)
				write("  pattern '%s' near line %d:" % (pattern, line_index + 1))
				for item_index in range(start, end):
					write("    %s" % lines[item_index])
				break

def dump_shader_slot(label, vertex_base, vertex_index, pixel_base, pixel_index):
	vertex_slot = vertex_base + vertex_index * 4
	pixel_slot = pixel_base + pixel_index * 4
	vertex_value = read_dword(vertex_slot)
	pixel_value = read_dword(pixel_slot)
	write("  %-32s VS[%03d] slot=0x%08x value=0x%08x %s" % (label, vertex_index, vertex_slot, vertex_value if vertex_value is not None else 0, label_for_addr(vertex_value)))
	write("  %-32s PS[%03d] slot=0x%08x value=0x%08x %s" % (label, pixel_index, pixel_slot, pixel_value if pixel_value is not None else 0, label_for_addr(pixel_value)))
	find_refs_to(vertex_slot, "%s vertex shader table slot" % label)
	find_refs_to(pixel_slot, "%s pixel shader table slot" % label)

def dump_shader_slots():
	write("")
	write("=" * 70)
	write("TARGET TERRAIN/LANDLOD SHADER TABLE SLOTS")
	write("=" * 70)
	for item in TARGET_SHADER_SLOTS:
		dump_shader_slot(item[0], item[1], item[2], item[3], item[4])

def decompile_key_functions():
	for item in KEY_FUNCTIONS:
		print_decompile_matches(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])

def print_references():
	for item in REF_TARGETS:
		find_refs_to(item[0], item[1])
	for item in LAND_STRINGS:
		find_refs_to(item[0], item[1])

def decompile_pass_helper_callers():
	write("")
	write("=" * 70)
	write("PASS HELPER CALLERS")
	write("=" * 70)
	for item in PASS_HELPERS:
		find_refs_to(item[0], item[1])
		decompile_ref_callers(item[0], item[1], 12)

def decompile_ref_callers(target_addr, label, limit):
	refs = ref_mgr.getReferencesTo(toAddr(target_addr))
	seen = {}
	count = 0
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		if entry in seen:
			continue
		seen[entry] = True
		decompile_at(entry, "caller of %s" % label, 10000)
		count += 1
		if count >= limit:
			write("  [caller decompile limit reached]")
			break

def disasm_known_call_windows():
	write("")
	write("=" * 70)
	write("KNOWN LAND HELPER WINDOWS")
	write("=" * 70)
	disasm_window(0x00B66640, 16, 80, "terrain texture-array flag initializer")
	disasm_window(0x00B68660, 16, 100, "six texture-array writer")
	disasm_window(0x00BDAC00, 16, 140, "zero-resource land/specular helper")
	disasm_window(0x00BDF3E0, 16, 180, "LandO/light-resource helper")
	disasm_window(0x00BDF790, 24, 220, "PPLighting selector/pass-entry driver")
	disasm_window(0x00BD4BA0, 16, 90, "current pass shader-interface apply")
	disasm_window(0x00BE1F90, 16, 90, "BSShader::SetShaders")

def main():
	write("FNV PBR CLOSE TERRAIN PASS IDENTITY FOLLOWUP")
	write("")
	write("Goal:")
	write("- Find a positive identity key for true close landscape base/alpha draws.")
	write("- Prove exclusions for LandLOD, LandO, projected-shadow, point-light, SI, landlo-fog, helper, and interior-looking rows.")
	write("- Do not use selector +0xA8 == 9 or shader pair alone as sufficient proof.")
	dump_shader_slots()
	print_references()
	decompile_key_functions()
	decompile_pass_helper_callers()
	disasm_known_call_windows()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_pass_identity_followup.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
