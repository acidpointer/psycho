# @category Analysis
# @description Close FNV PBR close-terrain vertex and pixel ABI contract

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00B71BF0: "PPLighting shader constructor",
	0x00B74210: "PPLighting pixel descriptor constructor",
	0x00B7DAB0: "PPLighting pass-entry shader resource dispatcher",
	0x00BD4BA0: "current pass shader-interface apply",
	0x00BE0C00: "shader source path helper",
	0x00BE0FE0: "BSShader::CreateVertexShader",
	0x00BE08F0: "NiD3DPixelShader object constructor/initializer",
	0x00BE0B30: "NiD3DVertexShader object constructor/initializer",
	0x00BE1F90: "BSShader::SetShaders",
	0x010AEAB8: "lighting\\2x\\v\\land.v.hlsl",
	0x010AEBD4: "lighting\\2x\\v\\landlod.v.hlsl",
	0x010AF030: "lighting\\2x\\p\\land.p.hlsl",
	0x010AF0F4: "lighting\\2x\\p\\landlod.p.hlsl",
	0x011FDB08: "PPLighting pixel group B",
	0x011FDE5C: "PPLighting vertex group C",
	0x011F91E0: "current geometry slot global",
	0x0126F74C: "current pass global",
}

VERTEX_GROUP_C = 0x011FDE5C
PIXEL_GROUP_B = 0x011FDB08

SHADER_PAIRS = [
	("landlod", 2, 3),
	("landlod_projected_shadow", 5, 6),
	("close_projected_shadow", 53, 60),
	("close_alpha_projected_shadow", 54, 61),
	("close_base", 78, 80),
	("close_alpha", 79, 81),
	("close_landlo_fog", 80, 82),
	("close_si", 81, 84),
	("close_point", 82, 85),
	("close_alpha_point", 83, 86),
]

FOCUS_FUNCTIONS = [
	(0x00B71BF0, "PPLighting shader constructor", 36000),
	(0x00B74210, "PPLighting pixel descriptor constructor", 28000),
	(0x00B7DAB0, "PPLighting pass-entry shader resource dispatcher", 26000),
	(0x00BD4BA0, "current pass shader-interface apply", 26000),
	(0x00BE0C00, "shader source path helper", 16000),
	(0x00BE0FE0, "BSShader::CreateVertexShader", 22000),
	(0x00BE08F0, "NiD3DPixelShader object constructor/initializer", 22000),
	(0x00BE0B30, "NiD3DVertexShader object constructor/initializer", 22000),
	(0x00BE1F90, "BSShader::SetShaders", 22000),
]

REF_TARGETS = [
	(0x010AEAB8, "close terrain vanilla vertex source lighting\\2x\\v\\land.v.hlsl"),
	(0x010AEBD4, "terrain LOD vanilla vertex source lighting\\2x\\v\\landlod.v.hlsl"),
	(0x010AF030, "close terrain vanilla pixel source lighting\\2x\\p\\land.p.hlsl"),
	(0x010AF0F4, "terrain LOD vanilla pixel source lighting\\2x\\p\\landlod.p.hlsl"),
	(0x011FDE5C, "PPLighting vertex group C"),
	(0x011FDB08, "PPLighting pixel group B"),
	(0x00BE0FE0, "BSShader::CreateVertexShader"),
	(0x00BE08F0, "NiD3DPixelShader object constructor/initializer"),
	(0x00BE0B30, "NiD3DVertexShader object constructor/initializer"),
	(0x00BD4BA0, "current pass shader-interface apply"),
	(0x00B7DAB0, "PPLighting pass-entry shader resource dispatcher"),
]

DISASM_WINDOWS = [
	(0x00B74117, 32, 120, "PPLighting vertex group C construction loop"),
	(0x00B78804, 32, 140, "PPLighting pixel group B construction loop"),
	(0x00BD4BA0, 20, 110, "runtime shader-interface apply geometry args"),
	(0x00B7DAB0, 20, 180, "runtime pass-entry dispatcher"),
	(0x00BE0FE0, 20, 130, "BSShader::CreateVertexShader"),
	(0x00BE08F0, 20, 130, "NiD3DPixelShader initializer"),
	(0x00BE0B30, 20, 130, "NiD3DVertexShader initializer"),
]

SCAN_PATTERNS = [
	"lighting",
	"land.v.hlsl",
	"land.p.hlsl",
	"landlod",
	"vs_2_0",
	"ps_2_0",
	"FUN_00be0fe0",
	"FUN_00be08f0",
	"FUN_00be0b30",
	"FUN_00bd4ba0",
	"FUN_00b7dab0",
	"011fde5c",
	"011fdb08",
	"011f91e0",
	"0126f74c",
	"+ 0x68",
	"+0x68",
	"+ 0x78",
	"+0x78",
	"+ 0x44",
	"+0x44",
	"+ 0x5c",
	"+0x5c",
	"CreateVertexShader",
	"CreatePixelShader",
	"SetVertexShader",
	"SetPixelShader",
	"shader",
	"vertex",
	"pixel",
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

def decompile_at(addr_int, label, max_len=16000):
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
		from_addr = ref.getFromAddress()
		from_func = fm.getFunctionContaining(from_addr)
		fname = from_func.getName() if from_func else "???"
		inst = listing.getInstructionContaining(from_addr)
		inst_text = inst.toString() if inst is not None else ""
		write("  %s @ 0x%08x (in %s) %s" % (ref.getReferenceType(), from_addr.getOffset(), fname, inst_text))
		count += 1
		if count >= 160:
			write("  ... (truncated)")
			break
	write("  Total printed: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	func = get_function(addr_int)
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
				target = ref.getToAddress()
				taddr = target.getOffset()
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), taddr, label_for(taddr)))
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
		write("      ref %-18s -> 0x%08x %s" % (str(ref.getReferenceType()), target.getOffset(), label_for(target.getOffset())))

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("=" * 70)
	write("DISASM: %s around 0x%08x" % (label, center_int))
	write("=" * 70)
	inst = listing.getInstructionContaining(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(center_int))
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

def scan_patterns(addr_int, label):
	write("")
	write("=" * 70)
	write("MATCHED DECOMPILE LINES: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	code = decompile_text(addr_int)
	if code is None:
		write("  [decompilation failed]")
		return
	lines = code.splitlines()
	count = 0
	for line in lines:
		lower = line.lower()
		for pattern in SCAN_PATTERNS:
			if pattern.lower() in lower:
				write("  %s" % line)
				count += 1
				break
		if count >= 220:
			write("  ... (truncated)")
			break
	write("  Total matched lines: %d" % count)

def dump_close_terrain_shader_slots():
	write("")
	write("=" * 70)
	write("CLOSE TERRAIN SHADER GROUP SLOTS")
	write("=" * 70)
	for item in SHADER_PAIRS:
		name = item[0]
		vertex_index = item[1]
		pixel_index = item[2]
		vertex_slot = VERTEX_GROUP_C + vertex_index * 4
		pixel_slot = PIXEL_GROUP_B + pixel_index * 4
		vertex_value = read_u32(vertex_slot)
		pixel_value = read_u32(pixel_slot)
		write("%-32s vertex C[%3d] slot 0x%08x -> 0x%08x %-28s pixel B[%3d] slot 0x%08x -> 0x%08x %s" % (
			name,
			vertex_index,
			vertex_slot,
			vertex_value if vertex_value is not None else 0,
			label_for(vertex_value),
			pixel_index,
			pixel_slot,
			pixel_value if pixel_value is not None else 0,
			label_for(pixel_value),
		))

def decompile_focus_functions():
	for item in FOCUS_FUNCTIONS:
		decompile_at(item[0], item[1], item[2])
		find_and_print_calls_from(item[0], item[1])
		scan_patterns(item[0], item[1])

def print_reference_targets():
	for item in REF_TARGETS:
		find_refs_to(item[0], item[1])

def print_disasm_windows():
	for item in DISASM_WINDOWS:
		disasm_window(item[0], item[1], item[2], item[3])

def main():
	write("FNV PBR CLOSE TERRAIN VERTEX/PIXEL ABI CONTRACT")
	write("")
	write("Questions:")
	write("1. Which vanilla shader source descriptors back close terrain group C/B slots?")
	write("2. Which construction sites compile group C vertex and group B pixel shader descriptors?")
	write("3. Does runtime apply pass the geometry +0x68 shader-args block to shader-interface virtual +0x78?")
	write("4. Which shader object constructors and SetShaders fields are involved before visible replacement?")
	write("")
	write("Compare with NVR TerrainTemplate.hlsl vertex ABI:")
	write("  POSITION, TANGENT, BINORMAL, NORMAL, TEXCOORD0 uv, COLOR0 vertex_color, TEXCOORD1/2 blend channels")
	dump_close_terrain_shader_slots()
	print_reference_targets()
	print_disasm_windows()
	decompile_focus_functions()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_vertex_abi_contract.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
