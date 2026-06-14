# @category Analysis
# @description Close FNV PBR close-terrain pass/material identity contract

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00B7AF80: "PPLighting current pass writer",
	0x00B7DD50: "PPLighting pass texture-record helper A",
	0x00B7DDE0: "PPLighting pass texture-record helper B",
	0x00B7E150: "PPLighting pass texture-record helper C",
	0x00B98E80: "current draw apply dispatcher",
	0x00B99390: "draw selector setup dispatcher",
	0x00B994F0: "current draw dispatcher",
	0x00BA8C50: "pass-entry storage helper",
	0x00BA8EC0: "pass-entry constructor",
	0x00BA9EE0: "pass-entry append/reuse helper",
	0x00BD4BA0: "current pass shader-interface apply",
	0x00BDAC00: "land/specular helper",
	0x00BDAF10: "diffuse/glow material helper",
	0x00BDB4A0: "selector setup +0xF0 variant",
	0x00BDF3E0: "LandO/light-resource helper",
	0x00BDF790: "selector setup +0xF4 main",
	0x00BE1F90: "BSShader::SetShaders",
	0x00E7EA00: "texture record final apply",
	0x00E7EB00: "texture record resolver/apply bridge",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x011F91E0: "current draw global",
	0x011FFE2C: "last selector cache global",
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
	("close_si", 78, 83),
	("close_alpha_si", 81, 84),
	("close_point", 82, 85),
	("close_alpha_point", 83, 86),
]

FOCUS_FUNCTIONS = [
	(0x00B7AF80, "PPLighting current pass writer", 18000),
	(0x00B7DD50, "PPLighting pass texture-record helper A", 18000),
	(0x00B7DDE0, "PPLighting pass texture-record helper B", 18000),
	(0x00B7E150, "PPLighting pass texture-record helper C", 18000),
	(0x00B98E80, "current draw apply dispatcher", 22000),
	(0x00B99390, "draw selector setup dispatcher", 22000),
	(0x00B994F0, "current draw dispatcher", 22000),
	(0x00BA8C50, "pass-entry storage helper", 18000),
	(0x00BA8EC0, "pass-entry constructor", 18000),
	(0x00BA9EE0, "pass-entry append/reuse helper", 22000),
	(0x00BD4BA0, "current pass shader-interface apply", 24000),
	(0x00BDAC00, "land/specular helper", 22000),
	(0x00BDAF10, "diffuse/glow material helper", 24000),
	(0x00BDB4A0, "selector setup +0xF0 variant", 30000),
	(0x00BDF3E0, "LandO/light-resource helper", 22000),
	(0x00BDF790, "selector setup +0xF4 main", 30000),
	(0x00BE1F90, "BSShader::SetShaders", 22000),
	(0x00E7EA00, "texture record final apply", 22000),
	(0x00E7EB00, "texture record resolver/apply bridge", 22000),
]

REF_TARGETS = [
	(0x00BA9EE0, "pass-entry append/reuse helper"),
	(0x00BDAF10, "diffuse/glow material helper"),
	(0x00BDB4A0, "selector setup +0xF0 variant"),
	(0x00BDF790, "selector setup +0xF4 main"),
	(0x00BD4BA0, "current pass shader-interface apply"),
	(0x00BE1F90, "BSShader::SetShaders"),
	(0x011F91E0, "current draw global"),
	(0x011FFE2C, "last selector cache global"),
	(0x0126F74C, "current pass global"),
]

MATCH_PATTERNS = [
	"0xc0",
	"0xa8",
	"0xac",
	"0xb0",
	"0xc4",
	"0xc8",
	"0xcc",
	"0x3c",
	"0x44",
	"0x5c",
	"DAT_011f91e0",
	"DAT_011ffe2c",
	"DAT_0126f74c",
	"FUN_00ba9ee0",
	"FUN_00bdaf10",
	"FUN_00bdac00",
	"FUN_00bdf3e0",
	"FUN_00bdb4a0",
	"FUN_00bdf790",
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
	write("MATCHED LINES: %s" % label)
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

def dump_shader_slots():
	write("")
	write("=" * 70)
	write("PPLIGHTING LANDISH SHADER ARRAY SLOTS")
	write("=" * 70)
	for item in SHADER_PAIRS:
		name = item[0]
		vertex_index = item[1]
		pixel_index = item[2]
		vertex_slot = VERTEX_GROUP_C + vertex_index * 4
		pixel_slot = PIXEL_GROUP_B + pixel_index * 4
		vertex_value = read_u32(vertex_slot)
		pixel_value = read_u32(pixel_slot)
		write("%-32s vertex[%3d] slot 0x%08x -> 0x%08x %-30s pixel[%3d] slot 0x%08x -> 0x%08x %s" % (
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
		find_refs_to(vertex_slot, "%s vertex slot storage" % name, 12)
		find_refs_to(pixel_slot, "%s pixel slot storage" % name, 12)

def decompile_focus_functions():
	for item in FOCUS_FUNCTIONS:
		code = decompile_at(item[0], item[1], item[2])
		matched_lines(code, item[1])

def print_reference_targets():
	for item in REF_TARGETS:
		find_refs_to(item[0], item[1], 120)

def print_ba9ee0_call_windows():
	write("")
	write("=" * 70)
	write("BA9EE0 CALL WINDOWS IN FOCUS FUNCTIONS")
	write("=" * 70)
	for item in FOCUS_FUNCTIONS:
		func = get_function(item[0])
		if func is None:
			continue
		inst_iter = listing.getInstructions(func.getBody(), True)
		while inst_iter.hasNext():
			inst = inst_iter.next()
			refs = inst.getReferencesFrom()
			for ref in refs:
				if ref.getReferenceType().isCall() and ref.getToAddress().getOffset() == 0x00BA9EE0:
					disasm_window(inst.getAddress().getOffset(), 16, 18, "%s -> BA9EE0" % item[1])

def main():
	write("FNV PBR CLOSE TERRAIN PASS/MATERIAL CONTRACT CLOSURE")
	write("")
	write("Goal:")
	write("- Correlate close-terrain shader pair candidates with current draw selector, pass globals, and pass-entry rows.")
	write("- Keep base/alpha terrain blocked unless pass identity plus selector material state are both proven.")
	write("- Prove that later texture-record apply is too lossy or identify the safe side-table key.")
	dump_shader_slots()
	print_reference_targets()
	decompile_focus_functions()
	print_ba9ee0_call_windows()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_pass_material_contract_closure.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
