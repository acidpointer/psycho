# @category Analysis
# @description Audit FNV NVR/VPT PBR terrain contract gaps

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

OUTPUT_PATH = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_vpt_nvr_contract_gap_audit.txt"
# Ghidra DecompInterface uses 0 for no timeout.
DECOMPILE_TIMEOUT_SECONDS = 0

PPLIGHTING_VERTEX_GROUP_C_ADDR = 0x011FDE5C
PPLIGHTING_PIXEL_GROUP_B_ADDR = 0x011FDB08

CLOSE_SHADER_SLOTS = [
	("landlod_base", PPLIGHTING_VERTEX_GROUP_C_ADDR, 2, PPLIGHTING_PIXEL_GROUP_B_ADDR, 3),
	("landlod_projected_shadow", PPLIGHTING_VERTEX_GROUP_C_ADDR, 5, PPLIGHTING_PIXEL_GROUP_B_ADDR, 6),
	("close_land_projected_shadow", PPLIGHTING_VERTEX_GROUP_C_ADDR, 53, PPLIGHTING_PIXEL_GROUP_B_ADDR, 60),
	("close_land_alpha_projected_shadow", PPLIGHTING_VERTEX_GROUP_C_ADDR, 54, PPLIGHTING_PIXEL_GROUP_B_ADDR, 61),
	("close_land_base", PPLIGHTING_VERTEX_GROUP_C_ADDR, 78, PPLIGHTING_PIXEL_GROUP_B_ADDR, 80),
	("close_land_alpha", PPLIGHTING_VERTEX_GROUP_C_ADDR, 79, PPLIGHTING_PIXEL_GROUP_B_ADDR, 81),
	("close_land_landlo_fog", PPLIGHTING_VERTEX_GROUP_C_ADDR, 80, PPLIGHTING_PIXEL_GROUP_B_ADDR, 82),
	("close_land_si_dispatch_branch", PPLIGHTING_VERTEX_GROUP_C_ADDR, 81, PPLIGHTING_PIXEL_GROUP_B_ADDR, 83),
	("close_land_alpha_si", PPLIGHTING_VERTEX_GROUP_C_ADDR, 81, PPLIGHTING_PIXEL_GROUP_B_ADDR, 84),
	("close_land_point", PPLIGHTING_VERTEX_GROUP_C_ADDR, 82, PPLIGHTING_PIXEL_GROUP_B_ADDR, 85),
	("close_land_alpha_point", PPLIGHTING_VERTEX_GROUP_C_ADDR, 83, PPLIGHTING_PIXEL_GROUP_B_ADDR, 86),
]

KEY_FUNCTIONS = [
	(0x00BFC860, "close-land shader table dispatcher"),
	(0x00BDF3E0, "vanilla landscape/LandO pass helper"),
	(0x00B795B0, "ShadowLightShader::UpdateToggles"),
	(0x00B78A90, "ShadowLightShader::UpdateLights"),
	(0x00B7E430, "ShadowLightShader::InitShaderConstants"),
	(0x00BA9EE0, "render pass array AddPass helper"),
	(0x00BA8C50, "render pass SetLights helper"),
	(0x00B66640, "landscape specular exponent writer"),
	(0x00B68660, "selector material-array writer"),
	(0x00BDAF10, "diffuse/glow material row helper"),
	(0x00BDAC00, "zero-resource land/specular row helper"),
	(0x00BDB4A0, "selector setup variant"),
	(0x00BDF790, "selector/pass-entry driver"),
	(0x00BE1F90, "BSShader::SetShaders"),
]

REF_TARGETS = [
	(0x00BFC860, "close-land shader table dispatcher"),
	(0x00BDF3E0, "vanilla landscape/LandO pass helper"),
	(0x00B795B0, "ShadowLightShader::UpdateToggles"),
	(0x00B78A90, "ShadowLightShader::UpdateLights"),
	(0x00B7E430, "ShadowLightShader::InitShaderConstants"),
	(0x00BA9EE0, "render pass array AddPass helper"),
	(0x00BA8C50, "render pass SetLights helper"),
	(0x00B66640, "landscape specular exponent writer"),
	(0x00B68660, "selector material-array writer"),
	(0x00BDAF10, "diffuse/glow material row helper"),
	(0x00BDAC00, "zero-resource land/specular row helper"),
	(0x00BDB4A0, "selector setup variant"),
	(0x00BDF790, "selector/pass-entry driver"),
	(0x0126F74C, "current pass global"),
	(0x011F91E0, "current draw global"),
]

def write(msg):
	output.append(msg)
	print(msg)

def get_function(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	return func

def body_contains(func, addr):
	try:
		return func.getBody().contains(addr)
	except:
		return False

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

def decompile_at(addr_int, label):
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
		print_instruction_window(addr_int, "%s raw fallback" % label, 0, 80)
		return
	faddr = func.getEntryPoint().getOffset()
	func_size = func.getBody().getNumAddresses()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, func_size))
	if faddr != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	try:
		result = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor)
		if result and result.decompileCompleted():
			code = result.getDecompiledFunction().getC()
			write(code)
		else:
			write("  [decompilation failed]")
			if result:
				write("  Message: %s" % result.getErrorMessage())
	except Exception as err:
		write("  [decompilation exception: %s]" % err)

def find_refs_to(addr_int, label):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	try:
		refs = ref_mgr.getReferencesTo(toAddr(addr_int))
		count = 0
		while refs.hasNext():
			ref = refs.next()
			from_func = fm.getFunctionContaining(ref.getFromAddress())
			fname = from_func.getName() if from_func else "???"
			write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
			count += 1
		write("  Total: %d refs" % count)
	except Exception as err:
		write("  [reference scan exception: %s]" % err)

def find_and_print_calls_from(addr_int, label):
	func = get_function(addr_int)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	if func is None:
		write("  [function not found; raw fallback printed in decompile section]")
		return
	try:
		body = func.getBody()
		inst_iter = listing.getInstructions(body, True)
		count = 0
		while inst_iter.hasNext():
			inst = inst_iter.next()
			refs = inst.getReferencesFrom()
			for ref in refs:
				if ref.getReferenceType().isCall():
					tgt = ref.getToAddress().getOffset()
					tgt_func = fm.getFunctionAt(toAddr(tgt))
					name = tgt_func.getName() if tgt_func else "???"
					write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
					count += 1
		write("  Total: %d calls" % count)
	except Exception as err:
		write("  [call scan exception: %s]" % err)

def print_instruction_window(addr_int, label, before_count, after_count):
	write("")
	write("DISASM WINDOW: %s around 0x%08x" % (label, addr_int))
	write("-" * 70)
	try:
		inst = listing.getInstructionAt(toAddr(addr_int))
		if inst is None:
			write("  [instruction not found]")
			return
		func = get_function(addr_int)
		items = []
		current = inst
		count = 0
		while count < before_count:
			prev_inst = current.getPrevious()
			if prev_inst is None:
				break
			if func is not None and not body_contains(func, prev_inst.getAddress()):
				break
			items.insert(0, prev_inst)
			current = prev_inst
			count += 1
		items.append(inst)
		current = inst
		count = 0
		while count < after_count:
			next_inst = current.getNext()
			if next_inst is None:
				break
			if func is not None and not body_contains(func, next_inst.getAddress()):
				break
			items.append(next_inst)
			current = next_inst
			count += 1
		for item in items:
			prefix = "=> " if item.getAddress().getOffset() == addr_int else "   "
			write("%s0x%08x: %s" % (prefix, item.getAddress().getOffset(), item.toString()))
			refs = item.getReferencesFrom()
			for ref in refs:
				tgt = ref.getToAddress().getOffset()
				write("      ref %-18s -> 0x%08x %s" % (ref.getReferenceType(), tgt, label_for_addr(tgt)))
	except Exception as err:
		write("  [instruction window exception: %s]" % err)

def print_refs_with_windows(addr_int, label):
	write("")
	write("=" * 70)
	write("Reference windows for 0x%08x (%s)" % (addr_int, label))
	write("=" * 70)
	try:
		refs = ref_mgr.getReferencesTo(toAddr(addr_int))
		count = 0
		while refs.hasNext():
			ref = refs.next()
			from_addr = ref.getFromAddress().getOffset()
			print_instruction_window(from_addr, "%s ref %d" % (label, count + 1), 10, 16)
			count += 1
		write("  Total windows printed: %d" % count)
	except Exception as err:
		write("  [reference window exception: %s]" % err)

def build_immediate_values():
	values = []
	for value in range(503, 561):
		values.append((value, "VPT landscape/fade pass range"))
	for value in [254, 32, 34, 36, 37, 38, 39, 63, 88, 89, 90]:
		values.append((value, "terrain/LandLOD constant or pass value"))
	for value in range(0x14A, 0x153):
		values.append((value, "zero-resource land/spec row range"))
	for value in [0x93, 0x94, 0x1F2, 0x1F3, 0x1F4, 0x1F5, 0x1F7, 0x230]:
		values.append((value, "PPLighting material/LandO/helper row value"))
	return values

def scalar_values_for_instruction(inst):
	values = []
	index = 0
	while index < inst.getNumOperands():
		try:
			scalar = inst.getScalar(index)
			if scalar is not None:
				values.append(scalar.getUnsignedValue() & 0xffffffff)
		except:
			pass
		index += 1
	return values

def print_immediate_hits(addr_int, label, values):
	func = get_function(addr_int)
	write("")
	write("=" * 70)
	write("Immediate hits in %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	value_map = {}
	for item in values:
		value_map[item[0]] = item[1]
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		scalars = scalar_values_for_instruction(inst)
		hits = []
		for scalar in scalars:
			if scalar in value_map:
				hits.append((scalar, value_map[scalar]))
		if len(hits) > 0:
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
			for hit in hits:
				write("      hit 0x%x / %d: %s" % (hit[0], hit[0], hit[1]))
			count += 1
	write("  Total hit instructions: %d" % count)

def print_shader_slot_summary():
	write("")
	write("=" * 70)
	write("Close terrain/LandLOD shader slot targets")
	write("=" * 70)
	for item in CLOSE_SHADER_SLOTS:
		name = item[0]
		vs_slot = item[1] + item[2] * 4
		ps_slot = item[3] + item[4] * 4
		write("  %-34s VS[%03d] slot=0x%08x PS[%03d] slot=0x%08x" % (name, item[2], vs_slot, item[4], ps_slot))

def print_slot_ref_windows():
	for item in CLOSE_SHADER_SLOTS:
		name = item[0]
		vs_slot = item[1] + item[2] * 4
		ps_slot = item[3] + item[4] * 4
		print_refs_with_windows(vs_slot, "%s vertex slot" % name)
		print_refs_with_windows(ps_slot, "%s pixel slot" % name)

def print_ref_summaries():
	for item in REF_TARGETS:
		find_refs_to(item[0], item[1])

def print_function_summaries():
	for item in KEY_FUNCTIONS:
		write("")
		write(">>> decompile/calls: %s" % item[1])
		decompile_at(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])

def print_immediate_summaries():
	values = build_immediate_values()
	for item in KEY_FUNCTIONS:
		write("")
		write(">>> immediates: %s" % item[1])
		print_immediate_hits(item[0], item[1], values)

def write_output_file():
	fout = open(OUTPUT_PATH, "w")
	fout.write("\n".join(output))
	fout.close()

def main():
	write("FNV PBR VPT/NVR CONTRACT GAP AUDIT")
	write("")
	write("Goal:")
	write("- Map vanilla close-land shader table slots to branch context.")
	write("- Check where VPT-style pass IDs, terrain constants, and row IDs appear in vanilla functions.")
	write("- Identify remaining static gaps before runtime instrumentation.")
	print_shader_slot_summary()
	print_slot_ref_windows()
	print_ref_summaries()
	print_function_summaries()
	print_immediate_summaries()
	write("")
	write("Checklist:")
	write("- If VPT pass values 503..560 are absent from vanilla, Psycho must not assume vanilla creates VPT terrain passes.")
	write("- If c89/c90 do not appear in vanilla terrain paths, Psycho or a dependency must upload NVR terrain controls.")
	write("- If close-land slot branch windows do not expose a positive pass-entry key, use runtime pass-entry logs before patching.")

main()
write_output_file()
write("Output written to %s (%d lines)" % (OUTPUT_PATH, len(output)))
decomp.dispose()
