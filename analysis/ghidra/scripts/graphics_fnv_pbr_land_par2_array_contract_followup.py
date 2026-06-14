# @category Analysis
# @description Follow up PBR close terrain and PAR2 shader array contract from descriptor writes to runtime arrays

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

CREATE_VERTEX_SHADER_ADDR = 0x00BE0FE0
CREATE_PIXEL_SHADER_ADDR = 0x00BE1750
PPLIGHTING_VERTEX_CONSTRUCTOR_ADDR = 0x00B71BF0
PPLIGHTING_PIXEL_CONSTRUCTOR_ADDR = 0x00B74210
PPLIGHTING_PIXEL_GROUP_B_BASE_LEA_ADDR = 0x00B78804
PPLIGHTING_VERTEX_GROUP_C_BASE_LEA_ADDR = 0x00B74117
PAR2_VERTEX_CREATE_ADDR = 0x00BCCD67
PAR2_PIXEL_CREATE_A_ADDR = 0x00BCE386
PAR2_PIXEL_CREATE_B_ADDR = 0x00BCE456
PARALLAX_REGISTRATION_ADDR = 0x00FBACC0

PPLIGHTING_VERTEX_GROUP_C_GLOBAL = 0x011FDE5C
PPLIGHTING_PIXEL_GROUP_B_GLOBAL = 0x011FDB08
PPLIGHTING_VERTEX_GROUP_C_COUNT = 0x67
PPLIGHTING_PIXEL_GROUP_B_COUNT = 0xA0
PPLIGHTING_DESCRIPTOR_STRIDE = 0x4C

TARGET_STRINGS = [
	(0x010AEBD4, "lighting\\2x\\v\\landlod.v.hlsl"),
	(0x010AF0F4, "lighting\\2x\\p\\landlod.p.hlsl"),
	(0x010AEAB8, "lighting\\2x\\v\\land.v.hlsl"),
	(0x010AF030, "lighting\\2x\\p\\land.p.hlsl"),
	(0x010AEC2C, "lighting\\1x\\v\\land.v.hlsl"),
	(0x010AF13C, "lighting\\1x\\p\\land.p.hlsl"),
]

WATCH_GLOBALS = [
	(0x011F91C0, "shader model / 2x gate"),
	(0x011F91B0, "pixel shader model suffix"),
	(0x011FED88, "ParallaxShader RTTI/vtable anchor"),
	(0x012022B4, "ParallaxShader registration/global object candidate"),
	(0x012022C0, "ParallaxShader registration secondary global candidate"),
	(0x010BB774, "PAR2%03i.vso format"),
	(0x010BB91C, "PAR2%03i.pso format"),
	(0x010BB94C, "ParallaxShader string"),
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
	if len(chars) < 2:
		return None
	return "".join(chars)

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
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
		if count > 80:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	write("")
	write("-" * 70)
	write("Calls FROM 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found]")
		return
	inst = listing.getInstructionAt(func.getEntryPoint())
	count = 0
	while inst is not None and func.getBody().contains(inst.getAddress()):
		flows = inst.getFlows()
		if flows is not None and len(flows) > 0 and inst.getFlowType().isCall():
			for dest in flows:
				write("  0x%08x -> 0x%08x" % (inst.getAddress().getOffset(), dest.getOffset()))
				count += 1
		inst = listing.getInstructionAfter(inst.getAddress())
	write("  Total calls: %d" % count)

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
		text = read_c_string(target.getOffset(), 120)
		if text is None:
			text = ""
		write("      ref %-18s -> 0x%08x %s" % (str(ref.getReferenceType()), target.getOffset(), text))

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

def parse_esp_disp(text):
	marker = "[ESP"
	pos = text.find(marker)
	if pos < 0:
		return None
	end = text.find("]", pos)
	if end < 0:
		return None
	inside = text[pos + len(marker):end].strip()
	if inside == "":
		return 0
	if inside[0] == "+":
		return int(inside[1:].strip(), 16)
	if inside[0] == "-":
		return -int(inside[1:].strip(), 16)
	return None

def parse_immediate_at_end(text):
	comma = text.rfind(",")
	if comma < 0:
		return None
	value = text[comma + 1:].strip()
	if value.startswith("0x"):
		try:
			return int(value, 16)
		except:
			return None
	return None

def parse_mov_reg_imm(text):
	if not text.startswith("MOV "):
		return None
	body = text[4:]
	comma = body.find(",")
	if comma < 0:
		return None
	reg = body[:comma].strip()
	value = body[comma + 1:].strip()
	if reg not in ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP"]:
		return None
	if not value.startswith("0x"):
		return None
	try:
		return (reg, int(value, 16))
	except:
		return None

def parse_lea_reg_esp(text):
	if not text.startswith("LEA "):
		return None
	body = text[4:]
	comma = body.find(",")
	if comma < 0:
		return None
	reg = body[:comma].strip()
	if reg not in ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP"]:
		return None
	disp = parse_esp_disp(text)
	if disp is None:
		return None
	return (reg, disp)

def target_label(value):
	index = 0
	while index < len(TARGET_STRINGS):
		item = TARGET_STRINGS[index]
		if item[0] == value:
			return item[1]
		index += 1
	return None

def update_esp_delta(text, delta):
	if text.startswith("PUSH "):
		return delta - 4
	if text.startswith("POP "):
		return delta + 4
	if text.startswith("SUB ESP,"):
		value = text[text.find(",") + 1:].strip()
		try:
			return delta - int(value, 16)
		except:
			return delta
	if text.startswith("ADD ESP,"):
		value = text[text.find(",") + 1:].strip()
		try:
			return delta + int(value, 16)
		except:
			return delta
	return delta

def normalized_descriptor_indices(entry_addr, end_addr, base_lea_addr, group_label, group_count):
	write("")
	write("=" * 70)
	write("Stack-normalized descriptor writes for %s" % group_label)
	write("=" * 70)
	inst = listing.getInstructionAt(toAddr(entry_addr))
	delta = 0
	reg_values = {}
	base_norm = None
	records = []
	while inst is not None and inst.getAddress().getOffset() <= end_addr:
		addr = inst.getAddress().getOffset()
		text = inst.toString()
		if addr == base_lea_addr:
			lea = parse_lea_reg_esp(text)
			if lea is not None:
				base_norm = delta + lea[1]
				write("  Base LEA @ 0x%08x: %s, esp_delta=%d, normalized_base=0x%X" % (addr, text, delta, base_norm))
		mov = parse_mov_reg_imm(text)
		if mov is not None:
			reg_values[mov[0]] = mov[1]
		elif text.startswith("MOV ") and text.find("dword ptr [ESP") >= 0:
			disp = parse_esp_disp(text)
			value = parse_immediate_at_end(text)
			if value is None:
				comma = text.rfind(",")
				if comma >= 0:
					reg = text[comma + 1:].strip()
					if reg in reg_values:
						value = reg_values[reg]
			label = target_label(value) if value is not None else None
			if label is not None and disp is not None:
				norm = delta + disp
				records.append((addr, text, norm, value, label))
		delta = update_esp_delta(text, delta)
		inst = listing.getInstructionAfter(inst.getAddress())
	if base_norm is None:
		write("  [base LEA not found]")
		return
	index = 0
	while index < len(records):
		record = records[index]
		rel = record[2] - base_norm
		shader_index = rel // PPLIGHTING_DESCRIPTOR_STRIDE
		field = rel % PPLIGHTING_DESCRIPTOR_STRIDE
		status = "OUTSIDE"
		if shader_index >= 0 and shader_index < group_count:
			status = "IN_RANGE"
		write("  %s source=0x%08x %-32s write=0x%08x norm=0x%X rel=0x%X index=%d field=0x%X :: %s" % (status, record[3], record[4], record[0], record[2], rel, shader_index, field, record[1]))
		index += 1
	write("  Records: %d" % len(records))

def print_par2_summary():
	write("")
	write("=" * 70)
	write("PAR2 array contract notes to verify in output")
	write("=" * 70)
	write("  Vertex create window should show this+0x8C as PAR2 VS array base and loop count gate from 0x011F91C0.")
	write("  Pixel create first window should show this+0xDC as PAR2 PS primary array base, usually indices 0..0x1C.")
	write("  Pixel create second window should show this+0x150 as PAR2 PS extended array base, starting at index 0x1D when shader-model gate allows it.")
	write("  Follow-up implementation must classify live shader pointers from these proven arrays, not from PPLighting group C/B.")

def print_watch_refs():
	index = 0
	while index < len(WATCH_GLOBALS):
		item = WATCH_GLOBALS[index]
		find_refs_to(item[0], item[1])
		index += 1

def main():
	write("FNV PBR CLOSE TERRAIN / PAR2 ARRAY CONTRACT FOLLOWUP")
	write("")
	write("Goal: turn the source-string audit into runtime array indices and PAR2 ownership before replacement.")
	decompile_at(CREATE_VERTEX_SHADER_ADDR, "BSShader::CreateVertexShader", 4500)
	decompile_at(CREATE_PIXEL_SHADER_ADDR, "BSShader::CreatePixelShader", 4500)
	normalized_descriptor_indices(PPLIGHTING_VERTEX_CONSTRUCTOR_ADDR, 0x00B74210, PPLIGHTING_VERTEX_GROUP_C_BASE_LEA_ADDR, "PPLighting vertex group C", PPLIGHTING_VERTEX_GROUP_C_COUNT)
	normalized_descriptor_indices(PPLIGHTING_PIXEL_CONSTRUCTOR_ADDR, 0x00B78A00, PPLIGHTING_PIXEL_GROUP_B_BASE_LEA_ADDR, "PPLighting pixel group B", PPLIGHTING_PIXEL_GROUP_B_COUNT)
	disasm_window(PPLIGHTING_PIXEL_CONSTRUCTOR_ADDR, 0, 64, "PPLighting pixel constructor start")
	disasm_window(PPLIGHTING_VERTEX_GROUP_C_BASE_LEA_ADDR, 42, 72, "PPLighting vertex group C compile loop")
	disasm_window(PPLIGHTING_PIXEL_GROUP_B_BASE_LEA_ADDR, 42, 100, "PPLighting pixel group B compile loop")
	disasm_window(PAR2_VERTEX_CREATE_ADDR, 40, 100, "PAR2 vertex create and array write")
	disasm_window(PAR2_PIXEL_CREATE_A_ADDR, 46, 110, "PAR2 pixel primary create and array write")
	disasm_window(PAR2_PIXEL_CREATE_B_ADDR, 46, 110, "PAR2 pixel extended create and array write")
	disasm_window(PARALLAX_REGISTRATION_ADDR, 16, 40, "ParallaxShader registration")
	print_par2_summary()
	print_watch_refs()
	find_and_print_calls_from(PPLIGHTING_VERTEX_CONSTRUCTOR_ADDR, "PPLighting shader constructor")

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_land_par2_array_contract_followup.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
