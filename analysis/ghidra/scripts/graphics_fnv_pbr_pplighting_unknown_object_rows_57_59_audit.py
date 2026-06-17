# @category Analysis
# @description Dump PPLighting SLS2 object-adjacent rows 57/59 for native PBR contract research

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

PPLIGHTING_VERTEX_CONSTRUCTOR_ADDR = 0x00B71BF0
PPLIGHTING_PIXEL_CONSTRUCTOR_ADDR = 0x00B74210
PPLIGHTING_VERTEX_GROUP_C_BASE_LEA_ADDR = 0x00B74117
PPLIGHTING_PIXEL_GROUP_B_BASE_LEA_ADDR = 0x00B78804
PPLIGHTING_VERTEX_GROUP_C_COUNT = 0x67
PPLIGHTING_PIXEL_GROUP_B_COUNT = 0xA0
PPLIGHTING_DESCRIPTOR_STRIDE = 0x4C

TARGET_VERTEX_INDICES = [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59]
TARGET_PIXEL_INDICES = [47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59]

WATCH_STRINGS = [
	(0x010AE9B8, "lighting\\2x\\v\\base.v.hlsl candidate"),
	(0x010AEA34, "lighting\\2x\\p\\base.p.hlsl candidate"),
	(0x010AEB8C, "SPECULAR"),
	(0x010AEB98, "LIGHTS"),
	(0x010AEBA0, "PROJ_SHADOW"),
	(0x010AEB0C, "POINT"),
	(0x010AEAF0, "NUM_PT_LIGHTS candidate"),
	(0x010AEB24, "ONLY_SPECULAR candidate"),
	(0x010AEB70, "HAIR candidate"),
	(0x01011584, "empty string/common null define"),
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
	if len(chars) < 1:
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
		if count > 120:
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

def parse_hex_value(text):
	value = text.strip()
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
	imm = parse_hex_value(value)
	if imm is None:
		return None
	return (reg, imm)

def parse_mov_reg_reg(text):
	if not text.startswith("MOV "):
		return None
	body = text[4:]
	comma = body.find(",")
	if comma < 0:
		return None
	dst = body[:comma].strip()
	src = body[comma + 1:].strip()
	regs = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP"]
	if dst in regs and src in regs:
		return (dst, src)
	return None

def parse_xor_reg_reg(text):
	if not text.startswith("XOR "):
		return None
	body = text[4:]
	comma = body.find(",")
	if comma < 0:
		return None
	dst = body[:comma].strip()
	src = body[comma + 1:].strip()
	if dst == src and dst in ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP"]:
		return dst
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

def parse_stack_write(text):
	if not text.startswith("MOV "):
		return None
	if text.find("dword ptr [ESP") < 0:
		return None
	disp = parse_esp_disp(text)
	if disp is None:
		return None
	comma = text.rfind(",")
	if comma < 0:
		return None
	src = text[comma + 1:].strip()
	return (disp, src)

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

def update_register_tracking(text, delta, reg_values):
	lea = parse_lea_reg_esp(text)
	if lea is not None:
		reg_values[lea[0]] = ("stack_norm", delta + lea[1])
		return
	xor_reg = parse_xor_reg_reg(text)
	if xor_reg is not None:
		reg_values[xor_reg] = 0
		return
	mov_rr = parse_mov_reg_reg(text)
	if mov_rr is not None:
		if mov_rr[1] in reg_values:
			reg_values[mov_rr[0]] = reg_values[mov_rr[1]]
		elif mov_rr[0] in reg_values:
			del reg_values[mov_rr[0]]
		return
	mov = parse_mov_reg_imm(text)
	if mov is not None:
		reg_values[mov[0]] = mov[1]
		return
	if text.startswith("MOV "):
		body = text[4:]
		comma = body.find(",")
		if comma >= 0:
			dst = body[:comma].strip()
			if dst in reg_values:
				del reg_values[dst]

def value_from_src(src, reg_values):
	imm = parse_hex_value(src)
	if imm is not None:
		return imm
	if src in reg_values:
		return reg_values[src]
	return None

def format_value(value):
	if value is None:
		return "unknown"
	if isinstance(value, tuple):
		return "%s=0x%X" % (value[0], value[1])
	if value == 0:
		return "0"
	text = read_c_string(value, 160)
	if text is not None:
		return "0x%08x \"%s\"" % (value, text)
	return "0x%08x" % value

def target_contains(target_indices, shader_index):
	index = 0
	while index < len(target_indices):
		if target_indices[index] == shader_index:
			return True
		index += 1
	return False

def scan_descriptor_writes(entry_addr, end_addr, base_lea_addr, group_label, group_count, target_indices):
	write("")
	write("=" * 70)
	write("Descriptor field dump for %s" % group_label)
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
		stack_write = parse_stack_write(text)
		if stack_write is not None:
			value = value_from_src(stack_write[1], reg_values)
			norm = delta + stack_write[0]
			records.append((addr, text, norm, stack_write[1], value))
		update_register_tracking(text, delta, reg_values)
		delta = update_esp_delta(text, delta)
		inst = listing.getInstructionAfter(inst.getAddress())
	if base_norm is None:
		write("  [base LEA not found]")
		return
	print_descriptor_records(records, base_norm, group_count, target_indices)

def print_descriptor_records(records, base_norm, group_count, target_indices):
	last_index = -1
	index = 0
	found = 0
	while index < len(records):
		record = records[index]
		rel = record[2] - base_norm
		if rel >= 0:
			shader_index = rel // PPLIGHTING_DESCRIPTOR_STRIDE
			field = rel % PPLIGHTING_DESCRIPTOR_STRIDE
			if shader_index >= 0 and shader_index < group_count and target_contains(target_indices, shader_index):
				if shader_index != last_index:
					write("")
					write("  Index %d" % shader_index)
					last_index = shader_index
				write("    field=0x%02X write=0x%08x rhs=%-10s value=%-40s :: %s" % (field, record[0], record[3], format_value(record[4]), record[1]))
				found += 1
		index += 1
	write("")
	write("  Target descriptor writes: %d" % found)

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

def print_target_refs():
	index = 0
	while index < len(WATCH_STRINGS):
		item = WATCH_STRINGS[index]
		find_refs_to(item[0], item[1])
		index += 1

def print_constructor_windows():
	windows = [
		(0x00B73B00, "vertex group C rows after NVR object table"),
		(0x00B76300, "pixel group B rows after NVR object table"),
		(0x00B76480, "pixel group B unknown 57/59 neighborhood"),
	]
	index = 0
	while index < len(windows):
		item = windows[index]
		disasm_window(item[0], 24, 42, item[1])
		index += 1

def main():
	write("FNV PBR PPLIGHTING UNKNOWN OBJECT ROWS 57/59 AUDIT")
	write("")
	write("Goal: identify runtime pidx=57/59 and vidx=50/51/52 rows before mapping them into OMV PBR.")
	decompile_at(PPLIGHTING_VERTEX_CONSTRUCTOR_ADDR, "PPLighting vertex constructor", 4500)
	decompile_at(PPLIGHTING_PIXEL_CONSTRUCTOR_ADDR, "PPLighting pixel constructor", 4500)
	scan_descriptor_writes(PPLIGHTING_VERTEX_CONSTRUCTOR_ADDR, 0x00B74210, PPLIGHTING_VERTEX_GROUP_C_BASE_LEA_ADDR, "PPLighting vertex group C rows 48..59", PPLIGHTING_VERTEX_GROUP_C_COUNT, TARGET_VERTEX_INDICES)
	scan_descriptor_writes(PPLIGHTING_PIXEL_CONSTRUCTOR_ADDR, 0x00B78A00, PPLIGHTING_PIXEL_GROUP_B_BASE_LEA_ADDR, "PPLighting pixel group B rows 47..59", PPLIGHTING_PIXEL_GROUP_B_COUNT, TARGET_PIXEL_INDICES)
	print_constructor_windows()
	print_target_refs()
	find_and_print_calls_from(PPLIGHTING_VERTEX_CONSTRUCTOR_ADDR, "PPLighting vertex constructor")
	find_and_print_calls_from(PPLIGHTING_PIXEL_CONSTRUCTOR_ADDR, "PPLighting pixel constructor")

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_unknown_object_rows_57_59_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
