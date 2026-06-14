# @category Analysis
# @description Close FNV PBR close-terrain D3D vertex declaration ABI contract

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
	0x00B7DAB0: "PPLighting pass-entry shader resource dispatcher",
	0x00B994F0: "current draw dispatcher",
	0x00BD4BA0: "current pass shader-interface apply",
	0x00BE0FE0: "BSShader::CreateVertexShader",
	0x011F91E0: "current geometry slot global",
	0x0126F74C: "current pass global",
}

D3D_DEVICE_METHODS = [
	(0x158, "CreateVertexDeclaration"),
	(0x15C, "SetVertexDeclaration"),
	(0x164, "SetFVF"),
	(0x16C, "CreateVertexShader"),
	(0x170, "SetVertexShader"),
	(0x190, "SetStreamSource"),
	(0x1A0, "SetIndices"),
	(0x144, "DrawPrimitive"),
	(0x148, "DrawIndexedPrimitive"),
]

DECL_TYPES = {
	0: "FLOAT1",
	1: "FLOAT2",
	2: "FLOAT3",
	3: "FLOAT4",
	4: "D3DCOLOR",
	5: "UBYTE4",
	6: "SHORT2",
	7: "SHORT4",
	8: "UBYTE4N",
	9: "SHORT2N",
	10: "SHORT4N",
	11: "USHORT2N",
	12: "USHORT4N",
	13: "UDEC3",
	14: "DEC3N",
	15: "FLOAT16_2",
	16: "FLOAT16_4",
	17: "UNUSED",
}

DECL_USAGES = {
	0: "POSITION",
	1: "BLENDWEIGHT",
	2: "BLENDINDICES",
	3: "NORMAL",
	4: "PSIZE",
	5: "TEXCOORD",
	6: "TANGENT",
	7: "BINORMAL",
	8: "TESSFACTOR",
	9: "POSITIONT",
	10: "COLOR",
	11: "FOG",
	12: "DEPTH",
	13: "SAMPLE",
}

FOCUS_FUNCTIONS = [
	(0x00B71BF0, "PPLighting shader constructor", 32000),
	(0x00B7DAB0, "PPLighting pass-entry shader resource dispatcher", 26000),
	(0x00B994F0, "current draw dispatcher", 24000),
	(0x00BD4BA0, "current pass shader-interface apply", 26000),
	(0x00BE0FE0, "BSShader::CreateVertexShader", 26000),
]

REF_TARGETS = [
	(0x011F91E0, "current geometry slot global"),
	(0x0126F74C, "current pass global"),
	(0x00BD4BA0, "current pass shader-interface apply"),
	(0x00B7DAB0, "PPLighting pass-entry shader resource dispatcher"),
	(0x00BE0FE0, "BSShader::CreateVertexShader"),
]

SCAN_PATTERNS = [
	"CreateVertexDeclaration",
	"SetVertexDeclaration",
	"SetFVF",
	"SetStreamSource",
	"SetIndices",
	"DrawIndexedPrimitive",
	"DrawPrimitive",
	"CreateVertexShader",
	"SetVertexShader",
	"+ 0x158",
	"+0x158",
	"+ 0x15c",
	"+0x15c",
	"+ 0x164",
	"+0x164",
	"+ 0x16c",
	"+0x16c",
	"+ 0x170",
	"+0x170",
	"+ 0x190",
	"+0x190",
	"+ 0x1a0",
	"+0x1a0",
	"+ 0x144",
	"+0x144",
	"+ 0x148",
	"+0x148",
	"+ 0x68",
	"+0x68",
	"+ 0xc0",
	"+0xc0",
	"vertex",
	"declaration",
	"stream",
	"stride",
	"fvf",
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

def read_u16(addr_int):
	lo = read_byte(addr_int)
	hi = read_byte(addr_int + 1)
	if lo is None or hi is None:
		return None
	return lo | (hi << 8)

def read_u32(addr_int):
	b0 = read_byte(addr_int)
	b1 = read_byte(addr_int + 1)
	b2 = read_byte(addr_int + 2)
	b3 = read_byte(addr_int + 3)
	if b0 is None or b1 is None or b2 is None or b3 is None:
		return None
	return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)

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
		if count >= 120:
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
		if count >= 180:
			write("  ... (truncated)")
			break
	write("  Total matched lines: %d" % count)

def method_name_for_offset(offset):
	for item in D3D_DEVICE_METHODS:
		if item[0] == offset:
			return item[1]
	return "device method"

def instruction_mentions_method(inst, offset):
	text = inst.toString().lower().replace(" ", "")
	pattern = "0x%x" % offset
	if pattern in text and "[" in text and "]" in text:
		return True
	return False

def scan_d3d_device_method_offsets():
	write("")
	write("=" * 70)
	write("D3D9 DEVICE VIRTUAL METHOD OFFSET SCAN")
	write("=" * 70)
	write("Offsets: 0x158 CreateVertexDeclaration, 0x15C SetVertexDeclaration, 0x164 SetFVF, 0x190 SetStreamSource")
	seen_funcs = {}
	printed = 0
	func_iter = fm.getFunctions(True)
	while func_iter.hasNext():
		func = func_iter.next()
		inst_iter = listing.getInstructions(func.getBody(), True)
		while inst_iter.hasNext():
			inst = inst_iter.next()
			matched = None
			for item in D3D_DEVICE_METHODS:
				if instruction_mentions_method(inst, item[0]):
					matched = item
					break
			if matched is None:
				continue
			fname = func.getName()
			write("  0x%08x %-24s %-58s %s" % (inst.getAddress().getOffset(), matched[1], inst.toString(), fname))
			if matched[0] in [0x158, 0x15C, 0x164, 0x190]:
				seen_funcs[func.getEntryPoint().getOffset()] = fname
			printed += 1
			if printed >= 180:
				write("  ... (truncated)")
				write("  Total printed: %d candidate method-offset instructions" % printed)
				print_candidate_d3d_functions(seen_funcs)
				return
	write("  Total printed: %d candidate method-offset instructions" % printed)
	print_candidate_d3d_functions(seen_funcs)

def print_candidate_d3d_functions(seen_funcs):
	write("")
	write("Candidate functions touching these offsets:")
	for key in sorted(seen_funcs.keys()):
		write("  0x%08x %s" % (key, seen_funcs[key]))
		if key not in KNOWN:
			KNOWN[key] = seen_funcs[key]
	write("  Total candidate functions: %d" % len(seen_funcs))
	decompiled = 0
	for key in sorted(seen_funcs.keys()):
		decompile_at(key, "candidate D3D method user %s" % seen_funcs[key], 18000)
		scan_patterns(key, "candidate D3D method user %s" % seen_funcs[key])
		decompiled += 1
		if decompiled >= 35:
			write("  ... candidate function decompile list truncated")
			break

def decl_type_name(value):
	name = DECL_TYPES.get(value)
	if name is None:
		return "TYPE_%d" % value
	return name

def decl_usage_name(value):
	name = DECL_USAGES.get(value)
	if name is None:
		return "USAGE_%d" % value
	return name

def read_decl_element(addr_int):
	stream = read_u16(addr_int)
	offset = read_u16(addr_int + 2)
	typ = read_byte(addr_int + 4)
	method = read_byte(addr_int + 5)
	usage = read_byte(addr_int + 6)
	usage_index = read_byte(addr_int + 7)
	if stream is None or offset is None or typ is None or method is None or usage is None or usage_index is None:
		return None
	return (stream, offset, typ, method, usage, usage_index)

def is_decl_end(elem):
	if elem is None:
		return False
	return elem[0] == 0xff and elem[1] == 0 and elem[2] == 17

def is_plausible_decl_element(elem):
	if elem is None:
		return False
	if elem[0] > 15:
		return False
	if elem[1] > 512:
		return False
	if elem[2] > 17:
		return False
	if elem[3] > 7:
		return False
	if elem[4] > 13:
		return False
	if elem[5] > 15:
		return False
	return True

def decode_declaration_before_end(end_addr):
	elements = []
	index = 1
	while index <= 16:
		elem_addr = end_addr - index * 8
		elem = read_decl_element(elem_addr)
		if elem is None:
			break
		if is_decl_end(elem):
			break
		if not is_plausible_decl_element(elem):
			break
		elements.insert(0, (elem_addr, elem))
		index += 1
	if len(elements) == 0:
		return None
	return elements

def declaration_score(elements):
	usage_names = {}
	tex_count = 0
	for item in elements:
		elem = item[1]
		name = decl_usage_name(elem[4])
		usage_names[name] = 1
		if name == "TEXCOORD":
			tex_count += 1
	score = 0
	for name in ["POSITION", "NORMAL", "TANGENT", "BINORMAL", "COLOR"]:
		if usage_names.get(name) is not None:
			score += 1
	if tex_count >= 1:
		score += 1
	if tex_count >= 3:
		score += 1
	return score

def format_decl_element(item):
	addr_int = item[0]
	elem = item[1]
	return "0x%08x stream=%d offset=%d type=%s method=%d usage=%s%d" % (
		addr_int,
		elem[0],
		elem[1],
		decl_type_name(elem[2]),
		elem[3],
		decl_usage_name(elem[4]),
		elem[5],
	)

def print_refs_to_decl(addr_int):
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_addr = ref.getFromAddress()
		from_func = fm.getFunctionContaining(from_addr)
		fname = from_func.getName() if from_func else "???"
		inst = listing.getInstructionContaining(from_addr)
		inst_text = inst.toString() if inst is not None else ""
		write("      ref %s @ 0x%08x in %s %s" % (ref.getReferenceType(), from_addr.getOffset(), fname, inst_text))
		count += 1
		if count >= 12:
			write("      ... refs truncated")
			break
	if count == 0:
		write("      no direct refs to declaration start")

def scan_static_vertex_declarations():
	write("")
	write("=" * 70)
	write("STATIC D3DVERTEXELEMENT9 DECLARATION CANDIDATES")
	write("=" * 70)
	write("Candidate terminator is D3DDECL_END bytes: stream=0xFF offset=0 type=UNUSED.")
	blocks = memory.getBlocks()
	printed = 0
	seen_start = {}
	for block in blocks:
		if not block.isInitialized():
			continue
		if not block.isRead():
			continue
		start = block.getStart().getOffset()
		end = block.getEnd().getOffset()
		addr = start
		while addr <= end - 8:
			elem = read_decl_element(addr)
			if is_decl_end(elem):
				elements = decode_declaration_before_end(addr)
				if elements is not None:
					decl_start = elements[0][0]
					if seen_start.get(decl_start) is None:
						seen_start[decl_start] = 1
						score = declaration_score(elements)
						if score >= 4:
							write("")
							write("  declaration start 0x%08x end 0x%08x score=%d elements=%d block=%s" % (decl_start, addr, score, len(elements), block.getName()))
							for item in elements:
								write("    %s" % format_decl_element(item))
							print_refs_to_decl(decl_start)
							printed += 1
							if printed >= 80:
								write("  ... declaration candidate list truncated")
								write("  Total printed: %d" % printed)
								return
			addr += 4
	write("  Total printed: %d" % printed)

def decompile_focus_functions():
	for item in FOCUS_FUNCTIONS:
		decompile_at(item[0], item[1], item[2])
		find_and_print_calls_from(item[0], item[1])
		scan_patterns(item[0], item[1])

def print_reference_targets():
	for item in REF_TARGETS:
		find_refs_to(item[0], item[1])

def main():
	write("FNV PBR CLOSE TERRAIN VERTEX DECLARATION CONTRACT")
	write("")
	write("Questions:")
	write("1. Where does the engine create or bind D3D vertex declarations for the draw path?")
	write("2. Do close-terrain candidates use D3DVERTEXELEMENT9 declarations or legacy FVF?")
	write("3. Which static declarations, if any, match NVR TerrainTemplate.hlsl inputs?")
	write("4. Which runtime functions must be instrumented if the declaration is generated dynamically?")
	write("")
	write("NVR TerrainTemplate.hlsl expects POSITION, TANGENT, BINORMAL, NORMAL, TEXCOORD0, COLOR0, TEXCOORD1, and TEXCOORD2.")
	print_reference_targets()
	decompile_focus_functions()
	scan_d3d_device_method_offsets()
	scan_static_vertex_declarations()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_vertex_declaration_contract.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
