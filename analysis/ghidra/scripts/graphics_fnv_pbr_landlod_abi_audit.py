# @category Analysis
# @description Audit PPLighting landlod shader ABI before adding a native PBR LOD replacement

from ghidra.app.decompiler import DecompInterface
import re

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

VERTEX_SCAN_START = 0x00B74000
VERTEX_SCAN_END = 0x00B74240
VERTEX_GROUP_C_CALLSITE = 0x00B7419F
VERTEX_GROUP_C_GLOBAL = 0x011FDE5C
VERTEX_GROUP_C_COUNT = 0x67
VERTEX_FOCUS_INDICES = [0, 1, 2, 3, 4, 5, 12, 13, 22]

PIXEL_SCAN_START = 0x00B78780
PIXEL_SCAN_END = 0x00B78980
PIXEL_GROUP_B_CALLSITE = 0x00B78907
PIXEL_GROUP_B_GLOBAL = 0x011FDB08
PIXEL_GROUP_B_COUNT = 0xA0
PIXEL_FOCUS_INDICES = [0, 1, 2, 3, 4, 5, 17, 31]

LANDLOD_VERTEX_SOURCE = 0x010AEBD4
LANDLOD_PIXEL_SOURCE = 0x010AF0F4
MODELSPACENORM_DEFINE = 0x010AEBC4
LODLANDCLIP_DEFINE = 0x010AEBB8
GEOMORPH_DEFINE = 0x010AEBAC
LODLANDNOISE_DEFINE = 0x010AF0E4
LODLAND_PARAMS_GLOBAL = 0x011FA0B0
LODTEX_PARAMS_GLOBAL = 0x011FA300

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
		if count > 40:
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

def target_string_from_instruction(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		target = ref.getToAddress()
		if target is None:
			continue
		text = read_c_string(target.getOffset(), 180)
		if text is not None:
			return (target.getOffset(), text)
	return None

def parse_stack_disp(text):
	m = re.search(r"\[ESP\s*\+\s*0x([0-9a-fA-F]+)\]", text)
	if m is not None:
		return int(m.group(1), 16)
	m = re.search(r"\[ESP\s*\+\s*([0-9]+)\]", text)
	if m is not None:
		return int(m.group(1), 10)
	if "[ESP]" in text:
		return 0
	return None

def scan_stack_string_initializers(start_int, end_int):
	values = {}
	inst = listing.getInstructionAfter(toAddr(start_int - 1))
	while inst is not None and inst.getAddress().getOffset() < end_int:
		if inst.getMnemonicString() == "MOV":
			dst = inst.getDefaultOperandRepresentation(0)
			disp = parse_stack_disp(dst)
			if disp is not None:
				target = target_string_from_instruction(inst)
				if target is not None:
					values[disp] = target
		inst = listing.getInstructionAfter(inst.getAddress())
	return values

def format_near_fields(values, entry_base):
	parts = []
	rel = -0x10
	while rel <= 0x60:
		target = values.get(entry_base + rel)
		if target is not None:
			parts.append("%+03X=0x%08X '%s'" % (rel, target[0], target[1]))
		rel += 4
	if len(parts) == 0:
		return "[no nearby string fields]"
	return "; ".join(parts)

def find_loop_base_candidates(callsite_int, max_steps):
	candidates = []
	inst = listing.getInstructionContaining(toAddr(callsite_int))
	steps = 0
	while inst is not None and steps < max_steps:
		if inst.getMnemonicString() == "LEA":
			dst = inst.getDefaultOperandRepresentation(0)
			src = inst.getDefaultOperandRepresentation(1)
			if dst == "EBX":
				disp = parse_stack_disp(src)
				if disp is not None:
					candidates.append((inst.getAddress().getOffset(), disp, inst.toString()))
		inst = listing.getInstructionBefore(inst.getAddress())
		steps += 1
	return candidates

def print_descriptor_view(title, values, callsite, count, focus_indices):
	write("")
	write("=" * 70)
	write(title)
	write("=" * 70)
	candidates = find_loop_base_candidates(callsite, 180)
	if len(candidates) == 0:
		write("  [no EBX descriptor base candidates found]")
		return
	candidate_index = 0
	while candidate_index < len(candidates) and candidate_index < 4:
		base = candidates[candidate_index][1]
		write("")
		write("candidate[%d] base=ESP+0x%X from 0x%08X: %s" % (candidate_index, base, candidates[candidate_index][0], candidates[candidate_index][2]))
		for index in focus_indices:
			if index >= count:
				continue
			entry_base = base + index * 0x4C
			marker = "TARGET" if index in [2, 3] else "context"
			write("  [%03d] %-7s entry=ESP+0x%X %s" % (index, marker, entry_base, format_near_fields(values, entry_base)))
		candidate_index += 1

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
		text = read_c_string(target.getOffset(), 96)
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

def decompile_ref_callers(addr_int, label, max_funcs, max_len):
	write("")
	write("=" * 70)
	write("DECOMPILE REF CALLERS: %s 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = {}
	count = 0
	while refs.hasNext() and count < max_funcs:
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		if entry in seen:
			continue
		seen[entry] = True
		decompile_at(entry, "ref caller %s" % label, max_len)
		count += 1
	write("  Decompiled unique callers: %d" % count)

def print_known_string(addr_int, label):
	text = read_c_string(addr_int, 180)
	if text is None:
		text = "[not readable]"
	write("  0x%08X %-24s %s" % (addr_int, label, text))

def print_known_contract():
	write("Known target from runtime reports and prior audits:")
	write("- close-object PBR currently targets family 3 v12/p17 and v22/p31")
	write("- suspected far-distance dropout is family 3 landlod v2/p3")
	write("- do not reuse object PBR shaders until this output proves landlod inputs")
	write("")
	write("Known string/global anchors:")
	print_known_string(LANDLOD_VERTEX_SOURCE, "vertex source")
	print_known_string(LANDLOD_PIXEL_SOURCE, "pixel source")
	print_known_string(MODELSPACENORM_DEFINE, "define")
	print_known_string(LODLANDCLIP_DEFINE, "define")
	print_known_string(GEOMORPH_DEFINE, "define")
	print_known_string(LODLANDNOISE_DEFINE, "define")
	write("  0x%08X %-24s vertex c19 source candidate" % (LODLAND_PARAMS_GLOBAL, "LODLandParams global"))
	write("  0x%08X %-24s pixel c31 source candidate" % (LODTEX_PARAMS_GLOBAL, "LODTEXPARAMS global"))

def main():
	write("FNV PBR LANDLOD ABI AUDIT")
	write("")
	print_known_contract()
	vertex_values = scan_stack_string_initializers(VERTEX_SCAN_START, VERTEX_SCAN_END)
	pixel_values = scan_stack_string_initializers(PIXEL_SCAN_START, PIXEL_SCAN_END)
	print_descriptor_view("Vertex group C descriptor view, focus v2 landlod", vertex_values, VERTEX_GROUP_C_CALLSITE, VERTEX_GROUP_C_COUNT, VERTEX_FOCUS_INDICES)
	print_descriptor_view("Pixel group B descriptor view, focus p3 landlod", pixel_values, PIXEL_GROUP_B_CALLSITE, PIXEL_GROUP_B_COUNT, PIXEL_FOCUS_INDICES)
	disasm_window(VERTEX_GROUP_C_CALLSITE, 52, 32, "vertex group C create callsite")
	disasm_window(PIXEL_GROUP_B_CALLSITE, 52, 32, "pixel group B create callsite")
	find_refs_to(VERTEX_GROUP_C_GLOBAL, "PPLighting vertex group C global")
	find_refs_to(PIXEL_GROUP_B_GLOBAL, "PPLighting pixel group B global")
	find_refs_to(LANDLOD_VERTEX_SOURCE, "lighting\\2x\\v\\landlod.v.hlsl")
	find_refs_to(LANDLOD_PIXEL_SOURCE, "lighting\\2x\\p\\landlod.p.hlsl")
	find_refs_to(LODLAND_PARAMS_GLOBAL, "LODLandParams data global")
	find_refs_to(LODTEX_PARAMS_GLOBAL, "LODTEXPARAMS data global")
	decompile_ref_callers(LODLAND_PARAMS_GLOBAL, "LODLandParams data global", 6, 7000)
	decompile_ref_callers(LODTEX_PARAMS_GLOBAL, "LODTEXPARAMS data global", 6, 7000)
	decompile_at(0x00BE0FE0, "BSShader::CreateVertexShader", 4000)
	decompile_at(0x00BE1750, "BSShader::CreatePixelShader", 4000)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_landlod_abi_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
