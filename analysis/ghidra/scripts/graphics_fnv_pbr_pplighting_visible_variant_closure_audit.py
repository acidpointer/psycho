# @category Analysis
# @description Close visible native PBR PPLighting variants from the latest runtime log

from ghidra.app.decompiler import DecompInterface
import re

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

VERTEX_SCAN_START = 0x00B73F80
VERTEX_SCAN_END = 0x00B74230
PIXEL_SCAN_START = 0x00B78680
PIXEL_SCAN_END = 0x00B78980
VERTEX_GROUP_C_CALLSITE = 0x00B7419F
PIXEL_GROUP_B_CALLSITE = 0x00B78907
VERTEX_GROUP_C_GLOBAL = 0x011FDE5C
PIXEL_GROUP_B_GLOBAL = 0x011FDB08
VERTEX_GROUP_C_COUNT = 0x67
PIXEL_GROUP_B_COUNT = 0xA0
DESCRIPTOR_STRIDE = 0x4C

VERTEX_VISIBLE_INDICES = [0, 12, 13, 14, 15, 22, 25, 26, 27, 100]
PIXEL_VISIBLE_INDICES = [4, 17, 18, 19, 31, 34, 35, 36, 108]

STRING_HINTS = [
	"lighting\\2x\\v",
	"lighting\\2x\\p",
	"ADTS",
	"ADTS10",
	"SPECULAR",
	"LIGHTS",
	"SKIN",
	"OPT",
	"SI",
	"HAIR",
	"PROJ_SHADOW",
	"POINT",
	"PTLIGHTS",
	"landlod",
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
		if count > 60:
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

def selected_indices(count, targets):
	selected = {}
	for target in targets:
		for nearby in [target - 1, target, target + 1]:
			if nearby >= 0 and nearby < count:
				selected[nearby] = True
	keys = selected.keys()
	keys.sort()
	return keys

def format_descriptor_fields(values, entry_base):
	parts = []
	field = -0x18
	while field <= 0x70:
		slot = entry_base + field
		if slot in values:
			item = values[slot]
			if field < 0:
				parts.append("-0x%02X=0x%08X '%s'" % (-field, item[0], item[1]))
			else:
				parts.append("+0x%02X=0x%08X '%s'" % (field, item[0], item[1]))
		field += 4
	if len(parts) == 0:
		return "[no nearby string fields recovered]"
	return "; ".join(parts)

def print_descriptor_table(label, values, callsite, global_addr, count, targets, max_candidates):
	write("")
	write("=" * 70)
	write("%s descriptor closure" % label)
	write("=" * 70)
	write("global=0x%08x callsite=0x%08x count=0x%x targets=%s" % (global_addr, callsite, count, targets))
	candidates = find_loop_base_candidates(callsite, 420)
	write("loop base candidates nearest-first:")
	for candidate in candidates:
		write("  0x%08x ESP+0x%X  %s" % (candidate[0], candidate[1], candidate[2]))
	if len(candidates) == 0:
		write("  [no EBX stack base candidate found]")
		return
	candidate_index = 0
	while candidate_index < len(candidates) and candidate_index < max_candidates:
		base = candidates[candidate_index][1]
		write("")
		write("candidate[%d] descriptor base view: ESP+0x%X, stride 0x%X" % (candidate_index, base, DESCRIPTOR_STRIDE))
		indices = selected_indices(count, targets)
		for index in indices:
			entry_base = base + index * DESCRIPTOR_STRIDE
			marker = "target" if index in targets else "context"
			write("  [%03d] %-7s base=ESP+0x%X %s" % (index, marker, entry_base, format_descriptor_fields(values, entry_base)))
		candidate_index += 1

def print_string_hints(label, values):
	write("")
	write("=" * 70)
	write("%s stack string hints" % label)
	write("=" * 70)
	keys = values.keys()
	keys.sort()
	for key in keys:
		text = values[key][1]
		for hint in STRING_HINTS:
			if hint.lower() in text.lower():
				write("  ESP+0x%X -> 0x%08X '%s'" % (key, values[key][0], text))
				break

def main():
	write("FNV PBR PPLIGHTING VISIBLE VARIANT CLOSURE AUDIT")
	write("")
	write("Purpose:")
	write("- Map latest playtest-visible family-3 pairs before widening native PBR.")
	write("- Confirm whether v13/p17 can share the low-light SLS2017 replacement.")
	write("- Classify v22/p31 as ADTS10 high-light and recover unknown v100/p108 descriptors.")
	vertex_values = scan_stack_string_initializers(VERTEX_SCAN_START, VERTEX_SCAN_END)
	pixel_values = scan_stack_string_initializers(PIXEL_SCAN_START, PIXEL_SCAN_END)
	print_string_hints("Vertex group C", vertex_values)
	print_descriptor_table("Vertex group C", vertex_values, VERTEX_GROUP_C_CALLSITE, VERTEX_GROUP_C_GLOBAL, VERTEX_GROUP_C_COUNT, VERTEX_VISIBLE_INDICES, 3)
	print_string_hints("Pixel group B", pixel_values)
	print_descriptor_table("Pixel group B", pixel_values, PIXEL_GROUP_B_CALLSITE, PIXEL_GROUP_B_GLOBAL, PIXEL_GROUP_B_COUNT, PIXEL_VISIBLE_INDICES, 3)
	find_refs_to(VERTEX_GROUP_C_GLOBAL, "PPLighting vertex group C global")
	find_refs_to(PIXEL_GROUP_B_GLOBAL, "PPLighting pixel group B global")
	find_and_print_calls_from(0x00BE0FE0, "BSShader::CreateVertexShader")
	find_and_print_calls_from(0x00BE1750, "BSShader::CreatePixelShader")
	decompile_at(0x00BE0FE0, "BSShader::CreateVertexShader", 4000)
	decompile_at(0x00BE1750, "BSShader::CreatePixelShader", 4000)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_visible_variant_closure_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
