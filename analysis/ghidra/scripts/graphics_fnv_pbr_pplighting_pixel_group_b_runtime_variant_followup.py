# @category Analysis
# @description Recover PPLighting family-3 pixel group B runtime-hit descriptors without relying on function recovery

from ghidra.app.decompiler import DecompInterface
import re

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

SCAN_START = 0x00B74200
SCAN_END = 0x00B78980
PIXEL_GROUP_B_CALLSITE = 0x00B78907
PIXEL_GROUP_B_GLOBAL = 0x011FDB08
PIXEL_GROUP_B_COUNT = 0xA0
PIXEL_GROUP_B_RUNTIME_INDICES = [1, 3, 17, 31]

STRING_HINTS = [
	"lighting\\1x\\p",
	"lighting\\2x\\p",
	"SLS1",
	"SLS2",
	"SPECULAR",
	"LIGHTS",
	"POINT",
	"PROJ_SHADOW",
	"NO_TEX",
	"LANDALPHA",
	"FACEGENBLEND",
	"MODELSPACENORM",
	"ps_2_0",
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

def find_loop_base_candidates_raw(callsite_int, max_steps):
	candidates = []
	inst = listing.getInstructionContaining(toAddr(callsite_int))
	steps = 0
	while inst is not None and steps < max_steps:
		mnemonic = inst.getMnemonicString()
		if mnemonic == "LEA":
			dst = inst.getDefaultOperandRepresentation(0)
			src = inst.getDefaultOperandRepresentation(1)
			if dst == "EBX":
				disp = parse_stack_disp(src)
				if disp is not None:
					candidates.append((inst.getAddress().getOffset(), disp, inst.toString()))
		inst = listing.getInstructionBefore(inst.getAddress())
		steps += 1
	return candidates

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

def print_raw_range(start_int, end_int, label):
	write("")
	write("=" * 70)
	write("RAW RANGE: %s 0x%08x..0x%08x" % (label, start_int, end_int))
	write("=" * 70)
	inst = listing.getInstructionAfter(toAddr(start_int - 1))
	while inst is not None and inst.getAddress().getOffset() < end_int:
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		print_refs_from_instruction(inst)
		inst = listing.getInstructionAfter(inst.getAddress())

def focus_indices(count, runtime_indices):
	selected = {}
	index = 0
	while index < min(count, 8):
		selected[index] = True
		index += 1
	for runtime_index in runtime_indices:
		for nearby in [runtime_index - 1, runtime_index, runtime_index + 1]:
			if nearby >= 0 and nearby < count:
				selected[nearby] = True
	keys = selected.keys()
	keys.sort()
	return keys

def format_near_fields(values, entry_base):
	parts = []
	field = -0x10
	while field <= 0x60:
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

def print_string_hints(values):
	write("")
	write("=" * 70)
	write("Pixel setup stack string references")
	write("=" * 70)
	keys = values.keys()
	keys.sort()
	for key in keys:
		text = values[key][1]
		for hint in STRING_HINTS:
			if hint.lower() in text.lower():
				write("  ESP+0x%X -> 0x%08X '%s'" % (key, values[key][0], text))
				break

def print_descriptor_views(values):
	write("")
	write("=" * 70)
	write("Pixel group B descriptor candidates")
	write("=" * 70)
	write("global=0x%08x callsite=0x%08x count=0x%x runtime_indices=%s" % (PIXEL_GROUP_B_GLOBAL, PIXEL_GROUP_B_CALLSITE, PIXEL_GROUP_B_COUNT, PIXEL_GROUP_B_RUNTIME_INDICES))
	candidates = find_loop_base_candidates_raw(PIXEL_GROUP_B_CALLSITE, 360)
	write("loop base candidates nearest-first:")
	for candidate in candidates:
		write("  0x%08x ESP+0x%X  %s" % (candidate[0], candidate[1], candidate[2]))
	if len(candidates) == 0:
		write("  [no EBX stack base candidate found]")
		return
	candidate_index = 0
	while candidate_index < len(candidates) and candidate_index < 4:
		base = candidates[candidate_index][1]
		write("")
		write("candidate[%d] descriptor base view: ESP+0x%X, stride 0x4C" % (candidate_index, base))
		indices = focus_indices(PIXEL_GROUP_B_COUNT, PIXEL_GROUP_B_RUNTIME_INDICES)
		for index in indices:
			entry_base = base + index * 0x4C
			marker = "runtime-hit" if index in PIXEL_GROUP_B_RUNTIME_INDICES else "context"
			write("  [%03d] %-11s base=ESP+0x%X %s" % (index, marker, entry_base, format_near_fields(values, entry_base)))
		candidate_index += 1

def main():
	write("FNV PBR PPLIGHTING PIXEL GROUP B RUNTIME VARIANT FOLLOWUP")
	write("")
	write("Reason:")
	write("- Prior runtime ABI audit mapped visible vertex variants to family 3 / SLS2.")
	write("- The pixel group B section failed because Ghidra has no function object at 0x00B78907.")
	write("- This script scans raw instructions and stack string writes instead.")
	write("")
	write("Do not widen native PBR replacement until runtime-hit pixel descriptors are mapped.")
	values = scan_stack_string_initializers(SCAN_START, SCAN_END)
	print_string_hints(values)
	print_descriptor_views(values)
	disasm_window(0x00B78780, 38, 60, "pixel group A -> group B transition")
	disasm_window(PIXEL_GROUP_B_CALLSITE, 52, 36, "pixel group B create callsite")
	print_raw_range(0x00B78780, 0x00B78980, "pixel group B setup raw")
	find_refs_to(PIXEL_GROUP_B_GLOBAL, "PPLighting pixel group B global")
	find_refs_to(0x00BE1750, "BSShader::CreatePixelShader")
	decompile_at(0x00BE1750, "BSShader::CreatePixelShader", 4000)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_pixel_group_b_runtime_variant_followup.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
