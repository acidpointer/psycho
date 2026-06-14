# @category Analysis
# @description Audit parallax and near-terrain shader families before adding native PBR replacements

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
MAX_CANDIDATE_STRINGS = 220
MAX_REFS_PER_STRING = 24
MAX_DECOMP_CALLERS = 8
NEEDLES = [
	"PAR%03i",
	"PAR2",
	"parallax",
	"Parallax",
	"land.p.hlsl",
	"land.v.hlsl",
	"terrain",
	"Terrain",
	"LandSpec",
	"LandHeight",
	"SLS2%03i.vso",
	"SLS2%03i.pso",
	"SLS2%03is%01i.pso",
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

def string_matches(text):
	lower_text = text.lower()
	for needle in NEEDLES:
		if needle.lower() in lower_text:
			return True
	return False

def scan_block_strings(block, results):
	start = block.getStart().getOffset()
	end = block.getEnd().getOffset()
	addr = start
	chars = []
	string_start = start
	while addr <= end and len(results) < MAX_CANDIDATE_STRINGS:
		value = read_byte(addr)
		if value is not None and value >= 0x20 and value <= 0x7e:
			if len(chars) == 0:
				string_start = addr
			chars.append(chr(value))
		else:
			if len(chars) >= 4:
				text = "".join(chars)
				if string_matches(text):
					results.append((string_start, text))
			chars = []
		addr += 1
	if len(chars) >= 4 and len(results) < MAX_CANDIDATE_STRINGS:
		text = "".join(chars)
		if string_matches(text):
			results.append((string_start, text))

def scan_candidate_strings():
	results = []
	blocks = memory.getBlocks()
	index = 0
	while index < len(blocks) and len(results) < MAX_CANDIDATE_STRINGS:
		block = blocks[index]
		if block.isInitialized():
			scan_block_strings(block, results)
		index += 1
	results.sort()
	return results

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

def print_refs_and_callers(addr_int, label):
	write("")
	write("=" * 70)
	write("STRING REFS AND CALLERS: 0x%08x %s" % (addr_int, label))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = {}
	ref_count = 0
	decomp_count = 0
	while refs.hasNext() and ref_count < MAX_REFS_PER_STRING:
		ref = refs.next()
		from_addr = ref.getFromAddress().getOffset()
		func = fm.getFunctionContaining(ref.getFromAddress())
		fname = func.getName() if func else "???"
		write("  ref %-18s @ 0x%08x in %s" % (str(ref.getReferenceType()), from_addr, fname))
		disasm_window(from_addr, 18, 18, label)
		if func is not None:
			entry = func.getEntryPoint().getOffset()
			if entry not in seen and decomp_count < MAX_DECOMP_CALLERS:
				seen[entry] = True
				decompile_at(entry, "caller for %s" % label, 9000)
				decomp_count += 1
		ref_count += 1
	write("  Printed refs: %d, decompiled callers: %d" % (ref_count, decomp_count))

def print_candidate_summary(candidates):
	write("")
	write("=" * 70)
	write("Candidate shader strings")
	write("=" * 70)
	index = 0
	while index < len(candidates):
		item = candidates[index]
		write("  [%03d] 0x%08x %s" % (index, item[0], item[1]))
		index += 1

def print_candidate_details(candidates):
	index = 0
	while index < len(candidates):
		item = candidates[index]
		print_refs_and_callers(item[0], item[1])
		index += 1

def main():
	write("FNV PBR PARALLAX/TERRAIN SHADER FAMILY AUDIT")
	write("")
	write("Goal: prove exact shader-family globals, descriptor indices, source strings, and callsites for close terrain/parallax before replacement.")
	decompile_at(CREATE_VERTEX_SHADER_ADDR, "BSShader::CreateVertexShader", 5000)
	decompile_at(CREATE_PIXEL_SHADER_ADDR, "BSShader::CreatePixelShader", 5000)
	find_and_print_calls_from(CREATE_VERTEX_SHADER_ADDR, "BSShader::CreateVertexShader")
	find_and_print_calls_from(CREATE_PIXEL_SHADER_ADDR, "BSShader::CreatePixelShader")
	candidates = scan_candidate_strings()
	write("")
	write("Candidate strings found: %d" % len(candidates))
	print_candidate_summary(candidates)
	print_candidate_details(candidates)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_parallax_terrain_shader_family_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
