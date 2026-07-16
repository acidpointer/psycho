# @category Analysis
# @description Close FNV PBR object EnvMap material accessors and externally owned sampler stage 2

from ghidra.app.decompiler import DecompInterface

if currentProgram is None:
	raise RuntimeError("Open FalloutNV.exe in CodeBrowser and run this file from Script Manager; do not paste it into the Python console")

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

PPLIGHTING_VTABLES = [
	(0x010AE0D0, "BSShaderPPLightingProperty"),
	(0x010B8330, "Lighting30ShaderProperty"),
	(0x010B9338, "SpeedTreeBranchShaderProperty"),
	(0x010B9490, "SpeedTreeShaderPPLightingProperty"),
	(0x010B9910, "DistantLODShaderProperty"),
	(0x010BABF8, "TallGrassShaderProperty"),
]

VTABLE_SLOTS = [
	(0xEC, "texture-set mutation predecessor"),
	(0xF0, "SetTexture candidate"),
	(0xF4, "GetTexture candidate"),
	(0xF8, "texture accessor successor"),
]

FUNCTION_TARGETS = [
	(0x00C02F30, "B7C290 texture accessor", 16000),
	(0x00C03230, "B7C0E0 texture accessor", 16000),
	(0x00B7C290, "descriptor writer using C02F30", 12000),
	(0x00B7C0E0, "descriptor writer using C03230", 12000),
	(0x00B7C2C0, "descriptor writer using virtual texture semantic 5", 12000),
	(0x00B7D200, "PPLighting pass texture binder", 36000),
	(0x00BE2170, "non-null descriptor apply gate", 12000),
	(0x00E7EB00, "single descriptor apply wrapper", 12000),
	(0x00E7EA00, "final descriptor texture and sampler apply", 12000),
	(0x00B795B0, "EnvMap constants and selected environment record setup", 18000),
	(0x00C02D90, "selected environment record constant writer", 12000),
	(0x00B55520, "selected environment record resolver", 8000),
	(0x00B7B450, "lighting and environment shader-interface setup", 24000),
	(0x00BB41E0, "distance fade selector", 20000),
	(0x00BB4740, "distance pass-list invalidation owner", 36000),
	(0x00B66B80, "native specular fade formula", 12000),
	(0x00B66C40, "native EnvMap fade formula", 12000),
]

REFERENCE_TARGETS = [
	(0x00C02F30, "B7C290 texture accessor"),
	(0x00C03230, "B7C0E0 texture accessor"),
	(0x00C02D90, "selected environment record constant writer"),
	(0x00B55520, "selected environment record resolver"),
	(0x00BE2170, "non-null descriptor apply gate"),
	(0x00E7EB00, "single descriptor apply wrapper"),
	(0x011F91C4, "active environment selector index"),
	(0x011F91C8, "environment record pointer table base"),
	(0x0126F74C, "current NiD3DPass"),
]

MATCH_PATTERNS = [
	"0xac",
	"0xb0",
	"0xb4",
	"0xb8",
	"0xbc",
	"0xc0",
	"0xf0",
	"0xf4",
	"0x134",
	"0x248",
	"0x24b",
	"011f91c4",
	"011f91c8",
	"0126f74c",
	"011fa2d",
	"texture",
	"sampler",
	"distance",
]

def write(msg):
	output.append(msg)
	print(msg)

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
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found at 0x%08x]" % addr_int)
		return
	body = func.getBody()
	inst_iter = listing.getInstructions(body, True)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
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

def decompile_text(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		return None
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		return result.getDecompiledFunction().getC()
	return None

def line_matches(line):
	lower = line.lower()
	index = 0
	while index < len(MATCH_PATTERNS):
		if lower.find(MATCH_PATTERNS[index]) >= 0:
			return True
		index += 1
	return False

def print_matching_lines(addr_int, label):
	write("")
	write("MATCHED CONTRACT LINES: %s @ 0x%08x" % (label, addr_int))
	code = decompile_text(addr_int)
	if code is None:
		write("  [decompilation failed]")
		return
	lines = code.splitlines()
	index = 0
	count = 0
	while index < len(lines):
		if line_matches(lines[index]):
			write("  L%04d: %s" % (index + 1, lines[index]))
			count += 1
		index += 1
	write("  Total matched lines: %d" % count)

def print_instruction_references(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		write("      ref %-18s -> 0x%08x" % (str(ref.getReferenceType()), ref.getToAddress().getOffset()))

def print_raw_range(start_int, end_int, label):
	write("")
	write("=" * 70)
	write("RAW DISASSEMBLY: %s 0x%08x-0x%08x" % (label, start_int, end_int))
	write("=" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int - 1))
	count = 0
	while inst is not None and inst.getAddress().getOffset() <= end_int:
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		print_instruction_references(inst)
		inst = listing.getInstructionAfter(inst.getAddress())
		count += 1
		if count > 1000:
			write("  ... (instruction safety limit reached)")
			break
	write("  Total instructions: %d" % count)

def read_u32(addr_int):
	return memory.getInt(toAddr(addr_int)) & 0xffffffff

def vtable_slot_target(vtable, offset):
	return read_u32(vtable + offset)

def audit_pplighting_vtables():
	write("")
	write("=" * 70)
	write("PPLIGHTING MATERIAL TEXTURE VTABLE SLOTS")
	write("=" * 70)
	targets = {}
	index = 0
	while index < len(PPLIGHTING_VTABLES):
		item = PPLIGHTING_VTABLES[index]
		write("")
		write("%s vtable 0x%08x" % (item[1], item[0]))
		slot_index = 0
		while slot_index < len(VTABLE_SLOTS):
			slot = VTABLE_SLOTS[slot_index]
			target = vtable_slot_target(item[0], slot[0])
			func = fm.getFunctionAt(toAddr(target))
			name = func.getName() if func else "???"
			write("  +0x%02x %-34s -> 0x%08x %s" % (slot[0], slot[1], target, name))
			targets[target] = "%s %s" % (item[1], slot[1])
			slot_index += 1
		index += 1
	addresses = targets.keys()
	addresses.sort()
	index = 0
	while index < len(addresses):
		target = addresses[index]
		decompile_at(target, "vtable texture method: %s" % targets[target], 18000)
		find_and_print_calls_from(target, targets[target])
		print_matching_lines(target, targets[target])
		find_refs_to(target, targets[target])
		index += 1

def audit_functions():
	index = 0
	while index < len(FUNCTION_TARGETS):
		item = FUNCTION_TARGETS[index]
		decompile_at(item[0], item[1], item[2])
		find_and_print_calls_from(item[0], item[1])
		print_matching_lines(item[0], item[1])
		index += 1

def audit_references():
	index = 0
	while index < len(REFERENCE_TARGETS):
		item = REFERENCE_TARGETS[index]
		find_refs_to(item[0], item[1])
		index += 1

def main():
	write("FNV PBR OBJECT ENVMAP ACCESSORS AND STAGE-2 OWNER CLOSURE")
	write("")
	write("Established from the prior output:")
	write("- passes 0x248/0x249/0x24A bind descriptor indices 3, 1, and 0")
	write("- pass 0x24B binds descriptor index 0; its descriptor index 1 is static")
	write("- descriptor index 2 is not written by the EnvMap B7D200 block")
	write("- BE2170 skips descriptors whose texture pointer +8 is null")
	write("")
	write("Questions:")
	write("1. Which +0xAC..+0xC0 arrays do C03230, C02F30, and virtual semantic 5 return?")
	write("2. Is EnvMap stage 2 an external persistent binding, an unused sampler, or a missing native write?")
	write("3. Which environment record owns the stage-2 resource or related constant state?")
	write("4. Can distance change any texture binding, or only pass membership and fade constants?")
	audit_pplighting_vtables()
	print_raw_range(0x00B7D350, 0x00B7D395, "EnvMap descriptor indices 3, 1, 0 and eye fallthrough")
	print_raw_range(0x00BE2170, 0x00BE21A7, "descriptor non-null apply gate")
	audit_functions()
	audit_references()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_object_envmap_accessors_stage2_owner_closure.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
