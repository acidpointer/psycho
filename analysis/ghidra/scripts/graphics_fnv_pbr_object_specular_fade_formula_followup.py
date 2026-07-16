# @category Analysis
# @description Recover the exact PPLighting specular fade formula, property fields, and distance threshold orientation

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

FUNCTION_TARGETS = [
	(0x00B66B80, "BSShaderPPLightingProperty::GetSpecularFade"),
	(0x00B66C40, "BSShaderPPLightingProperty::GetEnvMapFade control"),
	(0x00B68B10, "BSShaderPPLightingProperty::SetSpecular control"),
	(0x00B70820, "PPLighting per-light fade staging caller"),
	(0x00BB4740, "PPLighting distance and selector cache updater"),
]

RAW_TARGETS = [
	(0x00B66B80, 0xC0, "GetSpecularFade raw code"),
	(0x00B66C40, 0xD0, "GetEnvMapFade raw code"),
	(0x00B68B10, 0x90, "SetSpecular raw code"),
]

VTABLE_TARGETS = [
	(0x010AE0D0, "BSShaderPPLightingProperty"),
	(0x010B8330, "PPLighting-derived family A"),
	(0x010B9338, "PPLighting-derived family B"),
	(0x010B9490, "PPLighting-derived family C"),
	(0x010B9910, "PPLighting-derived family D"),
	(0x010BABF8, "PPLighting-derived family E"),
]

REF_TARGETS = [
	(0x00B66B80, "GetSpecularFade target"),
	(0x00B66C40, "GetEnvMapFade target"),
	(0x011F9458, "PPLighting selector threshold A"),
	(0x011F9460, "PPLighting selector threshold B"),
	(0x011F9468, "PPLighting selector threshold C"),
]

MATCH_PATTERNS = [
	"0x34",
	"0x38",
	"0x7c",
	"0x80",
	"0x84",
	"011f9458",
	"011f9460",
	"011f9468",
	"011f91e0",
	"0x10c",
	"0x110",
	"004b3ab0",
	"00457990",
	"004e20c0",
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

def function_at_or_containing(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	return func

def function_label(addr_int):
	func = function_at_or_containing(addr_int)
	if func is None:
		return "unknown"
	entry = func.getEntryPoint().getOffset()
	if entry == addr_int:
		return func.getName()
	return "%s+0x%x" % (func.getName(), addr_int - entry)

def ensure_function_at(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is not None:
		return func
	func = fm.getFunctionContaining(toAddr(addr_int))
	if func is not None:
		write("  NOTE: 0x%08x is inside existing %s @ 0x%08x" % (addr_int, func.getName(), func.getEntryPoint().getOffset()))
		return func
	try:
		disassemble(toAddr(addr_int))
	except Exception as err:
		write("  disassemble failed at 0x%08x (%s): %s" % (addr_int, label, err))
	try:
		func = createFunction(toAddr(addr_int), "pbr_specular_fade_%08x" % addr_int)
		if func is not None:
			write("  created function at 0x%08x (%s)" % (addr_int, label))
		return func
	except Exception as err:
		write("  createFunction failed at 0x%08x (%s): %s" % (addr_int, label, err))
	return None

def decompile_at(addr_int, label, max_len=24000):
	write("")
	write("=" * 70)
	write("%s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = ensure_function_at(addr_int, label)
	if func is None:
		write("  [function not found]")
		return
	entry = func.getEntryPoint().getOffset()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), entry, func.getBody().getNumAddresses()))
	if entry != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), entry))
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
	func = function_at_or_containing(addr_int)
	if func is None:
		write("  [function not found at 0x%08x]" % addr_int)
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), target, function_label(target)))
				count += 1
	write("  Total: %d calls" % count)

def print_raw_bytes(addr_int, length, label):
	write("")
	write("-" * 70)
	write("RAW BYTES: %s @ 0x%08x length 0x%x" % (label, addr_int, length))
	write("-" * 70)
	offset = 0
	while offset < length:
		parts = []
		index = 0
		while index < 16 and offset + index < length:
			value = read_byte(addr_int + offset + index)
			parts.append("??" if value is None else "%02x" % value)
			index += 1
		write("  0x%08x: %s" % (addr_int + offset, " ".join(parts)))
		offset += 16

def print_instructions(addr_int, length, label):
	write("")
	write("-" * 70)
	write("INSTRUCTIONS: %s @ 0x%08x length 0x%x" % (label, addr_int, length))
	write("-" * 70)
	end = addr_int + length
	inst = listing.getInstructionAt(toAddr(addr_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(addr_int))
	count = 0
	while inst is not None and inst.getAddress().getOffset() < end:
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()
		count += 1
	write("  Total instructions: %d" % count)

def print_vtable_contract(base_int, label):
	write("")
	write("=" * 70)
	write("VTABLE CONTRACT: %s @ 0x%08x" % (label, base_int))
	write("=" * 70)
	offsets = [0x104, 0x108, 0x10C, 0x110, 0x114, 0x118]
	index = 0
	while index < len(offsets):
		offset = offsets[index]
		target = read_u32(base_int + offset)
		if target is None:
			write("  +0x%03x @ 0x%08x -> unreadable" % (offset, base_int + offset))
		else:
			write("  +0x%03x @ 0x%08x -> 0x%08x %s" % (offset, base_int + offset, target, function_label(target)))
		index += 1

def print_matching_decompile_lines(addr_int, label):
	write("")
	write("=" * 70)
	write("MATCHED DECOMPILE LINES: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = function_at_or_containing(addr_int)
	if func is None:
		write("  [function not found]")
		return
	result = decomp.decompileFunction(func, 120, monitor)
	if not result or not result.decompileCompleted():
		write("  [decompilation failed]")
		return
	lines = result.getDecompiledFunction().getC().splitlines()
	line_index = 0
	count = 0
	while line_index < len(lines):
		lower = lines[line_index].lower()
		pattern_index = 0
		matched = False
		while pattern_index < len(MATCH_PATTERNS):
			if lower.find(MATCH_PATTERNS[pattern_index].lower()) >= 0:
				matched = True
				break
			pattern_index += 1
		if matched:
			write("  L%04d: %s" % (line_index + 1, lines[line_index]))
			count += 1
		line_index += 1
	write("  Total matched lines: %d" % count)

def audit_functions():
	index = 0
	while index < len(FUNCTION_TARGETS):
		item = FUNCTION_TARGETS[index]
		decompile_at(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])
		print_matching_decompile_lines(item[0], item[1])
		index += 1

def audit_raw_targets():
	index = 0
	while index < len(RAW_TARGETS):
		item = RAW_TARGETS[index]
		print_raw_bytes(item[0], item[1], item[2])
		print_instructions(item[0], item[1], item[2])
		index += 1

def audit_vtables():
	index = 0
	while index < len(VTABLE_TARGETS):
		item = VTABLE_TARGETS[index]
		print_vtable_contract(item[0], item[1])
		index += 1

def audit_refs():
	index = 0
	while index < len(REF_TARGETS):
		item = REF_TARGETS[index]
		find_refs_to(item[0], item[1])
		index += 1

def print_questions():
	write("FNV PBR OBJECT SPECULAR FADE FORMULA FOLLOW-UP")
	write("")
	write("Questions:")
	write("1. What exact property fields and globals produce GetSpecularFade()?")
	write("2. Is its return value continuous, clamped, and oriented 0 far to 1 near?")
	write("3. Does GetEnvMapFade use the same distance basis or a separate contract?")
	write("4. Are selector thresholds only pass/cache boundaries, or do they also enter the fade formula?")
	write("5. Do all PPLighting-derived vtables share the same specular fade implementation?")

def main():
	print_questions()
	audit_vtables()
	audit_refs()
	audit_functions()
	audit_raw_targets()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_object_specular_fade_formula_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
