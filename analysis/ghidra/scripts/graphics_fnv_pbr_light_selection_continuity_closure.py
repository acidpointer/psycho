# @category Analysis
# @description Close FNV PPLighting camera-distance, light-list sorting, cap, fade, and pass-rebuild continuity

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []
decompile_cache = {}

OUTPATH = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_light_selection_continuity_closure.txt"

PRIMARY_TARGETS = [
	(0x00457990, "camera/object vector length primitive"),
	(0x00B70390, "PPLighting light-list sorter"),
	(0x00B9DBE0, "PPLighting light-list camera metric"),
	(0x00B704C0, "PPLighting staged-light reset"),
	(0x00B70590, "PPLighting first valid light iterator"),
	(0x00B70600, "PPLighting first valid non-special light iterator"),
	(0x00B70680, "PPLighting next valid light iterator"),
	(0x00B70700, "PPLighting next valid non-special light iterator"),
	(0x00B707D0, "PPLighting filtered light count"),
	(0x00B70820, "PPLighting ambient and per-light color staging"),
	(0x00B78A90, "PPLighting current-pass light constant staging"),
	(0x00BB4740, "PPLighting distance, sort, cache, and pass updater"),
]

COMPANION_TARGETS = [
	(0x004B3AB0, "distance fade interpolation helper"),
	(0x004E20C0, "PPLighting color staging helper"),
	(0x00B9DAE0, "PPLighting light eligibility and influence test"),
	(0x00B63320, "PPLighting staged-light reset caller"),
	(0x00B66B80, "BSShaderPPLightingProperty GetSpecularFade"),
	(0x00B66C40, "BSShaderPPLightingProperty GetEnvMapFade"),
	(0x00B66F50, "BSShaderPPLightingProperty constructor"),
	(0x00B67380, "BSShaderPPLightingProperty destructor"),
	(0x00B67BE0, "base PPLighting distance/pass updater"),
	(0x00B68B10, "PPLighting specular state invalidator"),
	(0x00B71410, "PPLighting base destructor"),
	(0x00B71720, "PPLighting base constructor"),
	(0x00BA8AB0, "PPLighting pass fade staging"),
	(0x00BA8C00, "pass-entry argument allocation"),
	(0x00BA8C30, "pass-entry argument capacity growth"),
	(0x00BA95E0, "pass-list clear/reset"),
	(0x00BA9EE0, "pass-entry append/reuse"),
	(0x00BC3E40, "alternate PPLighting distance/pass updater"),
	(0x00C058F0, "long alternate PPLighting distance/pass updater"),
]

RAW_FUNCTIONS = [
	(0x00457990, "camera/object vector length primitive"),
	(0x00B70390, "PPLighting light-list sorter"),
	(0x00B9DBE0, "PPLighting light-list camera metric"),
	(0x00B704C0, "PPLighting staged-light reset"),
	(0x00B70590, "first valid light iterator"),
	(0x00B70600, "first valid non-special light iterator"),
	(0x00B70680, "next valid light iterator"),
	(0x00B70700, "next valid non-special light iterator"),
	(0x00B707D0, "filtered light count"),
	(0x00B70820, "ambient and per-light color staging"),
	(0x00B78A90, "current-pass light constant staging"),
	(0x00B67BE0, "base PPLighting updater"),
	(0x00BB4740, "main PPLighting updater"),
	(0x00BC3E40, "alternate PPLighting updater"),
	(0x00C058F0, "long alternate PPLighting updater"),
]

CALLSITE_TARGETS = [
	(0x00457990, "vector length primitive"),
	(0x00B70390, "light-list sorter"),
	(0x00B9DBE0, "light-list camera metric"),
	(0x00B704C0, "staged-light reset"),
	(0x00B70590, "first valid light iterator"),
	(0x00B70600, "first non-special light iterator"),
	(0x00B70680, "next valid light iterator"),
	(0x00B70700, "next non-special light iterator"),
	(0x00B707D0, "filtered light count"),
	(0x00B70820, "per-light color staging"),
]

GLOBAL_TARGETS = [
	(0x011FA0C0, "AmbientColor c1 backing"),
	(0x011FA0D0, "PSLightColor c3 array backing"),
	(0x011FA170, "staged point-light position array"),
	(0x011FA1F0, "staged LightData array"),
	(0x011FD9A8, "renderer LightData c25 backing"),
	(0x011FD9B8, "high-path PSLightPosition c19 backing"),
	(0x011F91E0, "current PPLighting geometry"),
	(0x011F91E4, "current PPLighting row"),
	(0x011F9454, "specular fade start"),
	(0x011F9458, "specular fade end"),
	(0x011F945C, "fade range B start"),
	(0x011F9460, "fade range B end"),
	(0x011F9464, "fade range C start"),
	(0x011F9468, "fade range C end"),
	(0x011F946C, "fade range D start"),
	(0x011F9470, "fade range D end"),
	(0x011F947C, "light color floor/limit"),
]

PPLIGHTING_VTABLES = [
	(0x010AE0D0, "BSShaderPPLightingProperty"),
	(0x010B8330, "PPLighting-derived family A"),
	(0x010B9338, "PPLighting-derived family B"),
	(0x010B9490, "PPLighting-derived family C"),
	(0x010B9910, "PPLighting-derived family D"),
	(0x010BABF8, "PPLighting-derived family E"),
	(0x010BCB60, "PPLighting-derived family F"),
]

FIELD_SCALARS = [0x34, 0x38, 0x3C, 0x60, 0x74]

FOCUS_WINDOWS = [
	(0x00B6339C, 18, 24, "staged-light reset call"),
	(0x00B78B60, 28, 36, "per-light staging call and pass count"),
	(0x00BB4C10, 28, 42, "main updater distance calculation"),
	(0x00BB4F0E, 28, 42, "main updater light sort"),
	(0x00BB4F87, 20, 86, "main updater cached pass light refresh"),
	(0x00BB50C6, 24, 80, "main updater pass-list rebuild start"),
	(0x00BB53BC, 24, 110, "main updater light count and fill"),
	(0x00BB59B3, 24, 96, "main updater special-light handling"),
	(0x00BB5C45, 20, 32, "main updater final pass emission"),
	(0x00BC4083, 28, 42, "alternate updater distance calculation"),
	(0x00C05DB5, 28, 42, "long updater distance calculation"),
	(0x00C06075, 28, 48, "long updater light sort"),
	(0x00C060EA, 20, 92, "long updater cached pass refresh"),
	(0x00C064E6, 24, 96, "long updater light count and fill"),
]

def write(msg):
	output.append(msg)
	print(msg)

def checkpoint_output():
	fout = open(OUTPATH, "w")
	fout.write("\n".join(output))
	fout.close()

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

def read_u32(addr_int):
	try:
		return memory.getInt(toAddr(addr_int)) & 0xffffffff
	except:
		return None

def instruction_bytes(inst):
	try:
		values = inst.getBytes()
		parts = []
		index = 0
		while index < len(values):
			parts.append("%02x" % (values[index] & 0xff))
			index += 1
		return " ".join(parts)
	except:
		return "??"

def outgoing_refs_text(inst):
	parts = []
	refs = inst.getReferencesFrom()
	for ref in refs:
		target = ref.getToAddress()
		if target is not None:
			parts.append("%s->0x%08x" % (str(ref.getReferenceType()), target.getOffset()))
	return ", ".join(parts)

def decompile_text(addr_int):
	func = function_at_or_containing(addr_int)
	if func is None:
		return None
	entry = func.getEntryPoint().getOffset()
	if decompile_cache.has_key(entry):
		return decompile_cache[entry]
	result = decomp.decompileFunction(func, 180, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		decompile_cache[entry] = code
		return code
	decompile_cache[entry] = None
	return None

def decompile_at(addr_int, label, max_len=1000000):
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
	write("  Decompiled characters: %d" % len(code))
	if len(code) > max_len:
		write(code[:max_len])
		write("  [decompile truncated from %d characters]" % len(code))
	else:
		write(code)

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
		inst = listing.getInstructionContaining(ref.getFromAddress())
		text = inst.toString() if inst is not None else ""
		write("  %s @ 0x%08x (in %s) %s" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, text))
		count += 1
		if count >= 240:
			write("  ... (truncated)")
			break
	write("  Total printed refs: %d" % count)

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

def print_full_function_disassembly(addr_int, label):
	func = function_at_or_containing(addr_int)
	write("")
	write("=" * 70)
	write("RAW FUNCTION: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	entry = func.getEntryPoint().getOffset()
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		address = inst.getAddress().getOffset()
		refs = outgoing_refs_text(inst)
		write("  0x%08x +0x%04x  %-24s %-46s %s" % (address, address - entry, instruction_bytes(inst), inst.toString(), refs))
		count += 1
	write("  Total instructions: %d" % count)

def instruction_before_steps(inst, steps):
	current = inst
	index = 0
	while current is not None and index < steps:
		previous = listing.getInstructionBefore(current.getAddress())
		if previous is None:
			break
		current = previous
		index += 1
	return current

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("DISASM WINDOW: %s around 0x%08x" % (label, center_int))
	write("-" * 70)
	inst = listing.getInstructionContaining(toAddr(center_int))
	if inst is None:
		write("  [instruction not found]")
		return
	current = instruction_before_steps(inst, before_count)
	index = 0
	limit = before_count + after_count + 1
	while current is not None and index < limit:
		address = current.getAddress().getOffset()
		marker = " << TARGET" if address == center_int else ""
		write("  0x%08x  %-24s %-46s %s%s" % (address, instruction_bytes(current), current.toString(), outgoing_refs_text(current), marker))
		current = listing.getInstructionAfter(current.getAddress())
		index += 1

def print_callers_with_windows(addr_int, label):
	write("")
	write("=" * 70)
	write("CALLERS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		source = ref.getFromAddress().getOffset()
		func = fm.getFunctionContaining(ref.getFromAddress())
		name = func.getName() if func is not None else "???"
		write("  Caller %d: 0x%08x in %s" % (count + 1, source, name))
		disasm_window(source, 18, 20, "call to %s" % label)
		count += 1
		if count >= 80:
			write("  ... caller scan truncated")
			break
	write("  Total callers printed: %d" % count)

def scalar_values_for_instruction(inst):
	values = []
	op_index = 0
	while op_index < inst.getNumOperands():
		objects = inst.getOpObjects(op_index)
		object_index = 0
		while object_index < len(objects):
			obj = objects[object_index]
			try:
				value = obj.getValue() & 0xffffffff
				values.append(value)
			except:
				pass
			object_index += 1
		op_index += 1
	return values

def print_field_scalar_hits(addr_int, label):
	func = function_at_or_containing(addr_int)
	write("")
	write("FIELD-SCALAR CANDIDATES: %s @ 0x%08x" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		values = scalar_values_for_instruction(inst)
		field_index = 0
		while field_index < len(FIELD_SCALARS):
			field = FIELD_SCALARS[field_index]
			if field in values:
				write("  +0x%02x candidate @ 0x%08x: %-24s %s" % (field, inst.getAddress().getOffset(), instruction_bytes(inst), inst.toString()))
				count += 1
			field_index += 1
	write("  Total candidates: %d" % count)
	write("  NOTE: Raw scalar hits are candidates; callsite and receiver provenance decide whether they are property fields.")

def print_vtable(base_int, label):
	write("")
	write("=" * 70)
	write("PPLIGHTING VTABLE: %s @ 0x%08x" % (label, base_int))
	write("=" * 70)
	offset = 0
	while offset <= 0x118:
		target = read_u32(base_int + offset)
		if target is None:
			write("  +0x%03x -> unreadable" % offset)
		else:
			marker = " <== distance/pass updater" if offset == 0xA0 else ""
			write("  +0x%03x -> 0x%08x %s%s" % (offset, target, function_label(target), marker))
		offset += 4
	find_refs_to(base_int, "vtable %s" % label)

def audit_vtable_field_methods():
	write("")
	write("=" * 70)
	write("INDIRECT PPLIGHTING METHODS TOUCHING CONTINUITY FIELDS")
	write("=" * 70)
	seen = set()
	patterns = ["0x34", "0x38", "0x60", "0x64", "0x74", "[0xd]", "[0xe]", "[0x18]", "[0x19]", "[0x1d]"]
	vtable_index = 0
	while vtable_index < len(PPLIGHTING_VTABLES):
		item = PPLIGHTING_VTABLES[vtable_index]
		offset = 0
		while offset <= 0x118:
			target = read_u32(item[0] + offset)
			if target is not None and target not in seen:
				seen.add(target)
				code = decompile_text(target)
				if code is not None:
					lower = code.lower()
					pattern_index = 0
					matched = False
					while pattern_index < len(patterns):
						if lower.find(patterns[pattern_index]) >= 0:
							matched = True
							break
						pattern_index += 1
					if matched:
						write("  vtable=%s slot=+0x%03x target=0x%08x %s" % (item[1], offset, target, function_label(target)))
						decompile_at(target, "indirect PPLighting continuity-field method")
						find_and_print_calls_from(target, "indirect PPLighting continuity-field method")
			offset += 4
		vtable_index += 1

def audit_target_list(targets, raw):
	index = 0
	while index < len(targets):
		item = targets[index]
		find_refs_to(item[0], item[1])
		decompile_at(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])
		print_field_scalar_hits(item[0], item[1])
		if raw:
			print_full_function_disassembly(item[0], item[1])
		checkpoint_output()
		index += 1

def audit_raw_functions():
	index = 0
	while index < len(RAW_FUNCTIONS):
		item = RAW_FUNCTIONS[index]
		print_full_function_disassembly(item[0], item[1])
		checkpoint_output()
		index += 1

def audit_callers():
	index = 0
	while index < len(CALLSITE_TARGETS):
		item = CALLSITE_TARGETS[index]
		print_callers_with_windows(item[0], item[1])
		checkpoint_output()
		index += 1

def audit_globals():
	index = 0
	while index < len(GLOBAL_TARGETS):
		item = GLOBAL_TARGETS[index]
		find_refs_to(item[0], item[1])
		index += 1

def audit_vtables():
	index = 0
	while index < len(PPLIGHTING_VTABLES):
		item = PPLIGHTING_VTABLES[index]
		print_vtable(item[0], item[1])
		index += 1

def audit_focus_windows():
	index = 0
	while index < len(FOCUS_WINDOWS):
		item = FOCUS_WINDOWS[index]
		disasm_window(item[0], item[1], item[2], item[3])
		index += 1

def print_questions():
	write("FNV PBR LIGHT SELECTION CONTINUITY CLOSURE")
	write("")
	write("Required closure:")
	write("1. Prove the exact camera/object distance operation and coordinate inputs.")
	write("2. Prove ownership and every mutation of the property light list at +0x60.")
	write("3. Prove sort keys, dirty flag +0x74, cache key +0x38, and update frequency.")
	write("4. Separate the 8-slot staging cap, 10-entry pass cap, and uncapped list count.")
	write("5. Prove whether sorting and truncation preserve outgoing-light fade continuity.")
	write("6. Normalize cache-hit refresh and pass rebuild behavior across all updater vtables.")
	write("7. Identify a safe engine-side intervention point if membership replacement is discontinuous.")
	write("")
	write("Raw x86 call setup and x87 comparisons are authoritative when decompiler types disagree.")

def main():
	print_questions()
	audit_vtables()
	audit_vtable_field_methods()
	checkpoint_output()
	audit_globals()
	checkpoint_output()
	audit_target_list(PRIMARY_TARGETS, False)
	audit_target_list(COMPANION_TARGETS, False)
	audit_raw_functions()
	audit_callers()
	audit_focus_windows()
	checkpoint_output()
	write("")
	write("OUTPUT COMPLETE: %s (%d lines)" % (OUTPATH, len(output)))

try:
	main()
finally:
	checkpoint_output()
	decomp.dispose()
