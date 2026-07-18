# @category Analysis
# @description Audit FNV ShadowSceneLight classification and close-terrain portable point-light membership

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

OUTPATH = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_close_terrain_portable_light_classification_audit.txt"

TARGETS = [
	(0x00B70390, "PPLighting light-list sorter"),
	(0x00B70590, "first active general light iterator"),
	(0x00B70600, "first active non-shadow light iterator"),
	(0x00B70680, "next active general light iterator"),
	(0x00B70700, "next active non-shadow light iterator"),
	(0x00B70820, "native selected-light constant staging"),
	(0x00B78A90, "ShadowLightShader light constant owner"),
	(0x00BDF3E0, "vanilla close-land light pass builder"),
]

CLASSIFICATION_OFFSETS = [
	(0xEC, "ShadowSceneLight.is_shadow_casting"),
	(0xF4, "ShadowSceneLight.is_point_light"),
	(0xF5, "ShadowSceneLight.is_ambient_light"),
	(0x110, "ShadowSceneLight.enabled_or_state"),
]

PORTABLE_LIGHT_TERMS = ["pipboy", "pip-boy", "torch", "flashlight"]

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
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found at 0x%08x]" % addr_int)
		return
	body = func.getBody()
	inst_iter = currentProgram.getListing().getInstructions(body, True)
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

def compact_operand(text):
	return text.lower().replace(" ", "")

def instruction_writes_displacement(inst, offset):
	mnemonic = inst.getMnemonicString().upper()
	write_like = mnemonic in ["MOV", "AND", "OR", "XOR", "INC", "DEC"] or mnemonic.startswith("SET")
	if not write_like or inst.getNumOperands() == 0:
		return False
	operand = compact_operand(inst.getDefaultOperandRepresentation(0))
	needle = "+0x%x]" % offset
	return needle in operand

def scan_classification_writers():
	write("")
	write("=" * 70)
	write("SHADOWSCENELIGHT CLASSIFICATION FIELD WRITERS")
	write("=" * 70)
	hits = []
	seen_functions = {}
	inst_iter = listing.getInstructions(True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		index = 0
		while index < len(CLASSIFICATION_OFFSETS):
			item = CLASSIFICATION_OFFSETS[index]
			if instruction_writes_displacement(inst, item[0]):
				func = fm.getFunctionContaining(inst.getAddress())
				fname = func.getName() if func else "???"
				entry = func.getEntryPoint().getOffset() if func else 0
				hits.append((inst.getAddress().getOffset(), item[0], item[1], fname, inst.toString()))
				if func is not None:
					seen_functions[entry] = func
			index += 1
	write("Potential writes: %d" % len(hits))
	index = 0
	while index < len(hits):
		item = hits[index]
		write("  0x%08x  +0x%03x %-42s in %-24s %s" % (item[0], item[1], item[2], item[3], item[4]))
		index += 1
	entries = seen_functions.keys()
	entries.sort()
	write("")
	write("Unique containing functions: %d" % len(entries))
	index = 0
	while index < len(entries):
		entry = entries[index]
		func = seen_functions[entry]
		decompile_at(entry, "classification writer %s" % func.getName(), 24000)
		find_and_print_calls_from(entry, "classification writer %s" % func.getName())
		checkpoint_output()
		index += 1

def string_matches_portable_light(value):
	lower = value.lower()
	index = 0
	while index < len(PORTABLE_LIGHT_TERMS):
		if PORTABLE_LIGHT_TERMS[index] in lower:
			return True
		index += 1
	return False

def scan_portable_light_strings():
	write("")
	write("=" * 70)
	write("PORTABLE LIGHT STRING REFERENCES")
	write("=" * 70)
	data_iter = listing.getDefinedData(True)
	seen_functions = {}
	string_count = 0
	while data_iter.hasNext():
		data = data_iter.next()
		if not data.hasStringValue():
			continue
		value = str(data.getValue())
		if not string_matches_portable_light(value):
			continue
		address = data.getAddress()
		write("  0x%08x %s" % (address.getOffset(), value))
		string_count += 1
		refs = ref_mgr.getReferencesTo(address)
		while refs.hasNext():
			ref = refs.next()
			func = fm.getFunctionContaining(ref.getFromAddress())
			fname = func.getName() if func else "???"
			write("    %s @ 0x%08x in %s" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
			if func is not None:
				seen_functions[func.getEntryPoint().getOffset()] = func
	write("Matched strings: %d" % string_count)
	entries = seen_functions.keys()
	entries.sort()
	write("Unique referencing functions: %d" % len(entries))
	index = 0
	while index < len(entries):
		entry = entries[index]
		func = seen_functions[entry]
		decompile_at(entry, "portable light string user %s" % func.getName(), 24000)
		find_and_print_calls_from(entry, "portable light string user %s" % func.getName())
		checkpoint_output()
		index += 1

def audit_targets():
	index = 0
	while index < len(TARGETS):
		item = TARGETS[index]
		find_refs_to(item[0], item[1])
		decompile_at(item[0], item[1], 30000)
		find_and_print_calls_from(item[0], item[1])
		checkpoint_output()
		index += 1

def main():
	write("FNV CLOSE-TERRAIN PORTABLE POINT-LIGHT CLASSIFICATION AUDIT")
	write("")
	write("Questions:")
	write("1. Which functions assign ShadowSceneLight +0xEC shadow-casting state?")
	write("2. How are +0xF4 point lights and +0x110 active state initialized with it?")
	write("3. Do Pip-Boy, torch, or flashlight paths identify the same light owner?")
	write("4. Why do the non-shadow iterators exclude a light that object passes can still consume?")
	write("5. Is the safe correction in light classification, landscape pass membership, or neither?")
	audit_targets()
	scan_classification_writers()
	scan_portable_light_strings()
	checkpoint_output()
	write("")
	write("OUTPUT COMPLETE: %s (%d lines)" % (OUTPATH, len(output)))

try:
	main()
finally:
	checkpoint_output()
	decomp.dispose()
