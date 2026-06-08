# @category Analysis
# @description Audit FNV BSFogProperty layout and active scene-node fog pointer contract for Psycho Graphics

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00450B80: "BSShaderManager::GetShadowSceneNode",
	0x0047C070: "Fog-property field writer candidate 0047C070",
	0x0047D130: "Fog-property field reader candidate 0047D130",
	0x0047D220: "Fog-property field reader candidate 0047D220",
	0x0047D410: "Fog-property field reader candidate 0047D410",
	0x00479570: "Scene/fog candidate 00479570",
	0x004804D0: "Fog-property field reader candidate 004804D0",
	0x00480570: "Fog-property field reader candidate 00480570",
	0x004807A0: "Fog-property field reader candidate 004807A0",
	0x004808F0: "Fog-property field reader candidate 004808F0",
	0x00483D20: "Fog-property field reader candidate 00483D20",
	0x004867A0: "Scene/fog candidate 004867A0",
	0x004E20F0: "BSShaderManager scene graph index writer 004E20F0",
	0x00B5A220: "Shader camera fog constant writer 00B5A220",
	0x00B5E870: "CameraWriter 00B5E870",
	0x00BB8180: "BSFogProperty constructor candidate 00BB8180",
	0x00BB8250: "BSFogProperty constructor candidate 00BB8250",
	0x00BD66C0: "Shader camera fog constant writer 00BD66C0",
	0x010B9E38: "BSFogProperty vtable candidate",
	0x011F917C: "BSShaderManager::pCurrentCamera",
	0x011F91C4: "BSShaderManager::ucSceneGraph",
	0x011F91C8: "BSShaderManager::ShadowSceneNode array",
}

TARGET_FUNCTIONS = [
	0x00450B80,
	0x004E20F0,
	0x00B5E870,
	0x00B5A220,
	0x00BD66C0,
	0x00BB8180,
	0x00BB8250,
	0x0047C070,
	0x0047D130,
	0x0047D220,
	0x0047D410,
	0x004804D0,
	0x00480570,
	0x004807A0,
	0x004808F0,
	0x00483D20,
	0x00479570,
	0x004867A0,
]

REF_TARGETS = [
	0x010B9E38,
	0x011F917C,
	0x011F91C4,
	0x011F91C8,
	0x00450B80,
]

FIELD_WINDOWS = [
	0x00BB81F1,
	0x00BB8253,
	0x0047C1C4,
	0x0047C1E4,
	0x0047C364,
	0x0047D17B,
	0x0047D26C,
	0x0047D46B,
	0x0047D47B,
	0x00480527,
	0x004805B9,
	0x00480869,
	0x00480A00,
	0x00483D44,
	0x004796E1,
	0x00486807,
	0x00486840,
	0x00B5A232,
	0x00B5A241,
	0x00BD66C8,
	0x00BD66D5,
]

MATCH_PATTERNS = [
	"+ 0x2c",
	"+ 0x30",
	"+ 0x60",
	"+ 0x134",
	"+ 0xec",
	"+ 0xf0",
	"011f917c",
	"011f91c4",
	"011f91c8",
	"10b9e38",
]

def write(msg):
	output.append(msg)
	print(msg)

def label_for(addr_int):
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

def function_for(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	return func

def decompile_text_for_func(func):
	if func is None:
		return None
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		return result.getDecompiledFunction().getC()
	return None

def decompile_at(addr_int, label, max_len=18000):
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
	code = decompile_text_for_func(func)
	if code is None:
		write("  [decompilation failed]")
		return
	write(code[:max_len])

def line_matches(line):
	lower = line.lower()
	idx = 0
	while idx < len(MATCH_PATTERNS):
		if lower.find(MATCH_PATTERNS[idx]) >= 0:
			return True
		idx += 1
	return False

def print_matching_lines_for_func(func, label):
	write("")
	write("=" * 70)
	write("CONTRACT MATCHES: %s @ 0x%08x" % (label, func.getEntryPoint().getOffset()))
	write("=" * 70)
	code = decompile_text_for_func(func)
	if code is None:
		write("  [decompilation failed]")
		return
	lines = code.split("\n")
	idx = 0
	count = 0
	while idx < len(lines):
		line = lines[idx]
		if line_matches(line):
			write("  L%04d: %s" % (idx + 1, line))
			count += 1
		idx += 1
	write("  Total matched lines: %d" % count)

def print_matching_decompile_lines(addr_int, label):
	func = function_for(addr_int)
	if func is None:
		write("")
		write("=" * 70)
		write("CONTRACT MATCHES: %s @ 0x%08x" % (label, addr_int))
		write("=" * 70)
		write("  [function not found]")
		return
	print_matching_lines_for_func(func, label)

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
		if count > 120:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	func = function_for(addr_int)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, label_for(tgt)))
				count += 1
	write("  Total: %d calls" % count)

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionBefore(toAddr(center_int))
	count = 0
	while inst is not None and count < before_count:
		prev = inst.getPrevious()
		if prev is None:
			break
		inst = prev
		count += 1
	idx = 0
	limit = before_count + after_count + 1
	while inst is not None and idx < limit:
		addr_int = inst.getAddress().getOffset()
		marker = " << TARGET" if addr_int == center_int else ""
		extra = ""
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				extra = "%s ; CALL 0x%08x %s" % (extra, tgt, label_for(tgt))
		write("  0x%08x: %-52s%s%s" % (addr_int, inst.toString(), marker, extra))
		inst = inst.getNext()
		idx += 1

def read_u32(addr_int):
	try:
		value = memory.getInt(toAddr(addr_int))
		if value < 0:
			value = value + 0x100000000
		return value
	except:
		return None

def dump_vtable(addr_int, count):
	write("")
	write("=" * 70)
	write("VTABLE DUMP %s @ 0x%08x" % (label_for(addr_int), addr_int))
	write("=" * 70)
	idx = 0
	while idx < count:
		entry_addr = addr_int + idx * 4
		value = read_u32(entry_addr)
		if value is None:
			write("  [%02d] 0x%08x -> [read failed]" % (idx, entry_addr))
		else:
			write("  [%02d] 0x%08x -> 0x%08x %s" % (idx, entry_addr, value, label_for(value)))
		idx += 1

def decompile_vtable_entries(addr_int, count):
	write("")
	write("=" * 70)
	write("DECOMPILE VTABLE ENTRIES THAT TOUCH FOG FIELDS")
	write("=" * 70)
	idx = 0
	while idx < count:
		value = read_u32(addr_int + idx * 4)
		if value is not None:
			func = fm.getFunctionAt(toAddr(value))
			if func is not None:
				code = decompile_text_for_func(func)
				if code is not None and code.lower().find("+ 0x2c") >= 0:
					decompile_at(value, "vtable[%02d] %s" % (idx, label_for(value)), 14000)
					print_matching_lines_for_func(func, "vtable[%02d] %s" % (idx, label_for(value)))
				elif code is not None and code.lower().find("+ 0x30") >= 0:
					decompile_at(value, "vtable[%02d] %s" % (idx, label_for(value)), 14000)
					print_matching_lines_for_func(func, "vtable[%02d] %s" % (idx, label_for(value)))
				elif code is not None and code.lower().find("+ 0x60") >= 0:
					decompile_at(value, "vtable[%02d] %s" % (idx, label_for(value)), 14000)
					print_matching_lines_for_func(func, "vtable[%02d] %s" % (idx, label_for(value)))
		idx += 1

def collect_ref_functions(addr_int, functions):
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is not None:
			functions[func.getEntryPoint().getOffset()] = True

def function_instruction_has(func, needle):
	inst_iter = listing.getInstructions(func.getBody(), True)
	lower_needle = needle.lower()
	while inst_iter.hasNext():
		inst = inst_iter.next()
		if inst.toString().lower().find(lower_needle) >= 0:
			return True
	return False

def function_has_data_ref_to(func, target_int):
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getToAddress().getOffset() == target_int:
				return True
	return False

def audit_scene_ref_functions():
	write("")
	write("=" * 70)
	write("SCENE NODE FUNCTIONS THAT ALSO TOUCH +0x134")
	write("=" * 70)
	functions = {}
	collect_ref_functions(0x011F91C8, functions)
	collect_ref_functions(0x00450B80, functions)
	keys = functions.keys()
	keys.sort()
	idx = 0
	printed = 0
	while idx < len(keys):
		addr = keys[idx]
		func = function_for(addr)
		if func is not None:
			has_scene = function_has_data_ref_to(func, 0x011F91C8) or function_has_data_ref_to(func, 0x00450B80)
			has_134 = function_instruction_has(func, "+ 0x134") or function_instruction_has(func, "+0x134")
			if has_scene and has_134:
				decompile_at(addr, "scene-node +0x134 candidate %s" % label_for(addr), 16000)
				print_matching_lines_for_func(func, "scene-node +0x134 candidate %s" % label_for(addr))
				printed += 1
				if printed >= 20:
					write("  ... scene-node +0x134 candidate scan truncated")
					break
		idx += 1
	write("  Printed candidates: %d" % printed)

def audit_target_functions():
	idx = 0
	while idx < len(TARGET_FUNCTIONS):
		addr = TARGET_FUNCTIONS[idx]
		decompile_at(addr, label_for(addr), 22000)
		find_and_print_calls_from(addr, label_for(addr))
		print_matching_decompile_lines(addr, label_for(addr))
		idx += 1

def audit_refs():
	idx = 0
	while idx < len(REF_TARGETS):
		addr = REF_TARGETS[idx]
		find_refs_to(addr, label_for(addr))
		idx += 1

def audit_windows():
	idx = 0
	while idx < len(FIELD_WINDOWS):
		addr = FIELD_WINDOWS[idx]
		disasm_window(addr, 16, 28, label_for(addr))
		idx += 1

def print_header():
	write("FNV GRAPHICS BSFOGPROPERTY LAYOUT AUDIT")
	write("")
	write("Questions:")
	write("1. Does BSFogProperty vtable 0x010B9E38 identify constructors/methods for this object?")
	write("2. Do BSFogProperty methods or constructors prove fields +0x2C/+0x30/+0x60?")
	write("3. Which functions touch ShadowSceneNode array 0x011F91C8 or GetShadowSceneNode and also read +0x134?")
	write("4. Is the camera fog fallback pCurrentCamera +0xEC/+0xF0 still proven by shader constant writers?")

def main():
	print_header()
	dump_vtable(0x010B9E38, 48)
	decompile_vtable_entries(0x010B9E38, 48)
	audit_target_functions()
	audit_refs()
	audit_windows()
	audit_scene_ref_functions()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_bsfogproperty_layout_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
