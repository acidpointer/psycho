# @category Analysis
# @description Audit FNV PBR shader creation callsite arguments, globals, and NiD3D shader handle vtables

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00B74000: "selector +0x148 vertex create group A",
	0x00B740B3: "selector +0x148 vertex create group B",
	0x00B7419F: "selector +0x148 vertex create group C",
	0x00B78720: "selector +0x14C pixel create group A",
	0x00B78907: "selector +0x14C pixel create group B",
	0x00BE0FE0: "BSShader::CreateVertexShader",
	0x00BE1750: "BSShader::CreatePixelShader",
	0x00BE1F90: "BSShader::SetShaders",
	0x00BD4BA0: "current-pass shader-interface apply",
	0x010EF87C: "NiD3DVertexShader vtable",
	0x010EF7D4: "NiD3DPixelShader vtable",
	0x011FDD88: "PPLighting vertex shader global group A",
	0x011FDE04: "PPLighting vertex shader global group B",
	0x011FDE5C: "PPLighting vertex shader global group C",
	0x011FDA48: "PPLighting pixel shader global group A",
	0x011FDB08: "PPLighting pixel shader global group B",
}

CREATE_CALLS = [
	(0x00B74000, 0x00BE0FE0, "selector +0x148 vertex group A", 0x011FDD88),
	(0x00B740B3, 0x00BE0FE0, "selector +0x148 vertex group B", 0x011FDE04),
	(0x00B7419F, 0x00BE0FE0, "selector +0x148 vertex group C", 0x011FDE5C),
	(0x00B78720, 0x00BE1750, "selector +0x14C pixel group A", 0x011FDA48),
	(0x00B78907, 0x00BE1750, "selector +0x14C pixel group B", 0x011FDB08),
]

GLOBAL_ARRAYS = [
	(0x011FDD88, "vertex shader group A", 0x1F),
	(0x011FDE04, "vertex shader group B", 0x16),
	(0x011FDE5C, "vertex shader group C", 0x67),
	(0x011FDA48, "pixel shader group A", 0x30),
	(0x011FDB08, "pixel shader group B", 0xA0),
]

VTABLE_WINDOWS = [
	(0x010EF87C, "NiD3DVertexShader vtable", 0x70, 0x98),
	(0x010EF7D4, "NiD3DPixelShader vtable", 0x70, 0x90),
]

FOCUS_FUNCTIONS = [
	0x00BE0FE0,
	0x00BE1750,
	0x00BE1F90,
	0x00BD4BA0,
]

SCAN_PATTERNS = [
	"CreateVertexShader",
	"CreatePixelShader",
	"SetShaders",
	"FUN_00be0fe0",
	"FUN_00be1750",
	"FUN_00be1f90",
	"FUN_00bd4ba0",
	"+ 0x2c",
	"+0x2c",
	"+ 0x30",
	"+0x30",
	"+ 0x34",
	"+0x34",
	"+ 0x38",
	"+0x38",
	"+ 0x44",
	"+0x44",
	"+ 0x5c",
	"+0x5c",
	"+ 0x7c",
	"+0x7c",
	"+ 0x80",
	"+0x80",
	"+ 0x84",
	"+0x84",
	"+ 0x88",
	"+0x88",
	"0x11fdd88",
	"0x11fde04",
	"0x11fde5c",
	"0x11fda48",
	"0x11fdb08",
	"shader",
]

def write(msg):
	output.append(msg)
	print(msg)

def read_u32(addr_int):
	try:
		value = memory.getInt(toAddr(addr_int))
		if value < 0:
			value += 0x100000000
		return value
	except:
		return None

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
	if len(chars) < 3:
		return None
	return "".join(chars)

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
	text = read_c_string(addr_int, 96)
	if text is not None:
		return "\"%s\"" % text
	return "unknown"

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

def decompile_at(addr_int, label, max_len=30000):
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
		write("  NOTE: requested address is inside function at +0x%x" % (addr_int - faddr))
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
		if count >= 220:
			write("  ... (truncated)")
			break
	write("  Total printed: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
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

def collect_prev_instructions(inst, count):
	items = []
	current = inst
	seen = 0
	while current is not None and seen < count:
		current = current.getPrevious()
		if current is None:
			break
		items.append(current)
		seen += 1
	items.reverse()
	return items

def print_instruction(inst, target_addr):
	off = inst.getAddress().getOffset()
	marker = " << TARGET" if off == target_addr else ""
	write("  0x%08x: %-54s%s" % (off, inst.toString(), marker))
	refs = inst.getReferencesFrom()
	for ref in refs:
		to_addr = ref.getToAddress()
		to_int = to_addr.getOffset()
		text = read_c_string(to_int, 96)
		if text is None:
			write("      ref %s -> 0x%08x %s" % (ref.getReferenceType(), to_int, label_for(to_int)))
		else:
			write("      ref %s -> 0x%08x \"%s\"" % (ref.getReferenceType(), to_int, text))

def disasm_around_call(addr_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("CALLSITE WINDOW: %s around 0x%08x" % (label, addr_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(addr_int))
	if inst is None:
		inst = listing.getInstructionContaining(toAddr(addr_int))
	if inst is None:
		write("  [instruction not found]")
		return
	prev_items = collect_prev_instructions(inst, before_count)
	for prev in prev_items:
		print_instruction(prev, addr_int)
	print_instruction(inst, addr_int)
	current = inst
	seen = 0
	while seen < after_count:
		current = current.getNext()
		if current is None:
			break
		print_instruction(current, addr_int)
		seen += 1

def print_callsite_windows():
	for item in CREATE_CALLS:
		disasm_around_call(item[0], 36, 34, "%s -> %s, stores global 0x%08x" % (item[2], label_for(item[1]), item[3]))

def print_global_array_refs():
	for item in GLOBAL_ARRAYS:
		find_refs_to(item[0], item[1])

def print_vtable_window(vtable, label, start_offset, end_offset):
	write("")
	write("=" * 70)
	write("VTABLE WINDOW: %s 0x%08x offsets 0x%03x..0x%03x" % (label, vtable, start_offset, end_offset))
	write("=" * 70)
	offset = start_offset
	while offset <= end_offset:
		value = read_u32(vtable + offset)
		if value is None:
			write("  +0x%03x @ 0x%08x: unreadable" % (offset, vtable + offset))
		else:
			write("  +0x%03x @ 0x%08x -> 0x%08x %s" % (offset, vtable + offset, value, label_for(value)))
		offset += 4

def decompile_vtable_targets():
	seen = {}
	for item in VTABLE_WINDOWS:
		vtable = item[0]
		offset = item[2]
		while offset <= item[3]:
			value = read_u32(vtable + offset)
			if value is not None and seen.get(value) is None:
				seen[value] = 1
				decompile_at(value, "%s slot +0x%03x" % (item[1], offset), 18000)
				find_and_print_calls_from(value, "%s slot +0x%03x" % (item[1], offset))
				scan_patterns(value, "%s slot +0x%03x" % (item[1], offset), SCAN_PATTERNS)
			offset += 4

def print_all_vtable_windows():
	for item in VTABLE_WINDOWS:
		print_vtable_window(item[0], item[1], item[2], item[3])

def scan_patterns(addr_int, label, patterns):
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
		for pattern in patterns:
			if pattern.lower() in lower:
				write("  %s" % line)
				count += 1
				break
		if count >= 240:
			write("  ... (truncated)")
			break
	write("  Total matched lines: %d" % count)

def decompile_focus_functions():
	for addr_int in FOCUS_FUNCTIONS:
		decompile_at(addr_int, label_for(addr_int), 32000)
		find_and_print_calls_from(addr_int, label_for(addr_int))
		scan_patterns(addr_int, label_for(addr_int), SCAN_PATTERNS)

def main():
	write("FNV PBR SHADER CREATION CALLSITE ARGUMENT AUDIT")
	write("")
	write("Questions:")
	write("1. What paths, defines, profiles, and cache names are passed into PPLighting create calls?")
	write("2. Which global arrays receive returned NiD3D shader objects, and with what ref-count handoff?")
	write("3. Which NiD3D vtable slots get/set native D3D shader handles used by SetShaders?")
	write("4. Can Psycho key replacement side tables by returned NiD3D shader object without mutating layout?")
	write("")
	write("Compatibility rule:")
	write("Visible PBR replacement remains disabled until these callsite and handle-slot contracts are proven.")
	print_callsite_windows()
	print_global_array_refs()
	print_all_vtable_windows()
	decompile_vtable_targets()
	decompile_focus_functions()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_shader_creation_callsite_args_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
