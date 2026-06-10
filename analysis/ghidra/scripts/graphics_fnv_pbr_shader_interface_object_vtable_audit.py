# @category Analysis
# @description Resolve FNV PBR shader-interface object constructors, vtables, and +0x78 apply targets

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00A5F860: "Reference/adopt helper used after shader selector creation",
	0x00B55560: "Shader-interface object selector",
	0x00B579E0: "Shader property selector attach helper",
	0x00B64BF0: "Selector interface warm-up caller",
	0x00B7A380: "B55560 selector index 1 factory",
	0x00B7A870: "Per-shader resource/constant initialization helper",
	0x00B7AF80: "Pass-selection helper before selector vtable +0xF0",
	0x00B7DAB0: "Pass-entry shader resource dispatcher",
	0x00B7E330: "Shader-interface object constructor/factory candidate",
	0x00BCCE40: "Current pass selector writer",
	0x00BD24C0: "Shader-interface field constructor writer",
	0x00BD4BA0: "Current pass shader-interface apply helper",
	0x00BD4750: "B55560 selector index 4 factory",
	0x00E7F430: "Shader-interface field setup helper",
	0x00E7F5D0: "Shader-interface field allocator/helper",
	0x00E7F990: "NiD3DPass apply helper",
	0x00BE08F0: "NiD3DPixelShader object initializer",
	0x00BE0B30: "NiD3DVertexShader object initializer",
	0x00BE1F90: "BSShader::SetShaders",
	0x010EF7D4: "NiD3DPixelShader vtable",
	0x010EF87C: "NiD3DVertexShader vtable",
	0x011F9548: "B55560 selector cache slot 0",
	0x011F954C: "B55560 selector cache slot 1",
	0x0126F74C: "Current NiD3DPass global",
}

FOCUS_FUNCTIONS = [
	0x00B55560,
	0x00B7A380,
	0x00BD4750,
	0x00B7E330,
	0x00E7F5D0,
	0x00E7F430,
	0x00B7AF80,
	0x00A5F860,
	0x00B579E0,
	0x00B64BF0,
	0x00B7A870,
	0x00BCCE40,
	0x00BD24C0,
	0x00BD4BA0,
	0x00B7DAB0,
	0x00E7F990,
	0x00BE08F0,
	0x00BE0B30,
	0x00BE1F90,
]

REF_TARGETS = [
	0x00B7A380,
	0x00BD4750,
	0x00B7E330,
	0x00E7F5D0,
	0x00E7F430,
	0x00B7AF80,
	0x00A5F860,
	0x010EF7D4,
	0x010EF87C,
	0x011F9548,
	0x011F954C,
]

DATA_WINDOWS = [
	(0x010EF7D4, 0, 48, "NiD3DPixelShader vtable"),
	(0x010EF87C, 0, 56, "NiD3DVertexShader vtable"),
	(0x011F9548, 0, 0x22, "B55560 selector cache array"),
]

SCAN_PATTERNS = [
	"011f9548",
	"011f954c",
	"0126f74c",
	"010ef7d4",
	"010ef87c",
	"b55560",
	"b7a380",
	"b7e330",
	"e7f5d0",
	"e7f430",
	"a5f860",
	"+ 0x30",
	"+0x30",
	"+ 0x34",
	"+0x34",
	"+ 0x44",
	"+0x44",
	"+ 0x5c",
	"+0x5c",
	"+ 0x78",
	"+0x78",
	"+ 0x7c",
	"+0x7c",
	"+ 0x80",
	"+0x80",
	"+ 0x84",
	"+0x84",
	"+ 0x88",
	"+0x88",
	"+ 0x8c",
	"+0x8c",
	"+ 0x9c",
	"+0x9c",
	"+ 0xf0",
	"+0xf0",
	"PTR_FUN",
	"SetPixelShader",
	"SetVertexShader",
	"SetPixelShaderConstant",
	"SetVertexShaderConstant",
	"constant",
	"texture",
	"shader",
	"pixel",
	"vertex",
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

def decompile_at(addr_int, label, max_len=26000):
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
		if count >= 160:
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
		if count >= 220:
			write("  ... (truncated)")
			break
	write("  Total matched lines: %d" % count)

def disasm_window(addr_int, before, count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, addr_int))
	write("-" * 70)
	start = addr_int - before
	inst = listing.getInstructionAt(toAddr(start))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start))
	seen = 0
	while inst is not None and seen < count:
		off = inst.getAddress().getOffset()
		marker = " << TARGET" if off == addr_int else ""
		write("  0x%08x: %-54s%s" % (off, inst.toString(), marker))
		seen += 1
		inst = inst.getNext()

def print_data_window(center_int, before_slots, after_slots, label):
	write("")
	write("-" * 70)
	write("DATA WINDOW: %s centered at 0x%08x" % (label, center_int))
	write("-" * 70)
	slot = -before_slots
	while slot <= after_slots:
		addr_int = center_int + slot * 4
		value = read_u32(addr_int)
		marker = " << CENTER" if addr_int == center_int else ""
		if value is None:
			write("  0x%08x slot %+04d: unreadable%s" % (addr_int, slot, marker))
		else:
			write("  0x%08x slot %+04d: 0x%08x  %s%s" % (addr_int, slot, value, label_for(value), marker))
		slot += 1

def decompile_function_values_from_data_windows():
	write("")
	write("=" * 70)
	write("DECOMPILE FUNCTION POINTERS FROM DATA WINDOWS")
	write("=" * 70)
	seen = {}
	total = 0
	for item in DATA_WINDOWS:
		center = item[0]
		before = item[1]
		after = item[2]
		slot = -before
		while slot <= after:
			value = read_u32(center + slot * 4)
			if value is not None and seen.get(value) is None:
				func = fm.getFunctionAt(toAddr(value))
				if func is not None:
					seen[value] = 1
					decompile_at(value, "data-window function pointer %s" % label_for(value), 14000)
					find_and_print_calls_from(value, label_for(value))
					scan_patterns(value, label_for(value), SCAN_PATTERNS)
					total += 1
					if total >= 96:
						write("  ... function pointer decompile truncated at 96")
						return
			slot += 1

def decompile_ref_callers(addr_int, label, limit):
	write("")
	write("=" * 70)
	write("DECOMPILE REF CALLERS: %s 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = {}
	count = 0
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is not None:
			entry = func.getEntryPoint().getOffset()
			if seen.get(entry) is None:
				seen[entry] = 1
				decompile_at(entry, "ref caller %s" % label, 18000)
				find_and_print_calls_from(entry, "ref caller %s" % label)
				scan_patterns(entry, "ref caller %s" % label, SCAN_PATTERNS)
				count += 1
				if count >= limit:
					write("  ... ref caller decompile truncated")
					return

def print_selector_slot_refs():
	write("")
	write("=" * 70)
	write("B55560 SELECTOR CACHE SLOT REFERENCES")
	write("=" * 70)
	index = 0
	while index <= 0x22:
		addr_int = 0x011F9548 + index * 4
		find_refs_to(addr_int, "B55560 selector cache slot %d" % index)
		index += 1

def decompile_focus_functions():
	for addr_int in FOCUS_FUNCTIONS:
		decompile_at(addr_int, label_for(addr_int))
		find_and_print_calls_from(addr_int, label_for(addr_int))
		scan_patterns(addr_int, label_for(addr_int), SCAN_PATTERNS)

def print_all_refs():
	for addr_int in REF_TARGETS:
		find_refs_to(addr_int, label_for(addr_int))

def print_all_data_windows():
	for item in DATA_WINDOWS:
		print_data_window(item[0], item[1], item[2], item[3])

def print_focus_disasm():
	for addr_int in FOCUS_FUNCTIONS:
		disasm_window(addr_int, 20, 120, label_for(addr_int))

def decompile_targeted_ref_callers():
	decompile_ref_callers(0x00B7A380, "selector index 1 factory", 12)
	decompile_ref_callers(0x00B7E330, "shader-interface object constructor/factory candidate", 18)
	decompile_ref_callers(0x00E7F5D0, "shader-interface field allocator/helper", 18)
	decompile_ref_callers(0x00E7F430, "shader-interface field setup helper", 18)
	decompile_ref_callers(0x010EF7D4, "NiD3DPixelShader vtable", 12)
	decompile_ref_callers(0x010EF87C, "NiD3DVertexShader vtable", 12)

def main():
	write("FNV PBR SHADER INTERFACE OBJECT/VTABLE AUDIT")
	write("")
	write("Questions:")
	write("1. Which factory builds B55560 selector cache slot 1, and what vtable/object layout does it install?")
	write("2. Which writers populate selector/object +0x30 and +0x34?")
	write("3. What concrete functions live at the shader-interface objects' vtable +0x78 slots?")
	write("4. What do NiD3DPixelShader/NiD3DVertexShader vtable slots around +0x7C..+0x9C do?")
	write("")
	write("Compatibility rule:")
	write("Visible native PBR shader replacement remains unsafe until selector +0x30/+0x34 ownership and +0x78 behavior are proven.")
	print_focus_disasm()
	print_all_refs()
	print_selector_slot_refs()
	print_all_data_windows()
	decompile_focus_functions()
	decompile_targeted_ref_callers()
	decompile_function_values_from_data_windows()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_shader_interface_object_vtable_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
