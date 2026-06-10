# @category Analysis
# @description Resolve FNV PBR selector setup vtable slots that create shader-interface fields

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00B55560: "Shader-interface object selector cache",
	0x00B7A380: "Selector index 1 factory",
	0x00B79B00: "Selector base constructor",
	0x00BE2200: "Selector superclass constructor",
	0x00B7E330: "Shader-interface field object constructor",
	0x00E87690: "Shader-interface field object constructor variant",
	0x00B7AF80: "Current pass selector writer helper",
	0x00BD4BA0: "Current pass shader-interface apply helper",
	0x00B7DAB0: "Pass-entry shader resource dispatcher",
	0x00E826D0: "Shader-interface constant apply dispatcher",
	0x010AF2F8: "Selector index 1/base vtable",
	0x010EF544: "Shader-interface field object vtable",
	0x010F003C: "Shader-interface nested constant map vtable",
	0x0126F74C: "Current NiD3DPass global",
}

FOCUS_FUNCTIONS = [
	0x00B55560,
	0x00B7A380,
	0x00B79B00,
	0x00BE2200,
	0x00B7E330,
	0x00E87690,
	0x00B7AF80,
	0x00BD4BA0,
	0x00B7DAB0,
	0x00E826D0,
]

REF_TARGETS = [
	0x010AF2F8,
	0x00BE2200,
	0x00B7E330,
	0x00E87690,
	0x010EF544,
	0x010F003C,
	0x00E826D0,
]

DATA_WINDOWS = [
	(0x010AF2F8, 0, 100, "Selector index 1/base vtable"),
	(0x010EF544, 0, 42, "Shader-interface field object vtable"),
	(0x010F003C, 0, 62, "Shader-interface nested constant map vtable"),
]

TARGET_SLOTS = [
	(0x010AF2F8, 0x04C, "selector setup slot +0x4C"),
	(0x010AF2F8, 0x0C0, "selector setup slot +0xC0"),
	(0x010AF2F8, 0x11C, "selector setup slot +0x11C"),
	(0x010AF2F8, 0x144, "selector setup slot +0x144"),
	(0x010AF2F8, 0x150, "selector setup slot +0x150"),
	(0x010EF544, 0x078, "shader-interface apply slot +0x78"),
	(0x010EF544, 0x08C, "shader-interface type-2 helper slot +0x8C"),
	(0x010EF544, 0x090, "shader-interface type-1 helper slot +0x90"),
	(0x010EF544, 0x094, "shader-interface type-3 helper slot +0x94"),
	(0x010EF544, 0x098, "shader-interface type-4 helper slot +0x98"),
	(0x010EF544, 0x09C, "shader-interface type-5 helper slot +0x9C"),
	(0x010EF544, 0x0A4, "shader-interface type-6 helper slot +0xA4"),
]

SCAN_PATTERNS = [
	"010af2f8",
	"010ef544",
	"010f003c",
	"b7e330",
	"e87690",
	"e826d0",
	"+ 0x30",
	"+0x30",
	"+ 0x34",
	"+0x34",
	"+ 0x4c",
	"+0x4c",
	"+ 0x78",
	"+0x78",
	"+ 0x8c",
	"+0x8c",
	"+ 0x90",
	"+0x90",
	"+ 0x94",
	"+0x94",
	"+ 0x98",
	"+0x98",
	"+ 0x9c",
	"+0x9c",
	"+ 0xa4",
	"+0xa4",
	"+ 0xc0",
	"+0xc0",
	"+ 0x11c",
	"+0x11c",
	"+ 0x144",
	"+0x144",
	"+ 0x150",
	"+0x150",
	"SetPixelShaderConstant",
	"SetVertexShaderConstant",
	"constant",
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
		if count >= 200:
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
		if count >= 260:
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
			write("  0x%08x slot %+04d offset %+04x: unreadable%s" % (addr_int, slot, slot * 4, marker))
		else:
			write("  0x%08x slot %+04d offset %+04x: 0x%08x  %s%s" % (addr_int, slot, slot * 4, value, label_for(value), marker))
		slot += 1

def print_target_slots():
	write("")
	write("=" * 70)
	write("TARGET VTABLE SLOTS")
	write("=" * 70)
	for item in TARGET_SLOTS:
		vtable = item[0]
		offset = item[1]
		label = item[2]
		value = read_u32(vtable + offset)
		if value is None:
			write("  %s vtable=0x%08x offset=0x%03x unreadable" % (label, vtable, offset))
		else:
			write("  %s vtable=0x%08x offset=0x%03x -> 0x%08x %s" % (label, vtable, offset, value, label_for(value)))

def decompile_target_slots():
	write("")
	write("=" * 70)
	write("DECOMPILE TARGET VTABLE SLOT FUNCTIONS")
	write("=" * 70)
	seen = {}
	for item in TARGET_SLOTS:
		value = read_u32(item[0] + item[1])
		if value is not None and seen.get(value) is None:
			seen[value] = 1
			decompile_at(value, item[2], 30000)
			find_and_print_calls_from(value, item[2])
			scan_patterns(value, item[2], SCAN_PATTERNS)

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
					decompile_at(value, "data-window function pointer %s" % label_for(value), 18000)
					find_and_print_calls_from(value, label_for(value))
					scan_patterns(value, label_for(value), SCAN_PATTERNS)
					total += 1
					if total >= 140:
						write("  ... function pointer decompile truncated at 140")
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
				decompile_at(entry, "ref caller %s" % label, 24000)
				find_and_print_calls_from(entry, "ref caller %s" % label)
				scan_patterns(entry, "ref caller %s" % label, SCAN_PATTERNS)
				count += 1
				if count >= limit:
					write("  ... ref caller decompile truncated")
					return

def print_focus_disasm():
	for addr_int in FOCUS_FUNCTIONS:
		disasm_window(addr_int, 24, 160, label_for(addr_int))

def decompile_focus_functions():
	for addr_int in FOCUS_FUNCTIONS:
		decompile_at(addr_int, label_for(addr_int), 30000)
		find_and_print_calls_from(addr_int, label_for(addr_int))
		scan_patterns(addr_int, label_for(addr_int), SCAN_PATTERNS)

def print_all_refs():
	for addr_int in REF_TARGETS:
		find_refs_to(addr_int, label_for(addr_int))

def print_all_data_windows():
	for item in DATA_WINDOWS:
		print_data_window(item[0], item[1], item[2], item[3])

def decompile_targeted_ref_callers():
	decompile_ref_callers(0x010AF2F8, "selector base vtable", 20)
	decompile_ref_callers(0x00BE2200, "selector superclass constructor", 20)
	decompile_ref_callers(0x00B7E330, "shader-interface field object constructor", 20)
	decompile_ref_callers(0x00E87690, "shader-interface field object constructor variant", 20)
	decompile_ref_callers(0x00E826D0, "shader-interface constant apply dispatcher", 20)

def main():
	write("FNV PBR SELECTOR SETUP VTABLE DEEP AUDIT")
	write("")
	write("Questions:")
	write("1. What concrete functions are selector vtable slots +0x4C/+0xC0/+0x11C/+0x144/+0x150?")
	write("2. Which setup slots create or assign selector +0x30/+0x34/+0x7C/+0x80 interface fields?")
	write("3. Are selector +0x30/+0x34 always shader-interface field objects with vtable 0x010EF544 for index 1?")
	write("4. Does any setup slot mutate native shader handles or only constant maps/interface records?")
	write("")
	write("Compatibility rule:")
	write("Do not enable visible native PBR shader replacement until this output proves selector setup ownership and a safe replacement lifecycle.")
	print_focus_disasm()
	print_all_refs()
	print_all_data_windows()
	print_target_slots()
	decompile_focus_functions()
	decompile_target_slots()
	decompile_targeted_ref_callers()
	decompile_function_values_from_data_windows()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_selector_setup_vtable_deep_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
