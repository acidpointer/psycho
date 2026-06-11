# @category Analysis
# @description Audit FNV PPLighting shader array to pass pixel/vertex pair contract for native PBR replacement

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x011FDD88: "PPLighting vertex shader global group A",
	0x011FDE04: "PPLighting vertex shader global group B",
	0x011FDE5C: "PPLighting vertex shader global group C",
	0x011FDA48: "PPLighting pixel shader global group A",
	0x011FDB08: "PPLighting pixel shader global group B",
	0x0126F74C: "Current NiD3DPass global",
	0x00BD16F0: "current-pass shader creator/writer",
	0x00BD1C50: "current-pass writer and pixel shader owner updater",
	0x00BD4BA0: "current-pass shader-interface apply",
	0x00BE1F90: "BSShader::SetShaders raw entry",
	0x00BE22B0: "PPLighting global shader array reader candidate A",
	0x00BEB070: "PPLighting global shader array reader candidate B",
	0x00BEB830: "PPLighting global shader array reader candidate C",
	0x00BEBD20: "PPLighting global shader array reader candidate D",
	0x00C17510: "PPLighting pixel group B reader candidate",
}

GLOBAL_ARRAYS = [
	(0x011FDD88, "vertex group A", 0x1F),
	(0x011FDE04, "vertex group B", 0x16),
	(0x011FDE5C, "vertex group C", 0x67),
	(0x011FDA48, "pixel group A", 0x30),
	(0x011FDB08, "pixel group B", 0xA0),
]

FOCUS_FUNCTIONS = [
	0x00BE22B0,
	0x00BEB070,
	0x00BEB830,
	0x00BEBD20,
	0x00C17510,
	0x00BD16F0,
	0x00BD1C50,
	0x00BD4BA0,
	0x00BE1F90,
]

RAW_WINDOWS = [
	(0x00BE22B0, 0x20, 0xD0, "PPLighting reader A"),
	(0x00BEB070, 0x20, 0xD0, "PPLighting reader B"),
	(0x00BEB830, 0x20, 0xD0, "PPLighting reader C"),
	(0x00BEBD20, 0x20, 0xD0, "PPLighting reader D"),
	(0x00C17510, 0x20, 0xD0, "PPLighting pixel group B reader"),
	(0x00BD1C50, 0x20, 0xA0, "current-pass writer"),
	(0x00BE1F90, 0x10, 0x60, "SetShaders bind body"),
]

SCAN_PATTERNS = [
	"11fdd88",
	"11fde04",
	"11fde5c",
	"11fda48",
	"11fdb08",
	"0126f74c",
	"DAT_0126f74c",
	"FUN_00bd1c50",
	"FUN_00bd16f0",
	"FUN_00be1f90",
	"SetShaders",
	"+ 0x44",
	"+0x44",
	"+ 0x5c",
	"+0x5c",
	"+ 0x30",
	"+0x30",
	"+ 0x34",
	"+0x34",
	"+ 0x78",
	"+0x78",
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

def decompile_at(addr_int, label, max_len=24000):
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
		from_addr = ref.getFromAddress()
		from_func = fm.getFunctionContaining(from_addr)
		fname = from_func.getName() if from_func else "???"
		inst = listing.getInstructionContaining(from_addr)
		inst_text = inst.toString() if inst is not None else ""
		write("  %s @ 0x%08x (in %s) %s" % (ref.getReferenceType(), from_addr.getOffset(), fname, inst_text))
		count += 1
		if count > 160:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

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

def collect_ref_function_entries(addr_int, entries):
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		if from_func is not None:
			entry = from_func.getEntryPoint().getOffset()
			entries[entry] = from_func.getName()

def print_ref_function_summary(entries):
	write("")
	write("=" * 70)
	write("FUNCTIONS REFERENCING PPLIGHTING SHADER GLOBAL ARRAYS")
	write("=" * 70)
	keys = entries.keys()
	keys.sort()
	for entry in keys:
		write("  0x%08x %s" % (entry, entries[entry]))

def collect_all_ref_function_entries():
	entries = {}
	for item in GLOBAL_ARRAYS:
		collect_ref_function_entries(item[0], entries)
	return entries

def print_global_refs():
	for item in GLOBAL_ARRAYS:
		find_refs_to(item[0], "%s count=0x%x" % (item[1], item[2]))

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

def disasm_window(addr_int, before_bytes, count, label):
	write("")
	write("-" * 70)
	write("Raw disassembly %s around 0x%08x" % (label, addr_int))
	write("-" * 70)
	start = addr_int - before_bytes
	inst = listing.getInstructionAt(toAddr(start))
	if inst is None:
		inst = listing.getInstructionContaining(toAddr(start))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start))
	if inst is None:
		write("  [instruction not found]")
		return
	seen = 0
	while inst is not None and seen < count:
		print_instruction(inst, addr_int)
		seen += 1
		inst = inst.getNext()

def scan_raw_range(start, end, label):
	write("")
	write("=" * 70)
	write("RAW RANGE SHADER PAIR SCAN: %s 0x%08x..0x%08x" % (label, start, end))
	write("=" * 70)
	inst = listing.getInstructionAt(toAddr(start))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start))
	count = 0
	matched = 0
	while inst is not None:
		off = inst.getAddress().getOffset()
		if off >= end:
			break
		text = inst.toString()
		lower = text.lower()
		interesting = False
		refs = inst.getReferencesFrom()
		for ref in refs:
			to_int = ref.getToAddress().getOffset()
			if ref.getReferenceType().isCall() or KNOWN.get(to_int) is not None:
				interesting = True
		for pattern in SCAN_PATTERNS:
			if pattern.lower() in lower:
				interesting = True
				break
		if interesting:
			print_instruction(inst, start)
			matched += 1
		count += 1
		if count >= 420:
			write("  ... (range scan truncated)")
			break
		inst = inst.getNext()
	write("  Instructions scanned: %d, interesting printed: %d" % (count, matched))

def decompile_focus_functions():
	for addr_int in FOCUS_FUNCTIONS:
		decompile_at(addr_int, label_for(addr_int), 32000)
		find_and_print_calls_from(addr_int, label_for(addr_int))
		scan_patterns(addr_int, label_for(addr_int), SCAN_PATTERNS)

def decompile_ref_functions(entries):
	keys = entries.keys()
	keys.sort()
	for entry in keys:
		decompile_at(entry, "array ref function %s" % entries[entry], 18000)
		scan_patterns(entry, "array ref function %s" % entries[entry], SCAN_PATTERNS)

def print_raw_windows():
	for item in RAW_WINDOWS:
		disasm_window(item[0], item[1], item[2], item[3])

def main():
	write("FNV PBR PPLIGHTING PASS SHADER PAIR CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. Which functions read PPLighting global shader arrays after creation?")
	write("2. How are vertex groups 0x011FDD88/0x011FDE04/0x011FDE5C paired with pixel groups 0x011FDA48/0x011FDB08?")
	write("3. Which pair is written into current pass +0x5C/+0x44 before SetShaders?")
	write("4. Is there one safe PPLighting family for first visible side-table replacement?")
	write("")
	write("Compatibility rule:")
	write("Do not bind a replacement PBR shader until the array-to-pass pair and input family are proven.")
	print_global_refs()
	entries = collect_all_ref_function_entries()
	print_ref_function_summary(entries)
	print_raw_windows()
	decompile_focus_functions()
	decompile_ref_functions(entries)
	scan_raw_range(0x00BE2200, 0x00BE2D80, "near PPLighting reader A")
	scan_raw_range(0x00BEB000, 0x00BEBF80, "near PPLighting reader B/C/D")
	scan_raw_range(0x00C17480, 0x00C17780, "near pixel group B reader")
	scan_raw_range(0x00BD1600, 0x00BD1DA0, "current pass shader writer range")

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_pass_shader_pair_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
