# @category Analysis
# @description Audit FNV PBR shader creation call sites reached from selector setup slots

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00B71BF0: "selector slot +0x148 target",
	0x00B74210: "selector slot +0x14C raw target",
	0x00B7A730: "selector slot +0x150 raw target",
	0x00B7A870: "selector interface copy helper after +0x150",
	0x00E81420: "selector slot +0xC0 raw target",
	0x00BE0FE0: "BSShader::CreateVertexShader",
	0x00BE1750: "BSShader::CreatePixelShader",
	0x00BE0B30: "NiD3DVertexShader initializer",
	0x00BE08F0: "NiD3DPixelShader initializer",
	0x00BE1F90: "BSShader::SetShaders",
	0x00BD16F0: "current-pass shader creator/writer",
	0x00BD1C50: "current-pass writer",
	0x00BD4BA0: "current-pass shader-interface apply",
	0x00E826D0: "shader-interface constant apply dispatcher",
}

CREATE_TARGETS = [
	0x00BE0FE0,
	0x00BE1750,
]

FOCUS_FUNCTIONS = [
	0x00BE0FE0,
	0x00BE1750,
	0x00BE0B30,
	0x00BE08F0,
	0x00BD16F0,
	0x00BD1C50,
	0x00BD4BA0,
	0x00B71BF0,
]

RAW_RANGES = [
	(0x00B71BF0, 0x00B74210, "selector +0x148 recognized vertex creation function"),
	(0x00B74210, 0x00B79B00, "selector +0x14C raw candidate range"),
	(0x00B7A730, 0x00B7AA20, "selector +0x150 raw setup/copy range"),
	(0x00E81420, 0x00E81660, "selector +0xC0 raw setter and adjacent helpers"),
]

SCAN_PATTERNS = [
	"CreateVertexShader",
	"CreatePixelShader",
	"FUN_00be0fe0",
	"FUN_00be1750",
	"FUN_00be0b30",
	"FUN_00be08f0",
	"FUN_00bd1c50",
	"FUN_00bd4ba0",
	"vs_2_0",
	"ps_2_0",
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
	"shader",
]

def write(msg):
	output.append(msg)
	print(msg)

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
		range_label = raw_range_label(from_addr.getOffset())
		write("  %s @ 0x%08x (in %s) %s range=%s" % (ref.getReferenceType(), from_addr.getOffset(), fname, inst_text, range_label))
		count += 1
		if count >= 260:
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

def raw_range_label(addr_int):
	for item in RAW_RANGES:
		if addr_int >= item[0] and addr_int < item[1]:
			return item[2]
	return "outside focus ranges"

def disasm_window(addr_int, before_bytes, count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, addr_int))
	write("-" * 70)
	start = addr_int - before_bytes
	inst = listing.getInstructionAt(toAddr(start))
	if inst is None:
		inst = listing.getInstructionContaining(toAddr(addr_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start))
	seen = 0
	while inst is not None and seen < count:
		off = inst.getAddress().getOffset()
		marker = " << TARGET" if off == addr_int else ""
		write("  0x%08x: %-54s%s" % (off, inst.toString(), marker))
		refs = inst.getReferencesFrom()
		for ref in refs:
			target = ref.getToAddress()
			write("      ref %s -> 0x%08x %s" % (ref.getReferenceType(), target.getOffset(), label_for(target.getOffset())))
		seen += 1
		inst = inst.getNext()

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
		if count >= 320:
			write("  ... (truncated)")
			break
	write("  Total matched lines: %d" % count)

def scan_raw_range(start, end, label):
	write("")
	write("=" * 70)
	write("RAW RANGE CALL/PATTERN SCAN: %s 0x%08x..0x%08x" % (label, start, end))
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
			if ref.getReferenceType().isCall():
				taddr = ref.getToAddress().getOffset()
				write("  CALL 0x%08x: %-44s -> 0x%08x %s" % (off, text, taddr, label_for(taddr)))
				interesting = True
				matched += 1
		for pattern in SCAN_PATTERNS:
			if pattern.lower() in lower:
				if not interesting:
					write("  PAT  0x%08x: %s" % (off, text))
					matched += 1
				break
		count += 1
		if matched >= 360:
			write("  ... (matched output truncated)")
			break
		if count >= 12000:
			write("  ... (instruction scan truncated)")
			break
		inst = inst.getNext()
	write("  Instructions scanned: %d, matched lines: %d" % (count, matched))

def print_create_call_windows():
	write("")
	write("=" * 70)
	write("CREATE SHADER CALL WINDOWS INSIDE FOCUS RANGES")
	write("=" * 70)
	for target in CREATE_TARGETS:
		refs = ref_mgr.getReferencesTo(toAddr(target))
		while refs.hasNext():
			ref = refs.next()
			from_addr = ref.getFromAddress()
			from_int = from_addr.getOffset()
			range_label = raw_range_label(from_int)
			if range_label != "outside focus ranges":
				disasm_window(from_int, 96, 52, "%s call to %s" % (range_label, label_for(target)))

def decompile_focus_functions():
	for addr_int in FOCUS_FUNCTIONS:
		decompile_at(addr_int, label_for(addr_int), 36000)
		find_and_print_calls_from(addr_int, label_for(addr_int))
		scan_patterns(addr_int, label_for(addr_int), SCAN_PATTERNS)

def scan_all_raw_ranges():
	for item in RAW_RANGES:
		scan_raw_range(item[0], item[1], item[2])

def print_all_create_refs():
	for target in CREATE_TARGETS:
		find_refs_to(target, label_for(target))

def main():
	write("FNV PBR SHADER CREATION LIFECYCLE FOLLOWUP AUDIT")
	write("")
	write("Questions:")
	write("1. What exact arguments and return ownership do BSShader::CreateVertexShader/CreatePixelShader use?")
	write("2. Which selector setup slots create PPLighting shader objects, and where are returned objects assigned?")
	write("3. Does selector +0x14C contain pixel shader creation for the PPLighting family?")
	write("4. Is a creation-time replacement side table safer than mutating NiD3D shader object layouts?")
	write("")
	write("Compatibility rule:")
	write("Do not implement visible PBR replacement until creation hooks, return ownership, and draw-time restore timing are proven.")
	print_all_create_refs()
	decompile_focus_functions()
	scan_all_raw_ranges()
	print_create_call_windows()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_shader_creation_lifecycle_followup_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
