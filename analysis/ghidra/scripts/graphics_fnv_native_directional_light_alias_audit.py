# @category Analysis
# @description Audit FNV native Sun/Main directional light alias and NiDirectionalLight fields

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0045BB80: "Vector getter used by native sun screen projection",
	0x0045CBC0: "Main/TES user near Sky accessors",
	0x0045CD60: "Sky sun/current object getter (Sky +0x28)",
	0x00633C90: "Constructor helper used by Sun and scene objects",
	0x0063A630: "Sky update downstream candidate",
	0x0063F830: "Sun constructor first helper",
	0x006404F0: "Sun constructor candidate",
	0x0066B0D0: "Constructor pointer/helper used by Sun",
	0x006FB3D0: "Main/TES +0x1C cleanup/reference candidate",
	0x0086CF20: "Main/TES singleton setup candidate",
	0x00870BD0: "World render sky sun screen path",
	0x00B660D0: "Allocated object constructor used by Sun",
	0x0104F298: "Sun vtable candidate",
	0x011DEA10: "Main/TES singleton candidate",
	0x011DEA20: "Sky singleton",
}

DECOMPILE_TARGETS = [
	0x0045BB80,
	0x0045CBC0,
	0x0045CD60,
	0x00633C90,
	0x0063A630,
	0x0063F830,
	0x006404F0,
	0x0066B0D0,
	0x006FB3D0,
	0x0086CF20,
	0x00870BD0,
	0x00B660D0,
]

REF_TARGETS = [
	0x0104F298,
	0x011DEA10,
	0x011DEA20,
	0x006404F0,
	0x006FB3D0,
	0x0086CF20,
]

DISASM_WINDOWS = [
	(0x0063A935, 18, 56, "Sky +0x28 Sun constructor and attach path"),
	(0x0064051B, 10, 90, "Sun constructor body and field initialization"),
	(0x006FB3D0, 4, 130, "Main/TES +0x1C cleanup candidate"),
	(0x0086D062, 28, 100, "Main/TES singleton write/setup candidate"),
	(0x0045CC4F, 16, 90, "Main/TES user near Sky accessor refs"),
	(0x00871031, 16, 72, "Render path Sun vtable +0x04 root/vector getter"),
]

MAIN_1C_PATTERNS = [
	"+ 0x1c",
	"+0x1c",
	"[ecx + 0x1c]",
	"[eax + 0x1c]",
	"[edx + 0x1c]",
	"0x1c)",
]

LIGHT_FIELD_PATTERNS = [
	"+ 0x1c",
	"+0x1c",
	"+ 0xd4",
	"+0xd4",
	"+ 0xd8",
	"+0xd8",
	"+ 0xe0",
	"+0xe0",
	"+ 0xf0",
	"+0xf0",
	"+ 0xf4",
	"+0xf4",
	"+ 0xf8",
	"+0xf8",
	"direction",
	"diff",
	"light",
	"sun",
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
		if count >= 260:
			write("  ... (truncated)")
			break
	write("  Total printed: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
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

def text_has_pattern(text, patterns):
	lower = text.lower()
	idx = 0
	while idx < len(patterns):
		if lower.find(patterns[idx]) >= 0:
			return True
		idx += 1
	return False

def line_matches(line, patterns):
	lower = line.lower()
	idx = 0
	while idx < len(patterns):
		if lower.find(patterns[idx]) >= 0:
			return True
		idx += 1
	return False

def print_matching_decompile_lines(addr_int, label, patterns):
	write("")
	write("=" * 70)
	write("MATCHES: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	code = decompile_text(addr_int)
	if code is None:
		write("  [decompilation failed]")
		return
	lines = code.split("\n")
	idx = 0
	count = 0
	while idx < len(lines):
		line = lines[idx]
		if line_matches(line, patterns):
			write("  L%04d: %s" % (idx + 1, line))
			count += 1
		idx += 1
	write("  Total matched lines: %d" % count)

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionContaining(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionBefore(toAddr(center_int))
	if inst is None:
		write("  [instruction not found]")
		return
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

def dump_vtable(base_int, label, slot_count, decompile_count):
	write("")
	write("=" * 70)
	write("VTABLE DUMP: %s @ 0x%08x" % (label, base_int))
	write("=" * 70)
	idx = 0
	while idx < slot_count:
		ptr = read_u32(base_int + idx * 4)
		if ptr is None:
			write("  slot %02d +0x%02x -> [unreadable]" % (idx, idx * 4))
		else:
			write("  slot %02d +0x%02x -> 0x%08x %s" % (idx, idx * 4, ptr, label_for(ptr)))
		idx += 1
	idx = 0
	while idx < decompile_count:
		ptr = read_u32(base_int + idx * 4)
		if ptr is not None:
			decompile_at(ptr, "%s vtable slot %02d" % (label, idx), 16000)
			print_matching_decompile_lines(ptr, "%s vtable slot %02d" % (label, idx), LIGHT_FIELD_PATTERNS)
			find_and_print_calls_from(ptr, "%s vtable slot %02d" % (label, idx))
		idx += 1

def scan_refs_for_patterns(addr_int, label, required_patterns, print_patterns, limit_funcs, max_unique):
	write("")
	write("=" * 70)
	write("REF FUNCTION SCAN: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = {}
	printed = 0
	scanned = 0
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		if seen.get(entry) is not None:
			continue
		seen[entry] = True
		scanned += 1
		if scanned > max_unique:
			write("  ... (max unique function scan reached)")
			break
		code = decompile_text(entry)
		if code is None:
			continue
		if not text_has_pattern(code, required_patterns):
			continue
		decompile_at(entry, "%s matched ref %s" % (label, func.getName()), 30000)
		print_matching_decompile_lines(entry, "%s matched ref %s" % (label, func.getName()), print_patterns)
		find_and_print_calls_from(entry, "%s matched ref %s" % (label, func.getName()))
		disasm_window(ref.getFromAddress().getOffset(), 8, 24, "%s matched ref %s" % (label, func.getName()))
		printed += 1
		if printed >= limit_funcs:
			write("  ... (printed function limit reached)")
			break
	write("  Scanned unique functions: %d" % scanned)
	write("  Printed matching functions: %d" % printed)

def run_refs():
	idx = 0
	while idx < len(REF_TARGETS):
		addr = REF_TARGETS[idx]
		find_refs_to(addr, label_for(addr))
		idx += 1

def run_decompiles():
	idx = 0
	while idx < len(DECOMPILE_TARGETS):
		addr = DECOMPILE_TARGETS[idx]
		decompile_at(addr, label_for(addr), 30000)
		print_matching_decompile_lines(addr, label_for(addr), LIGHT_FIELD_PATTERNS)
		find_and_print_calls_from(addr, label_for(addr))
		idx += 1

def run_disasm_windows():
	idx = 0
	while idx < len(DISASM_WINDOWS):
		item = DISASM_WINDOWS[idx]
		disasm_window(item[0], item[1], item[2], item[3])
		idx += 1

def print_questions():
	write("FNV NATIVE DIRECTIONAL LIGHT ALIAS AUDIT")
	write("")
	write("Source claims being tested:")
	write("- Reloaded NewVegas Game.h: Sun +0x1C is the same pointer as Main/TES +0x1C directionalLight.")
	write("- Reloaded GameNi.h: NiLight +0xD4 is diffuse color and NiDirectionalLight +0xF0 is direction.")
	write("")
	write("Questions:")
	write("1. Which methods are in the Sun vtable rooted at 0x0104F298?")
	write("2. Does native executable code copy or compare Sun +0x1C and Main/TES +0x1C?")
	write("3. Are Main/TES +0x1C reads/writes specific to directional light, or only generic cleanup?")
	write("4. Does any proven aliased object read stable +0xD4 diffuse color or +0xF0 direction fields?")
	write("")
	write("Do not promote NVR header fields into Psycho constants unless this output proves the native alias.")

def main():
	print_questions()
	dump_vtable(0x0104F298, "Sun vtable candidate", 18, 10)
	run_refs()
	run_decompiles()
	run_disasm_windows()
	scan_refs_for_patterns(0x011DEA10, "Main/TES singleton candidate +0x1C users", MAIN_1C_PATTERNS, LIGHT_FIELD_PATTERNS, 20, 420)
	scan_refs_for_patterns(0x011DEA20, "Sky singleton users with light/sun offsets", LIGHT_FIELD_PATTERNS, LIGHT_FIELD_PATTERNS, 16, 260)
	scan_refs_for_patterns(0x0104F298, "Sun vtable refs with light fields", LIGHT_FIELD_PATTERNS, LIGHT_FIELD_PATTERNS, 12, 80)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_native_directional_light_alias_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
