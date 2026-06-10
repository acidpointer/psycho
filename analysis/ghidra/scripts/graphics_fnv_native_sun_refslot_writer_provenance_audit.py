# @category Analysis
# @description Audit FNV Sun ref-slot writers and Main directional light provenance

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0044FB20: "Main/TES constructor candidate",
	0x0045CD60: "Sky sun/current object getter (Sky +0x28)",
	0x00559450: "Ref-slot getter/helper candidate",
	0x00633C90: "Ref-slot init helper",
	0x0063A630: "Sky update downstream candidate",
	0x0063F830: "Sun base constructor helper",
	0x006404F0: "Sun constructor candidate",
	0x00640670: "Sun vtable slot 00 destructor thunk",
	0x006406A0: "Sun destructor/reset helper candidate",
	0x00640810: "Sun vtable slot 02 setup/update candidate",
	0x00641830: "Sun vtable slot 03 update/render candidate",
	0x0066B0D0: "Ref-slot assign helper",
	0x006FA420: "Caller of Main/TES +0x1C cleanup candidate",
	0x006FA920: "Caller of Main/TES +0x1C cleanup candidate",
	0x006FB3D0: "Main/TES +0x1C/+0x20 cleanup candidate",
	0x0086CF20: "Main/TES singleton setup candidate",
	0x00A74410: "Sun slot object constructor candidate",
	0x0051CF00: "Sun slot object constructor candidate",
	0x0051D000: "Sun slot object method candidate",
	0x00A75C20: "Sun slot object constructor candidate",
	0x00B660D0: "Sun +0x28 object constructor candidate",
	0x0104F298: "Sun vtable candidate",
	0x010724E8: "Main/TES vtable candidate",
	0x011DEA10: "Main/TES singleton",
	0x011DEA20: "Sky singleton",
}

DECOMPILE_TARGETS = [
	0x0044FB20,
	0x00559450,
	0x00633C90,
	0x0063A630,
	0x0063F830,
	0x006404F0,
	0x00640670,
	0x006406A0,
	0x00640810,
	0x00641830,
	0x0066B0D0,
	0x006FA420,
	0x006FA920,
	0x006FB3D0,
	0x0086CF20,
	0x00A74410,
	0x0051CF00,
	0x0051D000,
	0x00A75C20,
	0x00B660D0,
]

REF_TARGETS = [
	0x0044FB20,
	0x006404F0,
	0x006406A0,
	0x00640810,
	0x00641830,
	0x0066B0D0,
	0x0104F298,
	0x010724E8,
	0x011DEA10,
	0x011DEA20,
]

SUN_METHODS = [
	0x006404F0,
	0x006406A0,
	0x00640810,
	0x00641830,
]

MAIN_METHODS = [
	0x0044FB20,
	0x006FA420,
	0x006FA920,
	0x006FB3D0,
	0x0086CF20,
]

ASSIGN_WINDOWS = [
	(0x00640538, "Sun constructor ref init +0x08"),
	(0x00640549, "Sun constructor ref init +0x0C"),
	(0x0064055A, "Sun constructor ref init +0x10"),
	(0x0064056B, "Sun constructor ref init +0x14"),
	(0x0064057C, "Sun constructor ref init +0x1C"),
	(0x0064058D, "Sun constructor ref init +0x28"),
	(0x0064059E, "Sun constructor ref assign +0x04"),
	(0x006405AB, "Sun constructor ref assign +0x08"),
	(0x006405B8, "Sun constructor ref assign +0x0C"),
	(0x006405C5, "Sun constructor ref assign +0x10"),
	(0x006405D2, "Sun constructor ref assign +0x14"),
	(0x006405DF, "Sun constructor ref assign +0x1C"),
	(0x00640645, "Sun constructor ref assign +0x28"),
	(0x0064135C, "Sun slot02 assignment candidate 0"),
	(0x006413DB, "Sun slot02 assignment candidate 1"),
	(0x006414D4, "Sun slot02 assignment candidate 2"),
	(0x00641553, "Sun slot02 assignment candidate 3"),
	(0x00641681, "Sun slot02 assignment candidate 4"),
	(0x006FB410, "Main cleanup checks object +0x1C"),
	(0x006FB44A, "Main cleanup removes object +0x1C"),
	(0x006FB4D3, "Main cleanup clears object +0x1C"),
	(0x006FB4FA, "Main cleanup checks object +0x20"),
	(0x006FB534, "Main cleanup removes object +0x20"),
	(0x006FB5BD, "Main cleanup clears object +0x20"),
	(0x0086D03B, "Main constructor call in setup"),
]

MATCH_PATTERNS = [
	"+ 0x4",
	"+0x4",
	"+ 0x8",
	"+0x8",
	"+ 0xc",
	"+0xc",
	"+ 0x10",
	"+0x10",
	"+ 0x14",
	"+0x14",
	"+ 0x18",
	"+0x18",
	"+ 0x1c",
	"+0x1c",
	"+ 0x20",
	"+0x20",
	"+ 0x24",
	"+0x24",
	"+ 0x28",
	"+0x28",
	"+ 0xd4",
	"+0xd4",
	"+ 0xf0",
	"+0xf0",
	"011dea10",
	"011dea20",
	"0104f298",
	"010724e8",
	"directional",
	"light",
	"sun",
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

def read_u32(addr_int):
	try:
		value = memory.getInt(toAddr(addr_int))
		if value < 0:
			value += 0x100000000
		return value
	except:
		return None

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

def decompile_at(addr_int, label, max_len=36000):
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
		if count >= 180:
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

def line_matches(line):
	lower = line.lower()
	idx = 0
	while idx < len(MATCH_PATTERNS):
		if lower.find(MATCH_PATTERNS[idx]) >= 0:
			return True
		idx += 1
	return False

def print_matching_decompile_lines(addr_int, label):
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
		if line_matches(line):
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

def scan_instruction_patterns(addr_int, label, max_hits):
	write("")
	write("=" * 70)
	write("RAW INSTRUCTION SLOT SCAN: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		match = False
		if text.find("0x1c") >= 0 or text.find("0x20") >= 0 or text.find("0x28") >= 0:
			match = True
		if text.find("0xd4") >= 0 or text.find("0xf0") >= 0:
			match = True
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				if tgt == 0x0066B0D0 or tgt == 0x00633C90 or tgt == 0x00559450:
					match = True
		if match:
			extra = ""
			for ref in refs:
				if ref.getReferenceType().isCall():
					tgt = ref.getToAddress().getOffset()
					extra = "%s ; CALL 0x%08x %s" % (extra, tgt, label_for(tgt))
			write("  0x%08x: %-52s%s" % (inst.getAddress().getOffset(), inst.toString(), extra))
			count += 1
			if count >= max_hits:
				write("  ... (hit limit reached)")
				break
	write("  Hits printed: %d" % count)

def dump_vtable_words(base_int, label, word_count):
	write("")
	write("=" * 70)
	write("VTABLE/ADJACENT WORDS: %s @ 0x%08x" % (label, base_int))
	write("=" * 70)
	idx = 0
	while idx < word_count:
		ptr = read_u32(base_int + idx * 4)
		if ptr is None:
			write("  word %02d +0x%02x -> [unreadable]" % (idx, idx * 4))
		else:
			write("  word %02d +0x%02x -> 0x%08x %s" % (idx, idx * 4, ptr, label_for(ptr)))
		idx += 1

def run_decompiles():
	idx = 0
	while idx < len(DECOMPILE_TARGETS):
		addr = DECOMPILE_TARGETS[idx]
		decompile_at(addr, label_for(addr), 42000)
		print_matching_decompile_lines(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))
		idx += 1

def run_refs():
	idx = 0
	while idx < len(REF_TARGETS):
		addr = REF_TARGETS[idx]
		find_refs_to(addr, label_for(addr))
		idx += 1

def run_assign_windows():
	idx = 0
	while idx < len(ASSIGN_WINDOWS):
		item = ASSIGN_WINDOWS[idx]
		disasm_window(item[0], 10, 24, item[1])
		idx += 1

def run_raw_scans():
	idx = 0
	while idx < len(SUN_METHODS):
		addr = SUN_METHODS[idx]
		scan_instruction_patterns(addr, label_for(addr), 180)
		idx += 1
	idx = 0
	while idx < len(MAIN_METHODS):
		addr = MAIN_METHODS[idx]
		scan_instruction_patterns(addr, label_for(addr), 180)
		idx += 1

def print_questions():
	write("FNV NATIVE SUN REFSLOT WRITER PROVENANCE AUDIT")
	write("")
	write("Questions:")
	write("1. Which Sun methods write managed ref slots +0x1C and +0x20, and what object constructors feed those writes?")
	write("2. Does Main/TES constructor FUN_0044FB20 initialize Main +0x1C as a directional light object?")
	write("3. Is there executable proof that Sun +0x1C and Main +0x1C ever receive the same pointer?")
	write("4. Are +0xD4 diffuse color or +0xF0 direction fields read from a proven Sun/Main directional-light object?")
	write("")
	write("This script follows up the broad alias scan with targeted constructor, ref-slot helper, and raw instruction windows.")

def main():
	print_questions()
	dump_vtable_words(0x0104F298, "Sun vtable candidate", 8)
	dump_vtable_words(0x010724E8, "Main/TES vtable candidate", 16)
	run_refs()
	run_decompiles()
	run_assign_windows()
	run_raw_scans()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_native_sun_refslot_writer_provenance_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
