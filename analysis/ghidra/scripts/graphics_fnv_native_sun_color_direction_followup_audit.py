# @category Analysis
# @description Follow up FNV native sun color/direction fields after deep sun-light audit

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0040EBD0: "Float clamp/smoothing helper used after sun range update",
	0x0045BB80: "Vector getter used by sun screen projection",
	0x0045CD60: "Sky sun/current object getter (Sky +0x28)",
	0x004E3D00: "Weather/light range helper for Sky +0xD4",
	0x00507B20: "Weather/light range helper for Sky +0xD8",
	0x00544AB0: "Interior/exterior fog near helper candidate",
	0x00544B10: "Interior/exterior fog far helper candidate",
	0x00544B70: "Fog power helper candidate",
	0x00595F50: "Sky sunset/sunrise time helper",
	0x00595FC0: "Sky sunset/sunrise time helper",
	0x0063B9B0: "Sky sunrise color begin helper",
	0x0063BA30: "Sky sunset color end helper",
	0x0063BCE0: "Sky weather sun/fog range update",
	0x0063C420: "Sky sun/fog scalar table helper",
	0x0063C440: "Sky child weather update helper",
	0x0063C460: "Sky clamp/range update guard",
	0x0063C470: "Sky weather update state helper",
	0x0063C480: "Sky weather update range helper",
	0x0063C690: "Sky vector/color interpolation writer",
	0x006404F0: "Sun constructor candidate",
	0x00870BD0: "Main render world caller / sky sun screen path",
	0x00B8B1E0: "Sun screen vector globals writer",
	0x00C03410: "Image-space sun screen global reader candidate",
	0x011DEA10: "Main/TES singleton candidate",
	0x011DEA20: "Sky singleton",
	0x012023F4: "Sun screen/global value 0",
	0x012023F8: "Sun screen/global value 1",
}

DECOMPILE_TARGETS = [
	0x0040EBD0,
	0x0045BB80,
	0x0045CD60,
	0x004E3D00,
	0x00507B20,
	0x00544AB0,
	0x00544B10,
	0x00544B70,
	0x00595F50,
	0x00595FC0,
	0x0063B9B0,
	0x0063BA30,
	0x0063BCE0,
	0x0063C420,
	0x0063C440,
	0x0063C460,
	0x0063C470,
	0x0063C480,
	0x0063C690,
	0x006404F0,
	0x00870BD0,
	0x00B8B1E0,
	0x00C03410,
]

REF_TARGETS = [
	0x004E3D00,
	0x00507B20,
	0x00544AB0,
	0x00544B10,
	0x00544B70,
	0x00595F50,
	0x00595FC0,
	0x0063B9B0,
	0x0063BA30,
	0x0063C420,
	0x0063C440,
	0x0063C460,
	0x0063C470,
	0x0063C480,
	0x0063C690,
	0x006404F0,
	0x00C03410,
	0x011DEA10,
	0x011DEA20,
	0x012023F4,
	0x012023F8,
]

DISASM_WINDOWS = [
	(0x0063BD64, 10, 28, "Sky +0xD4 range helper call"),
	(0x0063BD75, 10, 28, "Sky +0xD8 range helper call"),
	(0x0063BE3F, 14, 40, "Sky +0x48 vector/color interpolation writer"),
	(0x0063C05D, 12, 70, "Sky +0xD4/+0xD8/+0xE8 sun scalar blend"),
	(0x0063C273, 12, 70, "Interior/exterior fallback fog range path"),
	(0x0063C35C, 12, 70, "Camera clamp after Sky +0xD4/+0xD8"),
	(0x0063A91D, 16, 46, "Sky +0x28 Sun constructor call"),
	(0x00871013, 14, 80, "Render sun screen projection path"),
	(0x00C03363, 16, 48, "Raw reader near 0x012023F8"),
	(0x00C03546, 16, 48, "Function reader of 0x012023F8/F4"),
	(0x00FBAE5B, 16, 32, "Unknown write to 0x012023F4/F8"),
]

MATCH_PATTERNS = [
	"011dea10",
	"011dea20",
	"012023f4",
	"012023f8",
	"0045cd60",
	"0063bce0",
	"0063c420",
	"0063c690",
	"006404f0",
	"+ 0x1c",
	"+0x1c",
	"+ 0x28",
	"+0x28",
	"+ 0x48",
	"+0x48",
	"+ 0x60",
	"+0x60",
	"+ 0x6c",
	"+0x6c",
	"+ 0xc0",
	"+0xc0",
	"+ 0xc4",
	"+0xc4",
	"+ 0xc8",
	"+0xc8",
	"+ 0xd4",
	"+0xd4",
	"+ 0xd8",
	"+0xd8",
	"+ 0xe8",
	"+0xe8",
	"+ 0xec",
	"+0xec",
	"+ 0xf0",
	"+0xf0",
	"+ 0xf4",
	"+0xf4",
	"+ 0xf8",
	"+0xf8",
	"+ 0x25c",
	"+0x25c",
	"+ 0x264",
	"+0x264",
	"+ 0x26c",
	"+0x26c",
	"+ 0x2a4",
	"+0x2a4",
	"sun",
	"light",
	"direction",
	"weather",
	"fog",
	"color",
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
		if count >= 220:
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
	write("SUN COLOR/DIRECTION MATCHES: %s @ 0x%08x" % (label, addr_int))
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

def scan_functions_referencing_global(addr_int, label, limit):
	write("")
	write("=" * 70)
	write("MATCHED FUNCTIONS REFERENCING %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = {}
	count = 0
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		if seen.get(entry) is not None:
			continue
		seen[entry] = True
		print_matching_decompile_lines(entry, "%s ref %s" % (label, func.getName()))
		find_and_print_calls_from(entry, "%s ref %s" % (label, func.getName()))
		count += 1
		if count >= limit:
			write("  ... (limit reached)")
			break
	write("  Printed ref functions: %d" % count)

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
		print_matching_decompile_lines(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))
		idx += 1

def run_disasm_windows():
	idx = 0
	while idx < len(DISASM_WINDOWS):
		item = DISASM_WINDOWS[idx]
		disasm_window(item[0], item[1], item[2], item[3])
		idx += 1

def print_questions():
	write("FNV NATIVE SUN COLOR/DIRECTION FOLLOWUP AUDIT")
	write("")
	write("Questions:")
	write("1. What do Sky update fields +0xD4/+0xD8/+0xE8 represent, and are they safer for material constants than raw TESWeather color tables?")
	write("2. Which helpers feed those fields: time boundaries, fog ranges, sun scalar table, or final renderer light color?")
	write("3. Does the Sun constructor or native methods prove Sun +0x1C points to Main +0x1C directionalLight?")
	write("4. Do 0x012023F4/0x012023F8 readers confirm these are screen-space sun coordinates?")
	write("")
	write("Do not infer final PSY_SunColor from NVR field names. Use only executable reads/writes proved here.")

def main():
	print_questions()
	run_refs()
	run_decompiles()
	run_disasm_windows()
	scan_functions_referencing_global(0x011DEA10, "Main/TES singleton candidate", 12)
	scan_functions_referencing_global(0x012023F4, "Sun screen/global value 0", 8)
	scan_functions_referencing_global(0x012023F8, "Sun screen/global value 1", 8)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_native_sun_color_direction_followup_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
