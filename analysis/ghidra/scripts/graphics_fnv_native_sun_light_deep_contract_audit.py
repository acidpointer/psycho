# @category Analysis
# @description Deep audit FNV native sun/light color and direction ownership for PBR environment constants

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0045BB80: "Sun/camera vector getter used by render sun path",
	0x0045C670: "Current camera getter used by render sun path",
	0x0045CBC0: "Sky/Sun adjacent caller of Sky sun getter",
	0x0045CD60: "Sky sun/current object getter (returns Sky +0x28)",
	0x00532220: "Generated/weather color blend candidate",
	0x00532FF0: "Weather/environment update candidate",
	0x00553700: "Sky sun getter high-priority caller",
	0x0056FCB0: "Sky sun getter high-priority caller",
	0x00573170: "Sky sun getter high-priority caller",
	0x00573800: "Sky sun getter high-priority caller",
	0x00573F40: "Sky sun getter high-priority caller",
	0x0059A030: "Sky sun getter high-priority caller",
	0x0059A1E0: "Sky sun getter high-priority caller",
	0x0061CAD0: "Sky sun getter high-priority caller",
	0x0061CB60: "Sky sun getter high-priority caller",
	0x0061CC90: "Sky sun getter high-priority caller",
	0x0061E2B0: "Sky sun getter high-priority caller",
	0x0063A630: "Sky update downstream candidate",
	0x0063BCE0: "Weather/sky sun update candidate",
	0x0063F790: "Environment/weather update candidate",
	0x006629F0: "Camera/scene getter used by render sun path",
	0x00853E10: "Sky sun getter high-priority caller",
	0x00870BD0: "Main render world caller / sky sun screen path",
	0x00872B00: "Main render helper before world scene graph",
	0x00877730: "Sky render/update singleton path",
	0x00B8AF10: "Environment color setter candidate A",
	0x00B8AFB0: "Environment color setter candidate B",
	0x00B8B000: "Environment color setter candidate C",
	0x00B8B0D0: "Environment color setter candidate D",
	0x00B8B1E0: "Sun screen vector globals writer",
	0x011DEA20: "Sky::singleton",
	0x012023F4: "Sun screen/global value 0",
	0x012023F8: "Sun screen/global value 1",
}

CURATED_TARGETS = [
	0x0045CBC0,
	0x0045CD60,
	0x00532220,
	0x00532FF0,
	0x00553700,
	0x0056FCB0,
	0x00573170,
	0x00573800,
	0x00573F40,
	0x0059A030,
	0x0059A1E0,
	0x0061CAD0,
	0x0061CB60,
	0x0061CC90,
	0x0061E2B0,
	0x0063A630,
	0x0063BCE0,
	0x0063F790,
	0x006629F0,
	0x00853E10,
	0x00870BD0,
	0x00872B00,
	0x00877730,
	0x00B8AF10,
	0x00B8AFB0,
	0x00B8B000,
	0x00B8B0D0,
	0x00B8B1E0,
]

REF_TARGETS = [
	0x0045CD60,
	0x011DEA20,
	0x012023F4,
	0x012023F8,
]

CALLSITE_WINDOWS = [
	(0x00553740, 10, 34, "FUN_00553700 first Sky sun getter call"),
	(0x0055374C, 10, 34, "FUN_00553700 second Sky sun getter call"),
	(0x005537E3, 10, 34, "FUN_00553700 third Sky sun getter call"),
	(0x00573DAC, 10, 38, "FUN_00573800 first Sky sun getter call"),
	(0x00573DB9, 10, 38, "FUN_00573800 second Sky sun getter call"),
	(0x0061CC17, 10, 38, "FUN_0061CB60 Sky sun getter call"),
	(0x0061CCAE, 10, 38, "FUN_0061CC90 second Sky sun getter call"),
	(0x0061E2F3, 10, 42, "FUN_0061E2B0 first Sky sun getter call"),
	(0x0061E316, 10, 42, "FUN_0061E2B0 second Sky sun getter call"),
	(0x0059A0C7, 10, 42, "FUN_0059A030 first Sky sun getter call"),
	(0x0059A143, 10, 42, "FUN_0059A030 second Sky sun getter call"),
	(0x0045CCC0, 12, 44, "FUN_0045CBC0 Sky/Sun adjacent call"),
	(0x0063BEF0, 14, 54, "FUN_0063BCE0 weather/sky first call"),
	(0x0063BF0B, 14, 54, "FUN_0063BCE0 weather/sky second call"),
	(0x0085408D, 12, 48, "FUN_00853E10 Sky sun getter call"),
	(0x00872D68, 12, 48, "FUN_00872B00 first Sky sun getter call"),
	(0x00872DAC, 12, 48, "FUN_00872B00 second Sky sun getter call"),
	(0x00871013, 14, 58, "FUN_00870BD0 render sun first call"),
	(0x00871026, 14, 58, "FUN_00870BD0 render sun second call"),
	(0x008777B5, 14, 54, "FUN_00877730 sky update first call"),
	(0x0087791C, 14, 54, "FUN_00877730 sky update second call"),
]

FIELD_MATCH_PATTERNS = [
	"011dea20",
	"012023f4",
	"012023f8",
	"0045cd60",
	"00b8af10",
	"00b8afb0",
	"00b8b000",
	"00b8b0d0",
	"00b8b1e0",
	"+ 0x1c",
	"+0x1c",
	"+ 0x28",
	"+0x28",
	"+ 0x60",
	"+0x60",
	"+ 0x64",
	"+0x64",
	"+ 0x68",
	"+0x68",
	"+ 0x6c",
	"+0x6c",
	"+ 0x70",
	"+0x70",
	"+ 0x74",
	"+0x74",
	"+ 0xc0",
	"+0xc0",
	"+ 0xc4",
	"+0xc4",
	"+ 0xc8",
	"+0xc8",
	"+ 0xd4",
	"+0xd4",
	"+ 0xe0",
	"+0xe0",
	"+ 0xf0",
	"+0xf0",
	"[0x7]",
	"[7]",
	"[0x18]",
	"[0x19]",
	"[0x1a]",
	"[0x1b]",
	"[0x1c]",
	"[0x1d]",
	"[0x30]",
	"[0x31]",
	"[0x32]",
	"[0x35]",
	"[0x38]",
	"[0x3c]",
	"sun",
	"light",
	"ambient",
	"diff",
	"spec",
	"direction",
	"weather",
	"color",
]

STRONG_FIELD_PATTERNS = [
	"+ 0x1c",
	"+0x1c",
	"+ 0x60",
	"+0x60",
	"+ 0x6c",
	"+0x6c",
	"+ 0xc0",
	"+0xc0",
	"+ 0xd4",
	"+0xd4",
	"+ 0xe0",
	"+0xe0",
	"+ 0xf0",
	"+0xf0",
	"012023f4",
	"012023f8",
	"[0x7]",
	"[0x1b]",
	"[0x30]",
	"[0x35]",
	"[0x38]",
	"[0x3c]",
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
		if count > 220:
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

def line_has_pattern(line, patterns):
	lower = line.lower()
	idx = 0
	while idx < len(patterns):
		if lower.find(patterns[idx]) >= 0:
			return True
		idx += 1
	return False

def count_patterns(text, patterns):
	lower = text.lower()
	idx = 0
	score = 0
	while idx < len(patterns):
		if lower.find(patterns[idx]) >= 0:
			score += 1
		idx += 1
	return score

def print_matching_decompile_lines(addr_int, label):
	write("")
	write("=" * 70)
	write("SUN/LIGHT FIELD MATCHES: %s @ 0x%08x" % (label, addr_int))
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
		if line_has_pattern(line, FIELD_MATCH_PATTERNS):
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

def scan_function_disasm_for_fields(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("=" * 70)
	write("DISASM FIELD-OFFSET SCAN: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		if line_has_pattern(text, STRONG_FIELD_PATTERNS):
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), text))
			count += 1
	write("  Total disasm matches: %d" % count)

def collect_ref_function_entries(addr_int):
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = {}
	entries = []
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		if seen.get(entry) is not None:
			continue
		seen[entry] = True
		entries.append(entry)
	return entries

def print_scored_sun_getter_ref_functions(limit):
	write("")
	write("=" * 70)
	write("SCORED FUNCTIONS REFERENCING Sky sun getter 0x0045CD60")
	write("=" * 70)
	entries = collect_ref_function_entries(0x0045CD60)
	scored = []
	idx = 0
	while idx < len(entries):
		entry = entries[idx]
		code = decompile_text(entry)
		if code is not None:
			score = count_patterns(code, STRONG_FIELD_PATTERNS)
			if score > 0:
				scored.append((score, entry))
		idx += 1
	scored.sort(reverse=True)
	idx = 0
	while idx < len(scored) and idx < limit:
		item = scored[idx]
		entry = item[1]
		write("")
		write("Rank %d: score %d, %s @ 0x%08x" % (idx + 1, item[0], label_for(entry), entry))
		print_matching_decompile_lines(entry, label_for(entry))
		find_and_print_calls_from(entry, label_for(entry))
		idx += 1
	write("  Printed scored ref functions: %d of %d" % (idx, len(scored)))

def run_refs():
	idx = 0
	while idx < len(REF_TARGETS):
		addr = REF_TARGETS[idx]
		find_refs_to(addr, label_for(addr))
		idx += 1

def run_curated_decompiles():
	idx = 0
	while idx < len(CURATED_TARGETS):
		addr = CURATED_TARGETS[idx]
		decompile_at(addr, label_for(addr), 26000)
		print_matching_decompile_lines(addr, label_for(addr))
		scan_function_disasm_for_fields(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))
		idx += 1

def run_callsite_windows():
	idx = 0
	while idx < len(CALLSITE_WINDOWS):
		item = CALLSITE_WINDOWS[idx]
		disasm_window(item[0], item[1], item[2], item[3])
		idx += 1

def print_questions():
	write("FNV NATIVE SUN LIGHT DEEP CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. Which native function writes or reads Sky +0x60/+0x6C/+0xC0 sun color fields?")
	write("2. Does Sun +0x1C equal Main +0x1C directional light, and is either render-owned?")
	write("3. Does any render path write/read NiDirectionalLight +0xD4 diffuse or +0xF0 direction?")
	write("4. Are globals 0x012023F4/0x012023F8 only screen-space sun coordinates?")
	write("")
	write("Compatibility rule:")
	write("Use a final renderer-owned field for PSY_SunColor/PSY_SunDirection only after this output proves ownership and lifetime. Otherwise keep existing CPU-projected sun data and do not copy NVR raw TESWeather color walking.")
	write("")
	write("Candidate fields from NewVegasReloaded source to prove, not assume:")
	write("  Sky +0x28: Sun*")
	write("  Sky +0x60/+0x64/+0x68: sunAmbient candidate")
	write("  Sky +0x6C/+0x70/+0x74: sunDirectional candidate")
	write("  Sky +0xC0/+0xC4/+0xC8: sunFog candidate")
	write("  Sun +0x1C: NiDirectionalLight* candidate")
	write("  Main +0x1C: NiDirectionalLight* candidate")
	write("  Main +0x68: Sky* candidate")
	write("  NiLight +0xC4: dimmer")
	write("  NiLight +0xC8/+0xD4/+0xE0: ambient/diffuse/specular color")
	write("  NiDirectionalLight +0xF0: direction")

def main():
	print_questions()
	run_refs()
	run_curated_decompiles()
	run_callsite_windows()
	print_scored_sun_getter_ref_functions(28)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_native_sun_light_deep_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
