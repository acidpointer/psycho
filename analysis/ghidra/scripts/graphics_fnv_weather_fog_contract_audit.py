# @category Analysis
# @description Audit FNV weather and fog data contract for Psycho Graphics AO and sunshafts

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0044FB20: "NewTES",
	0x004505A0: "Sky current climate/weather getter candidate",
	0x0045BB80: "CameraVectorGetter_0045BB80",
	0x0045CD60: "Sky sun/current object getter candidate",
	0x00595EA0: "Sky::GetSunriseBegin",
	0x00595F10: "Sky sunrise/sunset byte getter candidate",
	0x00595F50: "Sky::GetSunriseEnd",
	0x00595FC0: "Sky::GetSunsetBegin",
	0x00596030: "Sky::GetSunsetEnd",
	0x0063A630: "Sky setup/update with render textures candidate",
	0x0063B9B0: "Sky::GetSunriseColorBegin",
	0x0063BA30: "Sky::GetSunsetColorEnd",
	0x0086CF20: "Sky/TES initialization candidate",
	0x00870BD0: "Main render world caller B",
	0x00877730: "Sky render/update candidate",
	0x011CA9E8: "Cached sunrise begin",
	0x011CA9EC: "Cached sunrise end",
	0x011CA9F0: "Cached sunset begin",
	0x011CA9F4: "Cached sunset end",
	0x011CCCFC: "Cached sunrise color begin",
	0x011CCD00: "Cached sunset color end",
	0x011DEA10: "TES singleton candidate",
	0x011DEA20: "Sky::singleton",
}

FUNCTION_TARGETS = [
	0x0086CF20,
	0x0044FB20,
	0x004505A0,
	0x0045CD60,
	0x0063A630,
	0x00877730,
	0x00870BD0,
	0x00595F10,
	0x00595EA0,
	0x00595F50,
	0x00595FC0,
	0x00596030,
	0x0063B9B0,
	0x0063BA30,
]

GLOBAL_REFS = [
	0x011DEA20,
	0x011DEA10,
	0x011CA9E8,
	0x011CA9EC,
	0x011CA9F0,
	0x011CA9F4,
	0x011CCCFC,
	0x011CCD00,
]

DISASM_WINDOWS = [
	0x00871000,
	0x00871013,
	0x00871026,
	0x00871046,
	0x00877795,
	0x008777AF,
	0x008777D2,
	0x00877916,
]

MATCH_PATTERNS = [
	"0xc",
	"0x10",
	"0x14",
	"0x28",
	"0x60",
	"0x6c",
	"0xc0",
	"0xe4",
	"0xe5",
	"0xf4",
	"0x118",
	"011dea20",
	"011dea10",
	"011ca9",
	"011ccc",
	"011ccd",
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
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
		if count > 120:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

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

def read_bytes(addr_int, count):
	values = []
	i = 0
	while i < count:
		value = memory.getByte(toAddr(addr_int + i)) & 0xff
		values.append("%02X" % value)
		i += 1
	return " ".join(values)

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

def scan_refs_windows(addr_int, label, max_refs):
	write("")
	write("=" * 70)
	write("REFERENCE WINDOWS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_addr = ref.getFromAddress().getOffset()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("")
		write("Reference %d: 0x%08x in %s" % (count + 1, from_addr, fname))
		disasm_window(from_addr, 8, 20, "reference to %s" % label)
		count += 1
		if count >= max_refs:
			write("  ... reference window scan truncated")
			break
	write("Total reference windows printed: %d" % count)

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
	write("OFFSET MATCHES: %s @ 0x%08x" % (label, addr_int))
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

def print_contract_notes():
	write("")
	write("=" * 70)
	write("WEATHER/FOG CONTRACT TO PROVE")
	write("=" * 70)
	write("Read-only default runtime is acceptable only after these are proven in FNV:")
	write("  Sky firstWeather, secondWeather, weatherPercent offsets.")
	write("  TESWeather day/night fog near/far fields or getter functions.")
	write("  Fog color/current fog blend source used by image-space/fog rendering.")
	write("  Interior/exterior and weather transition behavior at image-space phase.")
	write("")
	write("Do not implement fog-aware AO or godray weather constants from TESReloaded offsets alone.")

def audit_globals():
	idx = 0
	while idx < len(GLOBAL_REFS):
		addr = GLOBAL_REFS[idx]
		find_refs_to(addr, label_for(addr))
		scan_refs_windows(addr, label_for(addr), 12)
		idx += 1

def audit_windows():
	idx = 0
	while idx < len(DISASM_WINDOWS):
		addr = DISASM_WINDOWS[idx]
		write("")
		write("Bytes @ 0x%08x (%s): %s" % (addr, label_for(addr), read_bytes(addr, 16)))
		disasm_window(addr, 14, 34, label_for(addr))
		idx += 1

def audit_functions():
	idx = 0
	while idx < len(FUNCTION_TARGETS):
		addr = FUNCTION_TARGETS[idx]
		decompile_at(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))
		print_matching_decompile_lines(addr, label_for(addr))
		idx += 1

def print_header():
	write("FNV GRAPHICS WEATHER/FOG CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. Which FNV Sky offsets expose first/second weather and weather blend?")
	write("2. Which TESWeather fields or methods expose fog distance/color used by vanilla fog?")
	write("3. Can Psycho read fog constants safely before ProcessImageSpaceShaders?")
	write("4. Which values must remain research-only because they are TESReloaded-derived but not FNV-proven?")

def main():
	print_header()
	print_contract_notes()
	audit_globals()
	audit_windows()
	audit_functions()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_weather_fog_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
