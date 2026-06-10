# @category Analysis
# @description Audit FNV weather sun fog color contracts used by NewVegasReloaded material-like effects

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0044EDB0: "GetCurrentWeather candidate",
	0x004505A0: "Sky current climate/weather getter candidate",
	0x0045CD60: "Sky sun/current object getter",
	0x0046DD00: "Weather controller setup/current world candidate",
	0x0050F9A0: "Weather slot value setter candidate",
	0x00532220: "Weather blend / fog setter candidate",
	0x00532E40: "Weather color/range helper candidate 00532E40",
	0x00532EC0: "Weather color/range helper candidate 00532EC0",
	0x00532F40: "Weather color/range helper candidate 00532F40",
	0x00532FD0: "Weather color blend helper candidate 00532FD0",
	0x00532FF0: "Default weather fallback candidate",
	0x005330E0: "Weather blend scalar helper candidate 005330E0",
	0x005822A0: "Climate weather slot getter candidate",
	0x00595EA0: "Sky::GetSunriseBegin",
	0x00595F50: "Sky::GetSunriseEnd",
	0x00595FC0: "Sky::GetSunsetBegin",
	0x00596030: "Sky::GetSunsetEnd",
	0x0043D450: "Weather color pointer/helper candidate 0043D450",
	0x00452DC0: "Weather color/field helper candidate 00452DC0",
	0x004DFE30: "Weather color blend result helper candidate 004DFE30",
	0x004E8880: "Weather color source helper candidate 004E8880",
	0x0063B630: "Sky weather phase weight builder",
	0x0063EF20: "Sky weather application/update",
	0x0063F790: "Weather slot weight setter candidate",
	0x006447D0: "Current weather percent getter candidate",
	0x006838B0: "Sky current weather/climate resolver candidate",
	0x006815C0: "Weather color/index helper candidate 006815C0",
	0x00B59D30: "Fog/weather vector/color writer helper 00B59D30",
	0x00B8AF10: "Fog/weather downstream setter 00B8AF10",
	0x00B8AF60: "Fog/weather downstream setter 00B8AF60",
	0x00B8AFB0: "Fog/weather downstream setter 00B8AFB0",
	0x00B8B000: "Fog/weather downstream setter 00B8B000",
	0x00B8B0D0: "Fog/weather downstream setter 00B8B0D0",
	0x00B8B1C0: "Fog/weather downstream setter 00B8B1C0",
	0x00B8B540: "Fog/weather downstream writer 00B8B540",
	0x00B8B610: "Fog/weather downstream writer 00B8B610",
	0x00B8BB70: "Fog/weather downstream setter 00B8BB70",
	0x00B8CB30: "Weather color downstream helper 00B8CB30",
	0x01034208: "Game time/weather byte divisor candidate",
	0x011CA9E8: "Cached sunrise/sunset global 0",
	0x011CA9EC: "Cached sunrise/sunset global 1",
	0x011CA9F0: "Cached sunrise/sunset global 2",
	0x011CA9F4: "Cached sunrise/sunset global 3",
	0x011CCB78: "Weather controller global candidate",
	0x011DEA20: "Sky::singleton",
}

FUNCTION_TARGETS = [
	0x0044EDB0,
	0x004505A0,
	0x0045CD60,
	0x0046DD00,
	0x0050F9A0,
	0x00532220,
	0x00532E40,
	0x00532EC0,
	0x00532F40,
	0x00532FD0,
	0x00532FF0,
	0x005330E0,
	0x005822A0,
	0x0043D450,
	0x00452DC0,
	0x004DFE30,
	0x004E8880,
	0x00595EA0,
	0x00595F50,
	0x00595FC0,
	0x00596030,
	0x0063B630,
	0x0063EF20,
	0x0063F790,
	0x006447D0,
	0x006838B0,
	0x006815C0,
	0x00B59D30,
	0x00B8AF10,
	0x00B8AF60,
	0x00B8AFB0,
	0x00B8B000,
	0x00B8B0D0,
	0x00B8B1C0,
	0x00B8B540,
	0x00B8B610,
	0x00B8BB70,
	0x00B8CB30,
]

REF_TARGETS = [
	0x0044EDB0,
	0x004505A0,
	0x0050F9A0,
	0x00532220,
	0x00532E40,
	0x00532EC0,
	0x00532F40,
	0x00532FD0,
	0x00532FF0,
	0x005330E0,
	0x005822A0,
	0x0043D450,
	0x00452DC0,
	0x004DFE30,
	0x004E8880,
	0x0063B630,
	0x0063EF20,
	0x0063F790,
	0x006447D0,
	0x006838B0,
	0x006815C0,
	0x00B59D30,
	0x00B8AF10,
	0x00B8AF60,
	0x00B8AFB0,
	0x00B8B000,
	0x00B8B0D0,
	0x00B8B1C0,
	0x00B8B540,
	0x00B8B610,
	0x00B8BB70,
	0x00B8CB30,
	0x01034208,
	0x011CA9E8,
	0x011CA9EC,
	0x011CA9F0,
	0x011CA9F4,
	0x011CCB78,
	0x011DEA20,
]

MATCH_PATTERNS = [
	"+ 0x10",
	"+ 0x14",
	"+ 0x1c",
	"+ 0x28",
	"+ 0x30",
	"+ 0x50",
	"+ 0x54",
	"+ 0x60",
	"+ 0xe8",
	"+ 0xec",
	"+ 0xf0",
	"+ 0xf4",
	"+ 0xf8",
	"+ 0xfc",
	"+ 0x100",
	"+ 0x101",
	"+ 0x104",
	"+ 0x108",
	"+ 0x10c",
	"+ 0x110",
	"+ 0x114",
	"+ 0x118",
	"+ 0x11c",
	"+ 0x120",
	"+ 0x124",
	"+ 0x128",
	"+ 0x12c",
	"011cca",
	"011ccb78",
	"011dea20",
	"011ca9e",
	"01034208",
	"color",
	"fog",
	"sun",
	"weather",
	"climate",
	"transition",
	"percent",
	"blend",
	"rgb",
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

def decompile_at(addr_int, label, max_len=32000):
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
		if count > 180:
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
	write("ENVIRONMENT COLOR MATCHES: %s @ 0x%08x" % (label, addr_int))
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

def scan_ref_function_decompiles(addr_int, label, max_refs):
	write("")
	write("=" * 70)
	write("DECOMPILE FUNCTIONS REFERENCING %s @ 0x%08x" % (label, addr_int))
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
		if seen.get(entry):
			continue
		seen[entry] = True
		decompile_at(entry, "%s ref function %s" % (label, func.getName()), 18000)
		print_matching_decompile_lines(entry, "%s ref function %s" % (label, func.getName()))
		count += 1
		if count >= max_refs:
			write("  ... (truncated ref-function scan)")
			break

def audit_functions():
	idx = 0
	while idx < len(FUNCTION_TARGETS):
		addr_int = FUNCTION_TARGETS[idx]
		decompile_at(addr_int, label_for(addr_int))
		print_matching_decompile_lines(addr_int, label_for(addr_int))
		find_and_print_calls_from(addr_int, label_for(addr_int))
		idx += 1

def audit_refs():
	idx = 0
	while idx < len(REF_TARGETS):
		addr_int = REF_TARGETS[idx]
		find_refs_to(addr_int, label_for(addr_int))
		idx += 1

def audit_ref_functions():
	scan_ref_function_decompiles(0x011CCB78, "Weather controller global candidate", 16)
	scan_ref_function_decompiles(0x011DEA20, "Sky::singleton", 16)
	scan_ref_function_decompiles(0x00532220, "Weather blend / fog setter candidate", 16)
	scan_ref_function_decompiles(0x00B8B1C0, "Fog/weather downstream setter 00B8B1C0", 12)
	scan_ref_function_decompiles(0x00B59D30, "Fog/weather vector/color writer helper 00B59D30", 12)
	scan_ref_function_decompiles(0x00B8CB30, "Weather color downstream helper 00B8CB30", 12)

def print_header():
	write("FNV NVR ENVIRONMENT COLOR CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. Which proven runtime source should Psycho use for fog color, sun color, and weather transition percent?")
	write("2. Are NVR source fields like firstWeather/secondWeather/weatherPercent directly valid in FNV, or are they TESReloaded extensions/guesses?")
	write("3. Which downstream fog/weather setters own final blended color/range state?")
	write("4. What data can be exposed to PBR-like material shaders without walking unproven TESWeather layouts?")
	write("")
	write("Compatibility rule:")
	write("Prefer normalized environment constants produced by guarded readers. Do not expose raw TESWeather/Sky fields until this output proves ownership, layout, and valid ranges.")

def main():
	print_header()
	audit_refs()
	audit_functions()
	audit_ref_functions()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_nvr_environment_color_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
