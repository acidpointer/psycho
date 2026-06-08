# @category Analysis
# @description Deep scan FNV fog weather strings refs and field accessors for Psycho Graphics

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x004503F0: "TES/weather config getter candidate 004503F0",
	0x00450410: "TES/weather config getter candidate 00450410",
	0x00450430: "TES/weather config setter candidate 00450430",
	0x00450450: "TES/weather config setter candidate 00450450",
	0x00450460: "TES/weather config setter candidate 00450460",
	0x00450470: "TES/weather config setter candidate 00450470",
	0x00450490: "TES/weather config setter candidate 00450490",
	0x004504A0: "TES/weather config setter candidate 004504A0",
	0x004504B0: "TES/weather config setter candidate 004504B0",
	0x004504C0: "TES/weather config setter candidate 004504C0",
	0x004504D0: "TES/weather config setter candidate 004504D0",
	0x004504E0: "TES/weather config setter candidate 004504E0",
	0x004504F0: "TES/weather config setter candidate 004504F0",
	0x00450510: "TES/weather config setter candidate 00450510",
	0x00450520: "TES/weather config setter candidate 00450520",
	0x00450530: "TES/weather config setter candidate 00450530",
	0x00450540: "TES/weather config setter candidate 00450540",
	0x00450550: "TES/weather config setter candidate 00450550",
	0x00450560: "TES/weather config setter candidate 00450560",
	0x00450570: "Sky secondary getter candidate 00450570",
	0x004505A0: "Sky current climate/weather getter candidate",
	0x00450D80: "TES/weather config finalize candidate 00450D80",
	0x00595F10: "Sky sunrise/sunset byte getter",
	0x00595EA0: "Sky::GetSunriseBegin",
	0x00595F50: "Sky::GetSunriseEnd",
	0x00595FC0: "Sky::GetSunsetBegin",
	0x00596030: "Sky::GetSunsetEnd",
	0x00870BD0: "Main render world caller B",
	0x00875FD0: "RenderImageSpaceCaller_00875FD0",
	0x00B55AC0: "ImageSpaceManager::ProcessImageSpaceShaders",
	0x011DEA20: "Sky::singleton",
}

FUNCTION_TARGETS = [
	0x004503F0,
	0x00450410,
	0x00450430,
	0x00450450,
	0x00450460,
	0x00450470,
	0x00450490,
	0x004504A0,
	0x004504B0,
	0x004504C0,
	0x004504D0,
	0x004504E0,
	0x004504F0,
	0x00450510,
	0x00450520,
	0x00450530,
	0x00450540,
	0x00450550,
	0x00450560,
	0x00450570,
	0x004505A0,
	0x00450D80,
	0x00595F10,
	0x00870BD0,
	0x00875FD0,
	0x00B55AC0,
]

STRING_PATTERNS = [
	"fog",
	"weather",
	"climate",
	"sun glare",
	"sun damage",
	"sunrise",
	"sunset",
	"near",
	"far",
]

FIELD_PATTERNS = [
	"+ 0xc",
	"+ 0x10",
	"+ 0x14",
	"+ 0x28",
	"+ 0x50",
	"+ 0x54",
	"+ 0x60",
	"+ 0x6c",
	"+ 0xc0",
	"+ 0xe4",
	"+ 0xe5",
	"+ 0xf4",
	"+ 0x118",
	"011dea20",
	"fog",
	"weather",
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
		if count > 100:
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

def string_matches(value):
	lower = value.lower()
	idx = 0
	while idx < len(STRING_PATTERNS):
		if lower.find(STRING_PATTERNS[idx]) >= 0:
			return True
		idx += 1
	return False

def line_matches(line):
	lower = line.lower()
	idx = 0
	while idx < len(FIELD_PATTERNS):
		if lower.find(FIELD_PATTERNS[idx]) >= 0:
			return True
		idx += 1
	return False

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

def print_matching_decompile_lines(addr_int, label):
	write("")
	write("=" * 70)
	write("FOG/WEATHER FIELD MATCHES: %s @ 0x%08x" % (label, addr_int))
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

def add_ref_functions_for_string(addr, functions):
	refs = ref_mgr.getReferencesTo(addr)
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is not None:
			functions[func.getEntryPoint().getOffset()] = True

def scan_strings(max_strings, functions):
	write("")
	write("=" * 70)
	write("FOG/WEATHER STRING SCAN")
	write("=" * 70)
	data_iter = listing.getDefinedData(True)
	count = 0
	while data_iter.hasNext():
		data = data_iter.next()
		try:
			if not data.hasStringValue():
				continue
			value = str(data.getValue())
		except:
			continue
		if not string_matches(value):
			continue
		addr = data.getAddress()
		write("")
		write("String %d @ 0x%08x: %s" % (count + 1, addr.getOffset(), value[:180]))
		find_refs_to(addr.getOffset(), "string %s" % value[:60])
		add_ref_functions_for_string(addr, functions)
		count += 1
		if count >= max_strings:
			write("  ... string scan truncated")
			break
	write("Total strings printed: %d" % count)

def audit_string_ref_functions(functions, max_functions):
	write("")
	write("=" * 70)
	write("DECOMPILE FUNCTIONS REFERENCING MATCHED STRINGS")
	write("=" * 70)
	keys = functions.keys()
	keys.sort()
	idx = 0
	while idx < len(keys):
		addr = keys[idx]
		decompile_at(addr, label_for(addr), 12000)
		find_and_print_calls_from(addr, label_for(addr))
		print_matching_decompile_lines(addr, label_for(addr))
		idx += 1
		if idx >= max_functions:
			write("  ... string ref function scan truncated")
			break

def audit_known_functions():
	idx = 0
	while idx < len(FUNCTION_TARGETS):
		addr = FUNCTION_TARGETS[idx]
		decompile_at(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))
		print_matching_decompile_lines(addr, label_for(addr))
		idx += 1

def print_header():
	write("FNV GRAPHICS FOG/WEATHER DEEP FIELD AUDIT")
	write("")
	write("Questions:")
	write("1. Which real code references fog/weather/climate strings or settings?")
	write("2. Which functions read or write TESWeather fog near/far/color fields?")
	write("3. Which Sky/TES fields are current weather, next weather, and transition percent?")
	write("4. Can Psycho read fog constants safely before ProcessImageSpaceShaders?")

def main():
	functions = {}
	print_header()
	scan_strings(120, functions)
	audit_string_ref_functions(functions, 50)
	audit_known_functions()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_fog_weather_deep_field_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
