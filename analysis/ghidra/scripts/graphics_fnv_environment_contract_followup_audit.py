# @category Analysis
# @description Follow up FNV camera fog weather environment contracts for OMV

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0044EDB0: "GetCurrentWeather candidate 0044EDB0",
	0x004505A0: "Sky current climate/weather getter candidate 004505A0",
	0x0045CD60: "Sky::GetSunObject candidate 0045CD60",
	0x0046DD00: "Weather command setup/current world candidate 0046DD00",
	0x0050F9A0: "ApplyWeather candidate 0050F9A0",
	0x00532FF0: "DefaultWeather fallback candidate 00532FF0",
	0x005822A0: "Climate weather slot getter candidate 005822A0",
	0x00595EA0: "Sky::GetSunriseBegin",
	0x00595F50: "Sky::GetSunriseEnd",
	0x00595FC0: "Sky::GetSunsetBegin",
	0x00596030: "Sky::GetSunsetEnd",
	0x0059EB60: "GetCurrentWeatherPercent script command",
	0x0059EBB0: "GetIsCurrentWeather script command",
	0x0063B630: "Sky weather phase weight builder 0063B630",
	0x0063EF20: "Sky weather application/update 0063EF20",
	0x0063F790: "Weather weight setter candidate 0063F790",
	0x006447D0: "Current weather percent getter candidate 006447D0",
	0x006838B0: "Sky current weather/climate resolver candidate 006838B0",
	0x00710AB0: "WorldCameraDepthValue_00710AB0",
	0x00874900: "FirstPersonCameraDepthValue_00874900",
	0x00875FD0: "RenderImageSpaceCaller_00875FD0",
	0x00B54000: "SetDepthOrClipValue_00B54000",
	0x00B5E870: "CameraWriter_00B5E870",
	0x00C52020: "SetCameraDepthValues_00C52020",
	0x011DEA20: "Sky::singleton",
	0x011F917C: "BSShaderManager::pCurrentCamera",
	0x011FA280: "Camera global block 0x011FA280",
	0x011FA2A0: "Camera position/vector global X",
	0x011FA2B0: "Camera basis/global candidate A",
	0x011FA2C0: "Camera basis/global candidate B",
}

FUNCTION_TARGETS = [
	0x0044EDB0,
	0x004505A0,
	0x0045CD60,
	0x0046DD00,
	0x0050F9A0,
	0x00532FF0,
	0x005822A0,
	0x0059EB60,
	0x0059EBB0,
	0x0063B630,
	0x0063EF20,
	0x0063F790,
	0x006447D0,
	0x006838B0,
	0x00710AB0,
	0x00874900,
	0x00875FD0,
	0x00B54000,
	0x00B5E870,
	0x00C52020,
]

REF_TARGETS = [
	0x0044EDB0,
	0x0050F9A0,
	0x00532FF0,
	0x005822A0,
	0x0063F790,
	0x006447D0,
	0x006838B0,
	0x00710AB0,
	0x00874900,
	0x00C52020,
	0x011DEA20,
	0x011F917C,
	0x011FA280,
	0x011FA2A0,
	0x011FA2B0,
	0x011FA2C0,
]

MATCH_PATTERNS = [
	"+ 0x10",
	"+ 0x14",
	"+ 0x28",
	"+ 0x50",
	"+ 0x54",
	"+ 0x60",
	"+ 0x8c",
	"+ 0x90",
	"+ 0x94",
	"+ 0xec",
	"+ 0xf0",
	"+ 0xf4",
	"+ 0xfc",
	"+ 0x100",
	"+ 0x110",
	"+ 0x12c",
	"+ 0x670",
	"+ 0x674",
	"+ 300",
	"011dea20",
	"011f917c",
	"011fa28",
	"011fa2",
	"0050f9a0",
	"00532ff0",
	"005822a0",
	"0063f790",
	"006447d0",
	"006838b0",
	"fog",
	"weather",
	"climate",
	"sunrise",
	"sunset",
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

def decompile_at(addr_int, label, max_len=22000):
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
	write("CONTRACT MATCHES: %s @ 0x%08x" % (label, addr_int))
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

def collect_ref_functions(addr_int, functions):
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is not None:
			functions[func.getEntryPoint().getOffset()] = True

def audit_targets(functions):
	idx = 0
	while idx < len(FUNCTION_TARGETS):
		addr = FUNCTION_TARGETS[idx]
		decompile_at(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))
		print_matching_decompile_lines(addr, label_for(addr))
		functions[addr] = True
		idx += 1

def audit_references(functions):
	idx = 0
	while idx < len(REF_TARGETS):
		addr = REF_TARGETS[idx]
		find_refs_to(addr, label_for(addr))
		collect_ref_functions(addr, functions)
		idx += 1

def audit_ref_functions(functions):
	write("")
	write("=" * 70)
	write("DECOMPILE FUNCTIONS THAT REFERENCE TARGETS")
	write("=" * 70)
	keys = functions.keys()
	keys.sort()
	idx = 0
	while idx < len(keys):
		addr = keys[idx]
		decompile_at(addr, label_for(addr), 14000)
		print_matching_decompile_lines(addr, label_for(addr))
		idx += 1
		if idx > 90:
			write("  ... referenced function scan truncated")
			break

def print_header():
	write("FNV GRAPHICS ENVIRONMENT CONTRACT FOLLOWUP AUDIT")
	write("")
	write("Questions:")
	write("1. Which object owns weather slots, time phase, and transition percent?")
	write("2. Does ApplyWeather candidate 0050F9A0 read TESWeather fog color/range fields?")
	write("3. Which callers own SetCameraDepthValues_00C52020 param_4 + 0xFC/+0x110?")
	write("4. Can any camera/frustum fields be safely exposed to Psycho shader constants?")

def main():
	functions = {}
	print_header()
	audit_targets(functions)
	audit_references(functions)
	audit_ref_functions(functions)
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_environment_contract_followup_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
