# @category Analysis
# @description Prove object ambient, light-list, light-fade, and specular-row transition ownership for PBR blinking

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

FUNCTION_TARGETS = [
	(0x00B66B80, "BSShaderPPLightingProperty::GetSpecularFade"),
	(0x00B70590, "PPLighting primary light selection helper"),
	(0x00B70820, "PPLighting ambient and per-light color staging"),
	(0x00B78A90, "PPLighting current-draw light constant staging"),
	(0x00B7DAB0, "PPLighting pass resource and constant dispatcher"),
	(0x00B994F0, "PPLighting current geometry and selector publisher"),
	(0x00BB4740, "PPLighting distance and selector cache updater"),
	(0x00BD4BA0, "PPLighting current pass apply"),
	(0x00BDB4A0, "PPLighting selector setup variant A"),
	(0x00BDF790, "PPLighting selector setup variant B"),
	(0x00BE1F90, "BSShader::SetShaders"),
]

GLOBAL_TARGETS = [
	(0x011FA0C0, "AmbientColor c1 backing"),
	(0x011FA0D0, "PSLightColor c3 array backing"),
	(0x011FA1F0, "staged LightData array"),
	(0x011FD9A8, "renderer LightData c25 and high-path light direction backing"),
	(0x011FD9B8, "high-path PSLightPosition c19 backing"),
	(0x011F91E0, "current PPLighting geometry"),
	(0x011F91E4, "current PPLighting row or pass id"),
	(0x011F91B8, "current PPLighting lighting mode"),
	(0x011F9454, "specular fade start"),
	(0x011F9458, "specular fade end"),
]

STRING_TARGETS = [
	"Ambient Color",
	"LightColors",
	"Light Position0",
	"LightData",
	"specular lod",
]

MATCH_PATTERNS = [
	"011fa0c0",
	"011fa0d0",
	"011fa1f0",
	"011fd9a8",
	"011fd9b8",
	"011f91e0",
	"011f91e4",
	"011f91b8",
	"011f9454",
	"011f9458",
	"0xf4",
	"0xf5",
	"0xf8",
	"0xc4",
	"0xd0",
	"0xd4",
	"0xe0",
	"0x10c",
	"ambient",
	"light",
	"specular",
]

def write(msg):
	output.append(msg)
	print(msg)

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
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		inst = listing.getInstructionContaining(ref.getFromAddress())
		inst_text = inst.toString() if inst is not None else ""
		write("  %s @ 0x%08x (in %s) %s" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, inst_text))
		count += 1
		if count > 160:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found at 0x%08x]" % addr_int)
		return
	body = func.getBody()
	inst_iter = currentProgram.getListing().getInstructions(body, True)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
	write("  Total: %d calls" % count)

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

def print_matching_lines(addr_int, label):
	write("")
	write("MATCHED LINES: %s @ 0x%08x" % (label, addr_int))
	code = decompile_text(addr_int)
	if code is None:
		write("  [decompilation failed]")
		return
	lines = code.splitlines()
	line_index = 0
	count = 0
	while line_index < len(lines):
		lower = lines[line_index].lower()
		pattern_index = 0
		matched = False
		while pattern_index < len(MATCH_PATTERNS):
			if lower.find(MATCH_PATTERNS[pattern_index].lower()) >= 0:
				matched = True
				break
			pattern_index += 1
		if matched:
			write("  L%04d: %s" % (line_index + 1, lines[line_index]))
			count += 1
		line_index += 1
	write("  Total matched lines: %d" % count)

def find_string_addresses(target):
	addresses = []
	data_iter = listing.getDefinedData(True)
	while data_iter.hasNext():
		data = data_iter.next()
		value = data.getValue()
		if value is not None and str(value).lower().find(target.lower()) >= 0:
			addresses.append(data.getAddress().getOffset())
	return addresses

def audit_string(target):
	write("")
	write("STRING AUDIT: %s" % target)
	addresses = find_string_addresses(target)
	index = 0
	while index < len(addresses):
		find_refs_to(addresses[index], "string %s" % target)
		index += 1
	write("  Total string matches: %d" % len(addresses))

def audit_functions():
	index = 0
	while index < len(FUNCTION_TARGETS):
		item = FUNCTION_TARGETS[index]
		decompile_at(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])
		print_matching_lines(item[0], item[1])
		index += 1

def audit_globals():
	index = 0
	while index < len(GLOBAL_TARGETS):
		item = GLOBAL_TARGETS[index]
		find_refs_to(item[0], item[1])
		index += 1

def audit_strings():
	index = 0
	while index < len(STRING_TARGETS):
		audit_string(STRING_TARGETS[index])
		index += 1

def print_questions():
	write("FNV PBR OBJECT LIGHTING TRANSITION OWNERSHIP AUDIT")
	write("")
	write("Questions that must be closed before changing object PBR again:")
	write("1. Which engine fields and fade terms produce AmbientColor c1 and every PSLightColor c3..c12 entry?")
	write("2. Does light fade multiply RGB before upload, live in alpha, or differ between low and ADTS10 object paths?")
	write("3. Which value controls the active-light count, and can camera rotation change light membership or ordering?")
	write("4. Which row transition changes diffuse, combined-specular, only-light, and only-specular ownership?")
	write("5. Which transitions are continuous in native bytecode and which depend on a separate pass?")
	write("6. What stable draw key can runtime telemetry use to correlate one geometry across adjacent frames?")
	write("")
	write("Required outcome: identify the exact changing input or row before selecting a shader or engine-side fix.")

def main():
	print_questions()
	audit_strings()
	audit_globals()
	audit_functions()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_object_lighting_transition_ownership_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
