# @category Analysis
# @description Audit FNV final renderer sun/light color constants for Psycho PBR

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00532220: "Weather/generated color blend candidate",
	0x0063B630: "Sky weather phase weight builder",
	0x0063EF20: "Sky weather application/update",
	0x00870BD0: "Main render world caller",
	0x00877730: "Sky render/update refs candidate",
	0x00B7E330: "Shader package constant-table constructor candidate",
	0x00B7E430: "Shader global constant registration candidate",
	0x00BB2F50: "Shader constant finalization helper candidate",
	0x00BD3000: "Lighting shader constant registration candidate",
	0x00BD5A60: "Diffuse lighting shader constant registration candidate",
	0x00BDF790: "BSShaderPPLighting setup geometry candidate",
	0x00BE1F90: "BSShader::SetShaders",
	0x00E87C50: "NiDX9RenderState::SetFog",
	0x011FA0C0: "Ambient Color backing global",
	0x011FA0D0: "LightColors / Diff Color 0 backing global",
	0x011FA0E0: "Diff Color 1 backing global",
	0x011FA1F0: "LightRadius backing global",
	0x011FA280: "FogParam backing global",
	0x011FA290: "FogColor backing global",
	0x011FD894: "EyePosition backing global",
	0x011FD8A4: "eye dir backing global",
	0x011FD8C4: "FogParams backing global",
	0x011FD8D4: "FogColor shader backing global",
	0x011FD8E4: "FogPlane backing global",
	0x011FD944: "RefractionParams backing global",
	0x011FD968: "ShadowProj backing global",
	0x011FD9A8: "Light Direction / LightData backing global",
	0x011FD9B8: "Light Position0 backing global",
	0x011FD9C8: "Light Position1 backing global",
	0x011FD9D8: "Light Position2 backing global",
	0x011FD9E8: "Light Position3 backing global",
	0x011FEC38: "LightColors shader constant handle global",
	0x011FEC48: "Light Direction shader constant handle global",
}

FUNCTION_TARGETS = [
	0x00532220,
	0x0063B630,
	0x0063EF20,
	0x00870BD0,
	0x00877730,
	0x00B7E330,
	0x00B7E430,
	0x00BB2F50,
	0x00BD3000,
	0x00BD5A60,
	0x00BDF790,
	0x00BE1F90,
	0x00E87C50,
]

GLOBAL_REFS = [
	0x011FA0C0,
	0x011FA0D0,
	0x011FA0E0,
	0x011FA1F0,
	0x011FA280,
	0x011FA290,
	0x011FD894,
	0x011FD8A4,
	0x011FD8C4,
	0x011FD8D4,
	0x011FD8E4,
	0x011FD944,
	0x011FD968,
	0x011FD9A8,
	0x011FD9B8,
	0x011FD9C8,
	0x011FD9D8,
	0x011FD9E8,
	0x011FEC38,
	0x011FEC48,
]

STRING_PATTERNS = [
	"LightColors",
	"Light Direction",
	"LightData",
	"Diffuse Light color",
	"Diffuse Light direction",
	"DirectronalLightDir",
	"Diff Color 0",
	"Diff Color 1",
	"Ambient Color",
	"ambient color",
	"Light Position0",
	"Light Position1",
	"Light Position2",
	"Light Position3",
	"LightRadius",
	"FogColor",
	"FogParams",
	"fogcolor",
	"fogparam",
]

MATCH_PATTERNS = [
	"lightcolors",
	"light direction",
	"lightdata",
	"diffuse light color",
	"diffuse light direction",
	"directronallightdir",
	"diff color",
	"ambient color",
	"light position",
	"lightradius",
	"fogcolor",
	"fogparams",
	"011fa0c0",
	"011fa0d0",
	"011fa0e0",
	"011fa1f0",
	"011fa280",
	"011fa290",
	"011fd8",
	"011fd9",
	"011fec38",
	"011fec48",
	"+ 0x88",
	"+ 0x98",
	"+ 0xa0",
	"+ 0xb0",
	"+ 0xc0",
	"+ 0xe0",
	"+ 0xf0",
	"+0x88",
	"+0x98",
	"+0xa0",
	"+0xb0",
	"+0xc0",
	"+0xe0",
	"+0xf0",
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

def read_bytes(addr_int, count):
	values = []
	idx = 0
	while idx < count:
		try:
			value = memory.getByte(toAddr(addr_int + idx)) & 0xff
			values.append("%02X" % value)
		except:
			values.append("??")
		idx += 1
	return " ".join(values)

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
	write("SUN/LIGHT CONSTANT MATCHES: %s @ 0x%08x" % (label, addr_int))
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
	idx = 0
	while idx < len(STRING_PATTERNS):
		if value.find(STRING_PATTERNS[idx]) >= 0:
			return True
		idx += 1
	return False

def add_ref_functions(addr, functions):
	refs = ref_mgr.getReferencesTo(addr)
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is not None:
			functions[func.getEntryPoint().getOffset()] = True

def scan_strings(max_strings, functions):
	write("")
	write("=" * 70)
	write("SHADER CONSTANT STRING SCAN")
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
		find_refs_to(addr.getOffset(), "constant string %s" % value[:80])
		add_ref_functions(addr, functions)
		count += 1
		if count >= max_strings:
			write("  ... string scan truncated")
			break
	write("Total strings printed: %d" % count)

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
		disasm_window(from_addr, 10, 24, "reference to %s" % label)
		count += 1
		if count >= max_refs:
			write("  ... reference window scan truncated")
			break
	write("Total reference windows printed: %d" % count)

def audit_functions():
	idx = 0
	while idx < len(FUNCTION_TARGETS):
		addr = FUNCTION_TARGETS[idx]
		decompile_at(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))
		print_matching_decompile_lines(addr, label_for(addr))
		idx += 1

def audit_globals(functions):
	idx = 0
	while idx < len(GLOBAL_REFS):
		addr = GLOBAL_REFS[idx]
		write("")
		write("Bytes @ 0x%08x (%s): %s" % (addr, label_for(addr), read_bytes(addr, 32)))
		find_refs_to(addr, label_for(addr))
		scan_refs_windows(addr, label_for(addr), 12)
		add_ref_functions(toAddr(addr), functions)
		idx += 1

def audit_ref_functions(functions, max_functions):
	write("")
	write("=" * 70)
	write("DECOMPILE FUNCTIONS THAT REFERENCE LIGHT CONSTANTS")
	write("=" * 70)
	keys = functions.keys()
	keys.sort()
	idx = 0
	while idx < len(keys):
		addr = keys[idx]
		decompile_at(addr, label_for(addr), 18000)
		find_and_print_calls_from(addr, label_for(addr))
		print_matching_decompile_lines(addr, label_for(addr))
		idx += 1
		if idx >= max_functions:
			write("  ... referenced function scan truncated")
			break

def print_header():
	write("FNV FINAL RENDERER SUN/LIGHT COLOR CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. Which shader constant registrations carry final light color/direction data?")
	write("2. Are LightColors / Diffuse Light color backed by renderer globals or per-material object fields?")
	write("3. Which code writes the backing globals before BSShader::SetShaders?")
	write("4. Is there a renderer-owned PSY_SunColor source independent of the rejected Sun +0x1C/Main +0x1C alias?")
	write("")
	write("Expected use:")
	write("Prefer final shader constant backing stores if this proves writer ownership and lifetime. Do not use Reloaded's rejected Sun/Main directional-light alias.")

def main():
	functions = {}
	print_header()
	scan_strings(80, functions)
	audit_globals(functions)
	audit_functions()
	audit_ref_functions(functions, 90)
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_final_sun_color_renderer_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
