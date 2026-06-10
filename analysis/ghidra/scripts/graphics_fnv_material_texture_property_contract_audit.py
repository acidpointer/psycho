# @category Analysis
# @description Audit FNV material texture property discovery contracts for Psycho PBR

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x004BC320: "BSRenderedTexture::GetTexture",
	0x00559450: "NiPointer/ref getter helper",
	0x00653290: "BSShader property flag/test helper candidate",
	0x00A59D30: "NiAVObject property lookup candidate",
	0x00A5FCA0: "NiSourceTexture destructor",
	0x00A61A60: "Texture cache find/load candidate",
	0x00B4F5C0: "Shader manager singleton getter",
	0x00B63320: "Current geometry writer candidate",
	0x00B651E0: "Stack geometry proxy writer candidate",
	0x00B70590: "Shader light iterator begin candidate",
	0x00B70680: "Shader light iterator next candidate",
	0x00B70700: "Shader light count/get candidate",
	0x00B707D0: "Shader/material mode classifier candidate",
	0x00BA9EE0: "Pass texture/state builder candidate",
	0x00BD9DA0: "PPLighting geometry setup branch candidate",
	0x00BD9E60: "PPLighting geometry setup branch candidate",
	0x00BD9F00: "PPLighting alpha/material setup branch candidate",
	0x00BD9F90: "PPLighting texture/material setup branch candidate",
	0x00BDF790: "BSShaderPPLighting setup geometry candidate",
	0x00BE0800: "BSShaderPPLighting setup geometry interior",
	0x00BE08DB: "VanillaPlus observed SetupGeometry callsite",
	0x00BE1F90: "BSShader::SetShaders",
	0x00E68A80: "NiDX9SourceTextureData load/create candidate",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x00E88A50: "NiDX9RenderState::GetTexture",
	0x00E88930: "NiDX9RenderState::SetTextureStageState",
	0x00E910A0: "NiDX9RenderState::SetSamplerState",
	0x011F91E0: "BSShaderManager current geometry candidate",
	0x011F91E4: "BSShaderManager current shader mode/id candidate",
	0x0126F74C: "Current NiD3DPass global",
}

FUNCTION_TARGETS = [
	0x004BC320,
	0x00559450,
	0x00653290,
	0x00A59D30,
	0x00A5FCA0,
	0x00A61A60,
	0x00B4F5C0,
	0x00B63320,
	0x00B651E0,
	0x00B70590,
	0x00B70680,
	0x00B70700,
	0x00B707D0,
	0x00BA9EE0,
	0x00BD9DA0,
	0x00BD9E60,
	0x00BD9F00,
	0x00BD9F90,
	0x00BDF790,
	0x00BE0800,
	0x00BE1F90,
	0x00E68A80,
	0x00E88A20,
	0x00E88A50,
	0x00E88930,
	0x00E910A0,
]

REF_TARGETS = [
	0x00653290,
	0x00A59D30,
	0x00BA9EE0,
	0x00BD9DA0,
	0x00BD9E60,
	0x00BD9F00,
	0x00BD9F90,
	0x00BDF790,
	0x00BE0800,
	0x00BE08DB,
	0x00E68A80,
	0x00E88A20,
	0x00E88930,
	0x00E910A0,
	0x011F91E0,
	0x011F91E4,
	0x0126F74C,
]

MAGIC_VALUES = [
	0x1200788,
	0x12024C8,
	0x12007A0,
]

TEXTURE_STRING_PATTERNS = [
	"NiTexturingProperty",
	"TexturingProperty",
	"BSShaderTextureSet",
	"TextureSet",
	"textures",
	"Textures",
	"normal",
	"Normal",
	"specular",
	"Specular",
	"glow",
	"Glow",
	"envmap",
	"EnvMap",
	"parallax",
	"Parallax",
	"diffuse",
	"Diffuse",
	"material",
	"Material",
]

MATCH_PATTERNS = [
	"nitexturingproperty",
	"texturingproperty",
	"textureset",
	"texture",
	"normal",
	"specular",
	"glow",
	"envmap",
	"parallax",
	"diffuse",
	"material",
	"011f91e0",
	"011f91e4",
	"0126f74c",
	"1200788",
	"12024c8",
	"12007a0",
	"+ 0x20",
	"+ 0x24",
	"+ 0x28",
	"+ 0x2c",
	"+ 0x34",
	"+ 0x3c",
	"+ 0x6c",
	"+ 0x9c",
	"+ 0xb4",
	"+ 0xb8",
	"+ 0xdc",
	"+ 0xec",
	"+ 0x104",
	"+ 0x114",
	"+0x20",
	"+0x24",
	"+0x28",
	"+0x2c",
	"+0x34",
	"+0x3c",
	"+0x6c",
	"+0x9c",
	"+0xb4",
	"+0xb8",
	"+0xdc",
	"+0xec",
	"+0x104",
	"+0x114",
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

def decompile_at(addr_int, label, max_len=28000):
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
		if count > 200:
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
	write("MATERIAL/TEXTURE MATCHES: %s @ 0x%08x" % (label, addr_int))
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
	while idx < len(TEXTURE_STRING_PATTERNS):
		if value.find(TEXTURE_STRING_PATTERNS[idx]) >= 0:
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
	write("MATERIAL/TEXTURE STRING SCAN")
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
		find_refs_to(addr.getOffset(), "material/texture string %s" % value[:80])
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

def scan_magic_values():
	write("")
	write("=" * 70)
	write("MAGIC MATERIAL FLAG VALUE REFERENCES")
	write("=" * 70)
	idx = 0
	while idx < len(MAGIC_VALUES):
		value = MAGIC_VALUES[idx]
		find_refs_to(value, "immediate/material flag value 0x%08x" % value)
		idx += 1

def audit_functions():
	idx = 0
	while idx < len(FUNCTION_TARGETS):
		addr = FUNCTION_TARGETS[idx]
		write("")
		write("Bytes @ 0x%08x (%s): %s" % (addr, label_for(addr), read_bytes(addr, 16)))
		decompile_at(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))
		print_matching_decompile_lines(addr, label_for(addr))
		idx += 1

def audit_refs(functions):
	idx = 0
	while idx < len(REF_TARGETS):
		addr = REF_TARGETS[idx]
		find_refs_to(addr, label_for(addr))
		scan_refs_windows(addr, label_for(addr), 14)
		add_ref_functions(toAddr(addr), functions)
		idx += 1

def audit_ref_functions(functions, max_functions):
	write("")
	write("=" * 70)
	write("DECOMPILE FUNCTIONS THAT REFERENCE MATERIAL/TEXTURE TARGETS")
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
	write("FNV MATERIAL TEXTURE PROPERTY CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. Where does BSShaderPPLighting setup read NiTexturingProperty or texture-set data from geometry?")
	write("2. Which property flags and texture slots control diffuse/normal/glow/specular/envmap paths?")
	write("3. Can Psycho discover optional PBR textures from native material context without trusting 0x011F91E0 blindly?")
	write("4. Which texture binding path owns native SetTexture/SetSamplerState calls for safe restore?")
	write("")
	write("Expected use:")
	write("Use this to prove a draw-time material texture discovery contract before adding roughness/metalness conventions.")

def main():
	functions = {}
	print_header()
	scan_strings(120, functions)
	scan_magic_values()
	audit_refs(functions)
	audit_functions()
	audit_ref_functions(functions, 100)
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_material_texture_property_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
