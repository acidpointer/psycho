# @category Analysis
# @description Follow FNV PPLighting texture/material slot layout for Psycho PBR

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0046E8E0: "Texture map attach/name helper candidate",
	0x0046E910: "Extra named texture map enumerator candidate",
	0x0046EB00: "Dark Map getter candidate",
	0x0046EB20: "Detail Map getter candidate",
	0x0046EB40: "Gloss Map getter candidate",
	0x0046EB60: "Glow Map getter candidate",
	0x0046EB80: "Bump Map getter candidate",
	0x0046EBA0: "Decal Map getter candidate",
	0x0046EBD0: "Decal Map count getter candidate",
	0x00540FE0: "TESLandTexture texture set validator candidate",
	0x005453B0: "Object/model texture set application candidate",
	0x005454D0: "Fallback model/geometry getter candidate",
	0x00569580: "Primary model/geometry getter candidate",
	0x005922E0: "BGSTextureSet constructor candidate",
	0x00593140: "NullTextureSet singleton setup",
	0x00653270: "BSShader property flag helper candidate",
	0x00653290: "BSShader property flag/test helper candidate",
	0x00A59D30: "NiAVObject property lookup by type",
	0x00A5FCA0: "NiSourceTexture destructor",
	0x00A61A60: "Texture cache find/load candidate",
	0x00A6B410: "Normal string texture candidate",
	0x00B43D80: "Normal string texture candidate",
	0x00B55480: "Shader/model texture binding candidate",
	0x00BA9EE0: "Pass texture/state builder candidate",
	0x00BD9BC0: "PPLighting late pass branch candidate",
	0x00BD9F90: "PPLighting texture/material setup branch",
	0x00BDC030: "PPLighting +0xDC late branch candidate",
	0x00BDF790: "BSShaderPPLighting setup geometry",
	0x00BE1F90: "BSShader::SetShaders",
	0x00CCB810: "Normal string texture candidate",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x00E88A50: "NiDX9RenderState::GetTexture",
	0x01019894: "Glow Map string",
	0x0101C29C: "Normal string",
	0x0102E800: "TextureSet missing normal texture string",
	0x0102E860: "TextureSet missing diffuse texture string",
	0x01033EAC: "NullTextureSet string",
	0x011F91E0: "Current geometry/material context global",
	0x0126F74C: "Current NiD3DPass global",
}

FUNCTION_TARGETS = [
	0x0046E8E0,
	0x0046E910,
	0x0046EB00,
	0x0046EB20,
	0x0046EB40,
	0x0046EB60,
	0x0046EB80,
	0x0046EBA0,
	0x0046EBD0,
	0x00540FE0,
	0x005453B0,
	0x005454D0,
	0x00569580,
	0x005922E0,
	0x00593140,
	0x00653270,
	0x00653290,
	0x00A59D30,
	0x00A5FCA0,
	0x00A61A60,
	0x00A6B410,
	0x00B43D80,
	0x00B55480,
	0x00BA9EE0,
	0x00BD9BC0,
	0x00BD9F90,
	0x00BDC030,
	0x00BDF790,
	0x00BE1F90,
	0x00CCB810,
	0x00E88A20,
	0x00E88A50,
]

REF_TARGETS = [
	0x0046E8E0,
	0x0046E910,
	0x0046EB00,
	0x0046EB20,
	0x0046EB40,
	0x0046EB60,
	0x0046EB80,
	0x0046EBA0,
	0x0046EBD0,
	0x00540FE0,
	0x005453B0,
	0x005922E0,
	0x00593140,
	0x00653270,
	0x00653290,
	0x00A59D30,
	0x00B55480,
	0x00BA9EE0,
	0x00BD9F90,
	0x00BDC030,
	0x00BDF790,
	0x00E88A20,
	0x00E88A50,
	0x01019894,
	0x0101C29C,
	0x0102E800,
	0x0102E860,
	0x01033EAC,
	0x011F91E0,
	0x0126F74C,
]

MATCH_PATTERNS = [
	"param_1[0x37]",
	"+ 0xdc",
	"+0xdc",
	"+ 0x6c",
	"+0x6c",
	"+ 0x8c",
	"+0x8c",
	"+ 0x9c",
	"+0x9c",
	"+ 0xb8",
	"+0xb8",
	"+ 0x1d0",
	"+0x1d0",
	"texture",
	"textureset",
	"nitexturingproperty",
	"normal",
	"bump",
	"glow",
	"gloss",
	"dark",
	"detail",
	"decal",
	"diffuse",
	"specular",
	"material",
	"011f91e0",
	"0126f74c",
]

INSTRUCTION_PATTERNS = [
	"+ 0xdc",
	"+0xdc",
	"+ 0x6c",
	"+0x6c",
	"+ 0x8c",
	"+0x8c",
	"+ 0x9c",
	"+0x9c",
	"+ 0x1d0",
	"+0x1d0",
	"0x011f91e0",
	"0x0126f74c",
	"0x01019894",
	"0x0101c29c",
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
		from_addr = ref.getFromAddress()
		from_func = fm.getFunctionContaining(from_addr)
		fname = from_func.getName() if from_func else "???"
		inst = listing.getInstructionContaining(from_addr)
		inst_text = inst.toString() if inst is not None else ""
		write("  %s @ 0x%08x (in %s) %s" % (ref.getReferenceType(), from_addr.getOffset(), fname, inst_text))
		count += 1
		if count > 160:
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
	write("SLOT/TEXTURE MATCHES: %s @ 0x%08x" % (label, addr_int))
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

def add_ref_functions(addr, functions):
	refs = ref_mgr.getReferencesTo(addr)
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is not None:
			functions[func.getEntryPoint().getOffset()] = True

def audit_refs(functions):
	idx = 0
	while idx < len(REF_TARGETS):
		addr = REF_TARGETS[idx]
		find_refs_to(addr, label_for(addr))
		add_ref_functions(toAddr(addr), functions)
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

def audit_ref_functions(functions, max_functions):
	write("")
	write("=" * 70)
	write("DECOMPILE FUNCTIONS THAT REFERENCE TARGETS")
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

def instruction_matches(text):
	lower = text.lower()
	idx = 0
	while idx < len(INSTRUCTION_PATTERNS):
		if lower.find(INSTRUCTION_PATTERNS[idx]) >= 0:
			return True
		idx += 1
	return False

def scan_instruction_patterns(max_matches):
	write("")
	write("=" * 70)
	write("GLOBAL INSTRUCTION PATTERN SCAN")
	write("=" * 70)
	inst_iter = listing.getInstructions(True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		if not instruction_matches(text):
			continue
		addr_int = inst.getAddress().getOffset()
		if addr_int < 0x00400000 or addr_int > 0x00F00000:
			continue
		func = fm.getFunctionContaining(inst.getAddress())
		fname = func.getName() if func is not None else "???"
		write("  0x%08x in %s: %s" % (addr_int, fname, text))
		count += 1
		if count >= max_matches:
			write("  ... instruction scan truncated")
			break
	write("  Total instruction matches printed: %d" % count)

def print_header():
	write("FNV MATERIAL TEXTURE SLOT LAYOUT FOLLOWUP AUDIT")
	write("")
	write("Questions:")
	write("1. What is BSShaderPPLighting object field +0xDC (param_1[0x37])?")
	write("2. What does that object's +0x6C gate represent before pass IDs 4/5?")
	write("3. Which functions map diffuse/normal/bump/glow/gloss/dark/decal source slots to draw-time bindings?")
	write("4. Can Psycho safely attach roughness/metalness conventions without trusting 0x011F91E0 outside the draw path?")

def main():
	functions = {}
	print_header()
	audit_refs(functions)
	audit_functions()
	audit_ref_functions(functions, 90)
	scan_instruction_patterns(220)
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_material_texture_slot_layout_followup_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
