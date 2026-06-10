# @category Analysis
# @description Follow FNV BSShaderPPLighting runtime texture object and binding ownership

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0046E910: "Named material map enumerator",
	0x0046EB00: "Dark Map slot getter",
	0x0046EB20: "Detail Map slot getter",
	0x0046EB40: "Gloss Map slot getter",
	0x0046EB60: "Glow Map slot getter",
	0x0046EB80: "Bump Map slot getter",
	0x0046EBA0: "Decal Map slot getter",
	0x0046EBD0: "Decal Map count getter",
	0x005585E0: "Texture/name conversion helper candidate",
	0x005E03D0: "Texture-set enumeration cleanup candidate",
	0x00658930: "Texture-set slot count getter candidate",
	0x00877A30: "Texture-set slot pointer getter candidate",
	0x00A59D30: "NiAVObject property lookup by type",
	0x00BDB4A0: "BSShaderPPLighting setup geometry variant",
	0x00BD5E40: "PPLighting shader package/setup candidate",
	0x00BD8750: "PPLighting shader package/setup candidate",
	0x00BD9F90: "PPLighting texture/material setup branch",
	0x00BDC030: "PPLighting +0xDC late branch",
	0x00BDF790: "BSShaderPPLighting setup geometry",
	0x00BE0FE0: "BSShader::CreateVertexShader",
	0x00BE1750: "BSShader::CreatePixelShader",
	0x00BE1F90: "BSShader::SetShaders",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x010AE1E8: "BSShaderPPLighting vtable entry -> 00BDF790",
	0x010B8448: "BSShaderPPLighting vtable entry -> 00BDF790",
	0x010B9450: "BSShaderPPLighting vtable entry -> 00BDF790",
	0x010B95A8: "BSShaderPPLighting vtable entry -> 00BDF790",
	0x010B9A28: "BSShaderPPLighting vtable entry -> 00BDF790",
	0x010BAD10: "BSShaderPPLighting vtable entry -> 00BDF790",
	0x010BCC78: "BSShaderPPLighting vtable entry -> 00BDF790",
	0x011F49AC: "Material map name/object root",
	0x011F49B0: "Base map name",
	0x011F49B4: "Dark map name",
	0x011F49B8: "Detail map name",
	0x011F49BC: "Gloss map name",
	0x011F49C0: "Glow map name",
	0x011F49C4: "Bump map name",
	0x011F49C8: "Normal map name",
	0x011F49CC: "Parallax map name",
	0x011F49D0: "Decal map name",
	0x011F49D4: "Shader map name",
	0x0126F74C: "Current NiD3DPass global",
}

FUNCTION_TARGETS = [
	0x0046E910,
	0x0046EB00,
	0x0046EB20,
	0x0046EB40,
	0x0046EB60,
	0x0046EB80,
	0x0046EBA0,
	0x0046EBD0,
	0x005585E0,
	0x005E03D0,
	0x00658930,
	0x00877A30,
	0x00BDB4A0,
	0x00BD5E40,
	0x00BD8750,
	0x00BD9F90,
	0x00BDC030,
	0x00BDF790,
	0x00BE0FE0,
	0x00BE1750,
	0x00BE1F90,
	0x00E88A20,
]

REF_TARGETS = [
	0x005585E0,
	0x005E03D0,
	0x00658930,
	0x00877A30,
	0x00BDB4A0,
	0x00BD5E40,
	0x00BD8750,
	0x00BD9F90,
	0x00BDC030,
	0x00BDF790,
	0x00BE0FE0,
	0x00BE1750,
	0x00BE1F90,
	0x00E88A20,
	0x0126F74C,
]

VTABLE_REFS = [
	0x010AE1E8,
	0x010B8448,
	0x010B9450,
	0x010B95A8,
	0x010B9A28,
	0x010BAD10,
	0x010BCC78,
]

MATERIAL_GLOBALS = [
	0x011F49AC,
	0x011F49B0,
	0x011F49B4,
	0x011F49B8,
	0x011F49BC,
	0x011F49C0,
	0x011F49C4,
	0x011F49C8,
	0x011F49CC,
	0x011F49D0,
	0x011F49D4,
]

MATCH_PATTERNS = [
	"param_1[0x37]",
	"+ 0xdc",
	"+0xdc",
	"+ 0x6c",
	"+0x6c",
	"+ 0x30",
	"+0x30",
	"+ 0x8c",
	"+0x8c",
	"+ 0x9c",
	"+0x9c",
	"+ 0x114",
	"+0x114",
	"+ 0x1d0",
	"+0x1d0",
	"0126f74c",
	"settexture",
	"texture",
	"textureset",
	"dark",
	"detail",
	"gloss",
	"glow",
	"bump",
	"normal",
	"parallax",
	"decal",
	"shader",
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

def read_dword(addr_int):
	try:
		return memory.getInt(toAddr(addr_int)) & 0xffffffff
	except:
		return None

def decompile_at(addr_int, label, max_len=30000):
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
	write("RUNTIME TEXTURE MATCHES: %s @ 0x%08x" % (label, addr_int))
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

def dump_vtable_window(addr_int, before_slots, after_slots):
	write("")
	write("=" * 70)
	write("VTABLE/DATA WINDOW AROUND 0x%08x (%s)" % (addr_int, label_for(addr_int)))
	write("=" * 70)
	start = addr_int - before_slots * 4
	idx = 0
	total = before_slots + after_slots + 1
	while idx < total:
		slot_addr = start + idx * 4
		value = read_dword(slot_addr)
		marker = " << target" if slot_addr == addr_int else ""
		if value is None:
			write("  0x%08x: ????????%s" % (slot_addr, marker))
		else:
			write("  0x%08x: 0x%08x %s%s" % (slot_addr, value, label_for(value), marker))
		idx += 1

def audit_vtable_windows(functions):
	idx = 0
	while idx < len(VTABLE_REFS):
		addr = VTABLE_REFS[idx]
		dump_vtable_window(addr, 12, 18)
		idx += 1

def audit_refs(functions):
	idx = 0
	while idx < len(REF_TARGETS):
		addr = REF_TARGETS[idx]
		find_refs_to(addr, label_for(addr))
		add_ref_functions(toAddr(addr), functions)
		idx += 1
	idx = 0
	while idx < len(MATERIAL_GLOBALS):
		addr = MATERIAL_GLOBALS[idx]
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
	write("DECOMPILE TARGET REFERENCING FUNCTIONS")
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

def text_has_runtime_marker(text):
	lower = text.lower()
	if lower.find("+ 0xdc") >= 0:
		return True
	if lower.find("+0xdc") >= 0:
		return True
	if lower.find("0x0126f74c") >= 0:
		return True
	if lower.find("0x011f49") >= 0:
		return True
	if lower.find("0x00877a30") >= 0:
		return True
	return False

def scan_renderer_dc_instructions(max_matches):
	write("")
	write("=" * 70)
	write("RENDERER-RANGE +0xDC / TEXTURE RUNTIME INSTRUCTION SCAN")
	write("=" * 70)
	inst_iter = listing.getInstructions(True)
	count = 0
	functions = {}
	while inst_iter.hasNext():
		inst = inst_iter.next()
		addr_int = inst.getAddress().getOffset()
		if addr_int < 0x00B00000 or addr_int > 0x00C30000:
			continue
		text = inst.toString()
		if not text_has_runtime_marker(text):
			continue
		func = fm.getFunctionContaining(inst.getAddress())
		fname = func.getName() if func is not None else "???"
		write("  0x%08x in %s: %s" % (addr_int, fname, text))
		disasm_window(addr_int, 8, 14, "renderer runtime marker")
		if func is not None:
			functions[func.getEntryPoint().getOffset()] = True
		count += 1
		if count >= max_matches:
			write("  ... renderer runtime marker scan truncated")
			break
	write("  Total renderer marker matches printed: %d" % count)
	return functions

def print_header():
	write("FNV PPLIGHTING TEXTURE RUNTIME BINDING FOLLOWUP AUDIT")
	write("")
	write("Questions:")
	write("1. Which vtable/class variants use BSShaderPPLighting::SetupGeometry at 0x00BDF790?")
	write("2. Where is shader object field +0xDC written, cleared, or addrefed in renderer code?")
	write("3. Does +0xDC point to a texture set, shader property, or some other material resource?")
	write("4. How do source texture-set slots from FUN_00877A30 reach draw-time shader texture stages?")

def main():
	functions = {}
	print_header()
	audit_vtable_windows(functions)
	audit_refs(functions)
	audit_functions()
	renderer_functions = scan_renderer_dc_instructions(140)
	keys = renderer_functions.keys()
	idx = 0
	while idx < len(keys):
		functions[keys[idx]] = True
		idx += 1
	audit_ref_functions(functions, 110)
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pplighting_texture_runtime_binding_followup_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
