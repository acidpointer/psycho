# @category Analysis
# @description Audit FNV PPLighting runtime texture arrays and draw-time stage binding

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x004B6360: "Caller of B668B0/B675C0 tex-effect setter path",
	0x004B6630: "Caller of B675C0 tex-effect setter path",
	0x00507B40: "Caller of B675C0 tex-effect setter path",
	0x00507C90: "Caller of B675C0 tex-effect setter path",
	0x00539960: "Constructs 0x104 PPLighting object and fills runtime texture arrays",
	0x00B66640: "Landscape per-layer flag initializer at +0xC4",
	0x00B66AD0: "Runtime texture array refresh from provider vcall +0x90",
	0x00B66F50: "0x104 PPLighting object constructor, vptr 0x010AE0D0",
	0x00B675C0: "spTexEffectData setter at +0xDC",
	0x00B676A0: "PPLighting copy/assign for arrays and spTexEffectData",
	0x00B68660: "Runtime texture array slot setter from provider vcall +0x90",
	0x00B690D0: "PPLighting serialization/name fanout for texture arrays",
	0x00B70590: "PPLighting texture iterator helper candidate",
	0x00B70600: "PPLighting texture iterator helper candidate",
	0x00B70680: "PPLighting texture iterator helper candidate",
	0x00B70700: "PPLighting texture iterator helper candidate",
	0x00B707D0: "PPLighting texture count/helper candidate",
	0x00BDB4A0: "PPLighting setup variant",
	0x00BDF790: "PPLighting setup main",
	0x00BC3E40: "Additional setup path with tex-effect BD9D00 call",
	0x00BA95E0: "Pass/reset helper candidate",
	0x00BA9EE0: "NiD3DPass construction/bind helper candidate",
	0x00BE1F90: "BSShader::SetShaders",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x0126F74C: "Current NiD3DPass global",
	0x010AE0D0: "PPLighting object vtable base",
	0x010AE1E4: "PPLighting setup variant slot -> BDB4A0",
	0x010AE1E8: "PPLighting setup main slot -> BDF790",
}

KEY_FUNCTIONS = [
	0x00539960,
	0x00B66F50,
	0x00B66640,
	0x00B66AD0,
	0x00B68660,
	0x00B676A0,
	0x00B690D0,
	0x00B70590,
	0x00B70600,
	0x00B70680,
	0x00B70700,
	0x00B707D0,
	0x00BDB4A0,
	0x00BDF790,
	0x00BC3E40,
	0x00BA9EE0,
	0x00BA95E0,
	0x00BE1F90,
	0x00E88A20,
]

SETTER_CALLERS = [
	0x004B6360,
	0x004B6630,
	0x00507B40,
	0x00507C90,
]

PASS_BUILDERS = [
	0x00BD9540,
	0x00BD9770,
	0x00BD9840,
	0x00BD99C0,
	0x00BD9AC0,
	0x00BD9BC0,
	0x00BD9D00,
	0x00BD9DA0,
	0x00BD9E60,
	0x00BD9F00,
	0x00BD9F90,
	0x00BDA030,
	0x00BDA0A0,
	0x00BDAC00,
	0x00BDAF10,
	0x00BDB380,
	0x00BDBF60,
	0x00BDC030,
	0x00BDC0D0,
	0x00BDC530,
	0x00BDCA60,
	0x00BDD050,
	0x00BDD520,
	0x00BDDA20,
	0x00BDDBC0,
	0x00BDDD80,
	0x00BDDE10,
	0x00BDDFB0,
	0x00BDE170,
	0x00BDE1D0,
	0x00BDE9B0,
	0x00BDEF40,
	0x00BDF3E0,
	0x00BDF650,
]

REF_TARGETS = [
	0x00B66640,
	0x00B66AD0,
	0x00B68660,
	0x00B70590,
	0x00B70600,
	0x00B70680,
	0x00B70700,
	0x00B707D0,
	0x00BDB4A0,
	0x00BDF790,
	0x00BA9EE0,
	0x00BA95E0,
	0x00BE1F90,
	0x00E88A20,
	0x0126F74C,
	0x010AE0D0,
	0x010AE1E4,
	0x010AE1E8,
]

DATA_WINDOWS = [
	0x010AE0D0,
	0x010AE1E4,
	0x010AE1E8,
	0x0126F74C,
]

FIELD_OFFSETS = [
	(0xA4, "source/provider pointer"),
	(0xA8, "runtime texture count"),
	(0xAC, "texture array 0 / base diffuse"),
	(0xB0, "texture array 1 / normal"),
	(0xB4, "texture array 2 / glow skin hair layer"),
	(0xB8, "texture array 3 / heightmap"),
	(0xBC, "texture array 4 / envmap"),
	(0xC0, "texture array 5 / envmap mask"),
	(0xC4, "per-layer flags"),
	(0xC8, "highest base layer index"),
	(0xCC, "per-layer type flags"),
	(0xD0, "refcounted runtime field"),
	(0xD4, "runtime field"),
	(0xD8, "runtime field"),
	(0xDC, "spTexEffectData, not PBR maps"),
	(0xE0, "runtime float/field"),
	(0xE4, "runtime float/field"),
]

MATCH_PATTERNS = [
	"param_1[0x2a]",
	"param_1[0x2b]",
	"param_1[0x2c]",
	"param_1[0x2d]",
	"param_1[0x2e]",
	"param_1[0x2f]",
	"param_1[0x30]",
	"param_1[0x31]",
	"param_1[0x32]",
	"param_1[0x33]",
	"param_1[0x34]",
	"param_1[0x35]",
	"param_1[0x36]",
	"param_1[0x37]",
	"+ 0xa8",
	"+0xa8",
	"+ 0xac",
	"+0xac",
	"+ 0xb0",
	"+0xb0",
	"+ 0xb4",
	"+0xb4",
	"+ 0xb8",
	"+0xb8",
	"+ 0xbc",
	"+0xbc",
	"+ 0xc0",
	"+0xc0",
	"+ 0xc4",
	"+0xc4",
	"+ 0xc8",
	"+0xc8",
	"+ 0xcc",
	"+0xcc",
	"+ 0xd0",
	"+0xd0",
	"+ 0xd4",
	"+0xd4",
	"+ 0xd8",
	"+0xd8",
	"+ 0xdc",
	"+0xdc",
	"b70590",
	"b70600",
	"b70680",
	"b70700",
	"b707d0",
	"ba9ee0",
	"e88a20",
	"settexture",
	"texture",
	"sampler",
	"stage",
	"pass",
	"base diff",
	"base tex",
	"normal",
	"glow",
	"heightmap",
	"envmap",
	"mask",
	"0xc1",
	"0xc2",
	"0x250",
	"0x251",
	"0x252",
	"0x254",
	"0x231",
	"0x232",
	"0x233",
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

def read_dword(addr_int):
	try:
		return memory.getInt(toAddr(addr_int)) & 0xffffffff
	except:
		return None

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
	write("MATCHED DECOMPILE LINES: %s @ 0x%08x" % (label, addr_int))
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
		write("  0x%08x: %-56s%s%s" % (addr_int, inst.toString(), marker, extra))
		inst = inst.getNext()
		idx += 1

def dump_data_window(addr_int, before_slots, after_slots):
	write("")
	write("=" * 70)
	write("DATA WINDOW AROUND 0x%08x (%s)" % (addr_int, label_for(addr_int)))
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

def text_has_field_offset(text, offset):
	lower = text.lower()
	if lower.find("+ 0x%x" % offset) >= 0:
		return True
	if lower.find("+0x%x" % offset) >= 0:
		return True
	if lower.find("+ %d" % offset) >= 0:
		return True
	if lower.find("+%d" % offset) >= 0:
		return True
	return False

def text_has_any_field_offset(text):
	idx = 0
	while idx < len(FIELD_OFFSETS):
		if text_has_field_offset(text, FIELD_OFFSETS[idx][0]):
			return True
		idx += 1
	return False

def call_target_from_inst(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		if ref.getReferenceType().isCall():
			return ref.getToAddress().getOffset()
	return None

def is_important_call(target):
	if target is None:
		return False
	if target == 0x00BA9EE0 or target == 0x00BA95E0 or target == 0x00E88A20 or target == 0x00BE1F90:
		return True
	idx = 0
	while idx < len(PASS_BUILDERS):
		if target == PASS_BUILDERS[idx]:
			return True
		idx += 1
	idx = 0
	while idx < 5:
		if target == KEY_FUNCTIONS[7 + idx]:
			return True
		idx += 1
	return False

def scan_function_markers(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("=" * 70)
	write("INSTRUCTION MARKERS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		target = call_target_from_inst(inst)
		if text_has_any_field_offset(text) or is_important_call(target):
			if target is None:
				write("  0x%08x: %s" % (inst.getAddress().getOffset(), text))
			else:
				write("  0x%08x: %s ; CALL 0x%08x %s" % (inst.getAddress().getOffset(), text, target, label_for(target)))
			disasm_window(inst.getAddress().getOffset(), 6, 12, "marker")
			count += 1
			if count > 100:
				write("  ... marker scan truncated")
				break
	write("  Total marker instructions: %d" % count)

def print_field_layout():
	write("")
	write("=" * 70)
	write("PPLighting runtime texture field layout under audit")
	write("=" * 70)
	idx = 0
	while idx < len(FIELD_OFFSETS):
		write("  +0x%02X: %s" % (FIELD_OFFSETS[idx][0], FIELD_OFFSETS[idx][1]))
		idx += 1

def audit_data_windows():
	idx = 0
	while idx < len(DATA_WINDOWS):
		dump_data_window(DATA_WINDOWS[idx], 12, 36)
		idx += 1

def audit_refs():
	idx = 0
	while idx < len(REF_TARGETS):
		find_refs_to(REF_TARGETS[idx], label_for(REF_TARGETS[idx]))
		idx += 1
	idx = 0
	while idx < len(PASS_BUILDERS):
		find_refs_to(PASS_BUILDERS[idx], label_for(PASS_BUILDERS[idx]))
		idx += 1

def audit_key_functions():
	idx = 0
	while idx < len(KEY_FUNCTIONS):
		addr = KEY_FUNCTIONS[idx]
		label = label_for(addr)
		decompile_at(addr, label, 26000)
		find_and_print_calls_from(addr, label)
		print_matching_decompile_lines(addr, label)
		scan_function_markers(addr, label)
		idx += 1

def audit_setter_callers():
	idx = 0
	while idx < len(SETTER_CALLERS):
		addr = SETTER_CALLERS[idx]
		label = label_for(addr)
		decompile_at(addr, label, 14000)
		find_and_print_calls_from(addr, label)
		print_matching_decompile_lines(addr, label)
		scan_function_markers(addr, label)
		idx += 1

def audit_pass_builders():
	idx = 0
	while idx < len(PASS_BUILDERS):
		addr = PASS_BUILDERS[idx]
		label = label_for(addr)
		decompile_at(addr, label, 12000)
		find_and_print_calls_from(addr, label)
		print_matching_decompile_lines(addr, label)
		scan_function_markers(addr, label)
		idx += 1

def print_header():
	write("FNV PPLIGHTING TEXTURE ARRAY STAGE BINDING AUDIT")
	write("")
	write("Questions:")
	write("1. Which PPLighting functions consume arrays +0xAC/+0xB0/+0xB4/+0xB8/+0xBC/+0xC0?")
	write("2. How do iterator helpers B70590/B70600/B70680/B70700/B707D0 walk those arrays?")
	write("3. Which pass builders receive iterator outputs and create NiD3DPass records through BA9EE0?")
	write("4. Where do those pass records become final D3D texture stages through SetShaders/SetTexture?")
	write("5. Are any six-array slots usable for PBR map discovery without relying on spTexEffectData +0xDC?")

def main():
	print_header()
	print_field_layout()
	audit_data_windows()
	audit_refs()
	audit_key_functions()
	audit_setter_callers()
	audit_pass_builders()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pplighting_texture_array_stage_binding_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
