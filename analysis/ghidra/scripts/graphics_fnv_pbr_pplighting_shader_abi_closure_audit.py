# @category Analysis
# @description Close FNV PPLighting native PBR shader ABI: source paths, shader families, constants, and texture stages

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00B74000: "PPLighting vertex group A CreateVertexShader callsite",
	0x00B740B3: "PPLighting vertex group B CreateVertexShader callsite",
	0x00B7419F: "PPLighting vertex group C CreateVertexShader callsite",
	0x00B78720: "PPLighting pixel group A CreatePixelShader callsite",
	0x00B78907: "PPLighting pixel group B CreatePixelShader callsite",
	0x00BD4BA0: "PPLighting current-pass shader-interface apply",
	0x00BDB4A0: "PPLighting selector setup +0xF0",
	0x00BDF790: "PPLighting selector setup +0xF4",
	0x00BE0FE0: "BSShader::CreateVertexShader",
	0x00BE1750: "BSShader::CreatePixelShader",
	0x00BE1F90: "BSShader::SetShaders",
	0x00E826D0: "shader-interface field apply",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x00E90B10: "renderer +0x8C4 texture resolver vfunc",
	0x010A93B4: "ps_3_0",
	0x010A93DC: "vs_3_0",
	0x010AE8D8: "SLS1S%03i.vso",
	0x010AE8E8: "SLS1%03i.vso",
	0x010AEDA8: "lighting\\1x\\v\\base.v.hlsl",
	0x010AEDF0: "SLS1%03i.pso",
	0x010AF2B4: "lighting\\1x\\p\\diffusePt.p.hlsl",
	0x010AF2D4: "lighting\\1x\\p\\base.p.hlsl",
	0x011FDA48: "PPLighting pixel group A",
	0x011FDB08: "PPLighting pixel group B",
	0x011FDD88: "PPLighting vertex group A",
	0x011FDE04: "PPLighting vertex group B",
	0x011FDE5C: "PPLighting vertex group C",
	0x0126F74C: "current NiD3DPass global",
}

STRING_TARGETS = [
	(0x010A93B4, "ps_3_0"),
	(0x010A93DC, "vs_3_0"),
	(0x010AE8D8, "SLS1S%03i.vso"),
	(0x010AE8E8, "SLS1%03i.vso"),
	(0x010AEDA8, "lighting\\1x\\v\\base.v.hlsl"),
	(0x010AEDF0, "SLS1%03i.pso"),
	(0x010AF2B4, "lighting\\1x\\p\\diffusePt.p.hlsl"),
	(0x010AF2D4, "lighting\\1x\\p\\base.p.hlsl"),
]

GLOBAL_ARRAYS = [
	(0x011FDD88, "vertex group A", 0x1F),
	(0x011FDE04, "vertex group B", 0x16),
	(0x011FDE5C, "vertex group C", 0x67),
	(0x011FDA48, "pixel group A", 0x30),
	(0x011FDB08, "pixel group B", 0xA0),
]

CREATE_CALLS = [
	(0x00B74000, "vertex group A creation"),
	(0x00B740B3, "vertex group B creation"),
	(0x00B7419F, "vertex group C creation"),
	(0x00B78720, "pixel group A creation"),
	(0x00B78907, "pixel group B creation"),
]

FOCUS_FUNCTIONS = [
	(0x00B73FB0, "PPLighting shader table setup function", 42000),
	(0x00B785E0, "PPLighting pixel shader table setup function", 42000),
	(0x00BD4BA0, "current-pass shader-interface apply", 26000),
	(0x00BDB4A0, "selector setup +0xF0", 42000),
	(0x00BDF790, "selector setup +0xF4", 42000),
	(0x00BE1F90, "BSShader::SetShaders", 24000),
	(0x00E826D0, "shader-interface field apply", 22000),
	(0x00E88A20, "NiDX9RenderState::SetTexture", 18000),
]

CALL_TARGETS = [
	(0x00BE0FE0, "BSShader::CreateVertexShader"),
	(0x00BE1750, "BSShader::CreatePixelShader"),
	(0x00BE1F90, "BSShader::SetShaders"),
	(0x00E826D0, "shader-interface field apply"),
	(0x00E88A20, "NiDX9RenderState::SetTexture"),
	(0x00E90B10, "renderer +0x8C4 texture resolver vfunc"),
]

SCAN_PATTERNS = [
	"CreateVertexShader",
	"CreatePixelShader",
	"SetShaders",
	"SetTexture",
	"SetSamplerState",
	"SetPixelShaderConstant",
	"SetVertexShaderConstant",
	"constant",
	"register",
	"sampler",
	"texture",
	"stage",
	"lighting",
	"SLS1",
	"ps_3_0",
	"vs_3_0",
	"DAT_011fda48",
	"DAT_011fdb08",
	"DAT_011fdd88",
	"DAT_011fde04",
	"DAT_011fde5c",
	"DAT_0126f74c",
	"+ 0x44",
	"+0x44",
	"+ 0x5c",
	"+0x5c",
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
]

def write(msg):
	output.append(msg)
	print(msg)

def read_byte(addr_int):
	try:
		value = memory.getByte(toAddr(addr_int))
		if value < 0:
			value += 0x100
		return value
	except:
		return None

def read_c_string(addr_int, limit):
	chars = []
	index = 0
	while index < limit:
		value = read_byte(addr_int + index)
		if value is None:
			return None
		if value == 0:
			break
		if value < 0x20 or value > 0x7e:
			return None
		chars.append(chr(value))
		index += 1
	if len(chars) < 3:
		return None
	return "".join(chars)

def label_for(addr_int):
	if addr_int is None:
		return "unreadable"
	label = KNOWN.get(addr_int)
	if label is not None:
		return label
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is not None:
		return func.getName()
	func = fm.getFunctionContaining(toAddr(addr_int))
	if func is not None:
		return "%s+0x%x" % (func.getName(), addr_int - func.getEntryPoint().getOffset())
	text = read_c_string(addr_int, 128)
	if text is not None:
		return "\"%s\"" % text
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

def decompile_at(addr_int, label, max_len=24000):
	write("")
	write("=" * 70)
	write("DECOMPILE: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	code = decompile_text(addr_int)
	if code is None:
		write("  [decompilation failed]")
		return
	if len(code) > max_len:
		write(code[:max_len])
		write("  ... [truncated, total chars=%d]" % len(code))
	else:
		write(code)

def find_refs_to(addr_int, label):
	write("")
	write("=" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_addr = ref.getFromAddress()
		from_func = fm.getFunctionContaining(from_addr)
		fname = from_func.getName() if from_func else "???"
		write("  %-18s @ 0x%08x in %s" % (str(ref.getReferenceType()), from_addr.getOffset(), fname))
		count += 1
	write("  Total refs: %d" % count)

def find_and_print_calls_from(addr_int, label):
	write("")
	write("=" * 70)
	write("Calls FROM %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found]")
		return
	inst = listing.getInstructionAt(func.getEntryPoint())
	count = 0
	while inst is not None and func.getBody().contains(inst.getAddress()):
		flows = inst.getFlows()
		if flows is not None and len(flows) > 0:
			for dest in flows:
				if inst.getFlowType().isCall():
					write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), dest.getOffset(), label_for(dest.getOffset())))
					count += 1
		inst = listing.getInstructionAfter(inst.getAddress())
	write("  Total direct calls: %d" % count)

def instruction_before_steps(inst, steps):
	cur = inst
	index = 0
	while cur is not None and index < steps:
		prev = listing.getInstructionBefore(cur.getAddress())
		if prev is None:
			break
		cur = prev
		index += 1
	return cur

def print_refs_from_instruction(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		target = ref.getToAddress()
		if target is None:
			continue
		target_int = target.getOffset()
		write("      ref %-18s -> 0x%08x %s" % (str(ref.getReferenceType()), target_int, label_for(target_int)))

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("=" * 70)
	write("DISASM: %s around 0x%08x" % (label, center_int))
	write("=" * 70)
	inst = listing.getInstructionContaining(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionAt(toAddr(center_int))
	if inst is None:
		write("  [instruction not found]")
		return
	cur = instruction_before_steps(inst, before_count)
	if cur is None:
		cur = inst
	limit = before_count + after_count + 1
	count = 0
	while cur is not None and count < limit:
		addr_int = cur.getAddress().getOffset()
		marker = "=> " if addr_int == inst.getAddress().getOffset() else "   "
		write("%s0x%08x: %-58s %s" % (marker, addr_int, cur.toString(), label_for(addr_int)))
		print_refs_from_instruction(cur)
		cur = listing.getInstructionAfter(cur.getAddress())
		count += 1

def scan_patterns(addr_int, label):
	write("")
	write("=" * 70)
	write("MATCHED DECOMPILE LINES: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	code = decompile_text(addr_int)
	if code is None:
		write("  [decompilation failed]")
		return
	lines = code.splitlines()
	line_no = 0
	for line in lines:
		line_no += 1
		lower = line.lower()
		for pattern in SCAN_PATTERNS:
			if pattern.lower() in lower:
				write("  L%-4d %s" % (line_no, line))
				break

def dump_known_string(addr_int, label):
	text = read_c_string(addr_int, 160)
	if text is None:
		text = "[unreadable]"
	write("  0x%08x %-40s %s" % (addr_int, label, text))

def print_known_strings():
	write("")
	write("=" * 70)
	write("Known shader path/profile strings")
	write("=" * 70)
	for item in STRING_TARGETS:
		dump_known_string(item[0], item[1])
		find_refs_to(item[0], item[1])

def print_global_arrays():
	write("")
	write("=" * 70)
	write("PPLighting shader array globals")
	write("=" * 70)
	for item in GLOBAL_ARRAYS:
		write("  0x%08x %-16s count=0x%x" % (item[0], item[1], item[2]))
		find_refs_to(item[0], "%s count=0x%x" % (item[1], item[2]))

def print_creation_windows():
	for item in CREATE_CALLS:
		disasm_window(item[0], 32, 28, item[1])

def decompile_focus():
	for item in FOCUS_FUNCTIONS:
		decompile_at(item[0], item[1], item[2])
		find_and_print_calls_from(item[0], item[1])
		scan_patterns(item[0], item[1])

def print_target_refs():
	for item in CALL_TARGETS:
		find_refs_to(item[0], item[1])

def main():
	write("FNV PBR PPLIGHTING SHADER ABI CLOSURE AUDIT")
	write("")
	write("Goal:")
	write("Close the exact shader ABI before broad native PBR rollout: shader source/profile selection, family array membership, pixel constants, vertex outputs, texture stage ownership, and SetShaders ordering.")
	write("")
	write("Current implementation expectation:")
	write("- s0 diffuse/base, s1 normal, s2 glow, s3 height, s4 environment, s5 environment mask")
	write("- c1 AmbientColor, c2 PSLightColor[0], c7 Toggles, c31 Psycho PBR material flags")
	write("- COLOR0 vertex color, COLOR1 fog, TEXCOORD0 uv, TEXCOORD1 light, TEXCOORD3 half vector, TEXCOORD6 view vector")
	write("")
	print_known_strings()
	print_global_arrays()
	print_creation_windows()
	print_target_refs()
	decompile_focus()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_shader_abi_closure_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
