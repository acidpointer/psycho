# @category Analysis
# @description Audit FNV PPLighting shader input, constant, and texture-stage contract for first native PBR replacement

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00B74000: "selector +0x148 vertex create group A callsite",
	0x00B740B3: "selector +0x148 vertex create group B callsite",
	0x00B7419F: "selector +0x148 vertex create group C callsite",
	0x00B78720: "selector +0x14C pixel create group A callsite",
	0x00B78907: "selector +0x14C pixel create group B callsite",
	0x00BDB4A0: "PPLighting texture/pass setup variant A",
	0x00BDF790: "PPLighting texture/pass setup variant B",
	0x00BA8C50: "pass-entry apply/storage helper A",
	0x00BA8EC0: "pass-entry apply/storage helper B",
	0x00BA9EE0: "pass-entry construction helper",
	0x00BD4BA0: "current-pass shader-interface apply",
	0x00BE0FE0: "BSShader::CreateVertexShader",
	0x00BE1750: "BSShader::CreatePixelShader",
	0x00BE1F90: "BSShader::SetShaders",
	0x00E7F430: "shader-interface record finalize/apply helper",
	0x00E7F5D0: "shader-interface record factory/helper",
	0x00E826D0: "shader-interface field vtable +0x78 apply",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x00E88FC0: "tracked texture-stage cache helper A",
	0x00E89060: "tracked sampler-state cache helper",
	0x00E890C0: "tracked texture-stage cache helper B",
	0x010EF544: "shader-interface field vtable",
	0x011FDD88: "PPLighting vertex shader global group A",
	0x011FDE04: "PPLighting vertex shader global group B",
	0x011FDE5C: "PPLighting vertex shader global group C",
	0x011FDA48: "PPLighting pixel shader global group A",
	0x011FDB08: "PPLighting pixel shader global group B",
	0x0126F74C: "Current NiD3DPass global",
}

GLOBAL_ARRAYS = [
	(0x011FDD88, "vertex group A", 0x1F),
	(0x011FDE04, "vertex group B", 0x16),
	(0x011FDE5C, "vertex group C", 0x67),
	(0x011FDA48, "pixel group A", 0x30),
	(0x011FDB08, "pixel group B", 0xA0),
]

CREATE_CALLS = [
	(0x00B74000, "vertex group A creation callsite"),
	(0x00B740B3, "vertex group B creation callsite"),
	(0x00B7419F, "vertex group C creation callsite"),
	(0x00B78720, "pixel group A creation callsite"),
	(0x00B78907, "pixel group B creation callsite"),
]

FOCUS_FUNCTIONS = [
	(0x00BD4BA0, "current-pass shader-interface apply"),
	(0x00E826D0, "shader-interface field apply"),
	(0x00E7F430, "shader-interface record finalize/apply helper"),
	(0x00E7F5D0, "shader-interface record factory/helper"),
	(0x00BDB4A0, "PPLighting texture/pass setup variant A"),
	(0x00BDF790, "PPLighting texture/pass setup variant B"),
	(0x00BA8C50, "pass-entry apply/storage helper A"),
	(0x00BA8EC0, "pass-entry apply/storage helper B"),
	(0x00BA9EE0, "pass-entry construction helper"),
	(0x00E88A20, "NiDX9RenderState::SetTexture"),
	(0x00E88FC0, "tracked texture-stage cache helper A"),
	(0x00E89060, "tracked sampler-state cache helper"),
	(0x00E890C0, "tracked texture-stage cache helper B"),
	(0x00BE0FE0, "BSShader::CreateVertexShader"),
	(0x00BE1750, "BSShader::CreatePixelShader"),
	(0x00BE1F90, "BSShader::SetShaders"),
]

CALL_TARGETS = [
	(0x00E826D0, "shader-interface field apply"),
	(0x00E7F430, "shader-interface finalize/apply helper"),
	(0x00E7F5D0, "shader-interface factory/helper"),
	(0x00E88A20, "NiDX9RenderState::SetTexture"),
	(0x00E88FC0, "tracked texture-stage cache helper A"),
	(0x00E89060, "tracked sampler-state cache helper"),
	(0x00E890C0, "tracked texture-stage cache helper B"),
	(0x00BE0FE0, "BSShader::CreateVertexShader"),
	(0x00BE1750, "BSShader::CreatePixelShader"),
	(0x00BE1F90, "BSShader::SetShaders"),
]

SCAN_PATTERNS = [
	"SetVertexShaderConstant",
	"SetPixelShaderConstant",
	"SetTexture",
	"SetRenderState",
	"SetSamplerState",
	"CreateVertexShader",
	"CreatePixelShader",
	"constant",
	"register",
	"sampler",
	"texture",
	"stage",
	"shader",
	"pixel",
	"vertex",
	"pass",
	"0x011fdd88",
	"0x011fde04",
	"0x011fde5c",
	"0x011fda48",
	"0x011fdb08",
	"DAT_011fdd88",
	"DAT_011fde04",
	"DAT_011fde5c",
	"DAT_011fda48",
	"DAT_011fdb08",
	"FUN_00e826d0",
	"FUN_00e7f430",
	"FUN_00e7f5d0",
	"FUN_00e88a20",
	"FUN_00e88fc0",
	"FUN_00e89060",
	"FUN_00e890c0",
	"+ 0x30",
	"+0x30",
	"+ 0x34",
	"+0x34",
	"+ 0x44",
	"+0x44",
	"+ 0x5c",
	"+0x5c",
	"+ 0x78",
	"+0x78",
	"+ 0xa0",
	"+0xa0",
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
	"+ 0xdc",
	"+0xdc",
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
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found]")
		return
	count = 0
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress()
				taddr = target.getOffset()
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), taddr, label_for(taddr)))
				count += 1
	write("  Total: %d calls" % count)

def print_refs_from_instruction(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		target = ref.getToAddress()
		taddr = target.getOffset()
		write("      ref %s -> 0x%08x %s" % (ref.getReferenceType(), taddr, label_for(taddr)))

def instruction_before_steps(inst, steps):
	cur = inst
	count = 0
	while count < steps and cur is not None:
		cur = listing.getInstructionBefore(cur.getAddress())
		count += 1
	return cur

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("=" * 70)
	write("Raw disassembly %s around 0x%08x" % (label, center_int))
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
	count = 0
	limit = before_count + after_count + 1
	while cur is not None and count < limit:
		addr_int = cur.getAddress().getOffset()
		marker = "=> " if addr_int == inst.getAddress().getOffset() else "   "
		write("%s0x%08x: %-58s %s" % (marker, addr_int, cur.toString(), label_for(addr_int)))
		print_refs_from_instruction(cur)
		cur = listing.getInstructionAfter(cur.getAddress())
		count += 1

def print_call_windows_to_target(target_int, label, before_count, after_count, limit):
	write("")
	write("=" * 70)
	write("CALL WINDOWS TO 0x%08x %s" % (target_int, label))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(target_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		from_addr = ref.getFromAddress()
		from_func = fm.getFunctionContaining(from_addr)
		fname = from_func.getName() if from_func else "???"
		write("")
		write("Call %d from 0x%08x in %s" % (count + 1, from_addr.getOffset(), fname))
		disasm_window(from_addr.getOffset(), before_count, after_count, "call to %s" % label)
		count += 1
		if count >= limit:
			write("  ... (truncated)")
			break
	write("  Total printed call windows: %d" % count)

def scan_patterns(addr_int, label, patterns):
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
		for pattern in patterns:
			if pattern.lower() in lower:
				write("  L%-4d %s" % (line_no, line))
				break

def print_global_refs():
	for item in GLOBAL_ARRAYS:
		find_refs_to(item[0], "%s count=0x%x" % (item[1], item[2]))

def print_create_callsite_windows():
	for item in CREATE_CALLS:
		disasm_window(item[0], 28, 22, item[1])

def decompile_focus_functions():
	for item in FOCUS_FUNCTIONS:
		decompile_at(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])
		scan_patterns(item[0], item[1], SCAN_PATTERNS)

def print_target_refs_and_windows():
	for item in CALL_TARGETS:
		find_refs_to(item[0], item[1])
		print_call_windows_to_target(item[0], item[1], 12, 10, 24)

def print_raw_focus_windows():
	disasm_window(0x00BD4BA0, 24, 70, "current-pass shader-interface apply")
	disasm_window(0x00E826D0, 24, 96, "shader-interface field apply")
	disasm_window(0x00BDB4A0, 24, 96, "PPLighting texture setup variant A")
	disasm_window(0x00BDF790, 24, 96, "PPLighting texture setup variant B")
	disasm_window(0x00E88A20, 10, 60, "NiDX9RenderState::SetTexture")
	disasm_window(0x00BE1F90, 10, 70, "BSShader::SetShaders")

def main():
	write("FNV PBR PPLIGHTING SHADER INPUT SIGNATURE FOLLOW-UP AUDIT")
	write("")
	write("Questions:")
	write("1. Which shader creation arguments identify the safe PPLighting families?")
	write("2. Which shader-interface apply path uploads constants before SetShaders?")
	write("3. Which texture-stage and sampler-state helpers are active for those passes?")
	write("4. What exact input/register/texture contract is still missing before visible replacement?")
	write("")
	write("Compatibility rule:")
	write("Do not emit or bind a replacement BRDF shader until one family has proven input semantics, constants, texture stages, and fallback ownership.")
	print_global_refs()
	print_create_callsite_windows()
	print_raw_focus_windows()
	decompile_focus_functions()
	print_target_refs_and_windows()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_shader_input_signature_followup_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
