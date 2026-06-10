# @category Analysis
# @description Audit FNV native PBR shader replacement interface gaps

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00BDB4A0: "PPLighting-like setup variant before BDF790",
	0x00BDF790: "PPLighting high-level material/pass setup",
	0x00BD1C50: "Current NiD3DPass writer / pixel shader ownership helper",
	0x00BD4BA0: "Current pass shader/resource apply helper",
	0x00BE0FE0: "BSShader::CreateVertexShader",
	0x00BE1750: "BSShader::CreatePixelShader",
	0x00BE1F90: "BSShader::SetShaders",
	0x00BE2170: "Current pass texture/resource neighbor",
	0x00BE21B0: "Current pass masked resource neighbor",
	0x00E7F7C0: "Renderer helper called by SetShaders",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x00E88930: "NiDX9RenderState::SetTextureStageState",
	0x00E910A0: "NiDX9RenderState::SetSamplerState",
	0x011FA0D0: "Renderer-owned LightColors array",
	0x011FD9A8: "Renderer-owned Light Direction/LightData array",
	0x011F91E0: "Optional current geometry/proxy slot",
	0x0126F74C: "Current NiD3DPass global",
}

FOCUS_FUNCTIONS = [
	0x00BE1F90,
	0x00BE2170,
	0x00BE21B0,
	0x00BE1750,
	0x00BE0FE0,
	0x00BD1C50,
	0x00BD4BA0,
	0x00BDB4A0,
	0x00BDF790,
	0x00E88A20,
	0x00E88930,
	0x00E910A0,
]

REF_TARGETS = [
	0x00BE1F90,
	0x00BE1750,
	0x00BE0FE0,
	0x00BD1C50,
	0x00BD4BA0,
	0x00BDB4A0,
	0x00BDF790,
	0x011FA0D0,
	0x011FD9A8,
	0x011F91E0,
	0x0126F74C,
]

RAW_WINDOWS = [
	(0x00BE1F90, 18, 92, "BSShader::SetShaders raw body"),
	(0x00BE1750, 24, 140, "BSShader::CreatePixelShader entry"),
	(0x00BE0FE0, 24, 140, "BSShader::CreateVertexShader entry"),
	(0x00BD1C50, 20, 120, "Current pass writer"),
	(0x00BD4BA0, 20, 120, "Current pass apply/helper"),
	(0x00BDB4A0, 18, 120, "PPLighting setup variant"),
	(0x00BDF790, 18, 160, "PPLighting material setup"),
]

MATCH_PATTERNS = [
	"0126f74c",
	"011f91e0",
	"011fa0d0",
	"011fd9a8",
	"011fec",
	"+ 0x44",
	"+0x44",
	"+ 0x5c",
	"+0x5c",
	"+ 0x7c",
	"+0x7c",
	"+ 0x84",
	"+0x84",
	"+ 0x20",
	"+0x20",
	"SetPixelShader",
	"SetVertexShader",
	"SetPixelShaderConstant",
	"SetVertexShaderConstant",
	"constant",
	"shader",
	"pixel",
	"vertex",
	"texture",
	"normal",
	"light",
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
	else:
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
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
		if count > 80:
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

def disasm_window(addr_int, before, count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, addr_int))
	write("-" * 70)
	start = addr_int - before
	inst = listing.getInstructionAt(toAddr(start))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start))
	seen = 0
	while inst is not None and seen < count:
		off = inst.getAddress().getOffset()
		marker = " << TARGET" if off == addr_int else ""
		write("  0x%08x: %-54s%s" % (off, inst.toString(), marker))
		seen += 1
		inst = inst.getNext()

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
	count = 0
	for line in lines:
		lower = line.lower()
		for pattern in patterns:
			if pattern.lower() in lower:
				write("  %s" % line)
				count += 1
				break
		if count > 120:
			write("  ... (truncated)")
			break
	write("  Total matched lines: %d" % count)

def decompile_focus_functions():
	for addr_int in FOCUS_FUNCTIONS:
		decompile_at(addr_int, label_for(addr_int))
		find_and_print_calls_from(addr_int, label_for(addr_int))
		scan_patterns(addr_int, label_for(addr_int), MATCH_PATTERNS)

def refs_for_targets():
	for addr_int in REF_TARGETS:
		find_refs_to(addr_int, label_for(addr_int))

def raw_windows():
	for item in RAW_WINDOWS:
		disasm_window(item[0], item[1], item[2], item[3])

def main():
	write("FNV PBR SHADER INTERFACE CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. What exact shader object methods/fields does SetShaders consume for native pixel replacement?")
	write("2. Which pass/PPLighting contexts have stable pixel-shader inputs suitable for PBR?")
	write("3. Where are renderer light constants uploaded relative to SetShaders?")
	write("4. Which texture stages are already final by the time SetShaders executes?")
	write("")
	write("Compatibility rule:")
	write("Do not enable Psycho native shader replacement until this output proves a stable pixel input contract.")
	raw_windows()
	refs_for_targets()
	decompile_focus_functions()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_shader_interface_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
