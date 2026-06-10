# @category Analysis
# @description Audit NewVegasReloaded-style native shader replacement contracts in FNV

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x008706B0: "Main::Render",
	0x00873200: "Main::RenderWorldSceneGraph",
	0x00875110: "Main::RenderFirstPerson",
	0x00B4F710: "SetShaderPackage",
	0x00B55AC0: "ImageSpaceManager::ProcessImageSpaceShaders",
	0x00BE0FE0: "BSShader::CreateVertexShader",
	0x00BE1750: "BSShader::CreatePixelShader",
	0x00BE1F90: "BSShader::SetShaders",
	0x00E910A0: "NiDX9RenderState::SetSamplerState",
	0x011F91BC: "ShaderPackageMax global",
	0x011F91C0: "ShaderPackage global",
	0x011F91E0: "Current geometry slot/pointer candidate",
	0x011F9548: "BSShader singleton array",
	0x011FDB08: "ShadowLight pixel shader array",
	0x011FDE5C: "ShadowLight vertex shader array",
	0x0126F74C: "Current NiD3DPass global",
}

FUNCTION_TARGETS = [
	0x008706B0,
	0x00873200,
	0x00875110,
	0x00B4F710,
	0x00B55AC0,
	0x00BE0FE0,
	0x00BE1750,
	0x00BE1F90,
	0x00E910A0,
]

REF_TARGETS = [
	0x00B4F710,
	0x00BE0FE0,
	0x00BE1750,
	0x00BE1F90,
	0x00E910A0,
	0x011F91BC,
	0x011F91C0,
	0x011F91E0,
	0x011F9548,
	0x011FDB08,
	0x011FDE5C,
	0x0126F74C,
]

DISASM_WINDOWS = [
	0x00BE1690,
	0x00BE1DFB,
	0x00BE1F90,
	0x00B4F710,
]

MATCH_PATTERNS = [
	"011f91bc",
	"011f91c0",
	"011f91e0",
	"011f9548",
	"011fdb08",
	"011fde5c",
	"0126f74c",
	"+ 0x2c",
	"+ 0x30",
	"+ 0x34",
	"+ 0x38",
	"+ 0x44",
	"+ 0x5c",
	"vertex",
	"pixel",
	"shader",
	"pass",
	"program",
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

def read_bytes(addr_int, count):
	values = []
	i = 0
	while i < count:
		values.append("%02X" % (memory.getByte(toAddr(addr_int + i)) & 0xff))
		i += 1
	return " ".join(values)

def print_patch_site_bytes():
	write("")
	write("=" * 70)
	write("NVR layout-size patch site bytes")
	write("=" * 70)
	write("NVR source writes sizeof(NiD3DVertexShaderEx) at 0x00BE1690.")
	write("NVR source writes sizeof(NiD3DPixelShaderEx) at 0x00BE1DFB.")
	write("These sites need proof before any Psycho native shader layer touches allocation sizes.")
	write("  0x00BE1690: %s" % read_bytes(0x00BE1690, 16))
	write("  0x00BE1DFB: %s" % read_bytes(0x00BE1DFB, 16))

def audit_functions():
	idx = 0
	while idx < len(FUNCTION_TARGETS):
		addr_int = FUNCTION_TARGETS[idx]
		decompile_at(addr_int, label_for(addr_int))
		print_matching_decompile_lines(addr_int, label_for(addr_int))
		find_and_print_calls_from(addr_int, label_for(addr_int))
		idx += 1

def audit_refs():
	idx = 0
	while idx < len(REF_TARGETS):
		addr_int = REF_TARGETS[idx]
		find_refs_to(addr_int, label_for(addr_int))
		idx += 1

def audit_windows():
	idx = 0
	while idx < len(DISASM_WINDOWS):
		addr_int = DISASM_WINDOWS[idx]
		disasm_window(addr_int, 10, 18, label_for(addr_int))
		idx += 1

def print_header():
	write("FNV NVR SHADER REPLACEMENT CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. What exact ABI do CreateVertexShader/CreatePixelShader expose in FNV?")
	write("2. Does SetShaders read current NiD3DPass and current geometry from stable globals?")
	write("3. Which shader singleton arrays are safe to inspect without mutating engine objects?")
	write("4. What allocation-size patch sites did NVR rely on, and should Psycho avoid them?")
	write("")
	write("Psycho compatibility rule:")
	write("Use side tables keyed by NiD3DVertexShader/NiD3DPixelShader pointers. Do not extend native object layouts unless a separate opt-in mode proves ownership and conflicts.")

def main():
	print_header()
	print_patch_site_bytes()
	audit_windows()
	audit_refs()
	audit_functions()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_nvr_shader_replacement_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
