# @category Analysis
# @description Audit FNV material texture and draw-state contracts needed for NVR-style PBR work

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x004E1BC0: "WaterManager::RenderReflections",
	0x008706B0: "Main::Render",
	0x00871290: "RenderShadowMaps",
	0x00873200: "Main::RenderWorldSceneGraph",
	0x00875110: "Main::RenderFirstPerson",
	0x008761E0: "RenderPipboy",
	0x00B65C60: "BSShaderAccumulator::RenderPostDepthGroups",
	0x00BE1F90: "BSShader::SetShaders",
	0x00E910A0: "NiDX9RenderState::SetSamplerState",
	0x011C73B4: "NiDX9Renderer::singleton",
	0x011F91E0: "Current geometry slot/pointer candidate",
	0x011F9548: "BSShader singleton array",
	0x011FDB08: "ShadowLight pixel shader array",
	0x011FDE5C: "ShadowLight vertex shader array",
	0x0126F74C: "Current NiD3DPass global",
	0x0126F92C: "NiDX9RenderState sampler TypeMap candidate",
}

FUNCTION_TARGETS = [
	0x004E1BC0,
	0x008706B0,
	0x00871290,
	0x00873200,
	0x00875110,
	0x008761E0,
	0x00B65C60,
	0x00BE1F90,
	0x00E910A0,
]

REF_TARGETS = [
	0x011C73B4,
	0x011F91E0,
	0x011F9548,
	0x011FDB08,
	0x011FDE5C,
	0x0126F74C,
	0x0126F92C,
]

MATCH_PATTERNS = [
	"011c73b4",
	"011f91e0",
	"011f9548",
	"011fdb08",
	"011fde5c",
	"0126f74c",
	"0126f92c",
	"+ 0x18",
	"+ 0x1c",
	"+ 0x20",
	"+ 0x24",
	"+ 0x30",
	"+ 0x34",
	"+ 0x38",
	"+ 0x44",
	"+ 0x48",
	"+ 0x50",
	"+ 0x58",
	"+ 0x5c",
	"geometry",
	"texture",
	"sampler",
	"property",
	"material",
	"shader",
	"renderstate",
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

def scan_ref_function_decompiles(addr_int, label, max_refs):
	write("")
	write("=" * 70)
	write("DECOMPILE FUNCTIONS REFERENCING %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = {}
	count = 0
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		if seen.get(entry):
			continue
		seen[entry] = True
		decompile_at(entry, "%s ref function %s" % (label, func.getName()), 14000)
		print_matching_decompile_lines(entry, "%s ref function %s" % (label, func.getName()))
		count += 1
		if count >= max_refs:
			write("  ... (truncated ref-function scan)")
			break

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

def audit_ref_function_decompiles():
	scan_ref_function_decompiles(0x0126F74C, "Current NiD3DPass global", 12)
	scan_ref_function_decompiles(0x011F91E0, "Current geometry slot/pointer candidate", 12)
	scan_ref_function_decompiles(0x0126F92C, "NiDX9RenderState sampler TypeMap candidate", 8)

def print_header():
	write("FNV NVR MATERIAL TEXTURE STATE AUDIT")
	write("")
	write("Questions:")
	write("1. Which functions publish or consume current geometry and NiD3DPass state?")
	write("2. Is SetShaders the only safe draw-time point for replacing native material shaders?")
	write("3. How do texture/sampler state writes flow through NiDX9RenderState?")
	write("4. What state would Psycho need to capture for material/PBR compatibility without owning the whole renderer?")
	write("")
	write("Expected implementation consequence:")
	write("Psycho native material mode should be opt-in, side-table based, and disabled when another graphics mod owns CreateShader/SetShaders unless chaining is explicitly proven.")

def main():
	print_header()
	audit_refs()
	audit_functions()
	audit_ref_function_decompiles()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_nvr_material_texture_state_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
