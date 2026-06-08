# @category Analysis
# @description Deep audit FNV sun direction, camera basis, and safe CPU sun projection contract

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0045CD60: "Sky sun/current object getter candidate",
	0x00595EA0: "Sky::GetSunriseBegin",
	0x00595F50: "Sky::GetSunriseEnd",
	0x00595FC0: "Sky::GetSunsetBegin",
	0x00596030: "Sky::GetSunsetEnd",
	0x0063B630: "Weather day phase weights",
	0x0063B9B0: "Sky::GetSunriseColorBegin",
	0x0063BA30: "Sky::GetSunsetColorEnd",
	0x0063EF20: "Weather weighted slot apply",
	0x0086CF20: "Sky singleton writer/initializer",
	0x00870BD0: "Main render world caller B",
	0x00873200: "Main::RenderWorldSceneGraph",
	0x00875FD0: "Render image-space caller",
	0x00877730: "Sky render/update refs candidate",
	0x00B5A220: "Shader camera near/far reader A",
	0x00B5E870: "Camera global writer",
	0x00BD66C0: "Shader camera near/far reader B",
	0x011DEA20: "Sky singleton",
	0x011F426C: "CameraLocation",
	0x011F474C: "CameraWorldTranslate",
	0x011F917C: "BSShaderManager::pCurrentCamera",
	0x011FA280: "Camera global block",
	0x011FA2A0: "Camera global position/vector X",
	0x011FA2A4: "Camera global position/vector Y",
	0x011FA2A8: "Camera global position/vector Z",
}

GLOBALS_TO_TRACE = [
	0x011DEA20,
	0x011F917C,
	0x011FA280,
	0x011FA2A0,
	0x011FA2A4,
	0x011FA2A8,
]

TARGETS = [
	0x0045CD60,
	0x00595EA0,
	0x00595F50,
	0x00595FC0,
	0x00596030,
	0x0063B630,
	0x0063B9B0,
	0x0063BA30,
	0x0063EF20,
	0x0086CF20,
	0x00870BD0,
	0x00873200,
	0x00875FD0,
	0x00877730,
	0x00B5A220,
	0x00B5E870,
	0x00BD66C0,
]

DISASM_WINDOWS = [
	0x00871000,
	0x0087100D,
	0x00871020,
	0x00876125,
	0x00876136,
	0x00B5EA46,
	0x00B5EAAA,
	0x00B5EC02,
]

NEEDLES = [
	"0x4",
	"0x28",
	"0x34",
	"0x58",
	"0x68",
	"0x70",
	"0x74",
	"0x7c",
	"0x80",
	"0x88",
	"0x8c",
	"0x90",
	"0x94",
	"0xd4",
	"0xec",
	"0xf0",
	"0xf4",
	"0x134",
	"011dea20",
	"011f917c",
	"011fa280",
	"011fa2a0",
	"011fa2a4",
	"011fa2a8",
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

def get_function_at_or_containing(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	return func

def print_matched_lines(code, label):
	write("")
	write("MATCHED CONTRACT LINES: %s" % label)
	lines = code.split("\n")
	count = 0
	idx = 0
	while idx < len(lines):
		line = lines[idx]
		lower = line.lower()
		needle_idx = 0
		matched = False
		while needle_idx < len(NEEDLES):
			if NEEDLES[needle_idx] in lower:
				matched = True
			needle_idx += 1
		if matched:
			write("  L%04d: %s" % (idx + 1, line))
			count += 1
		idx += 1
	write("  Total matched lines: %d" % count)

def decompile_at(addr_int, label, max_len=22000):
	func = get_function_at_or_containing(addr_int)
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
		print_matched_lines(code, label)
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
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
		if count > 120:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	func = get_function_at_or_containing(addr_int)
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

def decompile_unique_ref_functions(addr_int, label):
	write("")
	write("=" * 70)
	write("DECOMPILING FUNCTIONS THAT REFERENCE 0x%08x (%s)" % (addr_int, label))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = {}
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is not None:
			entry = func.getEntryPoint().getOffset()
			seen[entry] = func.getName()
	entries = seen.keys()
	entries.sort()
	idx = 0
	while idx < len(entries):
		entry = entries[idx]
		decompile_at(entry, "%s ref function %s" % (label, seen[entry]))
		idx += 1

def print_layout_notes():
	write("")
	write("=" * 70)
	write("LAYOUT CONTRACT TO PROVE")
	write("=" * 70)
	write("Sun source:")
	write("  Sky singleton: *(Sky**)0x011DEA20")
	write("  Sky::sun: Sky + 0x28")
	write("  Sun inherits SkyObject: RootNode at Sun + 0x04")
	write("  Sun direction candidate: normalize(SunRoot->m_localTransform.pos)")
	write("  Candidate local transform pos: RootNode + 0x58")
	write("Camera source:")
	write("  BSShaderManager::pCurrentCamera: *(NiCamera**)0x011F917C")
	write("  Current proven near/far: camera + 0xEC/+0xF0")
	write("  Prior output says camera +0x94 is not a matrix; do not use it as WorldToCam.")
	write("  Need proof for basis fields copied by 0x00B5E870 and frustum/global projection fields.")
	write("Target CPU constants:")
	write("  sun UV, sun available, forward-facing amount, sun color/glare, and optional view-space direction.")

def print_global_refs():
	idx = 0
	while idx < len(GLOBALS_TO_TRACE):
		addr = GLOBALS_TO_TRACE[idx]
		find_refs_to(addr, label_for(addr))
		idx += 1

def print_ref_decompiles():
	idx = 0
	while idx < len(GLOBALS_TO_TRACE):
		addr = GLOBALS_TO_TRACE[idx]
		decompile_unique_ref_functions(addr, label_for(addr))
		idx += 1

def print_targets():
	idx = 0
	while idx < len(TARGETS):
		addr = TARGETS[idx]
		decompile_at(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))
		idx += 1

def print_disasm_windows():
	idx = 0
	while idx < len(DISASM_WINDOWS):
		addr = DISASM_WINDOWS[idx]
		disasm_window(addr, 18, 46, label_for(addr))
		idx += 1

def main():
	write("FNV SUN PROJECTION DEEP CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. Can Psycho derive sun direction from Sky -> Sun -> RootNode without invasive hooks?")
	write("2. Which camera basis/frustum fields are valid at scene/final image-space phases?")
	write("3. Can CPU code project sun direction to screen UV using proven fields only?")
	write("4. Which read path should fail closed for compatibility with NVR/TESReloaded/Shader Loader?")
	print_layout_notes()
	print_global_refs()
	print_disasm_windows()
	print_targets()
	print_ref_decompiles()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_sun_projection_deep_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))

main()
decomp.dispose()
