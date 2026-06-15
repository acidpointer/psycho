# @category Analysis
# @description Audit FNV NiCamera matrix frustum and projection contract for OMV

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0045BB80: "CameraVectorGetter_0045BB80",
	0x0045C670: "CurrentCameraGetter_0045C670",
	0x006629F0: "CameraOrSceneGetter_006629F0",
	0x00710AB0: "WorldCameraDepthValue_00710AB0",
	0x00874900: "FirstPersonCameraDepthValue_00874900",
	0x00874C10: "RenderFirstPerson_Setup",
	0x00875110: "Main::RenderFirstPerson",
	0x00875FD0: "RenderImageSpaceCaller_00875FD0",
	0x00876125: "pCurrentCamera write before image-space",
	0x00876136: "ProcessImageSpaceShaders callsite",
	0x00B54000: "SetDepthOrClipValue_00B54000",
	0x00B54280: "CameraWriter_00B54280",
	0x00B54630: "CameraWriter_00B54630",
	0x00B5E870: "CameraWriter_00B5E870",
	0x00B6BA20: "CameraWriter_00B6BA20",
	0x00B6C0D0: "CameraWriter_00B6C0D0",
	0x00B55AC0: "ImageSpaceManager::ProcessImageSpaceShaders",
	0x00C52020: "SetCameraDepthValues_00C52020",
	0x011F426C: "CameraLocation",
	0x011F474C: "CameraWorldTranslate",
	0x011F917C: "BSShaderManager::pCurrentCamera",
}

FUNCTION_TARGETS = [
	0x0045BB80,
	0x0045C670,
	0x006629F0,
	0x00710AB0,
	0x00874900,
	0x00874C10,
	0x00875110,
	0x00875FD0,
	0x00B54000,
	0x00B54280,
	0x00B54630,
	0x00B5E870,
	0x00B6BA20,
	0x00B6C0D0,
	0x00C52020,
]

GLOBAL_REFS = [
	0x011F917C,
	0x011F426C,
	0x011F474C,
]

DISASM_WINDOWS = [
	0x00876125,
	0x00876136,
	0x00B548BD,
	0x00B5EA46,
	0x00B6BA3F,
	0x00B6C0EF,
	0x00874D1C,
	0x008752AE,
	0x008759E4,
	0x00875B86,
]

MATCH_PATTERNS = [
	"0x94",
	"0xd4",
	"0xec",
	"0xf0",
	"0xf4",
	"0x011f917c",
	"011f917c",
	"011f426c",
	"011f474c",
	"frustum",
	"camera",
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

def decompile_at(addr_int, label, max_len=20000):
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
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
		if count > 140:
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

def read_bytes(addr_int, count):
	values = []
	i = 0
	while i < count:
		value = memory.getByte(toAddr(addr_int + i)) & 0xff
		values.append("%02X" % value)
		i += 1
	return " ".join(values)

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
		disasm_window(from_addr, 8, 22, "reference to %s" % label)
		count += 1
		if count >= max_refs:
			write("  ... reference window scan truncated")
			break
	write("Total reference windows printed: %d" % count)

def scan_callers_to(addr_int, label, max_callers):
	write("")
	write("=" * 70)
	write("CALLER SCAN: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		if not ref.getReferenceType().isCall():
			continue
		from_addr = ref.getFromAddress().getOffset()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("")
		write("Caller %d: 0x%08x in %s" % (count + 1, from_addr, fname))
		disasm_window(from_addr, 10, 28, "caller of %s" % label)
		count += 1
		if count >= max_callers:
			write("  ... caller scan truncated")
			break
	write("Total callers printed: %d" % count)

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
	write("CAMERA OFFSET MATCHES: %s @ 0x%08x" % (label, addr_int))
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

def print_contract_notes():
	write("")
	write("=" * 70)
	write("CAMERA MATRIX CONTRACT TO PROVE")
	write("=" * 70)
	write("Candidate layout from prior audits/TESReloaded-style reading:")
	write("  NiCamera::WorldToCam candidate: Camera + 0x94")
	write("  NiCamera::Frustum candidate: Camera + 0xD4")
	write("  NiFrustum left/right/top/bottom/near/far: +0x00/+0x04/+0x08/+0x0C/+0x10/+0x14")
	write("  Current near/far reads used by Psycho: Camera + 0xEC and Camera + 0xF0")
	write("")
	write("Do not implement sun screen projection until this script proves these offsets in FNV code.")

def audit_globals():
	idx = 0
	while idx < len(GLOBAL_REFS):
		addr = GLOBAL_REFS[idx]
		find_refs_to(addr, label_for(addr))
		scan_refs_windows(addr, label_for(addr), 14)
		idx += 1

def audit_windows():
	idx = 0
	while idx < len(DISASM_WINDOWS):
		addr = DISASM_WINDOWS[idx]
		write("")
		write("Bytes @ 0x%08x (%s): %s" % (addr, label_for(addr), read_bytes(addr, 16)))
		disasm_window(addr, 16, 40, label_for(addr))
		idx += 1

def audit_functions():
	idx = 0
	while idx < len(FUNCTION_TARGETS):
		addr = FUNCTION_TARGETS[idx]
		decompile_at(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))
		print_matching_decompile_lines(addr, label_for(addr))
		idx += 1

def audit_callers():
	scan_callers_to(0x00B6C0D0, "CameraWriter_00B6C0D0", 16)
	scan_callers_to(0x00B6BA20, "CameraWriter_00B6BA20", 16)
	scan_callers_to(0x00B5E870, "CameraWriter_00B5E870", 16)
	scan_callers_to(0x00B54630, "CameraWriter_00B54630", 16)
	scan_callers_to(0x00875FD0, "RenderImageSpaceCaller_00875FD0", 16)

def print_header():
	write("FNV GRAPHICS CAMERA MATRIX CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. Are NiCamera world-to-camera and frustum offsets proven by FNV code?")
	write("2. Are near/far values at +0xEC/+0xF0 the same values as the frustum near/far fields?")
	write("3. Is pCurrentCamera valid immediately before ProcessImageSpaceShaders for sun projection?")
	write("4. Which camera writer function is safest to mirror for CPU-side view/projection constants?")

def main():
	print_header()
	print_contract_notes()
	audit_globals()
	audit_windows()
	audit_callers()
	audit_functions()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_camera_matrix_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
