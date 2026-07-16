# @category Analysis
# @description Prove the FNV world-camera transform and timing contract required by temporal AO

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0045C670: "MainCurrentCameraGetter_0045C670",
	0x004E9BB0: "CameraUpdate_004E9BB0",
	0x006629F0: "SceneGraphCameraGetter_006629F0",
	0x00875110: "Main::RenderFirstPerson",
	0x00875FD0: "ImageSpaceRenderOwner_00875FD0",
	0x00876119: "current camera getter before image space",
	0x00876120: "scene graph camera getter before image space",
	0x00876125: "pCurrentCamera publication before image space",
	0x00876136: "ProcessImageSpaceShaders callsite",
	0x00B54B10: "RendererCameraSetup_00B54B10",
	0x00B5E870: "RendererCameraWriter_00B5E870",
	0x00B8B7D0: "CameraRelativeTransform_00B8B7D0",
	0x00B8B8D0: "CameraRelativeTransform_00B8B8D0",
	0x00B8BB70: "CameraRelativeTransform_00B8BB70",
	0x011DEB7C: "WorldSceneGraph",
	0x011F917C: "BSShaderManager::pCurrentCamera",
	0x011FA2A0: "RendererCameraWorldTranslation",
	0x011FA2B0: "RendererCameraBasisColumn0",
	0x011FA2C0: "RendererCameraBasisColumn2",
}

FUNCTION_TARGETS = [
	0x0045C670,
	0x004E9BB0,
	0x006629F0,
	0x00875110,
	0x00875FD0,
	0x00B54B10,
	0x00B5E870,
	0x00B8B7D0,
	0x00B8B8D0,
	0x00B8BB70,
]

GLOBAL_TARGETS = [
	0x011DEB7C,
	0x011F917C,
	0x011FA2A0,
	0x011FA2B0,
	0x011FA2C0,
]

DISASM_TARGETS = [
	0x00876119,
	0x00876120,
	0x00876125,
	0x00876136,
	0x00B5EA9E,
	0x00B5EAE0,
	0x00B8B7D3,
	0x00B8B8D3,
	0x00B8BB73,
]

MATCH_PATTERNS = [
	"0x68",
	"0x6c",
	"0x70",
	"0x74",
	"0x78",
	"0x7c",
	"0x80",
	"0x84",
	"0x88",
	"0x8c",
	"0x90",
	"0x94",
	"0xac",
	"0xdc",
	"0xe0",
	"0xe4",
	"0xe8",
	"0xec",
	"0xf0",
	"011deb7c",
	"011f917c",
	"011fa2a0",
	"011fa2b0",
	"011fa2c0",
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

def decompile_at(addr_int, label, max_len=24000):
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
		if count > 120:
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
	idx = 0
	while idx < count:
		value = memory.getByte(toAddr(addr_int + idx)) & 0xff
		values.append("%02X" % value)
		idx += 1
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
	write("CAMERA CONTRACT OPERANDS: %s @ 0x%08x" % (label, addr_int))
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

def scan_reference_windows(addr_int, label, max_refs):
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
		disasm_window(from_addr, 10, 30, "reference to %s" % label)
		count += 1
		if count >= max_refs:
			write("  ... reference scan truncated")
			break
	write("Total reference windows printed: %d" % count)

def print_contract_questions():
	write("FNV AO TEMPORAL CAMERA CONTRACT AUDIT")
	write("")
	write("Questions to prove before temporal AO implementation:")
	write("1. Does WorldSceneGraph + 0xAC own the camera matching world depth at image-space time?")
	write("2. Are NiAVObject world rotation +0x68..+0x88 and translation +0x8C..+0x94 current and stable there?")
	write("3. Which columns are forward, up, and right, and what signs map positive view X/Y/Z to world space?")
	write("4. How do native camera-relative transform consumers multiply the basis and translation?")
	write("5. Is the world camera restored after Main::RenderFirstPerson and before ProcessImageSpaceShaders?")
	write("6. Can OMV safely retain one copied transform across Present as previous-frame history?")
	write("")
	write("Required outcome: an explicit current-view -> world -> previous-view formula with no inferred offsets or handedness.")

def audit_globals():
	idx = 0
	while idx < len(GLOBAL_TARGETS):
		addr = GLOBAL_TARGETS[idx]
		find_refs_to(addr, label_for(addr))
		scan_reference_windows(addr, label_for(addr), 24)
		idx += 1

def audit_disassembly():
	idx = 0
	while idx < len(DISASM_TARGETS):
		addr = DISASM_TARGETS[idx]
		write("")
		write("Bytes @ 0x%08x (%s): %s" % (addr, label_for(addr), read_bytes(addr, 16)))
		disasm_window(addr, 18, 48, label_for(addr))
		idx += 1

def audit_functions():
	idx = 0
	while idx < len(FUNCTION_TARGETS):
		addr = FUNCTION_TARGETS[idx]
		decompile_at(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))
		print_matching_decompile_lines(addr, label_for(addr))
		idx += 1

def main():
	print_contract_questions()
	audit_globals()
	audit_disassembly()
	audit_functions()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_ao_temporal_camera_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
