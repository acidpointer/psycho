# @category Analysis
# @description Audit FNV camera/projection state for first-person depth comparison

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00450F90: "SetCameraModeOrNode_00450F90",
	0x0045C670: "CurrentCameraGetter_0045C670",
	0x0045BB80: "CameraVectorGetter_0045BB80",
	0x006629F0: "CameraOrSceneGetter_006629F0",
	0x00705990: "CameraIndexGetter_00705990",
	0x00707AD0: "CameraIndexState_00707AD0",
	0x00710AB0: "WorldCameraDepthValue_00710AB0",
	0x00712E60: "SetCameraOrTarget_00712E60",
	0x00870790: "FirstPersonOffsetApply_00870790",
	0x00874900: "FirstPersonCameraDepthValue_00874900",
	0x00874C10: "RenderFirstPerson_Setup",
	0x008750E0: "FirstPersonOffsetRestore_008750E0",
	0x00875110: "Main::RenderFirstPerson",
	0x00875FD0: "RenderImageSpaceCaller_00875FD0",
	0x00B54000: "SetDepthOrClipValue_00B54000",
	0x00B54280: "CameraWriter_00B54280",
	0x00B54630: "CameraWriter_00B54630",
	0x00B5E870: "CameraWriter_00B5E870",
	0x00B6BA20: "CameraWriter_00B6BA20",
	0x00B6C0D0: "CameraWriter_00B6C0D0",
	0x00C52020: "SetCameraDepthValues_00C52020",
	0x011F917C: "BSShaderManager::pCurrentCamera",
}

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

def decompile_at(addr_int, label, max_len=8000):
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
		if count > 100:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found at 0x%08x]" % addr_int)
		return
	body = func.getBody()
	inst_iter = listing.getInstructions(body, True)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
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
		disasm_window(from_addr, 18, 32, "caller of %s" % label)
		count += 1
		if count >= max_callers:
			write("  ... caller scan truncated")
			break
	write("Total callers printed: %d" % count)

def print_questions():
	write("FNV CAMERA PROJECTION CONTRACT AUDIT")
	write("")
	write("=" * 70)
	write("QUESTIONS")
	write("=" * 70)
	write("1. Which functions write BSShaderManager::pCurrentCamera during world, first-person, and image-space?")
	write("2. Is pCurrentCamera valid for reading first-person near/far at the first-person depth resolve point?")
	write("3. Are first-person depth values linearizable with the same near/far fields as world depth?")
	write("4. Do 0x00874900 and 0x00710AB0 return near/far/clip values that can be mirrored in Psycho?")
	write("5. Which function is the safe source of first-person camera constants for shader comparison?")

def print_writer_windows():
	write("")
	write("=" * 70)
	write("PCURRENTCAMERA WRITER WINDOWS")
	write("=" * 70)
	disasm_window(0x00B548BD, 18, 28, "pCurrentCamera write in 00B54630")
	disasm_window(0x00B5EA46, 18, 28, "pCurrentCamera write in 00B5E870")
	disasm_window(0x00B6BA3F, 18, 28, "pCurrentCamera write in 00B6BA20")
	disasm_window(0x00B6C0EF, 18, 28, "pCurrentCamera write in 00B6C0D0")
	disasm_window(0x00876125, 18, 28, "pCurrentCamera write before image-space")

def print_first_person_windows():
	write("")
	write("=" * 70)
	write("FIRST-PERSON CAMERA WINDOWS")
	write("=" * 70)
	disasm_window(0x00874D1C, 18, 28, "RenderFirstPerson_Setup first-person depth value")
	disasm_window(0x00875011, 18, 34, "RenderFirstPerson_Setup offset apply")
	disasm_window(0x00875038, 18, 34, "RenderFirstPerson_Setup offset restore")
	disasm_window(0x008752AE, 18, 28, "RenderFirstPerson start depth value")
	disasm_window(0x008759E4, 18, 28, "RenderFirstPerson world depth value")
	disasm_window(0x00875B86, 18, 28, "RenderFirstPerson final first-person depth value")

def print_decompilations():
	write("")
	write("=" * 70)
	write("DECOMPILATIONS")
	write("=" * 70)
	decompile_at(0x00B54630, "CameraWriter_00B54630", 16000)
	decompile_at(0x00B5E870, "CameraWriter_00B5E870", 18000)
	decompile_at(0x00B6BA20, "CameraWriter_00B6BA20", 18000)
	decompile_at(0x00B6C0D0, "CameraWriter_00B6C0D0", 18000)
	decompile_at(0x00874900, "FirstPersonCameraDepthValue_00874900", 16000)
	decompile_at(0x00710AB0, "WorldCameraDepthValue_00710AB0", 16000)
	decompile_at(0x00C52020, "SetCameraDepthValues_00C52020", 16000)
	decompile_at(0x00B54000, "SetDepthOrClipValue_00B54000", 16000)
	decompile_at(0x00870790, "FirstPersonOffsetApply_00870790", 16000)
	decompile_at(0x008750E0, "FirstPersonOffsetRestore_008750E0", 16000)
	decompile_at(0x00875FD0, "RenderImageSpaceCaller_00875FD0", 22000)

def print_callers_and_refs():
	write("")
	write("=" * 70)
	write("CALLERS AND REFS")
	write("=" * 70)
	find_refs_to(0x011F917C, "BSShaderManager::pCurrentCamera")
	scan_callers_to(0x00B6C0D0, "CameraWriter_00B6C0D0", 16)
	scan_callers_to(0x00B6BA20, "CameraWriter_00B6BA20", 16)
	scan_callers_to(0x00B5E870, "CameraWriter_00B5E870", 16)
	scan_callers_to(0x00874900, "FirstPersonCameraDepthValue_00874900", 16)
	scan_callers_to(0x00710AB0, "WorldCameraDepthValue_00710AB0", 16)
	find_and_print_calls_from(0x00874C10, "RenderFirstPerson_Setup")
	find_and_print_calls_from(0x00875110, "Main::RenderFirstPerson")

def write_output():
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_camera_projection_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))

def main():
	print_questions()
	print_writer_windows()
	print_first_person_windows()
	print_decompilations()
	print_callers_and_refs()
	write_output()

main()
decomp.dispose()
