# @category Analysis
# @description Prove the persistent world camera and depth projection pairing for OMV depth of field

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0045C670: "CurrentCameraGetter_0045C670",
	0x00559450: "RefSlotGetter_00559450",
	0x006629F0: "CameraOrSceneGetter_006629F0",
	0x0066B0D0: "RefSlotAssign_0066B0D0",
	0x00710AB0: "WorldCameraDepthValue_00710AB0",
	0x00712E60: "SetCameraOrTarget_00712E60",
	0x0086D590: "MainRendererInitialization_0086D590",
	0x008706B0: "Main::Render",
	0x00873200: "Main::RenderWorldSceneGraph",
	0x00874900: "FirstPersonCameraDepthValue_00874900",
	0x00875110: "Main::RenderFirstPerson",
	0x00875FD0: "ImageSpaceRenderOwner_00875FD0",
	0x00878610: "SceneGraphConstructor_00878610",
	0x00B54000: "SetDepthOrClipValue_00B54000",
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
		if count > 80:
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

def scan_displacements(addr_int, label, displacements):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("=" * 70)
	write("MAIN/CAMERA FIELD OPERANDS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		matched = False
		for displacement in displacements:
			needle = "+ 0x%x" % displacement
			compact = "+0x%x" % displacement
			if needle in text or compact in text:
				matched = True
				break
		if matched:
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
			count += 1
	write("  Matched: %d instructions" % count)

def print_questions():
	write("FNV DOF PROJECTION PAIRING FOLLOW-UP")
	write("")
	write("=" * 70)
	write("QUESTIONS")
	write("=" * 70)
	write("1. Where is the SceneGraph named World stored after construction?")
	write("2. Is Main +0xA0 the persistent world camera used to build the world projection?")
	write("3. Which camera owns the hardware world depth at the post-RenderWorldSceneGraph resolve point?")
	write("4. Which camera owns first-person depth before and after Main::RenderFirstPerson returns?")
	write("5. Can OMV read the correct projection from existing Main/SceneGraph state without a new hook?")

def print_windows():
	write("")
	write("=" * 70)
	write("CONSTRUCTION AND RENDER WINDOWS")
	write("=" * 70)
	disasm_window(0x0086D601, 16, 28, "World SceneGraph construction")
	disasm_window(0x0086D62E, 16, 24, "World SceneGraph retained pointer assignment")
	disasm_window(0x00870AE8, 28, 30, "primary world-render callsite")
	disasm_window(0x00870E18, 28, 30, "alternate world-render callsite")
	disasm_window(0x00875258, 20, 30, "Main +0xA0 camera selection in first-person render")
	disasm_window(0x008759E4, 20, 30, "world projection restoration inside first-person render")
	disasm_window(0x00875B86, 20, 30, "final first-person projection restoration")
	disasm_window(0x00876119, 18, 24, "camera selection before image-space")

def print_decompilations():
	write("")
	write("=" * 70)
	write("DECOMPILATIONS")
	write("=" * 70)
	decompile_at(0x0086D590, "MainRendererInitialization_0086D590", 22000)
	decompile_at(0x008706B0, "Main::Render", 26000)
	decompile_at(0x00873200, "Main::RenderWorldSceneGraph", 32000)
	decompile_at(0x00875110, "Main::RenderFirstPerson", 32000)
	decompile_at(0x00875FD0, "ImageSpaceRenderOwner_00875FD0", 18000)
	decompile_at(0x00878610, "SceneGraphConstructor_00878610", 16000)
	decompile_at(0x0066B0D0, "RefSlotAssign_0066B0D0", 8000)
	decompile_at(0x00559450, "RefSlotGetter_00559450", 8000)

def print_field_scans():
	scan_displacements(0x008706B0, "Main::Render", [0x88, 0x8c, 0x90, 0x94, 0x98, 0xa0, 0xac, 0xb4, 0xbc])
	scan_displacements(0x00873200, "Main::RenderWorldSceneGraph", [0x88, 0x8c, 0x90, 0x94, 0x98, 0xa0, 0xac, 0xb4, 0xbc])
	scan_displacements(0x00875110, "Main::RenderFirstPerson", [0x88, 0x8c, 0x90, 0x94, 0x98, 0xa0, 0xac, 0xb4, 0xbc])
	scan_displacements(0x00875FD0, "ImageSpaceRenderOwner_00875FD0", [0x88, 0x8c, 0x90, 0x94, 0x98, 0xa0, 0xac, 0xb4, 0xbc])

def print_refs_and_calls():
	write("")
	write("=" * 70)
	write("REFERENCES AND CALLS")
	write("=" * 70)
	find_refs_to(0x00878610, "SceneGraphConstructor_00878610")
	find_refs_to(0x011F917C, "BSShaderManager::pCurrentCamera")
	find_and_print_calls_from(0x0086D590, "MainRendererInitialization_0086D590")
	find_and_print_calls_from(0x008706B0, "Main::Render")
	find_and_print_calls_from(0x00873200, "Main::RenderWorldSceneGraph")
	find_and_print_calls_from(0x00875110, "Main::RenderFirstPerson")

def write_output():
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_dof_projection_pairing_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))

def main():
	print_questions()
	print_windows()
	print_decompilations()
	print_field_scans()
	print_refs_and_calls()
	write_output()

main()
decomp.dispose()
