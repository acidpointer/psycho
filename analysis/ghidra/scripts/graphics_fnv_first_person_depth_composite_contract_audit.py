# @category Analysis
# @description Audit FNV first-person wall-clip depth and color composite contract for OMV

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x004EA970: "RendererLockFactory_004EA970",
	0x00559450: "MainPointerSlot_00559450",
	0x007148C0: "NiRenderer::Clear",
	0x00873200: "Main::RenderWorldSceneGraph",
	0x00874B50: "RenderFirstPerson_PostGeometryCleanup",
	0x00874C10: "RenderFirstPerson_Setup",
	0x00875110: "Main::RenderFirstPerson",
	0x00B55AC0: "ImageSpaceManager::ProcessImageSpaceShaders",
	0x00B639E0: "BSShaderAccumulator::RenderGeometryGroup",
	0x00B64570: "BSShaderAccumulator::RenderFirstPersonAccumulated",
	0x00B64E30: "BSShaderAccumulator::RenderFirstPersonGeometryGroups",
	0x00B65AE0: "BSShaderAccumulator::RenderLateSceneGroups",
	0x00B65C60: "BSShaderAccumulator::RenderPostDepthGroups",
	0x00B97E30: "RendererStateHelper_00B97E30",
	0x00B97FA0: "RendererStateHelper_00B97FA0",
	0x00B98320: "RendererStateHelper_00B98320",
	0x00B98380: "RendererStateHelper_00B98380",
	0x00BA3130: "RendererLockOrState_00BA3130",
	0x011C73B4: "NiDX9Renderer::singleton",
	0x011DE9D1: "bOffsetViewModelLights",
	0x011F917C: "BSShaderManager::pCurrentCamera",
	0x011F9438: "BSShaderManager::pCurrentRenderTarget",
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
		disasm_window(from_addr, 20, 44, "caller of %s" % label)
		count += 1
		if count >= max_callers:
			write("  ... caller scan truncated")
			break
	write("Total callers printed: %d" % count)

def print_questions():
	write("FNV FIRST-PERSON DEPTH COMPOSITE CONTRACT AUDIT")
	write("")
	write("=" * 70)
	write("QUESTIONS")
	write("=" * 70)
	write("1. Are world and first-person hardware depth values generated with comparable camera/projection state?")
	write("2. Is there a post-world/pre-first-person color hook that can be replayed after image-space without visual mismatch?")
	write("3. Does RenderFirstPerson_Setup change camera, frustum, viewport, or render target state that blocks raw depth comparison?")
	write("4. Does NiRenderer::Clear(0, 4) only clear depth, or does it also alter persistent render state?")
	write("5. Which candidate hook points overlap DepthResolve/TESReloaded patches and should stay off-limits?")

def print_render_order_callers():
	write("")
	write("=" * 70)
	write("RENDER ORDER CALLER WINDOWS")
	write("=" * 70)
	scan_callers_to(0x00873200, "Main::RenderWorldSceneGraph", 8)
	scan_callers_to(0x00875110, "Main::RenderFirstPerson", 8)
	scan_callers_to(0x00B55AC0, "ImageSpaceManager::ProcessImageSpaceShaders", 8)
	scan_callers_to(0x00B65AE0, "BSShaderAccumulator::RenderLateSceneGroups", 8)
	scan_callers_to(0x00B65C60, "BSShaderAccumulator::RenderPostDepthGroups", 8)

def print_known_windows():
	write("")
	write("=" * 70)
	write("KNOWN FIRST-PERSON WINDOWS")
	write("=" * 70)
	disasm_window(0x008751C6, 24, 44, "RenderFirstPerson depth clear")
	disasm_window(0x008755B6, 24, 48, "RenderFirstPerson color-write helper")
	disasm_window(0x0087590A, 26, 42, "RenderFirstPerson accumulator")
	disasm_window(0x0087591D, 18, 34, "RenderFirstPerson cleanup")
	disasm_window(0x00B64E83, 22, 38, "first-person group 2 alpha 1")
	disasm_window(0x00B64E8E, 22, 38, "first-person group 3 alpha 1")
	disasm_window(0x00B65C16, 26, 54, "post-depth first-person group call")
	disasm_window(0x00B65E18, 26, 54, "post-depth first-person group call 2")

def print_decompilations():
	write("")
	write("=" * 70)
	write("DECOMPILATIONS")
	write("=" * 70)
	decompile_at(0x00875110, "Main::RenderFirstPerson", 26000)
	decompile_at(0x00874C10, "RenderFirstPerson_Setup", 22000)
	decompile_at(0x00874B50, "RenderFirstPerson_PostGeometryCleanup", 16000)
	decompile_at(0x007148C0, "NiRenderer::Clear", 22000)
	decompile_at(0x00559450, "MainPointerSlot_00559450", 12000)
	decompile_at(0x00B64570, "BSShaderAccumulator::RenderFirstPersonAccumulated", 24000)
	decompile_at(0x00B64E30, "BSShaderAccumulator::RenderFirstPersonGeometryGroups", 20000)
	decompile_at(0x00B98380, "RendererStateHelper_00B98380", 14000)
	decompile_at(0x00B97E30, "RendererStateHelper_00B97E30", 14000)
	decompile_at(0x00B98320, "RendererStateHelper_00B98320", 14000)
	decompile_at(0x00B55AC0, "ImageSpaceManager::ProcessImageSpaceShaders", 22000)

def print_call_lists():
	write("")
	write("=" * 70)
	write("CALL LISTS")
	write("=" * 70)
	find_and_print_calls_from(0x00875110, "Main::RenderFirstPerson")
	find_and_print_calls_from(0x00874C10, "RenderFirstPerson_Setup")
	find_and_print_calls_from(0x00874B50, "RenderFirstPerson_PostGeometryCleanup")
	find_and_print_calls_from(0x007148C0, "NiRenderer::Clear")
	find_and_print_calls_from(0x00B55AC0, "ImageSpaceManager::ProcessImageSpaceShaders")

def print_refs():
	write("")
	write("=" * 70)
	write("GLOBAL REFERENCES")
	write("=" * 70)
	find_refs_to(0x011C73B4, "NiDX9Renderer::singleton")
	find_refs_to(0x011F917C, "BSShaderManager::pCurrentCamera")
	find_refs_to(0x011F9438, "BSShaderManager::pCurrentRenderTarget")
	find_refs_to(0x011DE9D1, "bOffsetViewModelLights")

def write_output():
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_first_person_depth_composite_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))

def main():
	print_questions()
	print_render_order_callers()
	print_known_windows()
	print_decompilations()
	print_call_lists()
	print_refs()
	write_output()

main()
decomp.dispose()
