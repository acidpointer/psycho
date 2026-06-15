# @category Analysis
# @description Audit FNV render-stage ordering for OMV scene/final shader boundaries

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x004EA970: "RendererLockFactory_004EA970",
	0x007148C0: "NiRenderer::Clear",
	0x008706B0: "Main::Render",
	0x00870A00: "Main render world caller A",
	0x00870BD0: "Main render world caller B",
	0x00870AE8: "call Main::RenderWorldSceneGraph A",
	0x00870AF8: "call RenderFirstPerson_Setup A",
	0x00870B0B: "call RenderFirstPerson_PostGeometryCleanup A",
	0x00870B21: "call Main::RenderFirstPerson A",
	0x00870E18: "call Main::RenderWorldSceneGraph B",
	0x00873200: "Main::RenderWorldSceneGraph",
	0x00874B50: "RenderFirstPerson_PostGeometryCleanup",
	0x00874C10: "RenderFirstPerson_Setup",
	0x00875110: "Main::RenderFirstPerson",
	0x008751C6: "RenderFirstPerson depth clear",
	0x00B55AC0: "ImageSpaceManager::ProcessImageSpaceShaders",
	0x00B63770: "BSShaderAccumulator::RenderBatches",
	0x00B639E0: "BSShaderAccumulator::RenderGeometryGroup",
	0x00B65C60: "BSShaderAccumulator::RenderPostDepthGroups",
	0x00B6B790: "BSRenderedTexture::StopOffscreen",
	0x00B6B8D0: "BSRenderedTexture::StartOffscreen",
	0x00B8C830: "ImageSpaceManager::RenderEffect rendered texture source",
	0x00B8C980: "ImageSpaceManager::RenderEffect NiTexture source",
	0x00B97550: "ImageSpaceManager::RenderEffect id/rendered texture",
	0x00B97900: "ImageSpaceManager::RenderEndOfFrameEffects",
	0x011F9438: "BSShaderManager::pCurrentRenderTarget",
	0x011F943C: "BSShaderManager::pWaterRefractionTexture",
}

WATCH_CALL_TARGETS = {
	0x00873200: "Main::RenderWorldSceneGraph",
	0x00874B50: "RenderFirstPerson_PostGeometryCleanup",
	0x00874C10: "RenderFirstPerson_Setup",
	0x00875110: "Main::RenderFirstPerson",
	0x007148C0: "NiRenderer::Clear",
	0x00B55AC0: "ImageSpaceManager::ProcessImageSpaceShaders",
	0x00B63770: "BSShaderAccumulator::RenderBatches",
	0x00B639E0: "BSShaderAccumulator::RenderGeometryGroup",
	0x00B6B790: "BSRenderedTexture::StopOffscreen",
	0x00B6B8D0: "BSRenderedTexture::StartOffscreen",
	0x00B8C830: "ImageSpaceManager::RenderEffect rendered texture source",
	0x00B8C980: "ImageSpaceManager::RenderEffect NiTexture source",
	0x00B97550: "ImageSpaceManager::RenderEffect id/rendered texture",
	0x00B97900: "ImageSpaceManager::RenderEndOfFrameEffects",
}

ORDER_FUNCTIONS = [
	0x008706B0,
	0x00870A00,
	0x00870BD0,
	0x00873200,
	0x00875110,
	0x00B55AC0,
	0x00B65C60,
	0x00B97900,
]

BOUNDARY_WINDOWS = [
	0x00870AE8,
	0x00870AF8,
	0x00870B0B,
	0x00870B21,
	0x00870E18,
	0x008751C6,
	0x00B65C84,
	0x00B65CD1,
	0x00B65D62,
	0x00B65DAD,
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

def decompile_at(addr_int, label, max_len=14000):
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
		disasm_window(from_addr, 12, 30, "caller of %s" % label)
		count += 1
		if count >= max_callers:
			write("  ... caller scan truncated")
			break
	write("Total callers printed: %d" % count)

def print_ordered_watch_calls(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("=" * 70)
	write("ORDERED WATCH CALLS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
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
				if WATCH_CALL_TARGETS.get(tgt) is not None:
					write("  %02d 0x%08x -> 0x%08x %s" % (count + 1, inst.getAddress().getOffset(), tgt, WATCH_CALL_TARGETS.get(tgt)))
					count += 1
	write("  Total watched calls: %d" % count)

def print_boundary_windows():
	idx = 0
	while idx < len(BOUNDARY_WINDOWS):
		addr = BOUNDARY_WINDOWS[idx]
		disasm_window(addr, 14, 34, label_for(addr))
		idx += 1

def print_order_functions():
	idx = 0
	while idx < len(ORDER_FUNCTIONS):
		addr = ORDER_FUNCTIONS[idx]
		print_ordered_watch_calls(addr, label_for(addr))
		idx += 1

def print_callers():
	scan_callers_to(0x00873200, "Main::RenderWorldSceneGraph", 8)
	scan_callers_to(0x00875110, "Main::RenderFirstPerson", 8)
	scan_callers_to(0x00B55AC0, "ImageSpaceManager::ProcessImageSpaceShaders", 12)
	scan_callers_to(0x00B97900, "ImageSpaceManager::RenderEndOfFrameEffects", 12)
	scan_callers_to(0x00B639E0, "BSShaderAccumulator::RenderGeometryGroup", 16)

def print_decompilations():
	decompile_at(0x008706B0, "Main::Render")
	decompile_at(0x00870A00, "Main render world caller A")
	decompile_at(0x00870BD0, "Main render world caller B")
	decompile_at(0x00873200, "Main::RenderWorldSceneGraph")
	decompile_at(0x00875110, "Main::RenderFirstPerson")
	decompile_at(0x00B55AC0, "ImageSpaceManager::ProcessImageSpaceShaders")
	decompile_at(0x00B97900, "ImageSpaceManager::RenderEndOfFrameEffects")
	decompile_at(0x00B65C60, "BSShaderAccumulator::RenderPostDepthGroups")

def print_refs():
	find_refs_to(0x011F9438, "BSShaderManager::pCurrentRenderTarget")
	find_refs_to(0x011F943C, "BSShaderManager::pWaterRefractionTexture")
	find_refs_to(0x00B8C830, "ImageSpaceManager::RenderEffect rendered texture source")
	find_refs_to(0x00B97550, "ImageSpaceManager::RenderEffect id/rendered texture")

def print_header():
	write("FNV GRAPHICS STAGE BOUNDARY ORDER DEEP AUDIT")
	write("")
	write("Questions:")
	write("1. Is post-world/pre-first-person a real boundary for scene-space AO?")
	write("2. Is post-ProcessImageSpaceShaders a real boundary for final AA/CAS/bloom?")
	write("3. Which callsites expose lower-collision alternatives to function-entry hooks?")
	write("4. Which vanilla calls overwrite or consume render targets after a candidate boundary?")

def main():
	print_header()
	print_order_functions()
	print_boundary_windows()
	print_callers()
	print_refs()
	print_decompilations()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_stage_boundary_order_deep_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
