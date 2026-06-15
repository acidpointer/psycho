# @category Analysis
# @description Audit FalloutNV first-person render state and depth contract for OMV

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x007148C0: "NiRenderer::Clear",
	0x00873200: "Main::RenderWorldSceneGraph",
	0x00874B50: "RenderFirstPerson_PostGeometryCleanup",
	0x00874C10: "RenderFirstPerson_Setup",
	0x00875110: "Main::RenderFirstPerson",
	0x00B63770: "BSShaderAccumulator::RenderBatches",
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
		if count > 60:
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
		disasm_window(from_addr, 12, 28, "caller of %s" % label)
		count += 1
		if count >= max_callers:
			write("  ... caller scan truncated")
			break
	write("Total callers printed: %d" % count)

def print_contract_questions():
	write("")
	write("=" * 70)
	write("QUESTIONS THIS AUDIT MUST ANSWER")
	write("=" * 70)
	write("1. Does RenderFirstPerson clear depth only, or also set no-depth render state?")
	write("2. Which RenderGeometryGroup call is first-person weapon/hand geometry?")
	write("3. Are first-person groups drawn with D3DRS_ZENABLE/ZWRITE/ZFUNC compatible with world depth?")
	write("4. Where can Psycho resolve world depth and apply shaders without first-person color/depth mismatch?")
	write("5. Which hook points overlap DepthResolve/TESReloaded patch callsites and must be avoided?")

def print_known_callsites():
	write("")
	write("=" * 70)
	write("KNOWN CALLSITE WINDOWS")
	write("=" * 70)
	disasm_window(0x008751C6, 18, 30, "RenderFirstPerson depth clear")
	disasm_window(0x008755B6, 18, 34, "RenderFirstPerson renderer state helper")
	disasm_window(0x0087590A, 22, 34, "RenderFirstPerson accumulator call")
	disasm_window(0x0087591D, 14, 24, "RenderFirstPerson cleanup call")
	disasm_window(0x00B64E83, 18, 30, "geometry group 2 alpha 1")
	disasm_window(0x00B64E8E, 18, 30, "geometry group 3 alpha 1")
	disasm_window(0x00B65B58, 18, 34, "late scene geometry group 10 alpha 0")
	disasm_window(0x00B65C09, 18, 34, "late scene geometry group 0 alpha 0")
	disasm_window(0x00B65D62, 18, 34, "post-depth geometry group 9 alpha 1")
	disasm_window(0x00B65DAD, 18, 34, "post-depth geometry group 1 alpha 0")

def print_decompilations():
	decompile_at(0x00875110, "Main::RenderFirstPerson", 22000)
	decompile_at(0x00874C10, "RenderFirstPerson_Setup", 18000)
	decompile_at(0x00874B50, "RenderFirstPerson_PostGeometryCleanup", 12000)
	decompile_at(0x00B64570, "BSShaderAccumulator::RenderFirstPersonAccumulated", 22000)
	decompile_at(0x00B64E30, "BSShaderAccumulator::RenderFirstPersonGeometryGroups", 16000)
	decompile_at(0x00B639E0, "BSShaderAccumulator::RenderGeometryGroup", 12000)
	decompile_at(0x00B65AE0, "BSShaderAccumulator::RenderLateSceneGroups", 18000)
	decompile_at(0x00B65C60, "BSShaderAccumulator::RenderPostDepthGroups", 18000)
	decompile_at(0x00B98380, "RendererStateHelper_00B98380", 12000)
	decompile_at(0x00B98320, "RendererStateHelper_00B98320", 12000)
	decompile_at(0x00B97E30, "RendererStateHelper_00B97E30", 12000)
	decompile_at(0x00B97FA0, "RendererStateHelper_00B97FA0", 12000)
	decompile_at(0x007148C0, "NiRenderer::Clear", 16000)

def print_call_scans():
	find_and_print_calls_from(0x00875110, "Main::RenderFirstPerson")
	find_and_print_calls_from(0x00874C10, "RenderFirstPerson_Setup")
	find_and_print_calls_from(0x00B64570, "BSShaderAccumulator::RenderFirstPersonAccumulated")
	find_and_print_calls_from(0x00B64E30, "BSShaderAccumulator::RenderFirstPersonGeometryGroups")
	find_and_print_calls_from(0x00B65AE0, "BSShaderAccumulator::RenderLateSceneGroups")
	find_and_print_calls_from(0x00B65C60, "BSShaderAccumulator::RenderPostDepthGroups")
	scan_callers_to(0x00B639E0, "BSShaderAccumulator::RenderGeometryGroup", 16)
	scan_callers_to(0x00B98380, "RendererStateHelper_00B98380", 20)
	scan_callers_to(0x00B98320, "RendererStateHelper_00B98320", 20)
	scan_callers_to(0x00B97E30, "RendererStateHelper_00B97E30", 20)
	scan_callers_to(0x00B97FA0, "RendererStateHelper_00B97FA0", 20)

def print_refs():
	find_refs_to(0x011F9438, "BSShaderManager::pCurrentRenderTarget")
	find_refs_to(0x011F917C, "BSShaderManager::pCurrentCamera")

def main():
	write("FNV FIRST-PERSON STATE CONTRACT AUDIT")
	print_contract_questions()
	print_known_callsites()
	print_decompilations()
	print_call_scans()
	print_refs()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_first_person_state_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))

main()
decomp.dispose()
