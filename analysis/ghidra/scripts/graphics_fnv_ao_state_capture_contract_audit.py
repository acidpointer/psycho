# @category Analysis
# @description Audit FNV render state and depth capture contracts at the OMV ambient occlusion boundary

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x007148C0: "NiRenderer::Clear",
	0x00875110: "Main::RenderFirstPerson",
	0x008751C6: "first-person depth clear callsite",
	0x0087590A: "first-person accumulated geometry callsite",
	0x00876125: "pCurrentCamera write before image-space",
	0x00876136: "ProcessImageSpaceShaders callsite",
	0x00B55AC0: "ImageSpaceManager::ProcessImageSpaceShaders",
	0x00B8C830: "ImageSpaceManager::RenderEffect rendered-texture source",
	0x00B8C980: "ImageSpaceManager::RenderEffect NiTexture source",
	0x00B97550: "ImageSpaceManager::RenderEffect effect-id rendered-texture source",
	0x00B975F0: "ImageSpaceManager::RenderEffect effect-id NiTexture source",
	0x00B97900: "ImageSpaceManager::RenderEndOfFrameEffects",
	0x00B97D90: "BSRenderState::SetRenderState",
	0x00B97FA0: "BSRenderState::SetAlphaBlendEnable",
	0x00B98380: "BSRenderState::SetColorWriteEnable",
	0x011DEB7C: "Main world SceneGraph pointer",
	0x011F917C: "BSShaderManager::pCurrentCamera",
	0x011F91AC: "ImageSpaceManager singleton",
	0x011F9438: "BSShaderManager::pCurrentRenderTarget",
	0x011FF9D8: "BSRenderState lock array",
	0x011FFA30: "D3D render-state to BSRenderState map",
}

FUNCTIONS = [
	0x00875110,
	0x00B55AC0,
	0x00B97900,
	0x00B97550,
	0x00B975F0,
	0x00B8C830,
	0x00B8C980,
	0x00B97D90,
	0x00B97FA0,
	0x00B98380,
]

WINDOWS = [
	0x008751C6,
	0x0087590A,
	0x00876125,
	0x00876136,
]

REFERENCE_TARGETS = [
	0x00B97D90,
	0x00B97FA0,
	0x00B98380,
	0x011DEB7C,
	0x011F917C,
	0x011F91AC,
	0x011F9438,
	0x011FF9D8,
	0x011FFA30,
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
	inst_iter = currentProgram.getListing().getInstructions(body, True)
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
		disasm_window(from_addr, 10, 24, "reference to %s" % label)
		count += 1
		if count >= max_refs:
			write("  ... reference scan truncated")
			break
	write("Total reference windows printed: %d" % count)

def audit_functions():
	idx = 0
	while idx < len(FUNCTIONS):
		addr = FUNCTIONS[idx]
		decompile_at(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))
		idx += 1

def audit_windows():
	idx = 0
	while idx < len(WINDOWS):
		addr = WINDOWS[idx]
		disasm_window(addr, 24, 56, label_for(addr))
		idx += 1

def audit_references():
	idx = 0
	while idx < len(REFERENCE_TARGETS):
		addr = REFERENCE_TARGETS[idx]
		find_refs_to(addr, label_for(addr))
		scan_reference_windows(addr, label_for(addr), 24)
		idx += 1

def print_header():
	write("FNV OMV AMBIENT OCCLUSION STATE AND CAPTURE CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. Which engine render states are established for a native image-space pass?")
	write("2. Can alpha test, stencil test, or scissor test remain active at 0x00876136?")
	write("3. Has current-frame first-person depth finished rendering before 0x00876136?")
	write("4. Is resolving first-person depth after Main::RenderFirstPerson necessarily too late for OMV scene-pre AO?")
	write("5. Which camera and rendered-texture objects are live at the image-space callsite?")
	write("")
	write("Render-state mapping from the available engine headers:")
	write("  BSRS_ALPHA_TEST=4, BSRS_STENCIL_ENABLE=9, BSRS_SCISSOR_TEST=13")
	write("  BSRS_COLOR_WRITE=16, BSRS_FILL_MODE=18, BSRS_CULL_MODE=19")
	write("")
	write("Static limitation:")
	write("This proves vanilla code shape only. Runtime GetRenderState telemetry is still required to show the exact inherited state on a blinking frame.")

def main():
	print_header()
	audit_windows()
	audit_references()
	audit_functions()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_ao_state_capture_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
