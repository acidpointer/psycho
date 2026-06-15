# @category Analysis
# @description Audit FNV effect phase boundaries for OMV scene/final shader dispatch

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x005BF43C: "Fallout Shader Loader ReloadShaders callsite A",
	0x005C5A39: "Fallout Shader Loader ReloadShaders callsite B",
	0x007148C0: "NiRenderer::Clear",
	0x008706B0: "Main::Render",
	0x00870A00: "Main render world caller A",
	0x00870BD0: "Main render world caller B",
	0x00870AE8: "call Main::RenderWorldSceneGraph A",
	0x00870B21: "call Main::RenderFirstPerson A",
	0x00870E18: "call Main::RenderWorldSceneGraph B",
	0x00870F74: "call Main::RenderFirstPerson B",
	0x00873200: "Main::RenderWorldSceneGraph",
	0x00875110: "Main::RenderFirstPerson",
	0x008751C6: "RenderFirstPerson depth clear",
	0x00876125: "pCurrentCamera write before image-space",
	0x00876136: "ProcessImageSpaceShaders callsite",
	0x00B54090: "ImageSpaceManager::GetDepthTexture",
	0x00B55AC0: "ImageSpaceManager::ProcessImageSpaceShaders",
	0x00B63770: "BSShaderAccumulator::RenderBatches",
	0x00B639E0: "BSShaderAccumulator::RenderGeometryGroup",
	0x00B64570: "BSShaderAccumulator::RenderFirstPersonAccumulated",
	0x00B64E30: "BSShaderAccumulator::RenderFirstPersonGeometryGroups",
	0x00B65C43: "DepthResolve alpha blend skip patch A",
	0x00B65C4C: "DepthResolve alpha blend skip patch B",
	0x00B65C60: "BSShaderAccumulator::RenderPostDepthGroups",
	0x00B6657D: "DepthResolve replacement call A",
	0x00B665AC: "DepthResolve replacement call B",
	0x00B6B790: "BSRenderedTexture::StopOffscreen",
	0x00B6B8D0: "BSRenderedTexture::StartOffscreen",
	0x00B8C830: "ImageSpaceManager::RenderEffect rendered texture source",
	0x00B8C980: "ImageSpaceManager::RenderEffect NiTexture source",
	0x00B97550: "ImageSpaceManager::RenderEffect id/rendered texture",
	0x00B97900: "ImageSpaceManager::RenderEndOfFrameEffects",
	0x00BE0FE0: "BSShader::CreateVertexShader",
	0x00BE1750: "BSShader::CreatePixelShader",
	0x011F917C: "BSShaderManager::pCurrentCamera",
	0x011F91E0: "BSShaderManager::current geometry candidate",
	0x011F9438: "BSShaderManager::pCurrentRenderTarget",
	0x0126F74C: "NiD3DPass::current pass candidate",
}

WATCH_CALL_TARGETS = {
	0x007148C0: "NiRenderer::Clear",
	0x00873200: "Main::RenderWorldSceneGraph",
	0x00875110: "Main::RenderFirstPerson",
	0x00B55AC0: "ImageSpaceManager::ProcessImageSpaceShaders",
	0x00B63770: "BSShaderAccumulator::RenderBatches",
	0x00B639E0: "BSShaderAccumulator::RenderGeometryGroup",
	0x00B64570: "BSShaderAccumulator::RenderFirstPersonAccumulated",
	0x00B64E30: "BSShaderAccumulator::RenderFirstPersonGeometryGroups",
	0x00B65C60: "BSShaderAccumulator::RenderPostDepthGroups",
	0x00B6B790: "BSRenderedTexture::StopOffscreen",
	0x00B6B8D0: "BSRenderedTexture::StartOffscreen",
	0x00B8C830: "ImageSpaceManager::RenderEffect rendered texture source",
	0x00B8C980: "ImageSpaceManager::RenderEffect NiTexture source",
	0x00B97550: "ImageSpaceManager::RenderEffect id/rendered texture",
	0x00B97900: "ImageSpaceManager::RenderEndOfFrameEffects",
}

PHASE_FUNCTIONS = [
	0x008706B0,
	0x00870A00,
	0x00870BD0,
	0x00873200,
	0x00875110,
	0x00B55AC0,
	0x00B97900,
	0x00B65C60,
	0x00B639E0,
	0x00B64570,
	0x00B64E30,
]

PHASE_WINDOWS = [
	0x00870AE8,
	0x00870B21,
	0x00870E18,
	0x00870F74,
	0x008751C6,
	0x00876125,
	0x00876136,
	0x00B65C60,
	0x00B97900,
]

COLLISION_WINDOWS = [
	0x00B54090,
	0x00B65C43,
	0x00B65C4C,
	0x00B6657D,
	0x00B665AC,
	0x00BE0FE0,
	0x00BE1750,
	0x005BF43C,
	0x005C5A39,
]

GLOBAL_REFS = [
	0x011F917C,
	0x011F91E0,
	0x011F9438,
	0x0126F74C,
]

CALLER_TARGETS = [
	0x00873200,
	0x00875110,
	0x00B55AC0,
	0x00B97900,
	0x00B65C60,
	0x00B639E0,
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

def decompile_at(addr_int, label, max_len=16000):
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
		disasm_window(from_addr, 8, 18, "reference to %s" % label)
		count += 1
		if count >= max_refs:
			write("  ... reference window scan truncated")
			break
	write("Total reference windows printed: %d" % count)

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

def print_phase_contract_notes():
	write("")
	write("=" * 70)
	write("PHASE CONTRACT NOTES")
	write("=" * 70)
	write("Current conservative milestone:")
	write("  scene_pre_image_space runs after Main::RenderWorldSceneGraph returns, only on is_first_person == 0.")
	write("  This avoids DepthResolve-owned sites and first-person depth-clear patches, but it is before weapon rendering.")
	write("  It is expected to fix AO over far fog for world geometry, not to solve every first-person composition issue.")
	write("")
	write("Boundary to prove before moving deeper:")
	write("  The ideal non-invasive scene boundary is after first-person geometry and before ProcessImageSpaceShaders.")
	write("  If that boundary is only available as a narrow callsite, prefer a targeted callsite hook over broad native replacement.")
	write("")
	write("Off-limits by default:")
	write("  DepthResolve-owned GetDepthTexture and replacement callsites.")
	write("  TESReloaded-style first-person depth-clear patch.")
	write("  Native shader creation hooks unless an opt-in compatibility mode is selected.")

def audit_ordered_calls():
	idx = 0
	while idx < len(PHASE_FUNCTIONS):
		addr = PHASE_FUNCTIONS[idx]
		print_ordered_watch_calls(addr, label_for(addr))
		idx += 1

def audit_windows():
	idx = 0
	while idx < len(PHASE_WINDOWS):
		addr = PHASE_WINDOWS[idx]
		write("")
		write("Bytes @ 0x%08x (%s): %s" % (addr, label_for(addr), read_bytes(addr, 16)))
		disasm_window(addr, 16, 42, label_for(addr))
		idx += 1

def audit_collision_windows():
	idx = 0
	while idx < len(COLLISION_WINDOWS):
		addr = COLLISION_WINDOWS[idx]
		write("")
		write("Collision bytes @ 0x%08x (%s): %s" % (addr, label_for(addr), read_bytes(addr, 16)))
		disasm_window(addr, 8, 18, label_for(addr))
		idx += 1

def audit_globals():
	idx = 0
	while idx < len(GLOBAL_REFS):
		addr = GLOBAL_REFS[idx]
		find_refs_to(addr, label_for(addr))
		scan_refs_windows(addr, label_for(addr), 12)
		idx += 1

def audit_callers():
	idx = 0
	while idx < len(CALLER_TARGETS):
		addr = CALLER_TARGETS[idx]
		scan_callers_to(addr, label_for(addr), 12)
		idx += 1

def audit_functions():
	idx = 0
	while idx < len(PHASE_FUNCTIONS):
		addr = PHASE_FUNCTIONS[idx]
		decompile_at(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))
		idx += 1

def print_header():
	write("FNV GRAPHICS EFFECT PHASE CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. Is there a stable non-invasive boundary after first-person rendering and before vanilla image-space?")
	write("2. Does the current post-world/pre-image-space milestone avoid known graphics-mod collision sites?")
	write("3. Which vanilla calls overwrite or consume render targets after each candidate scene phase?")
	write("4. Which DepthResolve, Shader Loader, and TESReloaded-style sites should stay opt-in or off-limits?")
	write("")
	write("Static limitation:")
	write("This script cannot see runtime detours from loaded DLLs. It proves vanilla code shape and known static collision areas only.")

def main():
	print_header()
	print_phase_contract_notes()
	audit_ordered_calls()
	audit_windows()
	audit_collision_windows()
	audit_globals()
	audit_callers()
	audit_functions()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_effect_phase_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
