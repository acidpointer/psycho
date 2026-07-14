# @category Analysis
# @description Bounded OMV evidence pack for FNV sun, camera, depth, first-person, and image-space phase contracts

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

DECOMPILE_TIMEOUT_SECONDS = 25
MAX_REFS = 48
MAX_CALLS = 160
MAX_FUNCTION_INSTRUCTIONS = 60000

KNOWN = {
	0x0045BB80: "vector getter used by native sun projection",
	0x0045CD60: "Sky sun/current object getter candidate",
	0x0063B630: "weather day phase weights",
	0x006629F0: "current camera/scene getter",
	0x007148C0: "NiRenderer::Clear",
	0x008706B0: "Main::Render",
	0x00870A00: "main render path A",
	0x00870BD0: "main render path B and native sun projection owner",
	0x00873200: "Main::RenderWorldSceneGraph",
	0x00875110: "Main::RenderFirstPerson",
	0x00875FD0: "image-space caller",
	0x00877730: "Sky render/update candidate",
	0x00A6FDB0: "native sun projection visibility helper",
	0x00B55AC0: "ImageSpaceManager::ProcessImageSpaceShaders",
	0x00B5E870: "shader camera global writer",
	0x00B6B260: "BSRenderedTexture::GetRenderTargetGroup",
	0x00B6B790: "BSRenderedTexture::StopOffscreen",
	0x00B6B8D0: "BSRenderedTexture::StartOffscreen",
	0x00BD66C0: "shader camera near/far consumer",
	0x011C73B4: "NiDX9Renderer singleton",
	0x011DEA20: "Sky singleton",
	0x011F917C: "BSShaderManager::pCurrentCamera",
	0x011F9438: "BSShaderManager::pCurrentRenderTarget",
	0x011F9684: "world camera/scene pointer candidate",
	0x011FA280: "shader camera global block",
}

DECOMPILE_TARGETS = [
	(0x0045BB80, "vector getter used by native sun projection", 8000),
	(0x0045CD60, "Sky sun/current object getter candidate", 10000),
	(0x006629F0, "current camera/scene getter", 8000),
	(0x00A6FDB0, "native sun projection visibility helper", 16000),
	(0x00870BD0, "main render path B and native sun projection owner", 24000),
	(0x0063B630, "weather day phase weights", 16000),
	(0x00873200, "Main::RenderWorldSceneGraph", 22000),
	(0x00875110, "Main::RenderFirstPerson", 26000),
	(0x007148C0, "NiRenderer::Clear", 14000),
	(0x00875FD0, "image-space caller", 18000),
	(0x00B55AC0, "ImageSpaceManager::ProcessImageSpaceShaders", 22000),
	(0x00B5E870, "shader camera global writer", 18000),
	(0x00BD66C0, "shader camera near/far consumer", 14000),
]

CALL_LIST_TARGETS = [
	(0x008706B0, "Main::Render"),
	(0x00870A00, "main render path A"),
	(0x00870BD0, "main render path B and native sun projection owner"),
	(0x00873200, "Main::RenderWorldSceneGraph"),
	(0x00875110, "Main::RenderFirstPerson"),
	(0x00875FD0, "image-space caller"),
	(0x00B55AC0, "ImageSpaceManager::ProcessImageSpaceShaders"),
]

REF_TARGETS = [
	(0x0045BB80, "vector getter used by native sun projection"),
	(0x006629F0, "current camera/scene getter"),
	(0x00A6FDB0, "native sun projection visibility helper"),
	(0x007148C0, "NiRenderer::Clear"),
	(0x00873200, "Main::RenderWorldSceneGraph"),
	(0x00875110, "Main::RenderFirstPerson"),
	(0x00B55AC0, "ImageSpaceManager::ProcessImageSpaceShaders"),
	(0x011C73B4, "NiDX9Renderer singleton"),
	(0x011DEA20, "Sky singleton"),
	(0x011F917C, "BSShaderManager::pCurrentCamera"),
	(0x011F9438, "BSShaderManager::pCurrentRenderTarget"),
	(0x011F9684, "world camera/scene pointer candidate"),
	(0x011FA280, "shader camera global block"),
]

DISASM_WINDOWS = [
	(0x00871000, 10, 52, "native sun guard and Sky/Sun source selection"),
	(0x00871046, 12, 24, "native sun vector getter call"),
	(0x00871092, 16, 24, "native sun camera transform call"),
	(0x00871099, 16, 34, "native sun projection/visibility call"),
	(0x00870AE8, 14, 28, "render path A world call"),
	(0x00870B21, 14, 28, "render path A first-person call"),
	(0x00870E18, 14, 28, "render path B world call"),
	(0x00870F74, 14, 28, "render path B first-person call"),
	(0x00872FDF, 16, 30, "current render target write"),
	(0x008751C6, 20, 40, "first-person depth clear"),
	(0x0087589F, 20, 46, "first-person current render target read"),
	(0x00876125, 18, 34, "current camera write before image-space"),
	(0x00876136, 18, 34, "ProcessImageSpaceShaders callsite"),
	(0x00B65C60, 18, 42, "post-depth render groups"),
	(0x00B6657D, 12, 24, "DepthResolve collision site A"),
	(0x00B665AC, 12, 24, "DepthResolve collision site B"),
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
	result = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
		if len(code) > max_len:
			write("  ... [truncated, total chars=%d]" % len(code))
	else:
		write("  [decompilation failed or timed out after %d seconds]" % DECOMPILE_TIMEOUT_SECONDS)

def find_refs_to(addr_int, label):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext() and count < MAX_REFS:
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
	if refs.hasNext():
		write("  ... [truncated at %d refs]" % MAX_REFS)
	write("  Printed: %d refs" % count)

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
	call_count = 0
	inst_count = 0
	while inst_iter.hasNext() and inst_count < MAX_FUNCTION_INSTRUCTIONS and call_count < MAX_CALLS:
		inst = inst_iter.next()
		inst_count += 1
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				name = label_for(tgt)
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				call_count += 1
				if call_count >= MAX_CALLS:
					break
	if inst_iter.hasNext():
		write("  ... [bounded scan stopped]")
	write("  Total printed: %d calls from %d instructions" % (call_count, inst_count))

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
	write("-" * 70)
	inst = listing.getInstructionContaining(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionBefore(toAddr(center_int))
	if inst is None:
		write("  [instruction not found]")
		return
	count = 0
	while inst is not None and count < before_count:
		prev = listing.getInstructionBefore(inst.getAddress())
		if prev is None:
			break
		inst = prev
		count += 1
	idx = 0
	limit = before_count + after_count + 1
	while inst is not None and idx < limit:
		addr_int = inst.getAddress().getOffset()
		marker = " << TARGET" if inst.getAddress().equals(toAddr(center_int)) else ""
		extra = ""
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				extra = "%s ; CALL 0x%08x %s" % (extra, tgt, label_for(tgt))
		write("  0x%08x: %-52s%s%s" % (addr_int, inst.toString(), marker, extra))
		inst = listing.getInstructionAfter(inst.getAddress())
		idx += 1

def run_decompile_targets():
	idx = 0
	while idx < len(DECOMPILE_TARGETS):
		if monitor.isCancelled():
			write("Cancelled before remaining decompilations")
			return
		item = DECOMPILE_TARGETS[idx]
		decompile_at(item[0], item[1], item[2])
		idx += 1

def run_call_lists():
	idx = 0
	while idx < len(CALL_LIST_TARGETS):
		if monitor.isCancelled():
			write("Cancelled before remaining call lists")
			return
		item = CALL_LIST_TARGETS[idx]
		find_and_print_calls_from(item[0], item[1])
		idx += 1

def run_refs():
	idx = 0
	while idx < len(REF_TARGETS):
		if monitor.isCancelled():
			write("Cancelled before remaining references")
			return
		item = REF_TARGETS[idx]
		find_refs_to(item[0], item[1])
		idx += 1

def run_disasm_windows():
	idx = 0
	while idx < len(DISASM_WINDOWS):
		if monitor.isCancelled():
			write("Cancelled before remaining disassembly windows")
			return
		item = DISASM_WINDOWS[idx]
		disasm_window(item[0], item[1], item[2], item[3])
		idx += 1

def write_header():
	write("FNV OMV SCENE EFFECTS EVIDENCE PACK")
	write("")
	write("This audit is deliberately bounded and non-recursive.")
	write("Decompiler timeout per function: %d seconds" % DECOMPILE_TIMEOUT_SECONDS)
	write("Reference cap per target: %d" % MAX_REFS)
	write("Call cap per function: %d" % MAX_CALLS)
	write("")
	write("Questions covered:")
	write("1. What exact object/vector does vanilla use for sun screen projection?")
	write("2. Which transform and visibility helper generate native sun screen coordinates?")
	write("3. What is the world -> first-person -> image-space render order?")
	write("4. Which depth surface/render-target state is active at each OMV hook boundary?")
	write("5. Where is first-person depth cleared and where do offscreen target transitions occur?")
	write("6. Where are camera near/far and projection globals updated?")
	write("7. Which sites collide with DepthResolve-style ownership?")

def write_output():
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_omv_scene_effects_evidence_pack.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))

def main():
	write_header()
	run_disasm_windows()
	run_refs()
	run_call_lists()
	run_decompile_targets()
	write_output()

def run():
	try:
		main()
	finally:
		decomp.dispose()

run()
