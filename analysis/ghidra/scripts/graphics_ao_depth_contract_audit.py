# @category Analysis
# @description Audit FNV image-space/depth contracts needed for fast screen-space AO

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00B55AC0: "ProcessImageSpaceShaders",
	0x00B97900: "ImageSpaceManager::RenderEndOfFrameEffects",
	0x00B54090: "ImageSpaceManager::GetDepthTexture",
	0x00B4F530: "ImageSpaceTexture::GetDepthBuffer",
	0x00B8C980: "ImageSpaceManager::RenderEffect effect/source NiTexture",
	0x00B8C830: "ImageSpaceManager::RenderEffect effect/source rendered texture",
	0x00B975F0: "ImageSpaceManager::RenderEffect id/source NiTexture",
	0x00B97550: "ImageSpaceManager::RenderEffect id/source rendered texture",
	0x00B8C730: "ImageSpaceManager::RenderEffect id/destination only",
	0x00B6B610: "BSRenderedTexture::CreateTexture",
	0x00B6E110: "BSTextureManager::BorrowRenderedTexture",
	0x00B6DA10: "BSTextureManager::ReturnRenderedTexture",
	0x00B6B890: "BSRenderedTexture::Start",
	0x00B6B8D0: "BSRenderedTexture::StartOffscreen",
	0x00B6B730: "BSRenderedTexture::Stop",
	0x00B6B790: "BSRenderedTexture::StopOffscreen",
	0x00BE0FE0: "BSShader::CreateVertexShader",
	0x00BE1750: "BSShader::CreatePixelShader",
	0x011AD884: "ImageSpaceManager EOF enabled global",
	0x011C73B4: "NiDX9Renderer singleton pointer",
	0x011F917C: "BSShaderManager::pCamera",
	0x011F91A8: "BSShaderManager texture manager pointer",
	0x011F91AC: "ImageSpaceManager singleton pointer",
	0x011F9438: "BSShaderManager::pCurrentRenderTarget",
	0x011F943C: "BSShaderManager::pWaterRefractionTexture",
	0x011F9508: "BSShaderManager renderer pointer",
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

def decompile_at(addr_int, label, max_len=12000):
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
		write("  0x%08x: %-44s%s%s" % (addr_int, inst.toString(), marker, extra))
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
		from_addr = ref.getFromAddress()
		from_func = fm.getFunctionContaining(from_addr)
		fname = from_func.getName() if from_func else "???"
		write("")
		write("Caller %d: 0x%08x in %s" % (count + 1, from_addr.getOffset(), fname))
		disasm_window(from_addr.getOffset(), 10, 20, "caller of %s" % label)
		count += 1
		if count >= max_callers:
			write("  ... caller scan truncated")
			break
	write("Total callers printed: %d" % count)

def print_global_refs():
	globals_to_check = [
		(0x011AD884, "EOF enabled"),
		(0x011C73B4, "NiDX9Renderer singleton"),
		(0x011F917C, "camera pointer"),
		(0x011F91A8, "texture manager pointer"),
		(0x011F91AC, "image-space manager singleton"),
		(0x011F9438, "current render target"),
		(0x011F943C, "water refraction target"),
		(0x011F9508, "renderer pointer"),
	]
	for item in globals_to_check:
		find_refs_to(item[0], item[1])

def analyze_functions():
	targets = [
		(0x00B55AC0, "ProcessImageSpaceShaders"),
		(0x00B97900, "ImageSpaceManager::RenderEndOfFrameEffects"),
		(0x00B54090, "ImageSpaceManager::GetDepthTexture"),
		(0x00B4F530, "ImageSpaceTexture::GetDepthBuffer"),
		(0x00B8C980, "RenderEffect with NiTexture source"),
		(0x00B8C830, "RenderEffect with rendered texture source"),
		(0x00B975F0, "RenderEffect id with NiTexture source"),
		(0x00B97550, "RenderEffect id with rendered texture source"),
		(0x00B6B610, "BSRenderedTexture::CreateTexture"),
		(0x00B6E110, "BSTextureManager::BorrowRenderedTexture"),
		(0x00B6DA10, "BSTextureManager::ReturnRenderedTexture"),
		(0x00B6B890, "BSRenderedTexture::Start"),
		(0x00B6B8D0, "BSRenderedTexture::StartOffscreen"),
		(0x00B6B730, "BSRenderedTexture::Stop"),
		(0x00B6B790, "BSRenderedTexture::StopOffscreen"),
	]
	for item in targets:
		decompile_at(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])

def analyze_refs_and_callers():
	targets = [
		(0x00B97900, "RenderEndOfFrameEffects"),
		(0x00B54090, "GetDepthTexture"),
		(0x00B4F530, "GetDepthBuffer"),
		(0x00B8C980, "RenderEffect with NiTexture source"),
		(0x00B8C830, "RenderEffect with rendered texture source"),
		(0x00B975F0, "RenderEffect id with NiTexture source"),
		(0x00B97550, "RenderEffect id with rendered texture source"),
		(0x00B6B610, "CreateTexture"),
	]
	for item in targets:
		find_refs_to(item[0], item[1])
		scan_callers_to(item[0], item[1], 8)

def analyze_hook_windows():
	windows = [
		(0x00B55AD6, "ProcessImageSpaceShaders call to RenderEndOfFrameEffects"),
		(0x00B97900, "RenderEndOfFrameEffects entry"),
		(0x00B54090, "GetDepthTexture entry"),
		(0x00B4F530, "GetDepthBuffer entry"),
		(0x00B8C980, "RenderEffect NiTexture entry"),
		(0x00B8C830, "RenderEffect rendered texture entry"),
	]
	for item in windows:
		disasm_window(item[0], 14, 40, item[1])

def main():
	write("=" * 70)
	write("GRAPHICS AO DEPTH CONTRACT AUDIT")
	write("=" * 70)
	write("Goal: verify image-space hook timing, depth texture access, and render-target helpers for Psycho AO.")
	analyze_functions()
	analyze_refs_and_callers()
	print_global_refs()
	analyze_hook_windows()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_ao_depth_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))

main()
decomp.dispose()
