# @category Analysis
# @description Audit FNV native depth texture object layout used by omv

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00B54090: "ImageSpaceManager::GetDepthTexture",
	0x00BA3780: "ImageSpaceTexture::GetTexture",
	0x00B8C980: "ImageSpaceManager::RenderEffect effect/source NiTexture",
	0x00B975F0: "ImageSpaceManager::RenderEffect id/source NiTexture",
	0x00BE0FE0: "BSShader::CreateVertexShader",
	0x00BE1750: "BSShader::CreatePixelShader",
	0x011F917C: "BSShaderManager::pCamera",
	0x011F91AC: "ImageSpaceManager singleton pointer",
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

def print_offset_contracts():
	write("")
	write("=" * 70)
	write("omv raw offset contract to verify")
	write("=" * 70)
	write("NiTexture::m_pkRendererData expected offset: 0x24")
	write("NiDX9TextureData::m_pkD3DTexture expected offset: 0x64")
	write("NiCamera::m_kViewFrustum.m_fNear expected offset: 0xEC")
	write("NiCamera::m_kViewFrustum.m_fFar expected offset: 0xF0")
	write("ImageSpaceManager::GetDepthTexture expected to return NiTexture* in EAX")

def analyze_targets():
	targets = [
		(0x00B54090, "ImageSpaceManager::GetDepthTexture"),
		(0x00BA3780, "ImageSpaceTexture::GetTexture"),
		(0x00B8C980, "RenderEffect with NiTexture source"),
		(0x00B975F0, "RenderEffect id with NiTexture source"),
		(0x00BE0FE0, "BSShader::CreateVertexShader"),
		(0x00BE1750, "BSShader::CreatePixelShader"),
	]
	for item in targets:
		decompile_at(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])

def analyze_globals():
	globals_to_check = [
		(0x011F917C, "BSShaderManager::pCamera"),
		(0x011F91AC, "ImageSpaceManager singleton pointer"),
	]
	for item in globals_to_check:
		find_refs_to(item[0], item[1])

def analyze_disassembly():
	disasm_window(0x00B54090, 4, 12, "GetDepthTexture entry")
	disasm_window(0x00BA3780, 8, 28, "ImageSpaceTexture::GetTexture entry")
	disasm_window(0x00B8C980, 16, 70, "RenderEffect NiTexture source")

def main():
	write("FNV DEPTH TEXTURE LAYOUT AUDIT")
	print_offset_contracts()
	analyze_targets()
	analyze_globals()
	analyze_disassembly()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_depth_texture_layout_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
