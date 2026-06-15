# @category Analysis
# @description Audit FNV render target group depth surface chain for OMV

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00B63770: "BSShaderAccumulator::RenderBatches",
	0x00B639E0: "BSShaderAccumulator::RenderGeometryGroup",
	0x00B65C60: "BSShaderAccumulator::FinishAccumulating_Standard_PreResolveDepth",
	0x00B6B260: "BSRenderedTexture::GetRenderTargetGroup",
	0x00B6657D: "DepthResolve replacement call A",
	0x00B665AC: "DepthResolve replacement call B",
	0x00B6B790: "BSRenderedTexture::StopOffscreen",
	0x00B6B8D0: "BSRenderedTexture::StartOffscreen",
	0x011F603C: "RTTI_NiDepthStencilBuffer",
	0x011F9438: "BSShaderManager::pCurrentRenderTarget",
	0x011F943C: "BSShaderManager::pWaterRefractionTexture",
	0x012708EC: "RTTI_NiRenderTargetGroup",
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

def decompile_at(addr_int, label, max_len=18000):
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
		disasm_window(from_addr, 10, 24, "caller of %s" % label)
		count += 1
		if count >= max_callers:
			write("  ... caller scan truncated")
			break
	write("Total callers printed: %d" % count)

def print_static_contract():
	write("")
	write("=" * 70)
	write("REFERENCE CONTRACT TO VERIFY")
	write("=" * 70)
	write("Expected BSShaderManager::pCurrentRenderTarget global: 0x011F9438")
	write("Expected BSRenderedTexture.spRenderTargetGroups[0] offset: +0x08")
	write("Expected NiRenderTargetGroup.m_spDepthStencilBuffer offset: +0x20")
	write("Expected NiDepthStencilBuffer.m_spRendererData offset: +0x10")
	write("Expected NiDX92DBufferData.Surface offset: +0x14")
	write("Expected first-person boundary hook: BSShaderAccumulator::RenderGeometryGroup(group=1, alpha=0)")
	write("Expected non-conflict with DepthResolve: hook RenderGeometryGroup, not callsites 0x00B6657D/0x00B665AC")

def main():
	write("FNV RTGROUP DEPTH SURFACE AUDIT")
	print_static_contract()
	find_refs_to(0x011F9438, "BSShaderManager::pCurrentRenderTarget")
	scan_refs_windows(0x011F9438, "BSShaderManager::pCurrentRenderTarget", 12)
	decompile_at(0x00B6B260, "BSRenderedTexture::GetRenderTargetGroup")
	find_and_print_calls_from(0x00B6B260, "BSRenderedTexture::GetRenderTargetGroup")
	find_refs_to(0x012708EC, "RTTI_NiRenderTargetGroup")
	scan_refs_windows(0x012708EC, "RTTI_NiRenderTargetGroup", 12)
	find_refs_to(0x011F603C, "RTTI_NiDepthStencilBuffer")
	scan_refs_windows(0x011F603C, "RTTI_NiDepthStencilBuffer", 12)
	decompile_at(0x00B65C60, "BSShaderAccumulator::FinishAccumulating_Standard_PreResolveDepth")
	find_and_print_calls_from(0x00B65C60, "BSShaderAccumulator::FinishAccumulating_Standard_PreResolveDepth")
	decompile_at(0x00B63770, "BSShaderAccumulator::RenderBatches")
	decompile_at(0x00B639E0, "BSShaderAccumulator::RenderGeometryGroup")
	scan_callers_to(0x00B639E0, "BSShaderAccumulator::RenderGeometryGroup", 20)
	disasm_window(0x00B6657D, 20, 32, "DepthResolve replacement call A")
	disasm_window(0x00B665AC, 20, 32, "DepthResolve replacement call B")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_rtgroup_depth_surface_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
