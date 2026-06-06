# @category Analysis
# @description Audit FNV NiTexture to D3D texture binding chain for psycho-graphics

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x004BC320: "BSRenderedTexture::GetTexture(index)",
	0x00BA37F0: "ImageSpaceTexture temp set source NiTexture",
	0x00BA37A0: "ImageSpaceTexture temp set rendered texture",
	0x00BA3CB0: "ImageSpaceShader bind texture input",
	0x00BA3780: "ImageSpaceTexture::GetTexture",
	0x00B8C980: "ImageSpaceManager::RenderEffect effect/source NiTexture",
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

def scan_for_offsets(func_addr, label):
	func = fm.getFunctionAt(toAddr(func_addr))
	if func is None:
		func = fm.getFunctionContaining(toAddr(func_addr))
	if func is None:
		return
	write("")
	write("-" * 70)
	write("Offset-use scan in %s" % label)
	write("-" * 70)
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		if "+ 0x24" in text or "+0x24" in text or "+ 0x64" in text or "+0x64" in text or "[ECX + 0x24]" in text or "[EAX + 0x64]" in text:
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), text))

def analyze_targets():
	targets = [
		(0x004BC320, "BSRenderedTexture::GetTexture(index)"),
		(0x00BA3780, "ImageSpaceTexture::GetTexture"),
		(0x00BA37F0, "ImageSpaceTexture temp set source NiTexture"),
		(0x00BA37A0, "ImageSpaceTexture temp set rendered texture"),
		(0x00BA3CB0, "ImageSpaceShader bind texture input"),
		(0x00B8C980, "ImageSpaceManager::RenderEffect effect/source NiTexture"),
	]
	for item in targets:
		decompile_at(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])
		scan_for_offsets(item[0], item[1])

def analyze_disassembly():
	disasm_window(0x004BC320, 8, 40, "BSRenderedTexture::GetTexture(index)")
	disasm_window(0x00BA3CB0, 12, 90, "ImageSpaceShader bind texture input")
	disasm_window(0x00BA37F0, 8, 40, "ImageSpaceTexture temp set source NiTexture")
	disasm_window(0x00BA37A0, 8, 40, "ImageSpaceTexture temp set rendered texture")

def main():
	write("FNV NITEXTURE D3D CHAIN AUDIT")
	write("")
	write("Goal: prove or disprove the chain used by psycho-graphics:")
	write("  ImageSpaceManager::GetDepthTexture -> NiTexture*")
	write("  NiTexture + 0x24 -> NiTexture::RendererData*")
	write("  NiDX9TextureData + 0x64 -> IDirect3DBaseTexture9*")
	analyze_targets()
	find_refs_to(0x00BA3CB0, "ImageSpaceShader bind texture input")
	analyze_disassembly()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_nitexture_d3d_chain_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
