# @category Analysis
# @description Audit FNV NiTexture renderer data and NiDX9TextureData D3D texture field

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

RTTI_NITEXTURE = 0x011A95A4
RTTI_NIDX9_TEXTURE_DATA = 0x011BE81C
RTTI_NIDX9_PERSISTENT_SRC_TEXTURE_RENDERER_DATA = 0x011C0588
LIKELY_NIDX9_SOURCE_TEXTURE_DATA_VTABLE = 0x010ED37C

KNOWN = {
	0x00559450: "NiPointer/texture pointer helper used by BSRenderedTexture::GetTexture",
	0x00B651E0: "depth/render texture creation path",
	0x00B654AC: "stores depth D3D texture candidate at +0x64",
	0x00B54090: "ImageSpaceManager::GetDepthTexture thunk",
	0x00BA3780: "ImageSpaceTexture::GetTexture",
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

def print_data_words(addr_int, count, label):
	write("")
	write("-" * 70)
	write("Data words at 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	for idx in range(count):
		slot = addr_int + idx * 4
		value = None
		try:
			value = memory.getInt(toAddr(slot)) & 0xffffffff
		except:
			value = None
		if value is None:
			write("  [%02d] +0x%02x: [read failed]" % (idx, idx * 4))
		else:
			write("  [%02d] +0x%02x: 0x%08x -> %s" % (idx, idx * 4, value, label_for(value)))

def decompile_data_words(addr_int, count, label):
	write("")
	write("-" * 70)
	write("Decompile function-looking data words at 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	seen = {}
	for idx in range(count):
		slot = addr_int + idx * 4
		try:
			value = memory.getInt(toAddr(slot)) & 0xffffffff
		except:
			value = 0
		if value == 0:
			continue
		if seen.get(value):
			continue
		seen[value] = True
		func = fm.getFunctionAt(toAddr(value))
		if func is not None:
			decompile_at(value, "%s slot %02d" % (label, idx), 4000)

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

def scan_function_for_texture_offsets(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		return
	write("")
	write("-" * 70)
	write("Texture offset scan in %s" % label)
	write("-" * 70)
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		if "0x24" in text or "0x60" in text or "0x64" in text or "0x68" in text:
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), text))

def main():
	write("FNV NIDX9 TEXTURE DATA AUDIT")
	write("")
	write("Goal: prove renderer-data offset use and D3D texture field for psycho-graphics depth binding.")
	find_refs_to(RTTI_NITEXTURE, "RTTI_NiTexture")
	find_refs_to(RTTI_NIDX9_TEXTURE_DATA, "RTTI_NiDX9TextureData")
	find_refs_to(RTTI_NIDX9_PERSISTENT_SRC_TEXTURE_RENDERER_DATA, "RTTI_NiDX9PersistentSrcTextureRendererData")
	print_data_words(LIKELY_NIDX9_SOURCE_TEXTURE_DATA_VTABLE, 44, "known NiDX9SourceTextureData vtable from renderer audit")
	decompile_data_words(LIKELY_NIDX9_SOURCE_TEXTURE_DATA_VTABLE, 44, "known NiDX9SourceTextureData vtable")
	decompile_at(0x00559450, "NiPointer/texture pointer helper used by BSRenderedTexture::GetTexture")
	decompile_at(0x00B651E0, "depth/render texture creation path")
	find_and_print_calls_from(0x00B651E0, "depth/render texture creation path")
	scan_function_for_texture_offsets(0x00B651E0, "depth/render texture creation path")
	disasm_window(0x00B654AC, 28, 38, "stores depth D3D texture candidate")
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_nidx9_texture_data_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
