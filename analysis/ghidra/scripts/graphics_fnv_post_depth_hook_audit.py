# @category Analysis
# @description Audit FNV post-depth render hook sites for Psycho Graphics

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00B65C60: "BSShaderAccumulator::FinishAccumulating_Standard_PreResolveDepth",
	0x00B6657D: "DepthResolve post-depth replacement call A",
	0x00B665AC: "DepthResolve post-depth replacement call B",
	0x00B64057: "DepthResolve skip depth-group accumulation patch",
	0x00B65C43: "DepthResolve skip alpha blend rendering patch A",
	0x00B65C4C: "DepthResolve skip alpha blend rendering patch B",
	0x00B54090: "ImageSpaceManager::GetDepthTexture",
	0x00B6B790: "BSRenderedTexture::StopOffscreen",
	0x00B6B8D0: "BSRenderedTexture::StartOffscreen",
	0x00B97550: "ImageSpaceManager::RenderEffect id/source rendered texture",
	0x00B975F0: "ImageSpaceManager::RenderEffect id/source NiTexture",
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

def print_function_identity(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	write("")
	write("-" * 70)
	write("Function identity for %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	entry = func.getEntryPoint().getOffset()
	write("  Function: %s" % func.getName())
	write("  Entry: 0x%08x" % entry)
	write("  Offset from entry: 0x%x" % (addr_int - entry))
	write("  Size: %d bytes" % func.getBody().getNumAddresses())
	write("  Body: %s" % func.getBody())

def print_instruction_detail(addr_int, label):
	write("")
	write("-" * 70)
	write("Instruction detail: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(addr_int))
	if inst is None:
		inst = listing.getInstructionContaining(toAddr(addr_int))
	if inst is None:
		write("  [instruction not found]")
		return
	ia = inst.getAddress().getOffset()
	write("  Address: 0x%08x" % ia)
	write("  Text: %s" % inst.toString())
	write("  Length: %d" % inst.getLength())
	write("  Bytes: %s" % read_bytes(ia, inst.getLength()))
	refs = inst.getReferencesFrom()
	for ref in refs:
		target = ref.getToAddress().getOffset()
		write("  Ref: %s -> 0x%08x %s" % (ref.getReferenceType(), target, label_for(target)))

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
		write("  0x%08x: %-48s%s%s" % (addr_int, inst.toString(), marker, extra))
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
		disasm_window(from_addr.getOffset(), 10, 24, "caller of %s" % label)
		count += 1
		if count >= max_callers:
			write("  ... caller scan truncated")
			break
	write("Total callers printed: %d" % count)

def analyze_hook_sites():
	sites = [
		(0x00B64057, "DepthResolve skip depth-group accumulation patch"),
		(0x00B65C43, "DepthResolve skip alpha blend rendering patch A"),
		(0x00B65C4C, "DepthResolve skip alpha blend rendering patch B"),
		(0x00B6657D, "DepthResolve post-depth replacement call A"),
		(0x00B665AC, "DepthResolve post-depth replacement call B"),
	]
	for item in sites:
		print_function_identity(item[0], item[1])
		print_instruction_detail(item[0], item[1])
		disasm_window(item[0], 24, 40, item[1])

def analyze_globals():
	globals_to_check = [
		(0x011F917C, "camera pointer"),
		(0x011F91A8, "texture manager pointer"),
		(0x011F91AC, "image-space manager singleton"),
		(0x011F9438, "current render target"),
		(0x011F943C, "water refraction target"),
		(0x011F9508, "renderer pointer"),
	]
	for item in globals_to_check:
		find_refs_to(item[0], item[1])

def analyze_related_functions():
	targets = [
		(0x00B65C60, "FinishAccumulating_Standard_PreResolveDepth owner"),
		(0x00B97550, "RenderEffect rendered texture"),
		(0x00B975F0, "RenderEffect NiTexture"),
		(0x00B54090, "GetDepthTexture"),
	]
	for item in targets:
		decompile_at(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])
		scan_callers_to(item[0], item[1], 10)

def main():
	write("=" * 70)
	write("FNV POST-DEPTH HOOK AUDIT")
	write("=" * 70)
	write("Goal: verify exact FNV render hook surface before Psycho Graphics patches it.")
	analyze_hook_sites()
	analyze_related_functions()
	analyze_globals()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_post_depth_hook_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))

main()
decomp.dispose()
