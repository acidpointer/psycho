# @category Analysis
# @description Audit the unmeasured time inside NiDX9SourceTextureData texture loading

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def label_for(addr_int):
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
		write("  0x%08x: %-44s%s" % (addr_int, inst.toString(), marker))
		inst = inst.getNext()
		idx += 1

def print_callsite(addr_int, label):
	write("")
	write("-" * 70)
	write("Callsite: %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(addr_int))
	if inst is None:
		write("  [instruction not found]")
		return
	write("  Instruction: %s" % inst.toString())
	refs = inst.getReferencesFrom()
	for ref in refs:
		if ref.getReferenceType().isCall():
			target = ref.getToAddress().getOffset()
			write("  CALL target: 0x%08x %s" % (target, label_for(target)))
	disasm_window(addr_int, 8, 16, label)

def print_callsite_table():
	items = [
		(0x00e68ade, "copy texture path to stack buffer"),
		(0x00e68aeb, "path normalize helper"),
		(0x00e68aff, "extension extraction helper"),
		(0x00e68b11, "extension check .bmp"),
		(0x00e68b2a, "extension check .tga"),
		(0x00e68b43, "extension check .dds"),
		(0x00e68b62, "BSFile open/resolve"),
		(0x00e68ba9, "temporary file buffer allocate and zero"),
		(0x00e68bb7, "read file into temporary buffer"),
		(0x00e68bcd, "D3DX image info from memory"),
		(0x00e68c13, "free buffer on image-info failure"),
		(0x00e68d64, "allocate trimmed DDS copy"),
		(0x00e68d72, "copy DDS header"),
		(0x00e68da8, "copy trimmed DDS payload"),
		(0x00e68db6, "free original DDS buffer after trim"),
		(0x00e68dcd, "D3DX create 2D texture from memory"),
		(0x00e68df3, "D3DX create cube texture from memory"),
		(0x00e68e18, "D3DX create volume texture from memory"),
		(0x00e68e2b, "free final temporary buffer")
	]
	write("")
	write("=" * 70)
	write("TEXTURE LOAD INTERNAL CALLSITES")
	write("=" * 70)
	for item in items:
		print_callsite(item[0], item[1])

def print_branch_windows():
	windows = [
		(0x00e68b80, "file object/file size/temporary buffer/read path"),
		(0x00e68c57, "2D DDS branch and mip-trim decision"),
		(0x00e68cf0, "mip-trim size loop"),
		(0x00e68d59, "trim-copy allocation/copy/free branch"),
		(0x00e68dc1, "D3DX texture creation branch")
	]
	write("")
	write("=" * 70)
	write("CRITICAL BRANCH WINDOWS")
	write("=" * 70)
	for item in windows:
		disasm_window(item[0], 10, 36, item[1])

def print_refs():
	refs = [
		(0x00e68a80, "NiDX9SourceTextureData texture load"),
		(0x00aa1070, "zeroing temporary allocation helper"),
		(0x00aa10f0, "temporary allocation free helper"),
		(0x00aa3e40, "GameHeap allocate"),
		(0x00aa4060, "GameHeap free"),
		(0x00462d80, "BSFile ReadBuffer"),
		(0x00ee6e22, "D3DXGetImageInfoFromFileInMemory import thunk"),
		(0x00ee6e1c, "D3DXCreateTextureFromFileInMemory import thunk"),
		(0x00ee6e16, "D3DXCreateCubeTextureFromFileInMemory import thunk"),
		(0x00ee6e10, "D3DXCreateVolumeTextureFromFileInMemory import thunk")
	]
	for item in refs:
		find_refs_to(item[0], item[1])

def main():
	write("=" * 70)
	write("TEXTURE LOAD GAP AUDIT")
	write("=" * 70)
	write("Runtime logs showed texture_load around 8.7s, while open/read/image_info were near zero.")
	write("This script maps every internal callsite inside 0x00E68A80 so the missing stage is concrete.")
	decompile_at(0x00e68a80, "NiDX9SourceTextureData texture load")
	find_and_print_calls_from(0x00e68a80, "NiDX9SourceTextureData texture load")
	print_callsite_table()
	print_branch_windows()
	print_refs()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/texture_load_gap_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
