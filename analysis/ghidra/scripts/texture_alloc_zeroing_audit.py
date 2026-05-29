# @category Analysis
# @description Audit texture temporary allocation and zeroing helpers used during startup texture load

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

def print_data_refs(addr_int, label):
	write("")
	write("-" * 70)
	write("Data/refs for %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	try:
		value = getInt(toAddr(addr_int)) & 0xffffffff
		write("  dword value: 0x%08x -> %s" % (value, label_for(value)))
	except:
		write("  dword value: <read failed>")
	find_refs_to(addr_int, label)

def print_callers_with_windows(addr_int, label, limit):
	write("")
	write("=" * 70)
	write("CALLERS OF %s @ 0x%08x" % (label, addr_int))
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
		disasm_window(from_addr, 8, 16, "caller of %s" % label)
		count += 1
		if count >= limit:
			write("  ... caller scan truncated")
			break
	write("Total callers printed: %d" % count)

def print_texture_patchpoints():
	items = [
		(0x00e68ba9, "texture file buffer allocate/zero callsite"),
		(0x00e8c051, "vertex-buffer lock allocate/zero callsite"),
		(0x00401000, "Stewie replacement target for texture zeroing"),
		(0x00401020, "GameHeap singleton getter"),
		(0x00401030, "operator delete / GameHeap free wrapper")
	]
	write("")
	write("=" * 70)
	write("PATCHPOINTS AND REPLACEMENT STUBS")
	write("=" * 70)
	for item in items:
		disasm_window(item[0], 8, 18, item[1])
		decompile_at(item[0], item[1], 6000)

def print_helper_details():
	items = [
		(0x00aa1070, "zeroing temporary allocation helper"),
		(0x00aa10f0, "temporary free helper"),
		(0x00aa10b0, "alternate temporary helper with source pointer"),
		(0x00aa1130, "alternate temporary allocation helper"),
		(0x00aa2020, "initializes DAT_011F6080 temporary allocator object"),
		(0x00aa3e40, "GameHeap allocate"),
		(0x00aa4060, "GameHeap free")
	]
	write("")
	write("=" * 70)
	write("ALLOCATOR HELPER DECOMPILE")
	write("=" * 70)
	for item in items:
		decompile_at(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])

def print_refs():
	items = [
		(0x011f6080, "temporary allocator global DAT_011F6080"),
		(0x011f6238, "default GameHeap object DAT_011F6238"),
		(0x00aa1070, "zeroing temporary allocation helper"),
		(0x00aa10f0, "temporary free helper"),
		(0x00aa3e40, "GameHeap allocate"),
		(0x00aa4060, "GameHeap free"),
		(0x00401000, "Stewie replacement target")
	]
	for item in items:
		print_data_refs(item[0], item[1])

def main():
	write("=" * 70)
	write("TEXTURE ALLOCATION/ZEROING AUDIT")
	write("=" * 70)
	write("Goal: prove whether the missing texture-load time is temp allocation/zeroing.")
	write("Stewie source says it skips texture zeroing at 0x00E68BA9; this checks the engine side.")
	print_texture_patchpoints()
	print_helper_details()
	print_refs()
	print_callers_with_windows(0x00aa1070, "zeroing temporary allocation helper", 40)
	print_callers_with_windows(0x00aa10f0, "temporary free helper", 40)
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/texture_alloc_zeroing_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
