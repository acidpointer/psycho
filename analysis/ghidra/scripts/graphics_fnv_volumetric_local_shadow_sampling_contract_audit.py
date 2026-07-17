# @category Analysis
# @description Audit FNV SimpleShadow shader selection, texture sampling, and projection-matrix pairing

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

OUTPATH = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_volumetric_local_shadow_sampling_contract_audit.txt"
DECOMPILE_TIMEOUT_SECONDS = 15
MAX_DECOMPILE_FUNCTION_BYTES = 5000
MAX_DECOMPILE_TEXT = 12000

SHADER_STRINGS = [
	(0x010AE968, "lighting\\2x\\v\\SimpleShadow.v.hlsl"),
	(0x010AEE30, "lighting\\2x\\p\\SimpleShadow.p.hlsl"),
	(0x010AEBA0, "PROJ_SHADOW"),
]

SHADER_ARRAYS = [
	(0x011FDE5C, "PPLighting vertex group C base"),
	(0x011FDB08, "PPLighting pixel group B base"),
]

SIMPLE_SHADOW_SLOTS = [
	(0x011FDFC0, "vertex group C index 89"),
	(0x011FDFC4, "vertex group C index 90"),
	(0x011FDFC8, "vertex group C index 91"),
	(0x011FDD68, "pixel group B index 152"),
	(0x011FDD6C, "pixel group B index 153"),
	(0x011FDD70, "pixel group B index 154"),
	(0x011FDD74, "pixel group B index 155"),
	(0x011FDD78, "pixel group B index 156"),
	(0x011FDD7C, "pixel group B index 157"),
]

FUNCTIONS = [
	(0x00C17510, "candidate local-shadow render path"),
	(0x00B7DFE0, "candidate shader apply"),
	(0x00B7DAB0, "candidate texture-stage bind"),
	(0x00B7DED0, "candidate nearby shader apply"),
	(0x00B7DDE0, "candidate nearby shader state"),
	(0x00B7B930, "candidate pass dispatcher"),
	(0x00B80600, "renderer texture bind helper"),
	(0x00E88A20, "D3D SetTexture wrapper"),
	(0x00B9F780, "per-light shadow render and filter"),
	(0x00B5AEE0, "per-light shadow texture publication"),
]

DISASM_WINDOWS = [
	(0x00BEBEE9, 28, 48, "PPLighting setup first vertex-array path"),
	(0x00BEBF23, 28, 48, "PPLighting setup first pixel-array path"),
	(0x00BEC1A5, 30, 55, "PPLighting setup vertex-array path B"),
	(0x00BECBB2, 30, 55, "PPLighting setup vertex-array path C"),
	(0x00BECE6A, 30, 55, "PPLighting setup vertex-array path D"),
	(0x00BED129, 30, 55, "PPLighting setup late pixel-array path"),
	(0x00C17510, 20, 80, "candidate local-shadow render path"),
	(0x00B7DFE0, 25, 80, "candidate shader apply"),
	(0x00B7DAB0, 25, 80, "candidate texture-stage bind"),
	(0x00B7DED0, 25, 70, "candidate nearby shader apply"),
	(0x00B7DDE0, 25, 70, "candidate nearby shader state"),
	(0x00B7B930, 25, 90, "candidate pass dispatcher"),
	(0x00B80600, 20, 70, "renderer texture bind helper"),
	(0x00E88A20, 16, 55, "D3D SetTexture wrapper"),
]


def write(msg):
	output.append(msg)
	print(msg)


def checkpoint_output():
	fout = open(OUTPATH, "w")
	try:
		fout.write("\n".join(output))
	finally:
		fout.close()


def decompile_at(addr_int, label, max_len=MAX_DECOMPILE_TEXT):
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
	fsize = func.getBody().getNumAddresses()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, fsize))
	if faddr != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	if fsize > MAX_DECOMPILE_FUNCTION_BYTES:
		write("  [skipped: function exceeds %d-byte bound]" % MAX_DECOMPILE_FUNCTION_BYTES)
		return
	result = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed or timed out]")


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
		inst = listing.getInstructionContaining(ref.getFromAddress())
		inst_text = inst.toString() if inst else "<no instruction>"
		write("  %s @ 0x%08x (in %s) %s" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, inst_text))
		count += 1
		if count > 40:
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
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
	write("  Total: %d calls" % count)


def disasm_window(addr_int, before_count, after_count, label):
	write("")
	write("=" * 70)
	write("DISASM: %s around 0x%08x" % (label, addr_int))
	write("=" * 70)
	inst = listing.getInstructionContaining(toAddr(addr_int))
	if inst is None:
		write("  [instruction not found]")
		return
	start = inst
	count = 0
	while count < before_count:
		previous = start.getPrevious()
		if previous is None:
			break
		start = previous
		count += 1
	current = start
	remaining = before_count + after_count + 1
	while current is not None and remaining > 0:
		marker = "=>" if current.getAddress() == inst.getAddress() else "  "
		write("%s 0x%08x: %s" % (marker, current.getAddress().getOffset(), current.toString()))
		refs = current.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall() or ref.getReferenceType().isData() or ref.getReferenceType().isJump():
				write("      ref %-18s -> 0x%08x" % (ref.getReferenceType(), ref.getToAddress().getOffset()))
		current = current.getNext()
		remaining -= 1


def reference_windows(addr_int, label, before_count, after_count):
	write("")
	write("=" * 70)
	write("REFERENCE WINDOWS: 0x%08x (%s)" % (addr_int, label))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		write("")
		write("Reference %s from 0x%08x" % (ref.getReferenceType(), ref.getFromAddress().getOffset()))
		disasm_window(ref.getFromAddress().getOffset(), before_count, after_count, label)
		count += 1
		if count >= 40:
			write("  ... (truncated)")
			break
	if count == 0:
		write("  [no references]")


def print_starting_contract():
	write("FNV VOLUMETRIC LOCAL-SHADOW SAMPLING CONTRACT AUDIT")
	write("")
	write("Proven starting point:")
	write("1. Per-light shadow object +0x10C owns a pooled type-0x2B 1024x1024 rendered texture.")
	write("2. B9F780 renders and filters that texture; BA3390 submits the queued shadow render.")
	write("3. Selector 9 uses base_old/copy and does not prove the normal SimpleShadow consumer path.")
	write("")
	write("Closure questions:")
	write("1. Which normal render path selects SimpleShadow vertex indices 89-91 and pixel indices 152-157?")
	write("2. Which texture stage receives the per-light type-0x2B texture, with what sampler/comparison state?")
	write("3. Which matrix/constant path supplies PROJ_SHADOW, and what object owns its lifetime?")
	write("")
	write("Descriptor identities:")
	write("- Vertex group C: base 0x011FDE5C, count 0x67, SimpleShadow indices 89-91.")
	write("- Pixel group B: base 0x011FDB08, count 0xA0, SimpleShadow indices 152-157.")
	write("- These identities do not by themselves prove runtime selection or resource binding.")


def audit_refs(items, include_windows):
	idx = 0
	while idx < len(items):
		item = items[idx]
		find_refs_to(item[0], item[1])
		if include_windows:
			reference_windows(item[0], item[1], 12, 24)
		checkpoint_output()
		if monitor.isCancelled():
			return
		idx += 1


def audit_disassembly():
	idx = 0
	while idx < len(DISASM_WINDOWS):
		item = DISASM_WINDOWS[idx]
		disasm_window(item[0], item[1], item[2], item[3])
		checkpoint_output()
		if monitor.isCancelled():
			return
		idx += 1


def audit_functions():
	idx = 0
	while idx < len(FUNCTIONS):
		item = FUNCTIONS[idx]
		decompile_at(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])
		checkpoint_output()
		if monitor.isCancelled():
			return
		idx += 1


def main():
	try:
		print_starting_contract()
		checkpoint_output()
		audit_refs(SHADER_STRINGS, True)
		if monitor.isCancelled():
			return
		audit_refs(SHADER_ARRAYS, True)
		if monitor.isCancelled():
			return
		audit_refs(SIMPLE_SHADOW_SLOTS, True)
		if monitor.isCancelled():
			return
		audit_disassembly()
		if monitor.isCancelled():
			return
		audit_functions()
	finally:
		checkpoint_output()
		decomp.dispose()


main()
