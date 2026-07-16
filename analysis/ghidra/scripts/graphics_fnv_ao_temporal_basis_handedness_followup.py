# @category Analysis
# @description Prove FNV camera basis order and inverse transform math for temporal AO reprojection

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0045BB80: "NiAVObjectWorldTranslationGetter",
	0x0045BBA0: "CameraWorldDirectionGetterCandidate",
	0x0045BBE0: "CameraFrustumOrViewportGetterCandidate",
	0x004A0D10: "CameraFrustumOrViewportGetterCandidate",
	0x004B4500: "NiMatrix3MultiplyVector",
	0x004B4880: "NiTransformInverse",
	0x004E9BB0: "NiRenderer::SetCameraData",
	0x004E9C10: "CameraBasisGetterCandidateA",
	0x004E9C50: "CameraBasisGetterCandidateB",
	0x004E9C90: "NiRendererDoSetCameraDataDispatch",
	0x0062C250: "NiTransformApplyTransform",
}

FUNCTION_TARGETS = [
	0x0045BB80,
	0x0045BBA0,
	0x0045BBE0,
	0x004A0D10,
	0x004B4500,
	0x004B4880,
	0x004E9BB0,
	0x004E9C10,
	0x004E9C50,
	0x004E9C90,
	0x0062C250,
]

DISASM_TARGETS = [
	0x0045BB80,
	0x0045BBA0,
	0x0045BBE0,
	0x004A0D10,
	0x004B4500,
	0x004B4880,
	0x004E9BB0,
	0x004E9C10,
	0x004E9C50,
	0x004E9C90,
	0x0062C250,
]

MATCH_PATTERNS = [
	"0x68",
	"0x6c",
	"0x70",
	"0x74",
	"0x78",
	"0x7c",
	"0x80",
	"0x84",
	"0x88",
	"0x8c",
	"0x90",
	"0x94",
	"0x98",
	"0xdc",
	"0xe0",
	"0xe4",
	"0xe8",
	"0xec",
	"0xf0",
	"0xf4",
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

def decompile_at(addr_int, label, max_len=32000):
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
		write(result.getDecompiledFunction().getC()[:max_len])
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

def read_bytes(addr_int, count):
	values = []
	idx = 0
	while idx < count:
		value = memory.getByte(toAddr(addr_int + idx)) & 0xff
		values.append("%02X" % value)
		idx += 1
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

def decompile_text(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		return None
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		return result.getDecompiledFunction().getC()
	return None

def line_matches(line):
	lower = line.lower()
	idx = 0
	while idx < len(MATCH_PATTERNS):
		if lower.find(MATCH_PATTERNS[idx]) >= 0:
			return True
		idx += 1
	return False

def print_matching_decompile_lines(addr_int, label):
	write("")
	write("=" * 70)
	write("BASIS OPERANDS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	code = decompile_text(addr_int)
	if code is None:
		write("  [decompilation failed]")
		return
	lines = code.split("\n")
	idx = 0
	count = 0
	while idx < len(lines):
		line = lines[idx]
		if line_matches(line):
			write("  L%04d: %s" % (idx + 1, line))
			count += 1
		idx += 1
	write("  Total matched lines: %d" % count)

def audit_targets():
	idx = 0
	while idx < len(FUNCTION_TARGETS):
		addr = FUNCTION_TARGETS[idx]
		find_refs_to(addr, label_for(addr))
		decompile_at(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))
		print_matching_decompile_lines(addr, label_for(addr))
		idx += 1

def audit_disassembly():
	idx = 0
	while idx < len(DISASM_TARGETS):
		addr = DISASM_TARGETS[idx]
		write("")
		write("Bytes @ 0x%08x (%s): %s" % (addr, label_for(addr), read_bytes(addr, 16)))
		disasm_window(addr, 12, 72, label_for(addr))
		idx += 1

def print_header():
	write("FNV AO TEMPORAL BASIS AND HANDEDNESS FOLLOW-UP")
	write("")
	write("Questions:")
	write("1. Which camera world-rotation column is passed as direction, up, and right?")
	write("2. Does NiMatrix3 multiply a column vector using row dot products?")
	write("3. Does NiTransform inverse transpose the rotation and divide translation by scale?")
	write("4. What exact formula converts current AO view coordinates to previous camera view coordinates?")
	write("")
	write("Do not implement temporal AO until direction/up/right order and signs are explicit in this output.")

def main():
	print_header()
	audit_targets()
	audit_disassembly()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_ao_temporal_basis_handedness_followup.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
