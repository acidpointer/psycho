# @category Analysis
# @description Prove FNV object EnvMap shader table pairing, owner fields, and runtime resource apply ABI

from ghidra.app.decompiler import DecompInterface

if currentProgram is None:
	raise RuntimeError("Open FalloutNV.exe in CodeBrowser and run this file from Script Manager; do not paste it into the Python console")

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

FUNCTION_TARGETS = [
	(0x00B66C40, "BSShaderPPLightingProperty GetEnvMapFade"),
	(0x00BB96F0, "PPLighting EnvMap vertex shader constructor"),
	(0x00BBA5D0, "PPLighting EnvMap pixel shader constructor"),
	(0x00BFBF60, "sole object EnvMap table-row consumer and owner initializer"),
	(0x00E88A20, "NiDX9RenderState SetTexture"),
]

ROW_READ_SITES = [
	(0x00BFC077, "VS row 50 paired read A"),
	(0x00BFC0B1, "PS row 57 paired read A"),
	(0x00BFC2AE, "VS row 51 paired read"),
	(0x00BFC2E7, "PS row 57 paired read B"),
	(0x00BFC4E4, "VS row 50 paired read B"),
	(0x00BFC51D, "PS row 58 paired read"),
	(0x00BFC6C3, "VS row 52 paired read"),
	(0x00BFC6FC, "PS row 59 paired read"),
]

REFERENCE_TARGETS = [
	(0x00BFBF60, "EnvMap table owner initializer"),
	(0x00E88A20, "NiDX9RenderState SetTexture"),
	(0x011FDF24, "PPLighting vertex group C row 50"),
	(0x011FDF28, "PPLighting vertex group C row 51"),
	(0x011FDF2C, "PPLighting vertex group C row 52"),
	(0x011FDBEC, "PPLighting pixel group B row 57"),
	(0x011FDBF0, "PPLighting pixel group B row 58"),
	(0x011FDBF4, "PPLighting pixel group B row 59"),
	(0x010AEAE0, "lighting 2x vertex EnvMap source string"),
	(0x010AF054, "lighting 2x pixel EnvMap source string"),
	(0x010AEAD8, "ENVMAP define string"),
	(0x010AF04C, "WINDOW define string"),
	(0x010AEAD4, "EYE define string"),
]

MATCH_PATTERNS = [
	"011fdf24",
	"011fdf28",
	"011fdf2c",
	"011fdbec",
	"011fdbf0",
	"011fdbf4",
	"010aeae0",
	"010af054",
	"010aead8",
	"010af04c",
	"010aead4",
	"00e88a20",
	"0xbc",
	"0xc0",
	"0x78",
	"envmap",
	"texture",
	"sampler",
	"window",
	"eye",
]

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=8000):
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
	inst_iter = currentProgram.getListing().getInstructions(body, True)
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
	index = 0
	while index < len(MATCH_PATTERNS):
		if lower.find(MATCH_PATTERNS[index]) >= 0:
			return True
		index += 1
	return False

def print_matching_lines(addr_int, label):
	write("")
	write("MATCHED CONTRACT LINES: %s @ 0x%08x" % (label, addr_int))
	code = decompile_text(addr_int)
	if code is None:
		write("  [decompilation failed]")
		return
	lines = code.splitlines()
	index = 0
	count = 0
	while index < len(lines):
		if line_matches(lines[index]):
			write("  L%04d: %s" % (index + 1, lines[index]))
			count += 1
		index += 1
	write("  Total matched lines: %d" % count)

def instruction_before_steps(inst, steps):
	current = inst
	index = 0
	while current is not None and index < steps:
		previous = listing.getInstructionBefore(current.getAddress())
		if previous is None:
			break
		current = previous
		index += 1
	return current

def print_instruction_references(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		write("      ref %-18s -> 0x%08x" % (str(ref.getReferenceType()), ref.getToAddress().getOffset()))

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("=" * 70)
	write("DISASM: %s around 0x%08x" % (label, center_int))
	write("=" * 70)
	inst = listing.getInstructionContaining(toAddr(center_int))
	if inst is None:
		write("  [instruction not found]")
		return
	current = instruction_before_steps(inst, before_count)
	limit = before_count + after_count + 1
	count = 0
	while current is not None and count < limit:
		marker = "=> " if current.getAddress().getOffset() == inst.getAddress().getOffset() else "   "
		write("%s0x%08x: %s" % (marker, current.getAddress().getOffset(), current.toString()))
		print_instruction_references(current)
		current = listing.getInstructionAfter(current.getAddress())
		count += 1

def audit_functions():
	index = 0
	while index < len(FUNCTION_TARGETS):
		item = FUNCTION_TARGETS[index]
		decompile_at(item[0], item[1], 40000)
		find_and_print_calls_from(item[0], item[1])
		print_matching_lines(item[0], item[1])
		index += 1

def audit_row_reads():
	index = 0
	while index < len(ROW_READ_SITES):
		item = ROW_READ_SITES[index]
		disasm_window(item[0], 28, 36, item[1])
		index += 1

def audit_references():
	index = 0
	while index < len(REFERENCE_TARGETS):
		item = REFERENCE_TARGETS[index]
		find_refs_to(item[0], item[1])
		index += 1

def main():
	write("FNV PBR OBJECT ENVMAP TABLE/APPLY FOLLOW-UP")
	write("")
	write("Goal: distinguish shader-table rows from pass-entry keys and prove the runtime EnvMap ABI.")
	write("The output must identify exact VS/PS pairing, owner fields, sampler stages, constants, and render state.")
	audit_functions()
	audit_row_reads()
	audit_references()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_object_envmap_table_apply_followup.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
