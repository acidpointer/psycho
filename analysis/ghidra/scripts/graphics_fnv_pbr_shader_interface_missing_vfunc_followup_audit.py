# @category Analysis
# @description Force-audit missing FNV shader-interface vtable helper targets for native PBR

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x010EF544: "shader-interface vtable",
	0x00E826D0: "shader-interface apply dispatcher",
	0x00E83DB0: "type 0x20000000 helper",
	0x00E84B60: "type 0x10000000 helper",
	0x00E84BA0: "type 0x30000000 helper",
	0x00E84D00: "type 0x40000000 helper target",
	0x00E87220: "type 0x50000000 helper",
	0x00E85C40: "type 0x60000000 helper target",
	0x00E7F430: "shader-interface record register/finalize",
	0x00E7F000: "shader-interface record lookup",
	0x00E83A90: "shader-interface fallback constant lookup",
	0x00E83550: "matrix/vector constant pack helper",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x00E88930: "texture stage state helper",
	0x00E910A0: "sampler state helper",
}

SLOT_TARGETS = [
	(0x78, 0x00E826D0, "apply dispatcher"),
	(0x8C, 0x00E83DB0, "type 0x20000000 helper"),
	(0x90, 0x00E84B60, "type 0x10000000 helper"),
	(0x94, 0x00E84BA0, "type 0x30000000 helper"),
	(0x98, 0x00E84D00, "type 0x40000000 helper target"),
	(0x9C, 0x00E87220, "type 0x50000000 helper"),
	(0xA4, 0x00E85C40, "type 0x60000000 helper target"),
]

FOCUS_TARGETS = [
	(0x00E84D00, "type 0x40000000 helper target"),
	(0x00E85C40, "type 0x60000000 helper target"),
]

SCAN_PATTERNS = [
	"SetTexture",
	"SetRenderState",
	"SetSamplerState",
	"SetVertexShaderConstant",
	"SetPixelShaderConstant",
	"texture",
	"sampler",
	"constant",
	"param_",
	"+ 0x14",
	"+0x14",
	"+ 0x18",
	"+0x18",
	"+ 0x1c",
	"+0x1c",
	"+ 0x20",
	"+0x20",
	"+ 0x24",
	"+0x24",
	"+ 0x30",
	"+0x30",
]

def write(msg):
	output.append(msg)
	print(msg)

def read_u32(addr_int):
	try:
		value = memory.getInt(toAddr(addr_int))
		if value < 0:
			value += 0x100000000
		return value
	except:
		return None

def label_for(addr_int):
	if addr_int is None:
		return "unreadable"
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

def operand_text(inst, index):
	try:
		return inst.getDefaultOperandRepresentation(index)
	except:
		return "?"

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

def ensure_function_at(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is not None:
		return func
	containing = fm.getFunctionContaining(toAddr(addr_int))
	if containing is not None:
		write("  NOTE: 0x%08x is inside existing %s @ 0x%08x" % (addr_int, containing.getName(), containing.getEntryPoint().getOffset()))
		return containing
	write("  creating function at 0x%08x (%s)" % (addr_int, label))
	try:
		return createFunction(toAddr(addr_int), "pbr_missing_vfunc_%08x" % addr_int)
	except Exception as err:
		write("  createFunction failed at 0x%08x: %s" % (addr_int, err))
		return None

def decompile_at(addr_int, label, max_len=22000):
	write("")
	write("=" * 70)
	write("%s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = ensure_function_at(addr_int, label)
	if func is None:
		write("  [function not found]")
		return
	faddr = func.getEntryPoint().getOffset()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, func.getBody().getNumAddresses()))
	if faddr != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	code = decompile_text(addr_int)
	if code is None:
		write("  [decompilation failed]")
		return
	write(code[:max_len])

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
	func = ensure_function_at(addr_int, label)
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

def instruction_before_steps(inst, steps):
	cur = inst
	count = 0
	while count < steps and cur is not None:
		cur = listing.getInstructionBefore(cur.getAddress())
		count += 1
	return cur

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("=" * 70)
	write("Raw disassembly %s around 0x%08x" % (label, center_int))
	write("=" * 70)
	inst = listing.getInstructionContaining(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionAt(toAddr(center_int))
	if inst is None:
		write("  [instruction not found]")
		return
	cur = instruction_before_steps(inst, before_count)
	if cur is None:
		cur = inst
	count = 0
	limit = before_count + after_count + 1
	while cur is not None and count < limit:
		addr_int = cur.getAddress().getOffset()
		marker = "=> " if addr_int == inst.getAddress().getOffset() else "   "
		write("%s0x%08x: %-58s %s" % (marker, addr_int, cur.toString(), label_for(addr_int)))
		refs = cur.getReferencesFrom()
		for ref in refs:
			write("      ref %s -> 0x%08x %s" % (ref.getReferenceType(), ref.getToAddress().getOffset(), label_for(ref.getToAddress().getOffset())))
		cur = listing.getInstructionAfter(cur.getAddress())
		count += 1

def scan_patterns(addr_int, label):
	write("")
	write("=" * 70)
	write("MATCHED DECOMPILE LINES: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	code = decompile_text(addr_int)
	if code is None:
		write("  [decompilation failed]")
		return
	lines = code.splitlines()
	line_no = 0
	for line in lines:
		line_no += 1
		lower = line.lower()
		for pattern in SCAN_PATTERNS:
			if pattern.lower() in lower:
				write("  L%-4d %s" % (line_no, line))
				break

def print_vtable_slots():
	write("")
	write("=" * 70)
	write("SHADER-INTERFACE VTABLE SLOT TARGETS")
	write("=" * 70)
	for item in SLOT_TARGETS:
		target = read_u32(0x010EF544 + item[0])
		status = "OK" if target == item[1] else "MISMATCH"
		write("  +0x%03x expected 0x%08x got 0x%08x %-8s %s" % (item[0], item[1], target if target is not None else 0, status, item[2]))

def print_focus_targets():
	for item in FOCUS_TARGETS:
		find_refs_to(item[0], item[1])
		disasm_window(item[0], 16, 120, item[1])
		decompile_at(item[0], item[1], 24000)
		find_and_print_calls_from(item[0], item[1])
		scan_patterns(item[0], item[1])

def main():
	write("FNV PBR SHADER-INTERFACE MISSING VFUNC FOLLOW-UP AUDIT")
	write("")
	write("Purpose:")
	write("1. Verify shader-interface vtable slots after the interface-record audit.")
	write("2. Force-create/decompile raw helper targets where Ghidra had no function.")
	write("3. Determine whether type 0x40000000 and 0x60000000 helpers bind textures, constants, or render state.")
	print_vtable_slots()
	print_focus_targets()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_shader_interface_missing_vfunc_followup_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
