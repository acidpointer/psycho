# @category Analysis
# @description Close FNV PPLighting BDAF10 caller parameter provenance for native PBR

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00A59D30: "NiAVObject property lookup by type",
	0x00B4F5C0: "renderer singleton getter",
	0x00B70600: "active-object iterator first",
	0x00B70700: "active-object iterator next",
	0x00BA9EE0: "PPLighting pass-entry append/reuse helper",
	0x00BDAF10: "PPLighting diffuse/glow material predicate helper",
	0x00BDB4A0: "PPLighting setup variant before BDF790",
	0x00BDF790: "PPLighting selector/pass-entry driver",
	0x00E7EA00: "final pass-entry resource resolver and SetTexture caller",
	0x00E88A20: "NiDX9RenderState::SetTexture",
}

BDAF10_CALLSITE = 0x00BDBAA7
BDB4A0 = 0x00BDB4A0
BDAF10 = 0x00BDAF10
BA9EE0 = 0x00BA9EE0

BDB4A0_STACK_OFFSETS = [
	(0x20, "BDAF10 stack_arg1 source at 0x00bdbaa3; decompile uVar1/global resource candidate"),
	(0x4C, "BDAF10 stack_arg0 source at 0x00bdbaa4; pass-entry seed/owner candidate"),
	(0x5C, "BDAF10 stack_arg4 pointer source at 0x00bdbaa0; local state pointer candidate"),
	(0x50, "post-BDAF10 param_3/DAT_010A91D4 compare source"),
	(0x13, "local branch byte used around BDAF10 block"),
	(0x15, "branch guard before BDAF10 call"),
]

BDAF10_STACK_PARAMS = [
	("this/ECX", "ESI", "owner object passed as ECX; helper reads this +0x3C pass-entry list and this +0xC8 material count"),
	("stack_arg0 / BDAF10 param_2", "EDX from [ESP+0x4C]", "forwarded to BA9EE0 stack_arg0 entry seed/owner"),
	("stack_arg1 / BDAF10 param_3", "ECX from [ESP+0x20]", "resource passed to BA9EE0 rows 0x93/0x94/0x1F2/0x1F3 when count=1"),
	("stack_arg2 / BDAF10 param_4", "EDI", "short counter pointer for count-only prepass"),
	("stack_arg3 / BDAF10 param_5", "EBP", "apply/count selector byte"),
	("stack_arg4 / BDAF10 param_6", "EAX = [ESP+0x5C]", "selector byte pointer dereferenced for entry +7"),
	("stack_arg5 / BDAF10 param_7", "0", "variant flag selecting 0x94/0x1F3 rows when nonzero"),
]

BDAF10_ROW_EXPECTATIONS = [
	("0x93", "base row; zero-resource in DAT_011F91A7 path, otherwise resource = param_3 when param_7 == 0"),
	("0x94", "base row variant; resource = param_3 when param_7 != 0"),
	("0x1EF", "active-object row; resource = iterator result from B70600/B70700 path"),
	("0x1F1", "zero-resource row gated by base +0xB4[0]"),
	("0x1F2", "layer diffuse row; zero-resource in DAT_011F91A7 path, otherwise resource = param_3 when param_7 == 0"),
	("0x1F3", "layer diffuse row variant; resource = param_3 when param_7 != 0"),
	("0x1F4", "zero-resource row gated by both +0xAC[index+1] and +0xB4[index+1]"),
	("0x1F5", "active-object row; resource = iterator result from B70600/B70700 path"),
]

def write(msg):
	output.append(msg)
	print(msg)

def read_byte(addr_int):
	try:
		value = memory.getByte(toAddr(addr_int))
		if value < 0:
			value += 0x100
		return value
	except:
		return None

def read_c_string(addr_int, limit):
	chars = []
	index = 0
	while index < limit:
		value = read_byte(addr_int + index)
		if value is None:
			return None
		if value == 0:
			break
		if value < 0x20 or value > 0x7e:
			return None
		chars.append(chr(value))
		index += 1
	if len(chars) < 3:
		return None
	return "".join(chars)

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
	text = read_c_string(addr_int, 96)
	if text is not None:
		return "\"%s\"" % text
	return "unknown"

def get_function(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	return func

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
	func = get_function(addr_int)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	calls = []
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress()
				target_int = target.getOffset()
				calls.append((inst.getAddress().getOffset(), target_int, label_for(target_int)))
	for item in calls:
		write("  0x%08x -> 0x%08x %s" % (item[0], item[1], item[2]))
	write("  Total: %d calls" % len(calls))

def inst_text(inst):
	if inst is None:
		return "[missing instruction]"
	return "%s %s" % (inst.getMnemonicString(), inst.getDefaultOperandRepresentation(0) if inst.getNumOperands() > 0 else "")

def full_inst_text(inst):
	if inst is None:
		return "[missing instruction]"
	parts = []
	index = 0
	while index < inst.getNumOperands():
		parts.append(inst.getDefaultOperandRepresentation(index))
		index += 1
	if len(parts) == 0:
		return inst.getMnemonicString()
	return "%s %s" % (inst.getMnemonicString(), ",".join(parts))

def print_disasm_range(start_int, end_int, label, focus_int):
	write("")
	write("=" * 70)
	write("Raw disassembly: %s" % label)
	write("=" * 70)
	addr = toAddr(start_int)
	end = toAddr(end_int)
	while addr.compareTo(end) <= 0:
		inst = listing.getInstructionAt(addr)
		if inst is None:
			addr = addr.add(1)
			continue
		prefix = "=> " if inst.getAddress().getOffset() == focus_int else "   "
		write("%s0x%08x: %-58s %s" % (prefix, inst.getAddress().getOffset(), full_inst_text(inst), label_for(inst.getAddress().getOffset())))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall() or ref.getReferenceType().isJump() or ref.getReferenceType().isData():
				write("      ref %s -> 0x%08x %s" % (ref.getReferenceType(), ref.getToAddress().getOffset(), label_for(ref.getToAddress().getOffset())))
		addr = inst.getAddress().add(inst.getLength())

def scan_decompile_lines(addr_int, label, patterns):
	func = get_function(addr_int)
	write("")
	write("=" * 70)
	write("Matched decompile lines: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	result = decomp.decompileFunction(func, 120, monitor)
	if not result or not result.decompileCompleted():
		write("  [decompilation failed]")
		return
	code = result.getDecompiledFunction().getC()
	lines = code.splitlines()
	count = 0
	line_no = 1
	for line in lines:
		lower = line.lower()
		matched = False
		for pattern in patterns:
			if pattern.lower() in lower:
				matched = True
		if matched:
			write("  L%-4d %s" % (line_no, line))
			count += 1
		line_no += 1
	write("  Total matched lines: %d" % count)

def print_stack_offset_uses(addr_int, label, offsets):
	func = get_function(addr_int)
	write("")
	write("=" * 70)
	write("Stack/local offset uses near BDAF10 call: %s" % label)
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = full_inst_text(inst).lower()
		for item in offsets:
			needle = "[esp + 0x%x]" % item[0]
			if needle in text:
				write("  0x%08x: %-56s ; %s" % (inst.getAddress().getOffset(), full_inst_text(inst), item[1]))

def print_bdaf10_callsite_contract():
	write("")
	write("=" * 70)
	write("Normalized BDB4A0 -> BDAF10 callsite contract")
	write("=" * 70)
	write("Callsite: 0x00BDBAA7. This script treats BDAF10 as thiscall.")
	for item in BDAF10_STACK_PARAMS:
		write("  %-32s = %-24s ; %s" % (item[0], item[1], item[2]))
	write("")
	write("Immediate raw call sequence shows exactly six stack pushes before MOV ECX,ESI/CALL.")
	print_disasm_range(0x00BDBA8B, 0x00BDBAB8, "BDAF10 callsite in BDB4A0", BDAF10_CALLSITE)

def print_bdaf10_row_contract():
	write("")
	write("=" * 70)
	write("BDAF10 BA9EE0 row semantic buckets to verify")
	write("=" * 70)
	for item in BDAF10_ROW_EXPECTATIONS:
		write("  stage %s: %s" % (item[0], item[1]))
	write("")
	write("Important question for visible PBR:")
	write("  If rows 0x93/0x94/0x1F2/0x1F3 bind BDAF10 param_3, this script must prove whether param_3 is a material texture, a fallback/global resource, or another wrapper.")
	write("  If param_3 comes from BDB4A0 uVar1 = *(FUN_00B4F5C0()+0x194)+0xE0, it is not a direct +0xAC/+0xB0/+0xB4/+0xB8/+0xBC/+0xC0 material array resource.")

def main():
	write("FNV PBR PPLIGHTING BDAF10 CALLSITE PARAM CLOSURE AUDIT")
	write("")
	write("Questions:")
	write("1. What are the exact thiscall ECX and stack arguments at BDB4A0 -> BDAF10?")
	write("2. Which BDAF10 parameter becomes BA9EE0 resource rows 0x93/0x94/0x1F2/0x1F3?")
	write("3. Is that parameter a material texture-array resource or the renderer/global fallback resource from BDB4A0?")
	write("4. Can BDAF10 be used as a safe visible PBR material-map binding contract?")
	find_refs_to(BDAF10, "PPLighting diffuse/glow material predicate helper")
	find_refs_to(BA9EE0, "PPLighting pass-entry append/reuse helper")
	decompile_at(BDB4A0, "PPLighting setup variant before BDF790", 38000)
	print_bdaf10_callsite_contract()
	print_stack_offset_uses(BDB4A0, "BDB4A0", BDB4A0_STACK_OFFSETS)
	scan_decompile_lines(BDB4A0, "BDB4A0", [
		"FUN_00bdaf10",
		"FUN_00b4f5c0",
		"+ 0x194",
		"+0x194",
		"+ 0xe0",
		"+0xe0",
		"FUN_00a59d30(0)",
		"FUN_00b70600",
		"FUN_00b70700",
		"+ 0xb4",
		"+ 0xb8",
		"+ 0xbc",
	])
	decompile_at(BDAF10, "PPLighting diffuse/glow material predicate helper", 26000)
	find_and_print_calls_from(BDAF10, "PPLighting diffuse/glow material predicate helper")
	scan_decompile_lines(BDAF10, "BDAF10", [
		"FUN_00ba9ee0",
		"FUN_00a59d30(3)",
		"param_2",
		"param_3",
		"param_6",
		"param_7",
		"+ 0xac",
		"+0xac",
		"+ 0xb4",
		"+0xb4",
		"+ 0xb0",
		"+0xb0",
		"+ 0xb8",
		"+0xb8",
		"+ 0xbc",
		"+0xbc",
		"+ 0xc0",
		"+0xc0",
		"0x93",
		"0x94",
		"0x1f1",
		"0x1f2",
		"0x1f5",
		"499",
		"500",
		"FUN_00b70600",
		"FUN_00b70700",
	])
	print_bdaf10_row_contract()
	decompile_at(0x00B4F5C0, "renderer singleton getter used by BDB4A0 uVar1 path", 12000)
	find_and_print_calls_from(BDB4A0, "PPLighting setup variant before BDF790")

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_bdaf10_callsite_param_closure_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
