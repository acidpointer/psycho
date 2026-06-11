# @category Analysis
# @description Reduce FNV PPLighting shader-interface record registrations and pass-entry helpers into tables

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00B7A870: "PPLighting/global shader-interface record setup",
	0x00BD20E0: "current-pass local shader-interface record setup",
	0x00B887C0: "lighting shader-interface record setup family A",
	0x00B83DD0: "lighting shader-interface record setup family B",
	0x00BEA040: "shader-interface record setup family C",
	0x00E7F000: "shader-interface record lookup",
	0x00E7F430: "shader-interface record register/finalize",
	0x00E7F5D0: "shader-interface record factory",
	0x00E826D0: "shader-interface field vtable +0x78 apply",
	0x00BA8C50: "pass-entry storage helper A",
	0x00BA8EC0: "pass-entry storage helper B",
	0x00BA9EE0: "pass-entry construction helper",
	0x00BD9540: "PPLighting pass-entry helper 00BD9540",
	0x00BD9840: "PPLighting pass-entry helper 00BD9840",
	0x00BD99C0: "PPLighting pass-entry helper 00BD99C0",
	0x00BD9AC0: "PPLighting pass-entry helper 00BD9AC0",
	0x00BD9BC0: "PPLighting pass-entry helper 00BD9BC0",
	0x00BD9D00: "PPLighting pass-entry helper 00BD9D00",
	0x00BD9DA0: "PPLighting pass-entry helper 00BD9DA0",
	0x00BD9E60: "PPLighting pass-entry helper 00BD9E60",
	0x00BD9F00: "PPLighting pass-entry helper 00BD9F00",
	0x00BD9F90: "PPLighting pass-entry helper 00BD9F90",
	0x00BDA0A0: "PPLighting pass-entry helper 00BDA0A0",
	0x00BDAF10: "PPLighting pass-entry helper 00BDAF10",
	0x00BDB380: "PPLighting pass-entry helper 00BDB380",
	0x00BDBF60: "PPLighting pass-entry helper 00BDBF60",
	0x00BDC030: "PPLighting pass-entry helper 00BDC030",
	0x00BDC0D0: "PPLighting pass-entry helper 00BDC0D0",
	0x00BDCA60: "PPLighting pass-entry helper 00BDCA60",
	0x00BDD050: "PPLighting pass-entry helper 00BDD050",
	0x00BDD520: "PPLighting pass-entry helper 00BDD520",
	0x00BDDA20: "PPLighting pass-entry helper 00BDDA20",
	0x00BDDBC0: "PPLighting pass-entry helper 00BDDBC0",
	0x00BDDD80: "PPLighting pass-entry helper 00BDDD80",
	0x00BDDE10: "PPLighting pass-entry helper 00BDDE10",
	0x00BDDFB0: "PPLighting pass-entry helper 00BDDFB0",
	0x00BDE1D0: "PPLighting pass-entry helper 00BDE1D0",
	0x00BDE9B0: "PPLighting pass-entry helper 00BDE9B0",
	0x00BDEF40: "PPLighting pass-entry helper 00BDEF40",
	0x00BDF3E0: "PPLighting pass-entry helper 00BDF3E0",
	0x010EF544: "shader-interface field vtable",
	0x011FDFF8: "NiD3DPass global array",
	0x0126F74C: "current NiD3DPass global",
}

RECORD_SETUP_FUNCTIONS = [
	(0x00B7A870, "PPLighting/global shader-interface record setup"),
	(0x00BD20E0, "current-pass local shader-interface record setup"),
	(0x00B887C0, "lighting shader-interface record setup family A"),
	(0x00B83DD0, "lighting shader-interface record setup family B"),
	(0x00BEA040, "shader-interface record setup family C"),
]

RECORD_CORE_FUNCTIONS = [
	(0x00E7F000, "shader-interface record lookup"),
	(0x00E7F430, "shader-interface record register/finalize"),
	(0x00E7F5D0, "shader-interface record factory"),
	(0x00E826D0, "shader-interface apply dispatcher"),
]

SHADER_INTERFACE_SLOTS = [
	(0x010EF544, 0x78, "apply dispatcher"),
	(0x010EF544, 0x8C, "type 0x20000000 helper"),
	(0x010EF544, 0x90, "type 0x10000000 fallback helper"),
	(0x010EF544, 0x94, "type 0x30000000 helper"),
	(0x010EF544, 0x98, "type 0x40000000 helper"),
	(0x010EF544, 0x9C, "type 0x50000000 helper"),
	(0x010EF544, 0xA4, "type 0x60000000 helper"),
]

PASS_ENTRY_HELPERS = [
	(0x00BD9540, "PPLighting pass-entry helper 00BD9540"),
	(0x00BD9840, "PPLighting pass-entry helper 00BD9840"),
	(0x00BD99C0, "PPLighting pass-entry helper 00BD99C0"),
	(0x00BD9AC0, "PPLighting pass-entry helper 00BD9AC0"),
	(0x00BD9BC0, "PPLighting pass-entry helper 00BD9BC0"),
	(0x00BD9D00, "PPLighting pass-entry helper 00BD9D00"),
	(0x00BD9DA0, "PPLighting pass-entry helper 00BD9DA0"),
	(0x00BD9E60, "PPLighting pass-entry helper 00BD9E60"),
	(0x00BD9F00, "PPLighting pass-entry helper 00BD9F00"),
	(0x00BD9F90, "PPLighting pass-entry helper 00BD9F90"),
	(0x00BDA0A0, "PPLighting pass-entry helper 00BDA0A0"),
	(0x00BDB380, "PPLighting pass-entry helper 00BDB380"),
	(0x00BDBF60, "PPLighting pass-entry helper 00BDBF60"),
	(0x00BDC030, "PPLighting pass-entry helper 00BDC030"),
	(0x00BDC0D0, "PPLighting pass-entry helper 00BDC0D0"),
	(0x00BDCA60, "PPLighting pass-entry helper 00BDCA60"),
	(0x00BDD050, "PPLighting pass-entry helper 00BDD050"),
	(0x00BDD520, "PPLighting pass-entry helper 00BDD520"),
	(0x00BDDA20, "PPLighting pass-entry helper 00BDDA20"),
	(0x00BDDBC0, "PPLighting pass-entry helper 00BDDBC0"),
	(0x00BDDD80, "PPLighting pass-entry helper 00BDDD80"),
	(0x00BDDE10, "PPLighting pass-entry helper 00BDDE10"),
	(0x00BDDFB0, "PPLighting pass-entry helper 00BDDFB0"),
	(0x00BDE1D0, "PPLighting pass-entry helper 00BDE1D0"),
	(0x00BDE9B0, "PPLighting pass-entry helper 00BDE9B0"),
	(0x00BDEF40, "PPLighting pass-entry helper 00BDEF40"),
	(0x00BDF3E0, "PPLighting pass-entry helper 00BDF3E0"),
]

SCAN_PATTERNS = [
	"E7F430",
	"e7f430",
	"E7F5D0",
	"e7f5d0",
	"E826D0",
	"e826d0",
	"BA8C50",
	"ba8c50",
	"BA8EC0",
	"ba8ec0",
	"BA9EE0",
	"ba9ee0",
	"SetPixelShaderConstant",
	"SetVertexShaderConstant",
	"SetTexture",
	"SetRenderState",
	"SetSamplerState",
	"constant",
	"register",
	"texture",
	"sampler",
	"shader",
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

def decompile_at(addr_int, label, max_len=24000):
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
		from_addr = ref.getFromAddress()
		from_func = fm.getFunctionContaining(from_addr)
		fname = from_func.getName() if from_func else "???"
		inst = listing.getInstructionContaining(from_addr)
		inst_text = inst.toString() if inst is not None else ""
		write("  %s @ 0x%08x (in %s) %s" % (ref.getReferenceType(), from_addr.getOffset(), fname, inst_text))
		count += 1
		if count > 220:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def is_call_to(inst, target_int):
	refs = inst.getReferencesFrom()
	for ref in refs:
		if ref.getReferenceType().isCall() and ref.getToAddress().getOffset() == target_int:
			return True
	return False

def collect_pushes_before(inst, wanted, max_steps):
	pushes = []
	cur = listing.getInstructionBefore(inst.getAddress())
	steps = 0
	while cur is not None and steps < max_steps and len(pushes) < wanted:
		mnemonic = cur.getMnemonicString()
		if mnemonic == "PUSH":
			pushes.append((cur.getAddress().getOffset(), operand_text(cur, 0)))
		elif mnemonic.startswith("CALL"):
			break
		cur = listing.getInstructionBefore(cur.getAddress())
		steps += 1
	return pushes

def print_refs_from_instruction(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		taddr = ref.getToAddress().getOffset()
		write("      ref %s -> 0x%08x %s" % (ref.getReferenceType(), taddr, label_for(taddr)))

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
		print_refs_from_instruction(cur)
		cur = listing.getInstructionAfter(cur.getAddress())
		count += 1

def scan_patterns(addr_int, label, patterns):
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
		for pattern in patterns:
			if pattern.lower() in lower:
				write("  L%-4d %s" % (line_no, line))
				break

def print_record_registration_table(addr_int, label):
	write("")
	write("=" * 70)
	write("E7F430 RECORD REGISTRATION TABLE: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found]")
		return
	count = 0
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		if is_call_to(inst, 0x00E7F430):
			pushes = collect_pushes_before(inst, 3, 18)
			arg1 = pushes[0][1] if len(pushes) > 0 else "?"
			arg2 = pushes[1][1] if len(pushes) > 1 else "?"
			arg3 = pushes[2][1] if len(pushes) > 2 else "?"
			write("  call 0x%08x: record_key=%s value_arg=%s list_flag=%s" % (inst.getAddress().getOffset(), arg1, arg2, arg3))
			index = 0
			for item in pushes:
				write("    push%d @ 0x%08x %s" % (index + 1, item[0], item[1]))
				index += 1
			count += 1
	write("  Total E7F430 calls: %d" % count)

def print_call_targets_from(addr_int, label):
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found]")
		return
	count = 0
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				taddr = ref.getToAddress().getOffset()
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), taddr, label_for(taddr)))
				count += 1
	write("  Total: %d calls" % count)

def print_shader_interface_slot_targets():
	write("")
	write("=" * 70)
	write("SHADER-INTERFACE VTABLE SLOT TARGETS")
	write("=" * 70)
	for item in SHADER_INTERFACE_SLOTS:
		target = read_u32(item[0] + item[1])
		write("  0x%08x +0x%03x %-32s -> 0x%08x %s" % (item[0], item[1], item[2], target if target is not None else 0, label_for(target)))
		if target is not None:
			decompile_at(target, "slot +0x%03x %s" % (item[1], item[2]), 18000)
			scan_patterns(target, "slot +0x%03x %s" % (item[1], item[2]), SCAN_PATTERNS)

def decompile_record_setup_functions():
	for item in RECORD_SETUP_FUNCTIONS:
		decompile_at(item[0], item[1], 30000)
		print_call_targets_from(item[0], item[1])
		print_record_registration_table(item[0], item[1])
		scan_patterns(item[0], item[1], SCAN_PATTERNS)

def decompile_record_core_functions():
	for item in RECORD_CORE_FUNCTIONS:
		decompile_at(item[0], item[1], 22000)
		print_call_targets_from(item[0], item[1])
		scan_patterns(item[0], item[1], SCAN_PATTERNS)

def decompile_pass_entry_helpers():
	for item in PASS_ENTRY_HELPERS:
		decompile_at(item[0], item[1], 18000)
		print_call_targets_from(item[0], item[1])
		scan_patterns(item[0], item[1], SCAN_PATTERNS)

def print_target_refs():
	find_refs_to(0x00E7F430, "shader-interface record register/finalize")
	find_refs_to(0x00BA8C50, "pass-entry storage helper A")
	find_refs_to(0x00BA8EC0, "pass-entry storage helper B")
	find_refs_to(0x00BA9EE0, "pass-entry construction helper")

def print_key_windows():
	disasm_window(0x00B7A870, 24, 160, "PPLighting/global shader-interface record setup")
	disasm_window(0x00BD20E0, 24, 120, "current-pass local shader-interface record setup")
	disasm_window(0x00B887C0, 24, 160, "lighting shader-interface record setup family A")
	disasm_window(0x00E7F430, 16, 90, "shader-interface record register/finalize")
	disasm_window(0x00E826D0, 16, 120, "shader-interface apply dispatcher")

def main():
	write("FNV PBR PPLIGHTING INTERFACE RECORD TABLE AUDIT")
	write("")
	write("Questions:")
	write("1. Which E7F430 record keys/lists are registered by PPLighting setup functions?")
	write("2. Which vtable helpers execute each shader-interface record type class?")
	write("3. Which pass-entry helpers map PPLighting branches to concrete pass IDs/resources?")
	write("4. Is one replacement family concrete enough to bind a BRDF shader without guessing?")
	write("")
	write("Compatibility rule:")
	write("Do not bind a replacement shader until this output yields a per-family record/stage table.")
	print_target_refs()
	print_key_windows()
	print_shader_interface_slot_targets()
	decompile_record_core_functions()
	decompile_record_setup_functions()
	decompile_pass_entry_helpers()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_interface_record_table_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
