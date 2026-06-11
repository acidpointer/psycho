# @category Analysis
# @description Audit FNV PPLighting draw-scope material pointer and pass-entry layer contract for native PBR

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
	0x00B68660: "PPLighting six texture-array writer",
	0x00BA8C50: "pass-entry reused-entry array setter",
	0x00BA8EC0: "pass-entry constructor",
	0x00BA9EE0: "PPLighting pass-entry append/reuse helper",
	0x00BDAF10: "PPLighting diffuse/glow material predicate helper",
	0x00BDB4A0: "PPLighting setup variant before BDF790",
	0x00BDF790: "PPLighting selector/pass-entry driver",
	0x00BD4BA0: "current-pass apply/bind candidate",
	0x00BE1F90: "BSShader::SetShaders",
	0x00E7EA00: "final pass-entry resource resolver and SetTexture caller",
	0x00E7EB00: "final pass-entry apply neighbor",
	0x00E826D0: "shader-interface apply dispatcher",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x011F95EC: "renderer singleton global",
	0x0126F74C: "current NiD3DPass global",
}

FOCUS_FUNCTIONS = [
	(0x00BA8C50, "pass-entry reused-entry array setter"),
	(0x00BA8EC0, "pass-entry constructor"),
	(0x00BA9EE0, "PPLighting pass-entry append/reuse helper"),
	(0x00BDAF10, "PPLighting diffuse/glow material predicate helper"),
	(0x00BDB4A0, "PPLighting setup variant before BDF790"),
	(0x00BDF790, "PPLighting selector/pass-entry driver"),
	(0x00BD4BA0, "current-pass apply/bind candidate"),
	(0x00BE1F90, "BSShader::SetShaders"),
	(0x00E7EA00, "final pass-entry resource resolver and SetTexture caller"),
	(0x00E7EB00, "final pass-entry apply neighbor"),
	(0x00E826D0, "shader-interface apply dispatcher"),
	(0x00E88A20, "NiDX9RenderState::SetTexture"),
]

DECOMPILE_FOCUS = [
	(0x00BA8C50, "pass-entry reused-entry array setter", 18000),
	(0x00BA8EC0, "pass-entry constructor", 18000),
	(0x00BA9EE0, "PPLighting pass-entry append/reuse helper", 26000),
	(0x00BDAF10, "PPLighting diffuse/glow material predicate helper", 24000),
	(0x00BD4BA0, "current-pass apply/bind candidate", 34000),
	(0x00BE1F90, "BSShader::SetShaders", 26000),
	(0x00E7EA00, "final pass-entry resource resolver and SetTexture caller", 36000),
	(0x00E7EB00, "final pass-entry apply neighbor", 24000),
]

CALL_TARGETS = [
	(0x00BA8C50, "pass-entry reused-entry array setter", 7),
	(0x00BA8EC0, "pass-entry constructor", 9),
	(0x00BA9EE0, "PPLighting pass-entry append/reuse helper", 8),
	(0x00A59D30, "NiAVObject property lookup by type", 1),
	(0x00E7EA00, "final pass-entry resource resolver and SetTexture caller", 4),
	(0x00E7EB00, "final pass-entry apply neighbor", 4),
	(0x00E826D0, "shader-interface apply dispatcher", 4),
	(0x00E88A20, "NiDX9RenderState::SetTexture", 3),
]

REF_TARGETS = [
	(0x00A59D30, "NiAVObject property lookup by type"),
	(0x00B68660, "PPLighting six texture-array writer"),
	(0x00BA8C50, "pass-entry reused-entry array setter"),
	(0x00BA8EC0, "pass-entry constructor"),
	(0x00BA9EE0, "PPLighting pass-entry append/reuse helper"),
	(0x00BDAF10, "PPLighting diffuse/glow material predicate helper"),
	(0x00BD4BA0, "current-pass apply/bind candidate"),
	(0x00BE1F90, "BSShader::SetShaders"),
	(0x00E7EA00, "final pass-entry resource resolver and SetTexture caller"),
	(0x00E7EB00, "final pass-entry apply neighbor"),
	(0x00E88A20, "NiDX9RenderState::SetTexture"),
	(0x011F95EC, "renderer singleton global"),
	(0x0126F74C, "current NiD3DPass global"),
]

PASS_ENTRY_OFFSETS = [
	(0x00, "entry id / stage key"),
	(0x04, "entry +4 word/short parameter"),
	(0x06, "entry +6 reset flag"),
	(0x07, "entry +7 byte/stage parameter"),
	(0x08, "entry +8 flag/resource boundary"),
	(0x09, "entry +9 resource count"),
	(0x0B, "entry +0x0B layer byte written by BDAF10"),
	(0x0C, "entry +0x0C resource slot array"),
	(0x10, "entry stride / next entry boundary"),
]

MATERIAL_ARRAY_OFFSETS = [
	(0xAC, "diffuse/base texture array"),
	(0xB0, "normal texture array"),
	(0xB4, "glow texture array"),
	(0xB8, "height texture array"),
	(0xBC, "env texture array"),
	(0xC0, "env-mask texture array"),
	(0xC4, "per-index material flags"),
	(0xCC, "per-index normal/spec flags"),
]

SCAN_PATTERNS = [
	"FUN_00a59d30",
	"FUN_00ba8c50",
	"FUN_00ba8ec0",
	"FUN_00ba9ee0",
	"FUN_00bdaf10",
	"FUN_00e7ea00",
	"FUN_00e7eb00",
	"FUN_00e826d0",
	"FUN_00e88a20",
	"SetTexture",
	"settexture",
	"+ 0x3c",
	"+0x3c",
	"+ 0x44",
	"+0x44",
	"+ 0x5c",
	"+0x5c",
	"+ 0xac",
	"+0xac",
	"+ 0xb0",
	"+0xb0",
	"+ 0xb4",
	"+0xb4",
	"+ 0xb8",
	"+0xb8",
	"+ 0xbc",
	"+0xbc",
	"+ 0xc0",
	"+0xc0",
	"+ 0xc4",
	"+0xc4",
	"+ 0xcc",
	"+0xcc",
	"+ 0xb",
	"+0xb",
	"+ 0x0b",
	"+0x0b",
	"+ 0xc",
	"+0xc",
]

BDAF10_LAYER_WRITE_WINDOWS = [
	(0x00BDB1C7, "BDAF10 layer-byte write after 0x1F2"),
	(0x00BDB204, "BDAF10 layer-byte write after 0x1F3"),
	(0x00BDB28E, "BDAF10 layer-byte write after 0x1F4"),
	(0x00BDB334, "BDAF10 layer-byte write after 0x1F5"),
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

def decompile_text_for_func(func):
	if func is None:
		return None
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		return result.getDecompiledFunction().getC()
	return None

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
	code = decompile_text_for_func(func)
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
		text = inst.toString() if inst is not None else ""
		write("  %s @ 0x%08x (in %s) %s" % (ref.getReferenceType(), from_addr.getOffset(), fname, text))
		count += 1
		if count > 160:
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
	count = 0
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target_int = ref.getToAddress().getOffset()
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), target_int, label_for(target_int)))
				count += 1
	write("  Total: %d calls" % count)

def operand_text(inst, index):
	try:
		return inst.getDefaultOperandRepresentation(index)
	except:
		return "?"

def full_inst_text(inst):
	if inst is None:
		return "[missing instruction]"
	parts = []
	index = 0
	while index < inst.getNumOperands():
		parts.append(operand_text(inst, index))
		index += 1
	if len(parts) == 0:
		return inst.getMnemonicString()
	return "%s %s" % (inst.getMnemonicString(), ",".join(parts))

def instruction_before_steps(inst, steps):
	cur = inst
	count = 0
	while count < steps and cur is not None:
		cur = listing.getInstructionBefore(cur.getAddress())
		count += 1
	return cur

def print_short_window(center_inst, before_count, after_count):
	start = instruction_before_steps(center_inst, before_count)
	if start is None:
		start = center_inst
	cur = start
	count = 0
	limit = before_count + after_count + 1
	while cur is not None and count < limit:
		prefix = "=> " if cur.getAddress().equals(center_inst.getAddress()) else "   "
		write("%s0x%08x: %s" % (prefix, cur.getAddress().getOffset(), full_inst_text(cur)))
		cur = listing.getInstructionAfter(cur.getAddress())
		count += 1

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

def offset_needles(offset_int):
	values = []
	hex_a = "0x%x" % offset_int
	hex_b = "0x%02x" % offset_int
	values.append("+ %s" % hex_a)
	values.append("+%s" % hex_a)
	values.append("+ %s" % hex_b)
	values.append("+%s" % hex_b)
	return values

def print_offset_accesses(addr_int, label, offsets):
	func = get_function(addr_int)
	write("")
	write("=" * 70)
	write("Raw offset access scan: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	count = 0
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = full_inst_text(inst).lower()
		for item in offsets:
			needles = offset_needles(item[0])
			matched = False
			for needle in needles:
				if needle.lower() in text:
					matched = True
			if matched:
				write("  0x%08x: %-62s ; %s" % (inst.getAddress().getOffset(), full_inst_text(inst), item[1]))
				count += 1
	if count == 0:
		write("  [no raw offset accesses matched]")
	write("  Total offset matches: %d" % count)

def scan_decompile_lines(addr_int, label, patterns):
	func = get_function(addr_int)
	write("")
	write("=" * 70)
	write("Matched decompile lines: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	code = decompile_text_for_func(func)
	if code is None:
		write("  [decompilation failed]")
		return
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

def collect_pushes_before(inst, max_pushes, max_steps):
	pushes = []
	cur = listing.getInstructionBefore(inst.getAddress())
	steps = 0
	while cur is not None and steps < max_steps and len(pushes) < max_pushes:
		mnemonic = cur.getMnemonicString()
		if mnemonic == "PUSH":
			pushes.append((cur.getAddress().getOffset(), operand_text(cur, 0), cur.toString()))
		elif mnemonic.startswith("CALL") or mnemonic.startswith("RET"):
			break
		cur = listing.getInstructionBefore(cur.getAddress())
		steps += 1
	return pushes

def find_ecx_owner_before(inst, max_steps):
	cur = listing.getInstructionBefore(inst.getAddress())
	steps = 0
	while cur is not None and steps < max_steps:
		mnemonic = cur.getMnemonicString()
		dst = operand_text(cur, 0).upper()
		if dst == "ECX":
			if mnemonic == "MOV" or mnemonic == "LEA":
				return (cur.getAddress().getOffset(), mnemonic, operand_text(cur, 1), cur.toString())
			if mnemonic == "POP":
				return (cur.getAddress().getOffset(), mnemonic, "stack", cur.toString())
			if mnemonic == "XOR" and operand_text(cur, 1).upper() == "ECX":
				return (cur.getAddress().getOffset(), mnemonic, "0", cur.toString())
		if mnemonic.startswith("CALL") or mnemonic.startswith("RET"):
			break
		cur = listing.getInstructionBefore(cur.getAddress())
		steps += 1
	return None

def is_call_to(inst, target_int):
	refs = inst.getReferencesFrom()
	for ref in refs:
		if ref.getReferenceType().isCall() and ref.getToAddress().getOffset() == target_int:
			return True
	return False

def print_call_arg_windows_for_target(caller_addr_int, caller_label, target_addr_int, target_label, arg_count, max_calls):
	func = get_function(caller_addr_int)
	write("")
	write("=" * 70)
	write("Call argument windows: %s -> %s" % (caller_label, target_label))
	write("=" * 70)
	if func is None:
		write("  [caller function not found]")
		return
	count = 0
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		if is_call_to(inst, target_addr_int):
			write("")
			write("  CALL @ 0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), target_addr_int, target_label))
			owner = find_ecx_owner_before(inst, 32)
			if owner is not None:
				write("    ECX before call: 0x%08x %s %s ; %s" % (owner[0], owner[1], owner[2], owner[3]))
			else:
				write("    ECX before call: [not found before prior call/ret]")
			pushes = collect_pushes_before(inst, arg_count, 48)
			arg_index = 0
			for item in pushes:
				write("    stack_arg%d from PUSH @ 0x%08x: %-24s ; %s" % (arg_index, item[0], item[1], item[2]))
				arg_index += 1
			write("    Raw short window:")
			print_short_window(inst, 10, 4)
			count += 1
			if count >= max_calls:
				write("  ... call windows truncated at %d" % max_calls)
				break
	if count == 0:
		write("  [no calls to target in caller]")
	write("  Total printed calls: %d" % count)

def print_bdaf10_layer_write_windows():
	write("")
	write("=" * 70)
	write("BDAF10 raw layer-byte write windows")
	write("=" * 70)
	for item in BDAF10_LAYER_WRITE_WINDOWS:
		print_disasm_range(item[0] - 0x24, item[0] + 0x20, item[1], item[0])

def print_contract_questions():
	write("")
	write("=" * 70)
	write("Contract questions this output must answer")
	write("=" * 70)
	write("1. Does any final apply/bind function still have a recoverable type-3 material property pointer?")
	write("2. Is pass-entry +0x0B, written by BDAF10 as the layer index, read by final apply or only preserved in the entry?")
	write("3. Which pass-entry fields are read at final apply: +0/+4/+7/+8/+9/+0x0B/+0x0C?")
	write("4. Can a runtime side-table safely key by pass-entry owner, entry pointer, shader interface, or current draw scope?")
	write("5. If no material pointer survives to final apply, the first PBR implementation must capture arrays earlier and bind later with a proven lifetime key.")

def main():
	write("FNV PBR PPLIGHTING DRAW-SCOPE MATERIAL POINTER CONTRACT AUDIT")
	print_contract_questions()
	for item in REF_TARGETS:
		find_refs_to(item[0], item[1])
	for item in FOCUS_FUNCTIONS:
		find_and_print_calls_from(item[0], item[1])
	for item in DECOMPILE_FOCUS:
		decompile_at(item[0], item[1], item[2])
		scan_decompile_lines(item[0], item[1], SCAN_PATTERNS)
	for item in FOCUS_FUNCTIONS:
		print_offset_accesses(item[0], item[1], PASS_ENTRY_OFFSETS)
	for item in FOCUS_FUNCTIONS:
		print_offset_accesses(item[0], item[1], MATERIAL_ARRAY_OFFSETS)
	print_bdaf10_layer_write_windows()
	for caller in FOCUS_FUNCTIONS:
		for target in CALL_TARGETS:
			print_call_arg_windows_for_target(caller[0], caller[1], target[0], target[1], target[2], 12)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_draw_scope_material_pointer_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
