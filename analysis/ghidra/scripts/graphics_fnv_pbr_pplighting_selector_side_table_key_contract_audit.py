# @category Analysis
# @description Audit FNV native PBR PPLighting side-table key candidates across selector and current-pass apply

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
	0x00B7DD50: "current-pass texture-record apply caller A",
	0x00B7DDE0: "current-pass texture-record writer/apply caller B",
	0x00B7DED0: "alternate current-pass texture-record caller",
	0x00B7DFE0: "alternate current-pass texture-record caller",
	0x00B7E150: "current-pass texture-record writer/apply caller C",
	0x00B98E80: "current-pass draw dispatch using DAT_011F4748 +0x0C",
	0x00B99390: "current-pass setup caller of B7DD50",
	0x00B994F0: "current geometry/global writer candidate",
	0x00BA8C50: "PPLighting pass-entry allocator/grow helper",
	0x00BA8EC0: "PPLighting pass-entry constructor/reset helper",
	0x00BA9EE0: "PPLighting pass-entry append/reuse helper",
	0x00BD4BA0: "PPLighting shader interface apply scope",
	0x00BDA0A0: "PPLighting pass row emitter family",
	0x00BDAC00: "PPLighting pass row emitter family",
	0x00BDAF10: "PPLighting diffuse/glow material predicate helper",
	0x00BDB380: "PPLighting setup helper",
	0x00BDB4A0: "PPLighting setup variant before BDAF10",
	0x00BDBF60: "PPLighting pass row emitter family",
	0x00BDF790: "PPLighting setup variant with BA9EE0 row",
	0x00C03230: "active object resource/state getter used before E7EB00",
	0x00E7EA00: "low-level texture-record resolver/bind",
	0x00E7EB00: "low-level texture-record cache/apply",
	0x00E826D0: "shader-interface apply dispatcher",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x011F4748: "current renderer/pass context global",
	0x011F91E0: "current geometry/object global",
	0x011F91A7: "PPLighting branch/global flag",
	0x011F951C: "global fallback resource used by B7E150 branch",
	0x011F95EC: "renderer singleton global",
	0x0126F680: "per-stage cached texture-record resource table",
	0x0126F74C: "current NiD3DPass global",
}

FOCUS_FUNCTIONS = [
	(0x00B98E80, "current-pass draw dispatch using DAT_011F4748 +0x0C", 32000),
	(0x00B99390, "current-pass setup caller of B7DD50", 16000),
	(0x00B994F0, "current geometry/global writer candidate", 22000),
	(0x00B7DDE0, "current-pass texture-record writer/apply caller B", 18000),
	(0x00B7E150, "current-pass texture-record writer/apply caller C", 22000),
	(0x00BD4BA0, "PPLighting shader interface apply scope", 26000),
	(0x00BDB4A0, "PPLighting setup variant before BDAF10", 42000),
	(0x00BDF790, "PPLighting setup variant with BA9EE0 row", 42000),
	(0x00BDAF10, "PPLighting diffuse/glow material predicate helper", 34000),
	(0x00BA9EE0, "PPLighting pass-entry append/reuse helper", 18000),
	(0x00BA8EC0, "PPLighting pass-entry constructor/reset helper", 16000),
	(0x00BA8C50, "PPLighting pass-entry allocator/grow helper", 18000),
	(0x00E826D0, "shader-interface apply dispatcher", 22000),
	(0x00E7EB00, "low-level texture-record cache/apply", 12000),
	(0x00E7EA00, "low-level texture-record resolver/bind", 18000),
]

REF_TARGETS = [
	(0x00B98E80, "current-pass draw dispatch using DAT_011F4748 +0x0C"),
	(0x00B99390, "current-pass setup caller of B7DD50"),
	(0x00B994F0, "current geometry/global writer candidate"),
	(0x00BDAF10, "PPLighting diffuse/glow material predicate helper"),
	(0x00BDB4A0, "PPLighting setup variant before BDAF10"),
	(0x00BDF790, "PPLighting setup variant with BA9EE0 row"),
	(0x00BA9EE0, "PPLighting pass-entry append/reuse helper"),
	(0x00BA8EC0, "PPLighting pass-entry constructor/reset helper"),
	(0x00BA8C50, "PPLighting pass-entry allocator/grow helper"),
	(0x00BD4BA0, "PPLighting shader interface apply scope"),
	(0x00E826D0, "shader-interface apply dispatcher"),
	(0x00E7EB00, "low-level texture-record cache/apply"),
	(0x00E7EA00, "low-level texture-record resolver/bind"),
	(0x011F4748, "current renderer/pass context global"),
	(0x011F91E0, "current geometry/object global"),
	(0x011F91A7, "PPLighting branch/global flag"),
	(0x011F951C, "global fallback resource used by B7E150 branch"),
	(0x011F95EC, "renderer singleton global"),
	(0x0126F680, "per-stage cached texture-record resource table"),
	(0x0126F74C, "current NiD3DPass global"),
]

CALL_WINDOWS = [
	(0x00B98E80, "B98E80 current-pass dispatch", 0x00B7DDE0, "B7DDE0 slot writer", 1, 8),
	(0x00B98E80, "B98E80 current-pass dispatch", 0x00B7E150, "B7E150 slot writer", 1, 8),
	(0x00B98E80, "B98E80 current-pass dispatch", 0x00B7DED0, "B7DED0 slot writer", 1, 8),
	(0x00B98E80, "B98E80 current-pass dispatch", 0x00B7DFE0, "B7DFE0 slot writer", 1, 8),
	(0x00BDB4A0, "BDB4A0 selector setup", 0x00BDAF10, "BDAF10 material predicate helper", 7, 6),
	(0x00BDAF10, "BDAF10 material predicate helper", 0x00BA9EE0, "BA9EE0 pass-entry append/reuse", 8, 20),
	(0x00BDF790, "BDF790 selector setup", 0x00BA9EE0, "BA9EE0 pass-entry append/reuse", 8, 8),
	(0x00BA9EE0, "BA9EE0 pass-entry append/reuse", 0x00BA8EC0, "BA8EC0 entry constructor/reset", 8, 8),
	(0x00BA9EE0, "BA9EE0 pass-entry append/reuse", 0x00BA8C50, "BA8C50 entry allocator/grow", 3, 8),
	(0x00BD4BA0, "BD4BA0 apply scope", 0x00E826D0, "E826D0 shader dispatcher", 10, 12),
	(0x00E7EB00, "E7EB00 low-level cache/apply", 0x00E7EA00, "E7EA00 texture resolver/bind", 1, 4),
]

RAW_WINDOWS = [
	(0x00B98F00, "B98E80 -> B7DDE0 with current-pass context"),
	(0x00B98F39, "B98E80 -> B7E150 with current-pass context"),
	(0x00B98F43, "B98E80 -> B7DED0 with current-pass context"),
	(0x00B98F7C, "B98E80 -> B7DFE0 with current-pass context"),
	(0x00BDBAA7, "BDB4A0 -> BDAF10 selector/material predicate call"),
	(0x00BDAF89, "BDAF10 -> BA9EE0 row 0x93 count-only"),
	(0x00BDAFE3, "BDAF10 -> BA9EE0 row 0x1F2 count-only"),
	(0x00BDB045, "BDAF10 -> BA9EE0 row 0x93 resource-bearing"),
	(0x00BDB06E, "BDAF10 -> BA9EE0 row 0x94 resource-bearing"),
	(0x00BDB0A7, "BDAF10 -> BA9EE0 row 0x1F1 zero-resource"),
	(0x00BDB139, "BDAF10 -> BA9EE0 row 0x1EF active-object resource"),
	(0x00BDB1B1, "BDAF10 -> BA9EE0 row 0x1F2 resource-bearing"),
	(0x00BDB1EE, "BDAF10 -> BA9EE0 row 0x1F3 resource-bearing"),
	(0x00BDB278, "BDAF10 -> BA9EE0 row 0x1F4 zero-resource"),
	(0x00BDB31E, "BDAF10 -> BA9EE0 row 0x1F5 active-object resource"),
	(0x00BDFD30, "BDF790 -> BA9EE0 selector row"),
	(0x00BD4BA0, "BD4BA0 apply scope entry"),
	(0x00E7EB00, "E7EB00 low-level texture-record cache/apply entry"),
]

SCAN_PATTERNS = [
	"DAT_011f4748",
	"DAT_011f91e0",
	"DAT_011f91a7",
	"DAT_011f951c",
	"DAT_011f95ec",
	"DAT_0126f680",
	"DAT_0126f74c",
	"FUN_00ba9ee0",
	"FUN_00bdaf10",
	"FUN_00b98e80",
	"FUN_00e7eb00",
	"FUN_00e7ea00",
	"FUN_00a59d30",
	"FUN_00c03230",
	"FUN_00e826d0",
	"param_1 + 0xc",
	"+ 0x3c",
	"+0x3c",
	"+ 0x10",
	"+0x10",
	"+ 0xc",
	"+0xc",
	"+ 0x24",
	"+0x24",
	"+ 0x2b",
	"+0x2b",
	"+ 0x78",
	"+0x78",
	"+ 0x7c",
	"+0x7c",
	"+ 0x80",
	"+0x80",
	"+ 0x84",
	"+0x84",
	"+ 0x88",
	"+0x88",
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
		if count > 260:
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

def find_register_writes_before(inst, registers, max_steps):
	writes = []
	cur = listing.getInstructionBefore(inst.getAddress())
	steps = 0
	while cur is not None and steps < max_steps:
		mnemonic = cur.getMnemonicString()
		dst = operand_text(cur, 0).upper()
		for reg in registers:
			if dst == reg:
				writes.append((reg, cur.getAddress().getOffset(), mnemonic, operand_text(cur, 1), cur.toString()))
		if mnemonic.startswith("CALL") or mnemonic.startswith("RET"):
			break
		cur = listing.getInstructionBefore(cur.getAddress())
		steps += 1
	return writes

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
	write("Call argument/register windows: %s -> %s" % (caller_label, target_label))
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
			reg_writes = find_register_writes_before(inst, ["ECX", "EDX", "EDI", "ESI", "EBX", "EBP", "EAX"], 56)
			for item in reg_writes:
				write("    recent %s write: 0x%08x %s %s ; %s" % (item[0], item[1], item[2], item[3], item[4]))
			pushes = collect_pushes_before(inst, arg_count, 72)
			arg_index = 0
			for item in pushes:
				write("    stack_arg%d from PUSH @ 0x%08x: %-24s ; %s" % (arg_index, item[0], item[1], item[2]))
				arg_index += 1
			write("    Raw short window:")
			print_short_window(inst, 16, 8)
			count += 1
			if count >= max_calls:
				write("  ... call windows truncated at %d" % max_calls)
				break
	if count == 0:
		write("  [no calls to target in caller]")
	write("  Total printed calls: %d" % count)

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

def print_candidate_key_questions():
	write("")
	write("=" * 70)
	write("Native PBR side-table key questions")
	write("=" * 70)
	write("1. Does DAT_011F4748 +0x0C identify the same current-pass context as selector-side material capture?")
	write("2. Can *DAT_011F91E0, DAT_0126F74C, or the BA9EE0 list owner (this +0x3C) link capture to final apply?")
	write("3. Do BDAF10/BDF790 append rows leave a stable entry pointer or generation that survives into BD4BA0/E7EB00?")
	write("4. If no stable later key exists, the implementation needs a hook where material arrays and bind action are both in scope.")

def print_all_refs():
	for item in REF_TARGETS:
		find_refs_to(item[0], item[1])

def print_all_calls():
	for item in FOCUS_FUNCTIONS:
		find_and_print_calls_from(item[0], item[1])

def print_all_decompiles():
	for item in FOCUS_FUNCTIONS:
		decompile_at(item[0], item[1], item[2])
		scan_decompile_lines(item[0], item[1], SCAN_PATTERNS)

def print_all_raw_windows():
	for item in RAW_WINDOWS:
		print_disasm_range(item[0] - 0x40, item[0] + 0x38, item[1], item[0])

def print_all_call_windows():
	for item in CALL_WINDOWS:
		print_call_arg_windows_for_target(item[0], item[1], item[2], item[3], item[4], item[5])

def main():
	write("FNV PBR PPLIGHTING SELECTOR SIDE-TABLE KEY CONTRACT AUDIT")
	print_candidate_key_questions()
	print_all_refs()
	print_all_calls()
	print_all_decompiles()
	print_all_raw_windows()
	print_all_call_windows()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_selector_side_table_key_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
