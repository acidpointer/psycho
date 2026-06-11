# @category Analysis
# @description Trace FNV PPLighting pass-entry rows into low-level texture-record apply calls for native PBR

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
	0x00BA8C50: "PPLighting pass-entry resource-array setter",
	0x00BA8EC0: "PPLighting pass-entry constructor",
	0x00BA9EE0: "PPLighting pass-entry append/reuse helper",
	0x00BDAF10: "PPLighting diffuse/glow material predicate helper",
	0x00BD4BA0: "current-pass shader-interface apply candidate",
	0x00BDF790: "PPLighting selector/pass-entry driver",
	0x00B7DD50: "low-level texture-record apply caller A",
	0x00B7DDE0: "low-level texture-record apply caller B",
	0x00B7E150: "low-level texture-record apply caller C",
	0x00E7EA00: "low-level texture-record resolver/bind",
	0x00E7EB00: "low-level texture-record cache/apply",
	0x00E826D0: "shader-interface apply dispatcher",
	0x00E89060: "texture stage state resolver helper",
	0x00E89410: "texture-stage cache/test helper",
	0x00E7DC90: "texture bind post-helper A",
	0x00E7E940: "texture bind post-helper B",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x0126F680: "per-stage cached texture-record resource table",
	0x0126F6C4: "renderer/device object global A",
	0x0126F6C8: "renderer/device state object global B",
	0x0126F74C: "current NiD3DPass global",
}

BRIDGE_FUNCTIONS = [
	(0x00B7DD50, "low-level texture-record apply caller A"),
	(0x00B7DDE0, "low-level texture-record apply caller B"),
	(0x00B7E150, "low-level texture-record apply caller C"),
	(0x00E7EB00, "low-level texture-record cache/apply"),
	(0x00E7EA00, "low-level texture-record resolver/bind"),
	(0x00E826D0, "shader-interface apply dispatcher"),
	(0x00BD4BA0, "current-pass shader-interface apply candidate"),
	(0x00BA9EE0, "PPLighting pass-entry append/reuse helper"),
]

DECOMPILE_FOCUS = [
	(0x00B7DD50, "low-level texture-record apply caller A", 20000),
	(0x00B7DDE0, "low-level texture-record apply caller B", 26000),
	(0x00B7E150, "low-level texture-record apply caller C", 30000),
	(0x00E7EB00, "low-level texture-record cache/apply", 14000),
	(0x00E7EA00, "low-level texture-record resolver/bind", 22000),
	(0x00E826D0, "shader-interface apply dispatcher", 34000),
	(0x00BD4BA0, "current-pass shader-interface apply candidate", 22000),
]

REF_TARGETS = [
	(0x00B7DD50, "low-level texture-record apply caller A"),
	(0x00B7DDE0, "low-level texture-record apply caller B"),
	(0x00B7E150, "low-level texture-record apply caller C"),
	(0x00E7EB00, "low-level texture-record cache/apply"),
	(0x00E7EA00, "low-level texture-record resolver/bind"),
	(0x00E826D0, "shader-interface apply dispatcher"),
	(0x00BA9EE0, "PPLighting pass-entry append/reuse helper"),
	(0x0126F680, "per-stage cached texture-record resource table"),
	(0x0126F6C4, "renderer/device object global A"),
	(0x0126F6C8, "renderer/device state object global B"),
	(0x0126F74C, "current NiD3DPass global"),
]

E7EB00_CALLS = [
	(0x00B7DD63, "caller A first E7EB00 call"),
	(0x00B7DE52, "caller B first E7EB00 call"),
	(0x00B7DE65, "caller B second E7EB00 call"),
	(0x00B7E200, "caller C first E7EB00 call"),
	(0x00B7E213, "caller C second E7EB00 call"),
	(0x00B7E225, "caller C third E7EB00 call"),
]

SCAN_PATTERNS = [
	"FUN_00e7eb00",
	"FUN_00e7ea00",
	"FUN_00e89410",
	"FUN_00e89060",
	"FUN_00ba9ee0",
	"FUN_00ba8ec0",
	"FUN_00ba8c50",
	"DAT_0126f680",
	"DAT_0126f6c4",
	"DAT_0126f6c8",
	"DAT_0126f74c",
	"0x8c4",
	"0xc0",
	"0xcc",
	"+ 0x4",
	"+0x4",
	"+ 0x8",
	"+0x8",
	"+ 0x9",
	"+0x9",
	"+ 0xb",
	"+0xb",
	"+ 0xc",
	"+0xc",
	"+ 0x10",
	"+0x10",
	"param_1[1]",
	"param_1[2]",
	"param_1 + 4",
	"param_1 + 8",
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
		if count > 180:
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
			reg_writes = find_register_writes_before(inst, ["ECX", "EDX", "EDI", "ESI", "EAX"], 40)
			for item in reg_writes:
				write("    recent %s write: 0x%08x %s %s ; %s" % (item[0], item[1], item[2], item[3], item[4]))
			pushes = collect_pushes_before(inst, arg_count, 48)
			arg_index = 0
			for item in pushes:
				write("    stack_arg%d from PUSH @ 0x%08x: %-24s ; %s" % (arg_index, item[0], item[1], item[2]))
				arg_index += 1
			write("    Raw short window:")
			print_short_window(inst, 14, 5)
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

def print_hypothesis():
	write("")
	write("=" * 70)
	write("Bridge contract questions")
	write("=" * 70)
	write("1. Are B7DD50/B7DDE0/B7E150 applying low-level texture records, not BA9EE0 PPLighting entries?")
	write("2. At every E7EB00 call, what is ECX, what is EDI, and do those registers carry record +4/+8 state?")
	write("3. Does any bridge caller retain a pointer back to the BA9EE0 entry, its +0x0B layer byte, or the type-3 material property?")
	write("4. If the bridge is lossy, native PBR must capture material arrays before the bridge and key by a proven owner/entry generation.")

def main():
	write("FNV PBR PPLIGHTING ENTRY TO TEXTURE RECORD BRIDGE AUDIT")
	print_hypothesis()
	for item in REF_TARGETS:
		find_refs_to(item[0], item[1])
	for item in BRIDGE_FUNCTIONS:
		find_and_print_calls_from(item[0], item[1])
	for item in DECOMPILE_FOCUS:
		decompile_at(item[0], item[1], item[2])
		scan_decompile_lines(item[0], item[1], SCAN_PATTERNS)
	for item in E7EB00_CALLS:
		print_disasm_range(item[0] - 0x30, item[0] + 0x28, item[1], item[0])
	for item in BRIDGE_FUNCTIONS:
		print_call_arg_windows_for_target(item[0], item[1], 0x00E7EB00, "low-level texture-record cache/apply", 2, 16)
	print_call_arg_windows_for_target(0x00E7EB00, "low-level texture-record cache/apply", 0x00E7EA00, "low-level texture-record resolver/bind", 1, 8)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_entry_to_texture_record_bridge_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
