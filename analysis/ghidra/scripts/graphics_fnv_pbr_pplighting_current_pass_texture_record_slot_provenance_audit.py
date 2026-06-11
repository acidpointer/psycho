# @category Analysis
# @description Audit FNV current-pass texture-record slot provenance for native PBR material binding

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
	0x00B7DD50: "current-pass texture-record apply caller A",
	0x00B7DDE0: "current-pass texture-record writer/apply caller B",
	0x00B7DED0: "alternate current-pass texture-record caller",
	0x00B7DFE0: "alternate current-pass texture-record caller",
	0x00B7E150: "current-pass texture-record writer/apply caller C",
	0x00B98E80: "caller of B7DDE0/B7E150",
	0x00B99390: "caller of B7DD50",
	0x00BCA760: "E7EB00 caller candidate",
	0x00BE2170: "current-pass entry apply neighbor",
	0x00BE21B0: "current-pass entry apply neighbor",
	0x00C04310: "E7EB00 caller candidate",
	0x00C03230: "active object resource/state getter used before E7EB00",
	0x00E7DE90: "low-level texture-record pre-resolver/helper",
	0x00E7EA00: "low-level texture-record resolver/bind",
	0x00E7EB00: "low-level texture-record cache/apply",
	0x00E7F8D0: "E7EB00 caller candidate near raw call",
	0x00E826D0: "shader-interface apply dispatcher",
	0x011F91E0: "current geometry/object global",
	0x011F951C: "global fallback resource used by B7E150 branch",
	0x0126F680: "per-stage cached texture-record resource table",
	0x0126F74C: "current NiD3DPass global",
}

FOCUS_FUNCTIONS = [
	(0x00B99390, "caller of B7DD50", 26000),
	(0x00B98E80, "caller of B7DDE0/B7E150", 30000),
	(0x00B7DD50, "current-pass texture-record apply caller A", 18000),
	(0x00B7DDE0, "current-pass texture-record writer/apply caller B", 24000),
	(0x00B7E150, "current-pass texture-record writer/apply caller C", 30000),
	(0x00B7DED0, "alternate current-pass texture-record caller", 22000),
	(0x00B7DFE0, "alternate current-pass texture-record caller", 22000),
	(0x00BCA760, "E7EB00 caller candidate", 24000),
	(0x00BE2170, "current-pass entry apply neighbor", 16000),
	(0x00BE21B0, "current-pass entry apply neighbor", 16000),
	(0x00C04310, "E7EB00 caller candidate", 20000),
	(0x00E7EB00, "low-level texture-record cache/apply", 14000),
	(0x00E7EA00, "low-level texture-record resolver/bind", 18000),
]

REF_TARGETS = [
	(0x00B7DD50, "current-pass texture-record apply caller A"),
	(0x00B7DDE0, "current-pass texture-record writer/apply caller B"),
	(0x00B7E150, "current-pass texture-record writer/apply caller C"),
	(0x00B7DED0, "alternate current-pass texture-record caller"),
	(0x00B7DFE0, "alternate current-pass texture-record caller"),
	(0x00E7EB00, "low-level texture-record cache/apply"),
	(0x00E7EA00, "low-level texture-record resolver/bind"),
	(0x00C03230, "active object resource/state getter used before E7EB00"),
	(0x00E7DE90, "low-level texture-record pre-resolver/helper"),
	(0x011F91E0, "current geometry/object global"),
	(0x011F951C, "global fallback resource used by B7E150 branch"),
	(0x0126F680, "per-stage cached texture-record resource table"),
	(0x0126F74C, "current NiD3DPass global"),
]

E7EB00_CALLSITES = [
	(0x00B7DD63, "B7DD50 current pass slot +0x14"),
	(0x00B7DE52, "B7DDE0 current pass slot +0"),
	(0x00B7DE65, "B7DDE0 current pass slot +4"),
	(0x00B7DF45, "B7DED0 current pass slot candidate A"),
	(0x00B7DF58, "B7DED0 current pass slot candidate B"),
	(0x00B7E059, "B7DFE0 current pass slot candidate A"),
	(0x00B7E06C, "B7DFE0 current pass slot candidate B"),
	(0x00B7E200, "B7E150 current pass slot +0"),
	(0x00B7E213, "B7E150 current pass slot +4"),
	(0x00B7E225, "B7E150 current pass slot +0xC"),
	(0x00BCA913, "BCA760 E7EB00 call A"),
	(0x00BCA92D, "BCA760 E7EB00 call B"),
	(0x00BE219A, "BE2170 E7EB00 call"),
	(0x00BE21E2, "BE21B0 E7EB00 call"),
	(0x00C043A4, "C04310 E7EB00 call"),
	(0x00B89CF7, "raw E7EB00 call with unknown function A"),
	(0x00B89D68, "raw E7EB00 call with unknown function B"),
	(0x00BA627E, "raw E7EB00 call with unknown function C"),
	(0x00BB66EE, "raw E7EB00 call with unknown function D"),
	(0x00BC8D82, "raw E7EB00 call with unknown function E"),
	(0x00E7F8D3, "E7F8D0 E7EB00 call"),
	(0x00BCBCD0, "raw E7EB00 jump"),
]

CALL_TARGETS = [
	(0x00B7DD50, "current-pass texture-record apply caller A", 2),
	(0x00B7DDE0, "current-pass texture-record writer/apply caller B", 2),
	(0x00B7E150, "current-pass texture-record writer/apply caller C", 2),
	(0x00C03230, "active object resource/state getter used before E7EB00", 3),
	(0x00E7DE90, "low-level texture-record pre-resolver/helper", 2),
	(0x00E7EB00, "low-level texture-record cache/apply", 2),
]

SCAN_PATTERNS = [
	"FUN_00b7dd50",
	"FUN_00b7dde0",
	"FUN_00b7e150",
	"FUN_00e7eb00",
	"FUN_00e7ea00",
	"FUN_00c03230",
	"FUN_00e7de90",
	"DAT_0126f74c",
	"DAT_011f91e0",
	"DAT_011f951c",
	"param_1 + 0xc",
	"+ 0x24",
	"+0x24",
	"+ 0x14",
	"+0x14",
	"+ 0xc",
	"+0xc",
	"+ 0x8",
	"+0x8",
	"+ 0x4",
	"+0x4",
	"+ 0xe0",
	"+0xe0",
	"+ 0xf4",
	"+0xf4",
	"piVar1[0x2b]",
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
		if count > 220:
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
			reg_writes = find_register_writes_before(inst, ["ECX", "EDX", "EDI", "ESI", "EBX", "EAX"], 48)
			for item in reg_writes:
				write("    recent %s write: 0x%08x %s %s ; %s" % (item[0], item[1], item[2], item[3], item[4]))
			pushes = collect_pushes_before(inst, arg_count, 56)
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

def print_contract_header():
	write("")
	write("=" * 70)
	write("Current-pass texture-record provenance questions")
	write("=" * 70)
	write("1. Who fills records under *(DAT_0126F74C +0x24), especially slots +0, +4, +0xC, and +0x14?")
	write("2. Is the source object at B7DDE0/B7E150 param_1 +0xC recoverable from selector/material state?")
	write("3. Do any E7EB00 callers receive a BA9EE0 entry pointer, BDAF10 layer byte, or type-3 material property?")
	write("4. If not, native PBR must capture material arrays before current-pass texture-record application.")

def main():
	write("FNV PBR PPLIGHTING CURRENT-PASS TEXTURE-RECORD SLOT PROVENANCE AUDIT")
	print_contract_header()
	for item in REF_TARGETS:
		find_refs_to(item[0], item[1])
	for item in FOCUS_FUNCTIONS:
		find_and_print_calls_from(item[0], item[1])
	for item in FOCUS_FUNCTIONS:
		decompile_at(item[0], item[1], item[2])
		scan_decompile_lines(item[0], item[1], SCAN_PATTERNS)
	for item in E7EB00_CALLSITES:
		print_disasm_range(item[0] - 0x34, item[0] + 0x2c, item[1], item[0])
	for focus in FOCUS_FUNCTIONS:
		for target in CALL_TARGETS:
			print_call_arg_windows_for_target(focus[0], focus[1], target[0], target[1], target[2], 18)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_current_pass_texture_record_slot_provenance_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
