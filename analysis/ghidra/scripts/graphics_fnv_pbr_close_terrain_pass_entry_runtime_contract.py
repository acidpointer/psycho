# @category Analysis
# @description Close FNV PBR close-terrain pass-entry runtime row contract

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00B7AF80: "PPLighting current pass writer",
	0x00B7DAB0: "PPLighting pass-entry shader resource dispatcher",
	0x00B98E80: "current draw apply dispatcher",
	0x00B994F0: "current draw dispatcher",
	0x00BA8C50: "pass-entry arg storage helper",
	0x00BA8D30: "pass-entry list grow helper",
	0x00BA8EC0: "pass-entry constructor",
	0x00BA9EE0: "pass-entry append/reuse helper",
	0x00BD4BA0: "current pass shader-interface apply",
	0x00BDAC00: "land/specular zero-resource row helper",
	0x00BDAF10: "diffuse/glow material row helper",
	0x00BDB4A0: "selector setup +0xF0 variant",
	0x00BDF3E0: "LandO/light-resource row helper",
	0x00BDF650: "PPLighting row helper BDF650",
	0x00BDF6C0: "PPLighting row helper BDF6C0",
	0x00BDF790: "selector setup +0xF4 main",
	0x00BE1F90: "BSShader::SetShaders",
	0x011F91E0: "current geometry slot global",
	0x011FFE2C: "last selector cache global",
	0x0126F74C: "current pass global",
}

FOCUS_FUNCTIONS = [
	(0x00B7AF80, "PPLighting current pass writer", 22000),
	(0x00B7DAB0, "PPLighting pass-entry shader resource dispatcher", 26000),
	(0x00B98E80, "current draw apply dispatcher", 22000),
	(0x00B994F0, "current draw dispatcher", 22000),
	(0x00BA8C50, "pass-entry arg storage helper", 18000),
	(0x00BA8D30, "pass-entry list grow helper", 18000),
	(0x00BA8EC0, "pass-entry constructor", 18000),
	(0x00BA9EE0, "pass-entry append/reuse helper", 22000),
	(0x00BD4BA0, "current pass shader-interface apply", 26000),
	(0x00BDAC00, "land/specular zero-resource row helper", 24000),
	(0x00BDAF10, "diffuse/glow material row helper", 28000),
	(0x00BDF3E0, "LandO/light-resource row helper", 24000),
	(0x00BDF650, "PPLighting row helper BDF650", 22000),
	(0x00BDF6C0, "PPLighting row helper BDF6C0", 22000),
	(0x00BDF790, "selector setup +0xF4 main", 32000),
]

REF_TARGETS = [
	(0x00BA9EE0, "pass-entry append/reuse helper"),
	(0x00BA8C50, "pass-entry arg storage helper"),
	(0x00BA8EC0, "pass-entry constructor"),
	(0x00BA8D30, "pass-entry list grow helper"),
	(0x00B7DAB0, "PPLighting pass-entry shader resource dispatcher"),
	(0x00BD4BA0, "current pass shader-interface apply"),
	(0x011F91E0, "current geometry slot global"),
	(0x011FFE2C, "last selector cache global"),
	(0x0126F74C, "current pass global"),
]

SCAN_PATTERNS = [
	"FUN_00ba9ee0",
	"FUN_00ba8c50",
	"FUN_00ba8ec0",
	"FUN_00ba8d30",
	"FUN_00b7dab0",
	"FUN_00bd4ba0",
	"FUN_00bdac00",
	"FUN_00bdaf10",
	"FUN_00bdf3e0",
	"FUN_00bdf650",
	"FUN_00bdf6c0",
	"+ 0x3c",
	"+0x3c",
	"+ 0x10",
	"+0x10",
	"+ 0xc",
	"+0xc",
	"+ 0xb",
	"+0xb",
	"+ 0x9",
	"+0x9",
	"+ 0x7",
	"+0x7",
	"0x93",
	"0x94",
	"0x14a",
	"0x14b",
	"0x14c",
	"0x14d",
	"0x14e",
	"0x14f",
	"0x150",
	"0x151",
	"0x152",
	"0x1f1",
	"0x1f2",
	"0x1f3",
	"0x1f4",
	"0x1f5",
	"0x230",
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

def get_function(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	return func

def decompile_text(addr_int):
	func = get_function(addr_int)
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
		if count >= 160:
			write("  ... (truncated)")
			break
	write("  Total printed: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	func = get_function(addr_int)
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
				target = ref.getToAddress()
				taddr = target.getOffset()
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), taddr, label_for(taddr)))
				count += 1
	write("  Total: %d calls" % count)

def instruction_before_steps(inst, steps):
	cur = inst
	index = 0
	while cur is not None and index < steps:
		prev = listing.getInstructionBefore(cur.getAddress())
		if prev is None:
			break
		cur = prev
		index += 1
	return cur

def print_refs_from_instruction(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		target = ref.getToAddress()
		if target is None:
			continue
		write("      ref %-18s -> 0x%08x %s" % (str(ref.getReferenceType()), target.getOffset(), label_for(target.getOffset())))

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("=" * 70)
	write("DISASM: %s around 0x%08x" % (label, center_int))
	write("=" * 70)
	inst = listing.getInstructionContaining(toAddr(center_int))
	if inst is None:
		write("  [instruction not found]")
		return
	cur = instruction_before_steps(inst, before_count)
	count = 0
	while cur is not None and count <= before_count + after_count:
		prefix = "=> " if cur.getAddress().getOffset() == inst.getAddress().getOffset() else "   "
		func = fm.getFunctionContaining(cur.getAddress())
		fname = func.getName() if func else "???"
		write("%s0x%08x: %-58s %s" % (prefix, cur.getAddress().getOffset(), cur.toString(), fname))
		print_refs_from_instruction(cur)
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
	count = 0
	for line in lines:
		lower = line.lower()
		for pattern in SCAN_PATTERNS:
			if pattern.lower() in lower:
				write("  %s" % line)
				count += 1
				break
		if count >= 220:
			write("  ... (truncated)")
			break
	write("  Total matched lines: %d" % count)

def collect_push_args_before_call(call_inst, max_args):
	args = []
	cur = listing.getInstructionBefore(call_inst.getAddress())
	scanned = 0
	while cur is not None and scanned < 40 and len(args) < max_args:
		text = cur.toString()
		upper = text.upper()
		if upper.startswith("PUSH"):
			arg = text[4:].strip()
			args.append((cur.getAddress().getOffset(), arg, text))
		cur = listing.getInstructionBefore(cur.getAddress())
		scanned += 1
	return args

def print_ba9ee0_stack_contract(call_inst, owner_label):
	write("")
	write("-" * 70)
	write("BA9EE0 STACK-NORMALIZED ARGS: %s call @ 0x%08x" % (owner_label, call_inst.getAddress().getOffset()))
	write("-" * 70)
	write("  ECX at call is the selector pass-entry list. Stack pushes closest to CALL are param_2, param_3, ...")
	args = collect_push_args_before_call(call_inst, 8)
	index = 0
	while index < len(args):
		item = args[index]
		param_name = "param_%d" % (index + 2)
		meaning = ""
		if index == 0:
			meaning = "resource/owner"
		elif index == 1:
			meaning = "row id low word"
		elif index == 2:
			meaning = "selector flag byte"
		else:
			meaning = "arg slot %d copied into entry +0x0C" % (index - 3)
		write("  %-8s @ 0x%08x %-28s ; %s" % (param_name, item[0], item[1], meaning))
		index += 1

def print_all_ba9ee0_call_contracts():
	write("")
	write("=" * 70)
	write("BA9EE0 CALLS WITH NORMALIZED ROW ARGUMENTS")
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(0x00BA9EE0))
	seen = {}
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_addr = ref.getFromAddress()
		if seen.get(from_addr.getOffset()) is not None:
			continue
		seen[from_addr.getOffset()] = 1
		inst = listing.getInstructionContaining(from_addr)
		if inst is None:
			continue
		owner = fm.getFunctionContaining(from_addr)
		owner_label = owner.getName() if owner else "???"
		print_ba9ee0_stack_contract(inst, owner_label)
		disasm_window(from_addr.getOffset(), 18, 12, "%s -> BA9EE0" % owner_label)
		count += 1
		if count >= 120:
			write("  ... BA9EE0 call list truncated")
			break
	write("  Total BA9EE0 calls printed: %d" % count)

def decompile_focus_functions():
	for item in FOCUS_FUNCTIONS:
		decompile_at(item[0], item[1], item[2])
		find_and_print_calls_from(item[0], item[1])
		scan_patterns(item[0], item[1])

def print_reference_targets():
	for item in REF_TARGETS:
		find_refs_to(item[0], item[1])

def main():
	write("FNV PBR CLOSE TERRAIN PASS-ENTRY RUNTIME CONTRACT")
	write("")
	write("Questions:")
	write("1. Which pass-entry rows does vanilla build for close terrain and adjacent land helpers?")
	write("2. Which BA9EE0 param_3 row IDs map to material arrays, zero-resource land/spec rows, and LandO/light rows?")
	write("3. What exactly is stored in entry +0x09/+0x0A arg counts, +0x0B layer byte, and +0x0C arg table?")
	write("4. Can runtime PBR replacement key from selector +0x3C rows instead of shader pair alone?")
	write("")
	write("Runtime probe fields added in omv should be compared against this output:")
	write("  list +0x04 entry pointers, +0x08 count_low, +0x0C capacity, +0x0E grow_count, +0x10 active_count")
	write("  entry +0x00 resource, +0x04 row, +0x07 selector_flag, +0x09 arg_count, +0x0A arg_capacity, +0x0B layer, +0x0C args")
	print_reference_targets()
	decompile_focus_functions()
	print_all_ba9ee0_call_contracts()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_pass_entry_runtime_contract.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
