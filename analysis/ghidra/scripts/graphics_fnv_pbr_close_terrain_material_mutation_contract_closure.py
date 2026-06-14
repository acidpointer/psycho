# @category Analysis
# @description Close FNV PBR close-terrain material mutation and cache invalidation contract

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00539960: "terrain texture writer callsite A",
	0x0053A090: "terrain texture writer callsite B",
	0x00592CF0: "terrain texture resolver/callback constructor",
	0x00592F30: "terrain texture resolver/callback slot target",
	0x00B66640: "terrain layer flag initializer",
	0x00B68450: "selector material array initializer",
	0x00B68660: "six material array writer",
	0x00B690D0: "selector material array related method",
	0x00BDB4A0: "selector setup +0xF0 variant",
	0x00BDF790: "selector setup +0xF4 main",
}

FOCUS_FUNCTIONS = [
	(0x00539960, "terrain texture writer callsite A", 30000),
	(0x0053A090, "terrain texture writer callsite B", 30000),
	(0x00592CF0, "terrain texture resolver/callback constructor", 22000),
	(0x00592F30, "terrain texture resolver/callback slot target", 22000),
	(0x00B66640, "terrain layer flag initializer", 22000),
	(0x00B68450, "selector material array initializer", 24000),
	(0x00B68660, "six material array writer", 26000),
	(0x00B690D0, "selector material array related method", 22000),
	(0x00BDB4A0, "selector setup +0xF0 variant", 30000),
	(0x00BDF790, "selector setup +0xF4 main", 30000),
]

REF_TARGETS = [
	(0x00592CF0, "terrain texture resolver/callback constructor"),
	(0x00592F30, "terrain texture resolver/callback slot target"),
	(0x00B66640, "terrain layer flag initializer"),
	(0x00B68450, "selector material array initializer"),
	(0x00B68660, "six material array writer"),
	(0x00B690D0, "selector material array related method"),
]

CALL_WINDOW_TARGETS = [
	(0x00B66640, "terrain layer flag initializer"),
	(0x00B68660, "six material array writer"),
	(0x00592CF0, "terrain texture resolver/callback constructor"),
	(0x00592F30, "terrain texture resolver/callback slot target"),
]

FIELD_PATTERNS = [
	"0xa8",
	"0xac",
	"0xb0",
	"0xb4",
	"0xb8",
	"0xbc",
	"0xc0",
	"0xc4",
	"0xc8",
	"0xcc",
	"0x90",
	"FUN_00b68450",
	"FUN_00b68660",
	"FUN_00b66640",
	"FUN_00592cf0",
	"FUN_00592f30",
	"InterlockedDecrement",
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

def read_u32(addr_int):
	try:
		value = memory.getInt(toAddr(addr_int))
		if value < 0:
			value += 0x100000000
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

def get_function(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	return func

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

def decompile_text_for_func(func):
	if func is None:
		return None
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		return result.getDecompiledFunction().getC()
	return None

def decompile_at(addr_int, label, max_len=12000):
	func = get_function(addr_int)
	write("")
	write("=" * 70)
	write("%s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return None
	faddr = func.getEntryPoint().getOffset()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, func.getBody().getNumAddresses()))
	if faddr != addr_int:
		write("  NOTE: requested 0x%08x is inside entry 0x%08x" % (addr_int, faddr))
	code = decompile_text_for_func(func)
	if code is None:
		write("  [decompilation failed]")
		return None
	write(code[:max_len])
	return code

def matched_lines(code, label):
	write("")
	write("=" * 70)
	write("MATCHED MUTATION LINES: %s" % label)
	write("=" * 70)
	if code is None:
		write("  [no code]")
		return
	lines = code.splitlines()
	count = 0
	for index in range(len(lines)):
		lower = lines[index].lower()
		for pattern in FIELD_PATTERNS:
			if pattern.lower() in lower:
				write("  L%-4d %s" % (index + 1, lines[index]))
				count += 1
				break
	write("  Total matched lines: %d" % count)

def find_refs_to(addr_int, label, limit):
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
		if count >= limit:
			write("  ... (truncated)")
			break
	write("  Total printed: %d refs" % count)

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

def print_ref_targets():
	for item in REF_TARGETS:
		find_refs_to(item[0], item[1], 120)

def decompile_focus_functions():
	for item in FOCUS_FUNCTIONS:
		code = decompile_at(item[0], item[1], item[2])
		matched_lines(code, item[1])

def print_call_windows_to_targets():
	write("")
	write("=" * 70)
	write("CALL WINDOWS TO MUTATION TARGETS")
	write("=" * 70)
	for target in CALL_WINDOW_TARGETS:
		refs = ref_mgr.getReferencesTo(toAddr(target[0]))
		count = 0
		while refs.hasNext():
			ref = refs.next()
			if not ref.getReferenceType().isCall():
				continue
			from_addr = ref.getFromAddress().getOffset()
			from_func = fm.getFunctionContaining(ref.getFromAddress())
			fname = from_func.getName() if from_func else "???"
			disasm_window(from_addr, 18, 10, "%s caller %s" % (target[1], fname))
			count += 1
			if count >= 24:
				write("  [call window limit reached for %s]" % target[1])
				break

def print_field_instruction_hits():
	write("")
	write("=" * 70)
	write("MATERIAL FIELD INSTRUCTION HITS")
	write("=" * 70)
	for item in FOCUS_FUNCTIONS:
		func = get_function(item[0])
		if func is None:
			continue
		write("")
		write("--- %s ---" % item[1])
		inst_iter = listing.getInstructions(func.getBody(), True)
		count = 0
		while inst_iter.hasNext():
			inst = inst_iter.next()
			text = inst.toString().lower()
			if "0xa8" in text or "0xac" in text or "0xb0" in text or "0xb4" in text or "0xb8" in text or "0xbc" in text or "0xc0" in text or "0xc4" in text or "0xc8" in text or "0xcc" in text:
				write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
				print_refs_from_instruction(inst)
				count += 1
		write("  Total field hits: %d" % count)

def main():
	write("FNV PBR CLOSE TERRAIN MATERIAL MUTATION CONTRACT CLOSURE")
	write("")
	write("Goal:")
	write("- Prove which functions mutate selector material arrays, layer flags, and active layer count.")
	write("- Decide whether selector snapshot generation must be incremented from B68660/B66640, not just setup callbacks.")
	write("- Recover callsite argument shape for a safe runtime hook or telemetry point.")
	print_ref_targets()
	decompile_focus_functions()
	print_call_windows_to_targets()
	print_field_instruction_hits()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_material_mutation_contract_closure.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
