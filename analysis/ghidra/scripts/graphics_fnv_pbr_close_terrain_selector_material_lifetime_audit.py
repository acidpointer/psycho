# @category Analysis
# @description Audit close-terrain selector material-array lifetime and cache invalidation points

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
	0x00B66640: "terrain layer flag initializer",
	0x00B68660: "six material array writer",
	0x00B79B00: "PPLighting selector constructor",
	0x00B79DE0: "PPLighting selector clone/constructor",
	0x00B7A380: "PPLighting selector factory",
	0x00B99390: "draw selector setup dispatcher",
	0x00B994F0: "current draw dispatcher",
	0x00BDB4A0: "PPLighting selector setup +0xF0 variant",
	0x00BDF790: "PPLighting selector setup +0xF4 main",
	0x010AE0F4: "candidate material-array owner vtable",
	0x010AF2F8: "PPLighting shader selector vtable",
	0x011F91E0: "current draw record global",
	0x011FFE2C: "last selector object global",
}

FOCUS_FUNCTIONS = [
	(0x00539960, "terrain texture writer callsite A", 20000),
	(0x0053A090, "terrain texture writer callsite B", 20000),
	(0x00B66640, "terrain layer flag initializer", 22000),
	(0x00B68660, "six material array writer", 24000),
	(0x00B79B00, "PPLighting selector constructor", 24000),
	(0x00B79DE0, "PPLighting selector clone/constructor", 24000),
	(0x00B7A380, "PPLighting selector factory", 24000),
	(0x00B99390, "draw selector setup dispatcher", 18000),
	(0x00B994F0, "current draw dispatcher", 22000),
	(0x00BDB4A0, "PPLighting selector setup +0xF0 variant", 28000),
	(0x00BDF790, "PPLighting selector setup +0xF4 main", 30000),
]

REF_TARGETS = [
	(0x00B66640, "terrain layer flag initializer"),
	(0x00B68660, "six material array writer"),
	(0x00B79B00, "PPLighting selector constructor"),
	(0x00B79DE0, "PPLighting selector clone/constructor"),
	(0x00B99390, "draw selector setup dispatcher"),
	(0x00BDB4A0, "PPLighting selector setup +0xF0 variant"),
	(0x00BDF790, "PPLighting selector setup +0xF4 main"),
	(0x010AE0F4, "candidate material-array owner vtable"),
	(0x010AF2F8, "PPLighting shader selector vtable"),
	(0x011F91E0, "current draw record global"),
	(0x011FFE2C, "last selector object global"),
]

FIELD_PATTERNS = [
	"+ 0x3c",
	"+0x3c",
	"+ 0xa8",
	"+0xa8",
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
	"[0xf]",
	"[0x2a]",
	"[0x2b]",
	"[0x2c]",
	"[0x2d]",
	"[0x2e]",
	"[0x2f]",
	"[0x30]",
	"[0x31]",
	"[0x33]",
	"FUN_00b66640",
	"FUN_00b68660",
	"FUN_00bdb4a0",
	"FUN_00bdf790",
	"DAT_011f91e0",
	"DAT_011ffe2c",
]

VTABLES = [
	(0x010AE0F4, "candidate material-array owner vtable"),
	(0x010AF2F8, "PPLighting shader selector vtable"),
]

VTABLE_OFFSETS = [
	0x00,
	0x04,
	0x08,
	0x0c,
	0x30,
	0x34,
	0x3c,
	0x78,
	0x7c,
	0x80,
	0x84,
	0x88,
	0x8c,
	0xdc,
	0xf0,
	0xf4,
	0x144,
	0x148,
	0x14c,
	0x150,
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
		return None
	faddr = func.getEntryPoint().getOffset()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, func.getBody().getNumAddresses()))
	if faddr != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	code = decompile_text_for_func(func)
	if code is None:
		write("  [decompilation failed]")
		return None
	write(code[:max_len])
	return code

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
	write("  Total printed: %d refs" % count)

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

def scan_decompile_lines(addr_int, label, patterns):
	write("")
	write("=" * 70)
	write("Matched decompile lines: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = get_function(addr_int)
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
		rtype = ref.getReferenceType()
		if rtype.isCall() or rtype.isJump() or rtype.isData() or rtype.isRead() or rtype.isWrite():
			write("      ref %-18s -> 0x%08x %s" % (str(rtype), target.getOffset(), label_for(target.getOffset())))

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("=" * 70)
	write("DISASM: %s around 0x%08x" % (label, center_int))
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
		marker = "=> " if cur.getAddress().getOffset() == inst.getAddress().getOffset() else "   "
		write("%s0x%08x: %-58s %s" % (marker, cur.getAddress().getOffset(), full_inst_text(cur), label_for(cur.getAddress().getOffset())))
		print_refs_from_instruction(cur)
		cur = listing.getInstructionAfter(cur.getAddress())
		count += 1

def print_instruction_field_hits(addr_int, label):
	write("")
	write("=" * 70)
	write("FIELD INSTRUCTION HITS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = get_function(addr_int)
	if func is None:
		write("  [function not found]")
		return
	count = 0
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = full_inst_text(inst).lower()
		matched = False
		for pattern in FIELD_PATTERNS:
			if pattern.lower() in text:
				matched = True
		if matched:
			write("  0x%08x: %-58s %s" % (inst.getAddress().getOffset(), full_inst_text(inst), label_for(inst.getAddress().getOffset())))
			print_refs_from_instruction(inst)
			count += 1
	write("  Total field hits: %d" % count)

def print_vtable_slots(base_int, label):
	write("")
	write("=" * 70)
	write("VTABLE SLOTS: %s base 0x%08x" % (label, base_int))
	write("=" * 70)
	for offset in VTABLE_OFFSETS:
		ptr = read_u32(base_int + offset)
		write("  +0x%03x @ 0x%08x -> 0x%08x %s" % (offset, base_int + offset, ptr if ptr is not None else 0, label_for(ptr)))

def collect_ref_functions(addr_int):
	entries = []
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	while refs.hasNext():
		ref = refs.next()
		func = fm.getFunctionContaining(ref.getFromAddress())
		if func is None:
			continue
		entry = func.getEntryPoint().getOffset()
		already = False
		for item in entries:
			if item == entry:
				already = True
		if not already:
			entries.append(entry)
	return entries

def decompile_ref_owners(addr_int, label, limit):
	entries = collect_ref_functions(addr_int)
	count = 0
	for entry in entries:
		decompile_at(entry, "ref owner for %s" % label, 18000)
		scan_decompile_lines(entry, "ref owner for %s" % label, FIELD_PATTERNS)
		print_instruction_field_hits(entry, "ref owner for %s" % label)
		count += 1
		if count >= limit:
			write("  [ref owner limit reached]")
			break

def print_all_refs():
	for item in REF_TARGETS:
		find_refs_to(item[0], item[1])

def print_all_focus_functions():
	for item in FOCUS_FUNCTIONS:
		find_and_print_calls_from(item[0], item[1])
		decompile_at(item[0], item[1], item[2])
		scan_decompile_lines(item[0], item[1], FIELD_PATTERNS)
		print_instruction_field_hits(item[0], item[1])

def print_vtable_lifetime_context():
	for item in VTABLES:
		print_vtable_slots(item[0], item[1])
		find_refs_to(item[0], item[1])
		decompile_ref_owners(item[0], item[1], 8)

def print_manual_lifetime_windows():
	disasm_window(0x00B66640, 12, 120, "terrain layer flag initializer")
	disasm_window(0x00B68660, 12, 160, "six material array writer")
	disasm_window(0x00B99390, 10, 95, "selector setup dispatcher")
	disasm_window(0x00B994F0, 10, 140, "current draw dispatcher")

def main():
	write("FNV PBR CLOSE TERRAIN SELECTOR MATERIAL LIFETIME AUDIT")
	write("")
	write("Goal:")
	write("- Find writers and clearers for selector material arrays +0xAC..+0xC0, layer flags +0xC4/+0xCC, layer kind/count +0xA8, and pass list +0x3C.")
	write("- Prove whether selector pointer is a stable cache key or needs generation/clear rules.")
	write("- Prove whether setup callbacks always run after material-array mutation before final texture binding.")
	print_all_refs()
	print_vtable_lifetime_context()
	print_all_focus_functions()
	print_manual_lifetime_windows()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_selector_material_lifetime_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
