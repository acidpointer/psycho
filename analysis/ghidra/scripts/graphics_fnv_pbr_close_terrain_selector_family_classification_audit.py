# @category Analysis
# @description Classify PPLighting selector families that share close-terrain setup slots

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00B55560: "shader-interface object selector cache",
	0x00B66640: "terrain layer flag initializer",
	0x00B68660: "six material array writer",
	0x00B79B00: "PPLighting selector constructor",
	0x00B79DE0: "PPLighting selector clone/constructor",
	0x00B7A380: "PPLighting selector factory",
	0x00B7AF80: "PPLighting current pass writer",
	0x00B7D200: "PPLighting pass setup slot +0x78",
	0x00B7DAB0: "PPLighting pass resource dispatcher",
	0x00BDB4A0: "PPLighting selector setup +0xF0 variant",
	0x00BDF790: "PPLighting selector setup +0xF4 main",
	0x00BE1F90: "BSShader::SetShaders",
	0x010AF2F8: "PPLighting shader selector vtable",
	0x011F91E0: "current draw record global",
	0x011FFE2C: "last selector object global",
	0x0126F74C: "current NiD3DPass global",
}

SHARED_TERRAIN_SETUP_VTABLES = [
	(0x010AE0F4, "candidate family A / material-array owner"),
	(0x010B8354, "candidate family B"),
	(0x010B935C, "candidate family C"),
	(0x010B94B4, "candidate family D"),
	(0x010B9934, "candidate family E"),
	(0x010BAC1C, "candidate family F"),
	(0x010BCB84, "candidate family G"),
]

KNOWN_SELECTOR_VTABLES = [
	(0x010AF2F8, "PPLighting selector index 1 vtable"),
]

VTABLE_OFFSETS = [
	0x00,
	0x04,
	0x08,
	0x0c,
	0x18,
	0x30,
	0x34,
	0x3c,
	0x4c,
	0x68,
	0x6c,
	0x78,
	0x7c,
	0x80,
	0x84,
	0x88,
	0x8c,
	0xc0,
	0xdc,
	0xf0,
	0xf4,
	0xf8,
	0x11c,
	0x144,
	0x148,
	0x14c,
	0x150,
	0x154,
]

SETUP_FUNCTIONS = [
	(0x00BDB4A0, "shared selector setup +0xF0 variant"),
	(0x00BDF790, "shared selector setup +0xF4 main"),
	(0x00B66640, "terrain layer flag initializer"),
	(0x00B68660, "six material array writer"),
	(0x00B99390, "draw selector setup dispatcher"),
	(0x00B994F0, "current draw dispatcher"),
]

SCAN_PATTERNS = [
	"0xa8",
	"0xac",
	"0xb0",
	"0xb4",
	"0xb8",
	"0xbc",
	"0xc0",
	"0xc4",
	"0xcc",
	"FUN_00b66640",
	"FUN_00b68660",
	"FUN_00bdb4a0",
	"FUN_00bdf790",
	"FUN_00b99390",
	"FUN_00b994f0",
	"DAT_011f91e0",
	"DAT_011ffe2c",
	"terrain",
	"land",
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

def print_ascii_near(base_int, label):
	write("")
	write("-" * 70)
	write("ASCII near 0x%08x (%s)" % (base_int, label))
	write("-" * 70)
	addr = base_int - 0x100
	end = base_int + 0x40
	found = 0
	while addr < end:
		text = read_c_string(addr, 120)
		if text is not None and len(text) >= 4:
			write("  0x%08x: %s" % (addr, text))
			found += 1
			addr += len(text) + 1
		else:
			addr += 1
	write("  Total strings: %d" % found)

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

def print_constructor_refs_for_vtable(base_int, label):
	find_refs_to(base_int, "%s vtable base" % label)
	entries = collect_ref_functions(base_int)
	count = 0
	for entry in entries:
		decompile_at(entry, "constructor/ref owner for %s" % label, 18000)
		scan_decompile_lines(entry, "constructor/ref owner for %s" % label, SCAN_PATTERNS)
		count += 1
		if count >= 8:
			write("  [constructor/ref owner limit reached]")
			break

def print_slot_ref_windows(base_int, label):
	for offset in [0xf0, 0xf4]:
		ptr = read_u32(base_int + offset)
		find_refs_to(base_int + offset, "%s vtable slot +0x%03x storage" % (label, offset))
		if ptr is not None:
			find_refs_to(ptr, "%s vtable slot +0x%03x target" % (label, offset))

def print_shared_family_candidate(item):
	base_int = item[0]
	label = item[1]
	print_ascii_near(base_int, label)
	print_vtable_slots(base_int, label)
	print_constructor_refs_for_vtable(base_int, label)
	print_slot_ref_windows(base_int, label)

def print_known_selector(item):
	base_int = item[0]
	label = item[1]
	print_ascii_near(base_int, label)
	print_vtable_slots(base_int, label)
	print_constructor_refs_for_vtable(base_int, label)

def print_setup_functions():
	for item in SETUP_FUNCTIONS:
		find_refs_to(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])
		decompile_at(item[0], item[1], 26000)
		scan_decompile_lines(item[0], item[1], SCAN_PATTERNS)

def print_manual_call_windows():
	disasm_window(0x00B99390, 8, 80, "selector setup dispatcher virtual calls")
	disasm_window(0x00B994F0, 12, 120, "current draw dispatcher selector source")
	disasm_window(0x00BDB4A0, 12, 140, "shared setup variant prologue")
	disasm_window(0x00BDF790, 12, 140, "shared setup main prologue")

def main():
	write("FNV PBR CLOSE TERRAIN SELECTOR FAMILY CLASSIFICATION AUDIT")
	write("")
	write("Goal:")
	write("- Classify selector/vtable families that share BDB4A0/BDF790 setup slots.")
	write("- Find constructor/ref owners for each candidate family.")
	write("- Prove whether any vtable identity can safely distinguish true close landscape from land-ish helpers/interiors.")
	write("- If no static vtable discriminator exists, the runtime hook must require stronger selector/pass/material proof and default to no-op.")
	for item in SHARED_TERRAIN_SETUP_VTABLES:
		print_shared_family_candidate(item)
	for item in KNOWN_SELECTOR_VTABLES:
		print_known_selector(item)
	print_setup_functions()
	print_manual_call_windows()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_close_terrain_selector_family_classification_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
