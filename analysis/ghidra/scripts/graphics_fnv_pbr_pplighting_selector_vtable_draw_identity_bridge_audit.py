# @category Analysis
# @description Audit FNV PPLighting selector vtable slots and current draw identity bridge for native PBR

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00B7DDE0: "current-pass texture-record writer/apply caller B",
	0x00B7DED0: "alternate current-pass texture-record caller",
	0x00B7DFE0: "alternate current-pass texture-record caller",
	0x00B7E150: "current-pass texture-record writer/apply caller C",
	0x00B98E80: "current-pass draw dispatch using selector at *draw +0xC0",
	0x00B99390: "current-pass selector setup dispatcher",
	0x00B994F0: "current draw dispatcher and DAT_011F91E0 writer",
	0x00BDAF10: "PPLighting diffuse/glow material predicate helper",
	0x00BDB4A0: "selector vtable setup slot candidate",
	0x00BDF790: "selector vtable setup slot candidate",
	0x00BD4BA0: "PPLighting shader interface apply scope",
	0x00E826D0: "shader-interface apply dispatcher",
	0x011F4748: "current renderer/pass context global",
	0x011F91E0: "current draw record global",
	0x011FFE2C: "last selector object global",
	0x0126F74C: "current NiD3DPass global",
}

FOCUS_FUNCTIONS = [
	(0x00B994F0, "current draw dispatcher and selector pointer source", 26000),
	(0x00B99390, "selector setup virtual dispatcher", 18000),
	(0x00B98E80, "current-pass draw dispatch using selector object", 26000),
	(0x00BD4BA0, "PPLighting shader interface apply scope", 22000),
	(0x00BDB4A0, "selector vtable setup slot candidate BDB4A0", 26000),
	(0x00BDF790, "selector vtable setup slot candidate BDF790", 26000),
]

REF_TARGETS = [
	(0x00BDB4A0, "selector vtable setup slot candidate BDB4A0"),
	(0x00BDF790, "selector vtable setup slot candidate BDF790"),
	(0x00BD4BA0, "PPLighting shader interface apply scope"),
	(0x00E826D0, "shader-interface apply dispatcher"),
	(0x00B99390, "selector setup virtual dispatcher"),
	(0x00B98E80, "current-pass draw dispatch"),
	(0x00B994F0, "current draw dispatcher"),
	(0x011F91E0, "current draw record global"),
	(0x011F4748, "current renderer/pass context global"),
	(0x011FFE2C, "last selector object global"),
]

VTABLE_SLOT_OFFSETS = [
	0x30,
	0x34,
	0x6c,
	0x78,
	0x7c,
	0x80,
	0x84,
	0x88,
	0x8c,
	0xdc,
	0xf0,
	0xf4,
	0xf8,
	0xfc,
	0x100,
	0x110,
	0x114,
	0x154,
]

RAW_WINDOWS = [
	(0x00B99390, 0x00B99495, "B99390 full selector virtual setup dispatch"),
	(0x00B99520, 0x00B99555, "B994F0 -> B99390 selector setup call"),
	(0x00B995D0, 0x00B99605, "B994F0 -> B98E80 current draw dispatch call"),
	(0x00B98E80, 0x00B98ED5, "B98E80 builds DAT_011F4748 +0x0C from *draw +0x9C"),
	(0x00B98E80, 0x00B99095, "B98E80 selector apply virtual dispatch"),
	(0x00BD4BA0, 0x00BD4D00, "BD4BA0 final shader interface apply scope"),
]

SCAN_PATTERNS = [
	"DAT_011f91e0",
	"DAT_011f4748",
	"DAT_011ffe2c",
	"DAT_0126f74c",
	"FUN_00b99390",
	"FUN_00b98e80",
	"FUN_00bdb4a0",
	"FUN_00bdf790",
	"+ 0xc0",
	"+0xc0",
	"[0x30]",
	"piVar3[0x30]",
	"+ 0x3c",
	"+0x3c",
	"[0xf]",
	"+ 0xf0",
	"+0xf0",
	"+ 0xf4",
	"+0xf4",
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
	"+ 0x8c",
	"+0x8c",
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

def collect_ref_offsets(addr_int):
	offsets = []
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	while refs.hasNext():
		ref = refs.next()
		offsets.append(ref.getFromAddress().getOffset())
	return offsets

def add_unique(values, value):
	if value is None:
		return
	for item in values:
		if item == value:
			return
	values.append(value)

def collect_candidate_vtable_bases():
	bases = []
	bdb4a0_refs = collect_ref_offsets(0x00BDB4A0)
	bdf790_refs = collect_ref_offsets(0x00BDF790)
	bd4ba0_refs = collect_ref_offsets(0x00BD4BA0)
	e826d0_refs = collect_ref_offsets(0x00E826D0)
	for ref in bdb4a0_refs:
		add_unique(bases, ref - 0xf0)
	for ref in bdf790_refs:
		add_unique(bases, ref - 0xf4)
	for ref in bd4ba0_refs:
		add_unique(bases, ref - 0x78)
	for ref in e826d0_refs:
		add_unique(bases, ref - 0x78)
	return bases

def print_vtable_slots(base_int, label):
	write("")
	write("=" * 70)
	write("Candidate vtable slots: %s base 0x%08x" % (label, base_int))
	write("=" * 70)
	for offset in VTABLE_SLOT_OFFSETS:
		ptr = read_u32(base_int + offset)
		write("  +0x%03x @ 0x%08x -> 0x%08x %s" % (offset, base_int + offset, ptr if ptr is not None else 0, label_for(ptr)))

def print_candidate_vtables():
	write("")
	write("=" * 70)
	write("Selector/apply vtable candidate bases")
	write("=" * 70)
	bdb4a0_refs = collect_ref_offsets(0x00BDB4A0)
	for ref in bdb4a0_refs:
		write("  BDB4A0 data ref 0x%08x -> candidate selector vtable base 0x%08x if slot +0xF0" % (ref, ref - 0xf0))
	bdf790_refs = collect_ref_offsets(0x00BDF790)
	for ref in bdf790_refs:
		write("  BDF790 data ref 0x%08x -> candidate selector vtable base 0x%08x if slot +0xF4" % (ref, ref - 0xf4))
	bd4ba0_refs = collect_ref_offsets(0x00BD4BA0)
	for ref in bd4ba0_refs:
		write("  BD4BA0 data ref 0x%08x -> candidate apply vtable base 0x%08x if slot +0x78" % (ref, ref - 0x78))
	e826d0_refs = collect_ref_offsets(0x00E826D0)
	for ref in e826d0_refs:
		write("  E826D0 data ref 0x%08x -> candidate apply vtable base 0x%08x if slot +0x78" % (ref, ref - 0x78))
	bases = collect_candidate_vtable_bases()
	for base in bases:
		print_vtable_slots(base, label_for(base))

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
	write("Selector vtable draw-identity bridge questions")
	write("=" * 70)
	write("1. Are BDB4A0/BDF790 data refs selector vtable slots +0xF0/+0xF4 called by B99390?")
	write("2. Does B994F0 pass *( *current_draw +0xC0) into setup and B98E80 use the same selector pointer?")
	write("3. Can final apply recover the same selector pointer from *DAT_011F91E0 for a side-table key?")

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
		print_disasm_range(item[0], item[1], item[2], item[0])

def main():
	write("FNV PBR PPLIGHTING SELECTOR VTABLE DRAW IDENTITY BRIDGE AUDIT")
	print_contract_header()
	print_all_refs()
	print_candidate_vtables()
	print_all_calls()
	print_all_decompiles()
	print_all_raw_windows()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_selector_vtable_draw_identity_bridge_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
