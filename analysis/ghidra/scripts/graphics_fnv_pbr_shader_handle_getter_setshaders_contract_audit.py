# @category Analysis
# @description Audit FNV PBR shader handle getter slots and SetShaders binding contract

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00BE1F90: "BSShader::SetShaders raw entry",
	0x0126F74C: "Current NiD3DPass global",
	0x00BE0FE0: "BSShader::CreateVertexShader",
	0x00BE1750: "BSShader::CreatePixelShader",
	0x010EF87C: "NiD3DVertexShader vtable",
	0x010EF7D4: "NiD3DPixelShader vtable",
	0x00BE0B10: "NiD3DPixelShader getter candidate slot +0x7C",
	0x00BE0B20: "NiD3DPixelShader setter slot +0x80",
	0x00E898C0: "NiD3DPixelShader slot +0x84",
	0x00E898D0: "NiD3DPixelShader slot +0x88",
	0x00BE0B90: "NiD3DVertexShader slot +0x7C",
	0x00BE0BA0: "NiD3DVertexShader setter slot +0x80",
	0x00E95D50: "NiD3DVertexShader getter candidate slot +0x84",
	0x00BE0BB0: "NiD3DVertexShader setter slot +0x88",
	0x00BE0BC0: "NiD3DVertexShader slot +0x8C",
	0x00BE0BD0: "NiD3DVertexShader setter slot +0x90",
	0x00BE0BE0: "NiD3DVertexShader slot +0x94",
	0x00BE0BF0: "NiD3DVertexShader byte setter slot +0x98",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x00BD4BA0: "current-pass shader-interface apply",
}

VTABLE_SLOTS = [
	(0x010EF7D4, 0x07C, "NiD3DPixelShader getter candidate used by SetShaders"),
	(0x010EF7D4, 0x080, "NiD3DPixelShader native handle setter used by CreatePixelShader"),
	(0x010EF7D4, 0x084, "NiD3DPixelShader release/check slot"),
	(0x010EF7D4, 0x088, "NiD3DPixelShader adjacent slot"),
	(0x010EF87C, 0x07C, "NiD3DVertexShader adjacent slot"),
	(0x010EF87C, 0x080, "NiD3DVertexShader setter slot +0x80"),
	(0x010EF87C, 0x084, "NiD3DVertexShader getter candidate used by SetShaders"),
	(0x010EF87C, 0x088, "NiD3DVertexShader native handle setter used by CreateVertexShader"),
	(0x010EF87C, 0x08C, "NiD3DVertexShader adjacent slot +0x8C"),
	(0x010EF87C, 0x090, "NiD3DVertexShader setter slot +0x90"),
	(0x010EF87C, 0x094, "NiD3DVertexShader adjacent slot +0x94"),
	(0x010EF87C, 0x098, "NiD3DVertexShader byte setter slot +0x98"),
]

RAW_TARGETS = [
	(0x00BE1F90, 0x40, 0xA0, "BSShader::SetShaders raw entry and bind sequence"),
	(0x00BE0B10, 0x10, 0x18, "NiD3DPixelShader getter candidate"),
	(0x00BE0B20, 0x10, 0x18, "NiD3DPixelShader setter"),
	(0x00BE0B90, 0x10, 0x18, "NiD3DVertexShader slot +0x7C"),
	(0x00BE0BA0, 0x10, 0x18, "NiD3DVertexShader setter +0x80"),
	(0x00E95D50, 0x10, 0x20, "NiD3DVertexShader getter candidate +0x84"),
	(0x00BE0BB0, 0x10, 0x18, "NiD3DVertexShader setter +0x88"),
	(0x00BE0BC0, 0x10, 0x18, "NiD3DVertexShader slot +0x8C"),
	(0x00BE0BD0, 0x10, 0x18, "NiD3DVertexShader setter +0x90"),
	(0x00BE0BE0, 0x10, 0x18, "NiD3DVertexShader slot +0x94"),
	(0x00BE0BF0, 0x10, 0x18, "NiD3DVertexShader byte setter +0x98"),
]

FOCUS_FUNCTIONS = [
	0x00BE1F90,
	0x00BE0B10,
	0x00BE0B20,
	0x00BE0B90,
	0x00BE0BA0,
	0x00E95D50,
	0x00BE0BB0,
	0x00BE0BC0,
	0x00BE0BD0,
	0x00BE0BE0,
	0x00BE0BF0,
	0x00BE0FE0,
	0x00BE1750,
]

REF_TARGETS = [
	0x00BE1F90,
	0x0126F74C,
	0x010EF87C,
	0x010EF7D4,
	0x00BE0B10,
	0x00BE0B20,
	0x00BE0B90,
	0x00BE0BA0,
	0x00E95D50,
	0x00BE0BB0,
	0x00BE0BC0,
	0x00BE0BD0,
	0x00BE0BE0,
	0x00BE0BF0,
]

SCAN_PATTERNS = [
	"0126f74c",
	"DAT_0126f74c",
	"+ 0x2c",
	"+0x2c",
	"+ 0x30",
	"+0x30",
	"+ 0x34",
	"+0x34",
	"+ 0x38",
	"+0x38",
	"+ 0x44",
	"+0x44",
	"+ 0x5c",
	"+0x5c",
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
	"SetShaders",
	"CreateVertexShader",
	"CreatePixelShader",
	"shader",
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
		return
	faddr = func.getEntryPoint().getOffset()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, func.getBody().getNumAddresses()))
	if faddr != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

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
		if count > 80:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
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
				target = ref.getToAddress()
				taddr = target.getOffset()
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), taddr, label_for(taddr)))
				count += 1
	write("  Total: %d calls" % count)

def print_bytes(addr_int, count, label):
	write("")
	write("-" * 70)
	write("Bytes: %s @ 0x%08x len=0x%x" % (label, addr_int, count))
	write("-" * 70)
	offset = 0
	while offset < count:
		items = []
		line_addr = addr_int + offset
		line_index = 0
		while line_index < 16 and offset + line_index < count:
			value = read_byte(addr_int + offset + line_index)
			if value is None:
				items.append("??")
			else:
				items.append("%02x" % value)
			line_index += 1
		write("  0x%08x: %s" % (line_addr, " ".join(items)))
		offset += 16

def print_instruction(inst, target_addr):
	off = inst.getAddress().getOffset()
	marker = " << TARGET" if off == target_addr else ""
	write("  0x%08x: %-54s%s" % (off, inst.toString(), marker))
	refs = inst.getReferencesFrom()
	for ref in refs:
		to_addr = ref.getToAddress()
		to_int = to_addr.getOffset()
		text = read_c_string(to_int, 96)
		if text is None:
			write("      ref %s -> 0x%08x %s" % (ref.getReferenceType(), to_int, label_for(to_int)))
		else:
			write("      ref %s -> 0x%08x \"%s\"" % (ref.getReferenceType(), to_int, text))

def disasm_window(addr_int, before_bytes, count, label):
	write("")
	write("-" * 70)
	write("Raw disassembly %s around 0x%08x" % (label, addr_int))
	write("-" * 70)
	start = addr_int - before_bytes
	inst = listing.getInstructionAt(toAddr(start))
	if inst is None:
		inst = listing.getInstructionContaining(toAddr(start))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start))
	if inst is None:
		write("  [instruction not found]")
		return
	seen = 0
	while inst is not None and seen < count:
		print_instruction(inst, addr_int)
		seen += 1
		inst = inst.getNext()

def print_nearby_functions(addr_int, label):
	write("")
	write("-" * 70)
	write("Nearby functions for %s 0x%08x" % (label, addr_int))
	write("-" * 70)
	containing = fm.getFunctionContaining(toAddr(addr_int))
	before = None
	after = None
	try:
		before = listing.getFunctionBefore(toAddr(addr_int))
	except:
		before = None
	try:
		after = listing.getFunctionAfter(toAddr(addr_int))
	except:
		after = None
	if containing is None:
		write("  containing: none")
	else:
		write("  containing: %s @ 0x%08x" % (containing.getName(), containing.getEntryPoint().getOffset()))
	if before is None:
		write("  before: none")
	else:
		write("  before: %s @ 0x%08x" % (before.getName(), before.getEntryPoint().getOffset()))
	if after is None:
		write("  after: none")
	else:
		write("  after: %s @ 0x%08x" % (after.getName(), after.getEntryPoint().getOffset()))

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
	count = 0
	for line in lines:
		lower = line.lower()
		for pattern in patterns:
			if pattern.lower() in lower:
				write("  %s" % line)
				count += 1
				break
		if count >= 160:
			write("  ... (truncated)")
			break
	write("  Total matched lines: %d" % count)

def scan_raw_range(start, end, label):
	write("")
	write("=" * 70)
	write("RAW RANGE BINDING SCAN: %s 0x%08x..0x%08x" % (label, start, end))
	write("=" * 70)
	inst = listing.getInstructionAt(toAddr(start))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start))
	count = 0
	matched = 0
	while inst is not None:
		off = inst.getAddress().getOffset()
		if off >= end:
			break
		text = inst.toString()
		lower = text.lower()
		interesting = False
		refs = inst.getReferencesFrom()
		for ref in refs:
			to_int = ref.getToAddress().getOffset()
			if ref.getReferenceType().isCall() or KNOWN.get(to_int) is not None:
				interesting = True
		for pattern in SCAN_PATTERNS:
			if pattern.lower() in lower:
				interesting = True
				break
		if interesting:
			print_instruction(inst, start)
			matched += 1
		count += 1
		if count >= 260:
			write("  ... (range scan truncated)")
			break
		inst = inst.getNext()
	write("  Instructions scanned: %d, interesting printed: %d" % (count, matched))

def print_vtable_slots():
	write("")
	write("=" * 70)
	write("FOCUSED SHADER HANDLE VTABLE SLOTS")
	write("=" * 70)
	for item in VTABLE_SLOTS:
		vtable = item[0]
		offset = item[1]
		target = read_u32(vtable + offset)
		if target is None:
			write("  %s +0x%03x @ 0x%08x: unreadable (%s)" % (label_for(vtable), offset, vtable + offset, item[2]))
		else:
			write("  %s +0x%03x @ 0x%08x -> 0x%08x %s (%s)" % (label_for(vtable), offset, vtable + offset, target, label_for(target), item[2]))

def print_slot_refs():
	for item in VTABLE_SLOTS:
		slot_addr = item[0] + item[1]
		find_refs_to(slot_addr, item[2] + " vtable cell")
		target = read_u32(slot_addr)
		if target is not None:
			find_refs_to(target, item[2] + " target")

def print_raw_targets():
	for item in RAW_TARGETS:
		print_nearby_functions(item[0], item[3])
		print_bytes(item[0], 0x40, item[3])
		disasm_window(item[0], item[1], item[2], item[3])

def decompile_focus_functions():
	for addr_int in FOCUS_FUNCTIONS:
		decompile_at(addr_int, label_for(addr_int), 16000)
		find_and_print_calls_from(addr_int, label_for(addr_int))
		scan_patterns(addr_int, label_for(addr_int), SCAN_PATTERNS)

def print_refs():
	for addr_int in REF_TARGETS:
		find_refs_to(addr_int, label_for(addr_int))

def main():
	write("FNV PBR SHADER HANDLE GETTER AND SETSHADERS CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. What exact tiny getter/setter thunks back NiD3DPixelShader +0x7C/+0x80 and NiD3DVertexShader +0x84/+0x88?")
	write("2. Does BSShader::SetShaders bind handles by calling those getters from current pass +0x44/+0x5C?")
	write("3. Is replacement safer through a side-table getter hook, a SetShaders handle substitution, or object-field mutation?")
	write("")
	write("Compatibility rule:")
	write("Visible native PBR remains disabled until getter slots and bind/restore timing are proven by raw code.")
	print_vtable_slots()
	print_refs()
	print_slot_refs()
	print_raw_targets()
	scan_raw_range(0x00BE1F90, 0x00BE20E0, "SetShaders expected bind body")
	scan_raw_range(0x00BE0B00, 0x00BE0C10, "NiD3D shader tiny getter/setter thunk area")
	decompile_focus_functions()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_shader_handle_getter_setshaders_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
