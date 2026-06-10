# @category Analysis
# @description Audit raw FNV PBR selector setup vtable slots that Ghidra did not bind as functions

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x010AF2F8: "PPLighting selector vtable",
	0x010EF544: "Shader-interface field object vtable",
	0x00B7A170: "Selector setup slot +0x4C cache reset",
	0x00E81420: "Selector setup slot +0xC0 raw target",
	0x00B7E430: "Selector setup slot +0x11C interface setup",
	0x00BD0470: "Selector setup slot +0x144 wrapper",
	0x00B71BF0: "Selector setup slot +0x148 target",
	0x00B74210: "Selector setup slot +0x14C target",
	0x00B7A730: "Selector setup slot +0x150 raw target",
	0x00E826D0: "Shader-interface constant apply dispatcher",
	0x00BE1F90: "BSShader::SetShaders",
	0x00BE1750: "BSShader::CreatePixelShader",
	0x00BE0FE0: "BSShader::CreateVertexShader",
	0x00E88A20: "NiDX9RenderState::SetTexture",
}

TARGET_SLOTS = [
	(0x010AF2F8, 0x0C0, "selector setup slot +0xC0"),
	(0x010AF2F8, 0x144, "selector setup slot +0x144"),
	(0x010AF2F8, 0x148, "selector setup slot +0x148"),
	(0x010AF2F8, 0x14C, "selector setup slot +0x14C"),
	(0x010AF2F8, 0x150, "selector setup slot +0x150"),
]

FOCUS_ADDRS = [
	(0x00E81420, "raw selector slot +0xC0 target"),
	(0x00BD0470, "selector slot +0x144 wrapper"),
	(0x00B71BF0, "selector slot +0x148 target"),
	(0x00B74210, "selector slot +0x14C target"),
	(0x00B7A730, "raw selector slot +0x150 target"),
]

REF_TARGETS = [
	0x010AF2F8,
	0x00E81420,
	0x00BD0470,
	0x00B71BF0,
	0x00B74210,
	0x00B7A730,
	0x00E826D0,
	0x00BE1F90,
	0x00BE1750,
	0x00BE0FE0,
]

SCAN_PATTERNS = [
	"010af2f8",
	"010ef544",
	"e826d0",
	"be1f90",
	"be1750",
	"be0fe0",
	"e88a20",
	"+ 0x30",
	"+0x30",
	"+ 0x34",
	"+0x34",
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
	"+ 0x78",
	"+0x78",
	"SetPixelShader",
	"SetVertexShader",
	"CreatePixelShader",
	"CreateVertexShader",
	"SetTexture",
	"shader",
	"constant",
	"pixel",
	"vertex",
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

def decompile_at(addr_int, label, max_len=30000):
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
		write("  NOTE: requested address is inside function at +0x%x" % (addr_int - faddr))
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
		if count >= 200:
			write("  ... (truncated)")
			break
	write("  Total printed: %d refs" % count)

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

def disasm_window(addr_int, before, count, label):
	write("")
	write("-" * 70)
	write("Raw disassembly %s around 0x%08x" % (label, addr_int))
	write("-" * 70)
	start = addr_int - before
	inst = listing.getInstructionAt(toAddr(start))
	if inst is None:
		inst = listing.getInstructionContaining(toAddr(addr_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start))
	seen = 0
	while inst is not None and seen < count:
		off = inst.getAddress().getOffset()
		marker = " << TARGET" if off == addr_int else ""
		write("  0x%08x: %-54s%s" % (off, inst.toString(), marker))
		refs = inst.getReferencesFrom()
		for ref in refs:
			target = ref.getToAddress()
			write("      ref %s -> 0x%08x %s" % (ref.getReferenceType(), target.getOffset(), label_for(target.getOffset())))
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
		if count >= 260:
			write("  ... (truncated)")
			break
	write("  Total matched lines: %d" % count)

def print_data_window(center_int, before_slots, after_slots, label):
	write("")
	write("-" * 70)
	write("DATA WINDOW: %s centered at 0x%08x" % (label, center_int))
	write("-" * 70)
	slot = -before_slots
	while slot <= after_slots:
		addr_int = center_int + slot * 4
		value = read_u32(addr_int)
		marker = " << CENTER" if addr_int == center_int else ""
		if value is None:
			write("  0x%08x slot %+04d offset %+04x: unreadable%s" % (addr_int, slot, slot * 4, marker))
		else:
			write("  0x%08x slot %+04d offset %+04x: 0x%08x  %s%s" % (addr_int, slot, slot * 4, value, label_for(value), marker))
		slot += 1

def print_target_slots():
	write("")
	write("=" * 70)
	write("TARGET SELECTOR VTABLE SLOTS")
	write("=" * 70)
	for item in TARGET_SLOTS:
		vtable = item[0]
		offset = item[1]
		label = item[2]
		value = read_u32(vtable + offset)
		if value is None:
			write("  %s vtable=0x%08x offset=0x%03x unreadable" % (label, vtable, offset))
		else:
			write("  %s vtable=0x%08x offset=0x%03x -> 0x%08x %s" % (label, vtable, offset, value, label_for(value)))

def analyze_focus_addrs():
	for item in FOCUS_ADDRS:
		addr_int = item[0]
		label = item[1]
		print_nearby_functions(addr_int, label)
		disasm_window(addr_int, 48, 180, label)
		find_refs_to(addr_int, label)
		decompile_at(addr_int, label, 36000)
		find_and_print_calls_from(addr_int, label)
		scan_patterns(addr_int, label, SCAN_PATTERNS)

def print_all_refs():
	for addr_int in REF_TARGETS:
		find_refs_to(addr_int, label_for(addr_int))

def main():
	write("FNV PBR SELECTOR SETUP RAW SLOT FOLLOWUP AUDIT")
	write("")
	write("Questions:")
	write("1. Are selector vtable raw slots +0xC0 and +0x150 code, thunks, or bad function boundaries?")
	write("2. What do wrapper slot +0x144 children +0x148 and +0x14C do?")
	write("3. Do any of these slots mutate native pixel/vertex shader handles, or are they constants/cache setup only?")
	write("4. Is visible native shader replacement safe after +0x11C setup, or do later slots still own shader objects?")
	write("")
	write("Compatibility rule:")
	write("Visible native PBR replacement remains blocked unless this script proves shader handle ownership and restore timing.")
	print_data_window(0x010AF2F8, 44, 92, "selector vtable around setup/finalize slots")
	print_target_slots()
	print_all_refs()
	analyze_focus_addrs()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_selector_setup_raw_slot_followup_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
