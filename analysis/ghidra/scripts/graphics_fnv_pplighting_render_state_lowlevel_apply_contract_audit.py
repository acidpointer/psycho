# @category Analysis
# @description Audit FNV low-level pass-state apply helpers behind PPLighting dispatcher

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00E7DE90: "Pass mode table apply helper called by B7 dispatcher",
	0x00E7EA00: "Pass-entry cache downstream apply helper",
	0x00E7EB00: "Pass-entry cache/apply helper",
	0x00E7ECD0: "Pass/resource release helper candidate",
	0x00E7F7C0: "Renderer helper called by SetShaders",
	0x00E88930: "NiDX9RenderState texture-stage-state setter",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x00E88A50: "NiDX9RenderState texture getter",
	0x00E88A60: "NiDX9RenderState clear texture from all stages",
	0x00E88FC0: "Render-state backup/apply helper candidate",
	0x00E89060: "Render-state backup/apply helper candidate",
	0x00E890C0: "Low-level render-state apply helper called by E7DE90",
	0x00E89410: "Pass-entry state validation/apply helper called by E7EB00",
	0x00E90850: "Current pass/render-state setup helper",
	0x00E910A0: "NiDX9RenderState sampler-state setter",
	0x010EF6E8: "Render-state vtable/data ref to SetTexture",
	0x010F0968: "Render-state vtable/data ref to SetTexture",
	0x0126F0B0: "Pass mode table first value used by E7DE90",
	0x0126F0B4: "Pass mode table second value used by E7DE90",
	0x0126F680: "Pass-entry value cache used by E7EB00",
	0x0126F728: "Renderer helper return global",
	0x0126F74C: "Current NiD3DPass global",
	0x0126F92C: "Sampler-state TypeMap",
	0x0126F958: "Texture-stage-state TypeMap",
}

LOWLEVEL_FUNCTIONS = [
	0x00E7DE90,
	0x00E7EA00,
	0x00E7EB00,
	0x00E7ECD0,
	0x00E7F7C0,
	0x00E88FC0,
	0x00E89060,
	0x00E890C0,
	0x00E89410,
	0x00E90850,
	0x00E88930,
	0x00E88A20,
	0x00E88A50,
	0x00E88A60,
	0x00E910A0,
]

REF_TARGETS = [
	0x00E7DE90,
	0x00E7EA00,
	0x00E7EB00,
	0x00E7ECD0,
	0x00E88FC0,
	0x00E89060,
	0x00E890C0,
	0x00E89410,
	0x00E88930,
	0x00E88A20,
	0x00E88A50,
	0x00E88A60,
	0x00E910A0,
	0x010EF6E8,
	0x010F0968,
	0x0126F0B0,
	0x0126F0B4,
	0x0126F680,
	0x0126F728,
	0x0126F74C,
	0x0126F92C,
	0x0126F958,
]

RAW_WINDOWS = [
	(0x00E7DE90, 16, 120, "E7DE90 pass mode table apply helper"),
	(0x00E7EA00, 20, 160, "E7EA00 pass-entry downstream apply helper"),
	(0x00E7EB00, 18, 100, "E7EB00 pass-entry cache/apply helper"),
	(0x00E7ECD0, 20, 120, "E7ECD0 pass/resource release helper candidate"),
	(0x00E88FC0, 20, 140, "E88FC0 render-state helper candidate"),
	(0x00E89060, 20, 120, "E89060 render-state helper candidate"),
	(0x00E890C0, 20, 160, "E890C0 low-level render-state apply helper"),
	(0x00E89410, 20, 160, "E89410 pass-entry state validation/apply helper"),
	(0x00E90850, 20, 120, "E90850 current pass/render-state setup helper"),
	(0x00E88930, 16, 90, "texture-stage-state setter"),
	(0x00E88A20, 16, 100, "SetTexture"),
	(0x00E910A0, 16, 90, "sampler-state setter"),
]

DATA_WINDOWS = [
	0x010EF6E8,
	0x010F0968,
	0x0126F0B0,
	0x0126F0B4,
	0x0126F680,
	0x0126F728,
	0x0126F74C,
	0x0126F92C,
	0x0126F958,
]

IMPORTANT_CALL_TARGETS = [
	0x00E7DE90,
	0x00E7EA00,
	0x00E7EB00,
	0x00E7ECD0,
	0x00E88FC0,
	0x00E89060,
	0x00E890C0,
	0x00E89410,
	0x00E88930,
	0x00E88A20,
	0x00E88A50,
	0x00E88A60,
	0x00E910A0,
]

MATCH_PATTERNS = [
	"e7de90",
	"e7ea00",
	"e7eb00",
	"e7ecd0",
	"e88fc0",
	"e89060",
	"e890c0",
	"e89410",
	"e88930",
	"e88a20",
	"e88a50",
	"e88a60",
	"e910a0",
	"0126f0b0",
	"0126f0b4",
	"0126f680",
	"0126f728",
	"0126f74c",
	"0126f92c",
	"0126f958",
	"10a0",
	"10f8",
	"0xa20",
	"0xe20",
	"0x104",
	"0x10c",
	"0x114",
	"settexture",
	"set texture",
	"texture",
	"sampler",
	"stage",
	"renderstate",
	"render state",
	"d3d",
	"pass",
	"cache",
]

def write(msg):
	output.append(msg)
	print(msg)

def label_for(addr_int):
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

def read_dword(addr_int):
	try:
		return memory.getInt(toAddr(addr_int)) & 0xffffffff
	except:
		return None

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
		if count > 220:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, label_for(tgt)))
				count += 1
	write("  Total: %d calls" % count)

def line_matches(line):
	lower = line.lower()
	idx = 0
	while idx < len(MATCH_PATTERNS):
		if lower.find(MATCH_PATTERNS[idx]) >= 0:
			return True
		idx += 1
	return False

def print_matching_decompile_lines(addr_int, label):
	write("")
	write("=" * 70)
	write("MATCHED DECOMPILE LINES: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	code = decompile_text(addr_int)
	if code is None:
		write("  [decompilation failed]")
		return
	lines = code.split("\n")
	idx = 0
	count = 0
	while idx < len(lines):
		line = lines[idx]
		if line_matches(line):
			write("  L%04d: %s" % (idx + 1, line))
			count += 1
		idx += 1
	write("  Total matched lines: %d" % count)

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionBefore(toAddr(center_int))
	count = 0
	while inst is not None and count < before_count:
		prev = inst.getPrevious()
		if prev is None:
			break
		inst = prev
		count += 1
	idx = 0
	limit = before_count + after_count + 1
	while inst is not None and idx < limit:
		addr_int = inst.getAddress().getOffset()
		marker = " << TARGET" if addr_int == center_int else ""
		extra = ""
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				extra = "%s ; CALL 0x%08x %s" % (extra, tgt, label_for(tgt))
		write("  0x%08x: %-56s%s%s" % (addr_int, inst.toString(), marker, extra))
		inst = inst.getNext()
		idx += 1

def dump_data_window(addr_int, before_slots, after_slots):
	write("")
	write("=" * 70)
	write("DATA WINDOW AROUND 0x%08x (%s)" % (addr_int, label_for(addr_int)))
	write("=" * 70)
	start = addr_int - before_slots * 4
	idx = 0
	total = before_slots + after_slots + 1
	while idx < total:
		slot_addr = start + idx * 4
		value = read_dword(slot_addr)
		marker = " << target" if slot_addr == addr_int else ""
		if value is None:
			write("  0x%08x: ????????%s" % (slot_addr, marker))
		else:
			write("  0x%08x: 0x%08x %s%s" % (slot_addr, value, label_for(value), marker))
		idx += 1

def text_has_important_scalar(text):
	lower = text.lower()
	if lower.find("0126f") >= 0:
		return True
	if lower.find("010ef6e8") >= 0:
		return True
	if lower.find("010f0968") >= 0:
		return True
	if lower.find("10a0") >= 0:
		return True
	if lower.find("10f8") >= 0:
		return True
	if lower.find("0xa20") >= 0:
		return True
	if lower.find("0xe20") >= 0:
		return True
	if lower.find("0x104") >= 0:
		return True
	if lower.find("0x10c") >= 0:
		return True
	if lower.find("0x114") >= 0:
		return True
	if lower.find("settexture") >= 0:
		return True
	return False

def call_target_from_inst(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		if ref.getReferenceType().isCall():
			return ref.getToAddress().getOffset()
	return None

def is_important_call(target):
	if target is None:
		return False
	idx = 0
	while idx < len(IMPORTANT_CALL_TARGETS):
		if target == IMPORTANT_CALL_TARGETS[idx]:
			return True
		idx += 1
	return False

def scan_function_markers(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("=" * 70)
	write("INSTRUCTION MARKERS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		target = call_target_from_inst(inst)
		if text_has_important_scalar(text) or is_important_call(target):
			if target is None:
				write("  0x%08x: %s" % (inst.getAddress().getOffset(), text))
			else:
				write("  0x%08x: %s ; CALL 0x%08x %s" % (inst.getAddress().getOffset(), text, target, label_for(target)))
			disasm_window(inst.getAddress().getOffset(), 5, 10, "marker")
			count += 1
			if count > 120:
				write("  ... marker scan truncated")
				break
	write("  Total marker instructions: %d" % count)

def list_contains_addr(items, addr_int):
	idx = 0
	while idx < len(items):
		if items[idx] == addr_int:
			return True
		idx += 1
	return False

def audit_unique_ref_callers(addr_int, label, max_funcs):
	write("")
	write("=" * 70)
	write("UNIQUE CALLERS/REF FUNCTIONS FOR 0x%08x (%s)" % (addr_int, label))
	write("=" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	seen = []
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		if from_func is not None:
			entry = from_func.getEntryPoint().getOffset()
			if not list_contains_addr(seen, entry):
				seen.append(entry)
				write("  Function 0x%08x %s referenced from 0x%08x" % (entry, from_func.getName(), ref.getFromAddress().getOffset()))
				decompile_at(entry, "ref caller of %s" % label, 14000)
				find_and_print_calls_from(entry, "ref caller of %s" % label)
				print_matching_decompile_lines(entry, "ref caller of %s" % label)
				scan_function_markers(entry, "ref caller of %s" % label)
				count += 1
				if count >= max_funcs:
					write("  ... unique ref caller audit truncated")
					break
	write("  Total unique ref functions audited: %d" % count)

def audit_data_windows():
	idx = 0
	while idx < len(DATA_WINDOWS):
		dump_data_window(DATA_WINDOWS[idx], 12, 36)
		idx += 1

def audit_raw_windows():
	idx = 0
	while idx < len(RAW_WINDOWS):
		item = RAW_WINDOWS[idx]
		disasm_window(item[0], item[1], item[2], item[3])
		idx += 1

def audit_refs():
	idx = 0
	while idx < len(REF_TARGETS):
		find_refs_to(REF_TARGETS[idx], label_for(REF_TARGETS[idx]))
		idx += 1

def audit_function_list():
	idx = 0
	while idx < len(LOWLEVEL_FUNCTIONS):
		addr = LOWLEVEL_FUNCTIONS[idx]
		label = label_for(addr)
		decompile_at(addr, label, 22000)
		find_and_print_calls_from(addr, label)
		print_matching_decompile_lines(addr, label)
		scan_function_markers(addr, label)
		idx += 1

def audit_key_ref_callers():
	audit_unique_ref_callers(0x00E890C0, label_for(0x00E890C0), 20)
	audit_unique_ref_callers(0x00E89410, label_for(0x00E89410), 16)
	audit_unique_ref_callers(0x00E7EA00, label_for(0x00E7EA00), 16)
	audit_unique_ref_callers(0x00E7ECD0, label_for(0x00E7ECD0), 12)
	audit_unique_ref_callers(0x00E88A20, label_for(0x00E88A20), 12)
	audit_unique_ref_callers(0x00E88930, label_for(0x00E88930), 12)
	audit_unique_ref_callers(0x00E910A0, label_for(0x00E910A0), 12)
	audit_unique_ref_callers(0x0126F680, label_for(0x0126F680), 14)
	audit_unique_ref_callers(0x0126F0B0, label_for(0x0126F0B0), 14)
	audit_unique_ref_callers(0x0126F0B4, label_for(0x0126F0B4), 14)

def print_header():
	write("FNV PPLIGHTING LOW-LEVEL RENDER-STATE APPLY CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. What does E890C0 apply when called by E7DE90 with pass-mode table values?")
	write("2. What does E89410 validate or apply for E7EB00 pass-entry indexes?")
	write("3. Does E7EA00 reach texture, texture-stage, sampler, or only render-state calls?")
	write("4. Do any low-level apply helpers call E88A20, E88930, or E910A0 directly or indirectly?")
	write("5. Are tables 0x0126F680, 0x0126F0B0, and 0x0126F0B4 texture-stage maps or non-texture pass-state caches?")

def main():
	print_header()
	audit_data_windows()
	audit_raw_windows()
	audit_refs()
	audit_function_list()
	audit_key_ref_callers()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pplighting_render_state_lowlevel_apply_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
