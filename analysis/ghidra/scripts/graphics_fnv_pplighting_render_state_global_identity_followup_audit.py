# @category Analysis
# @description Prove FNV PPLighting render-state global identity and virtual SetTexture route

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00E7DC90: "E7 helper: conditional state reset after resource bind",
	0x00E7DD50: "E7 helper: pass range state reset",
	0x00E7DF90: "E7 helper: matrix/constant block builder",
	0x00E7E8D0: "Renderer global setter: seeds DAT_0126F6C4/C0/C8",
	0x00E7E940: "E7 helper: matrix constant upload",
	0x00E7EA00: "Pass-entry downstream virtual apply helper",
	0x00E7EB00: "Pass-entry cache/apply helper",
	0x00E881A0: "Render-state TypeMap/global initialization candidate",
	0x00E88930: "NiDX9RenderState texture-stage-state setter",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x00E88A50: "NiDX9RenderState texture getter",
	0x00E88A60: "NiDX9RenderState clear texture from all stages",
	0x00E88FC0: "Texture-stage-state tracker setter",
	0x00E89060: "Texture-stage-state tracker getter",
	0x00E890C0: "Sampler-state tracker setter",
	0x00E89250: "Tracked texture-stage-state flush helper",
	0x00E892D0: "Tracked sampler-state flush helper",
	0x00E89410: "Pass-entry state validation/apply helper",
	0x00E90850: "Current pass/render-state setup helper",
	0x00E910A0: "NiDX9RenderState sampler-state setter",
	0x010EF60C: "candidate render-state vtable base A: +0xC0=E88930 +0xDC=E88A20",
	0x010EF6CC: "candidate vtable A +0xC0",
	0x010EF6D8: "candidate vtable A +0xCC",
	0x010EF6E8: "candidate vtable A +0xDC",
	0x010F088C: "candidate render-state vtable base B: +0xC0=E88930 +0xCC=E910A0 +0xDC=E88A20",
	0x010F094C: "candidate vtable B +0xC0",
	0x010F0958: "candidate vtable B +0xCC",
	0x010F0968: "candidate vtable B +0xDC",
	0x0126F6C0: "renderer-global object from renderer +0x288",
	0x0126F6C4: "renderer global object set directly by E7E8D0",
	0x0126F6C8: "renderer-global render-state candidate from renderer +0x8B8",
	0x0126F918: "sampler-state flush table used by E892D0",
	0x0126F92C: "sampler-state TypeMap",
	0x0126F948: "texture-stage-state flush table used by E89250",
	0x0126F958: "texture-stage-state TypeMap",
	0x0126F99C: "render-state global used by E89250/E892D0",
}

FOCUS_FUNCTIONS = [
	0x00E7E8D0,
	0x00E7EA00,
	0x00E7DC90,
	0x00E7DD50,
	0x00E7DF90,
	0x00E7E940,
	0x00E7EB00,
	0x00E89250,
	0x00E892D0,
	0x00E89410,
	0x00E881A0,
	0x00E90850,
	0x00E88FC0,
	0x00E89060,
	0x00E890C0,
	0x00E88930,
	0x00E910A0,
	0x00E88A20,
	0x00E88A50,
	0x00E88A60,
]

REF_TARGETS = [
	0x00E7E8D0,
	0x00E89250,
	0x00E892D0,
	0x00E89410,
	0x00E88930,
	0x00E910A0,
	0x00E88A20,
	0x010EF60C,
	0x010EF6CC,
	0x010EF6D8,
	0x010EF6E8,
	0x010F088C,
	0x010F094C,
	0x010F0958,
	0x010F0968,
	0x0126F6C0,
	0x0126F6C4,
	0x0126F6C8,
	0x0126F918,
	0x0126F92C,
	0x0126F948,
	0x0126F958,
	0x0126F99C,
]

GLOBAL_REF_TARGETS = [
	0x0126F99C,
	0x0126F6C8,
	0x0126F6C4,
	0x0126F6C0,
	0x0126F918,
	0x0126F948,
]

RAW_WINDOWS = [
	(0x00E7E8D0, 18, 120, "E7E8D0 renderer global setter"),
	(0x00E7EA00, 20, 170, "E7EA00 virtual apply helper"),
	(0x00E7DC90, 18, 120, "E7DC90 conditional reset helper"),
	(0x00E7DD50, 18, 120, "E7DD50 range reset helper"),
	(0x00E7E940, 18, 140, "E7E940 matrix constant upload helper"),
	(0x00E89250, 20, 120, "E89250 tracked texture-stage flush"),
	(0x00E892D0, 20, 120, "E892D0 tracked sampler flush"),
	(0x00E89410, 20, 80, "E89410 state validation/apply helper"),
	(0x00E881A0, 20, 180, "E881A0 TypeMap/global init candidate"),
	(0x00E88930, 16, 90, "E88930 texture-stage-state setter"),
	(0x00E910A0, 16, 90, "E910A0 sampler-state setter"),
	(0x00E88A20, 16, 110, "E88A20 SetTexture"),
]

DATA_WINDOWS = [
	0x010EF60C,
	0x010EF6CC,
	0x010EF6D8,
	0x010EF6E8,
	0x010F088C,
	0x010F094C,
	0x010F0958,
	0x010F0968,
	0x0126F6C0,
	0x0126F6C4,
	0x0126F6C8,
	0x0126F918,
	0x0126F92C,
	0x0126F948,
	0x0126F958,
	0x0126F99C,
]

VTABLE_BASES = [
	(0x010EF60C, "candidate vtable A"),
	(0x010F088C, "candidate vtable B"),
]

VTABLE_SLOTS = [
	(0x04, "addref-like slot"),
	(0x08, "release-like slot"),
	(0x68, "render-state-like slot used by E7DC90"),
	(0xB0, "constant upload-like slot used on DAT_0126F6C0"),
	(0xC0, "texture-stage-state candidate"),
	(0xCC, "sampler-state candidate"),
	(0xDC, "SetTexture candidate"),
	(0x114, "sampler/raw device/confusing slot candidate"),
]

IMPORTANT_CALL_TARGETS = [
	0x00E7E8D0,
	0x00E7EA00,
	0x00E7DC90,
	0x00E7DD50,
	0x00E7DF90,
	0x00E7E940,
	0x00E88930,
	0x00E88A20,
	0x00E88A50,
	0x00E88A60,
	0x00E88FC0,
	0x00E89060,
	0x00E890C0,
	0x00E89250,
	0x00E892D0,
	0x00E89410,
	0x00E910A0,
]

MATCH_PATTERNS = [
	"0126f99c",
	"0126f6c8",
	"0126f6c4",
	"0126f6c0",
	"0126f948",
	"0126f918",
	"0126f958",
	"0126f92c",
	"010f088c",
	"010ef60c",
	"010f094c",
	"010f0958",
	"010f0968",
	"010ef6cc",
	"010ef6d8",
	"010ef6e8",
	"e88a20",
	"e88930",
	"e910a0",
	"settexture",
	"set texture",
	"texture",
	"sampler",
	"stage",
	"renderstate",
	"render state",
	"d3d",
	"device",
	"0x288",
	"+ 0x288",
	"+0x288",
	"0x8b8",
	"+ 0x8b8",
	"+0x8b8",
	"0xc0",
	"+ 0xc0",
	"+0xc0",
	"0xcc",
	"+ 0xcc",
	"+0xcc",
	"0xdc",
	"+ 0xdc",
	"+0xdc",
	"0x10f8",
	"+ 0x10f8",
	"+0x10f8",
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

def ref_kind(ref):
	rt = ref.getReferenceType()
	name = rt.toString()
	flag = "?"
	try:
		if rt.isWrite():
			flag = "WRITE"
	except:
		pass
	try:
		if rt.isRead():
			if flag == "?":
				flag = "READ"
			else:
				flag = flag + "+READ"
	except:
		pass
	return "%s/%s" % (name, flag)

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
		write("  %s @ 0x%08x (in %s) %s" % (ref_kind(ref), from_addr.getOffset(), fname, inst_text))
		count += 1
		if count > 260:
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

def list_contains_addr(items, addr_int):
	idx = 0
	while idx < len(items):
		if items[idx] == addr_int:
			return True
		idx += 1
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

def text_has_important_scalar(text):
	lower = text.lower()
	if lower.find("0126f99c") >= 0:
		return True
	if lower.find("0126f6c") >= 0:
		return True
	if lower.find("0126f948") >= 0:
		return True
	if lower.find("0126f918") >= 0:
		return True
	if lower.find("010f088c") >= 0:
		return True
	if lower.find("010ef60c") >= 0:
		return True
	if lower.find("0x288") >= 0:
		return True
	if lower.find("0x8b8") >= 0:
		return True
	if lower.find("0xc0") >= 0:
		return True
	if lower.find("0xcc") >= 0:
		return True
	if lower.find("0xdc") >= 0:
		return True
	if lower.find("0x10f8") >= 0:
		return True
	if lower.find("settexture") >= 0:
		return True
	return False

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
			disasm_window(inst.getAddress().getOffset(), 6, 12, "marker")
			count += 1
			if count > 180:
				write("  ... marker scan truncated")
				break
	write("  Total marker instructions: %d" % count)

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

def dump_vtable_slots(base_int, label):
	write("")
	write("=" * 70)
	write("CANDIDATE VTABLE SLOT MAP: %s base 0x%08x" % (label, base_int))
	write("=" * 70)
	idx = 0
	while idx < len(VTABLE_SLOTS):
		item = VTABLE_SLOTS[idx]
		slot = item[0]
		slot_label = item[1]
		slot_addr = base_int + slot
		value = read_dword(slot_addr)
		if value is None:
			write("  +0x%03x @ 0x%08x: ???????? %s" % (slot, slot_addr, slot_label))
		else:
			write("  +0x%03x @ 0x%08x: 0x%08x %s ; %s" % (slot, slot_addr, value, label_for(value), slot_label))
		idx += 1

def audit_vtable_slot_refs(base_int, label):
	write("")
	write("=" * 70)
	write("CANDIDATE VTABLE SLOT REFS: %s base 0x%08x" % (label, base_int))
	write("=" * 70)
	find_refs_to(base_int, "%s base" % label)
	idx = 0
	while idx < len(VTABLE_SLOTS):
		item = VTABLE_SLOTS[idx]
		slot = item[0]
		find_refs_to(base_int + slot, "%s slot +0x%03x %s" % (label, slot, item[1]))
		idx += 1

def audit_unique_ref_callers(addr_int, label, max_funcs):
	write("")
	write("=" * 70)
	write("UNIQUE REF FUNCTIONS FOR 0x%08x (%s)" % (addr_int, label))
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
				write("  Function 0x%08x %s referenced from 0x%08x (%s)" % (entry, from_func.getName(), ref.getFromAddress().getOffset(), ref_kind(ref)))
				decompile_at(entry, "ref function for %s" % label, 18000)
				find_and_print_calls_from(entry, "ref function for %s" % label)
				print_matching_decompile_lines(entry, "ref function for %s" % label)
				scan_function_markers(entry, "ref function for %s" % label)
				count += 1
				if count >= max_funcs:
					write("  ... unique ref function audit truncated")
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

def audit_focus_functions():
	idx = 0
	while idx < len(FOCUS_FUNCTIONS):
		addr = FOCUS_FUNCTIONS[idx]
		label = label_for(addr)
		decompile_at(addr, label, 26000)
		find_and_print_calls_from(addr, label)
		print_matching_decompile_lines(addr, label)
		scan_function_markers(addr, label)
		idx += 1

def audit_global_ref_callers():
	idx = 0
	while idx < len(GLOBAL_REF_TARGETS):
		addr = GLOBAL_REF_TARGETS[idx]
		audit_unique_ref_callers(addr, label_for(addr), 40)
		idx += 1

def audit_vtables():
	idx = 0
	while idx < len(VTABLE_BASES):
		item = VTABLE_BASES[idx]
		dump_vtable_slots(item[0], item[1])
		audit_vtable_slot_refs(item[0], item[1])
		idx += 1

def print_slot_hypothesis():
	write("")
	write("=" * 70)
	write("SLOT IDENTITY HYPOTHESIS TO PROVE OR REJECT")
	write("=" * 70)
	write("If DAT_0126F6C8 and DAT_0126F99C use candidate vtable B at 0x010F088C:")
	write("  +0xC0 maps to E88930 (texture-stage-state setter)")
	write("  +0xCC maps to E910A0 (sampler-state setter)")
	write("  +0xDC maps to E88A20 (SetTexture)")
	write("If they use candidate vtable A at 0x010EF60C:")
	write("  +0xC0 maps to E88930 and +0xDC maps to E88A20, but +0xCC does not map to E910A0.")
	write("This audit must identify the global writers/vtable constructors before E7EA00 +0xDC can be promoted from candidate route to proven SetTexture route.")

def print_header():
	write("FNV PPLIGHTING RENDER-STATE GLOBAL IDENTITY FOLLOW-UP AUDIT")
	write("")
	write("Questions:")
	write("1. Who writes DAT_0126F99C, and is it the same render-state object/class as DAT_0126F6C8?")
	write("2. Does renderer +0x8B8 hold a NiDX9RenderState object with vtable B or A?")
	write("3. Do virtual slots +0xC0/+0xCC/+0xDC in E7EA00 and E89250/E892D0 map to E88930/E910A0/E88A20?")
	write("4. Can the PPLighting pass-entry resource pointer from E7EA00 be tied to final SetTexture stage ownership?")

def main():
	print_header()
	print_slot_hypothesis()
	audit_vtables()
	audit_data_windows()
	audit_raw_windows()
	audit_refs()
	audit_focus_functions()
	audit_global_ref_callers()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pplighting_render_state_global_identity_followup_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
