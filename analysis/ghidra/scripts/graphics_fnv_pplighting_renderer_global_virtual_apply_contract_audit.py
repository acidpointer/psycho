# @category Analysis
# @description Audit FNV PPLighting renderer globals and virtual apply methods behind E7EA00

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00E7DC90: "Helper called by E7EA00 after resource bind",
	0x00E7DD90: "Adjacent E7 apply helper candidate",
	0x00E7DDF0: "Adjacent E7 apply helper candidate",
	0x00E7DE90: "Pass mode table apply helper called by B7 dispatcher",
	0x00E7DEF0: "Sampler-state table apply helper candidate",
	0x00E7E940: "Helper called by E7EA00 after resource bind",
	0x00E7E990: "Renderer global virtual +0xB0 caller candidate",
	0x00E7EA00: "Pass-entry downstream virtual apply helper",
	0x00E7EB00: "Pass-entry cache/apply helper",
	0x00E7EB50: "Pass/resource helper candidate",
	0x00E7ECD0: "Pass/resource release helper candidate",
	0x00E7EDF0: "Renderer-global current resource helper candidate",
	0x00E7EF40: "Renderer helper called near E7F7D0",
	0x00E7F7C0: "Renderer helper return global",
	0x00E7F7D0: "Renderer helper near E7F7C0",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x00E88A50: "NiDX9RenderState texture getter",
	0x00E88A60: "NiDX9RenderState clear texture from all stages",
	0x00E88FC0: "Texture-stage-state tracker setter",
	0x00E88930: "NiDX9RenderState texture-stage-state setter",
	0x00E89060: "Texture-stage-state tracker getter",
	0x00E890C0: "Sampler-state tracker setter",
	0x00E89250: "E89410 bounded helper",
	0x00E892D0: "E89410 always-called helper",
	0x00E89410: "Pass-entry state validation/apply helper called by E7EB00",
	0x00E90850: "Current pass/render-state setup helper",
	0x00E910A0: "NiDX9RenderState sampler-state setter",
	0x010EF6CC: "Render-state vtable/data ref to texture-stage-state setter",
	0x010EF6E8: "Render-state vtable/data ref to SetTexture",
	0x010EF6EC: "Render-state vtable/data ref to texture getter",
	0x010EF6F0: "Render-state vtable/data ref to clear texture from all stages",
	0x010F094C: "Render-state vtable/data ref to texture-stage-state setter",
	0x010F0958: "Render-state vtable/data ref to sampler-state setter",
	0x010F0968: "Render-state vtable/data ref to SetTexture",
	0x010F096C: "Render-state vtable/data ref to texture getter",
	0x010F0970: "Render-state vtable/data ref to clear texture from all stages",
	0x011A9608: "Global value passed to DAT_0126F6C0 virtual +0x114",
	0x011BF558: "Pass-entry bounded count used by E7EA00/E89410",
	0x0126F680: "Pass-entry value cache used by E7EB00",
	0x0126F6C0: "Renderer global used by E7EA00 virtual +0x114 and nearby +0xB0",
	0x0126F6C4: "Renderer global whose +0x8C4 object is used by E7EA00",
	0x0126F6C8: "Renderer global used by E7EA00 virtual +0xC0/+0xCC/+0xDC",
	0x0126F6CC: "Renderer global/current resource helper pointer candidate",
	0x0126F728: "Renderer helper return global",
	0x0126F74C: "Current NiD3DPass global",
	0x0126F92C: "Sampler-state TypeMap",
	0x0126F958: "Texture-stage-state TypeMap",
}

FOCUS_FUNCTIONS = [
	0x00E7DC90,
	0x00E7DD90,
	0x00E7DDF0,
	0x00E7DE90,
	0x00E7DEF0,
	0x00E7E940,
	0x00E7E990,
	0x00E7EA00,
	0x00E7EB00,
	0x00E7EB50,
	0x00E7ECD0,
	0x00E7EDF0,
	0x00E7EF40,
	0x00E7F7C0,
	0x00E7F7D0,
	0x00E89250,
	0x00E892D0,
	0x00E89410,
	0x00E90850,
	0x00E88A20,
	0x00E88930,
	0x00E910A0,
]

REF_TARGETS = [
	0x00E7DC90,
	0x00E7E940,
	0x00E7EA00,
	0x00E7EB00,
	0x00E7EB50,
	0x00E7ECD0,
	0x00E7EDF0,
	0x00E89250,
	0x00E892D0,
	0x00E89410,
	0x00E88A20,
	0x00E88930,
	0x00E910A0,
	0x010EF6CC,
	0x010EF6E8,
	0x010EF6EC,
	0x010EF6F0,
	0x010F094C,
	0x010F0958,
	0x010F0968,
	0x010F096C,
	0x010F0970,
	0x011A9608,
	0x011BF558,
	0x0126F680,
	0x0126F6C0,
	0x0126F6C4,
	0x0126F6C8,
	0x0126F6CC,
	0x0126F728,
	0x0126F74C,
	0x0126F92C,
	0x0126F958,
]

GLOBAL_REF_TARGETS = [
	0x0126F6C0,
	0x0126F6C4,
	0x0126F6C8,
	0x0126F6CC,
	0x011A9608,
	0x011BF558,
	0x0126F680,
	0x0126F728,
	0x0126F74C,
]

RAW_WINDOWS = [
	(0x00E7DC90, 18, 140, "E7DC90 helper called by E7EA00"),
	(0x00E7DD90, 18, 140, "E7DD90 adjacent helper"),
	(0x00E7DDF0, 18, 150, "E7DDF0 adjacent helper"),
	(0x00E7DE90, 18, 130, "E7DE90 pass mode table apply helper"),
	(0x00E7DEF0, 18, 150, "E7DEF0 sampler-state table apply helper"),
	(0x00E7E940, 18, 150, "E7E940 helper called by E7EA00"),
	(0x00E7E990, 18, 120, "E7E990 renderer global +0xB0 caller candidate"),
	(0x00E7EA00, 24, 190, "E7EA00 renderer-global virtual apply helper"),
	(0x00E7EB00, 18, 110, "E7EB00 pass-entry cache/apply helper"),
	(0x00E7EB50, 18, 150, "E7EB50 pass/resource helper candidate"),
	(0x00E7ECD0, 18, 150, "E7ECD0 pass/resource release helper candidate"),
	(0x00E7EDF0, 18, 150, "E7EDF0 renderer-global current resource helper candidate"),
	(0x00E89250, 20, 180, "E89250 helper called by E89410"),
	(0x00E892D0, 20, 180, "E892D0 helper called by E89410"),
	(0x00E89410, 20, 90, "E89410 validation/apply helper"),
	(0x00E88A20, 16, 100, "NiDX9RenderState::SetTexture"),
	(0x00E88930, 16, 90, "NiDX9RenderState texture-stage-state setter"),
	(0x00E910A0, 16, 90, "NiDX9RenderState sampler-state setter"),
]

DATA_WINDOWS = [
	0x010EF6CC,
	0x010EF6E8,
	0x010EF6EC,
	0x010EF6F0,
	0x010F094C,
	0x010F0958,
	0x010F0968,
	0x010F096C,
	0x010F0970,
	0x011A9608,
	0x011BF558,
	0x0126F680,
	0x0126F6C0,
	0x0126F6C4,
	0x0126F6C8,
	0x0126F6CC,
	0x0126F728,
	0x0126F74C,
]

IMPORTANT_CALL_TARGETS = [
	0x00E7DC90,
	0x00E7E940,
	0x00E7EA00,
	0x00E7EB00,
	0x00E7EB50,
	0x00E7ECD0,
	0x00E7EDF0,
	0x00E88A20,
	0x00E88930,
	0x00E88FC0,
	0x00E89060,
	0x00E890C0,
	0x00E89250,
	0x00E892D0,
	0x00E89410,
	0x00E910A0,
]

MATCH_PATTERNS = [
	"0126f6c0",
	"0126f6c4",
	"0126f6c8",
	"0126f6cc",
	"011a9608",
	"011bf558",
	"0126f680",
	"0126f728",
	"0126f74c",
	"0126f92c",
	"0126f958",
	"e7dc90",
	"e7e940",
	"e7ea00",
	"e7eb00",
	"e7eb50",
	"e7ecd0",
	"e7edf0",
	"e88a20",
	"e88930",
	"e88fc0",
	"e89060",
	"e890c0",
	"e89250",
	"e892d0",
	"e89410",
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
	"vtable",
	"0x8c4",
	"+ 0x8c4",
	"+0x8c4",
	"0xc0",
	"+ 0xc0",
	"+0xc0",
	"0xcc",
	"+ 0xcc",
	"+0xcc",
	"0xdc",
	"+ 0xdc",
	"+0xdc",
	"0x104",
	"+ 0x104",
	"+0x104",
	"0x10c",
	"+ 0x10c",
	"+0x10c",
	"0x114",
	"+ 0x114",
	"+0x114",
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
	write_flag = "?"
	try:
		if rt.isWrite():
			write_flag = "WRITE"
	except:
		pass
	try:
		if rt.isRead():
			if write_flag == "?":
				write_flag = "READ"
			else:
				write_flag = write_flag + "+READ"
	except:
		pass
	return "%s/%s" % (name, write_flag)

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

def call_target_from_inst(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		if ref.getReferenceType().isCall():
			return ref.getToAddress().getOffset()
	return None

def list_contains_addr(items, addr_int):
	idx = 0
	while idx < len(items):
		if items[idx] == addr_int:
			return True
		idx += 1
	return False

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
	if lower.find("0126f6c") >= 0:
		return True
	if lower.find("011a9608") >= 0:
		return True
	if lower.find("011bf558") >= 0:
		return True
	if lower.find("0126f680") >= 0:
		return True
	if lower.find("0126f728") >= 0:
		return True
	if lower.find("0126f74c") >= 0:
		return True
	if lower.find("0x8c4") >= 0:
		return True
	if lower.find("0xc0") >= 0:
		return True
	if lower.find("0xcc") >= 0:
		return True
	if lower.find("0xdc") >= 0:
		return True
	if lower.find("0x104") >= 0:
		return True
	if lower.find("0x10c") >= 0:
		return True
	if lower.find("0x114") >= 0:
		return True
	if lower.find("0x10f8") >= 0:
		return True
	if lower.find("settexture") >= 0:
		return True
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
			disasm_window(inst.getAddress().getOffset(), 6, 12, "marker")
			count += 1
			if count > 160:
				write("  ... marker scan truncated")
				break
	write("  Total marker instructions: %d" % count)

def collect_call_targets(addr_int, max_targets):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	result = []
	if func is None:
		return result
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				if not list_contains_addr(result, tgt):
					result.append(tgt)
					if len(result) >= max_targets:
						return result
	return result

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

def audit_direct_callees_from_focus():
	write("")
	write("=" * 70)
	write("DIRECT CALLEES FROM E89410/E7EA00 HELPER CLUSTER")
	write("=" * 70)
	source_functions = [
		0x00E7DC90,
		0x00E7E940,
		0x00E7EA00,
		0x00E89250,
		0x00E892D0,
		0x00E89410,
	]
	seen = []
	src_idx = 0
	while src_idx < len(source_functions):
		src = source_functions[src_idx]
		targets = collect_call_targets(src, 80)
		tgt_idx = 0
		while tgt_idx < len(targets):
			tgt = targets[tgt_idx]
			if not list_contains_addr(seen, tgt):
				seen.append(tgt)
				write("")
				write("Callee from 0x%08x %s -> 0x%08x %s" % (src, label_for(src), tgt, label_for(tgt)))
				decompile_at(tgt, "direct callee from E89410/E7EA00 cluster", 12000)
				find_and_print_calls_from(tgt, "direct callee from E89410/E7EA00 cluster")
				print_matching_decompile_lines(tgt, "direct callee from E89410/E7EA00 cluster")
			tgt_idx += 1
		src_idx += 1
	write("  Total unique direct callees audited: %d" % len(seen))

def print_virtual_slot_questions():
	write("")
	write("=" * 70)
	write("VIRTUAL SLOT QUESTIONS")
	write("=" * 70)
	write("E7EA00 currently calls DAT_0126F6C8 slots +0xC0, +0xDC, and +0xCC.")
	write("E7EA00 calls DAT_0126F6C4 +0x8C4 object's vtable slot +0x0C.")
	write("E7EA00 calls DAT_0126F6C0 slot +0x114 only when the pass-entry type is 6.")
	write("This script must prove the object identities and slot implementations before any of those calls are treated as D3D, NiDX9RenderState, texture-stage, or sampler-state calls.")

def print_header():
	write("FNV PPLIGHTING RENDERER-GLOBAL VIRTUAL APPLY CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. What objects are stored in DAT_0126F6C0, DAT_0126F6C4, and DAT_0126F6C8?")
	write("2. Which functions write or initialize those globals, and what constructors/vtables do they imply?")
	write("3. What do the E7EA00 virtual slots +0xC0/+0xCC/+0xDC/+0x114 and nested +0x8C4/+0x0C apply?")
	write("4. Do E89250, E892D0, E7DC90, or E7E940 reach E88A20/E88930/E910A0 or raw D3D texture/stage/sampler calls?")
	write("5. Is the remaining pass-entry apply path a final texture-stage ownership contract, or only pass-resource/effect-object state?")

def main():
	print_header()
	print_virtual_slot_questions()
	audit_data_windows()
	audit_raw_windows()
	audit_refs()
	audit_focus_functions()
	audit_global_ref_callers()
	audit_direct_callees_from_focus()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pplighting_renderer_global_virtual_apply_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
