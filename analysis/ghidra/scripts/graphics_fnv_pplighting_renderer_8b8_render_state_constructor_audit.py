# @category Analysis
# @description Prove FNV PPLighting renderer +0x8B8 render-state constructor and vtable identity

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00E7E8D0: "Renderer global setter: DAT_0126F6C4/C0/C8",
	0x00E7EA00: "PPLighting pass-entry downstream virtual apply helper",
	0x00E81940: "Renderer setup: seeds DAT_0126F99C from renderer +0x8B8",
	0x00E819F0: "Renderer clear/shutdown: clears DAT_0126F99C",
	0x00E87AB0: "Candidate vtable A +0x100 target",
	0x00E881A0: "Candidate vtable A constructor/init",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x00E88B00: "Candidate vtable A destructor/reset",
	0x00E88930: "NiDX9RenderState texture-stage-state setter",
	0x00E89250: "Tracked texture-stage-state flush helper",
	0x00E892D0: "Tracked sampler-state flush helper",
	0x00E910A0: "NiDX9RenderState sampler-state setter",
	0x00E91160: "Candidate vtable B constructor/init",
	0x00E911E0: "Candidate vtable B +0x100 target",
	0x00E91590: "Candidate vtable B constructor/copy/init",
	0x010EF60C: "candidate render-state vtable A base",
	0x010EF70C: "candidate vtable A +0x100 slot address",
	0x010F088C: "candidate render-state vtable B base",
	0x010F098C: "candidate vtable B +0x100 slot address",
	0x0126F6C0: "renderer-global object from renderer +0x288",
	0x0126F6C4: "renderer global object set directly by E7E8D0",
	0x0126F6C8: "renderer-global render-state object from renderer +0x8B8",
	0x0126F918: "sampler-state flush table",
	0x0126F92C: "sampler-state TypeMap",
	0x0126F948: "texture-stage-state flush table",
	0x0126F958: "texture-stage-state TypeMap",
	0x0126F99C: "render-state global used by E89250/E892D0",
}

FOCUS_FUNCTIONS = [
	0x00E81940,
	0x00E819F0,
	0x00E7E8D0,
	0x00E7EA00,
	0x00E89250,
	0x00E892D0,
	0x00E881A0,
	0x00E88B00,
	0x00E91160,
	0x00E91590,
	0x00E87AB0,
	0x00E911E0,
	0x00E88930,
	0x00E910A0,
	0x00E88A20,
]

REF_TARGETS = [
	0x00E81940,
	0x00E819F0,
	0x00E7E8D0,
	0x00E881A0,
	0x00E88B00,
	0x00E91160,
	0x00E91590,
	0x00E87AB0,
	0x00E911E0,
	0x00E88930,
	0x00E910A0,
	0x00E88A20,
	0x010EF60C,
	0x010EF70C,
	0x010F088C,
	0x010F098C,
	0x0126F6C8,
	0x0126F99C,
]

CALLER_TARGETS = [
	0x00E81940,
	0x00E819F0,
	0x00E7E8D0,
	0x00E881A0,
	0x00E88B00,
	0x00E91160,
	0x00E91590,
	0x00E87AB0,
	0x00E911E0,
]

RAW_WINDOWS = [
	(0x00E81940, 20, 130, "E81940 renderer setup"),
	(0x00E819F0, 20, 110, "E819F0 renderer clear"),
	(0x00E7E8D0, 18, 120, "E7E8D0 renderer global setter"),
	(0x00E881A0, 20, 190, "E881A0 vtable A constructor"),
	(0x00E88B00, 20, 130, "E88B00 vtable A destructor/reset"),
	(0x00E91160, 20, 180, "E91160 vtable B constructor"),
	(0x00E91590, 20, 180, "E91590 vtable B constructor/copy/init"),
	(0x00E87AB0, 16, 90, "vtable A +0x100 target"),
	(0x00E911E0, 16, 90, "vtable B +0x100 target"),
	(0x00E88A20, 16, 110, "E88A20 SetTexture"),
]

DATA_WINDOWS = [
	0x010EF60C,
	0x010EF6CC,
	0x010EF6D8,
	0x010EF6E8,
	0x010EF70C,
	0x010F088C,
	0x010F094C,
	0x010F0958,
	0x010F0968,
	0x010F098C,
	0x0126F6C8,
	0x0126F99C,
]

VTABLE_BASES = [
	(0x010EF60C, "candidate vtable A"),
	(0x010F088C, "candidate vtable B"),
]

VTABLE_SLOTS = [
	(0x04, "addref-like slot"),
	(0x08, "release-like slot"),
	(0x68, "render-state helper slot used by E7DC90"),
	(0xB0, "constant upload-like slot"),
	(0xC0, "texture-stage-state setter candidate"),
	(0xCC, "sampler-state setter candidate"),
	(0xDC, "SetTexture candidate"),
	(0x100, "renderer setup virtual called by E81940"),
	(0x114, "extra high slot"),
]

SCAN_8B8_PATTERNS = [
	"0x8b8",
	"+ 0x8b8",
	"+0x8b8",
]

SCAN_VTABLE_PATTERNS = [
	"0x10ef60c",
	"010ef60c",
	"0x10f088c",
	"010f088c",
]

SCAN_RENDER_STATE_PATTERNS = [
	"0x8b8",
	"0x10ef60c",
	"010ef60c",
	"0x10f088c",
	"010f088c",
	"0x126f6c8",
	"0126f6c8",
	"0x126f99c",
	"0126f99c",
	"0x100",
	"+ 0x100",
	"+0x100",
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

def decompile_at(addr_int, label, max_len=22000):
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
		if count > 240:
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
		target = call_target_from_inst(inst)
		if target is not None:
			extra = " ; CALL 0x%08x %s" % (target, label_for(target))
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

def audit_unique_ref_callers(addr_int, label, max_funcs):
	write("")
	write("=" * 70)
	write("UNIQUE REF/CALLER FUNCTIONS FOR 0x%08x (%s)" % (addr_int, label))
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
				decompile_at(entry, "ref/caller for %s" % label, 26000)
				find_and_print_calls_from(entry, "ref/caller for %s" % label)
				count += 1
				if count >= max_funcs:
					write("  ... unique caller audit truncated")
					break
	write("  Total unique ref/caller functions audited: %d" % count)

def pattern_matches(text, patterns):
	lower = text.lower()
	idx = 0
	while idx < len(patterns):
		if lower.find(patterns[idx]) >= 0:
			return True
		idx += 1
	return False

def classify_8b8_access(text):
	lower = text.lower()
	idx = lower.find("0x8b8")
	comma = lower.find(",")
	if idx < 0:
		return "not-8b8"
	if comma >= 0 and idx < comma:
		return "field-as-destination-or-address-operand"
	if comma >= 0 and idx > comma:
		return "field-as-source-or-late-operand"
	return "field-reference"

def scan_functions_for_instruction_patterns(patterns, label, max_hits, max_funcs_to_decompile):
	write("")
	write("=" * 70)
	write("WHOLE-PROGRAM INSTRUCTION SCAN: %s" % label)
	write("=" * 70)
	func_iter = fm.getFunctions(True)
	hit_count = 0
	seen_funcs = []
	while func_iter.hasNext():
		func = func_iter.next()
		inst_iter = listing.getInstructions(func.getBody(), True)
		while inst_iter.hasNext():
			inst = inst_iter.next()
			text = inst.toString()
			if pattern_matches(text, patterns):
				entry = func.getEntryPoint().getOffset()
				access = classify_8b8_access(text)
				write("  HIT 0x%08x in 0x%08x %s [%s] %s" % (inst.getAddress().getOffset(), entry, func.getName(), access, text))
				disasm_window(inst.getAddress().getOffset(), 8, 16, "scan hit %s" % label)
				if not list_contains_addr(seen_funcs, entry):
					seen_funcs.append(entry)
				hit_count += 1
				if hit_count >= max_hits:
					write("  ... scan hit limit reached")
					decompile_scan_hit_functions(seen_funcs, label, max_funcs_to_decompile)
					write("  Total scan hits: %d" % hit_count)
					return
	write("  Total scan hits: %d" % hit_count)
	decompile_scan_hit_functions(seen_funcs, label, max_funcs_to_decompile)

def decompile_scan_hit_functions(seen_funcs, label, max_funcs):
	write("")
	write("=" * 70)
	write("UNIQUE FUNCTIONS FROM SCAN: %s" % label)
	write("=" * 70)
	idx = 0
	count = 0
	while idx < len(seen_funcs):
		entry = seen_funcs[idx]
		decompile_at(entry, "scan hit function for %s" % label, 26000)
		find_and_print_calls_from(entry, "scan hit function for %s" % label)
		count += 1
		if count >= max_funcs:
			write("  ... scan function decompile limit reached")
			break
		idx += 1
	write("  Total scan functions decompiled: %d" % count)

def audit_focus_functions():
	idx = 0
	while idx < len(FOCUS_FUNCTIONS):
		addr = FOCUS_FUNCTIONS[idx]
		label = label_for(addr)
		decompile_at(addr, label, 30000)
		find_and_print_calls_from(addr, label)
		idx += 1

def audit_refs():
	idx = 0
	while idx < len(REF_TARGETS):
		addr = REF_TARGETS[idx]
		find_refs_to(addr, label_for(addr))
		idx += 1

def audit_callers():
	idx = 0
	while idx < len(CALLER_TARGETS):
		addr = CALLER_TARGETS[idx]
		audit_unique_ref_callers(addr, label_for(addr), 30)
		idx += 1

def audit_raw_windows():
	idx = 0
	while idx < len(RAW_WINDOWS):
		item = RAW_WINDOWS[idx]
		disasm_window(item[0], item[1], item[2], item[3])
		idx += 1

def audit_data_windows():
	idx = 0
	while idx < len(DATA_WINDOWS):
		dump_data_window(DATA_WINDOWS[idx], 12, 36)
		idx += 1

def audit_vtables():
	idx = 0
	while idx < len(VTABLE_BASES):
		item = VTABLE_BASES[idx]
		dump_vtable_slots(item[0], item[1])
		idx += 1

def print_header():
	write("FNV PPLIGHTING RENDERER +0x8B8 RENDER-STATE CONSTRUCTOR AUDIT")
	write("")
	write("Questions:")
	write("1. Which code writes or constructs the object stored at renderer +0x8B8?")
	write("2. Does renderer +0x8B8 use vtable A 0x010EF60C or vtable B 0x010F088C?")
	write("3. Which +0x100 target is called by E81940 after DAT_0126F99C is seeded?")
	write("4. Can E7EA00 +0xDC be promoted to the final PPLighting SetTexture contract?")

def print_known_prior_contract():
	write("")
	write("=" * 70)
	write("PRIOR CONTRACT FROM render_state_global_identity_followup")
	write("=" * 70)
	write("E81940 loads EDI = *(renderer +0x8B8), calls E7E8D0(renderer), then writes DAT_0126F99C = EDI.")
	write("E7E8D0 independently writes DAT_0126F6C8 = *(renderer +0x8B8).")
	write("Therefore DAT_0126F99C and DAT_0126F6C8 share the same runtime pointer during renderer setup.")
	write("Vtable A maps +0xC0 -> E88930 and +0xDC -> E88A20, but +0xCC is 0x00EC60FA.")
	write("Vtable B maps +0xC0 -> E88930, +0xCC -> E910A0, and +0xDC -> E88A20.")
	write("This script must prove the renderer +0x8B8 object's constructor/vtable, not infer it.")

def run_scans():
	scan_functions_for_instruction_patterns(SCAN_8B8_PATTERNS, "all instructions mentioning +0x8B8", 160, 45)
	scan_functions_for_instruction_patterns(SCAN_VTABLE_PATTERNS, "all instructions mentioning candidate render-state vtable bases", 120, 35)
	scan_functions_for_instruction_patterns(SCAN_RENDER_STATE_PATTERNS, "broad render-state identity markers", 220, 45)

def main():
	print_header()
	print_known_prior_contract()
	audit_vtables()
	audit_data_windows()
	audit_refs()
	audit_raw_windows()
	audit_focus_functions()
	audit_callers()
	run_scans()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pplighting_renderer_8b8_render_state_constructor_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
