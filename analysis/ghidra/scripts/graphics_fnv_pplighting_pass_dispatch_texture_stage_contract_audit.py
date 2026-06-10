# @category Analysis
# @description Audit FNV PPLighting pass dispatcher to final texture-stage binding contract

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00B7C3A0: "B7 dispatcher/helper candidate",
	0x00B7C510: "B7 dispatcher/helper candidate",
	0x00B7C580: "B7 dispatcher/helper candidate",
	0x00B7C600: "B7 dispatcher/helper candidate",
	0x00B7C750: "B7 dispatcher/helper candidate",
	0x00B7C7B0: "B7 dispatcher/helper candidate",
	0x00B7C850: "B7 light/constant upload helper candidate",
	0x00B7CB00: "B7 dispatcher/helper candidate",
	0x00B7DAB0: "Current pass pre-apply helper called by BD4BA0",
	0x00B7DD50: "B7 current-pass ref helper candidate",
	0x00B7DDE0: "B7 current-pass/pass-entry apply helper candidate",
	0x00B7DED0: "B7 current-pass ref helper candidate",
	0x00B7DFE0: "B7 current-pass ref helper candidate",
	0x00B7E150: "B7 current-pass/pass-entry apply helper candidate",
	0x00BD1C50: "Current pass global writer / pass pixel-shader writer",
	0x00BD4BA0: "Current pass shader apply helper",
	0x00BE1F90: "BSShader::SetShaders shader-only entry",
	0x00BE2170: "Current-pass entry apply neighbor",
	0x00BE21B0: "Current-pass entry apply neighbor",
	0x00E7DE90: "Renderer/pass apply helper called by B7 functions",
	0x00E7EB00: "Renderer/pass entry apply helper candidate",
	0x00E7F7C0: "Renderer helper called by SetShaders",
	0x00E88930: "NiDX9RenderState texture-stage-state setter",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x00E910A0: "NiDX9RenderState sampler-state setter",
	0x010EF6E8: "Render-state vtable/data ref to SetTexture",
	0x010F0968: "Render-state vtable/data ref to SetTexture",
	0x011C73B4: "NiDX9Renderer singleton/global candidate",
	0x011F91C4: "Renderer/material global candidate",
	0x011F91C8: "Renderer/material global candidate",
	0x011F91E0: "Current geometry/material proxy candidate",
	0x011F91E4: "Current shader mode/id candidate",
	0x011FA0C0: "Renderer/pass global candidate",
	0x011FD9A8: "Renderer/pass global candidate",
	0x011FEBF0: "Renderer/pass global candidate",
	0x011FEC38: "Renderer/pass global candidate",
	0x011FEC4C: "Renderer/pass global candidate",
	0x0126F74C: "Current NiD3DPass global",
}

DISPATCH_FUNCTIONS = [
	0x00B7C3A0,
	0x00B7C510,
	0x00B7C580,
	0x00B7C600,
	0x00B7C750,
	0x00B7C7B0,
	0x00B7C850,
	0x00B7CB00,
	0x00B7DAB0,
	0x00B7DD50,
	0x00B7DDE0,
	0x00B7DED0,
	0x00B7DFE0,
	0x00B7E150,
]

APPLY_AND_BIND_FUNCTIONS = [
	0x00BD1C50,
	0x00BD4BA0,
	0x00BE1F90,
	0x00BE2170,
	0x00BE21B0,
	0x00E7DE90,
	0x00E7EB00,
	0x00E7F7C0,
	0x00E88930,
	0x00E88A20,
	0x00E910A0,
]

REF_TARGETS = [
	0x00B7C3A0,
	0x00B7C510,
	0x00B7C580,
	0x00B7C600,
	0x00B7C750,
	0x00B7C7B0,
	0x00B7C850,
	0x00B7CB00,
	0x00B7DAB0,
	0x00B7DD50,
	0x00B7DDE0,
	0x00B7DED0,
	0x00B7DFE0,
	0x00B7E150,
	0x00BD1C50,
	0x00BD4BA0,
	0x00BE2170,
	0x00BE21B0,
	0x00E7DE90,
	0x00E7EB00,
	0x00E88A20,
	0x010EF6E8,
	0x010F0968,
	0x011F91C4,
	0x011F91C8,
	0x011F91E0,
	0x011F91E4,
	0x011FA0C0,
	0x011FD9A8,
	0x011FEBF0,
	0x011FEC38,
	0x011FEC4C,
	0x0126F74C,
]

RAW_WINDOWS = [
	(0x00B7DAB0, 16, 90, "B7DAB0 current pass pre-apply helper"),
	(0x00B7DDE0, 18, 120, "B7DDE0 current-pass/pass-entry apply helper"),
	(0x00B7E150, 18, 140, "B7E150 current-pass/pass-entry apply helper"),
	(0x00B7C850, 18, 120, "B7C850 light/constant upload helper"),
	(0x00BE2170, 14, 80, "BE2170 current-pass entry apply neighbor"),
	(0x00BE21B0, 14, 80, "BE21B0 current-pass entry apply neighbor"),
	(0x00E7EB00, 18, 140, "E7EB00 renderer/pass entry apply candidate"),
	(0x00E7DE90, 18, 120, "E7DE90 renderer/pass apply helper"),
	(0x00BD1C50, 16, 90, "BD1C50 current pass writer"),
	(0x00BD4BA0, 16, 90, "BD4BA0 shader apply helper"),
	(0x00E88A20, 16, 100, "NiDX9RenderState::SetTexture"),
	(0x00E88930, 14, 90, "texture-stage-state setter"),
	(0x00E910A0, 14, 90, "sampler-state setter"),
]

DATA_WINDOWS = [
	0x010EF6E8,
	0x010F0968,
	0x011C73B4,
	0x011F91C4,
	0x011F91C8,
	0x011F91E0,
	0x011F91E4,
	0x011FA0C0,
	0x011FD9A8,
	0x011FEBF0,
	0x011FEC38,
	0x011FEC4C,
	0x0126F74C,
]

PASS_AND_ENTRY_OFFSETS = [
	(0x08, "pass-entry apply flag / written entry value field"),
	(0x09, "pass-entry vararg used count"),
	(0x0A, "pass-entry vararg capacity"),
	(0x0B, "pass-entry flag byte"),
	(0x0C, "pass-entry vararg pointer / current object list pointer"),
	(0x18, "NiD3DPass entry count candidate"),
	(0x24, "NiD3DPass pass-entry pointer array candidate"),
	(0x44, "NiD3DPass pixel shader pointer"),
	(0x5C, "NiD3DPass vertex shader pointer"),
	(0x64, "pass-entry resource/object pointer candidate"),
	(0x10A0, "NiDX9RenderState texture cache base"),
	(0x10F8, "NiDX9RenderState D3D device pointer"),
]

IMPORTANT_CALL_TARGETS = [
	0x00B7C3A0,
	0x00B7C510,
	0x00B7C580,
	0x00B7C600,
	0x00B7C750,
	0x00B7C7B0,
	0x00B7C850,
	0x00B7CB00,
	0x00B7DAB0,
	0x00B7DD50,
	0x00B7DDE0,
	0x00B7DED0,
	0x00B7DFE0,
	0x00B7E150,
	0x00BD1C50,
	0x00BD4BA0,
	0x00BE1F90,
	0x00BE2170,
	0x00BE21B0,
	0x00E7DE90,
	0x00E7EB00,
	0x00E7F7C0,
	0x00E88930,
	0x00E88A20,
	0x00E910A0,
]

MATCH_PATTERNS = [
	"0126f74c",
	"011f91c4",
	"011f91c8",
	"011f91e0",
	"011f91e4",
	"011fa0c0",
	"011fd9a8",
	"011febf0",
	"011fec38",
	"011fec4c",
	"b7dab0",
	"b7dde0",
	"b7e150",
	"e7eb00",
	"e7de90",
	"e88a20",
	"e88930",
	"e910a0",
	"10a0",
	"10f8",
	"settexture",
	"set texture",
	"texture",
	"sampler",
	"stage",
	"pass",
	"shader",
	"0x231",
	"0x232",
	"0x233",
	"0x250",
	"0x251",
	"+ 0x104",
	"+0x104",
	"+ 0x24",
	"+0x24",
	"+ 0x18",
	"+0x18",
	"+ 0x44",
	"+0x44",
	"+ 0x5c",
	"+0x5c",
	"+ 0x64",
	"+0x64",
	"+ 0xc",
	"+0xc",
	"+ 0xb",
	"+0xb",
	"+ 0xa",
	"+0xa",
	"+ 0x9",
	"+0x9",
	"+ 0x8",
	"+0x8",
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
		if count > 200:
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

def text_has_field_offset(text, offset):
	lower = text.lower()
	if lower.find("+ 0x%x" % offset) >= 0:
		return True
	if lower.find("+0x%x" % offset) >= 0:
		return True
	if lower.find("+ %d" % offset) >= 0:
		return True
	if lower.find("+%d" % offset) >= 0:
		return True
	return False

def text_has_any_pass_or_entry_offset(text):
	idx = 0
	while idx < len(PASS_AND_ENTRY_OFFSETS):
		if text_has_field_offset(text, PASS_AND_ENTRY_OFFSETS[idx][0]):
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

def inst_has_important_scalar(text):
	lower = text.lower()
	if lower.find("0126f74c") >= 0:
		return True
	if lower.find("011f91") >= 0:
		return True
	if lower.find("011fa0c0") >= 0:
		return True
	if lower.find("011fd9a8") >= 0:
		return True
	if lower.find("011fec") >= 0:
		return True
	if lower.find("010ef6e8") >= 0:
		return True
	if lower.find("010f0968") >= 0:
		return True
	if lower.find("10a0") >= 0:
		return True
	if lower.find("10f8") >= 0:
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
		if text_has_any_pass_or_entry_offset(text) or inst_has_important_scalar(text) or is_important_call(target):
			if target is None:
				write("  0x%08x: %s" % (inst.getAddress().getOffset(), text))
			else:
				write("  0x%08x: %s ; CALL 0x%08x %s" % (inst.getAddress().getOffset(), text, target, label_for(target)))
			disasm_window(inst.getAddress().getOffset(), 5, 10, "marker")
			count += 1
			if count > 100:
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

def print_offset_legend():
	write("")
	write("=" * 70)
	write("Pass/pass-entry/render-state offsets under audit")
	write("=" * 70)
	idx = 0
	while idx < len(PASS_AND_ENTRY_OFFSETS):
		item = PASS_AND_ENTRY_OFFSETS[idx]
		write("  +0x%04X: %s" % (item[0], item[1]))
		idx += 1

def audit_data_windows():
	idx = 0
	while idx < len(DATA_WINDOWS):
		dump_data_window(DATA_WINDOWS[idx], 10, 28)
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

def audit_function_list(functions, max_len):
	idx = 0
	while idx < len(functions):
		addr = functions[idx]
		label = label_for(addr)
		decompile_at(addr, label, max_len)
		find_and_print_calls_from(addr, label)
		print_matching_decompile_lines(addr, label)
		scan_function_markers(addr, label)
		idx += 1

def audit_key_ref_callers():
	audit_unique_ref_callers(0x00E7EB00, label_for(0x00E7EB00), 18)
	audit_unique_ref_callers(0x00E7DE90, label_for(0x00E7DE90), 14)
	audit_unique_ref_callers(0x00E88A20, label_for(0x00E88A20), 16)
	audit_unique_ref_callers(0x010EF6E8, label_for(0x010EF6E8), 8)
	audit_unique_ref_callers(0x010F0968, label_for(0x010F0968), 8)
	audit_unique_ref_callers(0x0126F74C, label_for(0x0126F74C), 16)

def print_header():
	write("FNV PPLIGHTING PASS DISPATCH TEXTURE-STAGE CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. Which B7 helpers dispatch current-pass pass entries and call E7EB00/E7DE90?")
	write("2. Which pass-entry fields are consumed during apply, especially +0x08/+0x09/+0x0C/+0x64?")
	write("3. Does the dispatcher path directly or indirectly reach NiDX9RenderState::SetTexture @ 0x00E88A20?")
	write("4. Can a final stage map be proven from pass IDs/varargs, or must Psycho capture E88A20 runtime bindings?")
	write("5. Are vtable/data refs 0x010EF6E8 and 0x010F0968 only SetTexture vtable slots, or used by callable dispatch sites?")

def main():
	print_header()
	print_offset_legend()
	audit_data_windows()
	audit_raw_windows()
	audit_refs()
	audit_function_list(DISPATCH_FUNCTIONS, 18000)
	audit_function_list(APPLY_AND_BIND_FUNCTIONS, 18000)
	audit_key_ref_callers()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pplighting_pass_dispatch_texture_stage_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
