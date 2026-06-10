# @category Analysis
# @description Audit FNV PPLighting pass-entry layout and draw-time apply/bind contract

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00BA3AA0: "Vector/list append helper used by pass entry list",
	0x00BA8B10: "Pass entry init/copy candidate",
	0x00BA8C50: "Pass entry reused-entry parameter setter candidate",
	0x00BA8CD0: "Pass entry cleanup/release candidate",
	0x00BA8D30: "Pass entry list reserve/grow candidate",
	0x00BA8EC0: "Pass entry constructor candidate",
	0x00BA94B0: "Pass list/container constructor candidate",
	0x00BA95E0: "Pass list/container reset/ensure candidate",
	0x00BA9EE0: "Pass entry append/reuse helper",
	0x00BD1C50: "Current pass writer/apply candidate",
	0x00BD4BA0: "Current pass reader/bind candidate",
	0x00BE1F90: "BSShader::SetShaders raw entry",
	0x00BE2170: "BSShader current-pass neighbor",
	0x00BE21B0: "BSShader current-pass neighbor",
	0x00E7F7C0: "Renderer/helper called by SetShaders",
	0x00E806C0: "Texture/render-state bind candidate",
	0x00E80766: "Texture/render-state bind candidate interior",
	0x00E811D0: "Texture/render-state bind candidate",
	0x00E814B0: "Texture/render-state bind candidate",
	0x00E81510: "Texture/render-state bind candidate",
	0x00E88930: "Texture stage state candidate",
	0x00E88A20: "NiDX9RenderState::SetTexture raw entry",
	0x00E90850: "Sampler/render-state candidate",
	0x00E90933: "Sampler/render-state candidate interior",
	0x00E910A0: "Sampler state candidate",
	0x00DA2990: "D3D SetTexture thunk/call-site candidate",
	0x00DA2A25: "D3D SetTexture call instruction",
	0x011C73B4: "NiDX9Renderer singleton/global candidate",
	0x011F91E0: "Current geometry slot/proxy candidate",
	0x011F91E4: "Current shader mode/id candidate",
	0x0126F74C: "Current NiD3DPass global",
}

PASS_ENTRY_FUNCTIONS = [
	0x00BA8B10,
	0x00BA8C50,
	0x00BA8CD0,
	0x00BA8D30,
	0x00BA8EC0,
	0x00BA94B0,
	0x00BA95E0,
	0x00BA9EE0,
	0x00BA3AA0,
]

APPLY_FUNCTIONS = [
	0x00BD1C50,
	0x00BD4BA0,
	0x00BE1F90,
	0x00BE2170,
	0x00BE21B0,
	0x00E7F7C0,
	0x00E88A20,
	0x00E88930,
	0x00E910A0,
	0x00E90850,
	0x00E90933,
	0x00E806C0,
	0x00E80766,
	0x00E811D0,
	0x00E814B0,
	0x00E81510,
	0x00DA2990,
]

REF_TARGETS = [
	0x00BA8B10,
	0x00BA8C50,
	0x00BA8CD0,
	0x00BA8D30,
	0x00BA8EC0,
	0x00BA94B0,
	0x00BA95E0,
	0x00BA9EE0,
	0x00BD1C50,
	0x00BD4BA0,
	0x00BE1F90,
	0x00BE2170,
	0x00BE21B0,
	0x00E7F7C0,
	0x00E88A20,
	0x00DA2990,
	0x00DA2A25,
	0x011C73B4,
	0x011F91E0,
	0x011F91E4,
	0x0126F74C,
]

RAW_WINDOWS = [
	(0x00BA8C50, 10, 44, "pass entry reused-entry setter"),
	(0x00BA8EC0, 10, 60, "pass entry constructor"),
	(0x00BA9EE0, 12, 80, "pass entry append/reuse helper"),
	(0x00BD1C50, 16, 80, "current pass writer/apply candidate"),
	(0x00BD4BA0, 16, 80, "current pass reader/bind candidate"),
	(0x00BE1F90, 12, 70, "BSShader::SetShaders raw entry"),
	(0x00BE2170, 12, 56, "BSShader current-pass neighbor"),
	(0x00BE21B0, 12, 56, "BSShader current-pass neighbor"),
	(0x00E88A20, 16, 90, "NiDX9RenderState::SetTexture raw entry"),
	(0x00E88930, 14, 70, "texture stage state candidate"),
	(0x00E910A0, 14, 70, "sampler state candidate"),
	(0x00DA2990, 16, 80, "D3D SetTexture thunk/call-site candidate"),
	(0x00DA2A25, 20, 48, "D3D SetTexture call instruction"),
]

DATA_WINDOWS = [
	0x011C73B4,
	0x011F91E0,
	0x011F91E4,
	0x0126F74C,
]

PASS_ENTRY_OFFSETS = [
	(0x00, "pass/mode id byte/dword slot"),
	(0x04, "short parameter slot written by BA9EE0"),
	(0x06, "flag byte reset by BA9EE0"),
	(0x07, "byte parameter slot written by BA9EE0"),
	(0x08, "flag byte reset by BA9EE0 and special branch sets to 1"),
	(0x0B, "flag byte reset by BA9EE0"),
	(0x0C, "probable parameter/storage slot"),
	(0x10, "pass entry object/list stride boundary"),
]

IMPORTANT_CALL_TARGETS = [
	0x00BA3AA0,
	0x00BA8B10,
	0x00BA8C50,
	0x00BA8CD0,
	0x00BA8D30,
	0x00BA8EC0,
	0x00BA94B0,
	0x00BA95E0,
	0x00BA9EE0,
	0x00BD1C50,
	0x00BD4BA0,
	0x00BE1F90,
	0x00BE2170,
	0x00BE21B0,
	0x00E7F7C0,
	0x00E88A20,
	0x00DA2990,
]

MATCH_PATTERNS = [
	"0126f74c",
	"011c73b4",
	"011f91e0",
	"011f91e4",
	"ba8c50",
	"ba8ec0",
	"ba8d30",
	"ba3aa0",
	"ba9ee0",
	"bd1c50",
	"bd4ba0",
	"be1f90",
	"e88a20",
	"da2990",
	"settexture",
	"set texture",
	"texture",
	"sampler",
	"stage",
	"pass",
	"shader",
	"+ 0x44",
	"+0x44",
	"+ 0x5c",
	"+0x5c",
	"+ 0x10",
	"+0x10",
	"+ 0xc",
	"+0xc",
	"+ 0xb",
	"+0xb",
	"+ 0x8",
	"+0x8",
	"+ 0x7",
	"+0x7",
	"+ 0x6",
	"+0x6",
	"+ 0x4",
	"+0x4",
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
		if count > 180:
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

def text_has_any_pass_entry_offset(text):
	idx = 0
	while idx < len(PASS_ENTRY_OFFSETS):
		if text_has_field_offset(text, PASS_ENTRY_OFFSETS[idx][0]):
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
	if lower.find("011c73b4") >= 0:
		return True
	if lower.find("011f91e0") >= 0:
		return True
	if lower.find("011f91e4") >= 0:
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
		if text_has_any_pass_entry_offset(text) or inst_has_important_scalar(text) or is_important_call(target):
			if target is None:
				write("  0x%08x: %s" % (inst.getAddress().getOffset(), text))
			else:
				write("  0x%08x: %s ; CALL 0x%08x %s" % (inst.getAddress().getOffset(), text, target, label_for(target)))
			disasm_window(inst.getAddress().getOffset(), 5, 10, "marker")
			count += 1
			if count > 90:
				write("  ... marker scan truncated")
				break
	write("  Total marker instructions: %d" % count)

def print_pass_entry_layout():
	write("")
	write("=" * 70)
	write("Pass entry field layout under audit")
	write("=" * 70)
	idx = 0
	while idx < len(PASS_ENTRY_OFFSETS):
		write("  +0x%02X: %s" % (PASS_ENTRY_OFFSETS[idx][0], PASS_ENTRY_OFFSETS[idx][1]))
		idx += 1

def audit_data_windows():
	idx = 0
	while idx < len(DATA_WINDOWS):
		dump_data_window(DATA_WINDOWS[idx], 10, 24)
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
				decompile_at(entry, "ref caller of %s" % label, 12000)
				print_matching_decompile_lines(entry, "ref caller of %s" % label)
				scan_function_markers(entry, "ref caller of %s" % label)
				count += 1
				if count >= max_funcs:
					write("  ... unique ref caller audit truncated")
					break
	write("  Total unique ref functions audited: %d" % count)

def audit_key_ref_callers():
	audit_unique_ref_callers(0x0126F74C, label_for(0x0126F74C), 12)
	audit_unique_ref_callers(0x00DA2990, label_for(0x00DA2990), 12)
	audit_unique_ref_callers(0x00DA2A25, label_for(0x00DA2A25), 8)
	audit_unique_ref_callers(0x00E88A20, label_for(0x00E88A20), 12)

def print_header():
	write("FNV PPLIGHTING PASS ENTRY APPLY CONTRACT AUDIT")
	write("")
	write("Questions:")
	write("1. What fields do BA8C50/BA8EC0 store in the 0x10-byte pass entry used by BA9EE0?")
	write("2. Which pass/list functions later consume those fields?")
	write("3. Where does the current NiD3DPass global feed shader binding versus texture binding?")
	write("4. Which function owns final D3D SetTexture calls for draw-time stages?")
	write("5. Can Psycho PBR rely on vanilla-bound textures at BSShader::SetShaders, or is another apply hook required?")

def main():
	print_header()
	print_pass_entry_layout()
	audit_data_windows()
	audit_raw_windows()
	audit_refs()
	audit_function_list(PASS_ENTRY_FUNCTIONS, 22000)
	audit_function_list(APPLY_FUNCTIONS, 18000)
	audit_key_ref_callers()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pplighting_pass_entry_apply_contract_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
