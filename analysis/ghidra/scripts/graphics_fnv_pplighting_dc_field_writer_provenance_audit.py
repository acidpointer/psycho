# @category Analysis
# @description Audit FNV BSShaderPPLighting +0xDC writer provenance from vtables and constructor refs

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00AA13E0: "Game allocation helper",
	0x00A75C20: "+0xDC candidate allocated-object init",
	0x00B4E150: "+0xDC writer candidate",
	0x00B4E1E0: "+0xDC ref/update candidate",
	0x00B5AAC0: "+0xDC writer candidate",
	0x00B5AC90: "+0xDC ref/update candidate",
	0x00B5E0F0: "+0xDC refcounted writer candidate",
	0x00B5E5A0: "+0xDC release/reset candidate",
	0x00B660D0: "Shader-property init/copy helper candidate",
	0x00B666D0: "PPLighting vtable method candidate",
	0x00B66B80: "PPLighting vtable method candidate",
	0x00B66C40: "PPLighting vtable method candidate",
	0x00B66F50: "+0xDC writer candidate near PPLighting vtable methods",
	0x00B671E0: "PPLighting vtable method candidate",
	0x00B671F0: "PPLighting vtable method candidate",
	0x00B67200: "PPLighting vtable method candidate",
	0x00B67260: "PPLighting vtable method candidate",
	0x00B67290: "PPLighting vtable method candidate",
	0x00B672E0: "PPLighting vtable method candidate",
	0x00B67330: "PPLighting vtable method candidate",
	0x00B67380: "+0xDC release/reset candidate near PPLighting vtable methods",
	0x00B675C0: "+0xDC reset candidate near PPLighting vtable methods",
	0x00B676A0: "+0xDC copy/assign candidate near PPLighting vtable methods",
	0x00B68B10: "PPLighting vtable method candidate",
	0x00B690D0: "+0xDC reader fanout candidate",
	0x00B6A6C0: "+0xDC copy candidate",
	0x00B707D0: "PPLighting runtime light count helper candidate",
	0x00B70820: "Native light-list color builder",
	0x00B70DE0: "+0xDC reader candidate",
	0x00B71130: "+0xDC reader candidate",
	0x00B9FDA0: "+0xDC candidate object copy/init",
	0x00BDB4A0: "PPLighting setup geometry variant",
	0x00BD9D00: "PPLighting +0xDC pass builder",
	0x00BD9F90: "PPLighting +0xDC +0x6C pass builder",
	0x00BDC030: "PPLighting +0xDC late pass builder",
	0x00BDF790: "PPLighting setup geometry",
	0x00FDF1C0: "InterlockedIncrement import pointer",
	0x00FDF1C4: "InterlockedDecrement import pointer",
	0x010AE1B8: "PPLighting-like vtable start 0",
	0x010AE1E4: "PPLighting-like vtable setup variant slot 0",
	0x010AE1E8: "PPLighting-like vtable setup slot 0",
	0x010B8418: "SpeedTreeBillboardShaderProperty vtable start",
	0x010B8444: "SpeedTreeBillboardShaderProperty setup variant slot",
	0x010B8448: "SpeedTreeBillboardShaderProperty setup slot",
	0x010B9420: "SpeedTreeBranchShaderProperty vtable start",
	0x010B944C: "SpeedTreeBranchShaderProperty setup variant slot",
	0x010B9450: "SpeedTreeBranchShaderProperty setup slot",
	0x010B9578: "SpeedTree shader-property vtable start",
	0x010B95A4: "SpeedTree shader-property setup variant slot",
	0x010B95A8: "SpeedTree shader-property setup slot",
	0x010B99F8: "DistantTree shader-property vtable start",
	0x010B9A24: "DistantTree shader-property setup variant slot",
	0x010B9A28: "DistantTree shader-property setup slot",
	0x010BACE0: "Light/beam-adjacent shader-property vtable start",
	0x010BAD0C: "Light/beam-adjacent shader-property setup variant slot",
	0x010BAD10: "Light/beam-adjacent shader-property setup slot",
	0x010BCC48: "BeamShaderProperty vtable start",
	0x010BCC74: "BeamShaderProperty setup variant slot",
	0x010BCC78: "BeamShaderProperty setup slot",
	0x011F4998: "Renderer float/color global triple start",
	0x011F49A0: "Renderer float/color global triple end",
}

VTABLE_STARTS = [
	0x010AE1B8,
	0x010B8418,
	0x010B9420,
	0x010B9578,
	0x010B99F8,
	0x010BACE0,
	0x010BCC48,
]

VTABLE_SETUP_SLOTS = [
	0x010AE1E4,
	0x010AE1E8,
	0x010B8444,
	0x010B8448,
	0x010B944C,
	0x010B9450,
	0x010B95A4,
	0x010B95A8,
	0x010B9A24,
	0x010B9A28,
	0x010BAD0C,
	0x010BAD10,
	0x010BCC74,
	0x010BCC78,
]

PPLIGHTING_METHODS = [
	0x00B671E0,
	0x00B671F0,
	0x00B67200,
	0x00B67260,
	0x00B666D0,
	0x00B67290,
	0x00B672E0,
	0x00B67330,
	0x00B68B10,
	0x00B66B80,
	0x00B66C40,
	0x00BDB4A0,
	0x00BDF790,
]

DC_CANDIDATE_FUNCTIONS = [
	0x00B4E150,
	0x00B4E1E0,
	0x00B5AAC0,
	0x00B5AC90,
	0x00B5E0F0,
	0x00B5E5A0,
	0x00B66F50,
	0x00B67380,
	0x00B675C0,
	0x00B676A0,
	0x00B690D0,
	0x00B6A6C0,
	0x00B70820,
	0x00B70DE0,
	0x00B71130,
]

DC_INSTRUCTION_TARGETS = [
	0x00B4E174,
	0x00B4E225,
	0x00B5ABBA,
	0x00B5ACDE,
	0x00B5E152,
	0x00B5E313,
	0x00B5E33D,
	0x00B5E3DC,
	0x00B5E648,
	0x00B5E665,
	0x00B66FCC,
	0x00B67114,
	0x00B67135,
	0x00B6747D,
	0x00B674A0,
	0x00B674F3,
	0x00B675C9,
	0x00B675EE,
	0x00B67930,
	0x00B67936,
	0x00B67959,
	0x00B6795F,
	0x00B6A872,
	0x00B6A878,
]

REF_TARGETS = [
	0x00BDB4A0,
	0x00BDF790,
	0x00BD9D00,
	0x00BD9F90,
	0x00BDC030,
	0x00AA13E0,
	0x00A75C20,
	0x00B9FDA0,
	0x00FDF1C0,
	0x00FDF1C4,
]

MATCH_PATTERNS = [
	"+ 0xdc",
	"+0xdc",
	"param_1[0x37]",
	"+ 0x6c",
	"+0x6c",
	"00bdb4a0",
	"00bdf790",
	"010ae1b8",
	"010b8418",
	"010b9420",
	"010b9578",
	"010b99f8",
	"010bace0",
	"010bcc48",
	"fdf1c0",
	"fdf1c4",
	"aa13e0",
	"a75c20",
	"b9fda0",
	"interlocked",
	"textureset",
	"texture",
	"speedtree",
	"beamshaderproperty",
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

def decompile_at(addr_int, label, max_len=26000):
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

def decompile_text_for_func(func):
	if func is None:
		return None
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		return result.getDecompiledFunction().getC()
	return None

def find_refs_to(addr_int, label):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		inst = listing.getInstructionContaining(ref.getFromAddress())
		inst_text = inst.toString() if inst is not None else ""
		write("  %s @ 0x%08x (in %s) %s" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, inst_text))
		count += 1
		if count > 80:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found at 0x%08x]" % addr_int)
		return
	body = func.getBody()
	inst_iter = listing.getInstructions(body, True)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else label_for(tgt)
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
	write("  Total: %d calls" % count)

def add_function_for_addr(addr, functions):
	func = fm.getFunctionContaining(addr)
	if func is not None:
		functions[func.getEntryPoint().getOffset()] = True

def add_ref_functions(addr_int, functions):
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	while refs.hasNext():
		ref = refs.next()
		add_function_for_addr(ref.getFromAddress(), functions)

def text_has_pattern(text):
	lower = text.lower()
	idx = 0
	while idx < len(MATCH_PATTERNS):
		if lower.find(MATCH_PATTERNS[idx]) >= 0:
			return True
		idx += 1
	return False

def text_mentions_addr(text, addr_int):
	lower = text.lower()
	full = "%08x" % addr_int
	short = "%x" % addr_int
	if lower.find(full) >= 0:
		return True
	if lower.find(short) >= 0:
		return True
	return False

def text_mentions_any_addr(text, addrs):
	idx = 0
	while idx < len(addrs):
		if text_mentions_addr(text, addrs[idx]):
			return True
		idx += 1
	return False

def function_has_dc_marker(func):
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		if text.find("+ 0xdc") >= 0 or text.find("+0xdc") >= 0:
			return True
	code = decompile_text_for_func(func)
	if code is None:
		return False
	lower = code.lower()
	if lower.find("+ 0xdc") >= 0 or lower.find("+0xdc") >= 0:
		return True
	if lower.find("param_1[0x37]") >= 0:
		return True
	return False

def function_mentions_any_vtable(func):
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		if text_mentions_any_addr(text, VTABLE_STARTS):
			return True
		if text_mentions_any_addr(text, VTABLE_SETUP_SLOTS):
			return True
	code = decompile_text_for_func(func)
	if code is None:
		return False
	if text_mentions_any_addr(code, VTABLE_STARTS):
		return True
	if text_mentions_any_addr(code, VTABLE_SETUP_SLOTS):
		return True
	return False

def print_matching_decompile_lines(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("=" * 70)
	write("MATCHED DECOMPILE LINES: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	code = decompile_text_for_func(func)
	if code is None:
		write("  [decompilation failed]")
		return
	lines = code.split("\n")
	idx = 0
	count = 0
	while idx < len(lines):
		line = lines[idx]
		if text_has_pattern(line):
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
		write("  0x%08x: %-54s%s%s" % (addr_int, inst.toString(), marker, extra))
		inst = inst.getNext()
		idx += 1

def dump_vtable_window(start_int, slot_count):
	write("")
	write("=" * 70)
	write("VTABLE/DATA WINDOW FROM 0x%08x (%s)" % (start_int, label_for(start_int)))
	write("=" * 70)
	idx = 0
	while idx < slot_count:
		slot_addr = start_int + idx * 4
		value = read_dword(slot_addr)
		marker = ""
		if slot_addr in VTABLE_SETUP_SLOTS:
			marker = " << setup slot"
		if value is None:
			write("  0x%08x: ????????%s" % (slot_addr, marker))
		else:
			write("  0x%08x: 0x%08x %s%s" % (slot_addr, value, label_for(value), marker))
		idx += 1

def collect_refs_and_print(targets, functions, title):
	write("")
	write("=" * 70)
	write(title)
	write("=" * 70)
	idx = 0
	while idx < len(targets):
		addr = targets[idx]
		find_refs_to(addr, label_for(addr))
		add_ref_functions(addr, functions)
		idx += 1

def scan_renderer_for_vtable_immediates(functions, max_matches):
	write("")
	write("=" * 70)
	write("RENDERER SCAN FOR PPLIGHTING-LIKE VTABLE IMMEDIATES")
	write("=" * 70)
	inst_iter = listing.getInstructions(True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		addr_int = inst.getAddress().getOffset()
		if addr_int < 0x00B00000 or addr_int > 0x00C30000:
			continue
		text = inst.toString()
		if not text_mentions_any_addr(text, VTABLE_STARTS):
			continue
		func = fm.getFunctionContaining(inst.getAddress())
		fname = func.getName() if func is not None else "???"
		has_dc = function_has_dc_marker(func) if func is not None else False
		write("  0x%08x in %s: %s ; function_has_dc=%s" % (addr_int, fname, text, has_dc))
		disasm_window(addr_int, 8, 18, "vtable immediate")
		if func is not None:
			functions[func.getEntryPoint().getOffset()] = True
		count += 1
		if count >= max_matches:
			write("  ... vtable immediate scan truncated")
			break
	write("  Total vtable immediate matches printed: %d" % count)

def scan_renderer_for_dc_writers(functions, max_matches):
	write("")
	write("=" * 70)
	write("RENDERER SCAN FOR +0xDC WRITES WITH PPLIGHTING-REF FILTER")
	write("=" * 70)
	inst_iter = listing.getInstructions(True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		addr_int = inst.getAddress().getOffset()
		if addr_int < 0x00B00000 or addr_int > 0x00C30000:
			continue
		text = inst.toString().lower()
		if text.find("+ 0xdc") < 0 and text.find("+0xdc") < 0:
			continue
		if text.find("mov") < 0 and text.find("lea") < 0 and text.find("cmp") < 0:
			continue
		func = fm.getFunctionContaining(inst.getAddress())
		fname = func.getName() if func is not None else "???"
		has_vtable = function_mentions_any_vtable(func) if func is not None else False
		if not has_vtable:
			continue
		write("  0x%08x in %s: %s ; function_mentions_pplighting_vtable=%s" % (addr_int, fname, inst.toString(), has_vtable))
		disasm_window(addr_int, 8, 18, "+0xDC vtable-filtered writer")
		if func is not None:
			functions[func.getEntryPoint().getOffset()] = True
		count += 1
		if count >= max_matches:
			write("  ... +0xDC vtable-filtered scan truncated")
			break
	write("  Total vtable-filtered +0xDC matches printed: %d" % count)

def audit_direct_dc_instruction_targets(functions):
	write("")
	write("=" * 70)
	write("KNOWN +0xDC INSTRUCTION TARGET WINDOWS")
	write("=" * 70)
	idx = 0
	while idx < len(DC_INSTRUCTION_TARGETS):
		addr = DC_INSTRUCTION_TARGETS[idx]
		disasm_window(addr, 10, 18, "known +0xDC instruction")
		add_function_for_addr(toAddr(addr), functions)
		idx += 1

def audit_function_set(functions, title, max_functions):
	write("")
	write("=" * 70)
	write(title)
	write("=" * 70)
	keys = functions.keys()
	keys.sort()
	idx = 0
	while idx < len(keys):
		addr = keys[idx]
		func = fm.getFunctionAt(toAddr(addr))
		if func is None:
			func = fm.getFunctionContaining(toAddr(addr))
		has_dc = function_has_dc_marker(func) if func is not None else False
		has_vtable = function_mentions_any_vtable(func) if func is not None else False
		write("")
		write("Candidate function 0x%08x %s ; has_dc=%s has_pplighting_vtable_ref=%s" % (addr, label_for(addr), has_dc, has_vtable))
		decompile_at(addr, label_for(addr), 22000)
		find_and_print_calls_from(addr, label_for(addr))
		print_matching_decompile_lines(addr, label_for(addr))
		idx += 1
		if idx >= max_functions:
			write("  ... candidate function decompile scan truncated")
			break

def audit_static_lists(functions):
	idx = 0
	while idx < len(VTABLE_STARTS):
		dump_vtable_window(VTABLE_STARTS[idx], 28)
		idx += 1
	collect_refs_and_print(VTABLE_STARTS, functions, "REFERENCES TO PPLIGHTING-LIKE VTABLE STARTS")
	collect_refs_and_print(VTABLE_SETUP_SLOTS, functions, "REFERENCES TO PPLIGHTING-LIKE SETUP SLOTS")
	collect_refs_and_print(PPLIGHTING_METHODS, functions, "REFERENCES TO PPLIGHTING-LIKE VTABLE METHODS")
	collect_refs_and_print(REF_TARGETS, functions, "REFERENCES TO +0xDC PASS/REFCOUNT/ALLOC HELPERS")
	idx = 0
	while idx < len(PPLIGHTING_METHODS):
		functions[PPLIGHTING_METHODS[idx]] = True
		idx += 1
	idx = 0
	while idx < len(DC_CANDIDATE_FUNCTIONS):
		functions[DC_CANDIDATE_FUNCTIONS[idx]] = True
		idx += 1

def print_header():
	write("FNV PPLIGHTING +0xDC FIELD WRITER PROVENANCE AUDIT")
	write("")
	write("Questions:")
	write("1. Which constructors or init/copy functions reference the PPLighting-like vtable starts?")
	write("2. Do those same functions write, clear, copy, addref, or release field +0xDC?")
	write("3. Are broad renderer +0xDC writers actually tied to PPLighting shader-property classes?")
	write("4. If not, which exact provenance gap remains before Psycho can consume +0xDC for PBR?")

def main():
	functions = {}
	print_header()
	audit_static_lists(functions)
	scan_renderer_for_vtable_immediates(functions, 80)
	scan_renderer_for_dc_writers(functions, 80)
	audit_direct_dc_instruction_targets(functions)
	audit_function_set(functions, "DECOMPILE PPLIGHTING/VTABLE/+0xDC CANDIDATE FUNCTIONS", 120)
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pplighting_dc_field_writer_provenance_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("")
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
