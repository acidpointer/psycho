# @category Analysis
# @description Correlate FNV PBR PPLighting pass-entry fields with final render-state texture stages

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00BA8C50: "pass-entry reused-entry array setter",
	0x00BA8EC0: "pass-entry constructor",
	0x00BA9EE0: "pass-entry append/reuse helper",
	0x00B7DD50: "B7 dispatcher current-pass entry apply",
	0x00B7DDE0: "B7 dispatcher variant",
	0x00B7DED0: "B7 dispatcher variant",
	0x00B7DFE0: "B7 dispatcher variant",
	0x00B7E150: "B7 dispatcher variant",
	0x00BD1C50: "current pass writer",
	0x00BD4BA0: "current pass shader-interface apply",
	0x00BE1F90: "BSShader::SetShaders",
	0x00E7DC90: "post-texture sampler helper called by E7EA00",
	0x00E7DD50: "texture clear/range helper",
	0x00E7DE90: "pass-mode sampler-state tracker helper",
	0x00E7EA00: "pass-entry downstream texture/state apply helper",
	0x00E7EB00: "pass-entry cache/apply helper",
	0x00E7F7C0: "renderer helper getter used by SetShaders",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x00E88930: "NiDX9RenderState::SetTextureStageState",
	0x00E89060: "texture-stage tracker getter",
	0x00E890C0: "sampler-state tracker setter",
	0x00E89410: "pass-entry tracked-state flush helper",
	0x00E910A0: "NiDX9RenderState::SetSamplerState",
	0x010EF60C: "render-state vtable A",
	0x010F088C: "render-state vtable B",
	0x011BF558: "pass-entry bounded count used by E7EA00/E89410",
	0x0126F680: "pass-entry +8 cache table keyed by entry +4",
	0x0126F6C0: "renderer global object from renderer +0x288",
	0x0126F6C4: "renderer global set directly by E7E8D0",
	0x0126F6C8: "renderer +0x8B8 render-state global used by E7EA00",
	0x0126F74C: "current NiD3DPass global",
}

PASS_ENTRY_SCAN_FUNCTIONS = [
	(0x00BD9540, "PPLighting pass-entry helper 00BD9540"),
	(0x00BD9770, "PPLighting pass-entry helper 00BD9770"),
	(0x00BD9840, "PPLighting pass-entry helper 00BD9840"),
	(0x00BD99C0, "PPLighting pass-entry helper 00BD99C0"),
	(0x00BD9AC0, "PPLighting pass-entry helper 00BD9AC0"),
	(0x00BD9BC0, "PPLighting pass-entry helper 00BD9BC0"),
	(0x00BD9D00, "PPLighting pass-entry helper 00BD9D00"),
	(0x00BD9DA0, "PPLighting pass-entry helper 00BD9DA0"),
	(0x00BD9E60, "PPLighting pass-entry helper 00BD9E60"),
	(0x00BD9F00, "PPLighting pass-entry helper 00BD9F00"),
	(0x00BD9F90, "PPLighting pass-entry helper 00BD9F90"),
	(0x00BDA030, "PPLighting pass-entry helper 00BDA030"),
	(0x00BDA060, "PPLighting pass-entry helper 00BDA060"),
	(0x00BDA0A0, "PPLighting pass-entry helper 00BDA0A0"),
	(0x00BDAC00, "PPLighting pass-entry helper 00BDAC00"),
	(0x00BDAF10, "PPLighting pass-entry helper 00BDAF10"),
	(0x00BDB380, "PPLighting pass-entry helper 00BDB380"),
	(0x00BDBF60, "PPLighting pass-entry helper 00BDBF60"),
	(0x00BDC030, "PPLighting pass-entry helper 00BDC030"),
	(0x00BDC0D0, "PPLighting pass-entry helper 00BDC0D0"),
	(0x00BDC530, "PPLighting pass-entry helper 00BDC530"),
	(0x00BDCA60, "PPLighting pass-entry helper 00BDCA60"),
	(0x00BDD050, "PPLighting pass-entry helper 00BDD050"),
	(0x00BDD520, "PPLighting pass-entry helper 00BDD520"),
	(0x00BDDA20, "PPLighting pass-entry helper 00BDDA20"),
	(0x00BDDBC0, "PPLighting pass-entry helper 00BDDBC0"),
	(0x00BDDD80, "PPLighting pass-entry helper 00BDDD80"),
	(0x00BDDE10, "PPLighting pass-entry helper 00BDDE10"),
	(0x00BDDFB0, "PPLighting pass-entry helper 00BDDFB0"),
	(0x00BDE1D0, "PPLighting pass-entry helper 00BDE1D0"),
	(0x00BDE9B0, "PPLighting pass-entry helper 00BDE9B0"),
	(0x00BDEF40, "PPLighting pass-entry helper 00BDEF40"),
	(0x00BDF3E0, "PPLighting pass-entry helper 00BDF3E0"),
	(0x00BDF650, "PPLighting pass-entry helper 00BDF650"),
	(0x00BDF6C0, "PPLighting pass-entry helper 00BDF6C0"),
	(0x00BDF790, "PPLighting pass-entry helper 00BDF790"),
]

APPLY_FUNCTIONS = [
	(0x00B7DD50, "B7 dispatcher current-pass entry apply"),
	(0x00B7DDE0, "B7 dispatcher variant"),
	(0x00B7DED0, "B7 dispatcher variant"),
	(0x00B7DFE0, "B7 dispatcher variant"),
	(0x00B7E150, "B7 dispatcher variant"),
	(0x00BD1C50, "current pass writer"),
	(0x00BD4BA0, "current pass shader-interface apply"),
	(0x00BE1F90, "BSShader::SetShaders"),
	(0x00E7EB00, "pass-entry cache/apply helper"),
	(0x00E7EA00, "pass-entry downstream texture/state apply helper"),
	(0x00E7DC90, "post-texture sampler helper called by E7EA00"),
	(0x00E7DD50, "texture clear/range helper"),
	(0x00E89410, "pass-entry tracked-state flush helper"),
	(0x00E88A20, "NiDX9RenderState::SetTexture"),
	(0x00E88930, "NiDX9RenderState::SetTextureStageState"),
	(0x00E910A0, "NiDX9RenderState::SetSamplerState"),
]

REF_TARGETS = [
	0x00BA9EE0,
	0x00E7EB00,
	0x00E7EA00,
	0x00E7DC90,
	0x00E7DD50,
	0x00E89410,
	0x00E88A20,
	0x00E88930,
	0x00E910A0,
	0x011BF558,
	0x0126F680,
	0x0126F6C0,
	0x0126F6C4,
	0x0126F6C8,
	0x0126F74C,
]

VTABLES = [
	(0x010EF60C, "render-state vtable A"),
	(0x010F088C, "render-state vtable B"),
]

VTABLE_SLOTS = [
	(0x0C, "resource resolver-like slot when reached through renderer +0x8C4"),
	(0x68, "render-state helper slot used by E7DC90"),
	(0xB0, "constant/matrix upload-like slot"),
	(0xC0, "texture-stage-state route"),
	(0xCC, "sampler-state route"),
	(0xDC, "texture bind route"),
	(0x100, "setup virtual"),
	(0x114, "auxiliary high slot used by E7EA00 type 6"),
]

MATCH_PATTERNS = [
	"param_1[1]",
	"param_1[2]",
	"param_1 + 4",
	"param_1 + 8",
	"+ 0x4",
	"+0x4",
	"+ 0x8",
	"+0x8",
	"+ 0xc0",
	"+0xc0",
	"+ 0xcc",
	"+0xcc",
	"+ 0xdc",
	"+0xdc",
	"+ 0x8c4",
	"+0x8c4",
	"0126f6c0",
	"0126f6c4",
	"0126f6c8",
	"0126f680",
	"011bf558",
	"e7ea00",
	"e7eb00",
	"e89410",
	"settexture",
	"texture",
	"sampler",
	"stage",
]

def write(msg):
	output.append(msg)
	print(msg)

def read_dword(addr_int):
	try:
		return memory.getInt(toAddr(addr_int)) & 0xffffffff
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

def operand_text(inst, index):
	try:
		return inst.getDefaultOperandRepresentation(index)
	except:
		return "?"

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
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("  %s/%s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getOperandIndex(), ref.getFromAddress().getOffset(), fname))
		count += 1
		if count > 90:
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
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, label_for(tgt)))
				count += 1
	write("  Total: %d calls" % count)

def instruction_before_steps(inst, steps):
	cur = inst
	count = 0
	while count < steps and cur is not None:
		cur = listing.getInstructionBefore(cur.getAddress())
		count += 1
	return cur

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("=" * 70)
	write("Raw disassembly %s around 0x%08x" % (label, center_int))
	write("=" * 70)
	inst = listing.getInstructionContaining(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionAt(toAddr(center_int))
	if inst is None:
		write("  [instruction not found]")
		return
	cur = instruction_before_steps(inst, before_count)
	if cur is None:
		cur = inst
	count = 0
	limit = before_count + after_count + 1
	while cur is not None and count < limit:
		addr_int = cur.getAddress().getOffset()
		marker = "=> " if addr_int == inst.getAddress().getOffset() else "   "
		write("%s0x%08x: %-58s %s" % (marker, addr_int, cur.toString(), label_for(addr_int)))
		refs = cur.getReferencesFrom()
		for ref in refs:
			write("      ref %s -> 0x%08x %s" % (ref.getReferenceType(), ref.getToAddress().getOffset(), label_for(ref.getToAddress().getOffset())))
		cur = listing.getInstructionAfter(cur.getAddress())
		count += 1

def scan_patterns(addr_int, label):
	write("")
	write("=" * 70)
	write("MATCHED DECOMPILE LINES: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	code = decompile_text(addr_int)
	if code is None:
		write("  [decompilation failed]")
		return
	lines = code.splitlines()
	line_no = 0
	for line in lines:
		line_no += 1
		lower = line.lower()
		for pattern in MATCH_PATTERNS:
			if pattern.lower() in lower:
				write("  L%-4d %s" % (line_no, line))
				break

def collect_pushes_before(inst, max_pushes, max_steps):
	pushes = []
	cur = listing.getInstructionBefore(inst.getAddress())
	steps = 0
	while cur is not None and steps < max_steps and len(pushes) < max_pushes:
		mnemonic = cur.getMnemonicString()
		if mnemonic == "PUSH":
			pushes.append((cur.getAddress().getOffset(), operand_text(cur, 0), cur.toString()))
		elif mnemonic.startswith("CALL") or mnemonic.startswith("RET"):
			break
		cur = listing.getInstructionBefore(cur.getAddress())
		steps += 1
	return pushes

def find_ecx_owner_before(inst, max_steps):
	cur = listing.getInstructionBefore(inst.getAddress())
	steps = 0
	while cur is not None and steps < max_steps:
		mnemonic = cur.getMnemonicString()
		dst = operand_text(cur, 0).upper()
		if dst == "ECX":
			if mnemonic == "MOV" or mnemonic == "LEA":
				return (cur.getAddress().getOffset(), mnemonic, operand_text(cur, 1), cur.toString())
			if mnemonic == "POP":
				return (cur.getAddress().getOffset(), mnemonic, "stack", cur.toString())
			if mnemonic == "XOR" and operand_text(cur, 1).upper() == "ECX":
				return (cur.getAddress().getOffset(), mnemonic, "0", cur.toString())
		if mnemonic.startswith("CALL") or mnemonic.startswith("RET"):
			break
		cur = listing.getInstructionBefore(cur.getAddress())
		steps += 1
	return None

def call_target_for_instruction(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		if ref.getReferenceType().isCall():
			return ref.getToAddress().getOffset()
	return None

def get_push_arg(pushes, index):
	if index < len(pushes):
		return pushes[index][1]
	return "?"

def get_push_addr(pushes, index):
	if index < len(pushes):
		return pushes[index][0]
	return 0

def is_hex_const(text):
	if text is None:
		return False
	lower = text.lower()
	if lower.startswith("0x"):
		return True
	return False

def add_histogram(hist, key, helper, call_addr):
	for row in hist:
		if row[0] == key:
			row[1] += 1
			if helper not in row[3]:
				row[3] = row[3] + ", " + helper
			return
	hist.append([key, 1, call_addr, helper])

def print_vtable_slots():
	write("")
	write("=" * 70)
	write("RENDER-STATE VTABLE SLOT CHECK")
	write("=" * 70)
	for table in VTABLES:
		write("")
		write("%s @ 0x%08x" % (table[1], table[0]))
		for slot in VTABLE_SLOTS:
			target = read_dword(table[0] + slot[0])
			write("  +0x%03x @ 0x%08x -> 0x%08x %-48s ; %s" % (slot[0], table[0] + slot[0], target if target is not None else 0, label_for(target), slot[1]))

def print_ba9ee0_rows():
	write("")
	write("=" * 70)
	write("BA9EE0 PASS-ENTRY FIELD ROWS")
	write("=" * 70)
	write("Columns: helper | call | entry+0 | entry+4 stage/key | entry+7 byte | entry+9 array_count | array0 | array1 | array2 | array3 | ECX owner")
	write("Important: entry+4 is the value consumed as param_1[1] by E7EA00 on the texture route. It is not the same thing as entry+0.")
	hist = []
	total = 0
	unknown_stage = 0
	for item in PASS_ENTRY_SCAN_FUNCTIONS:
		func = fm.getFunctionAt(toAddr(item[0]))
		if func is None:
			func = fm.getFunctionContaining(toAddr(item[0]))
		if func is None:
			continue
		inst_iter = listing.getInstructions(func.getBody(), True)
		while inst_iter.hasNext():
			inst = inst_iter.next()
			target = call_target_for_instruction(inst)
			if target == 0x00BA9EE0:
				pushes = collect_pushes_before(inst, 8, 48)
				owner = find_ecx_owner_before(inst, 42)
				owner_text = "?"
				if owner is not None:
					owner_text = "0x%08x %s %s" % (owner[0], owner[1], owner[2])
				stage_key = get_push_arg(pushes, 1)
				if is_hex_const(stage_key):
					add_histogram(hist, stage_key, item[1], inst.getAddress().getOffset())
				else:
					unknown_stage += 1
				write("  %s | 0x%08x | %s | %s | %s | %s | %s | %s | %s | %s | %s" % (item[1], inst.getAddress().getOffset(), get_push_arg(pushes, 0), stage_key, get_push_arg(pushes, 2), get_push_arg(pushes, 3), get_push_arg(pushes, 4), get_push_arg(pushes, 5), get_push_arg(pushes, 6), get_push_arg(pushes, 7), owner_text))
				total += 1
	write("")
	write("  Total BA9EE0 calls scanned: %d" % total)
	write("  Calls with non-constant entry+4 stage/key in local push window: %d" % unknown_stage)
	write("")
	write("ENTRY+4 STATIC STAGE/KEY HISTOGRAM")
	for row in hist:
		write("  entry+4=%-8s count=%-3d first_call=0x%08x helpers=%s" % (row[0], row[1], row[2], row[3]))
	write("  Total static entry+4 keys: %d" % len(hist))

def print_filtered_rows_for_constants(constants, title):
	write("")
	write("=" * 70)
	write(title)
	write("=" * 70)
	for item in PASS_ENTRY_SCAN_FUNCTIONS:
		func = fm.getFunctionAt(toAddr(item[0]))
		if func is None:
			func = fm.getFunctionContaining(toAddr(item[0]))
		if func is None:
			continue
		inst_iter = listing.getInstructions(func.getBody(), True)
		while inst_iter.hasNext():
			inst = inst_iter.next()
			target = call_target_for_instruction(inst)
			if target == 0x00BA9EE0:
				pushes = collect_pushes_before(inst, 8, 48)
				stage_key = get_push_arg(pushes, 1).lower()
				if stage_key in constants:
					write("  call=0x%08x helper=%s entry+0=%s entry+4=%s entry+7=%s count=%s array0=%s array1=%s array2=%s array3=%s" % (inst.getAddress().getOffset(), item[1], get_push_arg(pushes, 0), get_push_arg(pushes, 1), get_push_arg(pushes, 2), get_push_arg(pushes, 3), get_push_arg(pushes, 4), get_push_arg(pushes, 5), get_push_arg(pushes, 6), get_push_arg(pushes, 7)))

def print_apply_contract():
	write("")
	write("=" * 70)
	write("E7EB00/E7EA00 FIELD-TO-RENDER-STATE CONTRACT")
	write("=" * 70)
	write("- BA9EE0 writes entry+0 from stack_arg0, entry+4 from stack_arg1, entry+7 from stack_arg2, entry+9 array count from stack_arg3, and entry+0xC array values from stack_arg4+.")
	write("- E7EB00 compares entry+8 against cache table 0x0126F680 indexed by entry+4 and calls E89410(entry+4) before E7EA00 when the cache changes.")
	write("- E7EA00 consumes entry+4 as param_1[1]. On the texture route it calls render-state vtable slot +0xDC with (entry+4, resolved_texture).")
	write("- E7EA00 consumes entry+8 as param_1[2]. When nonzero, it resolves that resource through renderer global 0x0126F6C4 +0x8C4 -> vtable +0x0C before SetTexture.")
	write("- Renderer +0x8B8 is proven as vtable B, where +0xC0 is E88930, +0xCC is E910A0, and +0xDC is E88A20.")
	write("- Therefore the pass-entry correlation question is: which BA9EE0 rows produce entry+8 resource pointers for the entry+4 keys consumed by E7EA00, not merely which constants look like texture IDs.")

def print_core_apply_functions():
	for item in APPLY_FUNCTIONS:
		decompile_at(item[0], item[1], 16000)
		find_and_print_calls_from(item[0], item[1])
		scan_patterns(item[0], item[1])

def print_raw_windows():
	disasm_window(0x00E7EB00, 18, 120, "E7EB00 pass-entry cache/apply helper")
	disasm_window(0x00E7EA00, 24, 170, "E7EA00 final texture/state route")
	disasm_window(0x00E88A20, 16, 100, "NiDX9RenderState::SetTexture")
	disasm_window(0x00E88930, 16, 80, "NiDX9RenderState::SetTextureStageState")
	disasm_window(0x00E910A0, 16, 80, "NiDX9RenderState::SetSamplerState")

def print_refs():
	for addr_int in REF_TARGETS:
		find_refs_to(addr_int, label_for(addr_int))

def print_interest_rows():
	constants = [
		"0x0",
		"0x3",
		"0x4",
		"0x5",
		"0x8",
		"0x10",
		"0x11",
		"0x12",
		"0x13",
		"0x58",
		"0x59",
		"0x5a",
		"0x5b",
		"0x5c",
		"0x5d",
		"0x5e",
		"0x5f",
		"0x60",
		"0x62",
		"0x64",
		"0x7c",
		"0x93",
		"0x94",
		"0xab",
		"0xac",
		"0xd7",
		"0xe9",
		"0xfb",
		"0x116",
		"0x132",
		"0x13e",
		"0x15a",
		"0x16c",
		"0x172",
		"0x1e2",
		"0x1e3",
		"0x1e4",
		"0x1e5",
		"0x1e6",
		"0x230",
		"0x244",
		"0x24e",
		"0x24f",
		"0x250",
		"0x251",
	]
	print_filtered_rows_for_constants(constants, "SELECTED BA9EE0 ROWS FOR KNOWN LOW/CLUSTER KEYS")

def main():
	write("FNV PBR PPLIGHTING PASS-ID/STAGE CORRELATION AUDIT")
	write("")
	write("Purpose:")
	write("1. Make the entry+0 vs entry+4 distinction explicit for PPLighting pass entries.")
	write("2. Correlate BA9EE0 constructor rows with the E7EB00/E7EA00 texture route.")
	write("3. Re-prove final render-state vtable slots used by E7EA00 before any visible PBR replacement depends on them.")
	print_apply_contract()
	print_vtable_slots()
	print_refs()
	print_ba9ee0_rows()
	print_interest_rows()
	print_core_apply_functions()
	print_raw_windows()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_pass_id_stage_correlation_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
