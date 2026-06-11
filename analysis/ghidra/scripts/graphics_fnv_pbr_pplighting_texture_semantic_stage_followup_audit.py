# @category Analysis
# @description Correlate FNV PPLighting texture stages with material texture semantics for native PBR

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x0046E8E0: "extra named texture map attach/name helper",
	0x0046E910: "extra named texture map enumerator",
	0x0046EB00: "Dark Map getter",
	0x0046EB20: "Detail Map getter",
	0x0046EB40: "Gloss Map getter",
	0x0046EB60: "Glow Map getter",
	0x0046EB80: "Bump Map getter",
	0x0046EBA0: "Decal Map getter",
	0x0046EBD0: "Decal Map count getter",
	0x00540FE0: "TESLandTexture texture set validator candidate",
	0x005453B0: "model/geometry texture set application candidate",
	0x005454D0: "fallback model/geometry getter candidate",
	0x00569580: "primary model/geometry getter candidate",
	0x005922E0: "BGSTextureSet constructor candidate",
	0x00593140: "NullTextureSet singleton setup",
	0x00653290: "attached-data/property helper",
	0x00A59D30: "NiAVObject property lookup by type",
	0x00B4F5C0: "material branch/helper called by BDF790",
	0x00B55480: "shader/model texture binding candidate",
	0x00B70590: "PPLighting active-object resource helper 00B70590",
	0x00B70600: "PPLighting active-object resource helper 00B70600",
	0x00B70680: "PPLighting active-object resource helper 00B70680",
	0x00B70700: "PPLighting active-object resource helper 00B70700",
	0x00B707D0: "PPLighting active-object resource helper 00B707D0",
	0x00BA8C50: "pass-entry reused-entry array setter",
	0x00BA8EC0: "pass-entry constructor",
	0x00BA9EE0: "pass-entry append/reuse helper",
	0x00BD9540: "PPLighting pass-entry helper 00BD9540",
	0x00BD9840: "PPLighting pass-entry helper 00BD9840",
	0x00BD9BC0: "PPLighting pass-entry helper 00BD9BC0",
	0x00BD9DA0: "PPLighting pass-entry helper 00BD9DA0",
	0x00BD9E60: "PPLighting pass-entry helper 00BD9E60",
	0x00BD9F00: "PPLighting pass-entry helper 00BD9F00",
	0x00BD9F90: "PPLighting pass-entry helper 00BD9F90",
	0x00BDA030: "PPLighting pass-entry helper 00BDA030",
	0x00BDA0A0: "PPLighting pass-entry helper 00BDA0A0",
	0x00BDAF10: "PPLighting pass-entry helper 00BDAF10",
	0x00BDB380: "PPLighting pass-entry helper 00BDB380",
	0x00BDBF60: "PPLighting pass-entry helper 00BDBF60",
	0x00BDC030: "PPLighting pass-entry helper 00BDC030",
	0x00BDC0D0: "PPLighting pass-entry helper 00BDC0D0",
	0x00BDC530: "PPLighting pass-entry helper 00BDC530",
	0x00BDCA60: "PPLighting pass-entry helper 00BDCA60",
	0x00BDD050: "PPLighting pass-entry helper 00BDD050",
	0x00BDD520: "PPLighting pass-entry helper 00BDD520",
	0x00BDDA20: "PPLighting pass-entry helper 00BDDA20",
	0x00BDDBC0: "PPLighting pass-entry helper 00BDDBC0",
	0x00BDDD80: "PPLighting pass-entry helper 00BDDD80",
	0x00BDDE10: "PPLighting pass-entry helper 00BDDE10",
	0x00BDDFB0: "PPLighting pass-entry helper 00BDDFB0",
	0x00BDE1D0: "PPLighting pass-entry helper 00BDE1D0",
	0x00BDE9B0: "PPLighting pass-entry helper 00BDE9B0",
	0x00BDEF40: "PPLighting pass-entry helper 00BDEF40",
	0x00BDF3E0: "PPLighting pass-entry helper 00BDF3E0",
	0x00BDF650: "PPLighting pass-entry helper 00BDF650",
	0x00BDF790: "PPLighting selector/pass-entry driver",
	0x00E68EF0: "source-texture renderer-data factory",
	0x00E7EA00: "pass-entry downstream texture/state apply helper",
	0x00E7EB00: "pass-entry cache/apply helper",
	0x00E88A20: "NiDX9RenderState::SetTexture",
	0x00E90B10: "renderer +0x8C4 resolver slot +0x0C",
	0x011F91E0: "current geometry/proxy global",
	0x011F951C: "global fallback resource used by B7E150 branch",
	0x0126F680: "pass-entry +8 cache table keyed by entry +4",
	0x0126F6C4: "renderer global used for resource resolver",
	0x0126F74C: "current NiD3DPass global",
}

SEMANTIC_GETTERS = [
	(0x0046EB00, "Dark Map getter"),
	(0x0046EB20, "Detail Map getter"),
	(0x0046EB40, "Gloss Map getter"),
	(0x0046EB60, "Glow Map getter"),
	(0x0046EB80, "Bump Map getter"),
	(0x0046EBA0, "Decal Map getter"),
	(0x0046EBD0, "Decal Map count getter"),
]

MATERIAL_TEXTURE_TARGETS = [
	(0x0046E8E0, "extra named texture map attach/name helper"),
	(0x0046E910, "extra named texture map enumerator"),
	(0x00540FE0, "TESLandTexture texture set validator candidate"),
	(0x005453B0, "model/geometry texture set application candidate"),
	(0x005454D0, "fallback model/geometry getter candidate"),
	(0x00569580, "primary model/geometry getter candidate"),
	(0x005922E0, "BGSTextureSet constructor candidate"),
	(0x00593140, "NullTextureSet singleton setup"),
	(0x00653290, "attached-data/property helper"),
	(0x00A59D30, "NiAVObject property lookup by type"),
	(0x00B4F5C0, "material branch/helper called by BDF790"),
	(0x00B55480, "shader/model texture binding candidate"),
]

PPLIGHTING_HELPERS = [
	(0x00BD9540, "PPLighting pass-entry helper 00BD9540"),
	(0x00BD9840, "PPLighting pass-entry helper 00BD9840"),
	(0x00BD9BC0, "PPLighting pass-entry helper 00BD9BC0"),
	(0x00BD9DA0, "PPLighting pass-entry helper 00BD9DA0"),
	(0x00BD9E60, "PPLighting pass-entry helper 00BD9E60"),
	(0x00BD9F00, "PPLighting pass-entry helper 00BD9F00"),
	(0x00BD9F90, "PPLighting pass-entry helper 00BD9F90"),
	(0x00BDA030, "PPLighting pass-entry helper 00BDA030"),
	(0x00BDA0A0, "PPLighting pass-entry helper 00BDA0A0"),
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
	(0x00BDF790, "PPLighting selector/pass-entry driver"),
]

FOCUS_HELPERS = [
	(0x00BD9540, "resource-forwarding helper 00BD9540"),
	(0x00BDA0A0, "resource-forwarding helper 00BDA0A0"),
	(0x00BDAF10, "material/property helper 00BDAF10"),
	(0x00BDC0D0, "two-resource forwarding helper 00BDC0D0"),
	(0x00BDC530, "three-resource forwarding helper 00BDC530"),
	(0x00BDD050, "resource-forwarding helper 00BDD050"),
	(0x00BDD520, "resource-forwarding helper 00BDD520"),
	(0x00BDF3E0, "dynamic resource helper 00BDF3E0"),
	(0x00BDF650, "dynamic resource helper 00BDF650"),
	(0x00BDF790, "selector/pass-entry driver 00BDF790"),
]

RESOURCE_HELPERS = [
	0x00B4F5C0,
	0x00653290,
	0x00A59D30,
	0x00B70590,
	0x00B70600,
	0x00B70680,
	0x00B70700,
	0x00B707D0,
]

CALL_SCAN_TARGETS = [
	0x0046E8E0,
	0x0046E910,
	0x0046EB00,
	0x0046EB20,
	0x0046EB40,
	0x0046EB60,
	0x0046EB80,
	0x0046EBA0,
	0x0046EBD0,
	0x00540FE0,
	0x005453B0,
	0x00653290,
	0x00A59D30,
	0x00B4F5C0,
	0x00B55480,
	0x00BA9EE0,
	0x00E7EB00,
	0x00E7EA00,
]

ARG_NAMES = [
	"entry+0 type_or_mode",
	"entry+4 stage_key",
	"entry+7 byte",
	"entry+9 array_count",
	"resource0 entry+0x0c[0]",
	"resource1 entry+0x0c[1]",
	"resource2 entry+0x0c[2]",
	"resource3 entry+0x0c[3]",
]

REGISTERS = [
	"EAX",
	"EBX",
	"ECX",
	"EDX",
	"ESI",
	"EDI",
	"EBP",
]

PATTERNS = [
	"0046e8e0",
	"0046e910",
	"0046eb00",
	"0046eb20",
	"0046eb40",
	"0046eb60",
	"0046eb80",
	"0046eba0",
	"0046ebd0",
	"00653290",
	"00a59d30",
	"00ba9ee0",
	"00e7ea00",
	"00e7eb00",
	"dark map",
	"detail map",
	"gloss map",
	"glow map",
	"bump map",
	"decal map",
	"normal",
	"diffuse",
	"texture",
	"source",
	"resource",
	"stage",
	"+ 0x24",
	"+0x24",
	"+ 0x40",
	"+0x40",
	"+ 0x6c",
	"+0x6c",
	"+ 0xdc",
	"+0xdc",
	"+ 0xec",
	"+0xec",
	"+ 0xf4",
	"+0xf4",
]

def write(msg):
	output.append(msg)
	print(msg)

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

def get_function(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	return func

def decompile_text(addr_int):
	func = get_function(addr_int)
	if func is None:
		return None
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		return result.getDecompiledFunction().getC()
	return None

def decompile_at(addr_int, label, max_len=18000):
	func = get_function(addr_int)
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
		if count > 100:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	func = get_function(addr_int)
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

def call_target_for_instruction(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		if ref.getReferenceType().isCall():
			return ref.getToAddress().getOffset()
	return None

def target_in_list(target, values):
	for value in values:
		if value == target:
			return True
	return False

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

def instruction_before_steps(inst, steps):
	cur = inst
	count = 0
	while count < steps and cur is not None:
		cur = listing.getInstructionBefore(cur.getAddress())
		count += 1
	return cur

def print_short_window(center_inst, before_count, after_count):
	start = instruction_before_steps(center_inst, before_count)
	if start is None:
		start = center_inst
	cur = start
	count = 0
	limit = before_count + after_count + 1
	while cur is not None and count < limit:
		marker = "=>" if cur.getAddress().getOffset() == center_inst.getAddress().getOffset() else "  "
		write("    %s 0x%08x: %s" % (marker, cur.getAddress().getOffset(), cur.toString()))
		cur = listing.getInstructionAfter(cur.getAddress())
		count += 1

def is_register_text(text):
	upper = text.upper()
	for reg in REGISTERS:
		if upper == reg:
			return True
	return False

def is_zero_arg(text):
	lower = text.lower()
	return lower == "0" or lower == "0x0"

def instruction_writes_register(inst, reg):
	mnemonic = inst.getMnemonicString()
	dst = operand_text(inst, 0).upper()
	if dst == reg:
		return True
	if mnemonic == "POP" and dst == reg:
		return True
	if mnemonic.startswith("CALL") and reg == "EAX":
		return True
	return False

def print_refs_from_instruction(inst, indent):
	refs = inst.getReferencesFrom()
	for ref in refs:
		write("%sref %s -> 0x%08x %s" % (indent, ref.getReferenceType(), ref.getToAddress().getOffset(), label_for(ref.getToAddress().getOffset())))

def print_source_reg_defs(inst, written_reg, indent):
	src = operand_text(inst, 1).upper()
	if src == written_reg:
		return
	if is_register_text(src):
		write("%sfollow source register %s before 0x%08x:" % (indent, src, inst.getAddress().getOffset()))
		print_register_defs_before(inst, src, 36, 2, indent + "  ")

def print_register_defs_before(inst, reg, max_steps, max_hits, indent):
	cur = listing.getInstructionBefore(inst.getAddress())
	steps = 0
	hits = 0
	while cur is not None and steps < max_steps and hits < max_hits:
		if instruction_writes_register(cur, reg):
			write("%sdef %s @ 0x%08x: %s" % (indent, reg, cur.getAddress().getOffset(), cur.toString()))
			print_refs_from_instruction(cur, indent + "  ")
			hits += 1
			if hits == 1:
				print_source_reg_defs(cur, reg, indent + "  ")
		mnemonic = cur.getMnemonicString()
		if mnemonic.startswith("RET"):
			break
		cur = listing.getInstructionBefore(cur.getAddress())
		steps += 1
	if hits == 0:
		write("%sdef %s: [no local write found in %d instructions]" % (indent, reg, max_steps))

def get_push_arg(pushes, index):
	if index < len(pushes):
		return pushes[index][1]
	return "?"

def get_push_inst(pushes, index):
	if index < len(pushes):
		return listing.getInstructionAt(toAddr(pushes[index][0]))
	return None

def ba9ee0_row_is_resource_relevant(pushes):
	count_arg = get_push_arg(pushes, 3)
	if count_arg == "?":
		return True
	if not is_zero_arg(count_arg):
		return True
	index = 4
	while index < 8:
		arg = get_push_arg(pushes, index)
		if arg == "?":
			return True
		if not is_zero_arg(arg):
			return True
		index += 1
	return False

def print_arg_provenance(pushes, index):
	arg = get_push_arg(pushes, index)
	arg_inst = get_push_inst(pushes, index)
	if arg_inst is None:
		write("    %-28s = %-14s ; [push instruction not found]" % (ARG_NAMES[index], arg))
		return
	write("    %-28s = %-14s ; push @ 0x%08x" % (ARG_NAMES[index], arg, arg_inst.getAddress().getOffset()))
	if is_register_text(arg):
		print_register_defs_before(arg_inst, arg.upper(), 56, 5, "      ")

def print_ba9ee0_rows_for_helper(addr_int, label):
	func = get_function(addr_int)
	if func is None:
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	while inst_iter.hasNext():
		inst = inst_iter.next()
		target = call_target_for_instruction(inst)
		if target != 0x00BA9EE0:
			continue
		pushes = collect_pushes_before(inst, 8, 64)
		if not ba9ee0_row_is_resource_relevant(pushes):
			continue
		write("")
		write("  BA9EE0 call 0x%08x in %s" % (inst.getAddress().getOffset(), label))
		write("  row: entry+0=%s entry+4=%s entry+7=%s count=%s res0=%s res1=%s res2=%s res3=%s" % (get_push_arg(pushes, 0), get_push_arg(pushes, 1), get_push_arg(pushes, 2), get_push_arg(pushes, 3), get_push_arg(pushes, 4), get_push_arg(pushes, 5), get_push_arg(pushes, 6), get_push_arg(pushes, 7)))
		index = 0
		while index < 8:
			print_arg_provenance(pushes, index)
			index += 1
		write("    ECX/list owner before BA9EE0:")
		print_register_defs_before(inst, "ECX", 42, 4, "      ")
		write("    local window:")
		print_short_window(inst, 18, 8)

def print_ba9ee0_resource_rows():
	write("")
	write("=" * 70)
	write("RESOURCE-BEARING BA9EE0 ROWS BY PPLIGHTING HELPER")
	write("=" * 70)
	for item in PPLIGHTING_HELPERS:
		print_ba9ee0_rows_for_helper(item[0], item[1])

def print_call_arg_table_for_targets(addr_int, label, targets, max_args):
	func = get_function(addr_int)
	if func is None:
		return
	write("")
	write("=" * 70)
	write("CALLSITE ARGUMENT TABLE: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		target = call_target_for_instruction(inst)
		if target is None:
			continue
		if not target_in_list(target, targets):
			continue
		count += 1
		write("")
		write("  call 0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), target, label_for(target)))
		write("    ECX before call:")
		print_register_defs_before(inst, "ECX", 48, 5, "      ")
		pushes = collect_pushes_before(inst, max_args, 72)
		index = 0
		while index < max_args:
			arg = get_push_arg(pushes, index)
			arg_inst = get_push_inst(pushes, index)
			if arg_inst is None:
				write("    stack_arg%d = %-14s ; [push instruction not found]" % (index, arg))
			else:
				write("    stack_arg%d = %-14s ; push @ 0x%08x" % (index, arg, arg_inst.getAddress().getOffset()))
				if is_register_text(arg):
					print_register_defs_before(arg_inst, arg.upper(), 42, 4, "      ")
			index += 1
		write("    local window:")
		print_short_window(inst, 16, 7)
	write("")
	write("  Matched calls: %d" % count)

def print_focus_call_tables():
	for item in FOCUS_HELPERS:
		print_call_arg_table_for_targets(item[0], item[1], CALL_SCAN_TARGETS, 8)

def scan_decompile_patterns(addr_int, label):
	write("")
	write("=" * 70)
	write("DECOMPILE PATTERN LINES: %s @ 0x%08x" % (label, addr_int))
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
		for pattern in PATTERNS:
			if pattern in lower:
				write("  L%-4d %s" % (line_no, line))
				break

def print_pattern_sections():
	for item in FOCUS_HELPERS:
		scan_decompile_patterns(item[0], item[1])

def print_semantic_getter_refs():
	write("")
	write("=" * 70)
	write("SEMANTIC GETTER REFERENCES AND LOCAL WINDOWS")
	write("=" * 70)
	for item in SEMANTIC_GETTERS:
		find_refs_to(item[0], item[1])
		refs = ref_mgr.getReferencesTo(toAddr(item[0]))
		seen = 0
		while refs.hasNext() and seen < 20:
			ref = refs.next()
			inst = listing.getInstructionAt(ref.getFromAddress())
			if inst is not None:
				from_func = fm.getFunctionContaining(ref.getFromAddress())
				fname = from_func.getName() if from_func else "???"
				write("")
				write("  Local semantic-getter window for %s at 0x%08x in %s" % (item[1], ref.getFromAddress().getOffset(), fname))
				print_short_window(inst, 12, 8)
			seen += 1

def print_material_getter_decompiles():
	for item in SEMANTIC_GETTERS:
		decompile_at(item[0], item[1], 12000)
	for item in MATERIAL_TEXTURE_TARGETS:
		decompile_at(item[0], item[1], 16000)

def print_resource_helper_sections():
	for addr in RESOURCE_HELPERS:
		find_refs_to(addr, label_for(addr))
		find_and_print_calls_from(addr, label_for(addr))
		scan_decompile_patterns(addr, label_for(addr))

def print_apply_chain_summary():
	write("")
	write("=" * 70)
	write("PROVEN FINAL APPLY CHAIN")
	write("=" * 70)
	write("BA9EE0 writes pass-entry fields. E7EB00/E7EA00 consume entry +4 as the final texture stage/key and entry +8 as the resource pointer.")
	write("E7EA00 calls the renderer +0x8C4 resolver slot +0x0C. For the E68EF0-created source texture renderer-data object, vtable 0x010ED37C resolves as:")
	write("  +0xA4 -> null, +0xAC -> null, +0xA8 -> this, +0xB4 -> refresh/update, +0x98 -> *(this +0x68), +0x9C -> *(this +0x64).")
	write("Therefore the source-texture path binds *(rendererData +0x64) through NiDX9RenderState::SetTexture(stage = entry +4).")
	write("This script is only trying to prove which material or active-object source produced each BA9EE0 resource row.")

def print_key_refs():
	find_refs_to(0x00BA9EE0, "pass-entry append/reuse helper")
	find_refs_to(0x00E7EB00, "pass-entry cache/apply helper")
	find_refs_to(0x00E7EA00, "pass-entry downstream texture/state apply helper")
	find_refs_to(0x00E88A20, "NiDX9RenderState::SetTexture")
	find_refs_to(0x00E90B10, "renderer +0x8C4 resolver slot +0x0C")
	find_refs_to(0x00E68EF0, "source-texture renderer-data factory")
	find_refs_to(0x011F91E0, "current geometry/proxy global")
	find_refs_to(0x011F951C, "global fallback resource used by B7E150 branch")
	find_refs_to(0x0126F680, "pass-entry +8 cache table keyed by entry +4")

def print_core_decompiles():
	decompile_at(0x00BDF790, "PPLighting selector/pass-entry driver", 70000)
	decompile_at(0x00BDAF10, "PPLighting material/property helper 00BDAF10", 26000)
	decompile_at(0x00B4F5C0, "material branch/helper called by BDF790", 18000)
	decompile_at(0x00BA9EE0, "pass-entry append/reuse helper", 18000)
	decompile_at(0x00E7EB00, "pass-entry cache/apply helper", 14000)
	decompile_at(0x00E7EA00, "pass-entry downstream texture/state apply helper", 16000)

def main():
	write("FNV PBR PPLIGHTING TEXTURE SEMANTIC/STAGE FOLLOW-UP AUDIT")
	write("")
	write("Purpose:")
	write("1. Correlate resource-bearing BA9EE0 rows with material texture getters or active-object resource helpers.")
	write("2. Preserve the proven final path: BA9EE0 entry +4/+8 -> E7EB00/E7EA00 -> E90B10 -> SetTexture.")
	write("3. Block visible PBR replacement unless albedo/normal/glow/etc. semantics are proven for one shader family.")
	print_apply_chain_summary()
	print_key_refs()
	print_semantic_getter_refs()
	print_ba9ee0_resource_rows()
	print_focus_call_tables()
	print_pattern_sections()
	print_resource_helper_sections()
	print_material_getter_decompiles()
	print_core_decompiles()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_texture_semantic_stage_followup_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
