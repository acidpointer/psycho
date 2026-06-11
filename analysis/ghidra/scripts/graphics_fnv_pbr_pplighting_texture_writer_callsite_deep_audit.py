# @category Analysis
# @description Deep audit FNV PPLighting texture-array writer callsites and resolver slot +0x90 provenance for native PBR

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00539960: "PPLighting texture writer callsite A",
	0x0053A090: "PPLighting texture writer callsite B",
	0x005453B0: "model/geometry texture set application",
	0x00592E70: "BGSTextureSet +0x30 vtable +0x8C slot getter",
	0x00653290: "attached-data/property helper",
	0x00877A30: "TextureSet indexed slot storage getter",
	0x00A59D30: "NiAVObject property lookup by type",
	0x00B55480: "shader/model texture binding candidate",
	0x00B66640: "PPLighting texture-array flag initializer",
	0x00B68450: "PPLighting texture-array allocation/ensure helper",
	0x00B68660: "PPLighting six texture-array writer",
	0x00B690D0: "PPLighting texture/effect serialization",
	0x00BDAF10: "PPLighting material/property helper",
	0x00BDB4A0: "PPLighting setup variant before BDF790",
	0x00BDF790: "PPLighting selector/pass-entry driver",
	0x00E90B10: "renderer +0x8C4 resolver slot +0x0C texture pointer resolver",
	0x01033C7C: "BGSTextureSet +0x30 slot-interface vtable",
	0x01033D1C: "BGSTextureSet main vtable",
	0x010AE0D0: "B-range shader-property vtable",
	0x010F086C: "renderer +0x8C4 resolver vtable",
}

REF_TARGETS = [
	0x00539960,
	0x0053A090,
	0x005453B0,
	0x00592E70,
	0x00653290,
	0x00877A30,
	0x00A59D30,
	0x00B55480,
	0x00B66640,
	0x00B68450,
	0x00B68660,
	0x00B690D0,
	0x00BDAF10,
	0x00BDB4A0,
	0x00BDF790,
	0x00E90B10,
]

DECOMPILE_TARGETS = [
	(0x00539960, "PPLighting texture writer callsite A", 70000),
	(0x0053A090, "PPLighting texture writer callsite B", 70000),
	(0x00B68450, "PPLighting texture-array allocation/ensure helper", 26000),
	(0x00B68660, "PPLighting six texture-array writer", 32000),
	(0x00B66640, "PPLighting texture-array flag initializer", 20000),
	(0x005453B0, "model/geometry texture set application", 22000),
	(0x00592E70, "BGSTextureSet +0x30 vtable +0x8C slot getter", 18000),
	(0x00B55480, "shader/model texture binding candidate", 22000),
	(0x00B690D0, "PPLighting texture/effect serialization", 56000),
	(0x00BDAF10, "PPLighting material/property helper", 38000),
]

CALLSITE_FUNCTIONS = [
	(0x00539960, "PPLighting texture writer callsite A"),
	(0x0053A090, "PPLighting texture writer callsite B"),
	(0x00B68660, "PPLighting six texture-array writer"),
	(0x005453B0, "model/geometry texture set application"),
]

VTABLES = [
	(0x01033C7C, "BGSTextureSet +0x30 slot-interface vtable"),
	(0x01033D1C, "BGSTextureSet main vtable"),
	(0x010AE0D0, "B-range shader-property vtable"),
	(0x010F086C, "renderer +0x8C4 resolver vtable"),
]

VTABLE_SLOTS = [
	0x00,
	0x04,
	0x08,
	0x0C,
	0x10,
	0x14,
	0x18,
	0x1C,
	0x8C,
	0x90,
	0x94,
	0x98,
	0x9C,
	0xA0,
	0xA4,
	0xA8,
	0xAC,
	0xB0,
	0xB4,
	0xB8,
	0xBC,
	0xC0,
	0xC4,
	0xCC,
	0xDC,
	0xE0,
	0x114,
	0x118,
	0x11C,
	0x128,
	0x130,
	0x134,
]

PATTERNS = [
	"00b68660",
	"00b66640",
	"00b68450",
	"00592e70",
	"005453b0",
	"00877a30",
	"00653290",
	"00a59d30",
	"texture",
	"textureset",
	"diff",
	"normal",
	"glow",
	"height",
	"envmap",
	"mask",
	"specular",
	"+ 0x8c",
	"+0x8c",
	"+ 0x90",
	"+0x90",
	"+ 0xa8",
	"+0xa8",
	"+ 0xac",
	"+0xac",
	"+ 0xb0",
	"+0xb0",
	"+ 0xb4",
	"+0xb4",
	"+ 0xb8",
	"+0xb8",
	"+ 0xbc",
	"+0xbc",
	"+ 0xc0",
	"+0xc0",
	"+ 0xc4",
	"+0xc4",
	"+ 0xcc",
	"+0xcc",
]

DISASM_PATTERNS = [
	"+ 0x8c",
	"+0x8c",
	"+ 0x90",
	"+0x90",
	"+ 0xa8",
	"+0xa8",
	"+ 0xac",
	"+0xac",
	"+ 0xb0",
	"+0xb0",
	"+ 0xb4",
	"+0xb4",
	"+ 0xb8",
	"+0xb8",
	"+ 0xbc",
	"+0xbc",
	"+ 0xc0",
	"+0xc0",
	"+ 0xc4",
	"+0xc4",
	"+ 0xcc",
	"+0xcc",
	"00b68660",
	"00b66640",
	"00b68450",
	"00592e70",
	"00877a30",
	"call eax",
	"call edx",
	"call ecx",
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
		if count > 120:
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

def call_target_for_instruction(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		if ref.getReferenceType().isCall():
			return ref.getToAddress().getOffset()
	return None

def collect_pushes_before(inst, max_pushes, max_steps):
	pushes = []
	cur = listing.getInstructionBefore(inst.getAddress())
	steps = 0
	while cur is not None and steps < max_steps and len(pushes) < max_pushes:
		mnemonic = cur.getMnemonicString()
		if mnemonic == "PUSH":
			pushes.append((cur.getAddress().getOffset(), operand_text(cur, 0), cur.toString()))
		elif mnemonic.startswith("RET"):
			break
		cur = listing.getInstructionBefore(cur.getAddress())
		steps += 1
	return pushes

def print_direct_call_table(addr_int, label, targets, max_args):
	func = get_function(addr_int)
	if func is None:
		return
	write("")
	write("=" * 70)
	write("DIRECT CALL TABLE: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		target = call_target_for_instruction(inst)
		if target is None:
			continue
		found = False
		for value in targets:
			if target == value:
				found = True
				break
		if not found:
			continue
		count += 1
		write("")
		write("  call 0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), target, label_for(target)))
		write("    ECX before call:")
		print_register_defs_before(inst, "ECX", 64, 5, "      ")
		pushes = collect_pushes_before(inst, max_args, 120)
		index = 0
		while index < max_args:
			if index < len(pushes):
				arg = pushes[index][1]
				write("    stack_arg%d = %-14s ; push @ 0x%08x" % (index, arg, pushes[index][0]))
				if is_register_text(arg):
					arg_inst = listing.getInstructionAt(toAddr(pushes[index][0]))
					if arg_inst is not None:
						print_register_defs_before(arg_inst, arg.upper(), 56, 4, "      ")
			else:
				write("    stack_arg%d = ?" % index)
			index += 1
		write("    local window:")
		print_short_window(inst, 20, 10)
	write("")
	write("  Matched calls: %d" % count)

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

def scan_disasm_pattern_windows(addr_int, label):
	func = get_function(addr_int)
	if func is None:
		return
	write("")
	write("=" * 70)
	write("DISASM FIELD/CALL WINDOWS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		matched = False
		for pattern in DISASM_PATTERNS:
			if pattern in text:
				matched = True
				break
		if matched:
			count += 1
			write("")
			write("  match %d at 0x%08x: %s" % (count, inst.getAddress().getOffset(), inst.toString()))
			print_short_window(inst, 12, 10)
			if count >= 100:
				write("  ... (truncated)")
				break
	write("  Total matched windows: %d" % count)

def dump_vtable(base, label):
	write("")
	write("=" * 70)
	write("VTABLE DUMP: %s @ 0x%08x" % (label, base))
	write("=" * 70)
	for slot in VTABLE_SLOTS:
		ptr = read_u32(base + slot)
		if ptr is None:
			write("  +0x%03x -> unreadable" % slot)
		else:
			write("  +0x%03x -> 0x%08x %s" % (slot, ptr, label_for(ptr)))

def decompile_vtable_slots(base, label):
	write("")
	write("=" * 70)
	write("SELECTED VTABLE SLOT DECOMPILES: %s @ 0x%08x" % (label, base))
	write("=" * 70)
	for slot in VTABLE_SLOTS:
		ptr = read_u32(base + slot)
		if ptr is None:
			continue
		func = get_function(ptr)
		if func is None:
			continue
		if slot in [0x8C, 0x90, 0x94, 0x98, 0x9C, 0xA0, 0xA4, 0xA8, 0xAC, 0xB0, 0xB4, 0xB8, 0xBC, 0xC0, 0xE0, 0x114, 0x118, 0x11C]:
			decompile_at(ptr, "%s slot +0x%03x" % (label, slot), 14000)

def print_key_refs():
	for addr in REF_TARGETS:
		find_refs_to(addr, label_for(addr))

def print_vtables():
	for item in VTABLES:
		dump_vtable(item[0], item[1])
		decompile_vtable_slots(item[0], item[1])

def print_core_decompiles():
	for item in DECOMPILE_TARGETS:
		decompile_at(item[0], item[1], item[2])

def print_pattern_sections():
	for item in DECOMPILE_TARGETS:
		scan_decompile_patterns(item[0], item[1])
		scan_disasm_pattern_windows(item[0], item[1])

def print_direct_call_sections():
	targets = [
		0x005453B0,
		0x00592E70,
		0x00653290,
		0x00877A30,
		0x00A59D30,
		0x00B55480,
		0x00B66640,
		0x00B68450,
		0x00B68660,
		0x00B690D0,
	]
	for item in CALLSITE_FUNCTIONS:
		print_direct_call_table(item[0], item[1], targets, 12)

def print_calls_from_sections():
	for item in DECOMPILE_TARGETS:
		find_and_print_calls_from(item[0], item[1])

def main():
	write("FNV PBR PPLIGHTING TEXTURE WRITER CALLSITE DEEP AUDIT")
	write("")
	write("Purpose:")
	write("1. Deep-audit the two producer callsites that call FUN_00B68660 and FUN_00B66640.")
	write("2. Recover ECX/stack arguments for the texture-array writer and flag initializer.")
	write("3. Inspect resolver slot +0x90 usage before assigning BGSTextureSet/PBR texture semantics.")
	print_key_refs()
	print_vtables()
	print_core_decompiles()
	print_pattern_sections()
	print_direct_call_sections()
	print_calls_from_sections()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_texture_writer_callsite_deep_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
