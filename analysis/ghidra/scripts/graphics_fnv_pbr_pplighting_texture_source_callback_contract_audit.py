# @category Analysis
# @description Audit FNV PPLighting texture source callback contract behind B68660 for native PBR

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00408DA0: "TextureSet indexed path/string helper",
	0x00535AE0: "fallback texture source getter before 009611E0",
	0x00539960: "PPLighting texture writer callsite A",
	0x0053A090: "PPLighting texture writer callsite B",
	0x00592CF0: "texture-source slot-interface getter candidate",
	0x00592E70: "BGSTextureSet +0x30 vtable +0x8C indexed filename getter",
	0x00592F30: "BGSTextureSet +0x30 vtable +0x90 load/copy callback",
	0x00593030: "BGSTextureSet +0x30 vtable +0x94 path release callback",
	0x00633C90: "texture load context helper used by 00592F30",
	0x006E5CC0: "Ni smart-pointer copy/assign helper candidate",
	0x009611E0: "texture source dereference candidate",
	0x00B55840: "texture load from Data\\Textures path candidate",
	0x00B66640: "PPLighting texture-array flag initializer",
	0x00B68660: "PPLighting six texture-array writer",
	0x01033C7C: "BGSTextureSet +0x30 slot-interface vtable",
	0x01033E9C: "Data\\Textures\\ string",
}

REF_TARGETS = [
	0x00592CF0,
	0x00592E70,
	0x00592F30,
	0x00593030,
	0x006E5CC0,
	0x00B55840,
	0x00408DA0,
	0x009611E0,
	0x00535AE0,
	0x00B68660,
	0x00B66640,
	0x01033C7C,
	0x01033E9C,
]

DECOMPILE_TARGETS = [
	(0x00592CF0, "texture-source slot-interface getter candidate", 22000),
	(0x009611E0, "texture source dereference candidate", 22000),
	(0x00535AE0, "fallback texture source getter before 009611E0", 22000),
	(0x00592E70, "BGSTextureSet +0x30 +0x8C indexed filename getter", 22000),
	(0x00592F30, "BGSTextureSet +0x30 +0x90 load/copy callback", 30000),
	(0x00593030, "BGSTextureSet +0x30 +0x94 path release callback", 20000),
	(0x00408DA0, "TextureSet indexed path/string helper", 24000),
	(0x00B55840, "texture load from Data\\Textures path candidate", 30000),
	(0x006E5CC0, "Ni smart-pointer copy/assign helper candidate", 30000),
	(0x00B68660, "PPLighting six texture-array writer", 22000),
	(0x00B66640, "PPLighting texture-array flag initializer", 18000),
]

DISASM_TARGETS = [
	(0x00592CF0, "texture-source slot-interface getter candidate", 90),
	(0x00592E70, "BGSTextureSet +0x30 +0x8C indexed filename getter", 90),
	(0x00592F30, "BGSTextureSet +0x30 +0x90 load/copy callback", 140),
	(0x00593030, "BGSTextureSet +0x30 +0x94 path release callback", 80),
	(0x00B55840, "texture load from Data\\Textures path candidate", 160),
	(0x006E5CC0, "Ni smart-pointer copy/assign helper candidate", 130),
	(0x00B68660, "PPLighting six texture-array writer", 120),
]

PRODUCER_CALLS = [
	(0x00539BCF, "writer A base source present path", 2),
	(0x00539BEF, "writer A base fallback path", 2),
	(0x00539C4C, "writer A layer source present path", 2),
	(0x00539C5C, "writer A layer clear/fallback path", 2),
	(0x00539E35, "writer A flag initializer", 10),
	(0x0053A253, "writer B base source present path", 2),
	(0x0053A273, "writer B base fallback path", 2),
	(0x0053A2D0, "writer B layer source present path", 2),
	(0x0053A2E0, "writer B layer clear/fallback path", 2),
	(0x0053A48C, "writer B flag initializer", 10),
]

CALL_TABLE_FUNCTIONS = [
	(0x00539960, "PPLighting texture writer callsite A", [0x00592CF0, 0x00B68660, 0x00B66640], 10),
	(0x0053A090, "PPLighting texture writer callsite B", [0x00592CF0, 0x00B68660, 0x00B66640], 10),
	(0x00592F30, "BGSTextureSet +0x30 +0x90 load/copy callback", [], 8),
	(0x00B68660, "PPLighting six texture-array writer", [], 6),
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

def ensure_function_at(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is not None:
		return func
	containing = fm.getFunctionContaining(addr)
	if containing is not None:
		write("  NOTE: 0x%08x is inside existing %s @ 0x%08x" % (addr_int, containing.getName(), containing.getEntryPoint().getOffset()))
		return containing
	try:
		disassemble(addr)
	except Exception as err:
		write("  disassemble failed at 0x%08x (%s): %s" % (addr_int, label, err))
	try:
		func = createFunction(addr, "pbr_texture_source_callback_%08x" % addr_int)
		if func is not None:
			write("  created function at 0x%08x (%s)" % (addr_int, label))
		return func
	except Exception as err:
		write("  createFunction failed at 0x%08x (%s): %s" % (addr_int, label, err))
		return None

def decompile_text_for_func(func):
	if func is None:
		return None
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		return result.getDecompiledFunction().getC()
	return None

def decompile_at(addr_int, label, max_len=22000):
	write("")
	write("=" * 70)
	write("%s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = ensure_function_at(addr_int, label)
	if func is None:
		write("  [function not found]")
		return
	faddr = func.getEntryPoint().getOffset()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, func.getBody().getNumAddresses()))
	if faddr != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	code = decompile_text_for_func(func)
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
		inst = listing.getInstructionAt(ref.getFromAddress())
		itext = inst.toString() if inst is not None else ""
		write("  %s/%s @ 0x%08x (in %s) %s" % (ref.getReferenceType(), ref.getOperandIndex(), ref.getFromAddress().getOffset(), fname, itext))
		count += 1
		if count > 180:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_and_print_calls_from(addr_int, label):
	func = ensure_function_at(addr_int, label)
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
		target = None
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				break
		if target is None:
			if inst.getMnemonicString().upper().startswith("CALL"):
				write("  0x%08x -> indirect %s" % (inst.getAddress().getOffset(), inst.toString()))
				count += 1
			continue
		write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), target, label_for(target)))
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
	mnemonic = inst.getMnemonicString().upper()
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
		mnemonic = cur.getMnemonicString().upper()
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

def is_backward_barrier(inst):
	mnemonic = inst.getMnemonicString().upper()
	if mnemonic.startswith("CALL"):
		return True
	if mnemonic.startswith("RET"):
		return True
	if mnemonic.startswith("J"):
		return True
	return False

def collect_pushes_until_barrier(inst, max_pushes, max_steps):
	pushes = []
	cur = listing.getInstructionBefore(inst.getAddress())
	steps = 0
	while cur is not None and steps < max_steps and len(pushes) < max_pushes:
		mnemonic = cur.getMnemonicString().upper()
		if mnemonic == "PUSH":
			pushes.append((cur.getAddress().getOffset(), operand_text(cur, 0), cur.toString()))
		elif is_backward_barrier(cur):
			break
		cur = listing.getInstructionBefore(cur.getAddress())
		steps += 1
	return pushes

def print_precise_stack_args(inst, max_args, indent):
	pushes = collect_pushes_until_barrier(inst, max_args, 80)
	index = 0
	while index < max_args:
		if index < len(pushes):
			arg = pushes[index][1]
			write("%sstack_arg%d = %-18s ; push @ 0x%08x" % (indent, index, arg, pushes[index][0]))
			if is_register_text(arg):
				arg_inst = listing.getInstructionAt(toAddr(pushes[index][0]))
				if arg_inst is not None:
					print_register_defs_before(arg_inst, arg.upper(), 56, 4, indent + "  ")
		else:
			write("%sstack_arg%d = [not pushed since nearest call/jump barrier]" % (indent, index))
		index += 1

def print_exact_callsite(addr_int, label, max_args):
	inst = listing.getInstructionAt(toAddr(addr_int))
	write("")
	write("=" * 70)
	write("EXACT CALLSITE: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if inst is None:
		write("  [instruction not found]")
		return
	target = call_target_for_instruction(inst)
	if target is None:
		write("  call target: indirect or unresolved")
	else:
		write("  call target: 0x%08x %s" % (target, label_for(target)))
	write("  ECX before call:")
	print_register_defs_before(inst, "ECX", 64, 5, "    ")
	write("  stack arguments since nearest call/jump barrier:")
	print_precise_stack_args(inst, max_args, "    ")
	write("  local disassembly window:")
	print_short_window(inst, 24, 12)

def target_in_list(target, values):
	for value in values:
		if target == value:
			return True
	return False

def print_call_table(addr_int, label, targets, max_args):
	func = ensure_function_at(addr_int, label)
	if func is None:
		return
	write("")
	write("=" * 70)
	write("CALL TABLE WITH BARRIER-LIMITED STACK ARGS: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		if not inst.getMnemonicString().upper().startswith("CALL"):
			continue
		target = call_target_for_instruction(inst)
		if len(targets) > 0 and not target_in_list(target, targets):
			continue
		count += 1
		write("")
		if target is None:
			write("  call 0x%08x -> indirect %s" % (inst.getAddress().getOffset(), inst.toString()))
		else:
			write("  call 0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), target, label_for(target)))
		write("    ECX before call:")
		print_register_defs_before(inst, "ECX", 48, 4, "      ")
		write("    stack arguments since nearest call/jump barrier:")
		print_precise_stack_args(inst, max_args, "      ")
	write("")
	write("  Matched calls: %d" % count)

def print_function_disasm(addr_int, label, max_insts):
	write("")
	write("=" * 70)
	write("RAW DISASM: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	func = ensure_function_at(addr_int, label)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext() and count < max_insts:
		inst = inst_iter.next()
		line = "  0x%08x: %-58s" % (inst.getAddress().getOffset(), inst.toString())
		refs = inst.getReferencesFrom()
		ref_bits = []
		for ref in refs:
			if ref.getReferenceType().isCall() or ref.getReferenceType().isData() or ref.getReferenceType().isJump():
				ref_bits.append("%s -> 0x%08x %s" % (ref.getReferenceType(), ref.getToAddress().getOffset(), label_for(ref.getToAddress().getOffset())))
		if len(ref_bits) > 0:
			line = line + " ; " + " | ".join(ref_bits)
		write(line)
		count += 1
	if inst_iter.hasNext():
		write("  ... (truncated after %d instructions)" % max_insts)

def print_stack_use_scan(addr_int, label):
	func = ensure_function_at(addr_int, label)
	if func is None:
		return
	write("")
	write("=" * 70)
	write("STACK/RET/OUT-PTR SCAN: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString().lower()
		if ("[esp" in text) or ("[ebp + 0x8" in text) or ("[ebp + 0xc" in text) or ("ret" == inst.getMnemonicString().lower()) or ("006e5cc0" in text) or ("00b55840" in text):
			write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
			print_refs_from_instruction(inst, "    ")
			count += 1
	write("  Total stack/ret/out-ptr matches: %d" % count)

def dump_texture_source_vtable():
	write("")
	write("=" * 70)
	write("TEXTURE SOURCE VTABLE CHECK @ 0x01033c7c")
	write("=" * 70)
	for slot in [0x8C, 0x90, 0x94]:
		ptr = read_u32(0x01033C7C + slot)
		if ptr is None:
			write("  +0x%03x -> unreadable" % slot)
		else:
			write("  +0x%03x -> 0x%08x %s" % (slot, ptr, label_for(ptr)))

def print_key_refs():
	for addr in REF_TARGETS:
		find_refs_to(addr, label_for(addr))

def print_core_decompiles():
	for item in DECOMPILE_TARGETS:
		decompile_at(item[0], item[1], item[2])

def print_core_disasm():
	for item in DISASM_TARGETS:
		print_function_disasm(item[0], item[1], item[2])
		print_stack_use_scan(item[0], item[1])

def print_exact_calls():
	for item in PRODUCER_CALLS:
		print_exact_callsite(item[0], item[1], item[2])

def print_call_tables():
	for item in CALL_TABLE_FUNCTIONS:
		print_call_table(item[0], item[1], item[2], item[3])
		find_and_print_calls_from(item[0], item[1])

def main():
	write("FNV PBR PPLIGHTING TEXTURE SOURCE CALLBACK CONTRACT AUDIT")
	write("")
	write("Purpose:")
	write("1. Prove which object is passed from FUN_00592CF0 into FUN_00B68660.")
	write("2. Raw-disassemble BGSTextureSet +0x30 vtable slot +0x90 (FUN_00592F30).")
	write("3. Prove whether the second B68660 callback argument is an out pointer hidden by decompiler signatures.")
	write("4. Keep renderer-side vtable 0x010F086C separate from the source texture callback contract.")
	dump_texture_source_vtable()
	print_key_refs()
	print_core_decompiles()
	print_core_disasm()
	print_exact_calls()
	print_call_tables()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_texture_source_callback_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
