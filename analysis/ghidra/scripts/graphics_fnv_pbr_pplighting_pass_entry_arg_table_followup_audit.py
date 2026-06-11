# @category Analysis
# @description Build exact FNV PPLighting shader-interface and pass-entry callsite argument tables for native PBR

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

KNOWN = {
	0x00E7F000: "shader-interface record lookup",
	0x00E7F430: "shader-interface record register/finalize",
	0x00E7F5D0: "shader-interface record factory",
	0x00E826D0: "shader-interface apply dispatcher",
	0x00BA8C50: "pass-entry reused-entry array setter",
	0x00BA8EC0: "pass-entry constructor",
	0x00BA9EE0: "pass-entry append/reuse helper",
	0x00B7A870: "PPLighting/global shader-interface record setup",
	0x00BD20E0: "current-pass local shader-interface record setup",
	0x00B887C0: "lighting shader-interface record setup family A",
	0x00B83DD0: "lighting shader-interface record setup family B",
	0x00BEA040: "shader-interface record setup family C",
	0x00BE22B0: "PPLighting pass writer family A",
	0x00BEB070: "PPLighting pass writer family A/B",
	0x00BEB830: "PPLighting pass writer family A/B",
	0x00BEBD20: "PPLighting pass writer family C",
	0x00C17510: "PPLighting pass writer family C",
}

CALL_TARGETS = [
	(0x00E7F430, "shader-interface record register/finalize", 3, ["record_key", "record_value", "list_flag"]),
	(0x00BA9EE0, "pass-entry append/reuse helper", 8, ["entry_id", "entry_+4_word", "entry_+7_byte", "entry_+9_array_count", "entry_array_value0", "entry_array_value1", "entry_array_value2", "entry_array_value3"]),
	(0x00BA8EC0, "pass-entry constructor", 9, ["entry_ptr", "entry_id", "entry_+4_word", "entry_+7_byte", "entry_+9_array_count", "entry_array_value0", "entry_array_value1", "entry_array_value2", "entry_array_value3"]),
	(0x00BA8C50, "pass-entry reused-entry array setter", 7, ["entry_ptr", "entry_+9_array_count", "entry_array_value0", "entry_array_value1", "entry_array_value2", "entry_array_value3", "extra_or_cookie"]),
]

CORE_FUNCTIONS = [
	(0x00E7F430, "shader-interface record register/finalize"),
	(0x00BA9EE0, "pass-entry append/reuse helper"),
	(0x00BA8EC0, "pass-entry constructor"),
	(0x00BA8C50, "pass-entry reused-entry array setter"),
]

RECORD_SCAN_FUNCTIONS = [
	(0x00B7A870, "PPLighting/global shader-interface record setup"),
	(0x00BD20E0, "current-pass local shader-interface record setup"),
	(0x00B887C0, "lighting shader-interface record setup family A"),
	(0x00B83DD0, "lighting shader-interface record setup family B"),
	(0x00BEA040, "shader-interface record setup family C"),
	(0x00BE22B0, "PPLighting pass writer family A"),
	(0x00BEB070, "PPLighting pass writer family A/B"),
	(0x00BEB830, "PPLighting pass writer family A/B"),
	(0x00BEBD20, "PPLighting pass writer family C"),
	(0x00C17510, "PPLighting pass writer family C"),
]

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
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
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
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, label_for(tgt)))
				count += 1
	write("  Total: %d calls" % count)

def call_target_meta(target_int):
	for item in CALL_TARGETS:
		if item[0] == target_int:
			return item
	return None

def call_meta_for_instruction(inst):
	refs = inst.getReferencesFrom()
	for ref in refs:
		if ref.getReferenceType().isCall():
			meta = call_target_meta(ref.getToAddress().getOffset())
			if meta is not None:
				return meta
	return None

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

def semantic_name(meta, index):
	names = meta[3]
	if index < len(names):
		return names[index]
	return "extra"

def print_callsite_args(addr_int, label, window_limit):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	write("")
	write("=" * 70)
	write("CALLSITE ARGUMENT TABLE: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		meta = call_meta_for_instruction(inst)
		if meta is not None:
			need = meta[2]
			pushes = collect_pushes_before(inst, need + 4, 42)
			owner = find_ecx_owner_before(inst, 36)
			write("")
			write("  call 0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), meta[0], meta[1]))
			if meta[0] == 0x00E7F430 or meta[0] == 0x00BA9EE0:
				if owner is None:
					write("    ecx_owner: ?")
				else:
					write("    ecx_owner @ 0x%08x: %s %s ; %s" % (owner[0], owner[1], owner[2], owner[3]))
			index = 0
			for item in pushes:
				write("    stack_arg%-2d %-22s @ 0x%08x = %-24s ; %s" % (index, semantic_name(meta, index), item[0], item[1], item[2]))
				index += 1
			if count < window_limit:
				write("    local window:")
				print_short_window(inst, 8, 4)
			count += 1
	write("")
	write("  Total matched calls: %d" % count)

def unique_key_from_pushes(pushes, count):
	parts = []
	index = 0
	while index < count:
		if index < len(pushes):
			parts.append(pushes[index][1])
		else:
			parts.append("?")
		index += 1
	return "|".join(parts)

def add_unique_key(rows, key, first_addr):
	for item in rows:
		if item[0] == key:
			item[2] += 1
			return
	rows.append([key, first_addr, 1])

def print_unique_prefixes(functions, target_int, arg_count, label):
	write("")
	write("=" * 70)
	write("UNIQUE ARGUMENT PREFIXES: %s" % label)
	write("=" * 70)
	rows = []
	for item in functions:
		func = fm.getFunctionAt(toAddr(item[0]))
		if func is None:
			func = fm.getFunctionContaining(toAddr(item[0]))
		if func is None:
			continue
		inst_iter = listing.getInstructions(func.getBody(), True)
		while inst_iter.hasNext():
			inst = inst_iter.next()
			meta = call_meta_for_instruction(inst)
			if meta is not None and meta[0] == target_int:
				pushes = collect_pushes_before(inst, arg_count, 42)
				key = "%s | %s" % (item[1], unique_key_from_pushes(pushes, arg_count))
				add_unique_key(rows, key, inst.getAddress().getOffset())
	for row in rows:
		write("  first=0x%08x count=%-3d %s" % (row[1], row[2], row[0]))
	write("  Total unique rows: %d" % len(rows))

def print_core_contract():
	for item in CORE_FUNCTIONS:
		decompile_at(item[0], item[1], 22000)
		find_and_print_calls_from(item[0], item[1])

def print_target_refs():
	find_refs_to(0x00E7F430, "shader-interface record register/finalize")
	find_refs_to(0x00BA9EE0, "pass-entry append/reuse helper")
	find_refs_to(0x00BA8EC0, "pass-entry constructor")
	find_refs_to(0x00BA8C50, "pass-entry reused-entry array setter")

def scan_record_functions():
	for item in RECORD_SCAN_FUNCTIONS:
		print_callsite_args(item[0], item[1], 3)

def scan_pass_entry_functions():
	for item in PASS_ENTRY_SCAN_FUNCTIONS:
		print_callsite_args(item[0], item[1], 2)

def main():
	write("FNV PBR PPLIGHTING PASS-ENTRY ARG TABLE FOLLOW-UP AUDIT")
	write("")
	write("Purpose:")
	write("1. Prove callsite argument order for E7F430, BA9EE0, BA8EC0, and BA8C50.")
	write("2. Capture ECX owners for thiscall helpers instead of relying on decompiler formatting.")
	write("3. Reduce PPLighting record and pass-entry helpers into mechanical argument tuples.")
	write("")
	write("Interpretation rules:")
	write("- stack_arg0 is the first stack argument consumed by the callee, i.e. the last PUSH before CALL.")
	write("- E7F430 and BA9EE0 also use ECX as their owner/list object.")
	write("- BA9EE0 core layout already proved: arg0 -> entry +0, arg1 -> +4 word, arg2 -> +7 byte, arg3 -> +9 array count, arg4+ copied into entry +0xC array.")
	write("- Do not assign albedo/normal/roughness semantics until the argument rows are correlated with draw-time texture binding.")
	print_target_refs()
	print_core_contract()
	print_unique_prefixes(RECORD_SCAN_FUNCTIONS, 0x00E7F430, 3, "E7F430 record key/value/list by setup function")
	print_unique_prefixes(PASS_ENTRY_SCAN_FUNCTIONS, 0x00BA9EE0, 8, "BA9EE0 pass-entry id/fields/array args by helper")
	scan_record_functions()
	scan_pass_entry_functions()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_pplighting_pass_entry_arg_table_followup_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("")
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
