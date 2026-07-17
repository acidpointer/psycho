# @category Analysis
# @description Close the remaining FNV PBR light metric and shadow transition-to-PPLighting ownership gaps

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

OUTPATH = "/data/storage1/Workspace/psycho/analysis/ghidra/output/perf/graphics_fnv_pbr_light_shadow_continuity_final_followup.txt"

TARGETS = [
	(0x00B9DAE0, "PPLighting light eligibility and influence test"),
	(0x00B9DBE0, "PPLighting light-list camera metric"),
	(0x00B719E0, "alternate PPLighting light metric"),
	(0x00B9BB10, "shadow candidate transition initializer"),
	(0x00B9E970, "shadow candidate distance and transition fade updater"),
	(0x00B717A0, "shadow candidate PPLighting detach"),
]

WINDOWS = [
	(0x00B5A980, 24, 32, "shadow dependent-array pointer comparator"),
	(0x00B9ECEE, 24, 42, "shadow transition time accumulation"),
	(0x00B9EE90, 24, 48, "shadow fade change propagation to PPLighting"),
	(0x00B717A0, 20, 48, "shadow candidate PPLighting detach entry"),
]

def write(msg):
	output.append(msg)
	print(msg)

def checkpoint_output():
	fout = open(OUTPATH, "w")
	fout.write("\n".join(output))
	fout.close()

def function_at_or_containing(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	return func

def function_label(addr_int):
	func = function_at_or_containing(addr_int)
	if func is None:
		return "unknown"
	entry = func.getEntryPoint().getOffset()
	if entry == addr_int:
		return func.getName()
	return "%s+0x%x" % (func.getName(), addr_int - entry)

def instruction_bytes(inst):
	try:
		values = inst.getBytes()
		parts = []
		index = 0
		while index < len(values):
			parts.append("%02x" % (values[index] & 0xff))
			index += 1
		return " ".join(parts)
	except:
		return "??"

def outgoing_refs_text(inst):
	parts = []
	refs = inst.getReferencesFrom()
	for ref in refs:
		target = ref.getToAddress()
		if target is not None:
			parts.append("%s->0x%08x" % (str(ref.getReferenceType()), target.getOffset()))
	return ", ".join(parts)

def decompile_at(addr_int, label, max_len=1000000):
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
	result = decomp.decompileFunction(func, 180, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

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
		text = inst.toString() if inst is not None else ""
		write("  %s @ 0x%08x (in %s) %s" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, text))
		count += 1
		if count >= 240:
			write("  ... (truncated)")
			break
	write("  Total printed refs: %d" % count)

def find_and_print_calls_from(addr_int, label):
	func = function_at_or_containing(addr_int)
	if func is None:
		write("  [function not found at 0x%08x]" % addr_int)
		return
	inst_iter = listing.getInstructions(func.getBody(), True)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), target, function_label(target)))
				count += 1
	write("  Total: %d calls" % count)

def print_full_function_disassembly(addr_int, label):
	func = function_at_or_containing(addr_int)
	write("")
	write("=" * 70)
	write("RAW FUNCTION: %s @ 0x%08x" % (label, addr_int))
	write("=" * 70)
	if func is None:
		write("  [function not found]")
		return
	entry = func.getEntryPoint().getOffset()
	inst_iter = listing.getInstructions(func.getBody(), True)
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		address = inst.getAddress().getOffset()
		write("  0x%08x +0x%04x  %-24s %-46s %s" % (address, address - entry, instruction_bytes(inst), inst.toString(), outgoing_refs_text(inst)))
		count += 1
	write("  Total instructions: %d" % count)

def instruction_before_steps(inst, steps):
	current = inst
	index = 0
	while current is not None and index < steps:
		previous = listing.getInstructionBefore(current.getAddress())
		if previous is None:
			break
		current = previous
		index += 1
	return current

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("DISASM WINDOW: %s around 0x%08x" % (label, center_int))
	write("-" * 70)
	inst = listing.getInstructionContaining(toAddr(center_int))
	if inst is None:
		write("  [instruction not found]")
		return
	current = instruction_before_steps(inst, before_count)
	index = 0
	limit = before_count + after_count + 1
	while current is not None and index < limit:
		address = current.getAddress().getOffset()
		marker = " << TARGET" if address == center_int else ""
		write("  0x%08x  %-24s %-46s %s%s" % (address, instruction_bytes(current), current.toString(), outgoing_refs_text(current), marker))
		current = listing.getInstructionAfter(current.getAddress())
		index += 1

def audit_targets():
	index = 0
	while index < len(TARGETS):
		item = TARGETS[index]
		find_refs_to(item[0], item[1])
		decompile_at(item[0], item[1])
		find_and_print_calls_from(item[0], item[1])
		print_full_function_disassembly(item[0], item[1])
		checkpoint_output()
		index += 1

def audit_windows():
	index = 0
	while index < len(WINDOWS):
		item = WINDOWS[index]
		disasm_window(item[0], item[1], item[2], item[3])
		index += 1

def main():
	write("FNV PBR LIGHT/SHADOW CONTINUITY FINAL FOLLOW-UP")
	write("")
	write("Required closure:")
	write("1. Recover the exact camera-relative PPLighting list metric and equality behavior.")
	write("2. Prove how shadow transition direction/time changes per-candidate fade.")
	write("3. Prove when fade changes dirty attached PPLighting properties.")
	write("4. Prove when rejected shadow candidates detach from those properties.")
	write("5. Identify whether a safe intervention is needed after both native continuity paths are understood.")
	audit_targets()
	audit_windows()
	checkpoint_output()
	write("")
	write("OUTPUT COMPLETE: %s (%d lines)" % (OUTPATH, len(output)))

try:
	main()
finally:
	checkpoint_output()
	decomp.dispose()
