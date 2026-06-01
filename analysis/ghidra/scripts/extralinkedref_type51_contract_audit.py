# @category Analysis
# @description Audit ExtraLinkedRef type 0x51 layout, creation, lookup, and invalid target handling

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def func_for(addr_int):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	return func

def name_for_func(func):
	if func is None:
		return "???"
	return "%s @ 0x%08x" % (func.getName(), func.getEntryPoint().getOffset())

def decompile_at(addr_int, label, max_len=18000):
	addr = toAddr(addr_int)
	func = func_for(addr_int)
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
		if len(code) > max_len:
			write("  [decompile truncated at %d chars]" % max_len)
	else:
		write("  [decompilation failed]")

def find_refs_to(addr_int, label, limit=180):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), name_for_func(from_func)))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def find_and_print_calls_from(addr_int, label, limit=220):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Calls FROM %s (0x%08x)" % (label, addr_int))
	write("-" * 70)
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
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name_for_func(func_for(tgt))))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly: %s around 0x%08x" % (label, center_int))
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
		off = inst.getAddress().getOffset()
		marker = " << target" if off == center_int else ""
		write("  0x%08x: %-58s%s" % (off, inst.toString(), marker))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (tgt, name_for_func(func_for(tgt))))
		inst = inst.getNext()
		idx += 1

def operand_object_value(obj):
	try:
		return obj.getValue()
	except:
		pass
	try:
		return obj.getOffset()
	except:
		pass
	return None

def instruction_uses_immediate(inst, value):
	op_count = inst.getNumOperands()
	idx = 0
	while idx < op_count:
		objs = inst.getOpObjects(idx)
		for obj in objs:
			obj_value = operand_object_value(obj)
			if obj_value == value:
				return True
		idx += 1
	return False

def add_seen_func(seen, func):
	if func is None:
		return
	key = func.getEntryPoint().getOffset()
	if key not in seen:
		seen[key] = func

def scan_immediate_uses(value, label, limit=260):
	write("")
	write("=" * 70)
	write("Immediate scan for 0x%02x (%s)" % (value, label))
	write("=" * 70)
	inst_iter = listing.getInstructions(True)
	count = 0
	seen = {}
	while inst_iter.hasNext():
		inst = inst_iter.next()
		if instruction_uses_immediate(inst, value):
			func = fm.getFunctionContaining(inst.getAddress())
			add_seen_func(seen, func)
			write("  0x%08x: %-54s in %s" % (inst.getAddress().getOffset(), inst.toString(), name_for_func(func)))
			count += 1
			if count >= limit:
				write("  ... (truncated at %d)" % limit)
				break
	write("  Immediate uses printed: %d" % count)
	write("")
	write("Functions containing printed 0x%02x immediates:" % value)
	print_seen_functions(seen, 80)
	decompile_seen_functions(seen, "0x%02x immediate function" % value, 40)

def print_seen_functions(seen, limit):
	keys = sorted(seen.keys())
	count = 0
	for key in keys:
		func = seen[key]
		write("  0x%08x %s" % (key, name_for_func(func)))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total functions printed: %d" % count)

def decompile_seen_functions(seen, label, limit):
	keys = sorted(seen.keys())
	count = 0
	for key in keys:
		func = seen[key]
		decompile_at(func.getEntryPoint().getOffset(), "%s %s" % (label, name_for_func(func)), 12000)
		count += 1
		if count >= limit:
			write("  [seen function decompile truncated at %d]" % limit)
			break

def audit_known_functions():
	write("")
	write("=" * 70)
	write("Known functions and crash-path context")
	write("=" * 70)
	targets = [
		(0x00410220, "BaseExtraList::GetByType"),
		(0x0040ff60, "BaseExtraList add extra"),
		(0x00410140, "BaseExtraList remove by type"),
		(0x0044ddc0, "BSExtraData next helper"),
		(0x004f1540, "BSExtraData type helper"),
		(0x005012e9, "Current crash frame 1"),
		(0x00501485, "Current crash frame 2"),
		(0x00573733, "Current crash frame 3"),
		(0x0094328e, "No-activate-sound patched callsite"),
	]
	for item in targets:
		decompile_at(item[0], item[1], 18000)
		disasm_window(item[0], 18, 64, item[1])
		find_and_print_calls_from(item[0], item[1], 160)

def audit_rtti_and_extra_tables():
	find_refs_to(0x01184e1c, "RTTI_ExtraLinkedRef", 180)
	find_refs_to(0x01184df4, "RTTI_ExtraLinkedRefChildren", 120)
	find_refs_to(0x00410220, "BaseExtraList::GetByType", 300)
	find_refs_to(0x0040ff60, "BaseExtraList add extra", 180)
	find_refs_to(0x00410140, "BaseExtraList remove by type", 180)

def main():
	write("ExtraLinkedRef type 0x51 contract audit")
	write("")
	write("xNVSE GameExtraData.h says ExtraLinkedRef is type 0x51 and size 0x10.")
	write("Crash register EDX dereferences to ExtraLinkedRef, while GetTypeID receives ECX=0xFFFFFDA5.")
	write("This script searches for type 0x51 users and compares them with type 0x52, the older ExtraLinkedRefChildren crash.")
	audit_known_functions()
	audit_rtti_and_extra_tables()
	scan_immediate_uses(0x51, "ExtraLinkedRef type id", 260)
	scan_immediate_uses(0x52, "ExtraLinkedRefChildren type id comparison", 180)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/extralinkedref_type51_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
