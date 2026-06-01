# @category Analysis
# @description Audit safe guard surfaces for bhkRagdollController null bone-array entries

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

def decompile_at(addr_int, label, max_len=26000):
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
			write("  [decompile truncated at %d chars, total %d]" % (max_len, len(code)))
	else:
		write("  [decompilation failed]")

def decompiled_text(addr_int):
	func = func_for(addr_int)
	if func is None:
		return ""
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		return result.getDecompiledFunction().getC()
	return ""

def find_refs_to(addr_int, label, limit=220):
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

def find_and_print_calls_from(addr_int, label, limit=260):
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

def print_field_mentions(addr_int, label):
	code = decompiled_text(addr_int)
	write("")
	write("-" * 70)
	write("Field mentions in %s" % label)
	write("-" * 70)
	fields = ["0xa4", "0x2a4", "0x88", "0x58", "0x48", "0x4c", "0x0c", "0xc", "0x40", "0x41", "0x43"]
	lines = code.splitlines()
	count = 0
	for idx in range(len(lines)):
		line = lines[idx]
		lower = line.lower()
		matched = False
		for field in fields:
			if field in lower:
				matched = True
		if matched:
			write("  L%-4d %s" % (idx + 1, line))
			count += 1
	write("  Field mention lines: %d" % count)

def audit_guard_function(addr_int, label):
	decompile_at(addr_int, label, 28000)
	print_field_mentions(addr_int, label)
	disasm_window(addr_int, 20, 90, label)
	find_and_print_calls_from(addr_int, label, 260)

def audit_references():
	find_refs_to(0x00c79680, "Ragdoll skeleton update", 260)
	find_refs_to(0x00c7d810, "Bone transform update wrapper", 260)
	find_refs_to(0x00c7d630, "Alternate ragdoll update wrapper", 260)
	find_refs_to(0x00c7d030, "Post bone update", 260)
	find_refs_to(0x00c7f060, "Ragdoll constructor", 160)
	find_refs_to(0x00c7d900, "Ragdoll cleanup", 160)

def main():
	write("Ragdoll null-bone guard surface audit")
	write("")
	write("Known crash shape:")
	write("  FUN_00C79680 reads *(ragdoll + 0xA4)[boneIndex].")
	write("  The entry is NULL, then +0x34 is passed to FUN_00C74DD0.")
	write("  Downstream helper faults at ESI=0x34.")
	write("")
	write("Questions this output must answer before patching:")
	write("  1. Is it safer to skip the whole wrappers (00C7D810/00C7D630) or only skeleton update (00C79680)?")
	write("  2. Do callers treat these functions as void best-effort updates?")
	write("  3. Does post update (00C7D030) depend on skeleton update having succeeded?")
	write("  4. Which minimal pointer/range checks are required to identify a not-ready ragdoll?")
	audit_guard_function(0x00c79680, "Ragdoll skeleton update")
	audit_guard_function(0x00c7d810, "Bone transform update wrapper")
	audit_guard_function(0x00c7d630, "Alternate ragdoll update wrapper")
	audit_guard_function(0x00c7d030, "Post bone update")
	audit_guard_function(0x009308f0, "Actor-process caller of 00C7D810")
	audit_guard_function(0x00920150, "Other caller of 00C7D810")
	audit_references()

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/ragdoll_null_bone_guard_surface_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
