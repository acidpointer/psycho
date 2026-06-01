# @category Analysis
# @description Find bhkRagdollController +0xA4/+0x2A4 writers and allocation sequence

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.address import AddressSet

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

def add_seen(seen, func):
	if func is None:
		return
	key = func.getEntryPoint().getOffset()
	if key not in seen:
		seen[key] = func

def instruction_mentions_offset(inst_text, offset_text):
	text = inst_text.lower()
	if offset_text in text:
		return True
	return False

def is_probable_write(inst):
	mn = inst.getMnemonicString().lower()
	if mn.startswith("mov") or mn.startswith("lea") or mn.startswith("xchg") or mn.startswith("cmpxchg"):
		return True
	return False

def scan_offset_mentions(start_int, end_int, offset_text, label, limit=260):
	write("")
	write("=" * 70)
	write("Instruction scan for %s in 0x%08x-0x%08x (%s)" % (offset_text, start_int, end_int, label))
	write("=" * 70)
	aset = AddressSet(toAddr(start_int), toAddr(end_int))
	inst_iter = listing.getInstructions(aset, True)
	seen = {}
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		text = inst.toString()
		if instruction_mentions_offset(text, offset_text):
			func = fm.getFunctionContaining(inst.getAddress())
			add_seen(seen, func)
			tag = "WRITE-LIKE" if is_probable_write(inst) else "read/calc"
			write("  %-10s 0x%08x %-52s in %s" % (tag, inst.getAddress().getOffset(), text, name_for_func(func)))
			count += 1
			if count >= limit:
				write("  ... (instruction scan truncated at %d)" % limit)
				break
	write("  Matches printed: %d" % count)
	write("")
	write("-" * 70)
	write("Context windows for %s matches" % offset_text)
	write("-" * 70)
	keys = sorted(seen.keys())
	printed = 0
	for key in keys:
		func = seen[key]
		decompile_at(key, "owner with %s mention: %s" % (offset_text, name_for_func(func)), 22000)
		find_and_print_calls_from(key, "owner with %s mention" % offset_text, 220)
		printed += 1
		if printed >= 40:
			write("  [owner context truncated at 40]")
			break

def audit_init_sequence():
	write("")
	write("=" * 70)
	write("Known ragdoll constructor/init sequence")
	write("=" * 70)
	targets = [
		(0x00c7f060, "bhkRagdollController constructor"),
		(0x00c7d3b0, "Constructor helper before init"),
		(0x00c7e9a0, "Constructor helper likely allocates/links controller data"),
		(0x00c75c00, "Constructor helper after init"),
		(0x00c7d900, "bhkRagdollController cleanup"),
		(0x00c85750, "Havok allocator/context accessor"),
		(0x00c79680, "Skeleton update reader of +0xA4 entries"),
		(0x00c7d810, "Bone transform update wrapper"),
	]
	for item in targets:
		decompile_at(item[0], item[1], 26000)
		disasm_window(item[0], 20, 80, item[1])
		find_and_print_calls_from(item[0], item[1], 260)

def audit_refs():
	find_refs_to(0x00c7f060, "bhkRagdollController constructor", 180)
	find_refs_to(0x00c7d3b0, "Constructor helper before init", 180)
	find_refs_to(0x00c7e9a0, "Constructor helper likely data init", 180)
	find_refs_to(0x00c75c00, "Constructor helper after init", 180)
	find_refs_to(0x00c85750, "Havok allocator/context accessor", 260)
	find_refs_to(0x010c4ddc, "bhkRagdollController vtable", 260)

def main():
	write("Ragdoll bone array writer deep audit")
	write("")
	write("Goal:")
	write("  Find concrete writers/allocators for bhkRagdollController +0xA4 and +0x2A4.")
	write("  The crash is not solved until we know whether +0xA4 has NULL entries because allocation returned zeroed memory,")
	write("  because an init step was skipped, or because a cleanup/destructor partially cleared the structure.")
	write("")
	audit_init_sequence()
	audit_refs()
	scan_offset_mentions(0x00c00000, 0x00d10000, "0xa4", "Havok/ragdoll code", 320)
	scan_offset_mentions(0x00c00000, 0x00d10000, "0x2a4", "Havok/ragdoll code", 220)
	scan_offset_mentions(0x00800000, 0x00980000, "0x2b", "actor process high-process ragdoll pointer", 220)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/ragdoll_bone_array_writer_deep_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
