# @category Analysis
# @description Identify vtable 0x01097314 seen in TASK_RELEASE before stale queued-task crash

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()
mem = currentProgram.getMemory()
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

def label_for_addr(addr_int):
	func = func_for(addr_int)
	if func is None:
		return "0x%08x ???" % addr_int
	return "0x%08x %s" % (addr_int, name_for_func(func))

def decompile_at(addr_int, label, max_len=9000):
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

def find_refs_to(addr_int, label, limit=100):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		faddr = from_func.getEntryPoint().getOffset() if from_func else 0
		fname = from_func.getName() if from_func else "???"
		write("  %s @ 0x%08x (in %s @ 0x%08x)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname, faddr))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def find_and_print_calls_from(addr_int, label, limit=100):
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
				write("  0x%08x -> %s" % (inst.getAddress().getOffset(), label_for_addr(tgt)))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def safe_u32(addr_int):
	try:
		addr = toAddr(addr_int)
		if not mem.contains(addr):
			return None
		return getInt(addr) & 0xffffffff
	except:
		return None

def is_text_ptr(value):
	return value >= 0x00400000 and value < 0x00e00000

def print_vtable(base, label, slots=36):
	write("")
	write("-" * 70)
	write("VTable/dword table %s @ 0x%08x" % (label, base))
	write("-" * 70)
	for i in range(slots):
		slot = base + i * 4
		value = safe_u32(slot)
		if value is None:
			write("  [%02d] +0x%02x: <unreadable>" % (i, i * 4))
			continue
		write("  [%02d] +0x%02x: 0x%08x -> %s" % (i, i * 4, value, label_for_addr(value)))

def decompile_vtable_targets(base, label, offsets):
	write("")
	write("-" * 70)
	write("Selected vtable target decompiles: %s" % label)
	write("-" * 70)
	seen = []
	for off in offsets:
		value = safe_u32(base + off)
		if value is None:
			write("  +0x%02x: unreadable" % off)
			continue
		if not is_text_ptr(value):
			write("  +0x%02x: 0x%08x not text" % (off, value))
			continue
		if value in seen:
			write("  +0x%02x: 0x%08x duplicate" % (off, value))
			continue
		seen.append(value)
		decompile_at(value, "%s slot +0x%02x" % (label, off), 5000)

def print_refs_with_context(addr_int, label, before=0x35, after=0x75, limit=20):
	write("")
	write("-" * 70)
	write("References with compact context TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	highlights = [addr_int, 0x01097314, 0x00a3fa30, 0x00a3fae0]
	while refs.hasNext():
		ref = refs.next()
		from_addr = ref.getFromAddress().getOffset()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("")
		write("  REF %d: %s from 0x%08x in %s" % (count + 1, ref.getReferenceType(), from_addr, name_for_func(from_func)))
		disasm_window(from_addr - before, before + after, "xref context for 0x%08x" % from_addr, highlights, 90)
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Context refs printed: %d" % count)

def disasm_window(start_int, length, label, highlights, max_inst=120):
	end_int = start_int + length
	write("")
	write("-" * 70)
	write("Disassembly: %s 0x%08x..0x%08x" % (label, start_int, end_int))
	write("-" * 70)
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int))
	count = 0
	while inst is not None and inst.getAddress().getOffset() < end_int:
		off = inst.getAddress().getOffset()
		mark = "   "
		for item in highlights:
			if off == item:
				mark = "=> "
		write("%s0x%08x: %s" % (mark, off, inst.toString()))
		inst = inst.getNext()
		count += 1
		if count >= max_inst:
			write("  ... (truncated at %d instructions)" % max_inst)
			break
	write("  Instructions printed: %d" % count)

def main():
	write("=" * 70)
	write("VTABLE 0x01097314 IDENTITY AUDIT")
	write("=" * 70)
	write("")
	write("Goal:")
	write("  Identify the non-queued-task vtable observed on the freed 80-byte cell before the stale queued-task virtual call.")
	write("  If this is a reused Ni/render object, the fix vector is targeted task-cell quarantine, not another Havok null guard.")
	print_vtable(0x01097314, "runtime TASK_RELEASE vtable", 36)
	find_refs_to(0x01097314, "runtime TASK_RELEASE vtable", 120)
	print_refs_with_context(0x01097314, "runtime TASK_RELEASE vtable refs", 0x50, 0x90, 20)
	decompile_at(0x00a3fa30, "vtable 0x01097314 assign/ref #1", 10000)
	find_and_print_calls_from(0x00a3fa30, "vtable 0x01097314 assign/ref #1", 120)
	find_refs_to(0x00a3fa30, "function 0x00a3fa30", 80)
	decompile_at(0x00a3fae0, "vtable 0x01097314 assign/ref #2", 10000)
	find_and_print_calls_from(0x00a3fae0, "vtable 0x01097314 assign/ref #2", 120)
	find_refs_to(0x00a3fae0, "function 0x00a3fae0", 80)
	decompile_vtable_targets(0x01097314, "vtable 0x01097314", [0x00, 0x04, 0x08, 0x48, 0x4c, 0x50, 0x54, 0x58, 0x5c, 0x60, 0x64, 0x68, 0x6c])
	write("")
	write("=" * 70)
	write("END VTABLE 0x01097314 IDENTITY AUDIT")
	write("=" * 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/vtable_01097314_identity_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
