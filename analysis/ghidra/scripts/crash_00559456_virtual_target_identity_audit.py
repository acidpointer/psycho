# @category Analysis
# @description Identify the virtual target that reaches FUN_00449A50 in crash 0x00559456

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

def safe_u32(addr_int):
	try:
		addr = toAddr(addr_int)
		if not mem.contains(addr):
			return None
		return getInt(addr) & 0xffffffff
	except:
		return None

def decompile_at(addr_int, label, max_len=14000):
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
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), name_for_func(from_func)))
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def find_and_print_calls_from(addr_int, label, limit=160):
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

def disasm_window(start_int, length, label, highlights, max_inst=140):
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

def print_dwords(base, label, count):
	write("")
	write("-" * 70)
	write("DWords: %s @ 0x%08x" % (label, base))
	write("-" * 70)
	i = 0
	while i < count:
		addr = base + i * 4
		value = safe_u32(addr)
		if value is None:
			write("  +0x%02x: <unreadable>" % (i * 4))
		else:
			write("  +0x%02x: 0x%08x -> %s" % (i * 4, value, label_for_addr(value)))
		i += 1

def find_refs_with_context(addr_int, label, before=0x24, after=0x70, limit=50):
	write("")
	write("-" * 70)
	write("References with context TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_addr = ref.getFromAddress().getOffset()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		write("")
		write("REF %d: %s from 0x%08x in %s" % (count + 1, ref.getReferenceType(), from_addr, name_for_func(from_func)))
		disasm_window(max(0, from_addr - before), before + after, "xref context for 0x%08x" % from_addr, [from_addr], 80)
		count += 1
		if count >= limit:
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total printed: %d" % count)

def scan_rdata_for_target(target, limit=120):
	write("")
	write("=" * 70)
	write("RDATA SCAN FOR 0x%08x" % target)
	write("=" * 70)
	blocks = mem.getBlocks()
	count = 0
	for block in blocks:
		start = block.getStart().getOffset()
		end = block.getEnd().getOffset()
		if end < 0x01000000 or start > 0x01120000:
			continue
		addr = start
		while addr <= end - 3:
			value = safe_u32(addr)
			if value == target:
				write("  entry 0x%08x contains target; slot+0x1c candidate vtable=0x%08x" % (addr, addr - 0x1c))
				print_dwords(addr - 0x1c, "candidate vtable for CALL [vtable+0x1c]", 24)
				find_refs_to(addr - 0x1c, "candidate vtable base", 40)
				count += 1
				if count >= limit:
					write("  ... (truncated at %d entries)" % limit)
					write("  Total target entries printed: %d" % count)
					return
			addr += 4
	write("  Total target entries printed: %d" % count)

def audit_key_paths():
	disasm_window(0x00446c18, 0x78, "virtual call in FUN_00446B50", [0x00446c3c, 0x00446c53, 0x00446c55], 90)
	disasm_window(0x00449a40, 0x50, "target FUN_00449A50", [0x00449a50, 0x00449a5a, 0x00449a5f], 80)
	decompile_at(0x00446b50, "caller that invokes task vtable slot +0x1c", 16000)
	find_and_print_calls_from(0x00446b50, "caller that invokes task vtable slot +0x1c", 180)
	decompile_at(0x00449a50, "virtual target / scalar destructor candidate", 9000)
	decompile_at(0x00449c30, "FUN_00449C30 wrapper", 6000)
	decompile_at(0x00449c50, "LockFreeStringMap<Model*> destructor body", 9000)
	decompile_at(0x0044c480, "LockFree map clear/reset body", 12000)

def main():
	write("=" * 70)
	write("CRASH 0x00559456 VIRTUAL TARGET IDENTITY AUDIT")
	write("=" * 70)
	write("")
	write("Crash stack says FUN_00446B50 called through vtable slot +0x1c and landed in FUN_00449A50.")
	write("This script identifies which vtable contains 0x00449A50 and whether it is a stale queued task/model object.")
	audit_key_paths()
	find_refs_to(0x00449a50, "FUN_00449A50", 120)
	find_refs_with_context(0x00449a50, "FUN_00449A50", 0x28, 0x90, 80)
	scan_rdata_for_target(0x00449a50, 120)
	write("")
	write("=" * 70)
	write("END CRASH 0x00559456 VIRTUAL TARGET IDENTITY AUDIT")
	write("=" * 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_00559456_virtual_target_identity_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
