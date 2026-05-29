# @category Analysis
# @description Audit LockFreeStringMap<Model*> and LockFreeMap<TESObjectREFR*, QueuedReference> contracts around crash 0x00559456

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

def find_refs_to(addr_int, label, limit=120):
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

def find_and_print_calls_from(addr_int, label, limit=180):
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

def disasm_window(start_int, length, label, highlights, max_inst=160):
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

def print_refs_with_context(addr_int, label, before=0x30, after=0x80, limit=70):
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

def safe_u32(addr_int):
	try:
		addr = toAddr(addr_int)
		if not mem.contains(addr):
			return None
		return getInt(addr) & 0xffffffff
	except:
		return None

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

def audit_type(addr_int, label):
	print_dwords(addr_int, label, 32)
	find_refs_to(addr_int, label, 200)
	print_refs_with_context(addr_int, label, 0x30, 0x90, 80)

def audit_key_functions():
	items = [
		(0x00444850, "CreateQueuedCharacter / queued reference producer"),
		(0x00445750, "IsRefQueued / queued reference map lookup"),
		(0x004411D0, "QueuedReference base constructor"),
		(0x00449A5F, "Crash chain map/reference caller"),
		(0x00449C3F, "Crash chain map/reference caller"),
		(0x00449C90, "Crash chain map/reference caller"),
		(0x0044C4FA, "ESP[0] caller around stale map cell"),
		(0x0054835D, "Crash chain model/reference caller"),
		(0x00559450, "LockFree/NiPointer pointer get helper"),
		(0x00528CB0, "LockFree/NiPointer holder init-addref helper"),
		(0x006F74F0, "LockFree/NiPointer assignment helper"),
		(0x0044CBF0, "LockFree/NiPointer release helper"),
		(0x0092C870, "Refcount increment helper"),
	]
	for item in items:
		decompile_at(item[0], item[1], 16000)
		find_and_print_calls_from(item[0], item[1], 200)

def main():
	write("=" * 70)
	write("LOCKFREE MODEL MAP CONTRACT AUDIT FOR CRASH 0x00559456")
	write("=" * 70)
	write("")
	write("Runtime anchors:")
	write("  Freed pool cell 0x34E798F0 was classified by CrashLogger as LockFreeStringMap<Model*>.")
	write("  Stack also contains LockFreeMap<TESObjectREFR*, NiPointer<QueuedReference>> at 0x230F01C0.")
	write("  This script finds constructor/destructor/refcount users of the static type data and queued-reference helpers.")
	audit_type(0x010172DC, "RTTI/vtable: LockFreeStringMap<Model*>")
	audit_type(0x0101747C, "RTTI/vtable: LockFreeMap<TESObjectREFR*, NiPointer<QueuedReference>>")
	audit_type(0x01016BA4, "QueuedReference vtable")
	audit_type(0x01016788, "QueuedTexture vtable")
	audit_key_functions()
	write("")
	write("=" * 70)
	write("END LOCKFREE MODEL MAP CONTRACT AUDIT")
	write("=" * 70)

main()

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/lockfree_model_map_contract_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
