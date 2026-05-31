# @category Analysis
# @description Audit save crash at 0x00865DFB with ExtraOwnership owner=0x7

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()
mem = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

EXTRA_OWNERSHIP_VTABLE = 0x010158B4
BGSSAVEFORMBUFFER_VTABLE = 0x01082308
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

def entry_for(addr_int):
	func = func_for(addr_int)
	if func is None:
		return None
	return func.getEntryPoint().getOffset()

def read_u32(addr_int):
	try:
		return mem.getInt(toAddr(addr_int)) & 0xffffffff
	except:
		return None

def decompile_at(addr_int, label, max_len=16000):
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
				tgt_func = func_for(tgt)
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name_for_func(tgt_func)))
				count += 1
				if count >= limit:
					write("  ... (truncated at %d)" % limit)
					write("  Total printed: %d" % count)
					return
	write("  Total printed: %d" % count)

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly %s around 0x%08x" % (label, center_int))
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
		marker = " << CRASH" if off == center_int else ""
		write("  0x%08x: %-42s%s" % (off, inst.toString(), marker))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (target, name_for_func(func_for(target))))
		inst = inst.getNext()
		idx += 1

def print_function_range(addr_int, label):
	func = func_for(addr_int)
	write("")
	write("-" * 70)
	write("Function range for %s @ 0x%08x" % (label, addr_int))
	write("-" * 70)
	if func is None:
		write("  [function not found]")
		return
	write("  %s entry=0x%08x size=%d" % (func.getName(), func.getEntryPoint().getOffset(), func.getBody().getNumAddresses()))

def print_vtable(vtable_addr, label, slots):
	write("")
	write("=" * 70)
	write("%s vtable @ 0x%08x" % (label, vtable_addr))
	write("=" * 70)
	idx = 0
	while idx < slots:
		entry_addr = vtable_addr + idx * 4
		target = read_u32(entry_addr)
		if target is None:
			write("  [%02d] 0x%08x: [unreadable]" % (idx, entry_addr))
		else:
			write("  [%02d] 0x%08x -> 0x%08x %s" % (idx, entry_addr, target, name_for_func(func_for(target))))
		idx += 1

def print_vtable_calls(vtable_addr, label, slots):
	idx = 0
	while idx < slots:
		target = read_u32(vtable_addr + idx * 4)
		if target is not None:
			find_and_print_calls_from(target, "%s slot %02d" % (label, idx), 40)
		idx += 1

def decompile_matching_vtable_slots(vtable_addr, label, slots, interesting_entries):
	idx = 0
	while idx < slots:
		target = read_u32(vtable_addr + idx * 4)
		if target is not None:
			entry = entry_for(target)
			if entry is not None and entry in interesting_entries:
				decompile_at(target, "%s slot %02d candidate" % (label, idx), 14000)
		idx += 1

def print_calltrace_context():
	write("")
	write("# CrashLogger facts")
	write("  Fault: EIP=0x00865DFB, EAX=0x00000007")
	write("  ECX/ESI: BGSSaveFormBuffer vtable 0x01082308")
	write("  EDX: ExtraOwnership vtable 0x010158B4")
	write("  Extra type on stack: 0x21")
	write("  Ref context: Famine Box / PWBFamineBoxREF / Famine.esp")
	write("")
	write("# Calltrace")
	write("  0x00865DFB")
	write("  0x004BEDCC")
	write("  0x004D4112")
	write("  0x00562305")
	write("  0x00847B99")
	write("  0x008505C0")
	write("  0x00850A81")
	write("  0x00851DFE")
	write("  0x0086E83B")
	write("  0x0086B3E8")

def analyze_calltrace():
	targets = [
		(0x00865DFB, "Fault site"),
		(0x0086601C, "Nearby stack return"),
		(0x004BEDCC, "Caller 1"),
		(0x004D4112, "Caller 2"),
		(0x00562305, "Caller 3"),
		(0x00847B99, "Save/menu caller"),
		(0x008505C0, "Save/menu caller"),
		(0x00850A81, "Save/menu caller"),
		(0x00851DFE, "Save/menu caller"),
		(0x0086E83B, "Main loop caller"),
		(0x0086B3E8, "NVSE main loop hookpoint")
	]
	idx = 0
	while idx < len(targets):
		item = targets[idx]
		print_function_range(item[0], item[1])
		idx += 1
	disasm_window(0x00865DFB, 24, 40, "fault site")
	decompile_at(0x00865DFB, "Fault site containing function", 18000)
	find_and_print_calls_from(0x00865DFB, "Fault site containing function")
	fault_entry = entry_for(0x00865DFB)
	if fault_entry is not None:
		find_refs_to(fault_entry, "fault function entry")
	disasm_window(0x004BEDCC, 24, 36, "caller 1")
	decompile_at(0x004BEDCC, "Caller 1", 18000)
	find_and_print_calls_from(0x004BEDCC, "Caller 1")
	decompile_at(0x004D4112, "Caller 2", 18000)
	decompile_at(0x00562305, "Caller 3", 18000)

def analyze_vtables():
	print_vtable(EXTRA_OWNERSHIP_VTABLE, "ExtraOwnership", 18)
	print_vtable(BGSSAVEFORMBUFFER_VTABLE, "BGSSaveFormBuffer", 18)
	find_refs_to(EXTRA_OWNERSHIP_VTABLE, "ExtraOwnership vtable")
	find_refs_to(BGSSAVEFORMBUFFER_VTABLE, "BGSSaveFormBuffer vtable")
	print_vtable_calls(EXTRA_OWNERSHIP_VTABLE, "ExtraOwnership", 18)
	interesting = []
	entry = entry_for(0x004BEDCC)
	if entry is not None:
		interesting.append(entry)
	decompile_matching_vtable_slots(EXTRA_OWNERSHIP_VTABLE, "ExtraOwnership", 18, interesting)

def main():
	write("=" * 70)
	write("EXTRAOWNERSHIP SAVE CRASH 0x00865DFB")
	write("=" * 70)
	write("Goal: identify the exact save-form writer and the ExtraOwnership virtual method")
	write("so the runtime fix can skip or clear invalid owner pointers at the boundary.")
	print_calltrace_context()
	analyze_calltrace()
	analyze_vtables()
	outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/crash_00865dfb_extraownership_save_audit.txt"
	fout = open(outpath, "w")
	fout.write("\n".join(output))
	fout.close()
	write("Output written to %s (%d lines)" % (outpath, len(output)))
	decomp.dispose()

main()
