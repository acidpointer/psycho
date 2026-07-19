# @category Analysis
# @description Audit the LOD stress-test BSTree destruction invariant and distant-tree task ownership

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=8000):
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
	result = decomp.decompileFunction(func, 120, monitor)
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
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
		if count > 40:
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
	inst_iter = currentProgram.getListing().getInstructions(body, True)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				write("  0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
	write("  Total: %d calls" % count)

def function_for(addr_int):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	return func

def function_name(addr_int):
	func = function_for(addr_int)
	if func is None:
		return "???"
	return "%s @ 0x%08x" % (func.getName(), func.getEntryPoint().getOffset())

def read_u32(addr_int):
	try:
		return memory.getInt(toAddr(addr_int)) & 0xffffffff
	except:
		return None

def disasm_window(center_int, before_count, after_count, label):
	write("")
	write("-" * 70)
	write("Disassembly around 0x%08x (%s)" % (center_int, label))
	write("-" * 70)
	inst = listing.getInstructionContaining(toAddr(center_int))
	if inst is None:
		inst = listing.getInstructionBefore(toAddr(center_int))
	count = 0
	while inst is not None and count < before_count:
		previous = inst.getPrevious()
		if previous is None:
			break
		inst = previous
		count += 1
	index = 0
	limit = before_count + after_count + 1
	while inst is not None and index < limit:
		address = inst.getAddress().getOffset()
		marker = " << FOCUS" if address == center_int else ""
		write("  0x%08x: %-48s%s" % (address, inst.toString(), marker))
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				target = ref.getToAddress().getOffset()
				write("      call -> 0x%08x %s" % (target, function_name(target)))
		inst = inst.getNext()
		index += 1

def print_vtable(vtable_addr, label, slot_count):
	write("")
	write("=" * 70)
	write("%s vtable @ 0x%08x" % (label, vtable_addr))
	write("=" * 70)
	index = 0
	while index < slot_count:
		entry_addr = vtable_addr + index * 4
		target = read_u32(entry_addr)
		if target is None:
			write("  [%02d] +0x%02x unreadable" % (index, index * 4))
		else:
			write("  [%02d] +0x%02x -> 0x%08x %s" % (index, index * 4, target, function_name(target)))
		index += 1

def decompile_vtable_slots(vtable_addr, label, slot_count, max_len):
	index = 0
	while index < slot_count:
		target = read_u32(vtable_addr + index * 4)
		if target is not None and function_for(target) is not None:
			decompile_at(target, "%s vtable slot %d (+0x%02x)" % (label, index, index * 4), max_len)
			find_and_print_calls_from(target, "%s vtable slot %d" % (label, index))
		index += 1

write("LOD BSTree crash ownership audit")
write("=" * 70)
write("Crash signature: C0000417 at 0x00EC7C62 while destroying WastelandUndergrowth01.spt")
write("Goal: identify the exact invalid SpeedTree registration erase, its owner, and whether the DTL task path shares that ownership.")

write("")
write("# PART 1: Exact crash instruction and completed-task release chain")
disasm_window(0x00B03E48, 36, 44, "SpeedTree destructor return site before CRT invalid parameter")
decompile_at(0x00B03E48, "SpeedTree core destructor")
find_and_print_calls_from(0x00B03E48, "SpeedTree core destructor")
find_refs_to(0x00B03B30, "SpeedTree core destructor entry")
decompile_at(0x00B0DF00, "SpeedTree registration container erase helper")
find_and_print_calls_from(0x00B0DF00, "SpeedTree registration container erase helper")
find_refs_to(0x00B0DF00, "SpeedTree registration container erase helper")
decompile_at(0x00B10430, "SpeedTree registration iterator constructor")
decompile_at(0x00B0ECA0, "SpeedTree iterator comparison used before one erase")
decompile_at(0x00EC7C56, "CRT invalid-parameter wrapper")

disasm_window(0x00C459AB, 24, 24, "completed-task processor")
disasm_window(0x00C45A9E, 24, 24, "completed-task array cleanup")
disasm_window(0x00C45C4B, 24, 24, "completed-task element release")
decompile_at(0x00C458F0, "per-frame completed-task processor")
decompile_at(0x00C45A80, "completed-task array cleanup")
decompile_at(0x00C45B20, "completed-task container resize and release")
decompile_at(0x00CFCC20, "virtual deleting-destructor dispatch")

write("")
write("# PART 2: BSTreeNode, BSTreeModel, and core SpeedTree ownership")
disasm_window(0x0066B68F, 12, 20, "BSTreeNode scalar destructor")
disasm_window(0x006667DF, 12, 20, "BSTreeModel scalar destructor")
disasm_window(0x00666868, 18, 26, "BSTreeModel destructor releases core object")
disasm_window(0x0066691F, 10, 18, "core SpeedTree scalar destructor")
decompile_at(0x0066B120, "BSTreeNode constructor")
decompile_at(0x0066B6C0, "BSTreeNode destructor body")
decompile_at(0x00666650, "BSTreeModel constructor")
decompile_at(0x00666800, "BSTreeModel destructor body")
decompile_at(0x00666FC0, "BSTreeModel pre-destruction cleanup")
decompile_at(0x00666910, "core SpeedTree scalar destructor")
decompile_at(0x0066B0D0, "intrusive pointer assignment helper")
find_refs_to(0x00666650, "BSTreeModel constructor")
find_refs_to(0x006667D0, "BSTreeModel scalar destructor")
find_refs_to(0x00666910, "core SpeedTree scalar destructor")
print_vtable(0x010668E4, "BSTreeNode", 12)
print_vtable(0x01066768, "BSTreeModel", 12)

write("")
write("# PART 3: BSTreeManager registration and teardown ordering")
decompile_at(0x006649D0, "BSTreeManager update and registration reader")
decompile_at(0x00664CD0, "BSTreeManager cleanup")
decompile_at(0x00665BE0, "BSTreeManager remove by key")
decompile_at(0x0043DA00, "BSTreeManager add tree")
decompile_at(0x0043DAC0, "BSTreeManager remove tree")
find_refs_to(0x00664CD0, "BSTreeManager cleanup")
find_refs_to(0x0043DA00, "BSTreeManager add tree")
find_refs_to(0x0043DAC0, "BSTreeManager remove tree")

write("")
write("# PART 4: Distant-tree LOD block and task lifetime")
decompile_at(0x006FE330, "distant-tree block demand and retirement owner")
disasm_window(0x006FE3B8, 16, 32, "tree demand predicate and create or retire branches")
decompile_at(0x006FE780, "distant-tree demand predicate")
decompile_at(0x006F7540, "distant-tree block constructor and task submission")
decompile_at(0x006F74F0, "distant-tree task submission or owner publication")
decompile_at(0x006F76B0, "distant-tree block destructor body")
decompile_at(0x006FD950, "distant-tree block scalar destructor")
decompile_at(0x006F9360, "distant-tree load-task constructor")
find_refs_to(0x006F74F0, "distant-tree task submission or owner publication")
find_refs_to(0x006F76B0, "distant-tree block destructor body")
print_vtable(0x0106DED0, "distant-tree load task", 12)
decompile_vtable_slots(0x0106DED0, "distant-tree load task", 6, 6000)

write("")
write("# PART 5: Allocation and physical-reuse boundaries")
decompile_at(0x00401000, "GameHeap allocation wrapper used by DTL and tree internals")
decompile_at(0x00401030, "GameHeap free wrapper used by tree destructors")
decompile_at(0x00AA13E0, "sized GameHeap allocation wrapper")
decompile_at(0x00AA1460, "sized GameHeap free wrapper")
find_refs_to(0x00AA4060, "GameHeap free owner")

write("")
write("ANALYSIS COMPLETE")

outpath = "/data/storage1/Workspace/psycho/analysis/ghidra/output/crash/lod_bstree_crash_ownership_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
