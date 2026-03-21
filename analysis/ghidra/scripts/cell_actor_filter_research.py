# @category Analysis
# @description Research how to filter cells by actor process level for safe unloading
#
# NVSE crashes when we unload cells with High-process actors.
# Need to find: cell actor list, actor process level check.
# Goal: only unload cells where ALL actors are Low/None process.
#
# Also research: what does HeapCompact Stage 2 actually reclaim?
# And: what does FUN_00462290 (cell unload exec) do with actors?

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)
listing = currentProgram.getListing()

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=6000):
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
	entry = func.getEntryPoint().getOffset()
	sz = func.getBody().getNumAddresses()
	write("  Function: %s, Size: %d bytes" % (func.getName(), sz))
	write("  Entry: 0x%08x" % entry)
	result = decomp.decompileFunction(func, 60, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def disasm_range(start_int, count=25):
	inst = listing.getInstructionAt(toAddr(start_int))
	if inst is None:
		inst = listing.getInstructionAfter(toAddr(start_int - 1))
	for i in range(count):
		if inst is None:
			break
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()

def find_xrefs_to(addr_int, label, limit=10):
	addr = toAddr(addr_int)
	refs = getReferencesTo(addr)
	write("")
	write("--- XRefs to %s (0x%08x) ---" % (label, addr_int))
	count = 0
	for ref in refs:
		from_addr = ref.getFromAddress()
		func = fm.getFunctionContaining(from_addr)
		fname = func.getName() if func else "???"
		write("  %s @ 0x%s (in %s)" % (ref.getReferenceType(), from_addr, fname))
		count += 1
		if count >= limit:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

def find_calls_from(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	if func is None:
		write("  [function not found]")
		return
	body = func.getBody()
	addr_iter = body.getAddresses(True)
	count = 0
	while addr_iter.hasNext():
		a = addr_iter.next()
		inst = listing.getInstructionAt(a)
		if inst is None:
			continue
		if not inst.getFlowType().isCall():
			continue
		refs_from = inst.getReferencesFrom()
		for r in refs_from:
			target = r.getToAddress().getOffset()
			target_func = fm.getFunctionAt(toAddr(target))
			target_name = target_func.getName() if target_func else "unknown_0x%08x" % target
			write("  CALL 0x%08x -> %s (from 0x%08x)" % (target, target_name, a.getOffset()))
			count += 1
	write("  Total: %d calls" % count)


write("=" * 70)
write("CELL ACTOR FILTER + HEAPCOMPACT EFFECTIVENESS RESEARCH")
write("=" * 70)

# SECTION 1: FUN_004511e0 - cell unload eligibility (already have, but need FUN_00450fd0)
write("")
write("# SECTION 1: FUN_00450fd0 - cell state check (called by eligibility)")
decompile_at(0x00450FD0, "CellStateCheck")

# SECTION 2: TESObjectCELL actor list - how to iterate actors in a cell
# Cell+0x80 area seems important (FUN_00557090 checks cell+0x80)
write("")
write("# SECTION 2: FUN_005570b0 - cell reference list check")
decompile_at(0x005570B0, "CellRefListCheck")

# SECTION 3: How does the game check actor process level?
# Process levels: None=0, Low=1, MiddleLow=2, MiddleHigh=3, High=4
# Actor+0x108 or similar offset holds the process manager
write("")
write("# SECTION 3: FUN_009611e0 - get actor process level?")
decompile_at(0x009611E0, "GetActorProcess")

# SECTION 4: TESObjectCELL structure - where is the actor/ref list?
# FUN_00551620 iterates refs in cell (called by FUN_00462290)
write("")
write("# SECTION 4: FUN_00551620 - iterate cell references")
decompile_at(0x00551620, "CellIterateRefs")

# SECTION 5: FUN_00551480 - process single ref during cell detach
write("")
write("# SECTION 5: FUN_00551480 - detach single ref from cell")
decompile_at(0x00551480, "CellDetachRef")

# SECTION 6: HeapCompact stages - what does Stage 2 actually free?
# FUN_00878080 runs HeapCompact. Stage 2 = BSA/texture cleanup.
write("")
write("# SECTION 6: FUN_00878080 - HeapCompact stages")
decompile_at(0x00878080, "HeapCompact")
find_calls_from(0x00878080, "HeapCompact")

# SECTION 7: How does the game's OWN cell unload during loading differ?
# CellTransitionHandler at FUN_008774a0 - what makes it safe?
write("")
write("# SECTION 7: FUN_008774a0 - CellTransitionHandler")
write("# This runs during loading screens where NVSE is inactive")
decompile_at(0x008774A0, "CellTransitionHandler")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/cell_actor_filter_research.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
