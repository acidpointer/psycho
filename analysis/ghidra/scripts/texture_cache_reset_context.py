# @category Analysis
# @description Research FUN_00a62090 call context + FUN_00445670 cell task cancellation

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=15000):
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
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

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
	listing = currentProgram.getListing()
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

def find_xrefs_to(addr_int, label, limit=25):
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
			break
	write("  Total: %d refs" % count)

def disasm_range(start_int, count=30):
	listing = currentProgram.getListing()
	inst = listing.getInstructionAfter(toAddr(start_int - 1))
	for i in range(count):
		if inst is None:
			break
		write("  0x%08x: %s" % (inst.getAddress().getOffset(), inst.toString()))
		inst = inst.getNext()


write("=" * 70)
write("TEXTURE CACHE RESET CONTEXT + CELL TASK CANCELLATION")
write("=" * 70)

# PART 1: FUN_0086a850 — the outer update function
# This is HUGE. We need to see WHERE FUN_00a62090 is called.
# The call is at 0x0086b976. What condition gates it?
write("")
write("#" * 70)
write("# PART 1: FUN_0086a850 — where/when is TextureCache_Reset called?")
write("# Disasm around the call site at 0x0086b976")
write("#" * 70)

write("")
write("Disasm around TextureCache_Reset call (0x0086b976):")
disasm_range(0x0086b940, 30)

# Also show broader context
write("")
write("Broader context (0x0086b900):")
disasm_range(0x0086b900, 50)

# PART 2: FUN_00445670 — cell-specific task cancellation
# Called from CellState_Change with (DAT_011c3b3c, cell)
write("")
write("#" * 70)
write("# PART 2: FUN_00445670 — cancel tasks for specific cell")
write("#" * 70)

decompile_at(0x00445670, "CancelCellTasks")
find_calls_from(0x00445670, "CancelCellTasks")
find_xrefs_to(0x00445670, "CancelCellTasks_callers")

# PART 3: FUN_00c5ba50 — called multiple times from CellState_Change
# with different object types from the cell
write("")
write("#" * 70)
write("# PART 3: FUN_00c5ba50 — IO task cleanup for cell objects")
write("#" * 70)

decompile_at(0x00C5BA50, "IOTask_CellCleanup")
find_calls_from(0x00C5BA50, "IOTask_CellCleanup")
find_xrefs_to(0x00C5BA50, "IOTask_CellCleanup_callers")

# PART 4: FUN_00a62030 — called at START of TextureCache_Reset
# Before destroying the hash table, what does it do?
write("")
write("#" * 70)
write("# PART 4: FUN_00a62030 — pre-reset cleanup")
write("#" * 70)

decompile_at(0x00A62030, "TextureCache_PreReset")

# PART 5: FUN_00a615c0 — cleanup function called on hash table
write("")
write("#" * 70)
write("# PART 5: FUN_00a615c0 — hash table cleanup")
write("#" * 70)

decompile_at(0x00A615C0, "HashTable_Cleanup")

# PART 6: FUN_00557c40 — called from CellState_Change
# Early in the cell state change process
write("")
write("#" * 70)
write("# PART 6: FUN_00557c40 — early cell cleanup")
write("#" * 70)

decompile_at(0x00557C40, "CellEarlyCleanup")
find_calls_from(0x00557C40, "CellEarlyCleanup")

# PART 7: FUN_0086a850 FULL decompilation — the outer update
# This is the function that contains CellTransitionHandler call AND
# TextureCache_Reset call. We need the full flow.
write("")
write("#" * 70)
write("# PART 7: FUN_0086a850 — outer update (contains CellTransition + Reset)")
write("#" * 70)

decompile_at(0x0086A850, "OuterUpdate_Full", 20000)
find_calls_from(0x0086A850, "OuterUpdate_Full")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/texture_cache_reset_context.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
