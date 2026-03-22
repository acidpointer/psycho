# @category Analysis
# @description Trace EXACT timeline of cell frees during fast travel
#
# During fast travel, the game:
# 1. Opens loading screen (sets DAT_011dea2b)
# 2. Runs CellTransitionHandler (FUN_008774a0)
# 3. Unloads old cells (FUN_00462290 etc)
# 4. Loads new cells
# 5. Closes loading screen (clears DAT_011dea2b)
# 6. Returns to main loop
# 7. NVSE MainLoopHook fires (JIP processes events)
#
# The question: at step 7, are the old cells' forms still in quarantine?
# Or have they been freed by quarantine drain / emergency flush?
#
# Also: does the game call GameHeap::Free on cell/actor forms during
# step 2-3? If so, those frees go through our quarantine.
# When does quarantine drain them?

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


write("=" * 70)
write("FAST TRAVEL CELL FREE TIMELINE")
write("=" * 70)

# SECTION 1: FUN_0086a850 - the outer loop
# The fast travel flow goes through this function
# CellTransitionHandler is called from FUN_0086a850
write("")
write("# SECTION 1: Where does FUN_0086a850 call CellTransitionHandler?")
write("# And where does NVSE MainLoopHook fire relative to it?")
write("# Disasm around the CellTransition call")
# From comprehensive analysis: CellTransitionHandler called from FUN_0086a850
# NVSE hook at 0x00ECC470 is AFTER FUN_0086a850 returns
disasm_range(0x0086E880, 20)

# SECTION 2: Where does the loading flag get SET during fast travel?
# DAT_011dea2b is set at 0x0086e6e1 in FUN_0086e650
write("")
write("# SECTION 2: Loading flag (DAT_011dea2b) set/clear during fast travel")
write("# Where in the main loop iteration is it set? Before or after CellTransition?")
disasm_range(0x0086E6D0, 15)

# SECTION 3: FUN_00453a70 - called early in CellTransitionHandler
# What does it do? Cell grid reset?
write("")
write("# SECTION 3: FUN_00453a70 - called at start of CellTransition")
decompile_at(0x00453A70, "CellGridReset")

# SECTION 4: The loading screen loop - does it run our per-frame hooks?
# During loading, does FUN_0086e650 (per-frame) run? Or is there a
# separate loading screen loop?
write("")
write("# SECTION 4: Is there a loading screen loop?")
write("# FUN_0086a850 is the outer loop. Does it have an inner loop for loading?")
write("# Disasm near cell loading area")
disasm_range(0x0086B300, 20)

# SECTION 5: FUN_00c459d0 - Havok GC called in CellTransition
# Does this call GameHeap::Free?
write("")
write("# SECTION 5: FUN_00c459d0 - Havok GC")
decompile_at(0x00C459D0, "HavokGC")
find_calls_from(0x00C459D0, "HavokGC")

# SECTION 6: When does DAT_011dea2b get CLEARED after fast travel?
# This determines when our quarantine starts draining again
write("")
write("# SECTION 6: When is loading flag cleared?")
write("# Search for writes to DAT_011dea2b that clear it")
disasm_range(0x0086E7C0, 15)

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/fast_travel_cell_free_timeline.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
