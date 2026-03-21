# @category Analysis
# @description Research how JIP LN NVSE detects cell changes for LN_ProcessEvents
#
# Crash: InternalFunctionCaller::PopulateArgs during fast travel
# JIP fires nvseRuntimeScript260CellChange for actors in unloaded cells
# Need to find what game state JIP checks to detect cell change,
# and what flag we can set to prevent event dispatch during our unload.
#
# Also research: how does the game's own cell unload (during loading screens)
# avoid this issue? What state prevents NVSE event dispatch during loading?

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

def find_xrefs_to(addr_int, label, limit=15):
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
write("NVSE CELL CHANGE EVENT DISPATCH RESEARCH")
write("=" * 70)

# SECTION 1: NVSE MainLoopHook position in the main loop
write("")
write("# SECTION 1: NVSE MainLoopHook at 0x00ECC470")
write("# Where in the main loop does this run?")
disasm_range(0x00ECC450, 20)
find_xrefs_to(0x00ECC470, "MainLoopHook_addr")

# SECTION 2: The main loop structure around our hooks and NVSE hooks
write("")
write("# SECTION 2: Main loop (FUN_0086e650) - key positions")
write("# Find where 0x00ECC470 is called relative to AI_START/RENDER/AI_JOIN")

# Disasm the main loop top
disasm_range(0x0086E650, 25)

# Disasm around AI_START (0x0086ec87)
write("")
write("Main loop around AI_START (0x0086ec87):")
disasm_range(0x0086EC70, 15)

# Disasm around AI_JOIN (0x0086ee4e)
write("")
write("Main loop around AI_JOIN (0x0086ee4e):")
disasm_range(0x0086EE30, 15)

# SECTION 3: FindCellToUnload - what cells does it return?
write("")
write("# SECTION 3: FUN_00453a80 - FindCellToUnload")
write("# Does it check for actors with active processes?")
decompile_at(0x00453A80, "FindCellToUnload")

# SECTION 4: How does the game handle actor refs during cell unload?
write("")
write("# SECTION 4: Actor detach during cell state change")
write("# FUN_0054a070 - cell detach? check what it does with actors")
decompile_at(0x0054A070, "CellDetach_area")

# SECTION 5: DAT_011dea2b during fast travel
write("")
write("# SECTION 5: What sets DAT_011dea2b during fast travel?")
write("# If we set it before our unload and clear after,")
write("# would NVSE hooks skip event dispatch?")
# NVSE MainLoopHook checks game state before dispatching
# Find what conditions HandleMainLoopHook checks
disasm_range(0x0086E770, 25)

# SECTION 6: PLChangeEvent - how does the game fire cell change events?
write("")
write("# SECTION 6: PLChangeEvent dispatch mechanism")
write("# DAT_01202d6c (loading counter) suppresses these")
write("# Does JIP use the same mechanism or its own?")
find_xrefs_to(0x01202D6C, "LoadingStateCounter")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/nvse_cell_change_event.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
