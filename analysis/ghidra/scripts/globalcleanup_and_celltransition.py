# @category Analysis
# @description Research FUN_00AA7030 (we RET-patched it) and CellTransitionHandler

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
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
	write("  Function: %s, Size: %d bytes" % (func.getName(), func.getBody().getNumAddresses()))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def find_xrefs_to(addr_int, label, limit=30):
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
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total: %d refs" % count)

def find_xrefs_from(addr_int, label):
	addr = toAddr(addr_int)
	func = fm.getFunctionAt(addr)
	if func is None:
		func = fm.getFunctionContaining(addr)
	if func is None:
		write("  [function not found at 0x%08x]" % addr_int)
		return
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	body = func.getBody()
	count = 0
	seen = set()
	for rng in body:
		addr_iter = rng.getMinAddress()
		while addr_iter is not None and addr_iter.compareTo(rng.getMaxAddress()) <= 0:
			refs = getReferencesFrom(addr_iter)
			for ref in refs:
				if ref.getReferenceType().isCall():
					to_addr = ref.getToAddress()
					key = str(to_addr)
					if key not in seen:
						seen.add(key)
						target_func = fm.getFunctionAt(to_addr)
						tname = target_func.getName() if target_func else "???"
						write("  CALL 0x%s -> %s" % (to_addr, tname))
						count += 1
			addr_iter = addr_iter.next()
	write("  Total unique calls: %d" % count)

write("=" * 70)
write("GLOBALCLEANUP (0x00AA7030) + CELLTRANSITIONHANDLER ANALYSIS")
write("=" * 70)
write("")
write("CRITICAL: PostDestructionRestore calls FUN_00aa7030 which we RET-patched!")
write("Also: CellTransitionHandler may cancel ExteriorCellLoaderTasks")

# SECTION 1: What does FUN_00AA7030 actually do?
write("")
write("#" * 70)
write("# SECTION 1: FUN_00AA7030 (GlobalCleanup) - we RET-patched this!")
write("# PostDestructionRestore calls it on every cell unload cycle.")
write("# What are we breaking by skipping it?")
write("#" * 70)

decompile_at(0x00AA7030, "GlobalCleanup_FUN_00AA7030", 10000)
find_xrefs_to(0x00AA7030, "GlobalCleanup")
find_xrefs_from(0x00AA7030, "GlobalCleanup")

# SECTION 2: All our RET-patched functions - what do they really do?
write("")
write("#" * 70)
write("# SECTION 2: All 7 RET-patched SBM functions")
write("#" * 70)

decompile_at(0x00AA6840, "SBM_StatsReset_0xAA6840")
decompile_at(0x00866770, "SBM_ConfigInit_0x866770")
decompile_at(0x00866E00, "SBM_RelatedInit_0x866E00")
decompile_at(0x00866D10, "SBM_GetSingleton_0x866D10")
decompile_at(0x00AA7030, "SBM_GlobalCleanup_0xAA7030", 10000)
decompile_at(0x00AA5C80, "SBM_DeallocAllArenas_0xAA5C80")
decompile_at(0x00AA58D0, "SBM_SheapCleanup_0xAA58D0")

# SECTION 3: CellTransitionHandler - full decompile
write("")
write("#" * 70)
write("# SECTION 3: CellTransitionHandler 0x008774A0")
write("# How does the GAME handle cell transitions safely?")
write("# Does it cancel ExteriorCellLoaderTasks?")
write("#" * 70)

decompile_at(0x008774A0, "CellTransitionHandler", 15000)
find_xrefs_from(0x008774A0, "CellTransitionHandler")

# SECTION 4: FUN_00a5b460 - called by PostDestructionRestore before GlobalCleanup
write("")
write("#" * 70)
write("# SECTION 4: FUN_00a5b460 - unknown function in PostDestructionRestore")
write("#" * 70)

decompile_at(0x00A5B460, "PostDestruction_Unknown_0xA5B460")

# SECTION 5: ExteriorCellLoaderTask creation and cancellation
write("")
write("#" * 70)
write("# SECTION 5: ExteriorCellLoaderTask lifecycle")
write("# FUN_00527c00 and FUN_00527c70 reference the RTTI")
write("#" * 70)

decompile_at(0x00527C00, "ExteriorCellLoader_Func1")
decompile_at(0x00527C70, "ExteriorCellLoader_Func2")

# Where are ExteriorCellLoaderTasks created?
find_xrefs_to(0x00527C00, "ExteriorCellLoader_Func1")
find_xrefs_to(0x00527C70, "ExteriorCellLoader_Func2")

# SECTION 6: FUN_00454fc0 - called by FindCellToUnload when local_8 == NULL
write("")
write("#" * 70)
write("# SECTION 6: FUN_00454fc0 - called by FindCellToUnload")
write("#" * 70)

decompile_at(0x00454FC0, "FindCell_Fallback_0x454FC0")

# SECTION 7: Does the game have a mechanism to cancel IO tasks?
write("")
write("#" * 70)
write("# SECTION 7: IOManager cancel/abort mechanism")
write("#" * 70)

decompile_at(0x00C42380, "IOManager_ProcessOrCancel_area")
decompile_at(0x00C42560, "IOManager_SecondPath")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/globalcleanup_and_celltransition.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
