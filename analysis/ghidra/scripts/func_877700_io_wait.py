# @category Analysis
# @description Research FUN_00877700 - called by CellTransitionHandler before cell work
# This is the function we're MISSING in our pressure relief path.
# Also research FUN_00453a70 (different from FindCellToUnload 0x00453a80)

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=10000):
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
write("FUN_00877700 ANALYSIS - THE MISSING FUNCTION")
write("=" * 70)
write("")
write("CellTransitionHandler calls FUN_00877700(DAT_011dea3c) FIRST")
write("before any cell unloading. Our pressure relief SKIPS this.")
write("This likely waits for BSTaskManagerThread to finish pending")
write("ExteriorCellLoaderTasks.")

# SECTION 1: FUN_00877700 - the critical missing function
write("")
write("#" * 70)
write("# SECTION 1: FUN_00877700 - full decompile + call graph")
write("#" * 70)

decompile_at(0x00877700, "FUN_00877700_CriticalMissing", 15000)
find_xrefs_to(0x00877700, "FUN_00877700")
find_xrefs_from(0x00877700, "FUN_00877700")

# SECTION 2: FUN_00453a70 vs FUN_00453a80 (FindCellToUnload)
write("")
write("#" * 70)
write("# SECTION 2: FUN_00453a70 (CellTransition uses) vs")
write("# FUN_00453a80 (FindCellToUnload - we use)")
write("#" * 70)

decompile_at(0x00453A70, "FUN_00453a70_CellTransitionPrep")
find_xrefs_to(0x00453A70, "FUN_00453a70")

# SECTION 3: All functions called by FUN_00877700
# Decompile each callee to understand the full sync mechanism
write("")
write("#" * 70)
write("# SECTION 3: Subcalls of FUN_00877700 (deep dive)")
write("#" * 70)

# FUN_008776e0 - called at end of CellTransitionHandler too
decompile_at(0x008776E0, "FUN_008776e0_CellTransition_End")
find_xrefs_to(0x008776E0, "FUN_008776e0")

# SECTION 4: FUN_004539a0 - called by CellTransitionHandler
write("")
write("#" * 70)
write("# SECTION 4: FUN_004539a0 - CellTransition cell grid management")
write("#" * 70)

decompile_at(0x004539A0, "FUN_004539a0_CellGridManage")

# SECTION 5: FUN_0045ac80 - called near end of CellTransitionHandler
write("")
write("#" * 70)
write("# SECTION 5: FUN_0045ac80 - CellTransition late stage")
write("#" * 70)

decompile_at(0x0045AC80, "FUN_0045ac80_CellTransition_Late")
find_xrefs_from(0x0045AC80, "FUN_0045ac80")

# SECTION 6: FUN_005283c0 - creates ExteriorCellLoaderTask
write("")
write("#" * 70)
write("# SECTION 6: FUN_005283c0 - creates ExteriorCellLoaderTask")
write("# (only caller of ExteriorCellLoader constructor)")
write("#" * 70)

decompile_at(0x005283C0, "CreateExteriorCellLoaderTask", 10000)
find_xrefs_to(0x005283C0, "CreateExteriorCellLoaderTask")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/func_877700_io_wait.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
