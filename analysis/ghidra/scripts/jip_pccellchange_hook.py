# @category Analysis
# @description Research JIP PCCellChange hook at 0x94CB35 and player cell detection
#
# JIP hooks at 0x94CB35 to detect player cell changes.
# When g_thePlayer->parentCell changes, JIP fires CellChange events.
# Our loading counter (DAT_01202D6C) does NOT suppress this.
# Need to understand:
# 1. Where does 0x94CB35 run in the main loop timeline?
# 2. Is it before or after our cell unloading?
# 3. What game function does it hook?
# 4. Does our cell unload change g_thePlayer->parentCell?

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


write("=" * 70)
write("JIP PCCellChange HOOK RESEARCH")
write("=" * 70)

# SECTION 1: What is at 0x94CB35? What function does JIP hook?
write("")
write("# SECTION 1: 0x94CB35 - JIP hooks CALL at this address")
disasm_range(0x0094CB20, 20)

# SECTION 2: Function containing 0x94CB35
write("")
write("# SECTION 2: Function containing the hook point")
decompile_at(0x0094CB35, "PCCellChange_HookPoint")

# SECTION 3: Where in the main loop is this function called?
# Trace callers
write("")
write("# SECTION 3: Who calls the function containing 0x94CB35?")
func = fm.getFunctionContaining(toAddr(0x0094CB35))
if func is not None:
	entry = func.getEntryPoint().getOffset()
	write("  Hook is in: %s @ 0x%08x" % (func.getName(), entry))
	refs = getReferencesTo(func.getEntryPoint())
	count = 0
	for ref in refs:
		from_addr = ref.getFromAddress()
		caller = fm.getFunctionContaining(from_addr)
		cname = caller.getName() if caller else "???"
		write("  %s @ 0x%s (in %s)" % (ref.getReferenceType(), from_addr, cname))
		count += 1
		if count >= 10:
			break
	write("  Total: %d refs" % count)

# SECTION 4: Does FindCellToUnload change g_thePlayer->parentCell?
# g_thePlayer is at DAT_011dea3c+... actually PlayerCharacter is different
# g_thePlayer is a global pointer. When we unload a cell, does the
# player's parentCell change? Normally NO - we only unload OTHER cells.
write("")
write("# SECTION 4: g_thePlayer parentCell - offset in PlayerCharacter")
write("# 0x011dea3c = TES singleton, not player")
write("# Look for player singleton pointer")
disasm_range(0x0094CB20, 10)

# SECTION 5: FUN_00453a80 (FindCellToUnload) - does it skip player cell?
# Already decompiled before, but let's check the key guard functions
write("")
write("# SECTION 5: FUN_004511e0 - cell unload eligibility check")
decompile_at(0x004511E0, "CellUnloadEligible")

write("")
write("# SECTION 5b: FUN_00557090 - second eligibility check")
decompile_at(0x00557090, "CellUnloadCheck2")

# SECTION 6: What does FUN_00462290 do after FindCellToUnload finds a cell?
# This is called with local_8 (the cell to unload)
write("")
write("# SECTION 6: FUN_00462290 - cell unload execution")
decompile_at(0x00462290, "CellUnloadExecute")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/jip_pccellchange_hook.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
