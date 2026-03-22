# @category Analysis
# @description Deep research: JIP CellChange crash - what EXACTLY is the stale ref?
#
# Crash: InternalFunctionCaller::PopulateArgs during LN_ProcessEvents
# Script: nvseRuntimeScript260CellChange (SetOnCellChangeHandler)
# Actor: "Boop" (3DNPC follower, High process, SAME cell as player)
#
# The crash is NOT about Boop being in an unloaded cell - Boop is in the
# player's CURRENT cell. The crash is in PopulateArgs accessing a stale
# SCRIPT VARIABLE or FUNCTION PARAMETER.
#
# Need to find:
# 1. What does 0x0094CB35 hook actually pass to the CellChange handler?
# 2. What arguments does CallFunction pass to the script?
# 3. What does PopulateArgs read at the crash point?
# 4. Is the stale ref the OLD CELL (lastCell) or something else?
# 5. Does the game free cells during fast travel BEFORE NVSE fires events?
# 6. What is the exact order: fast travel load -> cell free -> NVSE hook?

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
write("JIP CellChange STALE REF DEEP ANALYSIS")
write("=" * 70)

# SECTION 1: The PCCellChange hook at 0x94CB35
# What game function does it hook? What cell transition does it detect?
write("")
write("# SECTION 1: Game function containing 0x94CB35")
write("# This is where JIP hooks PCCellChangeHook")
disasm_range(0x0094CB00, 25)

# SECTION 2: FUN_0094dba0 - the original function JIP replaces
# This is the CALL target at 0x94CB35 before JIP hooks it
write("")
write("# SECTION 2: FUN_0094dba0 - original target replaced by JIP")
decompile_at(0x0094DBA0, "OrigPCCellCheck")

# SECTION 3: The fast travel flow - what happens to cells?
# FUN_008774a0 = CellTransitionHandler. Does it free old cells
# BEFORE or AFTER returning to the main loop?
write("")
write("# SECTION 3: FUN_008774a0 - CellTransitionHandler internals")
write("# Does it free old cells? When relative to returning?")
find_calls_from(0x008774A0, "CellTransitionHandler")

# SECTION 4: What does FUN_004539a0 do? Called in CellTransitionHandler
# and in OOM Stage 5. Does it free cells?
write("")
write("# SECTION 4: FUN_004539a0 - cell grid management")
decompile_at(0x004539A0, "CellGridManage")

# SECTION 5: FUN_00868d70 - PDD (purge deferred delete)
# Called in CellTransitionHandler. Does it free actor forms?
write("")
write("# SECTION 5: FUN_00868d70 - purge deferred delete queue")
decompile_at(0x00868D70, "PurgeDeferredDelete")
find_calls_from(0x00868D70, "PurgeDeferredDelete")

# SECTION 6: The main loop position of NVSE MainLoopHook
# 0x00ECC470 - what happens between CellTransition end and NVSE hook?
write("")
write("# SECTION 6: Main loop around 0x00ECC470 (NVSE hook)")
disasm_range(0x00ECC450, 20)

# SECTION 7: FUN_0086a850 - the outer loop that contains
# both cell transitions and the NVSE hook point
write("")
write("# SECTION 7: What calls CellTransitionHandler?")
find_xrefs_to(0x008774A0, "CellTransitionHandler_callers")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/jip_cellchange_stale_ref.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
