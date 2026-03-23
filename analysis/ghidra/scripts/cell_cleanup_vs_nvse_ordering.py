# @category Analysis
# @description Determine EXACT ordering of cell cleanup vs NVSE dispatch
# during fast travel. The crash happens because ScriptEventList is
# destroyed during cell cleanup, then NVSE dispatch reads it.
# Need to find: can we reorder these? Can we hook between them?
# Key: FUN_00574400 (ScriptCleanup) and FUN_00573f40 are called from
# specific places. NVSE fires at 0x0086b3e3. What's between?

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

output = []

def write(msg):
	output.append(msg)
	print(msg)

def decompile_at(addr_int, label, max_len=12000):
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
			write("  ... (truncated at %d)" % limit)
			break
	write("  Total: %d refs" % count)


write("=" * 70)
write("CELL CLEANUP vs NVSE DISPATCH ORDERING")
write("Root cause: ScriptEventList destroyed during cell cleanup,")
write("then NVSE dispatch accesses it. Need to fix the engine lifecycle.")
write("=" * 70)

# =====================================================================
# PART 1: Who calls FUN_00574400 (ScriptCleanup)?
# This is the recursive function that destroys references/scripts.
# Understanding callers tells us WHEN cleanup runs.
# =====================================================================
write("")
write("#" * 70)
write("# PART 1: FUN_00574400 callers — when does script cleanup run?")
write("#" * 70)

find_xrefs_to(0x00574400, "ScriptCleanup_callers", 15)

# =====================================================================
# PART 2: Who calls FUN_00573f40 (second cleanup function)?
# =====================================================================
write("")
write("#" * 70)
write("# PART 2: FUN_00573f40 callers")
write("#" * 70)

find_xrefs_to(0x00573f40, "ScriptCleanup2_callers", 15)

# =====================================================================
# PART 3: FUN_005A8BC0 — the game's ScriptEventList destructor
# Called by NVSE's DeleteEventList. Who else calls it?
# This is what actually frees the event list memory.
# =====================================================================
write("")
write("#" * 70)
write("# PART 3: FUN_005a8bc0 — ScriptEventList destructor")
write("#" * 70)

decompile_at(0x005a8bc0, "ScriptEventList_GameDtor")
find_calls_from(0x005a8bc0, "ScriptEventList_GameDtor")
find_xrefs_to(0x005a8bc0, "ScriptEventList_GameDtor_callers", 15)

# =====================================================================
# PART 4: FUN_00579ac0 — called at the END of ScriptCleanup_574400
# line 962: FUN_00579ac0(param_1, '\0')
# Does this finalize the reference? Does it trigger NVSE notifications?
# =====================================================================
write("")
write("#" * 70)
write("# PART 4: FUN_00579ac0 — finalize reference after cleanup")
write("#" * 70)

decompile_at(0x00579ac0, "FinalizeRef_579ac0")
find_calls_from(0x00579ac0, "FinalizeRef_579ac0")

# =====================================================================
# PART 5: The per-frame PDD caller FUN_004556d0
# Does it call ScriptCleanup? Does it modify script data?
# This runs at Phase 4 of the inner loop.
# =====================================================================
write("")
write("#" * 70)
write("# PART 5: Does per-frame PDD (FUN_004556d0) call script cleanup?")
write("#" * 70)

# Check if FUN_004556d0 calls FUN_00574400 or FUN_00573f40
# Already have decompile from earlier, just check calls
find_xrefs_to(0x004556d0, "PerFramePDD_callers", 10)

# =====================================================================
# PART 6: FUN_005dc960 — called at the VERY END of the outer loop
# iteration at 0x0086b63c. What does it do?
# This runs AFTER the loading path JMP to 0x0086b636.
# =====================================================================
write("")
write("#" * 70)
write("# PART 6: FUN_005dc960 — end of outer loop iteration")
write("#" * 70)

decompile_at(0x005dc960, "OuterLoop_EndCall")
find_calls_from(0x005dc960, "OuterLoop_EndCall")

# =====================================================================
# PART 7: Where EXACTLY in the outer loop does the loading path
# rejoin the normal path? After fast travel loading completes,
# what code runs before the next CALL to FUN_0086e650 (inner loop)?
# This is the gap where script cleanup has happened but NVSE hasn't
# dispatched yet.
# =====================================================================
write("")
write("#" * 70)
write("# PART 7: Loading path → normal path transition")
write("# After 0x0086b636, what runs before 0x0086b3e3 (inner loop)?")
write("#" * 70)

# From disasm: 0x0086b636 is a JMP target. Let's see what's there.
# 0x0086b636: MOV ECX,[0x011dea0c]; CALL FUN_005dc960
# Then the loop iterates back. The loop head is somewhere before 0x0086b350.

# FUN_00446e10 — called at 0x0086b58a and 0x0086b421
# This seems to be a "should we render/update" check
decompile_at(0x00446e10, "ShouldUpdate_Check")

# =====================================================================
# PART 8: FUN_00452580 — called from FUN_0086f940 (early frame)
# This creates QueuedCharacter tasks. It's called during the first
# frame after fast travel. Does it access script data?
# =====================================================================
write("")
write("#" * 70)
write("# PART 8: FUN_00452580 — creates queued tasks (early frame)")
write("#" * 70)

decompile_at(0x00452580, "CreateQueuedTasks_452580")
find_calls_from(0x00452580, "CreateQueuedTasks_452580")

# =====================================================================
# PART 9: Critical section / synchronization primitives
# used by script system. DAT_011cacf8 from FUN_005aa720.
# FUN_004538a0 / FUN_004538c0 — Enter/LeaveCriticalSection wrappers
# =====================================================================
write("")
write("#" * 70)
write("# PART 9: Script system critical section")
write("#" * 70)

decompile_at(0x004538a0, "EnterScriptCS")
decompile_at(0x004538c0, "LeaveScriptCS")
find_xrefs_to(0x004538a0, "EnterScriptCS_callers", 15)

# =====================================================================
# PART 10: FUN_00576760 — called from ScriptCleanup_574400 line 833
# What does this do to the reference's script data?
# =====================================================================
write("")
write("#" * 70)
write("# PART 10: FUN_00576760 — script data detach during cleanup")
write("#" * 70)

decompile_at(0x00576760, "ScriptDetach_576760")
find_calls_from(0x00576760, "ScriptDetach_576760")


# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/cell_cleanup_vs_nvse_ordering.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
