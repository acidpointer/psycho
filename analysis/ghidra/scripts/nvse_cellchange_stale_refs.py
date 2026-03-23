# @category Analysis
# @description Research ALL stale pointer paths exposed by removing quarantine.
# Goal: understand the complete set of stale reference sources so we can
# fix them all with engine-level hooks. Focus areas:
# 1. NVSE MainLoopHook dispatch — what data does it access after cell change?
# 2. IOManager completed task dispatch — form data in task arguments
# 3. Per-frame PDD — what keeps references to freed objects between frames?
# 4. The game's own deferred reference system — how does vanilla handle
#    references that span cell transitions?
# 5. FUN_00451ef0 queue dispatch — does it validate forms before processing?

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
write("COMPREHENSIVE STALE REFERENCE RESEARCH")
write("Goal: Fix ALL stale pointer paths at the engine level")
write("=" * 70)

# =====================================================================
# PART 1: The game's deferred reference queue system
# DAT_011c3b3c is the task queue manager. It holds queued references.
# FUN_00444850 creates QueuedCharacter tasks.
# FUN_00445750 checks if a reference is already queued.
# How does the game track which references are queued?
# Can we intercept at the queue level to invalidate stale entries?
# =====================================================================
write("")
write("#" * 70)
write("# PART 1: Game's queued reference tracking system")
write("#" * 70)

# FUN_00445750 — checks if a reference is queued in task manager
decompile_at(0x00445750, "IsRefQueued_Check")
find_calls_from(0x00445750, "IsRefQueued_Check")

# FUN_00444850 — creates QueuedCharacter (from ctor xref)
decompile_at(0x00444850, "CreateQueuedCharacter")
find_calls_from(0x00444850, "CreateQueuedCharacter")

# FUN_004409e0 — called after QueuedCharacter processing
# This might remove the reference from the queue tracking
decompile_at(0x004409e0, "PostProcess_Cleanup")
find_calls_from(0x004409e0, "PostProcess_Cleanup")

# =====================================================================
# PART 2: FUN_0044dd60 — IOTask release (our existing hook)
# Does the game call this to CANCEL tasks, or only to release?
# Can we use this to detect when a form is being freed while
# tasks still reference it?
# =====================================================================
write("")
write("#" * 70)
write("# PART 2: FUN_0044dd60 — IOTask release semantics")
write("#" * 70)

decompile_at(0x0044dd60, "IOTask_Release_Full")
find_xrefs_to(0x0044dd60, "IOTask_Release_callers", 20)

# =====================================================================
# PART 3: FUN_00448620 — task cancellation (stale task cleanup)
# Called by DeferredCleanupSmall. What exactly does it cancel?
# Does it remove entries from the LockFreeMap?
# =====================================================================
write("")
write("#" * 70)
write("# PART 3: FUN_00448620 — task cancellation mechanism")
write("#" * 70)

decompile_at(0x00448620, "CancelStaleTasks")
find_calls_from(0x00448620, "CancelStaleTasks")
find_xrefs_to(0x00448620, "CancelStaleTasks_callers", 15)

# =====================================================================
# PART 4: LockFreeMap<TESObjectREFR*, QueuedReference>
# This is the map at 0x011c3b3c that tracks queued references.
# Understanding its structure tells us how to invalidate entries.
# =====================================================================
write("")
write("#" * 70)
write("# PART 4: LockFreeMap reference tracking structure")
write("#" * 70)

# FUN_00449f80 was GetCompletionQueue. What about the main task map?
# FUN_004489b0 — called from QueuedCharacter processing with DAT_011c3b3c
decompile_at(0x004489b0, "TaskManager_ProcessRef")
find_calls_from(0x004489b0, "TaskManager_ProcessRef")

# FUN_00449130 — early check in QueuedCharacter processing (bVar1 check)
decompile_at(0x00449130, "QueuedRef_EarlyCheck")

# =====================================================================
# PART 5: TESForm deletion lifecycle
# When a form is freed via GameHeap, what happens to references
# held by the task queue, NVSE plugins, and other subsystems?
# FUN_00440d80 checks if a form is persistent
# FUN_00440da0 checks another form flag
# =====================================================================
write("")
write("#" * 70)
write("# PART 5: TESForm deletion — who gets notified?")
write("#" * 70)

decompile_at(0x00440d80, "IsFormPersistent")
decompile_at(0x00440da0, "IsFormInAnotherState")

# FUN_00565730 — called from queue dispatch after processing
decompile_at(0x00565730, "PostDispatch_FormCleanup")
find_calls_from(0x00565730, "PostDispatch_FormCleanup")

# =====================================================================
# PART 6: NVSE MainLoopHook position
# The crash is at HandleMainLoopHook (0x10077xxx in nvse).
# Where does NVSE's MainLoopHook fire relative to the game's frame?
# It hooks at 0x0086B3E8 — what phase is this?
# =====================================================================
write("")
write("#" * 70)
write("# PART 6: NVSE MainLoopHook position in frame timeline")
write("#" * 70)

# 0x0086B3E8 is in the outer game loop FUN_0086a850
# What code is at this address? What phase?
decompile_at(0x0086a850, "OuterGameLoop_Brief", 6000)

# =====================================================================
# PART 7: DAT_01202d6c — loading state counter
# When > 0, JIP skips event dispatch. Who increments/decrements?
# Is this the right mechanism to suppress stale events?
# =====================================================================
write("")
write("#" * 70)
write("# PART 7: Loading state counter — all writers")
write("#" * 70)

find_xrefs_to(0x01202d6c, "LoadingStateCounter_writers", 20)

# FUN_0043b2b0 — InterlockedIncrement/Decrement on the counter
decompile_at(0x0043b2b0, "LoadingState_Modify")
find_xrefs_to(0x0043b2b0, "LoadingState_Modify_callers", 20)

# =====================================================================
# PART 8: Per-frame PDD (FUN_004556d0)
# The game's own per-frame PDD is gated by conditions.
# What conditions? Does it check loading state?
# This runs at Phase 4 — before NVSE MainLoopHook.
# =====================================================================
write("")
write("#" * 70)
write("# PART 8: Per-frame PDD caller — FUN_004556d0 conditions")
write("#" * 70)

decompile_at(0x004556d0, "PerFrame_PDD_Caller")
find_calls_from(0x004556d0, "PerFrame_PDD_Caller")

# =====================================================================
# PART 9: FUN_00548880 — called from queue dispatch (FUN_00451ef0)
# line 839: FUN_00548880(param_2, param_1) — before FUN_0056f700
# Does this modify the form's state? Add to PDD queue?
# =====================================================================
write("")
write("#" * 70)
write("# PART 9: FUN_00548880 — pre-processing form state change")
write("#" * 70)

decompile_at(0x00548880, "PreProcess_FormState")
find_calls_from(0x00548880, "PreProcess_FormState")

# =====================================================================
# PART 10: The game's cell unload notification system
# When a cell is unloaded, how are references in that cell notified?
# FUN_00551480 detaches references during cell unload (from DestroyCell)
# Does it cancel pending IO tasks for those references?
# =====================================================================
write("")
write("#" * 70)
write("# PART 10: Cell unload reference notification")
write("#" * 70)

decompile_at(0x00551480, "CellUnload_DetachRef")
find_calls_from(0x00551480, "CellUnload_DetachRef")

# FUN_005508b0 — remove cell from loaded list
decompile_at(0x005508b0, "CellUnload_RemoveFromList")
find_calls_from(0x005508b0, "CellUnload_RemoveFromList")


# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/nvse_cellchange_stale_refs.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
