# @category Analysis
# @description Research NVSE event dispatching during cell destruction.
# Goal: Find how to suppress event dispatching during FindCellToUnload
# so that NVSE plugins don't fire handlers on mid-destruction objects.
#
# The crash chain: DestroyCell → actor cleanup → event dispatch →
# JohnnyGuitar PLChangeEvent → accesses refcount-0 objects
#
# Key addresses from crash:
# 0x0088629B — event dispatcher (caller of JohnnyGuitar)
# 0x0054AF67 — cell actor cleanup (called by DestroyCell)
# 0x0096E261 — between cleanup and event dispatch

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
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
	faddr = func.getEntryPoint().getOffset()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, func.getBody().getNumAddresses()))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def find_refs_to(addr_int, label):
	write("")
	write("-" * 70)
	write("References TO 0x%08x (%s)" % (addr_int, label))
	write("-" * 70)
	refs = ref_mgr.getReferencesTo(toAddr(addr_int))
	count = 0
	while refs.hasNext():
		ref = refs.next()
		from_func = fm.getFunctionContaining(ref.getFromAddress())
		fname = from_func.getName() if from_func else "???"
		write("  %s @ %s (in %s)" % (ref.getReferenceType(), ref.getFromAddress(), fname))
		count += 1
		if count > 30:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

write("=" * 70)
write("EVENT DISPATCH SUPPRESSION RESEARCH")
write("Goal: Find a flag/lock to suppress NVSE event dispatching")
write("during FindCellToUnload → DestroyCell")
write("=" * 70)

# ===================================================================
# PART 1: The crash chain — trace from DestroyCell to event dispatch
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: Crash chain — DestroyCell → event dispatch")
write("#" * 70)

# DestroyCell calls FUN_0054af40 (actor/ref cleanup for unloading cell)
decompile_at(0x00462290, "DestroyCell (341 bytes)")

# FUN_0054af40 — the function that triggers actor processing
decompile_at(0x0054AF40, "CellCleanup_ActorProcess (contains 0x0054AF67)")

# FUN_0096e261 — between cleanup and event dispatch
decompile_at(0x0096E261, "ActorProcess_EventTrigger (contains 0x0096E261)")

# FUN_0088629B — the event dispatcher itself
decompile_at(0x0088629B, "EventDispatcher (contains 0x0088629B)")

# FUN_0088304A — inside event processing
decompile_at(0x0088304A, "EventProcess_Inner (contains 0x0088304A)")

# ===================================================================
# PART 2: The event dispatch system — is there a global disable flag?
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: Event dispatch system — global flags")
write("# Is there a flag that suppresses event dispatching?")
write("#" * 70)

# The event dispatcher function — look for guard checks
decompile_at(0x00886200, "EventDispatcher_Entry")
decompile_at(0x00886290, "EventDispatcher_Near")

# ===================================================================
# PART 3: The actor process change — what triggers PLChangeEvent?
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: Actor process change during cell unload")
write("# What exactly triggers PLChangeEvent?")
write("#" * 70)

decompile_at(0x009145EF, "ActorProcessChange (contains 0x009145EF)")
decompile_at(0x00914A98, "ActorProcessChange_Outer (contains 0x00914A98)")
decompile_at(0x0092CA53, "CombatPackage_Cleanup (contains 0x0092CA53)")

# ===================================================================
# PART 4: The crash function — what object is it accessing?
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: Crash at 0x00470488")
write("#" * 70)

decompile_at(0x00470488, "Crash_Function")

# ===================================================================
# PART 5: How does HeapCompact Stage 5 avoid this?
# Does it set a flag that suppresses events?
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: HeapCompact Stage 5 — does it suppress events?")
write("# TLS[0x298] = 0 might affect event dispatching")
write("#" * 70)

# SetTlsCleanupFlag — does this affect event dispatch?
decompile_at(0x00869190, "SetTlsCleanupFlag (29 bytes)")

# Does the event dispatcher check TLS[0x298]?
# The dispatcher at 0x00886200 might check this flag

# ===================================================================
# PART 6: CellTransitionHandler — how does it avoid event crashes?
# It also calls ForceUnloadCell → DestroyCell
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: CellTransitionHandler — event suppression?")
write("# Does it set state flags before cell unloading?")
write("#" * 70)

# FUN_004f15a0 — called at start of CellTransitionHandler
# Sets some state that might suppress events
decompile_at(0x004F15A0, "SetGameState (FUN_004f15a0)")
decompile_at(0x004F1540, "GetGameState (FUN_004f1540)")

# FUN_0043b2b0 — might set loading state
decompile_at(0x0043B2B0, "SetLoadingState? (FUN_0043b2b0)")

# ===================================================================
# PART 7: DAT_011dea2b — the "loading" flag from main loop
# The main loop sets this and gates many operations on it
# ===================================================================
write("")
write("#" * 70)
write("# PART 7: Loading/transition state flags")
write("#" * 70)

find_refs_to(0x011DEA2B, "DAT_011dea2b (loading flag)")

# FUN_00702360 — checks if in loading state
decompile_at(0x00702360, "IsLoading? (FUN_00702360)")
decompile_at(0x00709BC0, "IsTransitioning? (FUN_00709bc0)")

# ===================================================================
# PART 8: FUN_004539a0 (ForceUnloadCell) — does it set flags?
# This is what CellTransitionHandler calls before DestroyCell
# ===================================================================
write("")
write("#" * 70)
write("# PART 8: ForceUnloadCell — does it set pre-unload flags?")
write("#" * 70)

decompile_at(0x004539A0, "ForceUnloadCell (196 bytes)")

# FUN_00453940 — called by ForceUnloadCell before destruction
decompile_at(0x00453940, "PreUnload_Setup (FUN_00453940)")

# FUN_00455200 — called by ForceUnloadCell
decompile_at(0x00455200, "UnloadCell_Inner (FUN_00455200)")

# ===================================================================
# PART 9: FUN_0044ada0 — called by DestroyCell at start and end
# This might be the event suppression mechanism
# ===================================================================
write("")
write("#" * 70)
write("# PART 9: FUN_0044ada0 — called by DestroyCell(1) and (0)")
write("# DestroyCell calls FUN_0044ada0(1) at start, FUN_0044ada0(0) at end")
write("# This looks like a guard/lock for destruction")
write("#" * 70)

decompile_at(0x0044ADA0, "DestroyCell_Guard (FUN_0044ada0)")

find_refs_to(0x0044ADA0, "FUN_0044ada0 (destruction guard)")

write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/event_dispatch_suppress.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
