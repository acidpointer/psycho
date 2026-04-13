# @category Analysis
# @description Trace NVSE event dispatch timing during worldspace transition.
# The crash happens in jip_nvse LN_ProcessEvents which runs during
# HandleMainLoopHook BEFORE InnerLoop. The script accesses game objects
# that may have been freed/reallocated by our slab during the transition.
#
# Key question: what game state changes between the NVSE dispatch point
# and when objects were last valid? Does our Phase 7 hook (which runs
# BEFORE NVSE dispatch) modify game state that jip_nvse depends on?
#
# Timeline:
#   MainLoopHook (NVSE) -> HandleMainLoopHook -> Dispatch_Message
#     -> each plugin's NVSEMessageHandler
#     -> jip_nvse LN_ProcessEvents (CRASH HERE)
#   THEN: InnerLoop runs (Phase 3 IOManager, Phase 7 our hook, etc)
#
# But wait - our Phase 7 hook runs INSIDE InnerLoop, not before NVSE.
# The NVSE dispatch is at 0x0086B3E3 which calls InnerLoop.
# Actually: 0x0086B3E8 is InnerLoop_NVSEHook. The NVSE hook WRAPS
# InnerLoop. HandleMainLoopHook runs, dispatches plugin messages,
# THEN calls InnerLoop.

from ghidra.app.decompiler import DecompInterface

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
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
	faddr = func.getEntryPoint().getOffset()
	write("  Function: %s @ 0x%08x, Size: %d bytes" % (func.getName(), faddr, func.getBody().getNumAddresses()))
	if faddr != addr_int:
		write("  NOTE: Requested 0x%08x is inside %s (entry at 0x%08x)" % (addr_int, func.getName(), faddr))
	result = decomp.decompileFunction(func, 120, monitor)
	if result and result.decompileCompleted():
		code = result.getDecompiledFunction().getC()
		write(code[:max_len])
	else:
		write("  [decompilation failed]")

def find_and_print_calls_from(addr_int, label):
	func = fm.getFunctionAt(toAddr(addr_int))
	if func is None:
		func = fm.getFunctionContaining(toAddr(addr_int))
	if func is None:
		write("  [function not found at 0x%08x]" % addr_int)
		return
	body = func.getBody()
	inst_iter = currentProgram.getListing().getInstructions(body, True)
	write("")
	write("--- Calls FROM %s (0x%08x) ---" % (label, addr_int))
	count = 0
	while inst_iter.hasNext():
		inst = inst_iter.next()
		refs = inst.getReferencesFrom()
		for ref in refs:
			if ref.getReferenceType().isCall():
				tgt = ref.getToAddress().getOffset()
				tgt_func = fm.getFunctionAt(toAddr(tgt))
				name = tgt_func.getName() if tgt_func else "???"
				write("  CALL @ 0x%08x -> 0x%08x %s" % (inst.getAddress().getOffset(), tgt, name))
				count += 1
	write("  Total: %d calls" % count)

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
		write("  %s @ 0x%08x (in %s)" % (ref.getReferenceType(), ref.getFromAddress().getOffset(), fname))
		count += 1
		if count > 40:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)


write("######################################################################")
write("# NVSE EVENT DISPATCH TIMING DURING WORLDSPACE TRANSITION")
write("######################################################################")


write("")
write("######################################################################")
write("# PART 1: The outer main loop - where NVSE hooks")
write("# FUN_00ECC470 is the actual WinMain loop body")
write("# NVSE hooks the CALL to InnerLoop at 0x0086B3E3")
write("######################################################################")

decompile_at(0x00ECC470, "WinMain_LoopBody")
decompile_at(0x0086B3E0, "InnerLoop_CallSite (where NVSE hooks)")


write("")
write("######################################################################")
write("# PART 2: FUN_008774a0 - CellTransitionOrchestrator")
write("# When does the game actually do cell transitions?")
write("# Is it BEFORE or AFTER the NVSE dispatch point?")
write("######################################################################")

decompile_at(0x008774A0, "CellTransitionOrchestrator")
find_and_print_calls_from(0x008774A0, "CellTransitionOrchestrator")


write("")
write("######################################################################")
write("# PART 3: FUN_00878080 - HeapCompact frame check (Phase 6)")
write("# Checks if HeapCompact trigger field is set")
write("# Runs BEFORE our Phase 7 hook")
write("######################################################################")

decompile_at(0x00878080, "HeapCompact_FrameCheck")
find_and_print_calls_from(0x00878080, "HeapCompact_FrameCheck")


write("")
write("######################################################################")
write("# PART 4: FUN_004556d0 - PDD caller (checks loading counter)")
write("# This is the vanilla PDD call inside HeapCompact")
write("# Does it check LOADING_STATE_COUNTER?")
write("######################################################################")

decompile_at(0x004556D0, "PDD_Caller (vanilla)")
find_and_print_calls_from(0x004556D0, "PDD_Caller")


write("")
write("######################################################################")
write("# PART 5: The loading flag write sites")
write("# Who sets LOADING_FLAG (0x011dea2b) to 0 (loading done)?")
write("# This is what triggers our on_loading_end hook")
write("######################################################################")

find_refs_to(0x011DEA2B, "LOADING_FLAG write sites")


write("")
write("######################################################################")
write("# PART 6: FUN_0043b2b0 - loading state counter inc/dec")
write("# Who calls this? When is counter incremented/decremented")
write("# during cell transitions?")
write("######################################################################")

decompile_at(0x0043B2B0, "LoadingStateCounter_SetFlag")
find_refs_to(0x0043B2B0, "LoadingStateCounter_SetFlag callers")


write("")
write("######################################################################")
write("# PART 7: The per-frame queue drain (Phase 7 = 0x00868850)")
write("# Our hook wraps this. What does the vanilla version do?")
write("# Does it modify state that NVSE depends on?")
write("######################################################################")

decompile_at(0x00868850, "PerFrameQueueDrain (Phase 7 vanilla)")
find_and_print_calls_from(0x00868850, "PerFrameQueueDrain")


write("")
write("######################################################################")
write("# PART 8: FUN_0086F940 - cell transition in inner loop")
write("# Where exactly in InnerLoop does cell transition happen?")
write("######################################################################")

decompile_at(0x0086F940, "CellTransition_InnerLoop")
find_and_print_calls_from(0x0086F940, "CellTransition_InnerLoop")


outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/nvse_event_dispatch_timing.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
