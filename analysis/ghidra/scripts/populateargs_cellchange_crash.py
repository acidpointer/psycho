# @category Analysis
# @description Trace PopulateArgs crash from CellChange event during worldspace
# transition. Crash at InternalFunctionCaller::PopulateArgs+0xD4 with ECX=4.
# jip_nvse fires nvseRuntimeScript263CellChange via LN_ProcessEvents during
# NVSE HandleMainLoopHook dispatch. The script reads a game object argument
# whose slab cell was recycled -- new data has integer 4 at pointer offset.
#
# Key question: what EXACTLY does PopulateArgs read that contains the stale
# pointer? Is it a script local variable, an event argument, or a form ref?
# And: where in the CellChange event handler is the object accessed?

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
write("# POPULATEARGS CELLCHANGE CRASH ANALYSIS")
write("# Crash: InternalFunctionCaller::PopulateArgs+0xD4 with ECX=4")
write("# Script: nvseRuntimeScript263CellChange (jip_nvse CellChange)")
write("# Path: HandleMainLoopHook -> Dispatch -> jip_nvse LN_ProcessEvents")
write("#        -> CallFunctionScriptAlt -> UserFunctionManager::Call")
write("#        -> PopulateArgs -> CRASH")
write("######################################################################")


write("")
write("######################################################################")
write("# PART 1: Script event argument passing")
write("# How does jip_nvse pass event arguments to script functions?")
write("# LN_ProcessEvents fires CellChange events.")
write("# The script receives a reference to the old/new cell or actor.")
write("# If that reference points to freed memory -> PopulateArgs crash.")
write("######################################################################")

write("")
write("# jip_nvse source shows (lutana.h:355 area):")
write("# LN_ProcessEvents processes registered event handlers")
write("# CellChange event passes the actor whose cell changed")
write("# If the actor reference was freed during cell transition,")
write("# PopulateArgs reads the freed reference data -> crash")

write("")
write("# Key: PopulateArgs reads TESForm* arguments from the script's")
write("# argument list. The TESForm pointer is stale -> freed -> recycled")
write("# slab cell has integer data where the TESForm fields should be.")


write("")
write("######################################################################")
write("# PART 2: ProcessPendingCleanup + BSTreeManager during CellChange")
write("# DeferredCleanupSmall at 0x878250 runs PDD + ProcessPendingCleanup")
write("# ProcessPendingCleanup calls BSTreeManager cleanup twice")
write("# Who frees the actor/cell data that the script still references?")
write("######################################################################")

decompile_at(0x00878250, "DeferredCleanupSmall")


write("")
write("######################################################################")
write("# PART 3: The CellTransition path in InnerLoop")
write("# FUN_0086F940 = cell transition check")
write("# FUN_008774A0 = CellTransitionOrchestrator")
write("# These run INSIDE InnerLoop, AFTER NVSE dispatch.")
write("# But cell DATA is freed during PREVIOUS frame's InnerLoop.")
write("# On the NEXT frame, NVSE dispatch fires CellChange events")
write("# referencing the freed data.")
write("######################################################################")

decompile_at(0x0086F940, "CellTransition_InnerLoopCheck")


write("")
write("######################################################################")
write("# PART 4: FUN_00868850 (Phase 7 PerFrameQueueDrain)")
write("# Our hook wraps this. The VANILLA version drains PDD queues.")
write("# Does vanilla PDD free actor data that CellChange scripts use?")
write("######################################################################")

decompile_at(0x00868850, "PerFrameQueueDrain_Vanilla")


write("")
write("######################################################################")
write("# PART 5: Form lookup by FormID")
write("# When scripts access actors by FormID, the lookup goes through")
write("# a form table. If the form was freed but FormID not cleared,")
write("# the lookup returns stale pointer -> crash in PopulateArgs.")
write("######################################################################")

decompile_at(0x00483370, "FormTable_Lookup_or_CellChange_Counter")
find_and_print_calls_from(0x00483370, "FormTable_Lookup")


write("")
write("######################################################################")
write("# PART 6: Loading state counter callers near cell transition")
write("# FUN_004556d0 = PDD caller (vanilla) - huge function")
write("# Does it increment/decrement the counter around PDD?")
write("# If PDD frees forms while counter is 0, CellChange fires.")
write("######################################################################")

decompile_at(0x004556D0, "VanillaPDD_Caller (first 4000 chars)")


write("")
write("######################################################################")
write("# PART 7: Who calls DeferredCleanupSmall (0x878250)?")
write("# It showed up at stack frame #10 in the BSTreeNode crash.")
write("# It's called from CellTransitionOrchestrator and from")
write("# the InnerLoop's post-render path.")
write("######################################################################")

find_refs_to(0x00878250, "DeferredCleanupSmall callers")


write("")
write("######################################################################")
write("# PART 8: The loading_state_counter and CellChange interaction")
write("# When counter > 0, actor processing skips event dispatch.")
write("# jip_nvse CellChange: does IT check the counter?")
write("# Or does it always fire regardless?")
write("######################################################################")

write("")
write("# jip_nvse source (lutana.h:355):")
write("# LN_ProcessEvents is called from NVSEMessageHandler on")
write("# kMessage_MainGameLoop. It processes all registered events.")
write("# The CellChange event handler is registered by jip_nvse.")
write("# It does NOT check LOADING_STATE_COUNTER.")
write("# It fires whenever the game dispatches MainGameLoop messages.")
write("")
write("# The game dispatches MainGameLoop on EVERY frame, including")
write("# frames during loading (loading screen renders = main loop runs).")
write("# So CellChange fires even during loading transitions.")


outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/populateargs_cellchange_crash.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
