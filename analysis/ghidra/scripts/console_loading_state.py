# @category Analysis
# @description Trace how console open/close affects loading state.
# User opens console -> types coc command -> console closes -> transition.
# Each state change might trigger loading flag / loading counter changes.
# Our on_loading_start/on_loading_end detect via LOADING_FLAG (DAT_011dea2b).
# If console open sets this flag, we get false loading transitions.
#
# Also trace: what EXACTLY triggers jip_nvse CellChange events?
# Is it a game engine callback or does jip_nvse poll for changes?
#
# Key addresses:
# DAT_011dea2b = LOADING_FLAG
# DAT_01202d6c = LOADING_STATE_COUNTER
# FUN_0043b2b0 = counter inc/dec

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
		if count > 50:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)


write("######################################################################")
write("# CONSOLE + LOADING STATE + CELLCHANGE TIMING")
write("######################################################################")


write("")
write("######################################################################")
write("# PART 1: Who WRITES to LOADING_FLAG (DAT_011dea2b)?")
write("# Two WRITE refs found earlier. What sets it to 1 and 0?")
write("# Does console open/close write this flag?")
write("######################################################################")

decompile_at(0x0086E6E1, "LOADING_FLAG_write_1 (InnerLoop area)")
decompile_at(0x0086E7C9, "LOADING_FLAG_write_2 (InnerLoop area)")


write("")
write("######################################################################")
write("# PART 2: FUN_0086e650 - the InnerLoop that reads LOADING_FLAG")
write("# This is the 2272-byte inner loop. It reads the flag many times.")
write("# WHERE in the loop does it set/clear the flag?")
write("######################################################################")

decompile_at(0x0086E650, "InnerLoop (reads LOADING_FLAG)")


write("")
write("######################################################################")
write("# PART 3: Console command execution path")
write("# coc (CenterOnCell) command triggers worldspace transition.")
write("# What functions handle coc? Search for console command dispatch.")
write("# FUN_005B6CD0 is one of the DeferredCleanupSmall callers - maybe")
write("# related to console command execution.")
write("######################################################################")

decompile_at(0x005B6CD0, "DeferredCleanupSmall_caller_5B6CD0")
find_and_print_calls_from(0x005B6CD0, "DeferredCleanupSmall_caller_5B6CD0")


write("")
write("######################################################################")
write("# PART 4: FUN_00709bc0 - checked in cell transition path")
write("# CellTransition_InnerLoopCheck (0x86F940) checks this.")
write("# If it returns true AND loading=true, cell transition runs.")
write("# What is this? Console-related? Pause-related?")
write("######################################################################")

decompile_at(0x00709BC0, "CellTransition_Condition_Check")


write("")
write("######################################################################")
write("# PART 5: How does the game detect that player changed cells?")
write("# FUN_0093bea0 = ConditionalCellTransition (checked first in 86F940)")
write("# What triggers it? Does coc command set a flag here?")
write("######################################################################")

decompile_at(0x0093BEA0, "ConditionalCellTransition")
find_and_print_calls_from(0x0093BEA0, "ConditionalCellTransition")


write("")
write("######################################################################")
write("# PART 6: FUN_00878360 - PDD drain rate multiplier")
write("# Returns non-zero during loading -> doubles drain rate.")
write("# What constitutes 'loading' for this check?")
write("# Does console being open count?")
write("######################################################################")

decompile_at(0x00878360, "PDD_DrainRate_Multiplier")


write("")
write("######################################################################")
write("# PART 7: Console open/close functions")
write("# Search for InterfaceManager (DAT_011ddf38) which manages console.")
write("# FUN_00652110, FUN_00652130 etc in Phase 6 HeapCompact check.")
write("# Does opening console call FUN_0043b2b0 (counter inc/dec)?")
write("######################################################################")

decompile_at(0x00652110, "InterfaceManager_GetInstance_or_Console")
decompile_at(0x00652130, "InterfaceManager_Mode_or_Console")
decompile_at(0x00529EA0, "Console_or_Menu_Check")


write("")
write("######################################################################")
write("# PART 8: FUN_0086fba0 and FUN_0086fbc0 - called during cell transition")
write("# These are called in CellTransition_InnerLoopCheck (0x86F940)")
write("# with params 1/0. Do they set LOADING_FLAG?")
write("######################################################################")

decompile_at(0x0086FBA0, "CellTransition_SetFlag_1")
decompile_at(0x0086FBC0, "CellTransition_SetFlag_2")
decompile_at(0x0086FBE0, "CellTransition_CheckFlag")


write("")
write("######################################################################")
write("# PART 9: The exact PDD skip mask manipulation")
write("# DAT_011de804 = PDD skip mask. FUN_00869180 checks bits.")
write("# FUN_00869190 sets/clears bits (called in OOM Stage 5).")
write("# Does our Phase 7 hook modify this mask?")
write("######################################################################")

decompile_at(0x00869180, "PDD_SkipMask_Check")
decompile_at(0x00869190, "PDD_SkipMask_Set")


write("")
write("######################################################################")
write("# PART 10: Extra PDD drain in our Phase 7")
write("# Our hook calls original PDD, then runs up to 75 extra rounds.")
write("# Each round calls FUN_00868d70 (PDD) which drains ENTIRE Generic")
write("# queue. Is this the problem? Does vanilla NEVER drain more than")
write("# once per frame?")
write("######################################################################")

write("")
write("# Key insight: vanilla PerFrameQueueDrain (FUN_00868850) calls PDD")
write("# indirectly through its own queue processing. It does NOT call")
write("# FUN_00868d70 directly. It processes queues one at a time with")
write("# rate limits. Our hook calls FUN_00868d70 (the FULL PDD function)")
write("# 75 times, each time draining ALL queues completely.")
write("")
write("# FUN_00868d70 Generic queue drain (line 124 of decompile):")
write("# while (count != 0) { process_and_remove(0); }")
write("# This is an UNBOUNDED while loop that drains EVERYTHING.")
write("# Calling it 75 times = 75 full drains of all queues.")


outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/console_loading_state.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
