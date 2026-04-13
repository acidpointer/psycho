# @category Analysis
# @description Find the best hook point to synchronize BackgroundCloneThread
# before cell transitions free NiNode/animation data.
#
# FUN_008774a0 = CellTransitionOrchestrator (thiscall, 561 bytes).
# Called during cell transitions to orchestrate Havok stop, PDD, cleanup.
# BackgroundCloneThread is NOT synchronized here -- it continues cloning
# NiNode trees while the orchestrator frees cell data.
#
# Need to find:
# 1. Who calls FUN_008774a0 and from where
# 2. BackgroundCloneThread entry/loop structure
# 3. How BSTaskManagerThread iter_sem relates to BackgroundCloneThread
# 4. Is BackgroundCloneThread a BSTaskManagerThread instance?

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
write("# CELL TRANSITION HOOK POINT FOR BACKGROUNDCLONETHREAD SYNC")
write("######################################################################")


write("")
write("######################################################################")
write("# PART 1: Who calls CellTransitionOrchestrator (0x008774a0)?")
write("######################################################################")

find_refs_to(0x008774A0, "CellTransitionOrchestrator callers")


write("")
write("######################################################################")
write("# PART 2: BackgroundCloneThread entry point and loop")
write("# RTTI at 0x0118580C, vtable at 0x01016E50")
write("# Thread entry at 0x00C42DA0 (37 bytes)")
write("######################################################################")

decompile_at(0x00C42DA0, "BackgroundCloneThread_Entry")
find_and_print_calls_from(0x00C42DA0, "BackgroundCloneThread_Entry")


write("")
write("######################################################################")
write("# PART 3: BackgroundCloneThread main loop")
write("# What does it do? How does it get tasks? Does it have a semaphore?")
write("######################################################################")

decompile_at(0x00C41200, "BackgroundCloneThread_Loop_or_BSTask")
find_and_print_calls_from(0x00C41200, "BackgroundCloneThread_Loop")


write("")
write("######################################################################")
write("# PART 4: FUN_008324e0 = HavokStopStart(mode)")
write("# Called at line 418 of CellTransitionOrchestrator")
write("# mode=0 stops Havok. Does it also stop BackgroundCloneThread?")
write("######################################################################")

decompile_at(0x008324E0, "HavokStopStart")
find_and_print_calls_from(0x008324E0, "HavokStopStart")


write("")
write("######################################################################")
write("# PART 5: Where is BackgroundCloneThread created?")
write("# Search for refs to vtable 0x01016E50")
write("######################################################################")

find_refs_to(0x01016E50, "BackgroundCloneThread_vtable")


write("")
write("######################################################################")
write("# PART 6: FUN_008782b0 - called from InnerLoop near DeferredCleanupSmall")
write("# At InnerLoop line 83: if (cVar2 == 3 && !bVar1) FUN_008782b0()  ")
write("# This calls DeferredCleanupSmall. What is the condition?")
write("######################################################################")

decompile_at(0x008782B0, "InnerLoop_DeferredCleanup_Wrapper")
find_and_print_calls_from(0x008782B0, "InnerLoop_DeferredCleanup_Wrapper")


write("")
write("######################################################################")
write("# PART 7: FUN_00877700 - called at start of CellTransitionOrchestrator")
write("# line 414: FUN_00877700((int)DAT_011dea3c)")
write("# What does this do? Set up for transition?")
write("######################################################################")

decompile_at(0x00877700, "CellTransition_Setup")


write("")
write("######################################################################")
write("# PART 8: The crash site - FUN_00A4763A")
write("# Animation system crash in BackgroundCloneThread")
write("######################################################################")

decompile_at(0x00A4763A, "AnimSystem_CrashSite")
find_and_print_calls_from(0x00A47600, "AnimSystem_CrashSite_func")


write("")
write("######################################################################")
write("# PART 9: IOManager structure - does BackgroundCloneThread use it?")
write("# IOManager at DAT_01202D98, threads at +0x50")
write("# Are there more than 2 BSTaskManagerThreads?")
write("######################################################################")

decompile_at(0x00C3A6D0, "IOManager_Init_or_Create")
find_and_print_calls_from(0x00C3A6D0, "IOManager_Init")


outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/cell_transition_hook_point.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
