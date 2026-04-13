# @category Analysis
# @description Trace BSTreeNode C0000417 crash: DeferredCleanupSmall -> NiNode
# destruction -> BSTreeManager -> CRT invalid parameter.
# Root cause: missing stage 4 PDD purge leaves BSTreeNode children freed
# while parent is still in PDD queue. When parent destructor fires,
# it Release()s already-freed children -> RefCount:0 -> C0000417.
#
# Crash stack: InnerLoop -> DeferredCleanupSmall (0x878250)
#   -> 0xC45A4F -> 0xC4610E -> 0xCFCC2C -> 0x66B68F
#   -> 0x6667DF -> 0x666868 -> 0x66691F -> 0xB03E48 -> 0xEC7C62 (CRT)

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
write("# BSTreeNode C0000417 CRASH: PDD STAGE 4 ANALYSIS")
write("######################################################################")


write("")
write("######################################################################")
write("# PART 1: DeferredCleanupSmall (0x878250)")
write("# This is where the crash originates in InnerLoop")
write("######################################################################")

decompile_at(0x00878250, "DeferredCleanupSmall")
find_and_print_calls_from(0x00878250, "DeferredCleanupSmall")


write("")
write("######################################################################")
write("# PART 2: Crash stack frames (BSTreeNode destruction chain)")
write("######################################################################")

decompile_at(0x00C45A4F, "Frame9_near_DeferredCleanup")
decompile_at(0x00C4610E, "Frame8_IO_dispatch")
decompile_at(0x00CFCC2C, "Frame5_7_VirtualDtor_Caller")
decompile_at(0x0066B68F, "Frame6_NiNode_or_BSTree")
decompile_at(0x006667DF, "Frame4_NiNode_destruction")
decompile_at(0x00666868, "Frame3_NiNode_destruction")
decompile_at(0x0066691F, "Frame2_NiNode_destruction")
decompile_at(0x00B03E48, "Frame1_near_CRT_handler")


write("")
write("######################################################################")
write("# PART 3: BSTreeManager internals")
write("# Singleton: DAT_011d5c48")
write("# ProcessPendingCleanup (FUN_00452490) calls cleanup")
write("######################################################################")

decompile_at(0x00664CD0, "BSTreeManager_Cleanup")
decompile_at(0x00726070, "BSTreeManager_StateCheck")
decompile_at(0x00452490, "ProcessPendingCleanup")
find_and_print_calls_from(0x00452490, "ProcessPendingCleanup")


write("")
write("######################################################################")
write("# PART 4: PDD stages - what stage 4 does vs stage 2")
write("# HeapCompact at Phase 6 (FUN_00878080) runs OOM stages")
write("# FUN_00866a90 = OOM stage executor")
write("######################################################################")

decompile_at(0x00866A90, "OOM_StageExec")
find_and_print_calls_from(0x00866A90, "OOM_StageExec")


write("")
write("######################################################################")
write("# PART 5: PDD function (FUN_00868d70) - the actual PDD")
write("# How many items per call? What queues?")
write("######################################################################")

decompile_at(0x00868D70, "ProcessDeferredDestruction")


write("")
write("######################################################################")
write("# PART 6: Generic queue structure at DAT_011de874")
write("# The queue had 30000+ items in the crash. Why so many?")
write("######################################################################")

find_refs_to(0x011DE874, "PDD_Generic_Queue")


write("")
write("######################################################################")
write("# PART 7: CRT invalid parameter handler at crash site")
write("# 0x00EC7C62 and 0x00B03E48")
write("######################################################################")

decompile_at(0x00EC7C62, "CRT_InvalidParam_Handler")
decompile_at(0x00B03E48, "NiRefObject_Release_CRT_path")


outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/bstreenode_pdd_stage4.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
