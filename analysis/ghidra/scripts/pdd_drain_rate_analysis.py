# @category Analysis
# @description Analyze PDD drain rate: vanilla vs our extra rounds.
# Vanilla PerFrameQueueDrain (0x868850) drains 5-40 items per frame.
# Our hook drains 75 rounds. Stage 4 HeapCompact does full blocking drain.
# The crash: aggressive PDD frees Characters that jip_nvse CellChange
# scripts still reference via stale TESForm* pointers.
#
# Key questions:
# 1. How many items does vanilla drain per frame per queue?
# 2. What is local_1c (the multiplier) and when is it 1 vs 2?
# 3. Does vanilla PDD check any state before draining?
# 4. What queue addresses map to which object types?
# 5. How does the Generic queue (DAT_011de874) relate to NiNode/Form?

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
write("# PDD DRAIN RATE ANALYSIS")
write("# Vanilla vs our aggressive drain vs Stage 4 full drain")
write("######################################################################")


write("")
write("######################################################################")
write("# PART 1: PDD queue addresses and object types")
write("# From the vanilla PerFrameQueueDrain, each queue has a specific")
write("# drain rate multiplier and processes specific object types.")
write("######################################################################")

write("")
write("PDD Queue Addresses (from vanilla PerFrameQueueDrain FUN_00868850):")
write("  DAT_011de808 = NiNode queue (drained first)")
write("  DAT_011de910 = ??? queue")
write("  DAT_011de838 = ??? queue")
write("  DAT_011de888 = Form queue (drains local_1c * 10 items)")
write("  DAT_011de848 = ??? queue")
write("  DAT_011de874 = Generic queue (drains local_1c * 20 items) -- 30K+ items in crash")
write("  DAT_011de8bc = ??? queue")
write("  DAT_011de924 = Havok/NiRef queue (drains local_1c * 5 items)")
write("  DAT_011de898 = ??? queue (merged into 924)")
write("")
write("local_1c = 1 normally, 2 during loading (doubles drain rate)")
write("")
write("Vanilla drain rates per frame:")
write("  Havok queue: 5-10 items")
write("  Generic queue: 20-40 items")
write("  Form queue: 10-20 items")
write("  NiNode queue: 1 item (single virtual dispatch)")
write("")
write("Our drain: 75 rounds of full FUN_00868d70(try_lock=1)")
write("  Each round processes ALL queue types")
write("  75 rounds * all queues = potentially thousands of items freed")


write("")
write("######################################################################")
write("# PART 2: FUN_00868d70 (PDD) - what does try_lock param do?")
write("# param=0: blocking (takes lock, processes all)")
write("# param=1: non-blocking (try-lock, skip if busy)")
write("# Stage 4 calls with param=1 (blocking)")
write("######################################################################")

decompile_at(0x00868D70, "ProcessDeferredDestruction")


write("")
write("######################################################################")
write("# PART 3: FUN_00867f50 - called at start of PerFrameQueueDrain")
write("# What does this do? Initialize queues? Check state?")
write("######################################################################")

decompile_at(0x00867F50, "PDD_PreDrain_Init")


write("")
write("######################################################################")
write("# PART 4: FUN_00878360 - determines local_1c (drain rate multiplier)")
write("# Returns non-zero -> local_1c = 2 (double drain rate)")
write("# What condition causes doubled rate?")
write("######################################################################")

decompile_at(0x00878360, "PDD_DrainRate_Check")


write("")
write("######################################################################")
write("# PART 5: Who adds items to the Generic queue (DAT_011de874)?")
write("# The queue had 30K+ items. What puts them there?")
write("# Is it cell unload, PDD, or something else?")
write("######################################################################")

find_refs_to(0x011DE874, "PDD_Generic_Queue_refs")


write("")
write("######################################################################")
write("# PART 6: Who adds to NiNode queue (DAT_011de808)?")
write("######################################################################")

find_refs_to(0x011DE808, "PDD_NiNode_Queue_refs")


write("")
write("######################################################################")
write("# PART 7: Who adds to Form queue (DAT_011de828)?")
write("######################################################################")

find_refs_to(0x011DE828, "PDD_Form_Queue_refs")


write("")
write("######################################################################")
write("# PART 8: FUN_00658930 - queue count check")
write("# Used to check if queue has items before draining")
write("######################################################################")

decompile_at(0x00658930, "Queue_HasItems_Check")


write("")
write("######################################################################")
write("# PART 9: FUN_0044ddc0 - another queue count check")
write("######################################################################")

decompile_at(0x0044DDC0, "Queue_Count_Check")


outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/pdd_drain_rate_analysis.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
