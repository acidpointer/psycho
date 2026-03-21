# @category Analysis
# @description DEEP research: BSTaskManagerThread task lifecycle, vanilla sync mechanism, resource flush

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
write("DEEP RESEARCH: Complete BSTaskManagerThread + Vanilla Sync Mechanism")
write("Goal: Find the REAL synchronization the game uses, not workarounds")
write("=" * 70)

# =====================================================================
# PART 1: QueuedTexture COMPLETE lifecycle
# Who creates it, what references does it hold, how is it cancelled?
# =====================================================================
write("")
write("#" * 70)
write("# PART 1: QueuedTexture lifecycle — creation, references, cancellation")
write("#" * 70)

# QueuedTexture RTTI xrefs — find constructors
find_xrefs_to(0x01016788, "QueuedTexture_RTTI")

# QueuedTexture constructors (from RTTI xrefs: 0x0043bd10, 0x0043be60, 0x0043bef0, 0x0043bf80)
decompile_at(0x0043BD10, "QueuedTexture_ctor1")
decompile_at(0x0043BE60, "QueuedTexture_ctor2")
decompile_at(0x0043BEF0, "QueuedTexture_ctor3")
decompile_at(0x0043BF80, "QueuedTexture_ctor4")

# Who CALLS these constructors? These are the task SUBMITTERS
find_xrefs_to(0x0043BD10, "QueuedTexture_ctor1_callers")
find_xrefs_to(0x0043BE60, "QueuedTexture_ctor2_callers")
find_xrefs_to(0x0043BEF0, "QueuedTexture_ctor3_callers")
find_xrefs_to(0x0043BF80, "QueuedTexture_ctor4_callers")

# =====================================================================
# PART 2: How does CellTransitionHandler ACTUALLY prevent IO crashes?
# Trace the FULL sequence, not just PDD+AsyncFlush
# =====================================================================
write("")
write("#" * 70)
write("# PART 2: CellTransitionHandler — FULL sequence with all side effects")
write("#" * 70)

# FUN_00877700 waits for TES+0x77c. But what ELSE does the game do?
# FUN_004539a0 is called BEFORE cell unloading — what does it do to IO tasks?
decompile_at(0x004539A0, "PreCellUnload_cleanup_full")
find_calls_from(0x004539A0, "PreCellUnload_cleanup")

# FUN_00470470 — called at the start of PreCellUnload_cleanup
# This might cancel/drain IO tasks for the cells being unloaded
decompile_at(0x00470470, "PreCleanup_FirstCall")
find_calls_from(0x00470470, "PreCleanup_FirstCall")

# =====================================================================
# PART 3: FUN_00b5fd60 — resource flush (called by DeferredCleanupSmall)
# What does it do to NiSourceTexture references?
# =====================================================================
write("")
write("#" * 70)
write("# PART 3: FUN_00b5fd60 resource flush — texture reference cleanup")
write("#" * 70)

# FUN_00b5fd60 iterates linked lists at param+0xe4, +0xfc, +0xf0
# It calls FUN_00b5eca0, FUN_00b5cd00, FUN_00b5d300, FUN_00b5d930
# What do these sub-functions do?
decompile_at(0x00B5ECA0, "ResourceFlush_Sub1")
decompile_at(0x00B5CD00, "ResourceFlush_Sub2")
decompile_at(0x00B5D300, "ResourceFlush_Sub3")
decompile_at(0x00B5D930, "ResourceFlush_Sub4")

# =====================================================================
# PART 4: DAT_011c3b3c — the task queue manager
# What EXACTLY is this? What queues does it manage?
# How does FUN_00448620 cancel tasks?
# =====================================================================
write("")
write("#" * 70)
write("# PART 4: DAT_011c3b3c task queue manager — full structure")
write("#" * 70)

# FUN_00448620 iterates *(this+0) and *(this+4) queues
# What types of tasks are in each queue?
# FUN_0044c640 — dequeue from task list (called by FUN_00448620)
decompile_at(0x0044C640, "TaskQueue_Dequeue")

# FUN_00443190 / FUN_004431f0 — cancel/complete task
decompile_at(0x00443190, "Task_CheckComplete")
decompile_at(0x004431F0, "Task_Release1")
decompile_at(0x004431B0, "Task_CheckComplete2")
decompile_at(0x00443240, "Task_Release2")

# =====================================================================
# PART 5: NiSourceTexture reference management
# When is it created? Who adds/removes references?
# Does NiSourceTexture destructor NULL the pixelData?
# =====================================================================
write("")
write("#" * 70)
write("# PART 5: NiSourceTexture destructor — what does it zero?")
write("#" * 70)

# NiSourceTexture RTTI
find_xrefs_to(0x0109B9EC, "NiSourceTexture_RTTI")

# FUN_00a5fca0 / FUN_00a5fc10 — NiSourceTexture functions
decompile_at(0x00A5FCA0, "NiSourceTexture_func1")
decompile_at(0x00A5FC10, "NiSourceTexture_func2")

# =====================================================================
# PART 6: The FULL path from NiSourceTexture ref decrement to free
# When refcount hits 0, what happens? PDD queue? Immediate free?
# =====================================================================
write("")
write("#" * 70)
write("# PART 6: NiRefObject release path — refcount 0 → PDD or free?")
write("#" * 70)

# FUN_00401970 — the DecRef function used everywhere
decompile_at(0x00401970, "NiRefObject_DecRef")

# FUN_0040f6e0 — the IncRef function
decompile_at(0x0040F6E0, "NiRefObject_IncRef")

# FUN_00401030 — CommonDelete
decompile_at(0x00401030, "CommonDelete")

# =====================================================================
# PART 7: How does the game submit IO tasks?
# The LockFreeQueue and LockFreePriorityQueue — what goes where?
# =====================================================================
write("")
write("#" * 70)
write("# PART 7: IO task submission — what queues, what types")
write("#" * 70)

# FUN_00c3f860 area — task submission
decompile_at(0x0044CD00, "IOTask_Create")
find_xrefs_to(0x0044CD00, "IOTask_Create_callers")

# FUN_0044e010 — IOTask state management
decompile_at(0x0044E010, "IOTask_StateChange")

# =====================================================================
# PART 8: AsyncQueueFlush — does it drain tasks or just completions?
# We assumed it drains the COMPLETION queue. Verify.
# =====================================================================
write("")
write("#" * 70)
write("# PART 8: AsyncQueueFlush inner — what exactly is drained?")
write("#" * 70)

# FUN_00c45e00 — called by IO_FlushRequest (adds to completion queue?)
decompile_at(0x00C45E00, "AsyncFlush_AddToQueue")

# FUN_00c45e50 — called by IO_DeferredTaskBudget
decompile_at(0x00C45E50, "AsyncFlush_ProcessItem")

# =====================================================================
# PART 9: The game's per-frame PDD caller — what conditions gate it?
# FUN_004556d0 is called with conditions. What are they?
# =====================================================================
write("")
write("#" * 70)
write("# PART 9: Per-frame PDD conditions — FUN_00451530 + FUN_0086ef70")
write("#" * 70)

decompile_at(0x00451530, "PDD_Condition1")
decompile_at(0x0086EF70, "PDD_Condition2")

# =====================================================================
# PART 10: What happens BETWEEN cell unload and PDD?
# FindCellToUnload → DestroyCell → objects enter PDD queues
# Are IO task references cleaned BEFORE PDD runs?
# =====================================================================
write("")
write("#" * 70)
write("# PART 10: DestroyCell → what references are cleaned?")
write("#" * 70)

# FUN_005508b0 — called from DestroyCell
decompile_at(0x005508B0, "DestroyCell_Sub1")

# FUN_0054b750 — called from DestroyCell
decompile_at(0x0054B750, "DestroyCell_Sub2")

# FUN_00546970 — called from DestroyCell
decompile_at(0x00546970, "DestroyCell_Sub3")

# FUN_00585e00 — world space cleanup from DestroyCell
decompile_at(0x00585E00, "DestroyCell_WorldCleanup")

# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/deep_io_lifecycle.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
