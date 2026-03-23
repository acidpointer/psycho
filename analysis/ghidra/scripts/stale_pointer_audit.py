# @category Analysis
# @description Audit ALL stale pointer paths that quarantine currently masks.
# Goal: identify every case where the game reads freed GameHeap data,
# so we can fix each one with a targeted hook instead of quarantine.
# Focus areas:
# 1. QueuedCharacter ragdoll: HighProcess -> ragdoll controller -> bone array
# 2. Havok memory allocator: does it go through GameHeap or separate pool?
# 3. IOManager completed task dispatch: what other task types have stale refs?
# 4. NVSE plugin stale refs (Stewie's Tweaks dead creature weapon refs)
# 5. SpeedTree BSTreeNode cache references

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

def read_vtable(vtable_addr, label, count=8):
	write("")
	write("%s vtable at 0x%08x:" % (label, vtable_addr))
	for i in range(count):
		entry_addr = vtable_addr + i * 4
		val = getInt(toAddr(entry_addr)) & 0xFFFFFFFF
		func = fm.getFunctionContaining(toAddr(val))
		fname = func.getName() if func else "???"
		write("  [%2d] +0x%02x -> 0x%08x %s" % (i, i*4, val, fname))


write("=" * 70)
write("STALE POINTER AUDIT: All paths where freed data is read")
write("Goal: fix each path with targeted hooks, eliminate quarantine")
write("=" * 70)

# =====================================================================
# PART 1: Havok memory allocator — does it go through GameHeap?
# FUN_00c85750 returns hkMemoryAllocator. What are its vtable methods?
# Does alloc/free dispatch to GameHeap or a separate pool?
# =====================================================================
write("")
write("#" * 70)
write("# PART 1: Havok memory allocator — GameHeap or separate?")
write("#" * 70)

decompile_at(0x00c85750, "hkMemoryAllocator_GetInstance")

# Read the allocator vtable from runtime data
# DAT_011b02f0 area is referenced by ragdoll cleanup
# The allocator is at *(FUN_00c85750() + 0x10) -> vtable
# Let's check what FUN_00c85750 returns and trace its vtable
find_xrefs_to(0x00c85750, "hkMemoryAllocator_GetInstance_callers", 10)

# FUN_00cd8820 — Havok large block allocator (falls through to GameHeap?)
decompile_at(0x00cd8820, "Havok_LargeBlockAlloc")
find_calls_from(0x00cd8820, "Havok_LargeBlockAlloc")

# FUN_00cd8870 — Havok large block free
decompile_at(0x00cd8870, "Havok_LargeBlockFree")
find_calls_from(0x00cd8870, "Havok_LargeBlockFree")

# =====================================================================
# PART 2: hkThreadMemory — per-thread Havok allocator
# Object at 0x010CACD0 (from crash stack). How does it allocate?
# Does it sub-allocate from blocks obtained via GameHeap?
# =====================================================================
write("")
write("#" * 70)
write("# PART 2: hkThreadMemory — per-thread Havok allocator")
write("#" * 70)

# hkThreadMemory vtable at 0x010CACD0
read_vtable(0x010CACD0, "hkThreadMemory", 8)

# FUN_00cd87b0 — hkThreadMemory alloc?
decompile_at(0x00cd87b0, "hkThreadMemory_Alloc")
find_calls_from(0x00cd87b0, "hkThreadMemory_Alloc")

# FUN_00cd8780 — hkThreadMemory free?
decompile_at(0x00cd8780, "hkThreadMemory_Free")
find_calls_from(0x00cd8780, "hkThreadMemory_Free")

# =====================================================================
# PART 3: All IOTask types — what types besides QueuedCharacter and
# QueuedTexture exist? Each may have stale pointer issues.
# Search for IOTask vtable references.
# =====================================================================
write("")
write("#" * 70)
write("# PART 3: IOTask types — all task vtables in LockFreeQueue<IOTask>")
write("#" * 70)

# QueuedCharacter vtable: 0x01016CEC
# QueuedTexture vtable: 0x01016788
# Search for other vtables that inherit from IOTask base
# IOTask base has FUN_0044dd60 as release — find all vtables referencing it
find_xrefs_to(0x00440540, "IOTask_BaseCtor_callers", 30)

# FUN_00440540 is the IOTask base constructor (from QueuedCharacter ctor)
decompile_at(0x00440540, "IOTask_BaseCtor")

# =====================================================================
# PART 4: FUN_00c3dbf0 Phase 3 dispatch — vtable+0x14 callback
# What does Process do for each task type? Which ones read freed data?
# =====================================================================
write("")
write("#" * 70)
write("# PART 4: IOManager dispatch — task Process callbacks")
write("#" * 70)

# The dispatch calls: (**(code **)(*local_14 + 0x14))()
# For QueuedCharacter: vtable[5] = 0x0043fdf0
# For QueuedTexture: vtable[5] = 0x0043fdf0 (same base!)
# Check what vtable[5] dispatches to for different types
decompile_at(0x0043fdf0, "IOTask_Process_Base")

# vtable+0x3c is the REAL dispatch (called by Process)
# QueuedCharacter: vtable[15] = 0x00441800
decompile_at(0x00441800, "QueuedCharacter_RealProcess")
find_calls_from(0x00441800, "QueuedCharacter_RealProcess")

# QueuedTexture: check its vtable[15]
qtext_vtable15 = getInt(toAddr(0x01016788 + 15*4)) & 0xFFFFFFFF
write("\nQueuedTexture vtable[15] = 0x%08x" % qtext_vtable15)
decompile_at(qtext_vtable15, "QueuedTexture_RealProcess")
find_calls_from(qtext_vtable15, "QueuedTexture_RealProcess")

# =====================================================================
# PART 5: Character ragdoll pointer lifecycle
# Character+0x68 -> HighProcess -> ragdoll via vtable+0x28c
# When is this pointer set? When is it cleared?
# Can we hook the ragdoll detach to NULL this pointer?
# =====================================================================
write("")
write("#" * 70)
write("# PART 5: HighProcess ragdoll pointer — set/clear lifecycle")
write("#" * 70)

# FUN_009306d0 reads *(param_1 + 0x68) then calls vtable+0x28c
# What function is at vtable+0x28c of HighProcess?
# HighProcess vtable at 0x01087864 (from crash stack)
hp_vtable = 0x01087864
ragdoll_getter_offset = 0x28c // 4  # = 0xA3
write("\nHighProcess vtable[0xA3] (offset +0x28c):")
ragdoll_getter = getInt(toAddr(hp_vtable + 0x28c)) & 0xFFFFFFFF
write("  -> 0x%08x" % ragdoll_getter)
decompile_at(ragdoll_getter, "HighProcess_GetRagdoll")

# Who SETS the ragdoll in HighProcess? Search for writes to the ragdoll field
# FUN_00c741e0 creates ragdoll controller (from FUN_00930c70 line 227)
decompile_at(0x00c741e0, "CreateRagdollController")
find_calls_from(0x00c741e0, "CreateRagdollController")

# =====================================================================
# PART 6: Per-frame PDD NiNode queue 0x08 — what exactly frees ragdoll?
# Trace: PDD destroys NiNode -> NiNode tree destruction -> ragdoll freed
# Does PDD queue 0x08 destroy the Character's NiNode or just orphaned nodes?
# =====================================================================
write("")
write("#" * 70)
write("# PART 6: What enters PDD queue 0x08? Who adds items?")
write("#" * 70)

# DAT_011de808 is the NiNode queue. Who writes to it?
find_xrefs_to(0x011de808, "PDD_Queue_08_NiNode", 20)

# FUN_00418e00 — queue 0x04 (texture) destructor for comparison
decompile_at(0x00418e00, "PDD_Queue04_TextureDtor")

# =====================================================================
# PART 7: BSTaskManagerThread task completion — how tasks move from
# BSTaskManagerThread to main thread completion queue
# Can we intercept at completion to validate task references?
# =====================================================================
write("")
write("#" * 70)
write("# PART 7: Task completion path — BSTaskManagerThread -> main thread")
write("#" * 70)

# From COMPREHENSIVE analysis: IOManager vtable+0x4C and +0x50 are callbacks
# These are called AFTER task processing on BSTaskManagerThread
# vtable+0x50 is the "complete" callback that moves to completion queue
# The IOManager vtable is at *(DAT_01202d98)
# Let's check what's at the IOManager vtable
decompile_at(0x00c3dbf0, "IOManager_MainThread_Process_Brief", 3000)

# FUN_00449f80 — called from IOManager dequeue
decompile_at(0x00449f80, "IOManager_GetCompletionQueue")

# FUN_00c3ea60 — actual dequeue from completion queue
decompile_at(0x00c3ea60, "CompletionQueue_Dequeue")
find_calls_from(0x00c3ea60, "CompletionQueue_Dequeue")


# WRITE OUTPUT
outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/crash/stale_pointer_audit.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
write("Wrote %d lines to %s" % (len(output), outpath))
decomp.dispose()
