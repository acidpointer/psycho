# @category Analysis
# @description Research the Havok broadphase crash during stress testing.
# The crash is at 0x00CAFED5 in broadphase raycasting code, on the MAIN
# thread during normal pathfinding. We need to understand:
# 1. What does hkFreeListAllocator use for backing memory?
# 2. What happens to the broadphase during FindCellToUnload + PDD?
# 3. Does queue 0x20 properly remove objects from the broadphase?
# 4. What does the crash function at 0x00CAFED5 actually do?

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
		write("  %s @ %s (in %s)" % (ref.getReferenceType(), ref.getFromAddress(), fname))
		count += 1
		if count > 30:
			write("  ... (truncated)")
			break
	write("  Total: %d refs" % count)

write("=" * 70)
write("HAVOK BROADPHASE CRASH ANALYSIS")
write("Crash at 0x00CAFED5 during pathfinding raycasting")
write("Stack: hkp3AxisSweep, hkpWorldRayCaster, PathingSearchRayCast")
write("=" * 70)

# ===================================================================
# PART 1: The crash function — what operation crashed?
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: Crash function at 0x00CAFED5")
write("#" * 70)

decompile_at(0x00CAFED5, "Crash_Function (contains crash addr)")

# The calltrace chain
decompile_at(0x00D2610B, "Havok_Caller1")
decompile_at(0x00D1666A, "Havok_Caller2")
decompile_at(0x00CBF918, "Havok_Caller3")
decompile_at(0x00C698CC, "Havok_BroadphaseQuery")

# ===================================================================
# PART 2: hkFreeListAllocator — what memory does Havok use?
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: hkFreeListAllocator — Havok's memory allocator")
write("# Does it use GameHeap? Its own pool? What happens on OOM?")
write("#" * 70)

# hkFreeListAllocator vtable/RTTI at 0x010D7C34 (from crash stack)
# The stack showed 0x01204454 → 0x010D7C34 => Class: hkLargeBlockAllocator
# This suggests Havok uses hkLargeBlockAllocator for large blocks

# bhkCollisionObject destructor calls GameHeap::Free (FUN_00aa4060)
# But does hkFreeListAllocator also use GameHeap?
decompile_at(0x00C3E860, "hkFreeList_Operation (called from hkDeallocate)")

# The Havok memory init — how is the allocator configured?
decompile_at(0x0086A850, "Havok_Init (4532 bytes, references DAT_01202d98)", 12000)

# ===================================================================
# PART 3: PDD Queue 0x20 — Havok destructor chain
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: PDD Queue 0x20 Havok destruction")
write("# Does the destructor remove objects from the broadphase?")
write("#" * 70)

# Queue 0x20 destructor: FUN_00401970
decompile_at(0x00401970, "Havok_Release_PDD (queue 0x20, 43 bytes)")

# FUN_004019a0 — refcount decrement (called by Havok_Release)
decompile_at(0x004019A0, "Havok_DecRef (FUN_004019a0)")

# The vtable+4 call in Havok_Release — this is the actual destructor
# For hkpRigidBody, this would remove it from the hkpWorld
# We need to find what vtable+4 does for bhkRigidBody / hkpRigidBody

# bhkCollisionObject destructor (from earlier research)
decompile_at(0x00C40B70, "bhkCollisionObject_dtor (754 bytes)", 10000)

# FUN_00c420d0 — called before GameHeap::Free in the dtor
decompile_at(0x00C420D0, "Havok_RemoveFromWorld? (FUN_00c420d0)")

# ===================================================================
# PART 4: FindCellToUnload → what Havok state changes?
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: Cell destruction → Havok object lifecycle")
write("# What happens to collision objects when a cell is destroyed?")
write("#" * 70)

# DestroyCell (FUN_00462290) — what does it do with physics?
decompile_at(0x00462290, "DestroyCell (341 bytes)")

# FUN_00961f30 — called by DestroyCell with param_1=cell, param_2=0
decompile_at(0x00961F30, "DestroyCell_Physics? (FUN_00961f30)")

# FUN_005508b0 — called by DestroyCell (cell cleanup)
decompile_at(0x005508B0, "DestroyCell_Cleanup1 (FUN_005508b0)")

# FUN_0054b750 — called by DestroyCell (cell cleanup)
decompile_at(0x0054B750, "DestroyCell_Cleanup2 (FUN_0054b750)")

# ===================================================================
# PART 5: Pathfinding raycasting — what does it access?
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: Pathfinding raycast chain (crash calltrace)")
write("#" * 70)

decompile_at(0x006EBC61, "Pathfinding_Outer")
decompile_at(0x006EAF5D, "Pathfinding_Inner1")
decompile_at(0x006EA423, "Pathfinding_Inner2")
decompile_at(0x006E6919, "Pathfinding_RayCast")

# ===================================================================
# PART 6: hkpWorld::removeEntity — is this called during PDD?
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: Does PDD properly remove from hkpWorld?")
write("# If not, broadphase has stale entries")
write("#" * 70)

# The crash showed ahkpWorld at 0x2110B4C0 → 0x010C3BC4
# Let's trace what removeEntity does to the broadphase
decompile_at(0x00C41FE0, "Havok_FreeEntry (FUN_00c41fe0, called in dtor loop)")

# FUN_00c42180 — reconstruct (called at end of dtor)
decompile_at(0x00C42180, "Havok_Reconstruct (FUN_00c42180)")

# ===================================================================
# PART 7: What does the game's normal PDD caller do differently?
# Compare FUN_008782b0 (normal PDD) vs our approach
# ===================================================================
write("")
write("#" * 70)
write("# PART 7: Normal PDD caller FUN_008782b0 — does it handle Havok specially?")
write("#" * 70)

decompile_at(0x008782B0, "NormalPDD_Caller (FUN_008782b0, 130 bytes)")

# FUN_00878340 — called AFTER DeferredCleanupSmall in the normal caller
decompile_at(0x00878340, "PostPDD_Check (FUN_00878340)")
decompile_at(0x00878360, "HeapPressureCheck (FUN_00878360)")

# ===================================================================
# PART 8: hkp3AxisSweep — broadphase internals
# ===================================================================
write("")
write("#" * 70)
write("# PART 8: hkp3AxisSweep broadphase — how entries are managed")
write("#" * 70)

# hkp3AxisSweep RTTI at 0x010CD5CC
# The crash stack showed it at 0x211270C0
# It's the spatial data structure for collision detection

# Find functions that modify the broadphase
find_refs_to(0x010CD5CC, "hkp3AxisSweep RTTI")

write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/havok_broadphase_crash.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
