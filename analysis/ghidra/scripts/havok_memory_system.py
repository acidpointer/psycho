# @category Analysis
# @description Research the Havok memory system.
# Goal: Does hkFreeListAllocator use GameHeap? What happens on OOM?
# The stress test crash showed hkLargeBlockAllocator on the stack —
# Havok has its OWN allocator that may not go through our hooks.

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
write("HAVOK MEMORY SYSTEM ANALYSIS")
write("Goal: Does Havok allocate through GameHeap or its own system?")
write("If Havok has its own allocator, our quarantine doesn't protect it.")
write("=" * 70)

# ===================================================================
# PART 1: hkFreeListAllocator — the allocator on the crash stack
# ===================================================================
write("")
write("#" * 70)
write("# PART 1: hkFreeListAllocator / hkLargeBlockAllocator")
write("# RTTI: 0x010D7C34 (hkLargeBlockAllocator)")
write("# Stack address: 0x01204454")
write("#" * 70)

# 0x01204454 is a GLOBAL — this is the Havok allocator singleton
# It's near DAT_01202d98 (Havok world) in memory
write("0x01204454 is near DAT_01202d98 (Havok world at 0x01202d98)")
write("Offset: 0x01204454 - 0x01202d98 = 0x16BC bytes apart")

# Find who references this allocator
find_refs_to(0x01204454, "hkFreeListAllocator global (0x01204454)")

# ===================================================================
# PART 2: Havok allocate/free functions
# ===================================================================
write("")
write("#" * 70)
write("# PART 2: Havok allocate/free — do they call GameHeap?")
write("#" * 70)

# FUN_00c3e1b0 — hkAllocate (352 bytes, from earlier research)
# This was listed as 513 bytes but Ghidra resolved to FUN_00c3dfa0
decompile_at(0x00C3E1B0, "hkAllocate_Dispatcher (FUN_00c3e1b0)")

# The actual allocation — does it call GameHeap::Allocate or its own pool?
decompile_at(0x00C3E420, "hkWorld_AllocateInternal (FUN_00c3e420)")

# FUN_00c3e460 — called after allocation?
decompile_at(0x00C3E460, "hkAlloc_Post (FUN_00c3e460)")

# ===================================================================
# PART 3: Havok init — how is the memory system set up?
# ===================================================================
write("")
write("#" * 70)
write("# PART 3: Havok world creation and memory setup")
write("#" * 70)

# FUN_00c3dfa0 was the function containing hkAllocate and hkDeallocate
# It's 513 bytes — a complex function that manages Havok's memory pool
decompile_at(0x00C3DFA0, "hkMemory_Manager (513 bytes)", 10000)

# ===================================================================
# PART 4: bhkMemorySystem — Bethesda's Havok memory wrapper
# ===================================================================
write("")
write("#" * 70)
write("# PART 4: Bethesda's Havok memory wrapper")
write("# Bethesda wraps Havok's allocator. The wrapper may call GameHeap.")
write("#" * 70)

# Look for the bhkMemorySystem class
# The Havok init function at 0x0086A850 should set up the memory system
decompile_at(0x0086A850, "Game_HavokInit (4532 bytes)", 15000)

# ===================================================================
# PART 5: What does hkpWorld destruction look like?
# ===================================================================
write("")
write("#" * 70)
write("# PART 5: hkpWorld entity removal — broadphase update")
write("#" * 70)

# When PDD queue 0x20 runs the Havok destructor, it should call
# hkpWorld::removeEntity which updates the broadphase
decompile_at(0x00C41FE0, "hkWorld_RemoveEntry (FUN_00c41fe0)")

# ===================================================================
# PART 6: The crash path — trace from pathfinding to broadphase
# ===================================================================
write("")
write("#" * 70)
write("# PART 6: Crash path — pathfinding → broadphase")
write("# 0x006E6919 → 0x00C698CC → 0x00CBF918 → 0x00CAFED5")
write("#" * 70)

decompile_at(0x006E6919, "Pathfinding_StartRayCast")
decompile_at(0x00C698CC, "hkWorld_CastRay (broadphase entry)")

write("")
write("=" * 70)
write("RESEARCH COMPLETE")
write("=" * 70)

outpath = "/data/storage0/Workspace/psycho/analysis/ghidra/output/memory/havok_memory_system.txt"
fout = open(outpath, "w")
fout.write("\n".join(output))
fout.close()
print("Output written to %s (%d lines)" % (outpath, len(output)))
decomp.dispose()
